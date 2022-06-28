#include <linux/blkdev.h>
#include <linux/blk-mq.h>

struct elevator_queue;
struct request;

#include <linux/elevator.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/rbtree.h>
#include <linux/hrtimer.h>
#include <linux/list.h>
#include <linux/random.h>
#include <linux/ktime.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/sched/task.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 15, 0)
#include <linux/backing-dev-defs.h>
#endif

#include "ioem.h"
#include "comp.h"

#define rb_to_rq(rb) rb_entry_safe(rb, struct request, rb_node)
#define rq_rb_first(root) rb_to_rq(rb_first(root))

#define IS_RHEL 
#define IOEM_MQ_ENABLED ((LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)) || (defined RHEL_MAJOR && RHEL_MAJOR >= 7 && defined RHEL_MINOR && RHEL_MINOR >= 6))

/**
 * struct ioem_data - the main data of ioem
 * @root: The rb tree root, which is sorted according to `time_to_send`
 * @deivce: The device of current ioem_data
 * @lock: The spinlock of the whole structure
 * @timer: The timer used to trigger the dispatch after reaching the
 * `time_to_send`.
 * @next_expires: Record the next time when the timer will expire.
 * @hctx: For blk-mq, this is a pointer to hardward queue.
 * @q: Only for blk-sq, this is a pointer to the software request queue.
 * @unplug_work: Only for blk-sq, this is a `kblockd work_struct` to trigger the
 * dispatch.
 *
 * This sturcture holds all structure that is needed to inject errors. In
 * blk-mq, this struct is allocated per `hctx` and held by `hctx`. In blk-sq,
 * this struct is only allocated per `request_queue`.
 */
struct ioem_data {
    // The rb tree root is used to handle requests with delay. The request with
    // smaller `time_to_send` will be handled first. However, if the `delay` is
    // the same, then we will insert into this rb_tree with increasing data,
    // which may cause frequent rebalance. As the practice of netem, we should
    // add a list to optimize for this situation.
    // However, current performance seems fine.
    struct rb_root root;

    dev_t device;

    spinlock_t lock;

    struct hrtimer timer;
    u64 next_expires;

    #if IOEM_MQ_ENABLED
    struct blk_mq_hw_ctx* hctx;
    #endif

    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0))
    struct request_queue* q;
    struct work_struct unplug_work;
    #endif
};

static void ioem_error_injection(struct ioem_data* id, struct request* rq);

/**
 * struct ioem_priv - The priv data stored in request 
 * @time_to_send: The expected sending time of the request
 *
 * The expected sending time is calculated when this request comes into the
 * scheduler, then it will be stored in the `struct ioem_priv`. This struct
 * shouldn't be longer than three pointers, as the `rq->elv` only have three
 * pointers long.
 */
struct ioem_priv {
    u64 time_to_send;
    bool in_rbtree;
}__attribute__((packed));

struct ioem_priv* ioem_priv(struct request *rq)
{
    BUILD_BUG_ON(sizeof(struct ioem_priv) > sizeof(rq->elv));
    // `priv` has two pointers long, is enough to store the `ioem_priv`.
    return (struct ioem_priv*)(&rq->elv.priv[0]);
}

/**
 * ioem_erase_head() - remove the request from ioem data
 * @data: The `ioem_data` structure
 * @rq: The request.
 *
 * This function will remove the reqeust from ioem data, and will also
 * reinitialize the `rb_node` and `list_node` inside the request.
 */
static void ioem_erase_head(struct ioem_data *data, struct request *rq)
{
    if (ioem_priv(rq)->in_rbtree) {
        rb_erase(&rq->rb_node, &data->root);
        RB_CLEAR_NODE(&rq->rb_node);

        ioem_priv(rq)->in_rbtree = false;
    }
}

/**
 * ioem_peek_request() - peek the first request inside ioem
 * @data: The `ioem_data` strucutre
 */
static struct request* ioem_peek_request(struct ioem_data *data)
{
    struct request* ioem_rq = rq_rb_first(&data->root);

    return ioem_rq;
}

/**
 * ioem_data_init() - initialize the `ioem_data` structure
 * @data:  The `ioem_data` strucutre 
 * @function: The callback function of `data->timer`. It is a variable to be
 * compatible with multiple kernel versions.
 */
static void ioem_data_init(struct ioem_data* data, enum hrtimer_restart	(*function)(struct hrtimer *))
{
    hrtimer_init(&data->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED);

    spin_lock_init(&data->lock);
    data->root = RB_ROOT;

    data->timer.function = function;
    data->next_expires = 0;
}

/**
 * ioem_enqueue() - insert a request into the data 
 * @data: The `ioem_data` strucutre 
 * @rq: The request 
 *
 * The request will be inserted into the rb tree
 */
static void ioem_enqueue(struct ioem_data *data, struct request *rq)
{
    struct rb_node **p = &data->root.rb_node, *parent = NULL;

    while (*p) {
        struct request* parent_rq;

        parent = *p;
        parent_rq = rb_entry_safe(parent, struct request, rb_node);

        if (ioem_priv(rq)->time_to_send > ioem_priv(parent_rq)->time_to_send) {
            p = &parent->rb_right;
        }
        else
            p = &parent->rb_left;
    }

    rb_link_node(&rq->rb_node, parent, p);
    rb_insert_color(&rq->rb_node, &data->root);

    ioem_priv(rq)->in_rbtree = true;
}

/**
 * ioem_dequeue() - pop the first request whose `time_to_send` is earlier than
 * now.
 * @data: The `ioem_data` structure
 *
 * If the first request's `time_to_send` is earlier than now, it will be
 * returned and removed from the `ioem_data`.
 *
 * If the quota exceeded or the `time_to_send` is later than now, the hrtimer
 * will be used to trigger the next dispatch when it's possible to dispatch this
 * request.
 */
static struct request* ioem_dequeue(struct ioem_data *data)
{
    u64 now, time_to_send = 0;
    struct request* rq = NULL;

    now = ktime_get_ns();

    // at this time, rq is NULL, and the `time_to_send` is 0, or the next time
    // when irl counter will be reset.
    if (RB_EMPTY_ROOT(&data->root)) {
        goto out;
    }

    if (!RB_EMPTY_ROOT(&data->root)) {
        rq = ioem_peek_request(data);
        if (time_to_send == 0) {
            time_to_send = ioem_priv(rq)->time_to_send;
        } else {
            time_to_send = min(ioem_priv(rq)->time_to_send, time_to_send);
        }

        // if this request's `time_to_send` is earlier than now, later requests
        // will be all later than now, then we need to return without any
        // request dispatched.
        if (time_to_send > now) {
            rq = NULL;
        } else {
            ioem_erase_head(data, rq);
        }
    }

out:
    // There are three possible situations to reach here:
    // 1. The request is not NULL and is prepared to send
    // 2. The earliest time_to_send is later than now
    if (rq != NULL) {
        return rq;
    }

    if (time_to_send != 0) {
        if (hrtimer_is_queued(&data->timer)) {
            if (data->next_expires <= time_to_send) {
                return NULL;
            }
        }

        data->next_expires = time_to_send;
        hrtimer_start(&data->timer, ns_to_ktime(time_to_send), HRTIMER_MODE_ABS_PINNED);
    }

    return NULL;
}

#if IOEM_MQ_ENABLED

// ioem in blk-mq
//
// Every block device has one `request_queue` and multiple `hctx`. The
// `ioem_data` is allocated per `hctx` to increase to performance, but the `irl`
// is only allocataed for the `request_queue` to count the requests on the whole
// device (but not one `hctx`)
//
// The dispatch is triggered by hardward, schedule logic or other things. The
// direct way to trigger a dispatch is to call `blk_mq_run_hw_queue`. This
// function will trigger a dispatch on one `hctx`, if the `ioem_data` is not
// empty.

//
//           ┌─────────────┐
//      ┌────►REQUEST_QUEUE◄──────┐
//      │    └───────▲─────┘      │
//      │            │            │
// ┌────┴────┐  ┌────┴────┐  ┌────┴────┐
// │IOEM_DATA│  │IOEM_DATA│  │IOEM_DATA│
// └────▲────┘  └────▲────┘  └────▲────┘
//      │            │            │
//   ┌──┴──┐      ┌──┴──┐      ┌──┴──┐
//   │HCTX │      │HCTX │      │HCTX │
//   └─────┘      └─────┘      └─────┘


static enum hrtimer_restart ioem_mq_timer(struct hrtimer * timer)
{
    struct ioem_data* id = container_of(timer, struct ioem_data,
                         timer);

    blk_mq_run_hw_queue(id->hctx, 1);

    return HRTIMER_NORESTART;
}

static int ioem_mq_init_sched(struct request_queue *q, struct elevator_type *e)
{
    struct elevator_queue *eq;

    eq = elevator_alloc(q, e);
    if (!eq)
        return -ENOMEM;
    
    q->elevator = eq;

    return 0;
}

static void ioem_mq_exit_sched(struct elevator_queue *e)
{
}

static int ioem_mq_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
    struct ioem_data *id;

    id = kzalloc_node(sizeof(*id), GFP_KERNEL, hctx->numa_node);
    if (!id)
        return -ENOMEM;

    ioem_data_init(id, ioem_mq_timer);
    id->hctx = hctx;

    #if LINUX_VERSION_CODE > KERNEL_VERSION(5, 15, 0)
    id->device = hctx->queue->disk->bdi->dev->devt;
    #elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
    id->device = hctx->queue->backing_dev_info->owner->devt;
    #else
    id->device = hctx->queue->backing_dev_info.dev->devt;
    #endif

    hctx->sched_data = id;
    return 0;
}

static void ioem_mq_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
    struct ioem_data *id = hctx->sched_data;

    hrtimer_cancel(&id->timer);
    kfree(hctx->sched_data);
}

struct request* ioem_mq_dispatch_request(struct blk_mq_hw_ctx * hctx)
{
    struct ioem_data *id = hctx->sched_data;
    struct request *rq = NULL;

    spin_lock(&id->lock);
    
    rq = ioem_dequeue(id);

    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
    if (rq != NULL) {
        atomic_dec(&hctx->elevator_queued);
    }
    #endif

    spin_unlock(&id->lock);

    return rq;
}

static void ioem_mq_insert_requests(struct blk_mq_hw_ctx * hctx, struct list_head * list, bool at_head) 
{
    struct request *rq, *next;
    struct ioem_data *id = hctx->sched_data;

    spin_lock(&id->lock);

    list_for_each_entry_safe(rq, next, list, queuelist) {
        list_del_init(&rq->queuelist);

        if (at_head) {
            ioem_priv(rq)->time_to_send = 0;
        } else {
            ioem_priv(rq)->time_to_send = ktime_get_ns();
        }
        ioem_priv(rq)->in_rbtree = false;

        ioem_error_injection(id, rq);
        ioem_enqueue(id, rq);

        #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
        atomic_inc(&hctx->elevator_queued);
        #endif
    }
    spin_unlock(&id->lock);
}

static bool ioem_mq_has_work(struct blk_mq_hw_ctx * hctx)
{
    struct ioem_data *id = hctx->sched_data;
    bool has_work = 0;

    has_work = !RB_EMPTY_ROOT(&id->root);

    return has_work;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
// the following codes are only used to register mq elevator for normal linux >= 4.0

static struct elevator_type ioem_mq = {
    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0))
    .ops = {
    #else
    .uses_mq = true,
    .ops.mq = {
    #endif
        .init_sched = ioem_mq_init_sched,
        .exit_sched = ioem_mq_exit_sched,
        .init_hctx = ioem_mq_init_hctx,
        .exit_hctx = ioem_mq_exit_hctx,

        .insert_requests = ioem_mq_insert_requests,
        .dispatch_request = ioem_mq_dispatch_request,
        .has_work = ioem_mq_has_work,
    },
    .elevator_name = "ioem-mq",
    .elevator_owner = THIS_MODULE,
};

#else

static struct elevator_mq_ops ioem_mq_ops = {
    .init_sched = ioem_mq_init_sched,
    .exit_sched = ioem_mq_exit_sched,
    .init_hctx = ioem_mq_init_hctx,
    .exit_hctx = ioem_mq_exit_hctx,

    .insert_requests = ioem_mq_insert_requests,
    .dispatch_request = ioem_mq_dispatch_request,
    .has_work = ioem_mq_has_work,
};

static struct elevator_type ioem_mq = {
    .elevator_name = "ioem-mq",
    .elevator_owner = THIS_MODULE,
};

struct elevator_type_aux *elevator_aux_find(struct elevator_type *e);

static int ioem_mq_rhel_init(void)
{
    int ret = elv_register(&ioem_mq);
    struct elevator_type_aux *aux;

    if (ret)
        return ret;
    
    aux = elevator_aux_find(&ioem_mq);
    memcpy(&aux->ops.mq, &ioem_mq_ops, sizeof(struct elevator_mq_ops));
    aux->uses_mq = true;

    return 0;
}

#endif

#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0))

// ioem in blk-sq
//
// Every block device will have one `request_queue`, and the `ioem_data` and
// `irl` is allocated for it.
//
// The dispatch can be triggered by calling the `__blk_run_queue` function. This
// function is always synchronous, so we need to schedule it through `kblockd`
// to avoid deadlock.
//
// As the running context is protected by the lock inside the `request_queue`,
// there is no need to lock the `spinlock` inside the `ioem_data`.

//  ┌─────────────┐
//  │REQUEST_QUEUE│
//  └────┬────────┘
//       │
//       │
//  ┌────▼────┐
//  │IOEM_DATA│
//  └─────────┘

static void ioem_sq_kick_queue(struct work_struct *work)
{
	struct ioem_data *id =
		container_of(work, struct ioem_data, unplug_work);
	struct request_queue *q = id->q;

	spin_lock_irq(q->queue_lock);
	__blk_run_queue(q);
	spin_unlock_irq(q->queue_lock);
}

static enum hrtimer_restart ioem_sq_timer(struct hrtimer * timer)
{
	struct ioem_data *id =
		container_of(timer, struct ioem_data, timer);

    // though in 3.10 kernel, the signature of it was  `int kblockd_schedule_work(struct request_queue *q, struct work_struct *work);`
    // it has been updated to `int kblockd_schedule_work(struct work_struct *work);` in centos 7.
    // TODO: check the centos build version to decide the signature
    kblockd_schedule_work(&id->unplug_work);

    return HRTIMER_NORESTART;
}

static int ioem_sq_init_sched(struct request_queue *q, struct elevator_type *e)
{
    struct elevator_queue *eq;
    struct ioem_data *id;

    eq = elevator_alloc(q, e);
    if (!eq)
        return -ENOMEM;

    id = kzalloc_node(sizeof(*id), GFP_KERNEL, q->node);
    if (!id) {
        kobject_put(&eq->kobj);
        return -ENOMEM;
    }
    
    ioem_data_init(id, ioem_sq_timer);
    id->q = q;
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    id->device = q->backing_dev_info.dev->devt;
    #else
    id->device = q->backing_dev_info->dev->devt;
    #endif

    INIT_WORK(&id->unplug_work, ioem_sq_kick_queue);

    eq->elevator_data = id;

	spin_lock_irq(q->queue_lock);
	q->elevator = eq;
	spin_unlock_irq(q->queue_lock);

    return 0;
}

static void ioem_sq_exit_sched(struct elevator_queue * e)
{
    struct ioem_data *id = e->elevator_data;

	BUG_ON(!RB_EMPTY_ROOT(&id->root));
	kfree(id);
}

static void ioem_sq_insert_request(struct request_queue *q, struct request *rq)
{
    struct ioem_data *id = q->elevator->elevator_data;

    ioem_priv(rq)->time_to_send = ktime_get_ns();
    ioem_error_injection(id, rq);

    ioem_enqueue(id, rq);

}

static int ioem_sq_dispatch_request(struct request_queue *q, int force)
{
    struct ioem_data *id = q->elevator->elevator_data;
    struct request *rq = NULL;
    
    rq = ioem_dequeue(id);

    if (rq != NULL) {
        elv_dispatch_sort(q, rq);
        return 1;
    }
    return 0;
}

static void ioem_sq_merged_requests(struct request_queue *q, struct request *rq,
				 struct request *next)
{
    struct ioem_data *id = q->elevator->elevator_data;

	ioem_erase_head(id, next);
}

static struct elevator_type ioem_sq = {
    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))
    .ops.sq = {
    #else
    .ops = {
    #endif
        .elevator_merge_req_fn = ioem_sq_merged_requests,
        .elevator_init_fn = ioem_sq_init_sched,
        .elevator_exit_fn = ioem_sq_exit_sched,
        .elevator_add_req_fn = ioem_sq_insert_request,
        .elevator_dispatch_fn = ioem_sq_dispatch_request,
    },
    .elevator_name = "ioem",
    .elevator_owner = THIS_MODULE,
};

#endif

int ioem_register(void) 
{
    int ret = 0;

    #if IOEM_MQ_ENABLED

    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))
    ret = elv_register(&ioem_mq);
    if (ret != 0) {
        goto err;
    }
    #else
    ret = ioem_mq_rhel_init();
    if (ret != 0) {
        goto err;
    }
    #endif

    #endif

    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0))
    ret = elv_register(&ioem_sq);
    if (ret != 0) {
        goto err;
    }
    #endif

    return 0;
err:
    pr_err("ioem: failed to register ioem: %d\n", ret);
    return ret;
}

void ioem_unregister(void)
{
    #if IOEM_MQ_ENABLED
    elv_unregister(&ioem_mq);
    #endif

    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0))
    elv_unregister(&ioem_sq);
    #endif
}

struct ioem_injection {
    unsigned long id;

    struct list_head list;

    struct ioem_matcher_arg arg;

    struct kref refcount;

    u32 injector_type;
    union {
        struct {
            s64 delay;
            s64 delay_jitter;
            struct crndstate {
                u32 last;
                u32 rho;
            } delay_cor;
        } delay;
    };
};

void ioem_injection_release(struct kref *ref)
{
    struct ioem_injection *inj = container_of(ref, struct ioem_injection, refcount);

    kfree(inj);
}

static struct {
    rwlock_t lock;
    struct list_head list;
} ioem_injections = {
    .list = LIST_HEAD_INIT(ioem_injections.list),
    .lock = __RW_LOCK_UNLOCKED(ioem_injections.lock),
};

static int ioem_get_pid_ns_inode_from_pid(unsigned int pid_nr, struct pid_namespace* pid_ns, unsigned int* out)
{
    int ret = 0;
    struct pid *pid;
    struct task_struct* task;
    struct pid_namespace* ns;

    pid = find_pid_ns(pid_nr, pid_ns);
    if (pid) {
        get_pid(pid);
    } else {
        ret = ENOENT;
        goto fail;
    }

    task = pid_task(pid, PIDTYPE_PID);
    if (task) {
        get_task_struct(task);
    } else {
        ret = ENOENT;
        goto release_pid;
    }

    rcu_read_lock();

    ns = task_active_pid_ns(task);
    if (ns) {
        *out = ns_inum(ns);
    } else {
        ret = ENOENT;
    }

    rcu_read_unlock();
    put_task_struct(task);
release_pid:
    put_pid(pid);
fail:
    return ret;
}

int build_ioem_injection(unsigned long id, struct chaos_injection * injection)
{
    int ret = 0;
    struct ioem_injection* ioem_injection;
    struct ioem_injector_delay_arg delay_arg;

    ioem_injection = kmalloc(sizeof(*ioem_injection), GFP_KERNEL);
    if (ioem_injection == NULL)
    {
        return ENOMEM;
    }
    kref_init(&ioem_injection->refcount);

    INIT_LIST_HEAD(&ioem_injection->list);
    ioem_injection->id = id;

    if (copy_from_user(&ioem_injection->arg, injection->matcher_arg, sizeof(ioem_injection->arg)))
    {
        ret = EINVAL;
        goto free_matcher_arg;
    }

    ioem_injection->arg.device = new_decode_dev(ioem_injection->arg.device);
    if (ioem_injection->arg.pid_ns != 0) {
        unsigned int ns_inode;
        struct pid_namespace* pid_ns = get_pid_ns(task_active_pid_ns(current));

        ret = ioem_get_pid_ns_inode_from_pid(ioem_injection->arg.pid_ns, pid_ns, &ns_inode);
        put_pid_ns(pid_ns);

        if (ret > 0) {
            goto free_matcher_arg;
        }

        ioem_injection->arg.pid_ns = ns_inode;
    }

    ioem_injection->injector_type = injection->injector_type;
    switch (injection->injector_type)
    {
    case IOEM_INJECTOR_TYPE_DELAY:
        if (copy_from_user(&delay_arg, injection->injector_arg, sizeof(delay_arg)))
        {
            ret = EINVAL;
            goto free_matcher_arg;
        }
        ioem_injection->delay.delay = delay_arg.delay;
        ioem_injection->delay.delay_jitter = delay_arg.jitter;
        ioem_injection->delay.delay_cor.rho = delay_arg.corr;

        break;
    default:
        break;
    }

    write_lock(&ioem_injections.lock);

    list_add(&ioem_injection->list, &ioem_injections.list);

    write_unlock(&ioem_injections.lock);

    return ret;

free_matcher_arg:
    kref_put(&ioem_injection->refcount, ioem_injection_release);

    return ret;
}

int ioem_del(unsigned long id) {
    struct ioem_injection* e, *tmp;

    write_lock(&ioem_injections.lock);

    list_for_each_entry_safe(e, tmp, &ioem_injections.list, list)
    {
        if ( e->id == id )
        {
            list_del(&e->list);
            kref_put(&e->refcount, ioem_injection_release);
            break;
        }
    }

    write_unlock(&ioem_injections.lock);

    return 0;
}

static u32 get_crandom(struct crndstate *state)
{
	u64 value, rho;
	unsigned long answer;

	if (!state || state->rho == 0)	/* no correlation */
		return prandom_u32();

	value = prandom_u32();
	rho = (u64)state->rho + 1;
	answer = (value * ((1ull<<32) - rho) + state->last * rho) >> 32;
	state->last = answer;
	return answer;
}

static s64 ioem_random(s64 mu, s32 jitter, struct crndstate *state) {
    u32 rnd;

    if (jitter == 0)
        return mu;
    
    rnd = get_crandom(state);

    return ((rnd % (2 * (u32)jitter)) + mu) - jitter;
}

/**
 * ioem_should_inject() - whether this request should be injected
 * @rq: The io request
 * @e: The ioem injection
 *
 * This functions should be called under process context, which means the
 * `current` should point to the current process, so that we can get the pid
 * namespace (or other information) of the process.
 */
static bool ioem_should_inject(struct ioem_data* id, struct request* rq, struct ioem_injection* e) {
    if (rq->bio == NULL || e == NULL) {
        return 0;
    }

    if (e->arg.pid_ns != 0 && ns_inum(task_active_pid_ns(current)) != e->arg.pid_ns) {
        return 0;
    }

    if (e->arg.device != 0 && e->arg.device != id->device) {
        return 0;
    }

    if (e->arg.op) 
    {
        if (e->arg.op == 1 && !bio_is_read(rq->bio)) {
            return 0;
        }
        if (e->arg.op == 2 && !bio_is_write(rq->bio))
        {
            return 0;
        }
    }

    return 1;
}

static void ioem_error_injection(struct ioem_data* id, struct request* rq)
{
    struct ioem_injection* e;
    u64 delay = 0;

    read_lock(&ioem_injections.lock);
    list_for_each_entry(e, &ioem_injections.list, list)
    {
        if (!ioem_should_inject(id, rq, e)) {
            continue;
        }

        switch (e->injector_type)
        {
        case IOEM_INJECTOR_TYPE_DELAY:
            delay += ioem_random(e->delay.delay, e->delay.delay_jitter, &e->delay.delay_cor);
            break;
        default:
            break;
        }
    }
    read_unlock(&ioem_injections.lock);

    ioem_priv(rq)->time_to_send += delay;
    return;
}
