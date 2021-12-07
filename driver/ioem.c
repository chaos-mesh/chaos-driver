#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/rbtree.h>
#include <linux/hrtimer.h>
#include <linux/list.h>
#include <linux/random.h>
#include <linux/ktime.h>

#include "ioem.h"
#include "comp.h"

#define rb_to_rq(rb) rb_entry_safe(rb, struct request, rb_node)
#define rq_rb_first(root) rb_to_rq(rb_first(root))

/**
 * struct irl - request limit
 * @lock: The lock protects the config
 * @io_period_us: The period to reset the counter (in us)
 * @io_quota: The quota of dispatching request
 * @io_counter: The counter of all io requests in one period
 * @last_expire_time: The last time when the counter is reset
 * @timer: The hrtimer to reset the counter according to io_period_use
 *
 * Every device (request_queue) should have one `irl`. This struct can be used
 * to implement the limit of IOPS
 */
struct irl {
    rwlock_t lock;
    u64 io_period_us;
    u64 io_quota;

    atomic64_t io_counter;
    atomic64_t last_expire_time;
    struct hrtimer timer;
};

void ioem_error_injection(struct irl* irl, struct request* rq);

/**
 * irl_change() - change the config of irl
 * @counter: The corresponding irl struct
 * @io_period_us: The period of irl
 * @io_quota: The quota of irl
 */
static void irl_change(struct irl* counter, u64 io_period_us, u64 io_quota)
{
    write_lock(&counter->lock);

    counter->io_quota = io_quota;
    if (counter->io_period_us == 0) {
        hrtimer_start(&counter->timer, io_period_us * NSEC_PER_USEC, HRTIMER_MODE_ABS_PINNED);
    } else {
        hrtimer_cancel(&counter->timer);
    }
    counter->io_period_us = io_period_us;

    write_unlock(&counter->lock);
}

static enum hrtimer_restart irl_timer_callback(struct hrtimer * timer)
{
    enum hrtimer_restart ret;
    u64 period_us = 0;

    struct irl* counter = container_of(timer, struct irl, timer);

    atomic64_set(&counter->last_expire_time, timer->base->get_time());
    atomic64_set(&counter->io_counter, 0);

    read_lock(&counter->lock);
    period_us = counter->io_period_us;
    if (period_us > 0) {
        hrtimer_forward_now(timer, period_us * NSEC_PER_USEC);
        ret = HRTIMER_RESTART;
    } else {
        ret = HRTIMER_NORESTART;
    }
    read_unlock(&counter->lock);

    return ret;
}

static void irl_init(struct irl* counter)
{
    rwlock_init(&counter->lock);
    hrtimer_init(&counter->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED);
    counter->timer.function = irl_timer_callback;
}

struct irl_dispatch_return {
    bool dispatch;
    u64 time_to_send;
};

/**
 * irl_dispatch() - change the config of irl
 * @irl: The corresponding irl struct
 *
 * This function will increase the counter inside the irl. If the counter exceed
 * the quota, it will return `{0, time_to_send}`. Tthe `time_to_send` is the
 * next time to reset quota, which is `last_expire_time + period` (in absolute
 * ns)
 *
 * If the counter didn't exceed the quota, it will return `{1, 0}`
 */
static struct irl_dispatch_return irl_dispatch(struct irl* irl)
{
    struct irl_dispatch_return ret;
    u64 counter;
    u64 quota;

    read_lock(&irl->lock);
    if (irl->io_period_us == 0) {
        // the irl is not enabled
        ret.dispatch = 1;
        ret.time_to_send = 0;
    } else {
        // the irl is enabled
        counter = atomic64_read(&irl->io_counter);
        quota = irl->io_quota;
        while (counter < quota) {
            if (atomic64_cmpxchg(&irl->io_counter, counter, counter+1) == counter) {
                break;
            }
            counter = atomic64_read(&irl->io_counter);
        }
        if (counter < quota) {
            // 
            ret.dispatch = 1;
            ret.time_to_send = 0;
        } else { 
            ret.dispatch = 0;
            ret.time_to_send = ktime_get_ns() + irl->io_period_us * NSEC_PER_USEC;
        }
    }
    read_unlock(&irl->lock);

    return ret;
}

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
};

struct ioem_priv* ioem_priv(struct request *rq)
{
    // `priv` has two pointers long, is enough to store the `ioem_priv`.
    return (struct ioem_priv*)(&rq->elv.priv[0]);
}

/**
 * struct ioem_data - the main data of ioem
 * @root: The rb tree root, which is sorted according to `time_to_send`
 * @lock: The spinlock of the whole structure
 * @timer: The timer used to trigger the dispatch after reaching the
 * `time_to_send`.
 * @next_expires: Record the next time when the timer will expire.
 * @irl: The pointer to irl. It doesn't need to have the `irl`, which means the
 * `irl` may be allocated and stored in other structure, and this is only a
 * reference.
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
    struct rb_root root;
    spinlock_t lock;

    struct hrtimer timer;
    u64 next_expires;

    struct irl* irl;

    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))
    struct blk_mq_hw_ctx* hctx;
    #endif

    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0))
    struct request_queue* q;
    struct work_struct unplug_work;
    #endif
};

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
    rb_erase(&rq->rb_node, &data->root);
    RB_CLEAR_NODE(&rq->rb_node);
    INIT_LIST_HEAD(&rq->queuelist);
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
 * @irl: The pointer to irl.
 *
 * In blk-mq situation, the irl is allocated per `request_queue`, and the
 * `ioem_data` is allocated per `hctx`, so it only needs to set a pointer to the
 * `irl`.
 *
 * Be careful that the `ioem_data` should not be touched after the `irl` is
 * freed.
 */
static void ioem_data_init(struct ioem_data* data, enum hrtimer_restart	(*function)(struct hrtimer *), struct irl* irl)
{
    hrtimer_init(&data->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED);

    spin_lock_init(&data->lock);
    data->root = RB_ROOT;
    data->timer.function = function;
    data->next_expires = 0;

    data->irl = irl;
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

        if (ioem_priv(rq)->time_to_send >= ioem_priv(parent_rq)->time_to_send)
            p = &parent->rb_right;
        else
            p = &parent->rb_left;
    }

    rb_link_node(&rq->rb_node, parent, p);
    rb_insert_color(&rq->rb_node, &data->root);
}

/**
 * ioem_dequeue() - pop the first request whose `time_to_send` is earlier than
 * now.
 * @data: The `ioem_data` structure
 *
 * If the first request's `time_to_send` is earlier than now, and the quota in
 * `irl` doesn't exceeded, it will be returned and removed from the `ioem_data`.
 *
 * If the quota exceeded or the `time_to_send` is later than now, the hrtimer
 * will be used to trigger the next dispatch when it's possible to dispatch this
 * request.
 */
static struct request* ioem_dequeue(struct ioem_data *data)
{
    u64 now, time_to_send;
    struct request* rq = NULL;

    if (!RB_EMPTY_ROOT(&data->root)) {
        rq = ioem_peek_request(data);

        now = ktime_get_ns();
        time_to_send = ioem_priv(rq)->time_to_send;

        if (time_to_send <= now) {
            struct irl_dispatch_return irl_ret;
            irl_ret = irl_dispatch(data->irl);
            if (irl_ret.dispatch > 0) {
                ioem_erase_head(data, rq);
            } else {
                time_to_send = irl_ret.time_to_send;
                rq = NULL;
            }
        } else {
            rq = NULL;
        }
    }

    if (rq != NULL) {
        return rq;
    }

    if (hrtimer_is_queued(&data->timer)) {
        if (data->next_expires <= time_to_send) {
            return NULL;
        }
    }

    data->next_expires = time_to_send;
    hrtimer_start(&data->timer, ns_to_ktime(time_to_send), HRTIMER_MODE_ABS_PINNED);

    return NULL;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))

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

//             ┌─────────────┐
//             │REQUEST_QUEUE│
//             └─────┬───────┘
//                   │
//                 ┌─▼─┐
//      ┌──────────►IRL◄──────────┐
//      │          └─▲─┘          │
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
    struct irl *irl;

    eq = elevator_alloc(q, e);
    if (!eq)
        return -ENOMEM;
    
    irl = kzalloc_node(sizeof(*irl), GFP_KERNEL, q->node);
	if (!irl) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
    irl_init(irl);

    eq->elevator_data = irl;
    q->elevator = eq;

    return 0;
}

static void ioem_mq_exit_sched(struct elevator_queue *e)
{
    struct irl *irl = e->elevator_data;
    hrtimer_cancel(&irl->timer);
    kfree(irl);
}

static int ioem_mq_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
    struct ioem_data *id;

    id = kzalloc_node(sizeof(*id), GFP_KERNEL, hctx->numa_node);
    if (!id)
        return -ENOMEM;

    ioem_data_init(id, ioem_mq_timer, hctx->queue->elevator->elevator_data);
    id->hctx = hctx;

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
    struct ioem_data *id = hctx->sched_data;

    spin_lock(&id->lock);
    while (!list_empty(list)) {
        struct request *rq;

        rq = list_first_entry(list, struct request, queuelist);
        list_del_init(&rq->queuelist);

        ioem_priv(rq)->time_to_send = ktime_get_ns();

        ioem_error_injection(id->irl, rq);

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
//  └────┬───────┬┘
//       │       │
//       │       │
//  ┌────▼────┐ ┌▼──┐
//  │IOEM_DATA├─►IRL│
//  └─────────┘ └───┘

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
    struct irl *irl;

    eq = elevator_alloc(q, e);
    if (!eq)
        return -ENOMEM;

    irl = kzalloc_node(sizeof(*irl), GFP_KERNEL, q->node);
	if (!irl) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
    irl_init(irl);

    id = kzalloc_node(sizeof(*id), GFP_KERNEL, q->node);
    if (!id) {
        kobject_put(&eq->kobj);
        return -ENOMEM;
    }
    
    ioem_data_init(id, ioem_sq_timer, irl);
    id->q = q;
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
    hrtimer_cancel(&id->irl->timer);
	kfree(id->irl);
	kfree(id);
}

static void ioem_sq_insert_request(struct request_queue *q, struct request *rq)
{
    struct ioem_data *id = q->elevator->elevator_data;

    ioem_priv(rq)->time_to_send = ktime_get_ns();
    ioem_error_injection(id->irl, rq);

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

	ioem_erase_head(id, rq);
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

    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))
    ret = elv_register(&ioem_mq);
    if (ret != 0) {
        goto err;
    }
    #endif

    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0))
    ret = elv_register(&ioem_sq);
    if (ret != 0) {
        goto err;
    }
    #endif

    return 0;
err:
    pr_err("ioem: failed to register ioem_mq: %d\n", ret);
    return ret;
}

void ioem_unregister(void)
{
    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))
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

        struct {
            u64 period_us;
            u64 quota;
            atomic_t injected;
        } limit;
    };
};

LIST_HEAD(ioem_injection_list);
DEFINE_RWLOCK(ioem_injection_list_lock);

int build_ioem_injection(unsigned long id, struct chaos_injection * injection)
{
    int ret = 0;
    struct ioem_injection* ioem_injection;
    struct ioem_injector_delay_arg delay_arg;
    struct ioem_injector_limit_arg limit_arg;

    ioem_injection = kmalloc(sizeof(*ioem_injection), GFP_KERNEL);
    if (ioem_injection == NULL)
    {
        return ENOMEM;
    }

    INIT_LIST_HEAD(&ioem_injection->list);
    ioem_injection->id = id;

    if (copy_from_user(&ioem_injection->arg, injection->matcher_arg, sizeof(&ioem_injection->arg)))
    {
        ret = EINVAL;
        goto free_matcher_arg;
    }

    ioem_injection->arg.device = new_decode_dev(ioem_injection->arg.device);

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
    case IOEM_INJECTOR_TYPE_LIMIT:
        if (copy_from_user(&limit_arg, injection->injector_arg, sizeof(limit_arg)))
        {
            ret = EINVAL;
            goto free_matcher_arg;
        }
        ioem_injection->limit.period_us = limit_arg.period_us;
        ioem_injection->limit.quota = limit_arg.quota;
        ioem_injection->limit.injected.counter = 0;

        break;
    default:
        break;
    }

    write_lock(&ioem_injection_list_lock);
    list_add(&ioem_injection->list, &ioem_injection_list);
    write_unlock(&ioem_injection_list_lock);

    return ret;

free_matcher_arg:
    kfree(ioem_injection);

    return ret;
}

int ioem_del(unsigned long id) {
    struct ioem_injection* e, *tmp;

    write_lock(&ioem_injection_list_lock);

    list_for_each_entry_safe(e, tmp, &ioem_injection_list, list)
    {
        if ( e->id == id )
        {
            list_del(&e->list);
            kfree(e);
        }
    }

    write_unlock(&ioem_injection_list_lock);

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

void ioem_error_injection(struct irl* irl, struct request* rq)
{
    struct ioem_injection* e;
    u64 delay = 0;

    read_lock(&ioem_injection_list_lock);

    list_for_each_entry(e, &ioem_injection_list, list)
    {
        if (rq->bio == NULL) {
            continue;
        }

        if (e->arg.device != 0 && !bio_is_device(rq->bio, e->arg.device)) {
            continue;
        }

        if (e->arg.op) 
        {
            if (e->arg.op == 1 && !bio_is_read(rq->bio)) {
                continue;
            }
            if (e->arg.op == 2 && !bio_is_write(rq->bio))
            {
                continue;
            }
        }

        switch (e->injector_type)
        {
        case IOEM_INJECTOR_TYPE_DELAY:
            delay += ioem_random(e->delay.delay, e->delay.delay_jitter, &e->delay.delay_cor);
            break;
        case IOEM_INJECTOR_TYPE_LIMIT:
            if (atomic_cmpxchg(&e->limit.injected, 0, 1) == 0) {
                irl_change(irl, e->limit.period_us, e->limit.quota);
            }
        default:
            break;
        }
    }

    read_unlock(&ioem_injection_list_lock);

    ioem_priv(rq)->time_to_send += delay;
    return;
}
