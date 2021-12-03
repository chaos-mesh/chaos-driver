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

void ioem_error_injection(struct request* rq);

#define rb_to_rq(rb) rb_entry_safe(rb, struct request, rb_node)
#define rq_rb_first(root) rb_to_rq(rb_first(root))

struct ioem_priv {
    u64 time_to_send;
};

struct ioem_priv* ioem_priv(struct request *rq)
{
    // `priv` has two pointers long, is enough to store the `ioem_priv`.
    return (struct ioem_priv*)(&rq->elv.priv[0]);
}

struct ioem_hctx_data {
    struct rb_root root;
    spinlock_t lock;

    struct hrtimer timer;
    u64 last_expires;

    struct blk_mq_hw_ctx* hctx;
};

static enum hrtimer_restart ioem_timer(struct hrtimer * timer)
{
    struct ioem_hctx_data* ihd = container_of(timer, struct ioem_hctx_data,
                         timer);

    blk_mq_run_hw_queue(ihd->hctx, 1);

    return HRTIMER_NORESTART;
}

static int ioem_init_sched(struct request_queue *q, struct elevator_type *e)
{
    struct elevator_queue *eq;

    eq = elevator_alloc(q, e);
    if (!eq)
        return -ENOMEM;


    q->elevator = eq;

    return 0;
}

static int ioem_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
    struct ioem_hctx_data *ihd;

    ihd = kmalloc_node(sizeof(*ihd), GFP_KERNEL, hctx->numa_node);
    if (!ihd)
        return -ENOMEM;
    
    hrtimer_init(&ihd->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);

    spin_lock_init(&ihd->lock);
    ihd->root = RB_ROOT;
    ihd->timer.function = ioem_timer;
    ihd->last_expires = 0;
    ihd->hctx = hctx;

    hctx->sched_data = ihd;
    return 0;
}

static void ioem_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
    struct ioem_hctx_data *ihd = hctx->sched_data;

    hrtimer_cancel(&ihd->timer);
    kfree(hctx->sched_data);
}

static void ioem_enqueue(struct ioem_hctx_data *data, struct request *rq)
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

static struct request* ioem_peek_request(struct ioem_hctx_data *data)
{
    struct request* ioem_rq = rq_rb_first(&data->root);

    return ioem_rq;
}

static void ioem_erase_head(struct ioem_hctx_data *data, struct request *rq)
{
    rb_erase(&rq->rb_node, &data->root);
}

struct request* ioem_dispatch_request(struct blk_mq_hw_ctx * hctx)
{
    struct ioem_hctx_data *ihd = hctx->sched_data;
    struct request *rq = NULL;

    spin_lock(&ihd->lock);
    if (!RB_EMPTY_ROOT(&ihd->root)) {
        u64 now, time_to_send;

        rq = ioem_peek_request(ihd);

        now = ktime_get_ns();
        time_to_send = ioem_priv(rq)->time_to_send;

        if (time_to_send <= now) {
            ioem_erase_head(ihd, rq);
        } else {
            rq = NULL;
            if (hrtimer_is_queued(&ihd->timer)) {
                if (ihd->last_expires <= time_to_send) {
                    goto tail;
                }
            }

            ihd->last_expires = time_to_send;
            hrtimer_start(&ihd->timer, ns_to_ktime(time_to_send), HRTIMER_MODE_ABS);
        }
    }

tail:
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
    if (rq != NULL) {
        atomic_dec(&hctx->elevator_queued);
    }
    #endif

    spin_unlock(&ihd->lock);

    return rq;
}

static void ioem_insert_requests(struct blk_mq_hw_ctx * hctx, struct list_head * list, bool at_head) 
{
    struct ioem_hctx_data *ihd = hctx->sched_data;

    spin_lock(&ihd->lock);
    while (!list_empty(list)) {
        struct request *rq;

        rq = list_first_entry(list, struct request, queuelist);
        list_del_init(&rq->queuelist);

        ioem_priv(rq)->time_to_send = ktime_get_ns();

        ioem_error_injection(rq);

        ioem_enqueue(ihd, rq);

        #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
        atomic_inc(&hctx->elevator_queued);
        #endif
    }
    spin_unlock(&ihd->lock);
}

static bool has_work(struct blk_mq_hw_ctx * hctx)
{
    struct ioem_hctx_data *ihd = hctx->sched_data;
    bool has_work = 0;

    has_work = !RB_EMPTY_ROOT(&ihd->root);

    return has_work;
}

static struct elevator_type ioem = {
    .ops = {
        .init_sched = ioem_init_sched,
        .init_hctx = ioem_init_hctx,
        .exit_hctx = ioem_exit_hctx,

        .insert_requests = ioem_insert_requests,
        .dispatch_request = ioem_dispatch_request,
        .has_work = has_work,
    },
    .elevator_name = "ioem",
    .elevator_owner = THIS_MODULE,
};

int ioem_register(void) 
{
    return elv_register(&ioem);
}

void ioem_unregister(void)
{
    elv_unregister(&ioem);
}

struct ioem_injection {
    unsigned long id;

    struct list_head list;

    struct ioem_matcher_arg arg;

    s64 delay;
    s64 delay_jitter;
    struct crndstate {
        u32 last;
        u32 rho;
    } delay_cor;
};

LIST_HEAD(ioem_injection_list);
DEFINE_RWLOCK(ioem_injection_list_lock);

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
        ioem_injection->delay = delay_arg.delay;
        ioem_injection->delay_jitter = delay_arg.jitter;
        ioem_injection->delay_cor.rho = delay_arg.corr;

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

void ioem_error_injection(struct request* rq)
{
    struct ioem_injection* e;
    u64 delay = 0;

    read_lock(&ioem_injection_list_lock);

    list_for_each_entry(e, &ioem_injection_list, list)
    {
        if (rq->bio == NULL) {
            continue;
        }

        #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0))
        if (e->arg.device != 0 && (rq->bio != NULL && rq->bio->bi_disk != NULL && disk_devt(rq->bio->bi_disk) != e->arg.device)) {
        #else
        if (e->arg.device != 0 && (rq->bio->bi_bdev != NULL && rq->bio->bi_bdev->bd_dev != e->arg.device)) {
        #endif
            continue;
        }

        if (e->arg.op) 
        {
            unsigned int op = rq->bio->bi_opf & REQ_OP_MASK;
            if (e->arg.op == 1 && !(op == REQ_OP_WRITE || op == REQ_OP_WRITE_SAME || op == REQ_OP_WRITE_ZEROES))
            {
                continue;
            }
            if (e->arg.op == 2 && !(op == REQ_OP_READ))
            {
                continue;
            }
        }

        delay += ioem_random(e->delay, e->delay_jitter, &e->delay_cor);
    }

    read_unlock(&ioem_injection_list_lock);

    ioem_priv(rq)->time_to_send =  ktime_get_ns() + delay;
    return;
}
