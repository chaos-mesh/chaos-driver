#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/rbtree.h>
#include <linux/hrtimer.h>

#include "ioem.h"

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
    struct hrtimer timer;
    struct blk_mq_hw_ctx* hctx;
};

struct ioem_data {
    struct rb_root root;

    spinlock_t lock;
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
    struct ioem_data *data;
    struct elevator_queue *eq;

    eq = elevator_alloc(q, e);
    if (!eq)
        return -ENOMEM;

    data = kzalloc_node(sizeof(*data), GFP_KERNEL, q->node);
    if (!data) {
        kobject_put(&eq->kobj);
        return -ENOMEM;
    }
    eq->elevator_data = data;

    spin_lock_init(&data->lock);
    data->root = RB_ROOT;

    q->elevator = eq;

    return 0;
}

static void ioem_exit_sched(struct elevator_queue *e)
{
    struct ioem_data *data = e->elevator_data;
    kfree(data);
}

static int ioem_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
    struct ioem_hctx_data *ihd;

    ihd = kmalloc_node(sizeof(*ihd), GFP_KERNEL, hctx->numa_node);
    if (!ihd)
        return -ENOMEM;
    
    hrtimer_init(&ihd->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED);
    ihd->timer.function = ioem_timer;
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

static struct request* ioem_peek_request(struct ioem_data *data)
{
    struct request* ioem_rq = rq_rb_first(&data->root);

    return ioem_rq;
}

static void ioem_erase_head(struct ioem_data *data, struct request *rq)
{
    rb_erase(&rq->rb_node, &data->root);
}

struct request* ioem_dispatch_request(struct blk_mq_hw_ctx * hctx)
{
    struct ioem_hctx_data *ihd = hctx->sched_data;
    struct request *rq = NULL;
    struct request_queue *q = hctx->queue;
    struct ioem_data *data = q->elevator->elevator_data;

    spin_lock(&data->lock);
    if (!RB_EMPTY_ROOT(&data->root)) {
        u64 now;

        rq = ioem_peek_request(data);

        now = ktime_get_ns();
        if (ioem_priv(rq)->time_to_send < now) {
            ioem_erase_head(data, rq);
        } else {
            hrtimer_start(&ihd->timer, ioem_priv(rq)->time_to_send, HRTIMER_MODE_ABS_PINNED);
            rq = NULL;
        }

        #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0))
        atomic_dec(&hctx->elevator_queued);
        #endif
    }
    spin_unlock(&data->lock);

    return rq;
}

static void ioem_insert_requests(struct blk_mq_hw_ctx * hctx, struct list_head * list, bool at_head) 
{
    struct request_queue *q = hctx->queue;
    struct ioem_data *data = q->elevator->elevator_data;

    spin_lock(&data->lock);
    while (!list_empty(list)) {
        struct request *rq;

        rq = list_first_entry(list, struct request, queuelist);
        list_del_init(&rq->queuelist);

        ioem_priv(rq)->time_to_send = ktime_get_ns();
        ioem_enqueue(data, rq);

        #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0))
        atomic_inc(&hctx->elevator_queued);
        #endif
    }
    spin_unlock(&data->lock);
}

static bool has_work(struct blk_mq_hw_ctx * hctx)
{
    struct request_queue *q = hctx->queue;
    struct ioem_data *data = q->elevator->elevator_data;
    bool has_work = 0;

    spin_lock(&data->lock);
    has_work = !RB_EMPTY_ROOT(&data->root);
    spin_unlock(&data->lock);

    return has_work;
}

static struct elevator_type ioem = {
    .ops = {
        .init_sched = ioem_init_sched,
        .init_hctx = ioem_init_hctx,
        .exit_sched = ioem_exit_sched,
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
