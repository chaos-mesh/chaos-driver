#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/spinlock.h>
#include <linux/version.h>

#include "ioem.h"

struct ioem_data {
    struct list_head only_list;

    spinlock_t lock;
};

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
    INIT_LIST_HEAD(&data->only_list);

    q->elevator = eq;

    return 0;
}

struct request* ioem_dispatch_request(struct blk_mq_hw_ctx * hctx)
{
    struct request_queue *q = hctx->queue;
    struct ioem_data *data = q->elevator->elevator_data;

    spin_lock(&data->lock);
    if (!list_empty(&data->only_list)) {
        struct request *rq;

        rq = list_first_entry(&data->only_list, struct request, queuelist);
        list_del_init(&rq->queuelist);

        #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0))
        atomic_dec(&hctx->elevator_queued);
        #endif

        return rq;

    }
    spin_unlock(&data->lock);

    return NULL;
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

        list_add_tail(&rq->queuelist, &data->only_list);

        #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0))
        atomic_inc(&hctx->elevator_queued);
        #endif
    }
    spin_unlock(&data->lock);
}

static struct elevator_type ioem = {
    .ops = {
        .init_sched = ioem_init_sched,
        .insert_requests = ioem_insert_requests,
        .dispatch_request = ioem_dispatch_request,
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
