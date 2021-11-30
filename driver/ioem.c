#include <linux/elevator.h>
#include <linux/blkdev.h>

#include "ioem.h"

static int ioem_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	blk_stat_enable_accounting(q);

	q->elevator = eq;

	return 0;
}

struct request* ioem_dispatch_request(struct blk_mq_hw_ctx * hctx)
{
	return NULL;
}

static void ioem_insert_requests(struct blk_mq_hw_ctx * hctx, struct list_head * list, bool at_head) 
{

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