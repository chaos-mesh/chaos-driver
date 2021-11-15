#include <linux/errno.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/kprobes.h>
#include <linux/blkdev.h>

#include "config.h"
#include "blk_io_injection.h"
#include "protocol.h"
#include "comp.h"
#include "lazy_list.h"

struct blk_io_injection
{
    dev_t dev;

    void *injector_args;
    void (*injector)(void *);
};

struct blk_io_injection_executor_node
{
    __u32 id;

    // manually simulate closure
    struct blk_io_injection injection;

    struct list_head list;
};

struct blk_io_injector_delay_args {
    __u64 delay;
}__attribute__((packed));

int blk_io_complete_probe(struct kprobe *p, struct pt_regs *regs);

int blk_io_register_kprobe(struct lazy_list* l);
int blk_io_unregister_kprobe(struct lazy_list* l);

LAZY_LIST_DEFINE(blk_io_injection_list, blk_io_register_kprobe, blk_io_unregister_kprobe);

int blk_io_injection_executor_add(struct blk_io_injection_executor_node executor);

int should_inject_file(int fd, struct blk_io_injection_executor_node *e);

void blk_io_injector_delay(void *args);

long build_blk_io_injection(unsigned long id, struct chaos_injection *injection_request)
{
    int ret = 0;
    struct blk_io_injection injection;
    struct blk_io_injection_parameter argument;
    struct blk_io_injection_executor_node node;
    void *injector_args;

    if (copy_from_user(&argument, injection_request->matcher_arg, injection_request->matcher_arg_size))
    {
        return EINVAL;
    };

    injection.dev = argument.dev;

    injector_args = kmalloc(injection_request->injector_arg_size, GFP_KERNEL);
    if (injector_args == NULL)
    {
        return ENOMEM;
    }
    if (copy_from_user(injector_args, injection_request->injector_arg, injection_request->injector_arg_size))
    {
        ret = EINVAL;
        goto free_arg;
    };

    switch (injection_request->injector_type)
    {
    case blk_io_INJECTOR_TYPE_DELAY:
        injection.injector_args = injector_args;
        injection.injector = blk_io_injector_delay;
        break;
    default:
        ret = EINVAL;
        goto free_arg;
        break;
    }

    node.injection = injection;
    node.id = id;
    return blk_io_injection_executor_add(node);

free_arg:
    kfree(injector_args);
    return ret;
}

static struct kprobe blk_io_kprobe = {
    .symbol_name = "blk_account_io_start",
    .pre_handler = blk_io_complete_probe,
};

int blk_io_register_kprobe(struct lazy_list* l)
{
    int ret = 0;

    ret = register_kprobe(&blk_io_kprobe);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int blk_io_unregister_kprobe(struct lazy_list* l)
{
    unregister_kprobe(&blk_io_kprobe);

    return 0;
}

int blk_io_injection_executor_add(struct blk_io_injection_executor_node executor)
{
    int ret = 0;
    struct blk_io_injection_executor_node *node;

    // allocate the executors node and add it to the existing link list
    node = kmalloc(sizeof(struct blk_io_injection_executor_node), GFP_KERNEL);
    if (node == NULL)
    {
        return ENOMEM;
    }
    *node = executor;
    INIT_LIST_HEAD(&node->list);

    ret = lazy_list_add_tail(&node->list, &blk_io_injection_list);
    if (ret != 0) 
    {
        kfree(node);
    }

    return ret;
}

void blk_io_free_node(struct blk_io_injection_executor_node *e)
{
    if (e->injection.injector_args != NULL)
    {
        kfree(e->injection.injector_args);
    }
    kfree(e);
}

int blk_io_injection_executor_del(unsigned long id)
{
     int ret = 0;
    struct blk_io_injection_executor_node *e;
    struct blk_io_injection_executor_node *tmp;

    lazy_list_delete(&blk_io_injection_list, e, tmp, e->id == id, blk_io_free_node(e), list);

    return ret;
}

int blk_io_injection_executor_free_all(void)
{
    int ret = 0;
    struct blk_io_injection_executor_node *e;
    struct blk_io_injection_executor_node *tmp;

    lazy_list_delete_all(&blk_io_injection_list, e, tmp, blk_io_free_node(e), list);

    return ret;
}

void blk_io_injector_delay(void *args)
{
    struct blk_io_injector_delay_args *delay_args = args;
    udelay(delay_args->delay);
}

inline void blk_io_inject(struct blk_io_injection_executor_node *e, struct pt_regs *regs)
{
    struct request* req;
    req = (struct request*)compat_regs_get_kernel_argument(regs, 0);

    if (e->injection.dev != 0 && (req->bio != NULL && req->bio->bi_bdev != NULL && req->bio->bi_bdev->bd_dev != e->injection.dev)) {
        return;
    }

    e->injection.injector(e->injection.injector_args);
}

int blk_io_complete_probe(struct kprobe *p, struct pt_regs *regs)
{
    struct blk_io_injection_executor_node *e;

    lazy_list_for_each_entry(&blk_io_injection_list, e, blk_io_inject(e, regs), list);

    return 0;
}
