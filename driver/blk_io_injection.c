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

int register_blk_io_kprobe(void);

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

static LIST_HEAD(blk_io_injection_executor_list);
static DEFINE_RWLOCK(blk_io_injection_executor_list_lock);

// This variable is protected by the `blk_io_injection_executor_list_lock`
__u32 blk_io_kprobe_registered = 0;

static struct kprobe blk_io_kprobe = {
    .symbol_name = "blk_account_io_start",
    .pre_handler = blk_io_complete_probe,
};

int register_blk_io_kprobe(void)
{
    int ret = 0;

    ret = register_kprobe(&blk_io_kprobe);
    if (ret != 0) {
        return ret;
    }

    blk_io_kprobe_registered = 1;
    return 0;
}

int blk_io_injection_executor_add(struct blk_io_injection_executor_node executor)
{
    int ret = 0;
    struct blk_io_injection_executor_node *node;

    pr_info("adding blk io injection(%d)\n", executor.id);

    write_lock(&blk_io_injection_executor_list_lock);

    // lazily create the list and register kprobe
    if (blk_io_kprobe_registered == 0)
    {
        ret = register_blk_io_kprobe();
        if (ret != 0)
        {
            pr_err(MODULE_NAME ": err(%d), fail to register kprobe\n", ret);
            goto release;
        }
    }

    // allocate the executors node and add it to the existing link list
    node = kmalloc(sizeof(struct blk_io_injection_executor_node), GFP_KERNEL);
    if (node == NULL)
    {
        ret = ENOMEM;
        goto release;
    }
    *node = executor;
    INIT_LIST_HEAD(&node->list);

    list_add_tail(&node->list, &blk_io_injection_executor_list);

    pr_info("executor(%d) added\n", executor.id);
release:
    write_unlock(&blk_io_injection_executor_list_lock);
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

    write_lock(&blk_io_injection_executor_list_lock);

    list_for_each_entry_safe(e, tmp, &blk_io_injection_executor_list, list)
    {
        if (e->id == id)
        {
            list_del(&e->list);
            blk_io_free_node(e);
            goto release;
        }
    }

    ret = ENOENT;

release:
    if (ret == 0 && list_empty(&blk_io_injection_executor_list) && blk_io_kprobe_registered)
    {
        unregister_kprobe(&blk_io_kprobe);
    }

    write_unlock(&blk_io_injection_executor_list_lock);
    return ret;
}

int blk_io_injection_executor_free_all(void)
{
    int ret = 0;
    struct blk_io_injection_executor_node *e;
    struct blk_io_injection_executor_node *tmp;

    write_lock(&blk_io_injection_executor_list_lock);

    list_for_each_entry_safe(e, tmp, &blk_io_injection_executor_list, list)
    {
        list_del(&e->list);
        kfree(e);
    }

    // if the kprobe is not empty, it should be unregistered.
    if (blk_io_kprobe_registered)
    {
        unregister_kprobe(&blk_io_kprobe);
    }

    write_unlock(&blk_io_injection_executor_list_lock);
    return ret;
}

void blk_io_injector_delay(void *args)
{
    struct blk_io_injector_delay_args *delay_args = args;
    mdelay(delay_args->delay);
}

int blk_io_complete_probe(struct kprobe *p, struct pt_regs *regs)
{
    struct blk_io_injection_executor_node *e;
    struct request* req;

    read_lock(&blk_io_injection_executor_list_lock);

    list_for_each_entry(e, &blk_io_injection_executor_list, list)
    {
        req = (struct request*)compat_regs_get_kernel_argument(regs, 0);

        if (e->injection.dev != 0 && (req->bio != NULL && req->bio->bi_bdev != NULL && req->bio->bi_bdev->bd_dev != e->injection.dev)) {
            continue;
        }

        e->injection.injector(e->injection.injector_args);
    }

    read_unlock(&blk_io_injection_executor_list_lock);

    return 0;
}
