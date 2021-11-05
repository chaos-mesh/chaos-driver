#include <linux/errno.h>
#include <linux/types.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include "config.h"
#include "bio_injection.h"
#include "syscall_tracepoint.h"
#include "comp.h"
#include "protocol.h"

struct bio_injection
{
    dev_t dev;

    void *injector_args;
    void (*injector)(void *);
};

struct bio_injection_executor_node
{
    __u32 id;

    // manually simulate closure
    struct bio_injection injection;

    struct list_head list;
};

struct bio_injector_delay_args {
    __u64 delay;
}__attribute__((packed));

TRACEPOINT_PROBE(block_bio_queue_probe, struct bio* bio);

int register_block_bio_queue_tracepoint_executor(void);

int bio_injection_executor_add(struct bio_injection_executor_node executor);

int should_inject_file(int fd, struct bio_injection_executor_node *e);

void bio_injector_delay(void *args);

long build_bio_injection(unsigned long id, struct chaos_injection *injection_request)
{
    int ret = 0;
    struct bio_injection injection;
    struct bio_injection_parameter argument;
    struct bio_injection_executor_node node;
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
    case BIO_INJECTOR_TYPE_DELAY:
        injection.injector_args = injector_args;
        injection.injector = bio_injector_delay;
        break;
    default:
        ret = EINVAL;
        goto free_arg;
        break;
    }

    node.injection = injection;
    node.id = id;
    return bio_injection_executor_add(node);

free_arg:
    kfree(injector_args);
    return ret;
}

static LIST_HEAD(bio_injection_executor_list);
static DEFINE_RWLOCK(bio_injection_executor_list_lock);

// This variable is protected by the `bio_injection_executor_list_lock`
__u32 bio_tracepoint_registered = 0;

struct tracepoint *tp_block_bio_queue;
void bio_visit_tracepoint(struct tracepoint *tp, void *priv)
{
    if (!strcmp(tp->name, "block_bio_queue"))
    {
        tp_block_bio_queue = tp;
    }
}

int register_block_bio_queue_tracepoint(void)
{
    int ret = 0;

    iter_tp(bio_visit_tracepoint, NULL);

    if (tp_block_bio_queue != NULL)
    {
        ret = compat_register_trace(block_bio_queue_probe, "block_bio_queue", tp_block_bio_queue);
        if (ret != 0)
        {
            return ret;
        }

        pr_info(MODULE_NAME ": block_bio_queue tracepoint registered");
        // the tracepoint has been registered successfully
        bio_tracepoint_registered = 1;
        return 0;
    }

    // fail to find the block_bio_queue tracepoint
    return ENOENT;
}

int bio_injection_executor_add(struct bio_injection_executor_node executor)
{
    int ret = 0;
    struct bio_injection_executor_node *node;

    pr_info("adding bio injection(%d)\n", executor.id);

    write_lock(&bio_injection_executor_list_lock);

    // lazily create the list and register tracepoint
    if (bio_tracepoint_registered == 0)
    {
        ret = register_block_bio_queue_tracepoint();
        if (ret != 0)
        {
            pr_err(MODULE_NAME ": err(%d), fail to register tracepoint\n", ret);
            goto release;
        }
    }

    // allocate the executors node and add it to the existing link list
    node = kmalloc(sizeof(struct bio_injection_executor_node), GFP_KERNEL);
    if (node == NULL)
    {
        ret = ENOMEM;
        goto release;
    }
    *node = executor;
    INIT_LIST_HEAD(&node->list);

    list_add_tail(&node->list, &bio_injection_executor_list);

    pr_info("executor(%d) added\n", executor.id);
release:
    write_unlock(&bio_injection_executor_list_lock);
    return ret;
}

void bio_free_node(struct bio_injection_executor_node *e)
{
    if (e->injection.injector_args != NULL)
    {
        kfree(e->injection.injector_args);
    }
    kfree(e);
}

int bio_injection_executor_del(unsigned long id)
{
    int ret = 0;
    struct bio_injection_executor_node *e;
    struct bio_injection_executor_node *tmp;

    write_lock(&bio_injection_executor_list_lock);

    list_for_each_entry_safe(e, tmp, &bio_injection_executor_list, list)
    {
        if (e->id == id)
        {
            list_del(&e->list);
            bio_free_node(e);
            goto release;
        }
    }

    ret = ENOENT;

release:
    if (ret == 0 && list_empty(&bio_injection_executor_list) && bio_tracepoint_registered)
    {
        compat_unregister_trace(block_bio_queue_probe, "block_bio_queue", tp_block_bio_queue);
    }

    write_unlock(&bio_injection_executor_list_lock);
    return ret;
}

int bio_injection_executor_free_all(void)
{
    int ret = 0;
    struct bio_injection_executor_node *e;
    struct bio_injection_executor_node *tmp;

    write_lock(&bio_injection_executor_list_lock);

    list_for_each_entry_safe(e, tmp, &bio_injection_executor_list, list)
    {
        list_del(&e->list);
        kfree(e);
    }

    // if the tracepoint is not empty, it should be unregistered.
    if (bio_tracepoint_registered)
    {
        compat_unregister_trace(block_bio_queue_probe, "block_bio_queue", tp_block_bio_queue);
    }

    write_unlock(&bio_injection_executor_list_lock);
    return ret;
}

void bio_injector_delay(void *args)
{
    struct bio_injector_delay_args *delay_args = args;
    mdelay(delay_args->delay);
}

TRACEPOINT_PROBE(block_bio_queue_probe, struct bio* bio)
{
    struct bio_injection_executor_node *e;

    read_lock(&bio_injection_executor_list_lock);

    list_for_each_entry(e, &bio_injection_executor_list, list)
    {
        if (e->injection.dev != 0 && bio->bi_bdev->bd_dev != e->injection.dev) {
            continue;
        }

        e->injection.injector(e->injection.injector_args);
    }

    read_unlock(&bio_injection_executor_list_lock);
}