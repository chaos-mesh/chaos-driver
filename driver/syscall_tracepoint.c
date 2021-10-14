#include <linux/spinlock.h>
#include <linux/slab.h>

#include <linux/delay.h>

#include "config.h"
#include "syscall_tracepoint.h"

__u32 tracepoint_registered = 0;
struct tracepoint *tp_sys_exit;

void visit_tracepoint(struct tracepoint *tp, void *priv)
{
    if (!strcmp(tp->name, "sys_exit"))
    {
        tp_sys_exit = tp;
    }
}

TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret);
int register_syscall_tracepoint(void)
{
    int ret = 0;

    for_each_kernel_tracepoint(visit_tracepoint, NULL);

    if (tp_sys_exit != NULL)
    {
        ret = tracepoint_probe_register(tp_sys_exit, syscall_exit_probe, NULL);
        if (ret != 0)
        {
            return ret;
        }

        pr_info(MODULE_NAME ": tracepoint registered");
        // the tracepoint has been registered successfully
        tracepoint_registered = 1;
        return 0;
    }

    // fail to find the sys_exit tracepoint
    return ENOENT;
}
struct executor_list_node
{
    struct tracepoint_executor executor;

    struct list_head list;
};

static LIST_HEAD(syscall_tracepoint_executor_list);
static DEFINE_RWLOCK(syscall_tracepoint_executor_list_lock);

int syscall_tracepoint_executor_add(struct tracepoint_executor executor)
{
    int ret = 0;
    struct executor_list_node *node;

    write_lock(&syscall_tracepoint_executor_list_lock);

    // lazily create the list and register tracepoint
    if (tracepoint_registered == 0)
    {
        ret = register_syscall_tracepoint();
        if (ret != 0)
        {
            pr_err(MODULE_NAME ": err(%d), fail to register tracepoint\n", ret);
            goto release;
        }
    }

    // allocate the executors node and add it to the existing link list
    node = kmalloc(sizeof(struct executor_list_node), GFP_KERNEL);
    if (node == NULL)
    {
        ret = ENOMEM;
        goto release;
    }
    INIT_LIST_HEAD(&node->list);
    node->executor = executor;

    list_add_tail(&node->list, &syscall_tracepoint_executor_list);

release:
    write_unlock(&syscall_tracepoint_executor_list_lock);
    return ret;
}

int syscall_tracepoint_executor_del(__u32 id)
{
    int ret = 0;
    struct executor_list_node *e;
    struct executor_list_node *tmp;

    write_lock(&syscall_tracepoint_executor_list_lock);

    list_for_each_entry_safe(e, tmp, &syscall_tracepoint_executor_list, list)
    {
        if (e->executor.id == id)
        {
            list_del(&e->list);
            if (e->executor.context != NULL)
            {
                kfree(e->executor.context);
            }
            kfree(e);
            goto release;
        }
    }

    ret = ENOENT;

release:
    if (ret == 0 && list_empty(&syscall_tracepoint_executor_list) && tracepoint_registered)
    {
        ret = tracepoint_probe_unregister(tp_sys_exit, syscall_exit_probe, NULL);
        if (ret == 0)
        {
            tracepoint_registered = 0;
        }
    }

    write_unlock(&syscall_tracepoint_executor_list_lock);
    return ret;
}

int syscall_tracepoint_executor_free_all(void)
{
    int ret = 0;
    struct executor_list_node *e;
    struct executor_list_node *tmp;

    write_lock(&syscall_tracepoint_executor_list_lock);

    list_for_each_entry_safe(e, tmp, &syscall_tracepoint_executor_list, list)
    {
        list_del(&e->list);
        if (e->executor.context != NULL)
        {
            kfree(e->executor.context);
        }
        kfree(e);
    }

    // if the tracepoint is not empty, it should be unregistered.
    if (tracepoint_registered)
    {
        ret = tracepoint_probe_unregister(tp_sys_exit, syscall_exit_probe, NULL);
        if (ret == 0)
        {
            tracepoint_registered = 0;
        }
    }

    write_unlock(&syscall_tracepoint_executor_list_lock);
    return ret;
}

TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret)
{
    struct executor_list_node *e;

    read_lock(&syscall_tracepoint_executor_list_lock);

    list_for_each_entry(e, &syscall_tracepoint_executor_list, list)
    {
        e->executor.executor(e->executor.context, regs, ret);
    }

    read_unlock(&syscall_tracepoint_executor_list_lock);
}