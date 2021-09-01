#include <linux/spinlock.h>
#include <linux/slab.h>

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

struct executor_list_node *executors;
DEFINE_RWLOCK(executor_list_lock);

int executor_add(struct tracepoint_executor executor)
{
    int ret = 0;
    struct executor_list_node *node;

    write_lock(&executor_list_lock);

    // lazily create the list and register tracepoint
    if (tracepoint_registered == 0)
    {
        ret = register_syscall_tracepoint();
        if (ret != 0)
        {
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

    write_lock(&executor_list_lock);
    if (executors == NULL)
    {
        executors = node;
    }
    else
    {
        list_add_tail(&node->list, &executors->list);
    }

release:
    write_unlock(&executor_list_lock);
    return ret;
}

int executor_del(__u32 id)
{
    int ret = 0;
    struct executor_list_node *e;

    write_lock(&executor_list_lock);

    if (executors == NULL)
    {
        ret = ENOENT;
        goto release;
    }

    // if the list is empty, which means it has only one object, if it's deleted, we should free it
    if (list_empty(&executors->list))
    {
        if (id == executors->executor.id)
        {
            kfree(executors);
            executors = NULL;

            // if the tracepoint is not empty, it should be unregistered.
            if (tracepoint_registered)
            {
                ret = tracepoint_probe_unregister(tp_sys_exit, syscall_exit_probe, NULL);
                goto release;
            }
        }
        else
        {
            ret = ENOENT;
            goto release;
        }
    }

    list_for_each_entry(e, &executors->list, list)
    {
        if (e->executor.id == id)
        {
            list_del(&e->list);
            kfree(e);
            goto release;
        }
    }

    ret = ENOENT;

release:
    write_unlock(&executor_list_lock);
    return ret;
}

int executor_free_all(void)
{
    int ret = 0;
    struct executor_list_node *e;

    write_lock(&executor_list_lock);

    if (executors == NULL)
    {
        goto release;
    }

    list_for_each_entry(e, &executors->list, list)
    {
        list_del(&e->list);
        kfree(e);
    }

    // if the tracepoint is not empty, it should be unregistered.
    if (tracepoint_registered)
    {
        ret = tracepoint_probe_unregister(tp_sys_exit, syscall_exit_probe, NULL);
    }

release:
    write_unlock(&executor_list_lock);
    return ret;
}

TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret)
{
    struct executor_list_node *e;

    read_lock(&executor_list_lock);

    if (executors == NULL)
    {
        return;
    }

    list_for_each_entry(e, &executors->list, list)
    {
        e->executor.executor(e->executor.context, regs, ret);
    }

    read_unlock(&executor_list_lock);
}