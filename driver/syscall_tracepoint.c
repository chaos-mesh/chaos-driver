#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include "config.h"
#include "syscall_tracepoint.h"
#include "comp.h"
#include "lazy_list.h"

int register_syscall_tracepoint(struct lazy_list* l);
int unregister_syscall_tracepoint(struct lazy_list* l);

LAZY_LIST_DEFINE(syscall_tracepoint_list, register_syscall_tracepoint, unregister_syscall_tracepoint);

struct tracepoint *tp_sys_exit;

void syscall_visit_tracepoint(struct tracepoint *tp, void *priv)
{
    if (!strcmp(tp->name, "sys_exit"))
    {
        tp_sys_exit = tp;
    }
}

TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret);
int register_syscall_tracepoint(struct lazy_list* l)
{
    int ret = 0;

    iter_tp(syscall_visit_tracepoint, NULL);

    if (tp_sys_exit != NULL)
    {
        ret = compat_register_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
        if (ret != 0)
        {
            return ret;
        }

        pr_info(MODULE_NAME ": tracepoint registered");
        // the tracepoint has been registered successfully
        l->registered = 1;
        return 0;
    }

    // fail to find the sys_exit tracepoint
    return ENOENT;
}

int unregister_syscall_tracepoint(struct lazy_list* l)
{
    int ret = 0;

    ret = compat_unregister_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
    if (ret != 0) {
        return ret;
    }

    l->registered = 0;
    return ret;
}

struct executor_list_node
{
    struct tracepoint_executor executor;

    struct list_head list;
};

int syscall_tracepoint_executor_add(struct tracepoint_executor executor)
{
    int ret = 0;
    struct executor_list_node *node;

    node = kmalloc(sizeof(struct executor_list_node), GFP_KERNEL);
    if (node == NULL)
    {
        return ENOMEM;
    }
    
    INIT_LIST_HEAD(&node->list);
    node->executor = executor;

    ret = lazy_list_add_tail(&node->list, &syscall_tracepoint_list);
    if (ret != 0) 
    {
        kfree(node);
    }

    return ret;
}

inline void syscall_tracepoint_executor_node_drop(struct executor_list_node *e) {
    if (e->executor.context != NULL)
    {
        kfree(e->executor.context);
    }
    kfree(e);
}

int syscall_tracepoint_executor_del(__u32 id)
{
    int ret = 0;
    struct executor_list_node *e;
    struct executor_list_node *tmp;

    lazy_list_delete(&syscall_tracepoint_list, e, tmp, e->executor.id == id, syscall_tracepoint_executor_node_drop(e), list);

    return ret;
}

int syscall_tracepoint_executor_free_all(void)
{
    int ret = 0;
    struct executor_list_node *e;
    struct executor_list_node *tmp;

    lazy_list_delete_all(&syscall_tracepoint_list, e, tmp, syscall_tracepoint_executor_node_drop(e), list);

    return ret;
}

TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret)
{
    struct executor_list_node *e;

    lazy_list_for_each_entry(&syscall_tracepoint_list, e,e->executor.executor(e->executor.context, regs, ret), list);
}