#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/tracepoint.h>
#include <asm/syscall.h>

#ifndef SYSCALL_TRACEPOINT_H
#define SYSCALL_TRACEPOINT_H

#define TRACEPOINT_PROBE(probe, args...) static void __attribute__((optimize("O0"))) probe(void *__data, args)

struct tracepoint_executor
{
    __u32 id;

    // manually simulate closure
    void *context;
    // the first argument of this function is the context
    void (*executor)(void *, struct pt_regs *regs, long ret);
};

int syscall_tracepoint_executor_add(struct tracepoint_executor executor);
int syscall_tracepoint_executor_del(__u32 id);
int syscall_tracepoint_executor_free_all(void);

enum executor_id
{
    EXECUTOR_ID_FS_INJECTION = 0,
};

#endif