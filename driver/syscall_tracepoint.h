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

    void *context;
    void (*executor)(void *, struct pt_regs *regs, long ret);
};

int executor_add(struct tracepoint_executor executor);
int executor_del(__u32 id);
int executor_free_all(void);

#endif