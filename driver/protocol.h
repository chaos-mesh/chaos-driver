#include <linux/ioctl.h>
#include <asm/types.h>
#include <stddef.h>

#ifndef PROTOCOL_H
#define PROTOCOL_H

#define CHAOS_IOCTL_MAGIC 0xC1

#define GET_VERSION_NR 0
#define GET_VERSION _IO(CHAOS_IOCTL_MAGIC, GET_VERSION_NR)

struct chaos_injection
{
    u32 matcher_type;
    void __user *matcher_arg;

    u32 injector_type;
    void __user *injector_arg;
} __attribute__((packed));

#define ADD_INJECTION_NR 1
#define ADD_INJECTION _IOW(CHAOS_IOCTL_MAGIC, ADD_INJECTION_NR, struct chaos_injection)

#define DELETE_INJECTION_NR 2
#define DELETE_INJECTION _IOC(_IOC_WRITE, CHAOS_IOCTL_MAGIC, DELETE_INJECTION_NR, 0x4)

#endif