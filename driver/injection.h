#include "protocol.h"

#ifndef INJECTION_H
#define INJECTION_H

long inject(struct chaos_injection *injection);

long build_fs_syscall_injection(struct chaos_injection *injection);

enum matcher_type
{
    MATCHER_TYPE_FS_SYSCALL = 0,
};

struct fs_syscall_injection_parameter
{
    char __user *path;
    size_t path_len;

    __u8 recursive;

    pid_t pid;
} __attribute__((packed));

#endif