#include "protocol.h"

#ifndef FS_INJECTION_H
#define FS_INJECTION_H

long build_fs_syscall_injection(unsigned long id, struct chaos_injection *injection);
int fs_injection_executor_del(unsigned long id);

struct fs_syscall_injection_parameter
{
    int folder;
    __u8 recursive;

    __u64 syscall;

    pid_t pid;
} __attribute__((packed));

enum injector_type
{
    INJECTOR_TYPE_DELAY = 0,
};

#endif
