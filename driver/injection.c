#include <linux/errno.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/uaccess.h>

#include "injection.h"

long inject(struct chaos_injection *injection)
{
    switch (injection->matcher_type)
    {
    case MATCHER_TYPE_FS_SYSCALL:
        return build_fs_syscall_injection(injection);
        break;

    default:
        break;
    }
    return 0;
}

struct fs_syscall_injection
{
    char *path;

    __u8 recursive;

    pid_t pid;
};
long build_fs_syscall_injection(struct chaos_injection *injection)
{
    struct fs_syscall_injection_parameter argument;

    if (copy_from_user(&argument, injection->matcher_arg, injection->matcher_arg_size))
    {
        return -EINVAL;
    };
    return 0;
}