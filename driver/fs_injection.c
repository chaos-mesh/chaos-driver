#include <linux/errno.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include "config.h"
#include "fs_injection.h"
#include "syscall_tracepoint.h"
#include "protocol.h"
#include "comp.h"
#include "lazy_list.h"

struct fs_syscall_injection
{
    struct file *folder;
    __u8 recursive;

    __u64 syscall;

    pid_t pid;

    void *injector_args;
    void (*injector)(void *, struct pt_regs *regs, long ret);
};

struct fs_injection_executor_node
{
    __u32 id;

    // manually simulate closure
    struct fs_syscall_injection injection;

    struct list_head list;
};

struct fs_injector_delay_args {
    __u64 delay;
}__attribute__((packed));

void fs_injection_executor(void *_, struct pt_regs *regs, long ret);

void injector_delay(void *args, struct pt_regs *regs, long ret);

int fs_injection_executor_add(struct fs_injection_executor_node executor);

int should_inject_file(int fd, struct fs_injection_executor_node *e);

int register_fs_syscall_tracepoint_executor(struct lazy_list* l);
int unregister_fs_syscall_tracepoint_executor(struct lazy_list* l);

LAZY_LIST_DEFINE(fs_injection_list, register_fs_syscall_tracepoint_executor, unregister_fs_syscall_tracepoint_executor);

long build_fs_syscall_injection(unsigned long id, struct chaos_injection *injection_request)
{
    int ret = 0;
    struct files_struct *files;
    struct file *inject_root;
    struct fs_syscall_injection injection;
    struct fs_syscall_injection_parameter argument;
    struct fs_injection_executor_node node;
    void *injector_args;

    if (copy_from_user(&argument, injection_request->matcher_arg, injection_request->matcher_arg_size))
    {
        return EINVAL;
    };

    if (argument.folder != 0)
    {
        files = current->files;

        inject_root = files_lookup_fd(files, argument.folder);
        if (inject_root == NULL)
        {
            return EINVAL;
        }
        get_file(inject_root);

        injection.folder = inject_root;
        injection.recursive = argument.recursive;
    }

    injection.pid = argument.pid;
    injection.syscall = argument.syscall;

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
    case INJECTOR_TYPE_DELAY:
        injection.injector_args = injector_args;
        injection.injector = injector_delay;
        break;
    default:
        ret = EINVAL;
        goto free_arg;
        break;
    }

    node.injection = injection;
    node.id = id;
    return fs_injection_executor_add(node);

free_arg:
    kfree(injector_args);
    return ret;
}

int register_fs_syscall_tracepoint_executor(struct lazy_list* l)
{
    int ret = 0;
    struct tracepoint_executor executor = {
        .id = EXECUTOR_ID_FS_INJECTION,
        .context = NULL,
        .executor = fs_injection_executor,
    };

    ret = syscall_tracepoint_executor_add(executor);
    if (ret != 0)
    {
        goto error;
    }

error:
    return ret;
}

int unregister_fs_syscall_tracepoint_executor(struct lazy_list* l)
{
    return syscall_tracepoint_executor_del(EXECUTOR_ID_FS_INJECTION);
}

int fs_injection_executor_add(struct fs_injection_executor_node executor)
{
    int ret = 0;
    struct fs_injection_executor_node *node;

    // allocate the executors node and add it to the existing link list
    node = kmalloc(sizeof(struct fs_injection_executor_node), GFP_KERNEL);
    if (node == NULL)
    {
        return ENOMEM;
    }
    INIT_LIST_HEAD(&node->list);
    *node = executor;

    ret = lazy_list_add_tail(&node->list, &fs_injection_list);
    if (ret != 0) 
    {
        kfree(node);
    }

    return ret;
}

void fs_injection_node_drop(struct fs_injection_executor_node *e)
{
    if (e->injection.injector_args != NULL)
    {
        kfree(e->injection.injector_args);
    }
    if (e->injection.folder != NULL)
    {
        fput(e->injection.folder);
    }
    kfree(e);
}

int fs_injection_executor_del(unsigned long id)
{
    int ret = 0;
    struct fs_injection_executor_node *e;
    struct fs_injection_executor_node *tmp;

    lazy_list_delete(&fs_injection_list, e, tmp, e->id == id, fs_injection_node_drop(e), list);

    return ret;
}

int fs_injection_executor_free_all(void)
{
    int ret = 0;
    struct fs_injection_executor_node *e;
    struct fs_injection_executor_node *tmp;

    lazy_list_delete_all(&fs_injection_list, e, tmp, fs_injection_node_drop(e), list);

    return ret;
}

inline void fs_injection_execute(struct fs_injection_executor_node* e, struct pt_regs *regs, long ret) {
    unsigned long id = syscall_get_nr(current, regs);
    int fd = 0;

    if ((id == __NR_openat || 
        id == __NR_open || 
        id == __NR_write || 
        id == __NR_read || 
        id == __NR_sendfile || 
        id == __NR_fstat))
    {
        int inject_times = 0;

        if (e->injection.syscall != 0 && e->injection.syscall != id)
        {
            return;
        }

        if (e->injection.pid != 0 && e->injection.pid != current->pid)
        {
            return;
        }

        if (e->injection.folder != NULL) {
            if (id == __NR_openat || id == __NR_open) {
                fd = ret;
            } else {
                fd = (int)regs->di;
            }

            if (should_inject_file(fd, e)) {
                inject_times += 1;
            }

            if (id == __NR_sendfile) {
                // The second argument of sendfile should also be verified
                fd = (int)regs->si;
                if (should_inject_file(fd, e)) {
                    inject_times += 1;
                }
            }
        }

        while(inject_times--) {
            e->injection.injector(e->injection.injector_args, regs, ret);
        }
    }
}

void fs_injection_executor(void *_, struct pt_regs *regs, long ret)
{
    struct fs_injection_executor_node *e;

    lazy_list_for_each_entry(&fs_injection_list, e, fs_injection_execute(e, regs, ret), list);
}

void injector_delay(void *args, struct pt_regs *regs, long ret)
{
    struct fs_injector_delay_args *delay_args = args;
    udelay(delay_args->delay);
}

int should_inject_file(int fd, struct fs_injection_executor_node *e) {
    int should_inject = 0;
    long target_ino = 0;
    // TODO: not only verify the inode, we should also verify the mount
    struct file *opened_file = files_lookup_fd(current->files, fd);


    if (opened_file == NULL) {
        // if the user passed wrong fd and we cannot find the file,
        // we should just ignore
        return 0;
    }

    if (opened_file->f_path.dentry == NULL || opened_file->f_path.dentry->d_inode == NULL) {
        return 0;
    }

    if (e->injection.folder->f_path.dentry == NULL || e->injection.folder->f_path.dentry->d_inode == NULL) {
        return 0;
    }

    target_ino = e->injection.folder->f_path.dentry->d_inode->i_ino;
    if (opened_file->f_path.dentry->d_inode->i_ino == target_ino) {
        should_inject = 1;
    } else if (e->injection.recursive) {
        struct dentry *parent = opened_file->f_path.dentry;

        while (parent != NULL) {
            long last_ino = 0;

            if (parent->d_inode == NULL) {
                break;
            }

            if (parent->d_inode->i_ino == target_ino) {
                should_inject = 1;
                break;
            }

            last_ino = parent->d_inode->i_ino;
            parent = parent->d_parent;

            if (parent->d_inode == NULL) {
                break;
            }
            if (parent->d_inode->i_ino == last_ino) {
                break;
            }
        }
    }

    return should_inject;
}