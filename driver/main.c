// Copyright 2021 Chaos Mesh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// See the License for the specific language governing permissions and
// limitations under the License.

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/device.h>

#include <linux/delay.h>
#include <linux/fdtable.h>

#include "config.h"
#include "chaos_device.h"
#include "syscall_tracepoint.h"

// this is a simple example for tracepoint executor.
// these logic should be refined to meet the real requirements.
void executor(void *_, struct pt_regs *regs, long ret)
{
    struct path *path;
    struct files_struct *files;
    struct file *opened_file;
    char *full_path;
    char *buf;

    int id = syscall_get_nr(current, regs);
    if ((id == __NR_openat || id == __NR_open) && ret > 0)
    {

        files = current->files;
        opened_file = files_lookup_fd_rcu(files, ret);
        if (opened_file == NULL)
        {
            goto exit;
        }

        buf = (char *)get_zeroed_page(GFP_KERNEL);
        if (buf == NULL)
        {
            printk(KERN_ERR "fail to allocate page");
            goto exit_put_path;
        }

        path = &opened_file->f_path;
        if (path == NULL)
        {
            printk(KERN_INFO "path is NULL %d %ld", current->pid, ret);
            goto exit_free_page;
        }
        path_get(path);
        if (path->dentry == NULL)
        {
            printk(KERN_INFO "path->dentry is NULL %d %ld", current->pid, ret);
            goto exit_put_path;
        }

        full_path = d_path(path, buf, PAGE_SIZE);
        if (IS_ERR(full_path))
        {
            printk(KERN_ERR "fail to get full_path");
            goto exit_put_path;
        }

        if (full_path == NULL)
        {
            goto exit_put_path;
        }

        if (strstr(full_path, "test-chaos") != NULL)
        {
            printk(KERN_INFO "%s OPENAT(_, %s, _) -> %ld \n", current->comm, full_path, ret);
            mdelay(10);
        }

    exit_put_path:
        path_put(path);
    exit_free_page:
        free_page((unsigned long)buf);
    exit:
        return;
    }
}

static int __init chaos_main(void)
{
    // Return value of the function
    int ret = 0;
    struct tracepoint_executor test_executor;

    pr_info(MODULE_NAME " is loading \n");

    ret = register_chaos_device();
    if (ret < 0)
    {
        pr_err(MODULE_NAME ": register_chaos_device failed \n");
        goto err;
    }

    test_executor.id = 1;
    test_executor.executor = executor;
    test_executor.context = NULL;
    executor_add(test_executor);

err:
    return ret;
}
static void __exit chaos_exit(void)
{
    pr_info(MODULE_NAME " is unloading \n");

    executor_free_all();
    unregister_chaos_device();
}

module_init(chaos_main);
module_exit(chaos_exit);

MODULE_LICENSE("GPL");
