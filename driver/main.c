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

struct elevator_queue;
struct request;

#include <linux/elevator.h>

#include "config.h"
#include "chaos_device.h"
#include "injection.h"
#include "ioem.h"

static int __init chaos_main(void)
{
    // Return value of the function
    int ret = 0;

    pr_info(MODULE_NAME " is loading \n");

    ret = register_chaos_device();
    if (ret < 0)
    {
        pr_err(MODULE_NAME ": register_chaos_device failed \n");
        goto err;
    }

    ret = ioem_register();
    if (ret < 0)
    {
        pr_err(MODULE_NAME ": register_chaos_device failed \n");
        goto err;
    }
err:
    return ret;
}
static void __exit chaos_exit(void)
{
    int ret = 0;
    pr_info(MODULE_NAME " is unloading \n");

    ret = recover_all();
    if (ret != 0)
    {
        pr_err(MODULE_NAME ": fail to recover all injection\n");
    }
    unregister_chaos_device();

    ioem_unregister();
}

module_init(chaos_main);
module_exit(chaos_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chaos Mesh Authors");
MODULE_DESCRIPTION("Injection delay or errors into the system");