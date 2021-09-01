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
#include <linux/cdev.h>
#include <linux/slab.h>
#include "./config.h"
#include "./chaos_device.h"

int chaos_char_device_open(struct inode *inode, struct file *filp)
{
    return 0;
}

ssize_t chaos_char_device_read(struct file *flip, char __user *content, size_t length, loff_t *offset)
{
    return 0;
}

ssize_t chaos_char_device_write(struct file *flip, const char __user *user_content, size_t length, loff_t *offset)
{
    int ret = 0;
    char *content;

    content = kmalloc(length, GFP_KERNEL);
    if (copy_from_user(content, user_content, length))
    {
        ret = -EINVAL;
        goto cleanup_content;
    }
    pr_info(MODULE_NAME ": write %.*s\n", (int)length, content);
    ret = (int)length;

cleanup_content:
    kfree(content);
    return ret;
}

int chaos_char_device_release(struct inode *inode, struct file *filp)
{
    return 0;
}

long chaos_char_device_ioctl(struct file *flip, unsigned int cmd, unsigned long arg)
{
    return 0;
}

struct file_operations fops = {
    .read = chaos_char_device_read,
    .write = chaos_char_device_write,
    .open = chaos_char_device_open,
    .release = chaos_char_device_release,
    .unlocked_ioctl = chaos_char_device_ioctl};

// Return value of alloc_chrdev_region
int acrret = 0;

// The device handler of the char device
dev_t dev;
// The class of char device
struct class *chrdev_class = NULL;
// The char device
struct cdev cdev;
struct device *device = NULL;

int register_chaos_device()
{
    // Return value of the function
    int ret;
    int device_created = 0;

    acrret = alloc_chrdev_region(&dev, 0, 1, MODULE_DEVICE_NAME);
    if (acrret < 0)
    {
        pr_err(MODULE_NAME ": could not allocate major number for %s\n", MODULE_DEVICE_NAME);
        ret = -ENOMEM;
        goto err;
    }

    chrdev_class = class_create(THIS_MODULE, MODULE_DEVICE_NAME);
    if (IS_ERR(chrdev_class))
    {
        pr_err(MODULE_NAME ": fail to allocate char device class\n");
        ret = -EFAULT;
        goto err;
    }

    cdev_init(&cdev, &fops);
    cdev.owner = THIS_MODULE;
    if (cdev_add(&cdev, dev, 1) < 0)
    {
        pr_err("could not allocate chrdev for %s\n", MODULE_DEVICE_NAME);
        ret = -EFAULT;
        goto err;
    }

    // create device node /dev/mychardev-x where "x" is "i", equal to the Minor number
    device = device_create(chrdev_class, NULL, dev, NULL, MODULE_DEVICE_NAME);
    if (IS_ERR(device))
    {
        pr_err("error creating the device for  %s\n", MODULE_DEVICE_NAME);
        cdev_del(&cdev);
        ret = -EFAULT;
        goto err;
    }
    device_created = 1;

    return 0;

err:
    if (device_created)
    {
        device_destroy(chrdev_class, dev);
    }

    if (chrdev_class)
        class_destroy(chrdev_class);

    if (acrret == 0)
        unregister_chrdev_region(dev, 1);

    return ret;
}

int unregister_chaos_device()
{
    device_destroy(chrdev_class, dev);
    cdev_del(&cdev);

    if (chrdev_class)
        class_destroy(chrdev_class);

    if (acrret == 0)
        unregister_chrdev_region(dev, 1);

    return 0;
}