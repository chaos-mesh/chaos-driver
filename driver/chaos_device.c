#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include "config.h"
#include "chaos_device.h"
#include "protocol.h"
#include "injection.h"

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
    return 0;
}

int chaos_char_device_release(struct inode *inode, struct file *filp)
{
    return 0;
}

long chaos_char_device_ioctl(struct file *flip, unsigned int cmd, unsigned long arg)
{
    unsigned long ret = 0, err = 0;
    union
    {
        struct chaos_injection injection;
    } kernel_parameter;

    switch (cmd)
    {
    case GET_VERSION:
        return MODULE_PROTOCOL_VERSION;
        break;
    case ADD_INJECTION:
        if (copy_from_user(&kernel_parameter.injection, (void *)arg, sizeof(struct chaos_injection)))
        {
            ret = -EINVAL;
            return ret;
        }
        err = inject(&kernel_parameter.injection, &ret);
        if (err != 0) {
            ret = -err;
            return ret;
        }

        return ret;

        break;
    case DELETE_INJECTION:
        ret = recover(arg);

        return ret;

        break;
    default:
        break;
    }

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

    // create device node
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