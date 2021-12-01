#include <linux/errno.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include "injection.h"
#include "ioem.h"

static atomic_long_t injection_id = ATOMIC_LONG_INIT(0);

unsigned long get_id()
{
    return atomic_long_add_return(1, &injection_id);
}

struct injection_node
{
    unsigned long id;
    int (*del)(unsigned long id);

    struct list_head list;
};
static LIST_HEAD(injection_list);
static DEFINE_RWLOCK(injection_list_lock);

long inject(struct chaos_injection *injection, unsigned long *id_out)
{
    struct injection_node *node;
    int ret = 0;
    unsigned long id = get_id();

    switch (injection->matcher_type)
    {
    case MATCHER_TYPE_IOEM:
        ret = build_ioem_injection(id, injection);
        if (ret != 0)
        {
            return ret;
        }

        write_lock(&injection_list_lock);

        // allocate the injection node and add it to the existing link list
        node = kmalloc(sizeof(struct injection_node), GFP_KERNEL);
        if (node == NULL)
        {
            ret = ENOMEM;
            ioem_del(id);
            return ret;
        }
        node->id = id;
        node->del = ioem_del;
        INIT_LIST_HEAD(&node->list);
        list_add_tail(&node->list, &injection_list);

        write_unlock(&injection_list_lock);
        break;
    default:
        break;
    }

    *id_out = id;
    return 0;
}

int recover(unsigned long id)
{
    struct injection_node *node, *tmp;
    int ret = 0;

    write_lock(&injection_list_lock);

    list_for_each_entry_safe(node, tmp, &injection_list, list)
    {
        if (node->id == id)
        {
            ret = node->del(node->id);
            // only delete the node when it's recovered successfully
            if (ret == 0)
            {
                list_del(&node->list);
            }
        }
    }

    write_unlock(&injection_list_lock);

    return ret;
}

int recover_all()
{
    struct injection_node *node, *tmp;
    int ret = 0;

    write_lock(&injection_list_lock);

    list_for_each_entry_safe(node, tmp, &injection_list, list)
    {
        ret = node->del(node->id);
        // only delete the node when it's recovered successfully
        if (ret == 0)
        {
            list_del(&node->list);
        }
    }

    write_unlock(&injection_list_lock);

    return ret;
}