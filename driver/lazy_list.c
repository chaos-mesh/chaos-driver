#include "lazy_list.h"

int lazy_list_add_tail(struct list_head* head, struct lazy_list* l) {
    int ret = 0;

    write_lock(&l->list_lock);

    // lazily run the register function
    if (l->registered == 0)
    {
        ret = l->lazy_register(l);
        if (ret != 0)
        {
            goto release;
        }
    }

    list_add_tail(head, &l->head);

release:
    write_unlock(&l->list_lock);
    return ret;
}