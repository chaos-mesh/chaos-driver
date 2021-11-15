#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>

#include "injection.h"

#ifndef LAZY_LIST_H
#define LAZY_LIST_H

struct lazy_list {
    int registered;

    struct list_head head;
    rwlock_t list_lock;

    int (*lazy_register)(struct lazy_list*);
    int (*lazy_unregister)(struct lazy_list*);
};

#define LAZY_LIST_DEFINE(name, register_func, unregister_func) \
    struct lazy_list name = { \
        .registered = 0, \
        .head = LIST_HEAD_INIT(name.head), \
        .list_lock = __RW_LOCK_UNLOCKED(name.list_lock), \
        .lazy_register = register_func, \
        .lazy_unregister = unregister_func \
    }

/**
 * lazy_list_add_tail - add the item to the tail of lazy_list, will trigger the lazy_register
 * @l:      the lazy_list
 * @head:   the head of the list
 */
int lazy_list_add_tail(struct list_head* head, struct lazy_list* l);

/**
 * lazy_list_delete - add the item to the tail of lazy_list, will trigger the lazy_register
 * @list_ref:      the lazy_list
 * @pos:    the iterator of the list
 * @tmp:    the tmp varaible, should be the same type with pos
 * @delete_condition: the item will be deleted, iff the condition meets
 * @recycle: the recycle branch when the item is deleted
 * @name:   the name of the list head field in typeo of pos
 */
#define lazy_list_delete(list_ref, pos, tmp, delete_condition, recycle, name) \
    struct lazy_list* l = list_ref; \
    write_lock(&l->list_lock); \
    list_for_each_entry_safe(pos, tmp, &l->head, name) \
    { \
        if ( delete_condition ) \
        { \
            list_del(&e->list); \
            recycle; \
        } \
    } \
    if (list_empty(&l->head) && l->registered) \
    { \
        l->lazy_unregister(l); \
    } \
    write_unlock(&l->list_lock);

/**
 * lazy_list_delete_all - add the item to the tail of lazy_list, will trigger the lazy_register
 * @list_ref:      the lazy_list
 * @pos:    the iterator of the list
 * @tmp:    the tmp varaible, should be the same type with pos
 * @recycle: the recycle statement when the item is deleted
 * @name:   the name of the list head field in typeo of pos
 */
#define lazy_list_delete_all(list_ref, pos, tmp, recycle, name) \
    struct lazy_list* l = list_ref; \
    write_lock(&l->list_lock); \
    list_for_each_entry_safe(pos, tmp, &l->head, name) \
    { \
        list_del(&e->list); \
        recycle; \
    } \
    if (l->registered) \
    { \
        l->lazy_unregister(l); \
    } \
    write_unlock(&l->list_lock);

/**
 * lazy_list_for_each_entry - iterate over list of given type
 * @list_ref:      the lazy_list
 * @pos:    the iterator of the list
 * @stat:   the statement to execute each time
 * @name:   the name of the list head field in typeo of pos
 */
#define lazy_list_for_each_entry(list_ref, pos, stat, name) \
    struct lazy_list* l = list_ref; \
    read_lock(&l->list_lock); \
    list_for_each_entry(pos, &l->head, name) \
    { \
        stat; \
    } \
    read_unlock(&l->list_lock);

#endif