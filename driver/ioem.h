#include "injection.h"

#ifndef IOEM_H
#define IOEM_H

int ioem_register(void);
void ioem_unregister(void);

int build_ioem_injection(unsigned long id, struct chaos_injection * injection);

int ioem_del(unsigned long id);

struct ioem_matcher_arg {
    dev_t device;

    // 0 means all
    // 1 means write (include write, write_same, write_zeroes)
    // 2 means read
    int op;
} __attribute__((packed));

struct ioem_injector_delay_arg {
    s64 delay;
    s64 jitter;
    u32 corr;
} __attribute__((packed));

struct ioem_injector_limit_arg {
    u64 period_us;
    u64 quota;
} __attribute__((packed));

enum ioem_injector_type
{
    IOEM_INJECTOR_TYPE_DELAY = 0,
    IOEM_INJECTOR_TYPE_LIMIT = 1,
};

#endif