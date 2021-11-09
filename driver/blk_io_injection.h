#include <linux/types.h>

#include "protocol.h"

#ifndef blk_io_INJECTION_H
#define blk_io_INJECTION_H

long build_blk_io_injection(unsigned long id, struct chaos_injection *injection);
int blk_io_injection_executor_del(unsigned long id);

struct blk_io_injection_parameter
{
    dev_t dev;
} __attribute__((packed));

enum blk_io_injector_type
{
    blk_io_INJECTOR_TYPE_DELAY = 0,
};

#endif
