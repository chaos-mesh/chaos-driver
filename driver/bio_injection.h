#include <linux/types.h>

#include "protocol.h"

#ifndef BIO_INJECTION_H
#define BIO_INJECTION_H

long build_bio_injection(unsigned long id, struct chaos_injection *injection);
int bio_injection_executor_del(unsigned long id);

struct bio_injection_parameter
{
    dev_t dev;
} __attribute__((packed));

enum bio_injector_type
{
    BIO_INJECTOR_TYPE_DELAY = 0,
};

#endif
