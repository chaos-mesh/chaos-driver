#include "protocol.h"

#ifndef INJECTION_H
#define INJECTION_H

unsigned long get_id(void);

long inject(struct chaos_injection *injection, unsigned long *id);
int recover(unsigned long id);
int recover_all(void);

enum matcher_type
{
    MATCHER_TYPE_FS_SYSCALL = 0,
    MATCHER_TYPE_BLK_IO = 1,
};

#endif