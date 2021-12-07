#include <linux/version.h>

#ifndef COMP_H
#define COMP_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)

#define bio_comp_op(bio) (bio->bi_opf & REQ_OP_MASK)
#define bio_is_read(bio) (bio_comp_op(bio) == REQ_OP_READ)
#define bio_is_write(bio) (bio_comp_op(bio) == REQ_OP_WRITE || bio_comp_op(bio) == REQ_OP_WRITE_SAME || bio_comp_op(bio) == REQ_OP_WRITE_ZEROES)

#else

#define bio_comp_op(bio) (bio->bi_rw)
#define bio_is_write(bio) ((bio_comp_op(bio) & REQ_WRITE) || (bio_comp_op(bio) & REQ_WRITE_SAME))
#define bio_is_read(bio) !(bio_is_write(bio))

#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0))

#define bio_is_device(bio,device) (bio->bi_disk != NULL && disk_devt(bio->bi_disk) == device)

#else

#define bio_is_device(bio,device) (bio->bi_bdev != NULL && bio->bi_bdev->bd_dev == device)

#endif 

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))

#define ns_inum(n) (n->ns.inum)

#else

#define ns_inum(ns) (ns->proc_inum)

#endif

#endif