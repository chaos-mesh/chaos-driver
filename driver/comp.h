#include <linux/version.h>
#include <linux/tracepoint.h>
#include <linux/fdtable.h>
#include <linux/ptrace.h>

#ifndef COMP_H
#define COMP_H

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0))

#define iter_tp(VISIT, PRIV) \
    struct tracepoint_iter *__tp_iter = NULL;\
    for(tracepoint_iter_start(__tp_iter);__tp_iter->tracepoint;tracepoint_iter_next(__tp_iter)) {\
        VISIT(*__tp_iter->tracepoint, PRIV);\
    }

#else

#define iter_tp(VISIT, PRIV) \
    for_each_kernel_tracepoint(VISIT, PRIV);

#endif


#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0))

#define files_lookup_fd(FILES, FD) \
    fcheck_files(FILES, FD);\

#else

#define files_lookup_fd(FILES, FD) \
    files_lookup_fd_rcu(FILES, FD);\

#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
#define compat_register_trace(func, probename, tp) tracepoint_probe_register(probename, func, NULL)
#else
#define compat_register_trace(func, probename, tp) tracepoint_probe_register(tp, func, NULL)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
#define compat_unregister_trace(func, probename, tp) tracepoint_probe_unregister(probename, func, NULL)
#else
#define compat_unregister_trace(func, probename, tp) tracepoint_probe_unregister(tp, probename, NULL)
#endif

#endif



#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0))
static inline unsigned long compat_regs_get_kernel_argument(struct pt_regs *regs,
                                                    unsigned int n)
{
       static const unsigned int argument_offs[] = {
#ifdef __i386__
               offsetof(struct pt_regs, ax),
               offsetof(struct pt_regs, dx),
               offsetof(struct pt_regs, cx),
#define NR_REG_ARGUMENTS 3
#else
               offsetof(struct pt_regs, di),
               offsetof(struct pt_regs, si),
               offsetof(struct pt_regs, dx),
               offsetof(struct pt_regs, cx),
               offsetof(struct pt_regs, r8),
               offsetof(struct pt_regs, r9),
#define NR_REG_ARGUMENTS 6
#endif
       };

       if (n >= NR_REG_ARGUMENTS) {
               n -= NR_REG_ARGUMENTS - 1;
               return regs_get_kernel_stack_nth(regs, n);
       } else
               return regs_get_register(regs, argument_offs[n]);
}
#else
#define compat_regs_get_kernel_argument regs_get_kernel_argument
#endif
