#include <linux/version.h>
#include <linux/tracepoint.h>
#include <linux/fdtable.h>

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

#define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2, NULL)
#define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2, NULL)

static int compat_register_trace(void *func, const char *probename, struct tracepoint *tp)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
	return TRACEPOINT_PROBE_REGISTER(probename, func);
#else
	return tracepoint_probe_register(tp, func, NULL);
#endif
}

static void compat_unregister_trace(void *func, const char *probename, struct tracepoint *tp)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
	TRACEPOINT_PROBE_UNREGISTER(probename, func);
#else
	tracepoint_probe_unregister(tp, func, NULL);
#endif
}