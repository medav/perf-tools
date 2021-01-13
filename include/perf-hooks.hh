

#if defined(PINTOOL)

#define MAGIC_OP_ROI_BEGIN         (1025)
#define MAGIC_OP_ROI_END           (1026)
#define COMPILER_BARRIER() { __asm__ __volatile__("" ::: "memory");}

static inline void do_magic_op(uint64_t op) {
    COMPILER_BARRIER();
    __asm__ __volatile__("xchg %%rcx, %%rcx;" : : "c"(op));
    COMPILER_BARRIER();
}

#define PERF_ROI_BEGIN() do_magic_op(MAGIC_OP_ROI_BEGIN)
#define PERF_ROI_END() do_magic_op(MAGIC_OP_ROI_END)

#elif defined(COUNTERS)

#else
#define PERF_ROI_BEGIN()
#define PERF_ROI_END()
#endif