
#define PINTOOL

#if defined(PINTOOL)


#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>

[[maybe_unused]]
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
  int ret;
  ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
  return ret;
}

#define COMPILER_BARRIER() { __asm__ __volatile__("" ::: "memory");}

static inline void do_magic_op(uint64_t op) {
    COMPILER_BARRIER();
    __asm__ __volatile__("xchg %%rcx, %%rcx;" : : "c"(op));
    COMPILER_BARRIER();
}

struct read_format {
    uint64_t value;         /* The value of the event */
    uint64_t time_enabled;  /* if PERF_FORMAT_TOTAL_TIME_ENABLED */
    uint64_t time_running;  /* if PERF_FORMAT_TOTAL_TIME_RUNNING */
    uint64_t id;            /* if PERF_FORMAT_ID */
};

#define CHECK_SYSCALL(c) \
    if ((c) < 0) { \
        perror(# c); \
        exit(1); \
    }


#define CHECK_FD(c) \
    if ((c) < 0) { \
        perror(# c); \
        exit(1); \
    }

#define PERF_COUNTERS_BEGIN() \
    struct read_format ninst; \
    struct read_format ncyc; \
    struct read_format nraw; \
    struct perf_event_attr ninst_ev; \
    struct perf_event_attr ncyc_ev; \
    struct perf_event_attr raw_ev; \
    memset(&ninst_ev, 0, sizeof(struct perf_event_attr)); \
    memset(&ncyc_ev, 0, sizeof(struct perf_event_attr)); \
    memset(&raw_ev, 0, sizeof(struct perf_event_attr)); \
    ninst_ev.size = sizeof(struct perf_event_attr); \
    ncyc_ev.size = sizeof(struct perf_event_attr); \
    raw_ev.size = sizeof(struct perf_event_attr); \
    \
    ninst_ev.type = PERF_TYPE_HARDWARE; \
    ninst_ev.config = PERF_COUNT_HW_CPU_CYCLES; \
    ninst_ev.disabled = 1; \
    ninst_ev.exclude_kernel = 1; \
    ninst_ev.exclude_hv = 1; \
    \
    ncyc_ev.type = PERF_TYPE_HARDWARE; \
    ncyc_ev.config = PERF_COUNT_HW_INSTRUCTIONS; \
    ncyc_ev.disabled = 1; \
    ncyc_ev.exclude_kernel = 1; \
    ncyc_ev.exclude_hv = 1; \
    \
    raw_ev.type = PERF_TYPE_RAW; \
    raw_ev.config = 0x8B0; \
    raw_ev.disabled = 1; \
    raw_ev.exclude_kernel = 1; \
    raw_ev.exclude_hv = 1; \
    \
    int fd_ninst = perf_event_open(&ninst_ev, 0, -1, -1, 0); \
    CHECK_FD(fd_ninst); \
    int fd_ncyc = perf_event_open(&ncyc_ev, 0, -1, -1, 0); \
    CHECK_FD(fd_ncyc); \
    int fd_raw = perf_event_open(&raw_ev, 0, -1, -1, 0); \
    CHECK_FD(fd_raw); \
    \
    CHECK_SYSCALL(ioctl(fd_ninst, PERF_EVENT_IOC_RESET, 0)); \
    CHECK_SYSCALL(ioctl(fd_ncyc, PERF_EVENT_IOC_RESET, 0)); \
    CHECK_SYSCALL(ioctl(fd_raw, PERF_EVENT_IOC_RESET, 0)); \
    CHECK_SYSCALL(ioctl(fd_ninst, PERF_EVENT_IOC_ENABLE, 0)); \
    CHECK_SYSCALL(ioctl(fd_ncyc, PERF_EVENT_IOC_ENABLE, 0)); \
    CHECK_SYSCALL(ioctl(fd_raw, PERF_EVENT_IOC_ENABLE, 0));


#define PERF_ROI_BEGIN(rid) \
    do_magic_op(rid);

#define PERF_ROI_END(rid) \
    do_magic_op(rid); \

#define PERF_COUNTERS_END() \
    CHECK_SYSCALL(ioctl(fd_ninst, PERF_EVENT_IOC_DISABLE, 0)); \
    CHECK_SYSCALL(ioctl(fd_ncyc, PERF_EVENT_IOC_DISABLE, 0)); \
    CHECK_SYSCALL(ioctl(fd_raw, PERF_EVENT_IOC_DISABLE, 0)); \
    \
    CHECK_SYSCALL(read(fd_ninst, &ninst, sizeof(ninst))); \
    CHECK_SYSCALL(read(fd_ncyc, &ncyc, sizeof(ncyc))); \
    CHECK_SYSCALL(read(fd_ncyc, &nraw, sizeof(nraw)));


#else
#define PERF_ROI_BEGIN(rid)
#define PERF_ROI_END(rid)
#endif