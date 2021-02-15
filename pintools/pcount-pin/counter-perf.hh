
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>

[[maybe_unused]]
static long my_ioctl(int fd, unsigned long int request, unsigned long arg) {

    register int64_t rax __asm__ ("rax") = __NR_ioctl;
    register int rdi __asm__ ("rdi") = fd;
    register unsigned long int rsi __asm__ ("rsi") = request;
    register unsigned long rdx __asm__ ("rdx") = arg;
    __asm__ __volatile__ (
        "syscall"
        : "+r" (rax)
        : "r" (rdi), "r" (rsi), "r" (rdx)
        : "cc", "rcx", "r11", "memory"
    );

    return rax;
}

[[maybe_unused]]
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    register int64_t rax __asm__ ("rax") = __NR_perf_event_open;
    register struct perf_event_attr * rdi __asm__ ("rdi") = hw_event;
    register pid_t rsi __asm__ ("rsi") = pid;
    register int rdx __asm__ ("rdx") = cpu;
    register int r10 __asm__ ("r10") = group_fd;
    register int r8 __asm__ ("r8") = flags;
    __asm__ __volatile__ (
        "syscall"
        : "+r" (rax)
        : "r" (rdi), "r" (rsi), "r" (rdx), "r" (r10), "r" (r8)
        : "cc", "rcx", "r11", "memory"
    );

    return rax;
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

#define PERF_COUNTERS_VARS(prefix) \
    struct read_format prefix ## ninst; \
    struct read_format prefix ## ncyc; \
    struct read_format prefix ## nraw; \
    struct perf_event_attr prefix ## ninst_ev; \
    struct perf_event_attr prefix ## ncyc_ev; \
    struct perf_event_attr prefix ## raw_ev; \
    int prefix ## fd_ninst; \
    int prefix ## fd_ncyc; \
    int prefix ## fd_raw;


#define PERF_COUNTERS_SETUP(prefix) \
    memset(&prefix ## ninst_ev, 0, sizeof(struct perf_event_attr)); \
    memset(&prefix ## ncyc_ev, 0, sizeof(struct perf_event_attr)); \
    memset(&prefix ## raw_ev, 0, sizeof(struct perf_event_attr)); \
    (prefix ## ninst_ev).size = sizeof(struct perf_event_attr); \
    (prefix ## ncyc_ev).size = sizeof(struct perf_event_attr); \
    (prefix ## raw_ev).size = sizeof(struct perf_event_attr); \
    \
    (prefix ## ninst_ev).type = PERF_TYPE_HARDWARE; \
    (prefix ## ninst_ev).config = PERF_COUNT_HW_INSTRUCTIONS; \
    (prefix ## ninst_ev).disabled = 1; \
    (prefix ## ninst_ev).exclude_kernel = 1; \
    (prefix ## ninst_ev).exclude_hv = 1; \
    \
    (prefix ## ncyc_ev).type = PERF_TYPE_HARDWARE; \
    (prefix ## ncyc_ev).config = PERF_COUNT_HW_CPU_CYCLES; \
    (prefix ## ncyc_ev).disabled = 1; \
    (prefix ## ncyc_ev).exclude_kernel = 1; \
    (prefix ## ncyc_ev).exclude_hv = 1; \
    \
    (prefix ## raw_ev).type = PERF_TYPE_RAW; \
    (prefix ## raw_ev).config = 0x8B0; \
    (prefix ## raw_ev).disabled = 1; \
    (prefix ## raw_ev).exclude_kernel = 1; \
    (prefix ## raw_ev).exclude_hv = 1; \
    \
    (prefix ## fd_ninst) = perf_event_open(&prefix ## ninst_ev, 0, -1, -1, 0); \
    CHECK_FD(prefix ## fd_ninst); \
    (prefix ## fd_ncyc) = perf_event_open(&prefix ## ncyc_ev, 0, -1, -1, 0); \
    CHECK_FD(prefix ## fd_ncyc); \
    (prefix ## fd_raw) = perf_event_open(&prefix ## raw_ev, 0, -1, -1, 0); \
    CHECK_FD(prefix ## fd_raw);

#define PERF_COUNTERS_RESET(prefix) \
    CHECK_SYSCALL(my_ioctl(prefix ## fd_ninst, PERF_EVENT_IOC_RESET, 0)); \
    CHECK_SYSCALL(my_ioctl(prefix ## fd_ncyc, PERF_EVENT_IOC_RESET, 0)); \
    CHECK_SYSCALL(my_ioctl(prefix ## fd_raw, PERF_EVENT_IOC_RESET, 0)); \

#define PERF_COUNTERS_ENABLE(prefix) \
    CHECK_SYSCALL(my_ioctl(prefix ## fd_ninst, PERF_EVENT_IOC_ENABLE, 0)); \
    CHECK_SYSCALL(my_ioctl(prefix ## fd_ncyc, PERF_EVENT_IOC_ENABLE, 0)); \
    CHECK_SYSCALL(my_ioctl(prefix ## fd_raw, PERF_EVENT_IOC_ENABLE, 0));

#define PERF_COUNTERS_BEGIN(prefix) \
    PERF_COUNTERS_RESET(prefix) \
    PERF_COUNTERS_ENABLE(prefix)

#define PERF_COUNTERS_DISABLE(prefix) \
    CHECK_SYSCALL(my_ioctl(prefix ## fd_ninst, PERF_EVENT_IOC_DISABLE, 0)); \
    CHECK_SYSCALL(my_ioctl(prefix ## fd_ncyc, PERF_EVENT_IOC_DISABLE, 0)); \
    CHECK_SYSCALL(my_ioctl(prefix ## fd_raw, PERF_EVENT_IOC_DISABLE, 0));

#define PERF_COUNTERS_CAPTURE(prefix) \
    CHECK_SYSCALL(read(prefix ## fd_ninst, &prefix ## ninst, sizeof(prefix ## ninst))); \
    CHECK_SYSCALL(read(prefix ## fd_ncyc, &prefix ## ncyc, sizeof(prefix ## ncyc))); \
    CHECK_SYSCALL(read(prefix ## fd_ncyc, &prefix ## nraw, sizeof(prefix ## nraw)));

#define PERF_COUNTERS_END(prefix) \
    PERF_COUNTERS_DISABLE(prefix) \
    PERF_COUNTERS_CAPTURE(prefix)


struct CounterManager {
    PERF_COUNTERS_VARS(m_)

    CounterManager() {
        PERF_COUNTERS_SETUP(m_);
    }

    void Reset() {
        PERF_COUNTERS_RESET(m_);
    }

    void Start() {
        PERF_COUNTERS_ENABLE(m_);
    }

    void Pause() {
        PERF_COUNTERS_DISABLE(m_);
    }

    void Capture() {
        PERF_COUNTERS_CAPTURE(m_);
    }

    ~CounterManager() {
        CHECK_SYSCALL(close(m_fd_ninst));
        CHECK_SYSCALL(close(m_fd_ncyc));
        CHECK_SYSCALL(close(m_fd_raw));
    }
};
