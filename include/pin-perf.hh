
#include <time.h>
#include <unistd.h>
#include <stdint.h>

#define OP_ROI_BEGIN 1
#define OP_ROI_END 2

struct pin_call_args {
    uint64_t op;
    uint64_t rid;
    char * rname;
    char * opname;
};

#define COMPILER_BARRIER() { __asm__ __volatile__("" ::: "memory");}

static inline void do_magic_op(
    uint64_t op, uint64_t rid, const char * rname, const char * opname) {

    struct pin_call_args args = {
        .op = op,
        .rid = rid,
        .rname = (char *)rname,
        .opname = (char *)opname
    };

    uint64_t ptr = (uint64_t)&args;

    COMPILER_BARRIER();
    __asm__ __volatile__(
        "xchg %%rcx, %%rcx;"
        /* outputs  */:
        /* inputs   */: "c"(ptr)
        /* clobbers */ );
    COMPILER_BARRIER();
}

#define PERF_ROI_BEGIN(rid, rname, opname) \
    do_magic_op(OP_ROI_BEGIN, rid, rname, opname);

#define PERF_ROI_END(rid) \
    do_magic_op(OP_ROI_END, rid, 0, 0);
