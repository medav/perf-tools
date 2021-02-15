
#include <iostream>

extern "C"
void * pinperf_call(void * args, void * ctx) {
    return args;
}

namespace pin_perf {
constexpr uint64_t OP_ROI_BEGIN = 1;
constexpr uint64_t OP_ROI_END = 2;

extern "C" {
typedef struct pinperf_args {
    uint64_t op;
    uint64_t rid;
    const char * rname;
    const char * opname;
} pinperf_args_t;
}

void * call_pin(pinperf_args_t args, void * ctx = nullptr);

static inline pinperf_args_t roi_begin(
    uint64_t rid, const char * rname, const char * opname) {
    return pinperf_args_t {
        .op = OP_ROI_BEGIN,
        .rid = rid,
        .rname = rname,
        .opname = opname
    };
}

static inline pinperf_args_t roi_end(uint64_t rid) {
    return pinperf_args_t {
        .op = OP_ROI_END,
        .rid = rid,
        .rname = "",
        .opname = ""
    };
}

void * call_pin(pinperf_args_t args, void * ctx) {
    return pinperf_call((void*)&args, ctx);
}

}

extern "C"
void * perf_roi_begin(uint64_t rid, const char * rname, const char * opname) {
    using namespace pin_perf;
    return call_pin(roi_begin(rid, rname, opname));
}

extern "C"
void perf_roi_end(uint64_t rid, void * ctx) {
    using namespace pin_perf;
    call_pin(roi_end(rid), ctx);
}
