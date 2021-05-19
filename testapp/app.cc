#include <vector>
#include <iostream>

#define COMPILER_BARRIER() { __asm__ __volatile__("" ::: "memory");}

constexpr uint64_t OP_ROI_BEGIN = 1;
constexpr uint64_t OP_ROI_END = 2;

typedef struct pinperf_args {
    uint64_t op;
    uint64_t rid;
    const char * rname;
    const char * opname;
} pinperf_args_t;


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

extern "C"
void * pinperf_call(void * args, void * ctx) {
    uint64_t ptr = (uint64_t)&args;

    COMPILER_BARRIER();
    __asm__ __volatile__(
        "xchg %%rcx, %%rcx;"
        /* outputs  */:
        /* inputs   */: "c"(ptr)
        /* clobbers */ );
    COMPILER_BARRIER();

    return nullptr;
}

void * call_pin(pinperf_args_t args, void * ctx = nullptr) {
    return pinperf_call(&args, ctx);
}


int main() {
    int a;
    float r = 0;


    void * ctx = call_pin(roi_begin(0, "total", "opname"));
    for (a = 0; a < 100000; a++) {
        r += 1.0f;
    }
    call_pin(roi_end(0), ctx);


    std::cout << r << std::endl;


    return 0;
}
