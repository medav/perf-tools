#include <vector>
#include <iostream>

#define COMPILER_BARRIER() { __asm__ __volatile__("" ::: "memory");}

constexpr uint64_t OP_ROI_BEGIN = 1;
constexpr uint64_t OP_ROI_END = 2;
constexpr uint64_t OP_MEM_BEGIN = 4;
constexpr uint64_t OP_MEM_END = 5;

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

static inline pinperf_args_t mem_begin() {
    return pinperf_args_t {
        .op = OP_MEM_BEGIN,
        .rid = 0,
        .rname = "",
        .opname = ""
    };
}

static inline pinperf_args_t mem_end() {
    return pinperf_args_t {
        .op = OP_MEM_END,
        .rid = 0,
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

extern "C"
void perf_mem_begin() {
    // using namespace pin_perf;
    call_pin(mem_begin());
}

extern "C"
void perf_mem_end() {
    // using namespace pin_perf;
    call_pin(mem_end(), NULL);
}


int main() {
    int a;
    float r = 0;
    constexpr int arr_size = 1024 * 1024;
    std::cout << "Array size: " << arr_size * 4 << " bytes" << std::endl;

    perf_mem_begin();
    int * foo = new int[arr_size];
    for (a = 0; a < arr_size; a++) foo[a] = a;
    perf_mem_end();
    //void * ctx = call_pin(roi_begin(0, "total", "opname"));
    //for (a = 0; a < 100000; a++) {
    //    r += 1.0f;
    //}
    //call_pin(roi_end(0), ctx);


    //std::cout << r << std::endl;


    return 0;
}
