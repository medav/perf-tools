
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdint.h>
#include "locks.h"

#include "pin.H"
#include "counter-perf.hh"

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

KNOB<BOOL> KnobVerbose(KNOB_MODE_WRITEONCE, "pintool",
    "v", "FALSE", "Verbose (debug) output");

KNOB<std::string> KnobOutfile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "pcount.yaml", "output filename");

#define DEBUG(x) \
    if (KnobVerbose.Value()) { \
        std::cerr << x << std::endl; \
    }

uint32_t lock;
std::ofstream ofs;

struct Stats {
    UINT64 total;
    UINT64 cycles;

    Stats() : total(0), cycles(0) { }

    Stats& operator=(const Stats& other) = default;

    Stats operator-(const Stats& other) {
        Stats ret;
        ret.total = total - other.total;
        ret.cycles = cycles - other.cycles;

        return ret;
    }
};

struct Context {
    std::string rname;
    std::string opname;
    CounterManager * cm;

    Context(const char * _rname, const char * _opname) : rname(_rname), opname(_opname) {
        cm = new CounterManager();
        cm->Reset();
    }

    ~Context() {
        if (cm) {
            delete cm;
        }
    }
};


VOID DumpStats(THREADID tid, UINT64 rid, Context& rd, Stats& stats) {
    DEBUG("DumpStats");

    ofs << "- { tid: " << tid << ","
        << " rid: " << rid << ", "
        << " rname: " << rd.rname << ", "
        << " opname: " << rd.opname << ", "
        << " total: " << stats.total << ", "
        << " cycles: " << stats.cycles;

    ofs << "}" << std::endl;
}

Stats ReadCounters(CounterManager& cur) {
    Stats ret;
    ret.total = cur.m_ninst.value;
    ret.cycles = cur.m_ncyc.value;
    return ret;
}

extern "C"
void * probed_pinperf_call(ADDRINT _args, ADDRINT _ctx) {
    pinperf_args_t * args = (pinperf_args_t *)_args;
    DEBUG("probed_pinperf_call")

    if (args->op == OP_ROI_BEGIN) {
        DEBUG("Roi begin: " << args->rid)
        Context * c = new Context(args->rname, args->opname);
        c->cm->Start();
        return (void *)c;
    }
    else if (args->op == OP_ROI_END) {
        DEBUG("Roi end: " << args->rid)
        Context * c = (Context *)_ctx;
        c->cm->Pause();
        c->cm->Capture();
        Stats s = ReadCounters(*c->cm);
        futex_lock(&lock);
        DumpStats(-1, args->rid, *c, s);
        futex_unlock(&lock);
        delete c;
    }

    return nullptr;
}

INT32 Usage() {
    return -1;
}

VOID InstrumentImage(IMG img, VOID * v) {
    RTN rtn = RTN_FindByName(img, "pinperf_call");

    if (RTN_Valid(rtn))
    {
        std::cout << "Replacing pinperf_call in " << IMG_Name(img) << std::endl;

        PROTO proto_pinperf_call = PROTO_Allocate(
            PIN_PARG(void *),
            CALLINGSTD_DEFAULT,
            "proto_pinperf_call",
            PIN_PARG(void *),
            PIN_PARG(void *),
            PIN_PARG_END());

        // Replace the application routine with the replacement function.
        // Additional arguments have been added to the replacement routine.
        //
        RTN_ReplaceSignatureProbed(
            rtn, AFUNPTR(probed_pinperf_call),
            IARG_PROTOTYPE, proto_pinperf_call,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_END);

        PROTO_Free(proto_pinperf_call);
    }
}

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    futex_init(&lock);
    ofs.open(KnobOutfile.Value().c_str(), std::ios::trunc);

    IMG_AddInstrumentFunction(InstrumentImage, 0);

    PIN_StartProgramProbed();
    return 0;
}
