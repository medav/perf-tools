
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdint.h>
#include "locks.h"

#include "pin.H"

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

const UINT32 MAX_INDEX = 4096;

KNOB<BOOL> KnobVerbose(KNOB_MODE_WRITEONCE, "pintool",
    "v", "FALSE", "Verbose (debug) output");

KNOB<std::string> KnobOutfile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "imix.yaml", "output filename");

#define DEBUG(x) \
    if (KnobVerbose.Value()) { \
        std::cerr << x << std::endl; \
    }

TLS_KEY imix_key;

uint32_t lock;
std::ofstream ofs;

struct Stats {
    UINT64 count[MAX_INDEX];

    Stats() : count{{0}} { }

    Stats& operator=(const Stats& other) = default;

    Stats operator-(const Stats& other) {
        Stats ret;
        for (UINT64 i = 0; i < MAX_INDEX; i++) {
            ret.count[i] = count[i] - other.count[i];
        }

        return ret;
    }

    UINT64 Total() const {
        UINT64 total = 0;
        for (UINT64 i = 0; i < MAX_INDEX; i++) {
            total += count[i];
        }

        return total;
    }
};

struct Context {
    Stats start;
    std::string rname;
    std::string opname;

    Context(Stats& _stats, const char * _rname, const char * _opname) :
        start(_stats), rname(_rname), opname(_opname) {}
};

struct ThreadData {
    Stats cur;

    ThreadData() : cur() {}
};

LOCALFUN std::string IndexToOpcodeString( UINT32 index )
{
    return OPCODE_StringShort(index);
}

VOID DumpStats(THREADID tid, UINT64 rid, Context& rd, Stats& stats) {
    UINT64 total = stats.Total();
    DEBUG("DumpStats");

    ofs << "- { tid: " << tid << ","
        << " rid: " << rid << ", "
        << " rname: " << rd.rname << ", "
        << " opname: " << rd.opname << ", "
        << " total: " << total << ", "
        << " stats: {";

    for (UINT64 i = 0; i < MAX_INDEX; i++) {
        if (stats.count[i] > 0) {
            ofs << IndexToOpcodeString(i)
                << ": "
                << stats.count[i]
                << ", ";
        }
    }

    ofs << "}}" << std::endl;
}

VOID PIN_FAST_ANALYSIS_CALL docount(THREADID tid, UINT64 opcode, UINT64 n) {
    ThreadData * td = (ThreadData *)PIN_GetThreadData(imix_key, tid);
    td->cur.count[opcode] += n;
}

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
    PIN_SetThreadData(imix_key, new ThreadData(), tid);
}

extern "C"
void * probed_pinperf_call(THREADID tid, ADDRINT _args, ADDRINT _ctx) {
    pinperf_args_t * args = (pinperf_args_t *)_args;
    ThreadData * td = (ThreadData *)PIN_GetThreadData(imix_key, tid);

    if (args->op == OP_ROI_BEGIN) {
        DEBUG("Roi begin: " << args->rid)
        Context * c = new Context(td->cur, args->rname, args->opname);
        return (void *)c;
    }
    else if (args->op == OP_ROI_END) {
        DEBUG("Roi end: " << args->rid)
        Context * c = (Context *)_ctx;
        Stats s = td->cur - c->start;
        futex_lock(&lock);
        DumpStats(tid, args->rid, *c, s);
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
        RTN_ReplaceSignature(
            rtn, AFUNPTR(probed_pinperf_call),
            IARG_PROTOTYPE, proto_pinperf_call,
            IARG_THREAD_ID,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_END);

        PROTO_Free(proto_pinperf_call);
    }
}

VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block  in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        Stats bbl_stats;
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            bbl_stats.count[INS_Opcode(ins)]++;
        }

        for (UINT32 i = 0; i < MAX_INDEX; i++) {
            if (bbl_stats.count[i] > 0) {
                BBL_InsertCall(
                    bbl,
                    IPOINT_BEFORE,
                    AFUNPTR(docount), IARG_FAST_ANALYSIS_CALL,
                    IARG_THREAD_ID,
                    IARG_UINT64, i,
                    IARG_UINT64, bbl_stats.count[i],
                    IARG_END
                );
            }
        }
    }
}



void FreeThreadData(void * td) {
    delete (ThreadData *)td;
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    futex_init(&lock);
    ofs.open(KnobOutfile.Value().c_str(), std::ios::trunc);

    imix_key = PIN_CreateThreadDataKey(FreeThreadData);

    PIN_AddThreadStartFunction(ThreadStart, 0);
    TRACE_AddInstrumentFunction(Trace, 0);
    IMG_AddInstrumentFunction(InstrumentImage, 0);

    PIN_StartProgram();
    return 0;
}
