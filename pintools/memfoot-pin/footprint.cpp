
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdint.h>
#include "locks.h"

#include "pin.H"

constexpr uint64_t OP_ROI_BEGIN = 1;
constexpr uint64_t OP_ROI_END = 2;
constexpr uint64_t OP_ROI_SETMETA = 3;

extern "C" {
typedef struct pinperf_args {
    uint64_t op;
    uint64_t rid;
    const char * rname;
    const char * opname;
} pinperf_args_t;
}

const UINT32 MAX_INDEX = 4096;
const UINT32 MAX_SPECIAL = 100;

const UINT32 FP32_COUNT = 0;
const UINT32 NON_FP32_COUNT = 1;

#define OPCODE_ADDPS 10

UINT64 CountFp32(INS ins) {
    OPCODE opcode = INS_Opcode(ins);

    switch (opcode) {
    case OPCODE_ADDPS:
        return 4;

    default:
        return 1;
    }
}

KNOB<INT> KnobChunkSize(KNOB_MODE_WRITEONCE, "pintool",
    "c", "16", "Memory footprint chunk size");

KNOB<BOOL> KnobVerbose(KNOB_MODE_WRITEONCE, "pintool",
    "v", "FALSE", "Verbose (debug) output");

KNOB<std::string> KnobOutfile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "imix.yaml", "output filename");

#define DEBUG(x) \
    if (KnobVerbose.Value()) { \
        std::cerr << x << std::endl; \
    }

static inline INT chunk_size() {
    return KnobChunkSize.Value();
}

TLS_KEY imix_key;

uint32_t lock;
std::ofstream ofs;

struct Stats {
    UINT64 count[MAX_INDEX];
    UINT64 special[MAX_SPECIAL];

    Stats() {
        for (UINT64 i = 0; i < MAX_INDEX; i++) {
            count[i] = 0;
        }

        for (UINT64 i = 0; i < MAX_SPECIAL; i++) {
            special[i] = 0;
        }
    }

    Stats& operator=(const Stats& other) = default;

    Stats operator-(const Stats& other) {
        Stats ret;
        for (UINT64 i = 0; i < MAX_INDEX; i++) {
            ret.count[i] = count[i] - other.count[i];
        }

        for (UINT64 i = 0; i < MAX_SPECIAL; i++) {
            ret.special[i] = special[i] - other.special[i];
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
    std::string meta;
    std::map<ADDRINT, unsigned int> addr_map;

    Context(Stats& _stats, const char * _rname, const char * _opname) :
        start(_stats), rname(_rname), opname(_opname), meta("\"\"") {}
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
        << " meta: " << rd.meta << ", "
        << " total: " << total << ", "
        << " fp32: " << stats.special[FP32_COUNT] << ", "
        << " non-fp32: " << stats.special[NON_FP32_COUNT] << ", "
        << " stats: {";


    ofs << "}}" << std::endl;
}

VOID PIN_FAST_ANALYSIS_CALL docount(THREADID tid, UINT64 opcode, UINT64 n) {
    ThreadData * td = (ThreadData *)PIN_GetThreadData(imix_key, tid);
    td->cur.count[opcode] += n;
}

VOID PIN_FAST_ANALYSIS_CALL docount_special(THREADID tid, UINT64 opcode, UINT64 n) {
    ThreadData * td = (ThreadData *)PIN_GetThreadData(imix_key, tid);
    td->cur.special[opcode] += n;
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
    else if (args->op == OP_ROI_SETMETA) {
        DEBUG("Roi setmeta: " << args->rid)
        DEBUG("ctx: " << _ctx)
        DEBUG("meta: " << args->rname)
        Context * c = (Context *)_ctx;

        if (c == nullptr) {
            DEBUG("setmeta: c is null! Ignoring...")
        }
        else {
            c->meta = std::string("\"") + std::string(args->rname) + std::string("\"");
        }
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



ADDRINT mask(ADDRINT ea)  {
    const ADDRINT mask = ~static_cast<ADDRINT>(chunk_size()-1);
    return ea & mask;
}

void load(footprint_t* xthis, THREADID tid, ADDRINT memea, UINT32 length) {
    ADDRINT start = mask(memea);
    ADDRINT end   = mask(memea+length-1);
    footprint_thread_data_t* tdata = xthis->get_tls(tid);
    for(ADDRINT addr = start ; addr <= end ; addr += chunk_size()) {
        tdata->load(addr);
    }
}

void store(footprint_t* xthis, THREADID tid, ADDRINT memea, UINT32 length) {
    ADDRINT start = mask(memea);
    ADDRINT end   = mask(memea+length-1);
    footprint_thread_data_t* tdata = xthis->get_tls(tid);
    for(ADDRINT addr = start ; addr <= end ; addr += chunk_size()) {
        tdata->store(addr);
    }
}


VOID InstrumentMemInst(INS ins) {
    if (INS_IsMemoryRead(ins) && INS_IsStandardMemop(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) load,
                        IARG_PTR, this,
                        IARG_THREAD_ID,
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYREAD_SIZE,
                        IARG_END);

    }
    if (INS_HasMemoryRead2(ins) && INS_IsStandardMemop(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) load,
                        IARG_PTR, this,
                        IARG_THREAD_ID,
                        IARG_MEMORYREAD2_EA,
                        IARG_MEMORYREAD_SIZE,
                        IARG_END);

    }
    // instrument the store
    if (INS_IsMemoryWrite(ins) && INS_IsStandardMemop(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) store,
                        IARG_PTR, this,
                        IARG_THREAD_ID,
                        IARG_MEMORYWRITE_EA,
                        IARG_MEMORYWRITE_SIZE,
                        IARG_END);

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
            OPCODE opcode  = INS_Opcode(ins);
            bbl_stats.count[opcode]++;

            UINT32 flops = Fp32FlopCount_Cached(ins);

            if (flops == 0) {
                bbl_stats.special[NON_FP32_COUNT]++;
            }
            else {
                bbl_stats.special[FP32_COUNT] += flops;
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
