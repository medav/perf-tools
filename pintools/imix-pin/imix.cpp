
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
constexpr uint64_t OP_MEM_BEGIN = 4;
constexpr uint64_t OP_MEM_END = 5;

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
    "c", "64", "Memory footprint chunk size");

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
std::map<ADDRINT, unsigned int> mem;

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

VOID DumpMem() {
    uint32_t nlines = mem.size();
    ofs << "- {tid: -1 rid: null, rname: mem, opname: mem, "
        << "nlines: " << nlines << "}" << std::endl;
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
    else if (args->op == OP_MEM_BEGIN) {
        DEBUG("Mem Begin")
        mem.clear();
    }
    else if (args->op == OP_MEM_END) {
        DEBUG("Mem End")
        futex_lock(&lock);
        DumpMem();
        futex_unlock(&lock);
    }
    else {
        DEBUG("UNKNOWN OP: " << args->op)
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
static bool endswith(const std::string& str, const std::string& suffix)
{
    return str.size() >= suffix.size() && 0 == str.compare(str.size()-suffix.size(), suffix.size(), suffix);
}

static bool startswith(const std::string& str, const std::string& prefix)
{
    return str.size() >= prefix.size() && 0 == str.compare(0, prefix.size(), prefix);
}

#define MATCH_OPCODE_STR(str) \
    if (opcode_str == std::string(str))

#define FUZZYMATCH_OPCODE(prefix, suffix, w) \
    if (startswith(opcode_str, prefix) && endswith(opcode_str, suffix) && opw == w)

#define MATCH_OPCODE_STR_WIDTH(str, w) \
    if (opcode_str == std::string(str) && opw == w)

UINT32 Fp32FlopCount(std::string opcode_str, UINT32 opw) {
    // FMA
    FUZZYMATCH_OPCODE("VFMADD", "PS", 512) {
        return 16*2;
    }
    else FUZZYMATCH_OPCODE("VFMADD", "PS", 256) {
        return 8*2;
    }
    else FUZZYMATCH_OPCODE("VFMADD", "PS", 128) {
        return 4*2;
    }
    // Add
    else MATCH_OPCODE_STR("ADDSS") {
        return 1;
    }
    else MATCH_OPCODE_STR("VADDSS") {
        return 1;
    }
    else MATCH_OPCODE_STR("ADDPS") {
        return 4;
    }
    else MATCH_OPCODE_STR_WIDTH("VADDPS", 128) {
        return 4;
    }
    else MATCH_OPCODE_STR_WIDTH("VADDPS", 256) {
        return 8;
    }
    else MATCH_OPCODE_STR("FADD") {
        return 1;
    }
    else MATCH_OPCODE_STR("FADDP") {
        return 1;
    }
    // Subtract
    else MATCH_OPCODE_STR("SUBSS") {
        return 1;
    }
    else MATCH_OPCODE_STR("VSUBSS") {
        return 1;
    }
    else MATCH_OPCODE_STR("SUBPS") {
        return 4;
    }
    else MATCH_OPCODE_STR_WIDTH("VSUBPS", 128) {
        return 4;
    }
    else MATCH_OPCODE_STR_WIDTH("VSUBPS", 256) {
        return 8;
    }
    else MATCH_OPCODE_STR("FSUB") {
        return 1;
    }
    else MATCH_OPCODE_STR("FSUBP") {
        return 1;
    }
    // Multiply
    else MATCH_OPCODE_STR("MULSS") {
        return 1;
    }
    else MATCH_OPCODE_STR("VMULSS") {
        return 1;
    }
    else MATCH_OPCODE_STR("MULPS") {
        return 4;
    }
    else MATCH_OPCODE_STR_WIDTH("VMULPS", 128) {
        return 4;
    }
    else MATCH_OPCODE_STR_WIDTH("VMULPS", 256) {
        return 8;
    }
    else MATCH_OPCODE_STR("FMUL") {
        return 1;
    }
    else MATCH_OPCODE_STR("FMULP") {
        return 1;
    }
    // Divide
    else MATCH_OPCODE_STR("DIVSS") {
        return 1;
    }
    else MATCH_OPCODE_STR("VDIVSS") {
        return 1;
    }
    else MATCH_OPCODE_STR("DIVPS") {
        return 4;
    }
    else MATCH_OPCODE_STR_WIDTH("VDIVPS", 128) {
        return 4;
    }
    else MATCH_OPCODE_STR_WIDTH("VDIVPS", 256) {
        return 8;
    }
    else MATCH_OPCODE_STR("FDIV") {
        return 1;
    }
    else MATCH_OPCODE_STR("FDIVP") {
        return 1;
    }
    else {
        return 0;
    }
}
BOOL WidthDependent(std::string opcode_str) {
    const UINT32 opw = 0;
    // FMA
    FUZZYMATCH_OPCODE("VFMADD", "PS", 0) {
        return true;
    }
    // Add
    else MATCH_OPCODE_STR_WIDTH("VADDPS", 0) {
        return true;
    }
    else MATCH_OPCODE_STR_WIDTH("VADDPS", 0) {
        return true;
    }
    // Subtract
    else MATCH_OPCODE_STR_WIDTH("VSUBPS", 0) {
        return true;
    }
    else MATCH_OPCODE_STR_WIDTH("VSUBPS", 0) {
        return true;
    }
    // Multiply
    else MATCH_OPCODE_STR_WIDTH("VMULPS", 0) {
        return true;
    }
    else MATCH_OPCODE_STR_WIDTH("VMULPS", 0) {
        return true;
    }
    // Divide
    else MATCH_OPCODE_STR_WIDTH("VDIVPS", 0) {
        return true;
    }
    else MATCH_OPCODE_STR_WIDTH("VDIVPS", 0) {
        return true;
    }
    else {
        return false;
    }
}

UINT32 Fp32FlopCount_Cached(INS ins) {
    static std::map<std::pair<std::string, UINT32>, UINT32> opcode_flop_cache;
    UINT32 opw = 0;
    OPCODE opcode  = INS_Opcode(ins);
    std::string opcode_str = OPCODE_StringShort(opcode);

    if (WidthDependent(opcode_str)) {
        opw = INS_OperandWidth(ins, 0);
    }

    auto key = std::make_pair(opcode_str, opw);

    if (opcode_flop_cache.count(key) == 0) {
        UINT32 count = Fp32FlopCount(opcode_str, opw);
        opcode_flop_cache[key] = count;
        return count;
    }
    else {
        return opcode_flop_cache[key];
    }
}

#define MEM_CHUNK_SIZE 64

static inline ADDRINT mask(ADDRINT ea)  {
    constexpr ADDRINT mask = ~static_cast<ADDRINT>(MEM_CHUNK_SIZE - 1);
    return ea & mask;
}

void load(ADDRINT memea, UINT32 length) {
    ADDRINT start = mask(memea);
    ADDRINT end   = mask(memea + length - 1);
    for(ADDRINT addr = start ; addr <= end ; addr += MEM_CHUNK_SIZE) {
        mem[addr] = 1;
    }
}

void store(ADDRINT memea, UINT32 length) {
    ADDRINT start = mask(memea);
    ADDRINT end   = mask(memea + length - 1);
    for(ADDRINT addr = start ; addr <= end ; addr += MEM_CHUNK_SIZE) {
        mem[addr] = 1;
    }
}

VOID InstrumentMemInst(INS ins) {
    if (INS_IsMemoryRead(ins) && INS_IsStandardMemop(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) load,
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYREAD_SIZE,
                        IARG_END);

    }
    if (INS_HasMemoryRead2(ins) && INS_IsStandardMemop(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) load,
                        IARG_MEMORYREAD2_EA,
                        IARG_MEMORYREAD_SIZE,
                        IARG_END);

    }
    // instrument the store
    if (INS_IsMemoryWrite(ins) && INS_IsStandardMemop(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) store,
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

            InstrumentMemInst(ins);

            UINT32 flops = Fp32FlopCount_Cached(ins);

            if (flops == 0) {
                bbl_stats.special[NON_FP32_COUNT]++;
            }
            else {
                bbl_stats.special[FP32_COUNT] += flops;
            }

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

        for (UINT32 i = 0; i < MAX_SPECIAL; i++) {
            if (bbl_stats.special[i] > 0) {
                BBL_InsertCall(
                    bbl,
                    IPOINT_BEFORE,
                    AFUNPTR(docount_special), IARG_FAST_ANALYSIS_CALL,
                    IARG_THREAD_ID,
                    IARG_UINT64, i,
                    IARG_UINT64, bbl_stats.special[i],
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

    mem = std::map<ADDRINT, unsigned int>();

    futex_init(&lock);
    ofs.open(KnobOutfile.Value().c_str(), std::ios::trunc);

    imix_key = PIN_CreateThreadDataKey(FreeThreadData);

    PIN_AddThreadStartFunction(ThreadStart, 0);
    TRACE_AddInstrumentFunction(Trace, 0);
    IMG_AddInstrumentFunction(InstrumentImage, 0);

    PIN_StartProgram();
    return 0;
}
