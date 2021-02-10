
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdint.h>
#include "locks.h"

#include "pin.H"
#define PINTOOL
#include "../../include/pin-perf.hh"

const UINT32 MAX_INDEX = 4096;
const UINT64 MAX_REGION = 4096;

KNOB<BOOL> KnobVerbose(KNOB_MODE_WRITEONCE, "pintool",
    "v", "FALSE", "Verbose (debug) output");

KNOB<std::string> KnobOutfile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "stats.yaml", "output filename");

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

struct RegionData {
    BOOL active;
    Stats start;
    std::string rname;
    std::string opname;

    RegionData() : active(false), start(), rname(), opname() {}
};

struct ThreadData {
    RegionData regions[MAX_REGION];
    Stats cur;

    ThreadData() : regions(), cur() {}
};

LOCALFUN std::string IndexToOpcodeString( UINT32 index )
{
    return OPCODE_StringShort(index);
}

VOID DumpStats(THREADID tid, UINT64 rid, RegionData& rd, Stats& stats) {
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

VOID HandleMagicOp(THREADID tid, ADDRINT rcx) {
    struct pin_call_args * args =
        (struct pin_call_args *)rcx;

    DEBUG(
        "HandleMagicOp: tid = " << tid
        << ", op = " << args->op);

    ThreadData * td = (ThreadData *)PIN_GetThreadData(imix_key, tid);
    RegionData& rd = td->regions[args->rid];

    if (args->op == OP_ROI_BEGIN) {
        ASSERT(!rd.active, "OP_ROI_BEGIN isn't reentrant!");
        rd.start = td->cur;
        rd.active = true;
        rd.rname = args->rname;
        rd.opname = args->opname;
    }
    else if (args->op == OP_ROI_END) {
        ASSERT(rd.active, "ROI_END called before BEGIN?!");
        rd.active = false;
        Stats stats = td->cur - rd.start;
        futex_lock(&lock);
        DumpStats(tid, args->rid, rd, stats);
        futex_unlock(&lock);
    }
}

INT32 Usage() {
    return -1;
}

VOID PIN_FAST_ANALYSIS_CALL docount(THREADID tid, UINT64 opcode, UINT64 n) {
    ThreadData * td = (ThreadData *)PIN_GetThreadData(imix_key, tid);
    td->cur.count[opcode] += n;
}

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
    PIN_SetThreadData(imix_key, new ThreadData(), tid);
}

VOID Instruction(INS ins, VOID *v) {
    if (INS_IsXchg(ins) && INS_OperandReg(ins, 0) == REG_RCX && INS_OperandReg(ins, 1) == REG_RCX) {
        INS_InsertCall(
            ins,
            IPOINT_BEFORE,
            (AFUNPTR) HandleMagicOp,
            IARG_THREAD_ID,
            IARG_REG_VALUE, REG_RCX,
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
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    futex_init(&lock);
    ofs.open(KnobOutfile.Value().c_str(), std::ios::trunc);

    imix_key = PIN_CreateThreadDataKey(FreeThreadData);

    PIN_AddThreadStartFunction(ThreadStart, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    TRACE_AddInstrumentFunction(Trace, 0);

    PIN_StartProgram();
    return 0;
}
