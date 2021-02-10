
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdint.h>
#include "locks.h"

#include "pin.H"
#define PINTOOL
#include "../include/perf-hooks.hh"

const UINT32 MAX_INDEX = 4096;
const UINT64 MAX_REGION = 4096;

KNOB<std::string> KnobOutfile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "trace.yaml", "output filename");

KNOB<UINT64> KnobRegion(KNOB_MODE_WRITEONCE, "pintool",
    "r", 0, "region to track");

TLS_KEY imix_key;

uint32_t lock;
std::ofstream ofs;

struct ThreadData {
    BOOL active;

    ThreadData() : active{false} {}
};

LOCALFUN std::string IndexToOpcodeString( UINT32 index )
{
    return OPCODE_StringShort(index);
}


VOID HandleMagicOp(THREADID tid, ADDRINT rid) {
    futex_lock(&lock);
    ThreadData * td = (ThreadData *)PIN_GetThreadData(imix_key, tid);

    if (!td->r_active[rid]) {
        td->r_starts[rid] = td->cur;
        td->r_active[rid] = true;
    }
    else {
        td->r_active[rid] = false;
        DumpStats(td, tid, rid);
    }

    futex_unlock(&lock);
}

INT32 Usage() {
    return -1;
}

VOID PIN_FAST_ANALYSIS_CALL docount(THREADID tid, UINT64 opcode, UINT64 n) {
    ThreadData * td = (ThreadData *)PIN_GetThreadData(imix_key, tid);
    td->cur.count[opcode] += n;
}

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    std::cout << "New Thread: " << tid << std::endl;
    PIN_SetThreadData(imix_key, new ThreadData(), tid);
}

VOID Instruction(INS ins, VOID *v) {

    if (INS_IsXchg(ins) && INS_OperandReg(ins, 0) == REG_RCX && INS_OperandReg(ins, 1) == REG_RCX) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleMagicOp, IARG_THREAD_ID, IARG_REG_VALUE, REG_ECX, IARG_END);
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

        for ( UINT32 i = 0; i < MAX_INDEX; i++) {
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
