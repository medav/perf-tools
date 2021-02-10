
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
const UINT32 INDEX_SPECIAL =  3000;
const UINT32 MAX_MEM_SIZE = 520;


typedef UINT64 COUNTER;

class STATS
{
  public:
    COUNTER count[MAX_INDEX];

    VOID Clear()
    {
        for ( UINT32 i = 0; i < MAX_INDEX; i++)
        {
            count[i] = 0;
        }
    }
};

STATS stats;
THREADID track_tid;
UINT64 active = 0;

uint32_t lock;
std::ofstream ofs;

KNOB<BOOL> KnobCountAll(KNOB_MODE_WRITEONCE, "pintool",
    "a", "0", "count all instructions");

KNOB<UINT64> KnobRegion(KNOB_MODE_WRITEONCE, "pintool",
    "r", "0", "specify region to track");

LOCALFUN std::string IndexToOpcodeString( UINT32 index )
{
    return OPCODE_StringShort(index);
}

VOID DumpStats() {
    UINT64 total = 0;

    for ( UINT32 i = 0; i < MAX_INDEX; i++)
    {
        total += stats.count[i];
    }

    ofs << "- { tid: " << track_tid << ","
        << " total: " << total << ", "
        << " stats: {";

    for ( UINT32 i = 0; i < MAX_INDEX; i++)
    {
        if (stats.count[i] > 0) {
            ofs << IndexToOpcodeString(i) << ": " << stats.count[i] << ", ";
        }
    }

    ofs << "}}" << std::endl;
}

VOID HandleMagicOp(THREADID tid, ADDRINT op) {
    if (KnobCountAll.Value() != 0) return;
    std::cerr << std::hex << op << std::dec << std::endl;

    if (op == KnobRegion.Value()) {
        if (!active) {
            futex_lock(&lock);
            track_tid = tid;
            stats.Clear();
            active = 1;
            futex_unlock(&lock);
        }
        else {
            DumpStats();
            active = 0;
        }
    }
}

INT32 Usage() {
    return -1;
}

VOID PIN_FAST_ANALYSIS_CALL docount(COUNTER * counter) {
    (*counter) += active;
}

VOID Instruction(INS ins, VOID *v) {

    if (INS_IsXchg(ins) && INS_OperandReg(ins, 0) == REG_RCX && INS_OperandReg(ins, 1) == REG_RCX) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleMagicOp, IARG_THREAD_ID, IARG_REG_VALUE, REG_ECX, IARG_END);
    }

    INS_InsertCall(
        ins,
        IPOINT_BEFORE,
        AFUNPTR(docount), IARG_FAST_ANALYSIS_CALL,
        IARG_PTR, &(stats.count[INS_Opcode(ins)]),
        IARG_END);

}

VOID Fini(INT32 code, VOID *v) {
    if (KnobCountAll.Value() != 0) {
        DumpStats();
    }
}

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    futex_init(&lock);
    ofs.open("stats.yaml", std::ios::trunc);

    if (KnobCountAll.Value() != 0) {
        active = 1;
    }

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}
