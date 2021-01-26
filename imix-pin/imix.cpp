
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
    // std::cerr << std::hex << op << std::dec << std::endl;
    switch (op) {
        case MAGIC_OP_ROI_END:
            DumpStats();
            active = 0;
            break;

        case MAGIC_OP_ROI_BEGIN:
            futex_lock(&lock);
            ASSERT(active == 0, "Tool only supports single threaded tracking!");
            track_tid = tid;
            stats.Clear();
            active = 1;
            futex_unlock(&lock);
            break;
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


int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    futex_init(&lock);
    ofs.open("stats.yaml", std::ios::trunc);

    INS_AddInstrumentFunction(Instruction, 0);

    PIN_StartProgram();
    return 0;
}
