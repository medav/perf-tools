
#include <iostream>
#include <fstream>
#include <vector>
#include <stdint.h>
#include "locks.h"

#include "pin.H"
#define PINTOOL
#include "../include/perf-hooks.hh"


// To support multiple level calls to START_ROI, we just increment a counter 
// and stop recording if its zero
UINT64 record = 0;
UINT64 roi_counter = 0;

std::vector<INT64> active;
std::vector<UINT64> counters;

uint32_t lock;
std::ofstream ofs;

VOID HandleMagicOp(THREADID tid, ADDRINT op) {
    // std::cerr << std::hex << op << std::dec << std::endl;
    switch (op) {
        case MAGIC_OP_ROI_END:
            ofs << "{"
                << "thread: " << tid << ", "
                << "rid: " << active[tid] << ", "
                << "icount: " << counters[tid]
                << "}" << std::endl;
            
            active[tid] = -1;
            break;

        default:
            // std::cerr << "BEGIN" << std::endl;
            futex_lock(&lock);
            if (counters.size() <= tid) {
                counters.resize(tid + 1);
                active.resize(tid + 1, -1);
            }

            counters[tid] = 0;
            active[tid] = op;
            futex_unlock(&lock);
            break;
    }
}


INT32 Usage() {
    std::cerr <<
        "This tool prints out the number of dynamic instructions executed to stderr.\n"
        "\n";

    std::cerr << KNOB_BASE::StringKnobSummary();
    std::cerr << std::endl;
    return -1;
}

VOID docount(THREADID tid) {
    if (tid < active.size() && active[tid] != -1) counters[tid]++;
}

VOID Instruction(INS ins, VOID *v) {

    if (INS_IsXchg(ins) && INS_OperandReg(ins, 0) == REG_RCX && INS_OperandReg(ins, 1) == REG_RCX) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleMagicOp, IARG_THREAD_ID, IARG_REG_VALUE, REG_ECX, IARG_END);
    }

    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_THREAD_ID, IARG_END);
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
