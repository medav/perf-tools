
#include <iostream>
#include <fstream>
#include <vector>
#include <stdint.h>
#include "locks.h"

#include "pin.H"
#define PINTOOL
#include "../../include/pin-perf.hh"



uint32_t lock;
std::ofstream ofs;

VOID HandleMagicOp(THREADID tid, ADDRINT rcx) {
    struct pin_call_args * args =
        (struct pin_call_args *)rcx;

    std::cout << "{"
        << "thread: " << tid << ", "
        << "op: " << args->op << ", "
        << "rid: " << args->rid << ", "
        << "rname: " << args->rname << ", "
        << "opname: " << args->opname
        << "}" << std::endl;
}


INT32 Usage() {
    std::cerr <<
        "This tool prints out the number of dynamic instructions executed to stderr.\n"
        "\n";

    std::cerr << KNOB_BASE::StringKnobSummary();
    std::cerr << std::endl;
    return -1;
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
