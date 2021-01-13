#include "pin.H"
#include <iostream>
#include <fstream>
#define PINTOOL
#include "../../include/perf-hooks.hh"
using std::cerr;
using std::endl;


// To support multiple level calls to START_ROI, we just increment a counter 
// and stop recording if its zero
UINT64 record = 0;
UINT64 roi_counter = 0;

VOID HandleMagicOp(THREADID tid, ADDRINT op) {
    switch (op) {
        case MAGIC_OP_ROI_BEGIN:
            cerr << "ROI_BEGIN" << std::endl;
            record++;
            break;
        case MAGIC_OP_ROI_END:
            cerr << "ROI_END" << std::endl;
            record--;
            break;

        default:
            break;
    }
}


INT32 Usage() {
    cerr <<
        "This tool prints out the number of dynamic instructions executed to stderr.\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

VOID docount() {
    roi_counter++;
}

VOID Instruction(INS ins, VOID *v) {

    if (INS_IsXchg(ins) && INS_OperandReg(ins, 0) == REG_RCX && INS_OperandReg(ins, 1) == REG_RCX) {
        //info("Instrumenting magic op");
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) HandleMagicOp, IARG_THREAD_ID, IARG_REG_VALUE, REG_ECX, IARG_END);
    }

    if (record > 0) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);
    }
}

VOID Fini(INT32 code, VOID *v) {
    std::ofstream ofs("out.log", std::ios::trunc);
    ofs <<  "Count " << roi_counter  << endl;
    
}


int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
