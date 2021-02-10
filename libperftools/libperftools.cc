
#include <iostream>
#include "pin-perf.hh"
#include "counter-perf.hh"

extern "C"
void perf_roi_begin(uint64_t rid, const char * rname, const char * opname) {
    PERF_ROI_BEGIN(rid, rname, opname);
}

extern "C"
void perf_roi_end(uint64_t rid) {
    PERF_ROI_END(rid);
}

PERF_COUNTERS_VARS(global_)

extern "C"
void perf_counters_setup() {
    PERF_COUNTERS_SETUP(global_);
}


extern "C"
void perf_counters_begin() {
    PERF_COUNTERS_BEGIN(global_);
}

extern "C"
void perf_counters_end() {
    PERF_COUNTERS_END(global_);
}

extern "C"
uint64_t perf_counters_ninst() {
    return global_ninst.value;
}

extern "C"
uint64_t perf_counters_ncyc() {
    return global_ncyc.value;
}
