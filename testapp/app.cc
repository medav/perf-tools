
#include <iostream>
#include "pin-perf.hh"


int main() {
    int a;
    float r = 0;

    PERF_ROI_BEGIN(0, "rname", "opname");

    return 0;
}
