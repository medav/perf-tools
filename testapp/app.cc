
#include <iostream>
#include "pin-perf.hh"
#include "counter-perf.hh"


int main() {
    int a;
    float r = 0;

    PERF_COUNTERS_BEGIN();
    PERF_ROI_BEGIN(0, "rname", "opname");
    for (a = 0; a < 1000000000; a++) {
        r += 1.0f;
    }
    PERF_ROI_END(0);
    PERF_COUNTERS_END();

    std::cout << r << std::endl;
    std::cout << ninst.value << std::endl;

    return 0;
}
