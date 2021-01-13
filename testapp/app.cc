
#include <iostream>
#include "perf-hooks.hh"


int main() {
    int a, r = 0;

    PERF_ROI_BEGIN();
    for (a = 0; a < 1000; a++) {
        r += a;
    }
    PERF_ROI_END();

    std::cout << r << std::endl;

    return 0;
}
