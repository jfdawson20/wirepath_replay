#ifndef WPR_TIME_H
#define WPR_TIME_H

#define MIN_SLEEP_NS  (50 * 1000) // 50 us

static inline uint64_t wpr_now_ns(void)
{
    const uint64_t tsc    = rte_get_tsc_cycles();
    const uint64_t tsc_hz = rte_get_tsc_hz();

    // Whole seconds since boot
    const uint64_t sec = tsc / tsc_hz;
    // Remainder cycles within the current second
    const uint64_t rem = tsc % tsc_hz;

    // sec * 1e9 is safe: sec is at most ~6e9 even after centuries
    // rem < tsc_hz, so rem * 1e9 is also safe before division
    return sec * 1000000000ULL + (rem * 1000000000ULL) / tsc_hz;
}

/**
* Convert TSC cycles to milliseconds.
* @param tsc
*   Time in TSC cycles.
* @return
*   Time in milliseconds.
**/
static inline double tsc_to_ms(uint64_t tsc)
{
    uint64_t tsc_hz = rte_get_tsc_hz();
    return (double)tsc * 1000.0 / (double)tsc_hz;
}


#endif // WPR_TIME_Hs