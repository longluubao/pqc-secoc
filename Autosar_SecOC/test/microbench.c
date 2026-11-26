#define SECOC_PERF_INSTRUMENT 1
#include "Perf/SecOC_Perf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ITERS 1000000U

static int u64_cmp(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

static void summarise(const char *label, uint64_t *deltas, size_t n) {
    qsort(deltas, n, sizeof(uint64_t), u64_cmp);
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) sum += (double)deltas[i];
    printf("%-30s n=%zu  min=%llu  p50=%llu  p95=%llu  p99=%llu  max=%llu  mean=%.1f\n",
           label, n,
           (unsigned long long)deltas[0],
           (unsigned long long)deltas[n / 2],
           (unsigned long long)deltas[(n * 95) / 100],
           (unsigned long long)deltas[(n * 99) / 100],
           (unsigned long long)deltas[n - 1],
           sum / (double)n);
}

int main(void) {
    if (SecOC_Perf_Init() != 0) {
        fprintf(stderr, "SecOC_Perf_Init failed\n");
        return 1;
    }
    static uint64_t deltas[ITERS];

    for (size_t i = 0; i < ITERS; ++i) {
        uint64_t a = SecOC_Perf_NowNs();
        uint64_t b = SecOC_Perf_NowNs();
        deltas[i] = b - a;
    }
    summarise("clock_gettime back-to-back", deltas, ITERS);

    for (size_t i = 0; i < ITERS; ++i) {
        uint64_t a = SecOC_Perf_NowNs();
        PERF_PROBE_BEGIN(bench);
        PERF_PROBE_END(bench, 0, SECOC_PERF_STAGE_TX_TOTAL);
        uint64_t b = SecOC_Perf_NowNs();
        deltas[i] = b - a;
    }
    summarise("BEGIN/END probe pair total ", deltas, ITERS);

    SecOC_Perf_Shutdown();
    return 0;
}
