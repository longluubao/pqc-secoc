/********************************************************************************************************/
/***********************************************SecOC_Perf.h***********************************************/
/********************************************************************************************************/
/**
 * @file SecOC_Perf.h
 * @brief Lightweight performance instrumentation for SecOC pipeline (TL-Performance spec).
 *
 * Probes record per-stage latency samples into a lock-free SPSC ring. A drain
 * thread flushes records to /tmp/secoc_perf.csv every 5 ms and updates a live
 * seqlock-protected snapshot in /dev/shm/secoc_perf_live.
 *
 * When SECOC_PERF_INSTRUMENT is not defined, all probes compile to no-ops and
 * runtime overhead is zero.
 */
#ifndef INCLUDE_PERF_SECOC_PERF_H_
#define INCLUDE_PERF_SECOC_PERF_H_

#include <stdint.h>

typedef enum {
    SECOC_PERF_STAGE_IF_TRANSMIT     = 0,
    SECOC_PERF_STAGE_FRESHNESS_FETCH = 1,
    SECOC_PERF_STAGE_AUTH_GEN        = 2,
    SECOC_PERF_STAGE_PQC_MLDSA_SIGN  = 3,
    SECOC_PERF_STAGE_SECPDU_BUILD    = 4,
    SECOC_PERF_STAGE_PDUR_HANDOFF    = 5,
    SECOC_PERF_STAGE_SOAD_DISPATCH   = 6,
    SECOC_PERF_STAGE_ETHDRV_SEND     = 7,
    SECOC_PERF_STAGE_TX_TOTAL        = 8,
    SECOC_PERF_NUM_STAGES            = 9
} SecOC_Perf_StageType;

#ifdef SECOC_PERF_INSTRUMENT

#include <time.h>

int  SecOC_Perf_Init(void);
void SecOC_Perf_Shutdown(void);
void SecOC_Perf_RecordSample(uint16_t pdu_id, SecOC_Perf_StageType stage,
                             uint64_t begin_ns, uint64_t end_ns);

static inline uint64_t SecOC_Perf_NowNs(void) {
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#define PERF_PROBE_BEGIN(_tag) \
    const uint64_t _secoc_perf_begin_##_tag = SecOC_Perf_NowNs()

#define PERF_PROBE_END(_tag, _pdu_id, _stage)                                  \
    do {                                                                       \
        const uint64_t _secoc_perf_end_##_tag = SecOC_Perf_NowNs();            \
        SecOC_Perf_RecordSample((uint16_t)(_pdu_id), (_stage),                 \
                                _secoc_perf_begin_##_tag,                      \
                                _secoc_perf_end_##_tag);                       \
    } while (0)

void SecOC_Perf_TotalBegin(uint16_t pdu_id);
void SecOC_Perf_TotalEnd  (uint16_t pdu_id);

#else /* SECOC_PERF_INSTRUMENT not defined - zero overhead stubs */

#define PERF_PROBE_BEGIN(_tag)                          ((void)0)
#define PERF_PROBE_END(_tag, _pdu_id, _stage)           ((void)0)

static inline int  SecOC_Perf_Init(void)               { return 0; }
static inline void SecOC_Perf_Shutdown(void)           { }
static inline void SecOC_Perf_TotalBegin(uint16_t id)  { (void)id; }
static inline void SecOC_Perf_TotalEnd  (uint16_t id)  { (void)id; }

#endif

#endif /* INCLUDE_PERF_SECOC_PERF_H_ */
