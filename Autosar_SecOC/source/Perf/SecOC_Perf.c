/********************************************************************************************************/
/***********************************************SecOC_Perf.c***********************************************/
/********************************************************************************************************/
/**
 * @file SecOC_Perf.c
 * @brief SPSC ring buffer + drain thread + POSIX shm seqlock implementation.
 *
 * Producers (probe sites) call SecOC_Perf_RecordSample() which:
 *   1. relaxed-loads its own head index
 *   2. acquire-loads the consumer tail to detect overflow
 *   3. writes the record at head
 *   4. release-stores head + 1
 *
 * The drain thread mirrors the protocol on the consumer side, batches records
 * into /tmp/secoc_perf.csv, and updates a seqlock-protected live snapshot in
 * /dev/shm/secoc_perf_live so external monitors can poll without locks.
 *
 * Entire body is gated behind SECOC_PERF_INSTRUMENT - if the macro is not
 * defined this translation unit is empty and the SecOC_Perf_* symbols come
 * from inline stubs in the header instead.
 */

#define _POSIX_C_SOURCE 200809L

#include "Perf/SecOC_Perf.h"

#ifdef SECOC_PERF_INSTRUMENT

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* ---------------------------------------------------------------------- */
/* Configuration                                                          */
/* ---------------------------------------------------------------------- */
#define SECOC_PERF_RING_CAP        (16384U)            /* must be power of 2 */
#define SECOC_PERF_RING_MASK       (SECOC_PERF_RING_CAP - 1U)
#define SECOC_PERF_MAX_PDUS        (64U)
#define SECOC_PERF_DRAIN_PERIOD_NS (5000000L)          /* 5 ms */
#define SECOC_PERF_PCTL_WINDOW     (256U)
#define SECOC_PERF_CSV_PATH        "/tmp/secoc_perf.csv"
#define SECOC_PERF_SHM_NAME        "/secoc_perf_live"
#define SECOC_PERF_CACHE_LINE      (64)

/* ---------------------------------------------------------------------- */
/* Record format (32 bytes)                                               */
/* ---------------------------------------------------------------------- */
typedef struct {
    uint64_t seq;
    uint64_t begin_ns;
    uint64_t end_ns;
    uint16_t pdu_id;
    uint16_t stage;
    uint32_t _pad;
} SecOC_Perf_RecordType;

/* ---------------------------------------------------------------------- */
/* Live shared-memory snapshot                                            */
/* ---------------------------------------------------------------------- */
typedef struct {
    _Atomic uint64_t seq;                                /* odd while writing */
    uint64_t total_count;
    uint64_t last_total_ns;
    uint64_t p50_total_ns;
    uint64_t p95_total_ns;
    uint64_t p99_total_ns;
    uint64_t last_stage_ns[SECOC_PERF_NUM_STAGES];
    uint64_t stage_count [SECOC_PERF_NUM_STAGES];
} SecOC_Perf_LiveShmType;

/* ---------------------------------------------------------------------- */
/* Producer / consumer indices, cache-line aligned to avoid false sharing */
/* ---------------------------------------------------------------------- */
static _Atomic uint64_t g_head __attribute__((aligned(SECOC_PERF_CACHE_LINE)));
static _Atomic uint64_t g_tail __attribute__((aligned(SECOC_PERF_CACHE_LINE)));

static SecOC_Perf_RecordType g_ring[SECOC_PERF_RING_CAP]
    __attribute__((aligned(SECOC_PERF_CACHE_LINE)));

/* Per-PDU "begin of total span" timestamps */
static _Atomic uint64_t g_total_begin[SECOC_PERF_MAX_PDUS];

/* Monotonic record sequence */
static _Atomic uint64_t g_seq;

/* Drain thread bookkeeping */
static pthread_t       g_drain_thread;
static _Atomic int     g_drain_running;
static _Atomic int     g_drain_started;
static FILE           *g_csv = NULL;
static int             g_shm_fd = -1;
static SecOC_Perf_LiveShmType *g_live = NULL;

/* Rolling window for TX_TOTAL percentile estimation */
static uint64_t g_pctl_window[SECOC_PERF_PCTL_WINDOW];
static size_t   g_pctl_pos;
static size_t   g_pctl_filled;

/* Counter of dropped records due to overflow (lossy mode) */
static _Atomic uint64_t g_dropped;

/* ---------------------------------------------------------------------- */
/* Helpers                                                                */
/* ---------------------------------------------------------------------- */
static int u64_cmp(const void *a, const void *b) {
    const uint64_t x = *(const uint64_t *)a;
    const uint64_t y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

static uint64_t wallclock_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0U;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void update_pctl_window(uint64_t delta) {
    g_pctl_window[g_pctl_pos] = delta;
    g_pctl_pos = (g_pctl_pos + 1U) % SECOC_PERF_PCTL_WINDOW;
    if (g_pctl_filled < SECOC_PERF_PCTL_WINDOW) {
        g_pctl_filled++;
    }
}

static void compute_pctls(uint64_t *p50, uint64_t *p95, uint64_t *p99) {
    *p50 = 0U;
    *p95 = 0U;
    *p99 = 0U;
    if (g_pctl_filled == 0U) {
        return;
    }
    uint64_t tmp[SECOC_PERF_PCTL_WINDOW];
    memcpy(tmp, g_pctl_window, g_pctl_filled * sizeof(uint64_t));
    qsort(tmp, g_pctl_filled, sizeof(uint64_t), u64_cmp);
    const size_t n = g_pctl_filled;
    *p50 = tmp[(n * 50U) / 100U];
    *p95 = tmp[(n > 1U) ? ((n * 95U) / 100U) : 0U];
    *p99 = tmp[(n > 1U) ? ((n * 99U) / 100U) : 0U];
}

/* ---------------------------------------------------------------------- */
/* Live shm seqlock writers                                               */
/* ---------------------------------------------------------------------- */
static void live_publish_record(const SecOC_Perf_RecordType *rec, uint64_t delta) {
    if (g_live == NULL) {
        return;
    }
    /* Begin write: bump seq to odd */
    uint64_t s = atomic_load_explicit(&g_live->seq, memory_order_relaxed);
    atomic_store_explicit(&g_live->seq, s + 1U, memory_order_release);

    if (rec->stage < SECOC_PERF_NUM_STAGES) {
        g_live->last_stage_ns[rec->stage] = delta;
        g_live->stage_count [rec->stage]++;
    }

    if (rec->stage == (uint16_t)SECOC_PERF_STAGE_TX_TOTAL) {
        g_live->last_total_ns = delta;
        g_live->total_count++;
        update_pctl_window(delta);
        compute_pctls(&g_live->p50_total_ns,
                      &g_live->p95_total_ns,
                      &g_live->p99_total_ns);
    }

    /* End write: bump seq to next even */
    atomic_store_explicit(&g_live->seq, s + 2U, memory_order_release);
}

/* ---------------------------------------------------------------------- */
/* Drain thread                                                           */
/* ---------------------------------------------------------------------- */
static void drain_once(void) {
    const uint64_t tail = atomic_load_explicit(&g_tail, memory_order_relaxed);
    const uint64_t head = atomic_load_explicit(&g_head, memory_order_acquire);

    uint64_t cursor = tail;
    while (cursor != head) {
        const SecOC_Perf_RecordType rec = g_ring[cursor & SECOC_PERF_RING_MASK];
        const uint64_t delta = (rec.end_ns >= rec.begin_ns)
                               ? (rec.end_ns - rec.begin_ns) : 0U;

        if (g_csv != NULL) {
            (void)fprintf(g_csv,
                "%llu,%u,%u,%llu,%llu\n",
                (unsigned long long)rec.seq,
                (unsigned)rec.pdu_id,
                (unsigned)rec.stage,
                (unsigned long long)delta,
                (unsigned long long)wallclock_ns());
        }

        live_publish_record(&rec, delta);

        cursor++;
    }

    if (cursor != tail) {
        atomic_store_explicit(&g_tail, cursor, memory_order_release);
        if (g_csv != NULL) {
            (void)fflush(g_csv);
        }
    }
}

static void *drain_main(void *arg) {
    (void)arg;
    /* Block SIGPIPE on this thread so a closed pipe does not kill the app. */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    (void)pthread_sigmask(SIG_BLOCK, &mask, NULL);

    struct timespec period;
    period.tv_sec  = 0;
    period.tv_nsec = SECOC_PERF_DRAIN_PERIOD_NS;

    while (atomic_load_explicit(&g_drain_running, memory_order_acquire) != 0) {
        drain_once();
        (void)nanosleep(&period, NULL);
    }
    /* Final drain after stop request to flush stragglers. */
    drain_once();
    return NULL;
}

/* ---------------------------------------------------------------------- */
/* Public API                                                             */
/* ---------------------------------------------------------------------- */
int SecOC_Perf_Init(void) {
    if (atomic_load_explicit(&g_drain_started, memory_order_acquire) != 0) {
        return 0; /* idempotent */
    }

    atomic_store_explicit(&g_head, 0U, memory_order_relaxed);
    atomic_store_explicit(&g_tail, 0U, memory_order_relaxed);
    atomic_store_explicit(&g_seq,  0U, memory_order_relaxed);
    atomic_store_explicit(&g_dropped, 0U, memory_order_relaxed);

    for (size_t i = 0; i < SECOC_PERF_MAX_PDUS; ++i) {
        atomic_store_explicit(&g_total_begin[i], 0U, memory_order_relaxed);
    }
    g_pctl_pos = 0U;
    g_pctl_filled = 0U;

    /* Open CSV (truncate). Header row to keep perf_summary.py happy. */
    g_csv = fopen(SECOC_PERF_CSV_PATH, "w");
    if (g_csv != NULL) {
        (void)fprintf(g_csv, "seq,pdu_id,stage,ns_delta,wallclock_ns\n");
        (void)fflush(g_csv);
    }

    /* Open POSIX shm for live snapshot. Failure is non-fatal. */
    g_shm_fd = shm_open(SECOC_PERF_SHM_NAME, O_CREAT | O_RDWR, 0644);
    if (g_shm_fd >= 0) {
        if (ftruncate(g_shm_fd, (off_t)sizeof(SecOC_Perf_LiveShmType)) == 0) {
            void *p = mmap(NULL, sizeof(SecOC_Perf_LiveShmType),
                           PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd, 0);
            if (p != MAP_FAILED) {
                g_live = (SecOC_Perf_LiveShmType *)p;
                memset(g_live, 0, sizeof(*g_live));
                atomic_store_explicit(&g_live->seq, 0U, memory_order_release);
            } else {
                (void)close(g_shm_fd);
                g_shm_fd = -1;
                g_live = NULL;
            }
        } else {
            (void)close(g_shm_fd);
            g_shm_fd = -1;
        }
    }

    atomic_store_explicit(&g_drain_running, 1, memory_order_release);
    if (pthread_create(&g_drain_thread, NULL, drain_main, NULL) != 0) {
        atomic_store_explicit(&g_drain_running, 0, memory_order_release);
        if (g_csv != NULL) { (void)fclose(g_csv); g_csv = NULL; }
        if (g_live != NULL) {
            (void)munmap(g_live, sizeof(SecOC_Perf_LiveShmType));
            g_live = NULL;
        }
        if (g_shm_fd >= 0) { (void)close(g_shm_fd); g_shm_fd = -1; }
        return -1;
    }

    atomic_store_explicit(&g_drain_started, 1, memory_order_release);
    return 0;
}

void SecOC_Perf_Shutdown(void) {
    if (atomic_load_explicit(&g_drain_started, memory_order_acquire) == 0) {
        return;
    }
    atomic_store_explicit(&g_drain_running, 0, memory_order_release);
    (void)pthread_join(g_drain_thread, NULL);
    atomic_store_explicit(&g_drain_started, 0, memory_order_release);

    if (g_csv != NULL) {
        (void)fflush(g_csv);
        (void)fclose(g_csv);
        g_csv = NULL;
    }
    if (g_live != NULL) {
        (void)munmap(g_live, sizeof(SecOC_Perf_LiveShmType));
        g_live = NULL;
    }
    if (g_shm_fd >= 0) {
        (void)close(g_shm_fd);
        g_shm_fd = -1;
        (void)shm_unlink(SECOC_PERF_SHM_NAME);
    }
}

void SecOC_Perf_RecordSample(uint16_t pdu_id, SecOC_Perf_StageType stage,
                             uint64_t begin_ns, uint64_t end_ns) {
    /* Producer side of SPSC ring. */
    const uint64_t head = atomic_load_explicit(&g_head, memory_order_relaxed);
    const uint64_t tail = atomic_load_explicit(&g_tail, memory_order_acquire);

    if ((head - tail) >= SECOC_PERF_RING_CAP) {
        /* Full -> drop. Lossy by design; never block the hot path. */
        atomic_fetch_add_explicit(&g_dropped, 1U, memory_order_relaxed);
        return;
    }

    const uint64_t seq = atomic_fetch_add_explicit(&g_seq, 1U,
                                                   memory_order_relaxed) + 1U;
    SecOC_Perf_RecordType *slot = &g_ring[head & SECOC_PERF_RING_MASK];
    slot->seq      = seq;
    slot->begin_ns = begin_ns;
    slot->end_ns   = end_ns;
    slot->pdu_id   = pdu_id;
    slot->stage    = (uint16_t)stage;
    slot->_pad     = 0U;

    atomic_store_explicit(&g_head, head + 1U, memory_order_release);
}

void SecOC_Perf_TotalBegin(uint16_t pdu_id) {
    if ((unsigned)pdu_id >= SECOC_PERF_MAX_PDUS) {
        return;
    }
    atomic_store_explicit(&g_total_begin[pdu_id], SecOC_Perf_NowNs(),
                          memory_order_release);
}

void SecOC_Perf_TotalEnd(uint16_t pdu_id) {
    if ((unsigned)pdu_id >= SECOC_PERF_MAX_PDUS) {
        return;
    }
    const uint64_t begin = atomic_exchange_explicit(&g_total_begin[pdu_id], 0U,
                                                    memory_order_acquire);
    if (begin == 0U) {
        return; /* TotalEnd without matching TotalBegin */
    }
    const uint64_t end = SecOC_Perf_NowNs();
    SecOC_Perf_RecordSample(pdu_id, SECOC_PERF_STAGE_TX_TOTAL, begin, end);
}

#endif /* SECOC_PERF_INSTRUMENT */
