/********************************************************************************************************/
/****************************************** TX PERF 10K BENCHMARK ***************************************/
/********************************************************************************************************/
/* Legacy harness, kept for reference. Its direct ML-DSA calls use the empty FIPS 204 context, not the
 * 64-byte PDU signature context of the gateway. The harnesses of record are those under bench/. */
/**
 * @file tx_perf_10k.c
 * @brief Standalone PQC sign/verify benchmark driver (NEW_REQ_PLAN Item #1)
 *
 * @details Drives PQC_MLDSA_Sign / PQC_MLDSA_Verify directly (no SecOC stack), in a
 *          hot loop large enough to satisfy the thesis committee's N>=10,000 + warmup
 *          discard requirement. Uses CLOCK_MONOTONIC for sub-microsecond timing
 *          probes baked into this driver -- intentionally independent of the
 *          SecOC_Perf ring buffer, so this benchmark is robust against any
 *          probe-related changes elsewhere in the tree.
 *
 *          Output CSV columns: seq,phase,ns_delta,wallclock_ns
 *              phase = keygen | sign | verify
 *              ns_delta   = end_ns - start_ns of the operation
 *              wallclock_ns = end_ns (monotonic clock) -- enables per-iteration
 *                             pacing / drift analysis in post processing.
 *
 *          Discard of the first NUM_WARMUP rows is a post-processing step
 *          (scripts/perf_summary_extended.py --drop-warmup N). This driver
 *          records every iteration verbatim so the warmup data remains
 *          inspectable if needed.
 *
 *          Invocation:
 *              tx_perf_10k [NUM_ITERATIONS]
 *
 *          If NUM_ITERATIONS is omitted, the value of the NUM_ITERATIONS environment
 *          variable is used, falling back to the compile-time default
 *          (NUM_WARMUP + NUM_MEASURE = 1000 + 10000 = 11000).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>

#include "Std_Types.h"
#include "PQC.h"

/********************************************************************************************************/
/********************************************* CONSTANTS ************************************************/
/********************************************************************************************************/

#define DEFAULT_WARMUP_ITERS    1000U
#define DEFAULT_MEASURE_ITERS   10000U
#define DEFAULT_TOTAL_ITERS     (DEFAULT_WARMUP_ITERS + DEFAULT_MEASURE_ITERS)

/* 20-byte authentic PDU payload as required by Item #1 plan */
#define PDU_PAYLOAD_BYTES       20U

#define OUTPUT_CSV_PATH         "/tmp/tx_perf_10k.csv"

/********************************************************************************************************/
/********************************************* TIMING UTILITIES *****************************************/
/********************************************************************************************************/

static inline uint64_t now_ns(void) {
    struct timespec ts;
    /* clock_gettime(CLOCK_MONOTONIC) -- nanosecond resolution, monotonic so it is
     * unaffected by wall-clock adjustments such as NTP slew. This is the same
     * clock the SecOC_Perf probes use, so cross-validation with the in-tree
     * probe ring remains apples-to-apples. */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        return 0U;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/********************************************************************************************************/
/********************************************* PHASE RUNNERS ********************************************/
/********************************************************************************************************/

/* Generate a single ML-DSA-65 keypair, recording the keygen latency as a
 * one-shot phase=keygen row. Cost is amortised across all subsequent sign/verify
 * iterations but the committee asked for it to be visible in the data. */
static int run_keygen_phase(FILE* csv, PQC_MLDSA_KeyPairType* keypair) {
    uint64_t start = now_ns();
    Std_ReturnType result = PQC_MLDSA_KeyGen(keypair);
    uint64_t end = now_ns();

    if (result != PQC_E_OK) {
        fprintf(stderr, "[tx_perf_10k] PQC_MLDSA_KeyGen failed (%d)\n", (int)result);
        return -1;
    }
    fprintf(csv, "0,keygen,%" PRIu64 ",%" PRIu64 "\n",
            (uint64_t)(end - start), end);
    return 0;
}

/* Hot sign loop. The same 20-byte payload is signed each iteration. We do NOT
 * vary the message to keep cache state representative of the in-vehicle workload
 * (the same authentic PDU layout is signed repeatedly in steady state). */
static int run_sign_phase(FILE* csv,
                          const PQC_MLDSA_KeyPairType* keypair,
                          const uint8* payload,
                          uint32 total_iters,
                          uint8* sig_buf,
                          uint32* out_last_sig_len) {
    /* sig_len is passed by pointer to PQC_MLDSA_Sign whose contract is
     * `uint32*` (AUTOSAR type, which on aarch64 is `unsigned long`, 8 bytes).
     * Using <stdint.h>'s uint32_t (`unsigned int`, 4 bytes) would silently
     * corrupt the upper half of the word -- hence the AUTOSAR type. */
    uint32 signature_len = 0U;

    for (uint32 i = 0U; i < total_iters; ++i) {
        uint64_t start = now_ns();
        Std_ReturnType result = PQC_MLDSA_Sign(payload, PDU_PAYLOAD_BYTES, NULL, 0U,
                                               keypair->SecretKey,
                                               sig_buf, &signature_len);
        uint64_t end = now_ns();

        if (result != PQC_E_OK) {
            fprintf(stderr, "[tx_perf_10k] PQC_MLDSA_Sign failed at iter %lu (%d)\n",
                    (unsigned long)i, (int)result);
            return -1;
        }
        fprintf(csv, "%lu,sign,%" PRIu64 ",%" PRIu64 "\n",
                (unsigned long)i, (uint64_t)(end - start), end);
    }
    *out_last_sig_len = signature_len;
    return 0;
}

/* Hot verify loop. The signature produced in the last iteration of the sign
 * phase is reused -- it is a valid signature for `payload`, so verification
 * always succeeds. */
static int run_verify_phase(FILE* csv,
                            const PQC_MLDSA_KeyPairType* keypair,
                            const uint8* payload,
                            const uint8* sig_buf,
                            uint32 signature_len,
                            uint32 total_iters) {
    for (uint32 i = 0U; i < total_iters; ++i) {
        uint64_t start = now_ns();
        Std_ReturnType result = PQC_MLDSA_Verify(payload, PDU_PAYLOAD_BYTES, NULL, 0U,
                                                 sig_buf, signature_len,
                                                 keypair->PublicKey);
        uint64_t end = now_ns();

        if (result != PQC_E_OK) {
            fprintf(stderr, "[tx_perf_10k] PQC_MLDSA_Verify failed at iter %lu (%d)\n",
                    (unsigned long)i, (int)result);
            return -1;
        }
        fprintf(csv, "%lu,verify,%" PRIu64 ",%" PRIu64 "\n",
                (unsigned long)i, (uint64_t)(end - start), end);
    }
    return 0;
}

/********************************************************************************************************/
/*********************************** ITERATION COUNT RESOLUTION *****************************************/
/********************************************************************************************************/

static uint32 resolve_total_iters(int argc, char** argv) {
    /* argv[1] takes precedence, then env NUM_ITERATIONS, then compile-time default */
    if (argc >= 2) {
        long v = strtol(argv[1], NULL, 10);
        if (v > 0 && v <= 10000000L) {
            return (uint32)v;
        }
    }
    const char* env = getenv("NUM_ITERATIONS");
    if (env != NULL) {
        long v = strtol(env, NULL, 10);
        if (v > 0 && v <= 10000000L) {
            return (uint32)v;
        }
    }
    return (uint32)DEFAULT_TOTAL_ITERS;
}

/********************************************************************************************************/
/*********************************** MAIN ***************************************************************/
/********************************************************************************************************/

int main(int argc, char** argv) {
    uint32 total_iters = resolve_total_iters(argc, argv);

    printf("[tx_perf_10k] starting -- total iterations = %lu (warmup discard handled in post)\n",
           (unsigned long)total_iters);
    printf("[tx_perf_10k] output CSV: %s\n", OUTPUT_CSV_PATH);

    /* PQC bootstrap. Required so liboqs internal RNG and KAT material are set up. */
    if (PQC_Init() != PQC_E_OK) {
        fprintf(stderr, "[tx_perf_10k] PQC_Init failed\n");
        return 1;
    }

    /* Build a deterministic 20-byte authentic PDU payload. The pattern (i & 0xFF)
     * is conventional in the SecOC test corpus -- see test_pqc_standalone.c -- so
     * results are directly comparable to the existing benchmark suite. */
    uint8 payload[PDU_PAYLOAD_BYTES];
    for (uint32 i = 0U; i < PDU_PAYLOAD_BYTES; ++i) {
        payload[i] = (uint8)(i & 0xFFU);
    }

    /* Open CSV before doing any heavy crypto so a permissions issue surfaces fast. */
    FILE* csv = fopen(OUTPUT_CSV_PATH, "w");
    if (csv == NULL) {
        fprintf(stderr, "[tx_perf_10k] cannot open %s for writing: %s\n",
                OUTPUT_CSV_PATH, strerror(errno));
        return 2;
    }
    fprintf(csv, "seq,phase,ns_delta,wallclock_ns\n");

    /* Phase 0: keygen (one shot). */
    PQC_MLDSA_KeyPairType keypair;
    memset(&keypair, 0, sizeof(keypair));
    if (run_keygen_phase(csv, &keypair) != 0) {
        fclose(csv);
        return 3;
    }
    printf("[tx_perf_10k] keygen complete\n");

    /* Phase 1: hot sign loop. */
    uint8 signature[PQC_MLDSA_SIGNATURE_BYTES];
    uint32 signature_len = 0U;
    if (run_sign_phase(csv, &keypair, payload, total_iters,
                       signature, &signature_len) != 0) {
        fclose(csv);
        return 4;
    }
    printf("[tx_perf_10k] sign phase complete (%lu iters, last sig len=%lu)\n",
           (unsigned long)total_iters, (unsigned long)signature_len);

    /* Phase 2: hot verify loop -- identical iteration count so both phases share
     * the same warmup-discard rule in post processing. */
    if (run_verify_phase(csv, &keypair, payload, signature,
                         signature_len, total_iters) != 0) {
        fclose(csv);
        return 5;
    }
    printf("[tx_perf_10k] verify phase complete (%lu iters)\n",
           (unsigned long)total_iters);

    fclose(csv);
    printf("[tx_perf_10k] done. %lu iterations per phase recorded to %s\n",
           (unsigned long)total_iters, OUTPUT_CSV_PATH);
    return 0;
}
