/********************************************************************************************************/
/****************************************** PHASE COMPARISON BENCHMARK **********************************/
/********************************************************************************************************/
/* Legacy harness, kept for reference. Its direct ML-DSA calls (phase A) use the empty FIPS 204 context;
 * the Csm path (phase B) signs under the 64-byte PDU signature context. The two phases therefore do not
 * sign the same input, and their difference is not the overhead of the Csm layer alone. The harnesses
 * of record are those under bench/. */
/**
 * @file phase_compare.c
 * @brief 2-phase PQC sign/verify benchmark (NEW_REQ_PLAN Item #4 -- partial)
 *
 * @details NEW_REQ_PLAN.md Item #4 calls for a 4-phase comparison:
 *              Phase A -- Standalone direct PQC_MLDSA_Sign/Verify
 *              Phase B -- Csm_SignatureGenerate/Verify (wraps PQC)
 *              Phase C -- SecOC loopback (full authenticate_PQC -> verify_PQC)
 *              Phase D -- SecOC Pi-pinned (same as C but with taskset)
 *
 *          Phases C and D require a SECOC_PERF_LOOPBACK_MODE guard inside
 *          source/SecOC/SecOC.c which is outside the scope of this driver.
 *          To keep this driver purely additive
 *          (no source modifications outside of the test/ directory + CMakeLists),
 *          this driver implements Phases A and B only. The 2-phase comparison
 *          is enough to resolve the "Standalone vs Csm-integrated" anomaly the
 *          thesis committee flagged -- Phases C and D can be appended to the
 *          same CSV in a follow-up session.
 *
 *          Output CSV columns: phase,seq,ns_delta
 *              phase = A_Standalone_Sign | A_Standalone_Verify |
 *                      B_CsmIntegrated_Sign | B_CsmIntegrated_Verify
 *              seq   = 0..(NUM_WARMUP + NUM_MEASURE - 1), warmup discard is a
 *                      post-processing step (see perf_summary_extended.py).
 *
 *          Invocation:
 *              phase_compare [NUM_ITERATIONS]
 *
 *          NUM_ITERATIONS includes warmup. Default: 11000 = 1000 warmup +
 *          10000 measurement. Environment variable NUM_ITERATIONS overrides
 *          the default if argv[1] is absent.
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
#include "Csm/Csm.h"
#include "SecOC/SecOC_Cfg.h"

/********************************************************************************************************/
/********************************************* CONSTANTS ************************************************/
/********************************************************************************************************/

#define DEFAULT_WARMUP_ITERS    1000U
#define DEFAULT_MEASURE_ITERS   10000U
#define DEFAULT_TOTAL_ITERS     (DEFAULT_WARMUP_ITERS + DEFAULT_MEASURE_ITERS)

/* 256-byte message size -- matches the NEW_REQ_PLAN.md Item #4 spec
 * ("on the same byte buffer, same message size (256 B)"). This is the
 * "typical authentic PDU" size used by the existing comparison harness. */
#define PHASE_COMPARE_MSG_BYTES 256U

#define OUTPUT_CSV_PATH         "/tmp/phase_compare.csv"

/********************************************************************************************************/
/********************************************* TIMING UTILITIES *****************************************/
/********************************************************************************************************/

static inline uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        return 0U;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/********************************************************************************************************/
/********************************************* PHASE RUNNERS ********************************************/
/********************************************************************************************************/

/* --- Phase A: direct PQC_MLDSA_Sign / PQC_MLDSA_Verify (standalone) --- */

static int phase_a_sign(FILE* csv,
                        const PQC_MLDSA_KeyPairType* keypair,
                        const uint8* msg, uint32 msg_len,
                        uint32 iters,
                        uint8* sig_buf,
                        uint32* out_sig_len) {
    /* AUTOSAR `uint32` (= unsigned long on aarch64, 8 bytes) is used everywhere
     * a pointer is passed to PQC/Csm so the function-pointer ABI lines up. */
    uint32 sig_len = 0U;
    for (uint32 i = 0U; i < iters; ++i) {
        uint64_t start = now_ns();
        Std_ReturnType result = PQC_MLDSA_Sign(msg, msg_len, NULL, 0U,
                                               keypair->SecretKey,
                                               sig_buf, &sig_len);
        uint64_t end = now_ns();
        if (result != PQC_E_OK) {
            fprintf(stderr, "[phase_compare] Phase A sign failed at iter %lu\n",
                    (unsigned long)i);
            return -1;
        }
        fprintf(csv, "A_Standalone_Sign,%lu,%" PRIu64 "\n",
                (unsigned long)i, (uint64_t)(end - start));
    }
    *out_sig_len = sig_len;
    return 0;
}

static int phase_a_verify(FILE* csv,
                          const PQC_MLDSA_KeyPairType* keypair,
                          const uint8* msg, uint32 msg_len,
                          const uint8* sig, uint32 sig_len,
                          uint32 iters) {
    for (uint32 i = 0U; i < iters; ++i) {
        uint64_t start = now_ns();
        Std_ReturnType result = PQC_MLDSA_Verify(msg, msg_len, NULL, 0U,
                                                 sig, sig_len,
                                                 keypair->PublicKey);
        uint64_t end = now_ns();
        if (result != PQC_E_OK) {
            fprintf(stderr, "[phase_compare] Phase A verify failed at iter %lu\n",
                    (unsigned long)i);
            return -1;
        }
        fprintf(csv, "A_Standalone_Verify,%lu,%" PRIu64 "\n",
                (unsigned long)i, (uint64_t)(end - start));
    }
    return 0;
}

/* --- Phase B: Csm_SignatureGenerate / Csm_SignatureVerify (integrated) --- */

static int phase_b_sign(FILE* csv,
                        const uint8* msg, uint32 msg_len,
                        uint32 iters,
                        uint8* sig_buf,
                        uint32* out_sig_len) {
    uint32 sig_len = 0U;
    for (uint32 i = 0U; i < iters; ++i) {
        uint64_t start = now_ns();
        Std_ReturnType result = Csm_SignatureGenerate(CSM_JOBID,
                                                      CRYPTO_OPERATIONMODE_SINGLECALL,
                                                      msg, msg_len,
                                                      sig_buf, &sig_len);
        uint64_t end = now_ns();
        if (result != E_OK) {
            fprintf(stderr, "[phase_compare] Phase B sign failed at iter %lu (rc=%d)\n",
                    (unsigned long)i, (int)result);
            return -1;
        }
        fprintf(csv, "B_CsmIntegrated_Sign,%lu,%" PRIu64 "\n",
                (unsigned long)i, (uint64_t)(end - start));
    }
    *out_sig_len = sig_len;
    return 0;
}

static int phase_b_verify(FILE* csv,
                          const uint8* msg, uint32 msg_len,
                          const uint8* sig, uint32 sig_len,
                          uint32 iters) {
    Crypto_VerifyResultType verify_result = CRYPTO_E_VER_NOT_OK;
    for (uint32 i = 0U; i < iters; ++i) {
        uint64_t start = now_ns();
        Std_ReturnType result = Csm_SignatureVerify(CSM_JOBID_VERIFY_LOOPBACK,
                                                    CRYPTO_OPERATIONMODE_SINGLECALL,
                                                    msg, msg_len,
                                                    sig, sig_len,
                                                    &verify_result);
        uint64_t end = now_ns();
        if (result != E_OK || verify_result != CRYPTO_E_VER_OK) {
            fprintf(stderr,
                    "[phase_compare] Phase B verify failed at iter %lu (rc=%d vr=%d)\n",
                    (unsigned long)i, (int)result, (int)verify_result);
            return -1;
        }
        fprintf(csv, "B_CsmIntegrated_Verify,%lu,%" PRIu64 "\n",
                (unsigned long)i, (uint64_t)(end - start));
    }
    return 0;
}

/********************************************************************************************************/
/*********************************** ITERATION COUNT RESOLUTION *****************************************/
/********************************************************************************************************/

static uint32 resolve_total_iters(int argc, char** argv) {
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

    printf("[phase_compare] starting -- total iterations per phase = %lu\n",
           (unsigned long)total_iters);
    printf("[phase_compare] output CSV: %s\n", OUTPUT_CSV_PATH);
    printf("[phase_compare] message size: %u bytes\n", PHASE_COMPARE_MSG_BYTES);

    /* --- PQC bootstrap (used by both Phase A direct calls and indirectly by Csm) --- */
    if (PQC_Init() != PQC_E_OK) {
        fprintf(stderr, "[phase_compare] PQC_Init failed\n");
        return 1;
    }

    /* --- Csm bootstrap (Phase B). Csm_Init(NULL) selects DEMO_FILE_AUTO mode,
     * which load-or-generates an ML-DSA keypair on disk. The resulting key
     * lives inside Csm_KeyStore so Csm_SignatureGenerate works out of the box. */
    Csm_Init(NULL);

    /* --- Standalone keypair for Phase A. We use a *different* keypair than the
     * Csm one so the two phases are honestly independent -- this mirrors what
     * test_pqc_standalone.c does (it generates its own keypair). */
    PQC_MLDSA_KeyPairType phase_a_keypair;
    memset(&phase_a_keypair, 0, sizeof(phase_a_keypair));
    if (PQC_MLDSA_KeyGen(&phase_a_keypair) != PQC_E_OK) {
        fprintf(stderr, "[phase_compare] PQC_MLDSA_KeyGen (Phase A) failed\n");
        return 2;
    }

    /* --- Build a deterministic 256-byte message buffer shared by all phases --- */
    uint8 msg[PHASE_COMPARE_MSG_BYTES];
    for (uint32 i = 0U; i < PHASE_COMPARE_MSG_BYTES; ++i) {
        msg[i] = (uint8)(i & 0xFFU);
    }

    /* --- Open CSV --- */
    FILE* csv = fopen(OUTPUT_CSV_PATH, "w");
    if (csv == NULL) {
        fprintf(stderr, "[phase_compare] cannot open %s: %s\n",
                OUTPUT_CSV_PATH, strerror(errno));
        return 3;
    }
    fprintf(csv, "phase,seq,ns_delta\n");

    /* Buffers for sigs. Each phase has its own sig buffer so Phase B doesn't
     * clobber Phase A's verify input if the user later wants to interleave. */
    uint8 sig_a[PQC_MLDSA_SIGNATURE_BYTES];
    uint8 sig_b[PQC_MLDSA_SIGNATURE_BYTES];
    uint32 sig_a_len = 0U;
    uint32 sig_b_len = 0U;

    /* --- Phase A: Standalone --- */
    printf("[phase_compare] Phase A (Standalone) -- sign  %lu iters\n",
           (unsigned long)total_iters);
    if (phase_a_sign(csv, &phase_a_keypair, msg, (uint32)PHASE_COMPARE_MSG_BYTES,
                     total_iters, sig_a, &sig_a_len) != 0) {
        fclose(csv);
        return 4;
    }
    printf("[phase_compare] Phase A (Standalone) -- verify %lu iters\n",
           (unsigned long)total_iters);
    if (phase_a_verify(csv, &phase_a_keypair, msg, (uint32)PHASE_COMPARE_MSG_BYTES,
                       sig_a, sig_a_len, total_iters) != 0) {
        fclose(csv);
        return 5;
    }

    /* --- Phase B: Csm integrated --- */
    printf("[phase_compare] Phase B (Csm)        -- sign  %lu iters\n",
           (unsigned long)total_iters);
    if (phase_b_sign(csv, msg, (uint32)PHASE_COMPARE_MSG_BYTES,
                     total_iters, sig_b, &sig_b_len) != 0) {
        fclose(csv);
        return 6;
    }
    printf("[phase_compare] Phase B (Csm)        -- verify %lu iters\n",
           (unsigned long)total_iters);
    if (phase_b_verify(csv, msg, (uint32)PHASE_COMPARE_MSG_BYTES,
                       sig_b, sig_b_len, total_iters) != 0) {
        fclose(csv);
        return 7;
    }

    /* --- Phase C / Phase D --- intentionally skipped per implementer scope.
     * Adding them needs a SECOC_PERF_LOOPBACK_MODE guard in
     * source/SecOC/SecOC.c which is outside the scope of this driver.
     * Document the skip in the CSV trailer so consumers know it is intentional. */
    fprintf(csv, "#,SKIPPED,Phase_C_SecOCLoopback_requires_SECOC_PERF_LOOPBACK_MODE_guard\n");
    fprintf(csv, "#,SKIPPED,Phase_D_SecOCPiPinned_requires_same_guard\n");

    fclose(csv);
    printf("[phase_compare] done -- %lu iters/phase, phases A+B written to %s\n",
           (unsigned long)total_iters, OUTPUT_CSV_PATH);
    return 0;
}
