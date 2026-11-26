/********************************************************************************************************/
/********************************************attack_bench.c**********************************************/
/********************************************************************************************************/
/* Legacy harness, kept for reference. Its direct ML-DSA calls use the empty FIPS 204 context, not the
 * 64-byte PDU signature context of the gateway. The harnesses of record are those under bench/. */
/**
 * @file   attack_bench.c
 * @brief  Standalone attack-detection harness for SecOC PQC mode (Items #6 + #7).
 *
 * Drives the ML-DSA-65 sign/verify primitives plus an in-test freshness counter
 * to measure detection of four attack vectors:
 *
 *   - REPLAY              : sign once, replay same secured PDU N times
 *   - BIT_FLIP            : sign, then flip random bit in payload, verify
 *   - SIG_TAMPER          : sign, then flip random bit in signature, verify
 *   - FRESHNESS_ROLLBACK  : sign with freshness < last-seen, verify
 *
 * Also runs a benign baseline of N_BENIGN valid sign+verify rounds to measure
 * false-positive rate. Output is a CSV of raw events suitable for post-
 * processing by scripts/attack_rollup.py.
 *
 * MISRA-light because this is test code, but the surrounding style mirrors the
 * project's AUTOSAR conventions (typed sizes, explicit returns).
 *
 * CSV format (header on first line):
 *   vector,iter,detected,duration_ns,reason
 *
 *   reason values:
 *     OK              - verification succeeded as expected (benign)
 *     SIG_INVALID     - PQC_MLDSA_Verify returned non-success
 *     FRESH_REPLAY    - freshness counter <= last-seen (attack detected)
 *     FRESH_ROLLBACK  - freshness counter strictly less than last-seen
 *     UNEXPECTED      - attack was NOT detected (false negative)
 *
 * detected: 1 if the attack was detected (rejected), 0 if it slipped through.
 * duration_ns: ns from "feed attack" wallclock to "verify decision returned".
 *
 * CLI:
 *   ./attack_bench --n 1000 --benign 10000 \
 *                  --vectors replay,bitflip,sig_tamper,freshness_rollback \
 *                  --out /tmp/attack_raw.csv
 */

#include "PQC/PQC.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>

/********************************************************************************************************/
/*****************************************TUNABLE CONFIGURATION******************************************/
/********************************************************************************************************/

#define ATTACK_PAYLOAD_LEN          (20U)       /* "20-byte authentic PDU" per spec */
#define ATTACK_FRESHNESS_LEN        (8U)        /* 64-bit freshness, PQC mode */
#define ATTACK_MAX_VECTOR_NAMELEN   (24U)
#define ATTACK_DEFAULT_N            (1000U)
#define ATTACK_DEFAULT_BENIGN       (10000U)
#define ATTACK_DEFAULT_OUT          "/tmp/attack_raw.csv"

/* Composite "message-to-sign" = freshness(8) || payload(20) = 28 bytes */
#define ATTACK_MSG_LEN              (ATTACK_FRESHNESS_LEN + ATTACK_PAYLOAD_LEN)

/********************************************************************************************************/
/*********************************************TYPES******************************************************/
/********************************************************************************************************/

typedef enum {
    VEC_REPLAY              = 0,
    VEC_BITFLIP             = 1,
    VEC_SIG_TAMPER          = 2,
    VEC_FRESHNESS_ROLLBACK  = 3,
    VEC_BENIGN              = 4,
    VEC_MAX                 = 5
} attack_vector_t;

static const char *const VECTOR_NAMES[VEC_MAX] = {
    "REPLAY",
    "BIT_FLIP",
    "SIG_TAMPER",
    "FRESHNESS_ROLLBACK",
    "BENIGN"
};

typedef struct {
    uint32_t n_attack;
    uint32_t n_benign;
    int run_vec[VEC_MAX];
    char out_path[256];
} attack_cfg_t;

/********************************************************************************************************/
/********************************************HELPERS*****************************************************/
/********************************************************************************************************/

static uint64_t now_ns(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t seed_xorshift_state = 0xDEADBEEFCAFEBABEULL;

static uint64_t xorshift64(void)
{
    /* Reproducible non-crypto PRNG for picking random bit positions. */
    uint64_t x = seed_xorshift_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    seed_xorshift_state = x;
    return x;
}

static void freshness_to_bytes(uint64_t fv, uint8_t out[ATTACK_FRESHNESS_LEN])
{
    /* Big-endian on the wire. */
    for (uint32_t i = 0; i < ATTACK_FRESHNESS_LEN; ++i) {
        out[ATTACK_FRESHNESS_LEN - 1U - i] = (uint8_t)((fv >> (8U * i)) & 0xFFU);
    }
}

static uint64_t bytes_to_freshness(const uint8_t in[ATTACK_FRESHNESS_LEN])
{
    uint64_t fv = 0;
    for (uint32_t i = 0; i < ATTACK_FRESHNESS_LEN; ++i) {
        fv = (fv << 8U) | (uint64_t)in[i];
    }
    return fv;
}

/********************************************************************************************************/
/****************************************SECURED-PDU PACK/UNPACK*****************************************/
/********************************************************************************************************/

/**
 * Build the "message" the signer signs and the verifier checks. Identical on
 * both sides, so any tamper in payload OR freshness changes the hash input
 * and the verify will reject.
 */
static void build_message(uint64_t freshness,
                          const uint8_t payload[ATTACK_PAYLOAD_LEN],
                          uint8_t msg_out[ATTACK_MSG_LEN])
{
    uint8_t fbytes[ATTACK_FRESHNESS_LEN];
    freshness_to_bytes(freshness, fbytes);
    (void)memcpy(&msg_out[0], fbytes, ATTACK_FRESHNESS_LEN);
    (void)memcpy(&msg_out[ATTACK_FRESHNESS_LEN], payload, ATTACK_PAYLOAD_LEN);
}

/**
 * Verifier-side: replicates SecOC's "freshness window" decision. Returns
 * 0 if freshness is acceptable (strictly greater than last-seen), non-zero
 * otherwise. Mirrors the freshness check that happens before MAC/sig verify
 * in source/SecOC/SecOC.c::verify_PQC().
 */
static int freshness_accept(uint64_t last_seen, uint64_t new_fresh)
{
    return (new_fresh > last_seen) ? 0 : 1;
}

/********************************************************************************************************/
/****************************************CLI PARSING*****************************************************/
/********************************************************************************************************/

static int parse_vectors(const char *spec, int run_vec[VEC_MAX])
{
    if (spec == NULL) {
        return -1;
    }
    /* Default: nothing on, then OR-in whatever was named. */
    for (uint32_t i = 0; i < (uint32_t)VEC_MAX; ++i) {
        run_vec[i] = 0;
    }
    /* "all" turns on everything except BENIGN (BENIGN always runs anyway). */
    if (strcmp(spec, "all") == 0) {
        run_vec[VEC_REPLAY] = 1;
        run_vec[VEC_BITFLIP] = 1;
        run_vec[VEC_SIG_TAMPER] = 1;
        run_vec[VEC_FRESHNESS_ROLLBACK] = 1;
        return 0;
    }
    char buf[256];
    (void)strncpy(buf, spec, sizeof(buf) - 1U);
    buf[sizeof(buf) - 1U] = '\0';
    char *saveptr = NULL;
    char *tok = strtok_r(buf, ",", &saveptr);
    while (tok != NULL) {
        if (strcmp(tok, "replay") == 0) {
            run_vec[VEC_REPLAY] = 1;
        } else if (strcmp(tok, "bitflip") == 0) {
            run_vec[VEC_BITFLIP] = 1;
        } else if (strcmp(tok, "sig_tamper") == 0) {
            run_vec[VEC_SIG_TAMPER] = 1;
        } else if (strcmp(tok, "freshness_rollback") == 0) {
            run_vec[VEC_FRESHNESS_ROLLBACK] = 1;
        } else {
            (void)fprintf(stderr, "WARN: unknown vector '%s' ignored\n", tok);
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
    return 0;
}

static void usage(const char *prog)
{
    (void)fprintf(stderr,
        "Usage: %s [--n N_ATTACK] [--benign N_BENIGN]\n"
        "            [--vectors VEC1,VEC2,... | all]\n"
        "            [--out CSV_PATH]\n"
        "\n"
        "Vectors: replay, bitflip, sig_tamper, freshness_rollback\n"
        "Defaults: --n %u --benign %u --vectors all --out %s\n",
        prog,
        (unsigned)ATTACK_DEFAULT_N,
        (unsigned)ATTACK_DEFAULT_BENIGN,
        ATTACK_DEFAULT_OUT);
}

static int parse_cli(int argc, char **argv, attack_cfg_t *cfg)
{
    cfg->n_attack = ATTACK_DEFAULT_N;
    cfg->n_benign = ATTACK_DEFAULT_BENIGN;
    cfg->run_vec[VEC_REPLAY] = 1;
    cfg->run_vec[VEC_BITFLIP] = 1;
    cfg->run_vec[VEC_SIG_TAMPER] = 1;
    cfg->run_vec[VEC_FRESHNESS_ROLLBACK] = 1;
    cfg->run_vec[VEC_BENIGN] = 1;
    (void)strncpy(cfg->out_path, ATTACK_DEFAULT_OUT, sizeof(cfg->out_path) - 1U);
    cfg->out_path[sizeof(cfg->out_path) - 1U] = '\0';

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--n") == 0 && (i + 1) < argc) {
            cfg->n_attack = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--benign") == 0 && (i + 1) < argc) {
            cfg->n_benign = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--vectors") == 0 && (i + 1) < argc) {
            int local_vec[VEC_MAX] = {0};
            if (parse_vectors(argv[++i], local_vec) != 0) {
                return -1;
            }
            for (uint32_t v = 0; v < (uint32_t)VEC_MAX; ++v) {
                cfg->run_vec[v] = local_vec[v];
            }
            cfg->run_vec[VEC_BENIGN] = 1; /* benign always on */
        } else if (strcmp(argv[i], "--out") == 0 && (i + 1) < argc) {
            (void)strncpy(cfg->out_path, argv[++i], sizeof(cfg->out_path) - 1U);
            cfg->out_path[sizeof(cfg->out_path) - 1U] = '\0';
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 1;
        } else {
            (void)fprintf(stderr, "ERROR: unknown arg '%s'\n", argv[i]);
            usage(argv[0]);
            return -1;
        }
    }
    return 0;
}

/********************************************************************************************************/
/*****************************************CSV EVENT EMITTER**********************************************/
/********************************************************************************************************/

static FILE *g_out = NULL;

static int emit_header(void)
{
    if (g_out == NULL) {
        return -1;
    }
    if (fprintf(g_out, "vector,iter,detected,duration_ns,reason\n") < 0) {
        return -1;
    }
    return 0;
}

static void emit_event(const char *vector,
                       uint32_t iter,
                       int detected,
                       uint64_t duration_ns,
                       const char *reason)
{
    if (g_out == NULL) {
        return;
    }
    (void)fprintf(g_out, "%s,%u,%d,%" PRIu64 ",%s\n",
                  vector, (unsigned)iter, detected,
                  duration_ns, reason);
}

/********************************************************************************************************/
/****************************************ATTACK VECTORS**************************************************/
/****************************************************************************************************/

/**
 * Run benign baseline: full sign+verify cycle expected to PASS.
 * Records false-positive rate (verifies that legitimately failed).
 */
static int run_benign(const attack_cfg_t *cfg,
                      const PQC_MLDSA_KeyPairType *keys,
                      uint32_t *fp_count_out)
{
    if (!cfg->run_vec[VEC_BENIGN]) {
        return 0;
    }
    uint8_t payload[ATTACK_PAYLOAD_LEN];
    uint8_t msg[ATTACK_MSG_LEN];
    uint8_t sig[PQC_MLDSA_SIGNATURE_BYTES];
    uint32 sig_len = 0;
    uint64_t freshness = 1ULL;          /* monotonically increasing */
    uint64_t last_seen = 0ULL;
    uint32_t fp = 0;

    (void)fprintf(stderr, "[benign] running %u valid sign+verify rounds...\n",
                  (unsigned)cfg->n_benign);

    for (uint32_t i = 0; i < cfg->n_benign; ++i) {
        /* Fresh payload each iter (varies with index). */
        for (uint32_t b = 0; b < ATTACK_PAYLOAD_LEN; ++b) {
            payload[b] = (uint8_t)((i + b) & 0xFFU);
        }
        build_message(freshness, payload, msg);

        sig_len = (uint32)sizeof(sig);
        const uint64_t t0 = now_ns();
        Std_ReturnType rc_sign = PQC_MLDSA_Sign(msg, (uint32)ATTACK_MSG_LEN, NULL, 0U,
                                                 keys->SecretKey,
                                                 sig, &sig_len);
        if (rc_sign != PQC_E_OK) {
            (void)fprintf(stderr, "[benign] iter %u: sign FAILED (%d)\n",
                          (unsigned)i, (int)rc_sign);
            emit_event("BENIGN", i, 1, now_ns() - t0, "SIGN_FAIL");
            ++fp;
            continue;
        }

        /* Verifier side: freshness check, then sig verify. */
        int fresh_ok = (freshness_accept(last_seen, freshness) == 0) ? 1 : 0;
        Std_ReturnType rc_verify = PQC_MLDSA_Verify(msg, (uint32)ATTACK_MSG_LEN, NULL, 0U,
                                                     sig, sig_len,
                                                     keys->PublicKey);
        const uint64_t t1 = now_ns();
        int verified_ok = (rc_verify == PQC_E_OK) ? 1 : 0;

        if (fresh_ok && verified_ok) {
            emit_event("BENIGN", i, 0, t1 - t0, "OK");
            last_seen = freshness;
        } else {
            /* Legitimate PDU was rejected -> false positive. */
            emit_event("BENIGN", i, 1, t1 - t0,
                       verified_ok ? "FRESH_REPLAY" : "SIG_INVALID");
            ++fp;
        }
        ++freshness;
    }

    *fp_count_out = fp;
    (void)fprintf(stderr, "[benign] complete. false-positives: %u / %u\n",
                  (unsigned)fp, (unsigned)cfg->n_benign);
    return 0;
}

/**
 * REPLAY: capture one signed PDU, replay it N_ATTACK times. The verifier's
 * freshness counter advances after the first acceptance, so all subsequent
 * replays should be rejected by the freshness check.
 */
static void run_replay(const attack_cfg_t *cfg,
                       const PQC_MLDSA_KeyPairType *keys,
                       uint32_t *detected_out)
{
    uint8_t payload[ATTACK_PAYLOAD_LEN];
    uint8_t msg[ATTACK_MSG_LEN];
    uint8_t sig[PQC_MLDSA_SIGNATURE_BYTES];
    uint32 sig_len = 0;
    uint32_t detected = 0;

    for (uint32_t b = 0; b < ATTACK_PAYLOAD_LEN; ++b) {
        payload[b] = (uint8_t)(0xA5U ^ b);
    }

    const uint64_t captured_freshness = 42ULL;
    build_message(captured_freshness, payload, msg);

    sig_len = (uint32)sizeof(sig);
    if (PQC_MLDSA_Sign(msg, (uint32)ATTACK_MSG_LEN, NULL, 0U, keys->SecretKey,
                       sig, &sig_len) != PQC_E_OK) {
        (void)fprintf(stderr, "[replay] could not produce captured PDU; aborting vector\n");
        return;
    }

    /* Verifier state: assume it has already accepted some PDU at freshness=42. */
    uint64_t verifier_last_seen = captured_freshness;

    (void)fprintf(stderr, "[replay] running %u iterations...\n",
                  (unsigned)cfg->n_attack);

    for (uint32_t i = 0; i < cfg->n_attack; ++i) {
        const uint64_t t0 = now_ns();
        /* Step 1: freshness check on the REPLAYED freshness value. */
        int fresh_ok = (freshness_accept(verifier_last_seen,
                                          captured_freshness) == 0) ? 1 : 0;
        int detected_here = 0;
        const char *reason = "UNEXPECTED";

        if (!fresh_ok) {
            detected_here = 1;
            reason = "FRESH_REPLAY";
        } else {
            /* Freshness slipped through (shouldn't); fall back to sig check. */
            Std_ReturnType rc = PQC_MLDSA_Verify(msg, (uint32)ATTACK_MSG_LEN, NULL, 0U,
                                                  sig, sig_len, keys->PublicKey);
            if (rc != PQC_E_OK) {
                detected_here = 1;
                reason = "SIG_INVALID";
            }
        }
        const uint64_t t1 = now_ns();
        emit_event("REPLAY", i, detected_here, t1 - t0, reason);
        detected += (uint32_t)detected_here;
    }
    *detected_out = detected;
}

/**
 * BIT_FLIP: produce a valid signature, then flip a random bit in the payload
 * (NOT the freshness field, which would be detected before sig verify). The
 * verifier should reject because the signed message no longer matches.
 */
static void run_bitflip(const attack_cfg_t *cfg,
                        const PQC_MLDSA_KeyPairType *keys,
                        uint32_t *detected_out)
{
    uint8_t payload[ATTACK_PAYLOAD_LEN];
    uint8_t msg[ATTACK_MSG_LEN];
    uint8_t msg_tampered[ATTACK_MSG_LEN];
    uint8_t sig[PQC_MLDSA_SIGNATURE_BYTES];
    uint32 sig_len = 0;
    uint32_t detected = 0;
    uint64_t freshness = 100ULL;
    uint64_t verifier_last_seen = 0ULL;

    (void)fprintf(stderr, "[bitflip] running %u iterations...\n",
                  (unsigned)cfg->n_attack);

    for (uint32_t i = 0; i < cfg->n_attack; ++i) {
        for (uint32_t b = 0; b < ATTACK_PAYLOAD_LEN; ++b) {
            payload[b] = (uint8_t)((i + b * 7U) & 0xFFU);
        }
        build_message(freshness, payload, msg);

        sig_len = (uint32)sizeof(sig);
        if (PQC_MLDSA_Sign(msg, (uint32)ATTACK_MSG_LEN, NULL, 0U, keys->SecretKey,
                           sig, &sig_len) != PQC_E_OK) {
            emit_event("BIT_FLIP", i, 0, 0ULL, "SIGN_FAIL");
            ++freshness;
            continue;
        }

        /* Tamper: flip one random bit inside payload region. */
        (void)memcpy(msg_tampered, msg, ATTACK_MSG_LEN);
        uint32_t bit_idx = (uint32_t)(xorshift64() % (uint64_t)(ATTACK_PAYLOAD_LEN * 8U));
        uint32_t byte_off = ATTACK_FRESHNESS_LEN + (bit_idx / 8U);
        uint8_t  bit_mask = (uint8_t)(1U << (bit_idx & 7U));
        msg_tampered[byte_off] ^= bit_mask;

        /* Verifier: freshness OK first (we increment legitimately each iter). */
        const uint64_t t0 = now_ns();
        int fresh_ok = (freshness_accept(verifier_last_seen, freshness) == 0) ? 1 : 0;
        int detected_here = 0;
        const char *reason = "UNEXPECTED";

        if (!fresh_ok) {
            /* Defensive: shouldn't trigger here in pure bit-flip vector. */
            detected_here = 1;
            reason = "FRESH_REPLAY";
        } else {
            Std_ReturnType rc = PQC_MLDSA_Verify(msg_tampered, (uint32)ATTACK_MSG_LEN, NULL, 0U,
                                                  sig, sig_len, keys->PublicKey);
            if (rc != PQC_E_OK) {
                detected_here = 1;
                reason = "SIG_INVALID";
            }
        }
        const uint64_t t1 = now_ns();
        emit_event("BIT_FLIP", i, detected_here, t1 - t0, reason);
        detected += (uint32_t)detected_here;

        /* Don't advance verifier_last_seen — the tampered PDU was rejected. */
        ++freshness;
    }
    *detected_out = detected;
}

/**
 * SIG_TAMPER: produce a valid signature, then flip a random bit in the
 * signature bytes. Verifier should reject.
 */
static void run_sig_tamper(const attack_cfg_t *cfg,
                           const PQC_MLDSA_KeyPairType *keys,
                           uint32_t *detected_out)
{
    uint8_t payload[ATTACK_PAYLOAD_LEN];
    uint8_t msg[ATTACK_MSG_LEN];
    uint8_t sig[PQC_MLDSA_SIGNATURE_BYTES];
    uint8_t sig_tampered[PQC_MLDSA_SIGNATURE_BYTES];
    uint32 sig_len = 0;
    uint32_t detected = 0;
    uint64_t freshness = 200ULL;
    uint64_t verifier_last_seen = 0ULL;

    (void)fprintf(stderr, "[sig_tamper] running %u iterations...\n",
                  (unsigned)cfg->n_attack);

    for (uint32_t i = 0; i < cfg->n_attack; ++i) {
        for (uint32_t b = 0; b < ATTACK_PAYLOAD_LEN; ++b) {
            payload[b] = (uint8_t)((i * 3U + b) & 0xFFU);
        }
        build_message(freshness, payload, msg);

        sig_len = (uint32)sizeof(sig);
        if (PQC_MLDSA_Sign(msg, (uint32)ATTACK_MSG_LEN, NULL, 0U, keys->SecretKey,
                           sig, &sig_len) != PQC_E_OK) {
            emit_event("SIG_TAMPER", i, 0, 0ULL, "SIGN_FAIL");
            ++freshness;
            continue;
        }

        (void)memcpy(sig_tampered, sig, sig_len);
        uint32_t bit_idx = (uint32_t)(xorshift64() % (uint64_t)(sig_len * 8U));
        uint32_t byte_off = bit_idx / 8U;
        uint8_t  bit_mask = (uint8_t)(1U << (bit_idx & 7U));
        sig_tampered[byte_off] ^= bit_mask;

        const uint64_t t0 = now_ns();
        int fresh_ok = (freshness_accept(verifier_last_seen, freshness) == 0) ? 1 : 0;
        int detected_here = 0;
        const char *reason = "UNEXPECTED";

        if (!fresh_ok) {
            detected_here = 1;
            reason = "FRESH_REPLAY";
        } else {
            Std_ReturnType rc = PQC_MLDSA_Verify(msg, (uint32)ATTACK_MSG_LEN, NULL, 0U,
                                                  sig_tampered, sig_len, keys->PublicKey);
            if (rc != PQC_E_OK) {
                detected_here = 1;
                reason = "SIG_INVALID";
            }
        }
        const uint64_t t1 = now_ns();
        emit_event("SIG_TAMPER", i, detected_here, t1 - t0, reason);
        detected += (uint32_t)detected_here;
        ++freshness;
    }
    *detected_out = detected;
}

/**
 * FRESHNESS_ROLLBACK: sign with freshness value strictly less than the
 * verifier's last-seen counter. Verifier should reject at the freshness
 * stage before reaching sig verify.
 */
static void run_freshness_rollback(const attack_cfg_t *cfg,
                                    const PQC_MLDSA_KeyPairType *keys,
                                    uint32_t *detected_out)
{
    uint8_t payload[ATTACK_PAYLOAD_LEN];
    uint8_t msg[ATTACK_MSG_LEN];
    uint8_t sig[PQC_MLDSA_SIGNATURE_BYTES];
    uint32 sig_len = 0;
    uint32_t detected = 0;
    /* Verifier has already accepted PDU at freshness=10000. */
    const uint64_t verifier_last_seen = 10000ULL;

    (void)fprintf(stderr, "[freshness_rollback] running %u iterations...\n",
                  (unsigned)cfg->n_attack);

    for (uint32_t i = 0; i < cfg->n_attack; ++i) {
        for (uint32_t b = 0; b < ATTACK_PAYLOAD_LEN; ++b) {
            payload[b] = (uint8_t)((i + b + 0x33U) & 0xFFU);
        }
        /* Pick a rolled-back freshness < last_seen. */
        uint64_t rb_fresh = (uint64_t)(verifier_last_seen
                                       - 1ULL
                                       - (xorshift64() % 1000ULL));
        build_message(rb_fresh, payload, msg);

        sig_len = (uint32)sizeof(sig);
        if (PQC_MLDSA_Sign(msg, (uint32)ATTACK_MSG_LEN, NULL, 0U, keys->SecretKey,
                           sig, &sig_len) != PQC_E_OK) {
            emit_event("FRESHNESS_ROLLBACK", i, 0, 0ULL, "SIGN_FAIL");
            continue;
        }

        const uint64_t t0 = now_ns();
        int fresh_ok = (freshness_accept(verifier_last_seen, rb_fresh) == 0) ? 1 : 0;
        int detected_here = 0;
        const char *reason = "UNEXPECTED";

        if (!fresh_ok) {
            detected_here = 1;
            reason = "FRESH_ROLLBACK";
        } else {
            /* Defense in depth: if freshness slipped, ensure sig is OK. */
            Std_ReturnType rc = PQC_MLDSA_Verify(msg, (uint32)ATTACK_MSG_LEN, NULL, 0U,
                                                  sig, sig_len, keys->PublicKey);
            if (rc != PQC_E_OK) {
                detected_here = 1;
                reason = "SIG_INVALID";
            }
        }
        const uint64_t t1 = now_ns();
        emit_event("FRESHNESS_ROLLBACK", i, detected_here, t1 - t0, reason);
        detected += (uint32_t)detected_here;
    }
    *detected_out = detected;
}

/********************************************************************************************************/
/**********************************************MAIN******************************************************/
/********************************************************************************************************/

int main(int argc, char **argv)
{
    attack_cfg_t cfg;
    int parsed = parse_cli(argc, argv, &cfg);
    if (parsed != 0) {
        return (parsed < 0) ? 2 : 0;
    }

    (void)fprintf(stderr, "attack_bench: N_ATTACK=%u N_BENIGN=%u out=%s\n",
                  (unsigned)cfg.n_attack, (unsigned)cfg.n_benign, cfg.out_path);

    /* Seed PRNG from time + getpid()-equivalent to avoid identical bit picks
     * across runs while keeping single-run reproducibility within a build.   */
    {
        struct timespec ts;
        (void)clock_gettime(CLOCK_REALTIME, &ts);
        seed_xorshift_state ^= (uint64_t)ts.tv_nsec;
        seed_xorshift_state ^= ((uint64_t)ts.tv_sec) << 32U;
        if (seed_xorshift_state == 0ULL) {
            seed_xorshift_state = 0x1ULL;
        }
    }

    /* ---- Init PQC and generate fresh key pair (Tx side). ---- */
    if (PQC_Init() != PQC_E_OK) {
        (void)fprintf(stderr, "FATAL: PQC_Init failed\n");
        return 3;
    }
    PQC_MLDSA_KeyPairType keys;
    (void)memset(&keys, 0, sizeof(keys));
    (void)fprintf(stderr, "[init] generating ML-DSA-65 keypair...\n");
    if (PQC_MLDSA_KeyGen(&keys) != PQC_E_OK) {
        (void)fprintf(stderr, "FATAL: PQC_MLDSA_KeyGen failed\n");
        return 4;
    }
    (void)fprintf(stderr, "[init] keypair ready.\n");

    /* ---- Open output CSV. ---- */
    g_out = fopen(cfg.out_path, "w");
    if (g_out == NULL) {
        (void)fprintf(stderr, "FATAL: cannot open %s for writing: %s\n",
                      cfg.out_path, strerror(errno));
        return 5;
    }
    if (emit_header() != 0) {
        (void)fclose(g_out);
        return 6;
    }

    /* ---- Run benign baseline first; needed for false-positive rate. ---- */
    uint32_t fp_benign = 0;
    if (run_benign(&cfg, &keys, &fp_benign) != 0) {
        (void)fprintf(stderr, "FATAL: benign baseline failed\n");
        (void)fclose(g_out);
        return 7;
    }

    /* ---- Run each attack vector. ---- */
    uint32_t detected_replay = 0;
    uint32_t detected_bitflip = 0;
    uint32_t detected_sig = 0;
    uint32_t detected_fresh = 0;

    if (cfg.run_vec[VEC_REPLAY]) {
        run_replay(&cfg, &keys, &detected_replay);
    }
    if (cfg.run_vec[VEC_BITFLIP]) {
        run_bitflip(&cfg, &keys, &detected_bitflip);
    }
    if (cfg.run_vec[VEC_SIG_TAMPER]) {
        run_sig_tamper(&cfg, &keys, &detected_sig);
    }
    if (cfg.run_vec[VEC_FRESHNESS_ROLLBACK]) {
        run_freshness_rollback(&cfg, &keys, &detected_fresh);
    }

    (void)fflush(g_out);
    (void)fclose(g_out);

    /* ---- Stdout summary (machine-readable single line). ---- */
    (void)printf("SUMMARY benign_fp=%u/%u replay=%u/%u bitflip=%u/%u "
                 "sig_tamper=%u/%u freshness_rollback=%u/%u out=%s\n",
                 (unsigned)fp_benign,        (unsigned)cfg.n_benign,
                 (unsigned)detected_replay,  (unsigned)cfg.n_attack,
                 (unsigned)detected_bitflip, (unsigned)cfg.n_attack,
                 (unsigned)detected_sig,     (unsigned)cfg.n_attack,
                 (unsigned)detected_fresh,   (unsigned)cfg.n_attack,
                 cfg.out_path);

    return 0;
}
