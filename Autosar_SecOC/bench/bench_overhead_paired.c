/* bench_overhead_paired: standalone liboqs call against the Csm entry point SecOC uses, as
 * order-randomised pairs (overhead_paired.csv of DATA_SCHEMA.md: seq,order,op,standalone_ns,csm_ns).
 *
 *   A (standalone)      OQS_SIG_sign / OQS_SIG_verify on a context created once
 *   B (Csm-integrated)  Csm_SignatureGenerate(CSM_JOBID, CRYPTO_OPERATIONMODE_SINGLECALL, ...)
 *                       Csm_SignatureVerify(CSM_JOBID_VERIFY_PEER_BASE, CRYPTO_OPERATIONMODE_SINGLECALL, ...)
 *                       the calls of authenticate_PQC() / verify_PQC() in SecOC.c; with an idle job
 *                       they run synchronously through CryIf into PQC_MLDSA_Sign / PQC_MLDSA_Verify
 *
 * Both calls of a pair get the same message, the same key and the same signing randomness:
 * liboqs draws from a generator installed here, and its state is reset before each call. The
 * two signatures of a pair must therefore be identical; a mismatch means the paths did not do
 * the same work, and the run exits non-zero.
 *
 * --mode aa runs A against A (the second A is written to the csm_ns column): the noise floor.
 *
 * Usage: bench_overhead_paired --n <pairs> --seed <u64> --msg-bytes <bytes> --out <file>
 *                              [--op sign|verify|both] [--mode ab|aa] [--ctx-bytes <0..255>] [--launch <n>] [--allow-unlocked]
 * --ctx-bytes is the FIPS 204 context the standalone call signs with (default 64: the PDU context the Csm path signs with since the handshake). It has
 * to be what the Csm path of this tree uses, or the two signatures of a pair differ and the run
 * stops at its start-up check.
 */
#define _GNU_SOURCE
#include "bench_common.h"

#include <getopt.h>
#include <stdlib.h>

#include "Std_Types.h"
#include "Csm/Csm.h"
#include "SecOC/SecOC_Cfg.h"

#define BENCH_CSM_SIGN_JOB      ((uint32)CSM_JOBID)
#define BENCH_CSM_VERIFY_JOB    CSM_JOBID_VERIFY_PEER_BASE
#define BENCH_PEER_KEY_ID       CSM_KEYID_PEER_PUBKEY_BASE

#define OP_SIGN     0
#define OP_VERIFY   1
#define PATH_A      0
#define PATH_B      1

static OQS_SIG* Sig;
static uint8_t Pk[OQS_SIG_ml_dsa_65_length_public_key];
static uint8_t Sk[OQS_SIG_ml_dsa_65_length_secret_key];
static uint8_t Msg[BENCH_MAX_MSG_BYTES];
static size_t MsgLen;
static uint8_t Ctx[BENCH_MAX_CTX_BYTES];
static size_t CtxLen = 64U;
static unsigned long Launch = 1UL;      /* which process launch of a campaign this is: only written to the header */
/* Every call signs into, and verifies from, this one buffer, so that the two calls of a pair
 * differ in the path taken and in nothing else (not even the address they write to). */
static uint8_t SigWork[OQS_SIG_ml_dsa_65_length_signature];
static size_t SigWorkLen;
/* Copies of the two signatures of a pair (standalone_ns and csm_ns columns), taken outside the timed region. */
static uint8_t SigOut[2][OQS_SIG_ml_dsa_65_length_signature];
static size_t SigOutLen[2];

/* Deterministic stand-in for liboqs's generator: the only state the signing randomness has. */
static uint64_t DrbgState;
static uint64_t DrbgBytes;

static void drbg_randombytes(uint8_t* out, size_t len)
{
    bench_fill(out, len, &DrbgState);
    DrbgBytes += len;
}

static Std_ReturnType load_provisioned_keys(uint8* publicKeyPtr, uint32 publicKeyLength,
                                            uint8* secretKeyPtr, uint32 secretKeyLength)
{
    if ((publicKeyLength != sizeof(Pk)) || (secretKeyLength != sizeof(Sk))) {
        return E_NOT_OK;
    }
    (void)memcpy(publicKeyPtr, Pk, sizeof(Pk));
    (void)memcpy(secretKeyPtr, Sk, sizeof(Sk));
    return E_OK;
}

static int call(int op, int path)
{
    if (op == OP_SIGN) {
        if (path == PATH_A) {
            return OQS_SIG_sign_with_ctx_str(Sig, SigWork, &SigWorkLen, Msg, MsgLen, Ctx, CtxLen, Sk) != OQS_SUCCESS;
        } else {
            uint32 len = 0U;
            Std_ReturnType rc = Csm_SignatureGenerate(BENCH_CSM_SIGN_JOB, CRYPTO_OPERATIONMODE_SINGLECALL,
                                                      Msg, (uint32)MsgLen, SigWork, &len);
            SigWorkLen = (size_t)len;
            return rc != E_OK;
        }
    }
    if (path == PATH_A) {
        return OQS_SIG_verify_with_ctx_str(Sig, Msg, MsgLen, SigWork, SigWorkLen, Ctx, CtxLen, Pk) != OQS_SUCCESS;
    } else {
        Crypto_VerifyResultType verdict = CRYPTO_E_VER_NOT_OK;
        Std_ReturnType rc = Csm_SignatureVerify(BENCH_CSM_VERIFY_JOB, CRYPTO_OPERATIONMODE_SINGLECALL,
                                                Msg, (uint32)MsgLen, SigWork, (uint32)SigWorkLen, &verdict);
        return (rc != E_OK) || (verdict != CRYPTO_E_VER_OK);
    }
}

static uint64_t timed_call(int op, int path, int slot, uint64_t drbgState, int* failed)
{
    uint64_t t0;
    uint64_t t1;
    int rc;
    if (op == OP_SIGN) {
        /* A call that wrote nothing must not pass for one that reproduced the previous signature. */
        (void)memset(SigWork, 0, sizeof(SigWork));
        SigWorkLen = 0U;
    }
    DrbgState = drbgState;
    t0 = bench_now_ns();
    rc = call(op, path);
    t1 = bench_now_ns();
    *failed |= rc;
    if (op == OP_SIGN) {
        (void)memcpy(SigOut[slot], SigWork, sizeof(SigWork));
        SigOutLen[slot] = SigWorkLen;
    }
    return t1 - t0;
}

static int same_signature(void)
{
    return (SigOutLen[0] == SigOutLen[1]) && (memcmp(SigOut[0], SigOut[1], SigOutLen[0]) == 0);
}

/* Identical signatures prove nothing unless signing really draws from drbg_randombytes: the same
 * state must reproduce a signature and a different state must change it, on both paths.
 * Returns the bytes one signature draws, 0 on failure. */
static uint64_t check_generator_hookup(int pathB)
{
    int failed = 0;
    uint64_t bytesA;
    uint64_t bytesB;

    bench_fill(Msg, MsgLen, &DrbgState);
    DrbgBytes = 0U;
    (void)timed_call(OP_SIGN, PATH_A, 0, 1U, &failed);
    bytesA = DrbgBytes;
    DrbgBytes = 0U;
    (void)timed_call(OP_SIGN, pathB, 1, 1U, &failed);
    bytesB = DrbgBytes;
    if ((failed != 0) || (bytesA == 0U) || (bytesA != bytesB) || !same_signature()) {
        (void)fprintf(stderr, "self-check failed with the same generator state on both calls: call failed=%d, "
                              "bytes drawn first=%" PRIu64 " second=%" PRIu64 ", signatures equal=%d\n"
                              "the standalone call signed with a %zu-byte context (--ctx-bytes); the Csm path signs with "
                              "whatever context the tree at this commit gives its signature job: they must be the same\n",
                      failed, bytesA, bytesB, same_signature(), CtxLen);
        return 0U;
    }
    (void)timed_call(OP_SIGN, pathB, 1, 2U, &failed);
    if ((failed != 0) || same_signature()) {
        (void)fprintf(stderr, "self-check failed: a different generator state did not change the signature\n");
        return 0U;
    }
    return bytesA;
}

static int usage(void)
{
    (void)fprintf(stderr, "usage: bench_overhead_paired --n <pairs> --seed <u64> --msg-bytes <1..%u> --out <file> "
                          "[--op sign|verify|both] [--mode ab|aa] [--ctx-bytes <0..255>] [--allow-unlocked]\n", BENCH_MAX_MSG_BYTES);
    return 2;
}

static void write_run_header(FILE* f, const char* mlockStatus, unsigned long n, uint64_t seed,
                             const char* opName, int pathB, uint64_t drawBytes, int* cpu)
{
    *cpu = bench_write_header(f, "bench_overhead_paired", mlockStatus);
    (void)fprintf(f, "# ctx_bytes=%zu\n# launch=%lu\n", CtxLen, Launch);
    (void)fprintf(f, "# n=%lu\n# msg_bytes=%zu\n# seed=%" PRIu64 "\n# op=%s\n# mode=%s\n",
                  n, MsgLen, seed, opName, (pathB == PATH_B) ? "ab" : "aa");
    (void)fprintf(f, "# rng=deterministic\n# rng_bytes_per_sign=%" PRIu64 "\n", drawBytes);
    (void)fprintf(f, "# standalone_ns=OQS_SIG_sign / OQS_SIG_verify, context created once\n");
    if (pathB == PATH_B) {
        (void)fprintf(f, "# csm_ns=Csm_SignatureGenerate(job %lu) / Csm_SignatureVerify(job %lu), "
                         "CRYPTO_OPERATIONMODE_SINGLECALL, synchronous\n",
                      (unsigned long)BENCH_CSM_SIGN_JOB, (unsigned long)BENCH_CSM_VERIFY_JOB);
    } else {
        (void)fprintf(f, "# csm_ns=NOT the Csm path: second standalone call of the pair (noise floor)\n");
    }
}

int main(int argc, char** argv)
{
    static const struct option longOpts[] = {
        { "n", required_argument, NULL, 'n' },
        { "seed", required_argument, NULL, 's' },
        { "msg-bytes", required_argument, NULL, 'm' },
        { "ctx-bytes", required_argument, NULL, 'x' },
        { "launch", required_argument, NULL, 'l' },
        { "out", required_argument, NULL, 'o' },
        { "op", required_argument, NULL, 'p' },
        { "mode", required_argument, NULL, 'd' },
        { "allow-unlocked", no_argument, NULL, 'u' },
        { NULL, 0, NULL, 0 },
    };
    static const char* const opNames[] = { "sign", "verify" };
    Csm_ConfigType csmConfig = { CSM_MLDSA_BOOTSTRAP_PROVISIONED, load_provisioned_keys };
    unsigned long n = 0UL;
    uint64_t seed = 0U;
    int seedGiven = 0;
    const char* outPath = NULL;
    const char* opName = "both";
    int pathB = PATH_B;
    uint64_t msgRng;
    uint64_t orderRng;
    uint64_t pairRng;
    uint64_t drawBytes;
    uint64_t* ns[2];
    uint8_t* first;
    const char* mlockStatus;
    unsigned long mismatches = 0UL;
    unsigned long failures = 0UL;
    unsigned long i;
    FILE* out;
    int cpu = 0;
    int op;
    int allowUnlocked = 0;
    int c;
    uint64_t startNs = bench_now_ns();

    while ((c = getopt_long(argc, argv, "", longOpts, NULL)) != -1) {
        if (c == 'n') {
            n = strtoul(optarg, NULL, 10);
        } else if (c == 's') {
            seed = strtoull(optarg, NULL, 10);
            seedGiven = 1;
        } else if (c == 'm') {
            MsgLen = (size_t)strtoul(optarg, NULL, 10);
        } else if (c == 'x') {
            CtxLen = (size_t)strtoul(optarg, NULL, 10);
        } else if (c == 'l') {
            Launch = strtoul(optarg, NULL, 10);
        } else if (c == 'o') {
            outPath = optarg;
        } else if (c == 'p') {
            opName = optarg;
        } else if ((c == 'd') && (strcmp(optarg, "aa") == 0)) {
            pathB = PATH_A;
        } else if ((c == 'd') && (strcmp(optarg, "ab") == 0)) {
            pathB = PATH_B;
        } else if (c == 'u') {
            allowUnlocked = 1;
        } else {
            return usage();
        }
    }
    if ((n == 0UL) || (seedGiven == 0) || (MsgLen == 0U) || (MsgLen > BENCH_MAX_MSG_BYTES) || (outPath == NULL) ||
        (CtxLen > BENCH_MAX_CTX_BYTES) ||
        (optind != argc) ||
        ((strcmp(opName, "sign") != 0) && (strcmp(opName, "verify") != 0) && (strcmp(opName, "both") != 0))) {
        return usage();
    }
    bench_pdu_context(Ctx, CtxLen);

    /* Opened first: PQC_Init() tightens the umask to 0077 and the CSV should stay readable. */
    out = fopen(outPath, "w");
    ns[0] = malloc(n * sizeof(*ns[0]));
    ns[1] = malloc(n * sizeof(*ns[1]));
    first = malloc(n);
    if ((out == NULL) || (ns[0] == NULL) || (ns[1] == NULL) || (first == NULL)) {
        (void)fprintf(stderr, "cannot open %s or allocate %lu pairs: %s\n", outPath, n, strerror(errno));
        return 1;
    }
    (void)memset(ns[0], 0, n * sizeof(*ns[0]));     /* fault the pages in before the first sample */
    (void)memset(ns[1], 0, n * sizeof(*ns[1]));
    (void)memset(first, 0, n);

    /* Three independent streams from one seed: key and signing randomness, message bytes, call order. */
    DrbgState = seed;
    msgRng = seed ^ 0x6D65737361676573ULL;
    orderRng = seed ^ 0x6F726465726F7264ULL;
    pairRng = seed ^ 0x7061697270616972ULL;

    OQS_init();
    OQS_randombytes_custom_algorithm(drbg_randombytes);
    Sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if ((Sig == NULL) || (OQS_SIG_keypair(Sig, Pk, Sk) != OQS_SUCCESS)) {
        (void)fprintf(stderr, "ML-DSA-65 key generation failed\n");
        return 1;
    }
    /* The Csm signs with the key above (provisioned bootstrap) and verifies with it as peer 0's
     * public key, the job the receive path uses for PDUs from the peer gateway. */
    Csm_Init(&csmConfig);
    if ((Csm_KeyElementSet(BENCH_PEER_KEY_ID, CSM_KEYELEMENT_MLDSA_PEER_PUBLIC, Pk, (uint32)sizeof(Pk)) != E_OK) ||
        (Csm_KeySetValid(BENCH_PEER_KEY_ID) != E_OK)) {
        (void)fprintf(stderr, "Csm initialisation or key installation failed\n");
        return 1;
    }

    drawBytes = check_generator_hookup(pathB);
    if (drawBytes == 0U) {
        return 3;
    }
    mlockStatus = bench_lock_memory();
    if (bench_require_locked(mlockStatus, allowUnlocked) != 0) {
        return 1;
    }

    write_run_header(stdout, mlockStatus, n, seed, opName, pathB, drawBytes, &cpu);
    write_run_header(out, mlockStatus, n, seed, opName, pathB, drawBytes, &cpu);
    (void)fprintf(out, "seq,order,op,standalone_ns,csm_ns\n");

    for (op = OP_SIGN; op <= OP_VERIFY; op++) {
        if ((strcmp(opName, "both") != 0) && (strcmp(opName, opNames[op]) != 0)) {
            continue;
        }
        for (i = 0UL; i < n; i++) {
            int lead = (int)(bench_rand64(&orderRng) & 1U);    /* 0: standalone column runs first (AB) */
            uint64_t state = bench_rand64(&pairRng);
            int failed = 0;

            bench_fill(Msg, MsgLen, &msgRng);
            if (op == OP_VERIFY) {
                DrbgState = state;
                failed |= call(OP_SIGN, PATH_A);
            }
            if (lead == 0) {
                ns[0][i] = timed_call(op, PATH_A, 0, state, &failed);
                ns[1][i] = timed_call(op, pathB, 1, state, &failed);
            } else {
                ns[1][i] = timed_call(op, pathB, 1, state, &failed);
                ns[0][i] = timed_call(op, PATH_A, 0, state, &failed);
            }
            first[i] = (uint8_t)lead;
            if (failed != 0) {
                failures++;
            } else if ((op == OP_SIGN) && !same_signature()) {
                mismatches++;
            }
        }
        for (i = 0UL; i < n; i++) {
            (void)fprintf(out, "%lu,%s,%s,%" PRIu64 ",%" PRIu64 "\n", i, (first[i] == 0U) ? "AB" : "BA",
                          opNames[op], ns[0][i], ns[1][i]);
        }
        (void)printf("%s: %lu pairs\n", opNames[op], n);
    }

    (void)fprintf(out, "# signature_mismatches=%lu\n# failed_calls=%lu\n", mismatches, failures);
    bench_write_footer(out, cpu, startNs);
    if ((ferror(out) != 0) || (fclose(out) != 0)) {
        (void)fprintf(stderr, "write to %s failed: %s\n", outPath, strerror(errno));
        return 1;
    }
    (void)printf("signature_mismatches=%lu failed_calls=%lu\n", mismatches, failures);
    return ((mismatches != 0UL) || (failures != 0UL)) ? 4 : 0;
}
