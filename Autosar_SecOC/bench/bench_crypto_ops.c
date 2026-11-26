/* bench_crypto_ops: single-node timing of the primitives the stack uses, one row per call
 * (crypto_ops.csv of DATA_SCHEMA.md: op,seq,ns).
 *
 * What one sample covers (each call sits alone between two CLOCK_MONOTONIC reads; inputs are
 * prepared before the first read, results are stored in memory and written after the loop):
 *   mldsa_keygen  OQS_SIG_keypair
 *   mldsa_sign    OQS_SIG_sign_with_ctx_str, hedged (liboqs default), fresh message, the PDU context
 *                 of --ctx-bytes bytes (default 64; 0 = empty context)
 *   mldsa_verify  OQS_SIG_verify_with_ctx_str of a fresh message and its signature, same context
 *   mlkem_keygen  OQS_KEM_keypair
 *   mlkem_encaps  OQS_KEM_encaps to a fresh key
 *   mlkem_decaps  OQS_KEM_decaps of a fresh ciphertext
 *   hkdf          HKDF-SHA-256 (EVP_KDF, extract and expand): 32-byte salt and IKM, 87-byte info, 32-byte output
 *   hmac_gen      HMAC-SHA-256 (EVP_MAC, key installed once) over a fresh message
 *   hmac_verify   hmac_gen plus a constant-time compare of the 128-bit truncated tag
 * The liboqs calls use contexts created once and liboqs's default generator. The hkdf and hmac
 * rows time the OpenSSL primitives directly, not a Csm service.
 *
 * Usage: bench_crypto_ops --n <iterations> --msg-bytes <bytes> --out <file> [--ops <op,op,...>]
 *                         [--ctx-bytes <0..255>] [--allow-unlocked]
 */
#define _GNU_SOURCE
#include "bench_common.h"

#include <getopt.h>
#include <stdlib.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#define BENCH_SHA256_BYTES      32U
#define BENCH_MAC_TAG_BYTES     16U     /* SecOCAuthInfoTruncLength = 128 bits in the MAC profile */
#define BENCH_HKDF_INFO_BYTES   87U     /* label "PQC-SecOC-HS-v1" (15) + key label (8) + two 32-byte identities */

typedef struct {
    const char* name;
    void (*prepare)(void);
    int (*run)(void);
} bench_op_t;

static OQS_SIG* Sig;
static OQS_KEM* Kem;
static EVP_MAC_CTX* Hmac;
static EVP_KDF_CTX* Hkdf;
static OSSL_PARAM HkdfParams[5];
static char Sha256Name[] = "SHA256";
static uint64_t InputRng = 0x6372797074306F70ULL;

static uint8_t Msg[BENCH_MAX_MSG_BYTES];
static size_t MsgLen;
static uint8_t Ctx[BENCH_MAX_CTX_BYTES];
static size_t CtxLen = 64U;
static uint8_t SigPk[OQS_SIG_ml_dsa_65_length_public_key];
static uint8_t SigSk[OQS_SIG_ml_dsa_65_length_secret_key];
static uint8_t SigBuf[OQS_SIG_ml_dsa_65_length_signature];
static size_t SigLen;
static uint8_t ScratchPk[OQS_SIG_ml_dsa_65_length_public_key];
static uint8_t ScratchSk[OQS_SIG_ml_dsa_65_length_secret_key];
static uint8_t KemPk[OQS_KEM_ml_kem_768_length_public_key];
static uint8_t KemSk[OQS_KEM_ml_kem_768_length_secret_key];
static uint8_t KemCt[OQS_KEM_ml_kem_768_length_ciphertext];
static uint8_t KemSs[OQS_KEM_ml_kem_768_length_shared_secret];
static uint8_t HmacKey[BENCH_SHA256_BYTES];
static uint8_t HmacTag[BENCH_SHA256_BYTES];
static uint8_t HmacExpected[BENCH_MAC_TAG_BYTES];
static uint8_t HkdfIkm[BENCH_SHA256_BYTES];
static uint8_t HkdfSalt[BENCH_SHA256_BYTES];
static uint8_t HkdfInfo[BENCH_HKDF_INFO_BYTES];
static uint8_t HkdfOut[BENCH_SHA256_BYTES];

static void prep_none(void)
{
}

static void prep_msg(void)
{
    bench_fill(Msg, MsgLen, &InputRng);
}

static int run_mldsa_keygen(void)
{
    return OQS_SIG_keypair(Sig, ScratchPk, ScratchSk) != OQS_SUCCESS;
}

static int run_mldsa_sign(void)
{
    return OQS_SIG_sign_with_ctx_str(Sig, SigBuf, &SigLen, Msg, MsgLen, Ctx, CtxLen, SigSk) != OQS_SUCCESS;
}

static void prep_mldsa_verify(void)
{
    prep_msg();
    (void)run_mldsa_sign();
}

static int run_mldsa_verify(void)
{
    return OQS_SIG_verify_with_ctx_str(Sig, Msg, MsgLen, SigBuf, SigLen, Ctx, CtxLen, SigPk) != OQS_SUCCESS;
}

static int run_mlkem_keygen(void)
{
    return OQS_KEM_keypair(Kem, KemPk, KemSk) != OQS_SUCCESS;
}

/* A fresh key per encapsulation, as in the handshake (one ek per attempt). */
static void prep_mlkem_encaps(void)
{
    (void)run_mlkem_keygen();
}

static int run_mlkem_encaps(void)
{
    return OQS_KEM_encaps(Kem, KemCt, KemSs, KemPk) != OQS_SUCCESS;
}

static void prep_mlkem_decaps(void)
{
    (void)run_mlkem_keygen();
    (void)run_mlkem_encaps();
}

static int run_mlkem_decaps(void)
{
    return OQS_KEM_decaps(Kem, KemSs, KemCt, KemSk) != OQS_SUCCESS;
}

static void prep_hkdf(void)
{
    bench_fill(HkdfIkm, sizeof(HkdfIkm), &InputRng);
    bench_fill(HkdfSalt, sizeof(HkdfSalt), &InputRng);
    EVP_KDF_CTX_reset(Hkdf);
}

static int run_hkdf(void)
{
    return EVP_KDF_derive(Hkdf, HkdfOut, sizeof(HkdfOut), HkdfParams) != 1;
}

static int run_hmac_gen(void)
{
    size_t len = 0U;
    /* A NULL key re-arms the context with the key installed in setup(). */
    return (EVP_MAC_init(Hmac, NULL, 0U, NULL) != 1) ||
           (EVP_MAC_update(Hmac, Msg, MsgLen) != 1) ||
           (EVP_MAC_final(Hmac, HmacTag, &len, sizeof(HmacTag)) != 1);
}

static void prep_hmac_verify(void)
{
    prep_msg();
    (void)run_hmac_gen();
    (void)memcpy(HmacExpected, HmacTag, sizeof(HmacExpected));
}

static int run_hmac_verify(void)
{
    return (run_hmac_gen() != 0) || (CRYPTO_memcmp(HmacTag, HmacExpected, sizeof(HmacExpected)) != 0);
}

static const bench_op_t Ops[] = {
    { "mldsa_keygen", prep_none,         run_mldsa_keygen },
    { "mldsa_sign",   prep_msg,          run_mldsa_sign },
    { "mldsa_verify", prep_mldsa_verify, run_mldsa_verify },
    { "mlkem_keygen", prep_none,         run_mlkem_keygen },
    { "mlkem_encaps", prep_mlkem_encaps, run_mlkem_encaps },
    { "mlkem_decaps", prep_mlkem_decaps, run_mlkem_decaps },
    { "hkdf",         prep_hkdf,         run_hkdf },
    { "hmac_gen",     prep_msg,          run_hmac_gen },
    { "hmac_verify",  prep_hmac_verify,  run_hmac_verify },
};
#define BENCH_OP_COUNT (sizeof(Ops) / sizeof(Ops[0]))

/* One-shot reference HMAC, used only to check the reused contexts before anything is timed. */
static int ref_hmac(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen, uint8_t* out)
{
    size_t len = 0U;
    return EVP_Q_mac(NULL, "HMAC", NULL, Sha256Name, NULL, key, keyLen, data, dataLen, out, BENCH_SHA256_BYTES, &len) == NULL;
}

static int setup(void)
{
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    OSSL_PARAM macParams[2];
    uint8_t ref[BENCH_SHA256_BYTES];
    uint8_t prk[BENCH_SHA256_BYTES];
    uint8_t block[BENCH_HKDF_INFO_BYTES + 1U];

    OQS_init();
    Sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    Kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if ((Sig == NULL) || (Kem == NULL) || (mac == NULL) || (kdf == NULL)) {
        return 1;
    }
    if (OQS_SIG_keypair(Sig, SigPk, SigSk) != OQS_SUCCESS) {
        return 1;
    }

    bench_fill(HmacKey, sizeof(HmacKey), &InputRng);
    bench_fill(HkdfInfo, sizeof(HkdfInfo), &InputRng);
    macParams[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, Sha256Name, 0U);
    macParams[1] = OSSL_PARAM_construct_end();
    Hmac = EVP_MAC_CTX_new(mac);
    Hkdf = EVP_KDF_CTX_new(kdf);
    EVP_MAC_free(mac);
    EVP_KDF_free(kdf);
    if ((Hmac == NULL) || (Hkdf == NULL) || (EVP_MAC_init(Hmac, HmacKey, sizeof(HmacKey), macParams) != 1)) {
        return 1;
    }
    HkdfParams[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, Sha256Name, 0U);
    HkdfParams[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, HkdfIkm, sizeof(HkdfIkm));
    HkdfParams[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, HkdfSalt, sizeof(HkdfSalt));
    HkdfParams[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, HkdfInfo, sizeof(HkdfInfo));
    HkdfParams[4] = OSSL_PARAM_construct_end();

    /* The timed calls reuse contexts; a reuse that silently computed something else would make
     * the hkdf and hmac rows meaningless, so both are checked twice against one-shot HMACs. */
    for (int pass = 0; pass < 2; pass++) {
        prep_msg();
        if ((run_hmac_gen() != 0) || (ref_hmac(HmacKey, sizeof(HmacKey), Msg, MsgLen, ref) != 0) ||
            (memcmp(HmacTag, ref, sizeof(ref)) != 0)) {
            (void)fprintf(stderr, "self-check failed: reused HMAC context\n");
            return 1;
        }
        prep_hkdf();
        (void)memcpy(block, HkdfInfo, sizeof(HkdfInfo));
        block[sizeof(HkdfInfo)] = 0x01U;    /* RFC 5869: OKM = T(1) = HMAC(PRK, info | 0x01) for a 32-byte output */
        if ((run_hkdf() != 0) || (ref_hmac(HkdfSalt, sizeof(HkdfSalt), HkdfIkm, sizeof(HkdfIkm), prk) != 0) ||
            (ref_hmac(prk, sizeof(prk), block, sizeof(block), ref) != 0) || (memcmp(HkdfOut, ref, sizeof(ref)) != 0)) {
            (void)fprintf(stderr, "self-check failed: reused HKDF context\n");
            return 1;
        }
    }
    return 0;
}

static int usage(void)
{
    size_t i;
    (void)fprintf(stderr, "usage: bench_crypto_ops --n <iterations> --msg-bytes <1..%u> --out <file> [--ops <op,op,...>] "
                          "[--ctx-bytes <0..255>] [--allow-unlocked]\n  ops:",
                  BENCH_MAX_MSG_BYTES);
    for (i = 0U; i < BENCH_OP_COUNT; i++) {
        (void)fprintf(stderr, " %s", Ops[i].name);
    }
    (void)fprintf(stderr, "\n");
    return 2;
}

static void write_run_header(FILE* f, const char* mlockStatus, unsigned long n, int* cpu)
{
    *cpu = bench_write_header(f, "bench_crypto_ops", mlockStatus);
    (void)fprintf(f, "# n=%lu\n# msg_bytes=%zu\n# ctx_bytes=%zu\n", n, MsgLen, CtxLen);
#ifdef OQS_USE_OPENSSL
    (void)fprintf(f, "# rng=liboqs default (OpenSSL RAND_bytes, liboqs built with OQS_USE_OPENSSL)\n");
#else
    (void)fprintf(f, "# rng=liboqs default (system generator)\n");
#endif
    (void)fprintf(f, "# mldsa_signing=hedged (liboqs default)\n");
    (void)fprintf(f, "# hkdf=OpenSSL EVP_KDF HKDF-SHA-256 extract+expand, salt 32 B, ikm 32 B, info %u B, out 32 B\n", BENCH_HKDF_INFO_BYTES);
    (void)fprintf(f, "# hmac=OpenSSL EVP_MAC HMAC-SHA-256, key 32 B installed once, message msg_bytes, verify compares %u B\n",
                  BENCH_MAC_TAG_BYTES);
}

int main(int argc, char** argv)
{
    static const struct option longOpts[] = {
        { "n", required_argument, NULL, 'n' },
        { "msg-bytes", required_argument, NULL, 'm' },
        { "ctx-bytes", required_argument, NULL, 'x' },
        { "out", required_argument, NULL, 'o' },
        { "ops", required_argument, NULL, 'p' },
        { "allow-unlocked", no_argument, NULL, 'u' },
        { NULL, 0, NULL, 0 },
    };
    unsigned long n = 0UL;
    const char* outPath = NULL;
    int selected[BENCH_OP_COUNT];
    int selectedAny = 0;
    const char* mlockStatus;
    uint64_t* ns;
    FILE* out;
    size_t op;
    unsigned long i;
    int cpu = 0;
    int allowUnlocked = 0;
    int c;
    uint64_t startNs = bench_now_ns();

    (void)memset(selected, 0, sizeof(selected));
    while ((c = getopt_long(argc, argv, "", longOpts, NULL)) != -1) {
        if (c == 'n') {
            n = strtoul(optarg, NULL, 10);
        } else if (c == 'm') {
            MsgLen = (size_t)strtoul(optarg, NULL, 10);
        } else if (c == 'x') {
            CtxLen = (size_t)strtoul(optarg, NULL, 10);
        } else if (c == 'o') {
            outPath = optarg;
        } else if (c == 'p') {
            char* tok;
            for (tok = strtok(optarg, ","); tok != NULL; tok = strtok(NULL, ",")) {
                for (op = 0U; (op < BENCH_OP_COUNT) && (strcmp(tok, Ops[op].name) != 0); op++) {
                }
                if (op == BENCH_OP_COUNT) {
                    (void)fprintf(stderr, "unknown op '%s'\n", tok);
                    return usage();
                }
                selected[op] = 1;
                selectedAny = 1;
            }
        } else if (c == 'u') {
            allowUnlocked = 1;
        } else {
            return usage();
        }
    }
    if ((n == 0UL) || (MsgLen == 0U) || (MsgLen > BENCH_MAX_MSG_BYTES) || (CtxLen > BENCH_MAX_CTX_BYTES) ||
        (outPath == NULL) || (optind != argc)) {
        return usage();
    }
    bench_pdu_context(Ctx, CtxLen);

    if (setup() != 0) {
        (void)fprintf(stderr, "setup failed\n");
        return 1;
    }
    out = fopen(outPath, "w");
    ns = malloc(n * sizeof(*ns));
    if ((out == NULL) || (ns == NULL)) {
        (void)fprintf(stderr, "cannot open %s or allocate %lu samples: %s\n", outPath, n, strerror(errno));
        return 1;
    }
    (void)memset(ns, 0, n * sizeof(*ns));   /* fault the pages in before the first sample */
    mlockStatus = bench_lock_memory();
    if (bench_require_locked(mlockStatus, allowUnlocked) != 0) {
        return 1;
    }

    write_run_header(stdout, mlockStatus, n, &cpu);
    write_run_header(out, mlockStatus, n, &cpu);
    (void)fprintf(out, "op,seq,ns\n");

    for (op = 0U; op < BENCH_OP_COUNT; op++) {
        if ((selectedAny != 0) && (selected[op] == 0)) {
            continue;
        }
        for (i = 0UL; i < n; i++) {
            uint64_t t0;
            uint64_t t1;
            int rc;
            Ops[op].prepare();
            t0 = bench_now_ns();
            rc = Ops[op].run();
            t1 = bench_now_ns();
            if (rc != 0) {
                (void)fprintf(stderr, "%s failed at seq %lu\n", Ops[op].name, i);
                return 1;
            }
            ns[i] = t1 - t0;
        }
        for (i = 0UL; i < n; i++) {
            (void)fprintf(out, "%s,%lu,%" PRIu64 "\n", Ops[op].name, i, ns[i]);
        }
        (void)printf("%s: %lu samples\n", Ops[op].name, n);
    }

    bench_write_footer(out, cpu, startNs);
    if ((ferror(out) != 0) || (fclose(out) != 0)) {
        (void)fprintf(stderr, "write to %s failed: %s\n", outPath, strerror(errno));
        return 1;
    }
    return 0;
}
