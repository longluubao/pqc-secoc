/* bench_verify_only: verifies ONE ML-DSA-65 signature --n times and nothing else in the loop, so
 * that the instructions of one verification follow from the difference of two run lengths under
 * `perf stat` (the same way as for mldsa_sign of bench_crypto_ops). The verify row of
 * bench_crypto_ops signs a fresh message before every verification; that signing would be counted.
 *
 * Same library, calls, message and context as that row: OQS_SIG_verify_with_ctx_str of ML-DSA-65
 * over --msg-bytes pseudo-random bytes with the PDU context of --ctx-bytes bytes. Key generation and
 * the one signature happen before the loop and are the same for both run lengths.
 *
 *   perf stat -x, -e instructions:u,cycles:u -o perf_mldsa_verify_only_<n>.csv -- \
 *       taskset -c 3 bench_verify_only --n <n> --msg-bytes 14 --ctx-bytes 64
 *
 * It writes no CSV (it times nothing); one line on stdout says what was done.
 */
#define _GNU_SOURCE     /* bench_common.h: sched_getcpu, CPU_SET */
#include <getopt.h>
#include <stdlib.h>

#include "bench_common.h"

static uint8_t Msg[BENCH_MAX_MSG_BYTES];
static uint8_t Ctx[BENCH_MAX_CTX_BYTES];
static uint8_t SigPk[OQS_SIG_ml_dsa_65_length_public_key];
static uint8_t SigSk[OQS_SIG_ml_dsa_65_length_secret_key];
static uint8_t SigBuf[OQS_SIG_ml_dsa_65_length_signature];

int main(int argc, char** argv)
{
    static const struct option longOpts[] = {
        { "n", required_argument, NULL, 'n' },
        { "msg-bytes", required_argument, NULL, 'm' },
        { "ctx-bytes", required_argument, NULL, 'x' },
        { NULL, 0, NULL, 0 },
    };
    uint64_t inputRng = 0x6372797074306F70ULL;      /* the seed of bench_crypto_ops */
    unsigned long n = 0UL;
    unsigned long i;
    size_t msgLen = 0U;
    size_t ctxLen = 64U;
    size_t sigLen = 0U;
    OQS_SIG* sig;
    int c;

    while ((c = getopt_long(argc, argv, "", longOpts, NULL)) != -1) {
        if (c == 'n') {
            n = strtoul(optarg, NULL, 10);
        } else if (c == 'm') {
            msgLen = (size_t)strtoul(optarg, NULL, 10);
        } else if (c == 'x') {
            ctxLen = (size_t)strtoul(optarg, NULL, 10);
        } else {
            n = 0UL;
            break;
        }
    }
    if ((n == 0UL) || (msgLen == 0U) || (msgLen > BENCH_MAX_MSG_BYTES) || (ctxLen > BENCH_MAX_CTX_BYTES) ||
        (optind != argc)) {
        (void)fprintf(stderr, "usage: bench_verify_only --n <verifications> --msg-bytes <1..%u> [--ctx-bytes <0..255>]\n",
                      BENCH_MAX_MSG_BYTES);
        return 2;
    }

    OQS_init();
    sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    bench_pdu_context(Ctx, ctxLen);
    bench_fill(Msg, msgLen, &inputRng);
    if ((sig == NULL) || (OQS_SIG_keypair(sig, SigPk, SigSk) != OQS_SUCCESS) ||
        (OQS_SIG_sign_with_ctx_str(sig, SigBuf, &sigLen, Msg, msgLen, Ctx, ctxLen, SigSk) != OQS_SUCCESS)) {
        (void)fprintf(stderr, "setup failed\n");
        return 1;
    }
    for (i = 0UL; i < n; i++) {
        if (OQS_SIG_verify_with_ctx_str(sig, Msg, msgLen, SigBuf, sigLen, Ctx, ctxLen, SigPk) != OQS_SUCCESS) {
            (void)fprintf(stderr, "verification failed at %lu\n", i);
            return 1;
        }
    }
    (void)printf("tool=bench_verify_only commit=%s op=mldsa_verify_only n=%lu msg_bytes=%zu ctx_bytes=%zu\n",
                 BENCH_GIT_COMMIT, n, msgLen, ctxLen);
    return 0;
}
