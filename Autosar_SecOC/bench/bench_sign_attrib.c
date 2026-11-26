/* bench_sign_attrib: is a slow ML-DSA signing call slow because it computed longer (more rounds of
 * the rejection loop) or because the thread did not run? Wall time alone cannot tell; the thread's
 * CPU time can: for a pinned, CPU-bound thread, wall - cpu of one call is the time the thread was
 * not running: preemption, and interrupt handling too when the kernel accounts interrupt time
 * separately (CONFIG_IRQ_TIME_ACCOUNTING; without it interrupt time is charged to the thread).
 *
 * Same call and set-up as `bench_crypto_ops --ops mldsa_sign`: one key pair from OQS_SIG_keypair,
 * a fresh pseudo-random message of --msg-bytes per call, OQS_SIG_sign_with_ctx_str with the PDU
 * context of --ctx-bytes bytes (default 64), hedged signing (liboqs default generator), the OQS
 * context created once, no warm-up calls, memory locked, results in memory until the loop is over.
 *
 * Output (sign_attrib*.csv): seq,wall_ns,cpu_ns, one row per call.
 *   wall_ns  CLOCK_MONOTONIC around the call
 *   cpu_ns   CLOCK_THREAD_CPUTIME_ID around the same call
 * Clock order per call: monotonic, thread CPU, sign, thread CPU, monotonic. The CPU-time pair sits
 * inside the wall-time pair, so wall_ns >= cpu_ns up to the resolution of the two clocks.
 * Header: the lines of bench_crypto_ops, plus clock_order, cpu_clock and cpu_timer_overhead_ns
 * (timer_overhead_ns is the monotonic clock's; each is the median of back-to-back reads).
 *
 * --count-shake (off by default) adds a fourth column, shake_calls: how often the signing call
 * initialised an incremental SHAKE-256 state. ML-DSA does that a fixed number of times per round of
 * its rejection loop, so the column is an exact proxy for the number of rounds:
 * rounds = (shake_calls - shake_calls_min) / shake_calls_step + 1, both in the header. The count
 * comes from liboqs's public hook OQS_SHA3_set_callbacks (oqs/sha3_ops.h): a copy of liboqs's own
 * table with one entry replaced by a function that counts and forwards. The table to copy,
 * sha3_default_callbacks, is a symbol of liboqs.a that no installed header declares; nothing of
 * liboqs is changed or rebuilt. With the switch every SHAKE-256 start goes through one more
 * indirect call, which is why it is a switch. A start-up check signs and verifies
 * BENCH_SHAKE_PROBES messages and refuses to run unless every signature verifies and the counts
 * form an arithmetic progression.
 *
 * Usage: bench_sign_attrib --n <iterations> --msg-bytes <bytes> --out <file> [--ctx-bytes <0..255>]
 *                          [--count-shake] [--allow-unlocked]
 */
#define _GNU_SOURCE
#include "bench_common.h"

#include <getopt.h>
#include <stdlib.h>

#define BENCH_SHAKE_PROBES      64U

/* liboqs's own SHA-3 implementation table (src/common/sha3): in liboqs.a, in no installed header */
extern struct OQS_SHA3_callbacks sha3_default_callbacks;
static struct OQS_SHA3_callbacks Counting;
static unsigned long ShakeCalls;

static void counting_shake256_inc_init(OQS_SHA3_shake256_inc_ctx* state)
{
    ShakeCalls++;
    sha3_default_callbacks.SHA3_shake256_inc_init(state);
}

static unsigned long gcd(unsigned long a, unsigned long b)
{
    while (b != 0UL) {
        unsigned long t = a % b;
        a = b;
        b = t;
    }
    return a;
}

static uint64_t cpu_now_ns(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

/* Median cost of one start/stop pair of the thread CPU clock, as bench_timer_overhead_ns() does
 * for the monotonic clock. */
static uint64_t cpu_timer_overhead_ns(void)
{
    uint64_t d[BENCH_TIMER_PROBES];
    unsigned i;
    unsigned j;
    for (i = 0U; i < BENCH_TIMER_PROBES; i++) {
        uint64_t t0 = cpu_now_ns();
        d[i] = cpu_now_ns() - t0;
    }
    for (i = 1U; i < BENCH_TIMER_PROBES; i++) {
        uint64_t v = d[i];
        for (j = i; (j > 0U) && (d[j - 1U] > v); j--) {
            d[j] = d[j - 1U];
        }
        d[j] = v;
    }
    return d[BENCH_TIMER_PROBES / 2U];
}

static int usage(void)
{
    (void)fprintf(stderr, "usage: bench_sign_attrib --n <iterations> --msg-bytes <1..%u> --out <file> "
                          "[--ctx-bytes <0..255>] [--count-shake] [--allow-unlocked]\n", BENCH_MAX_MSG_BYTES);
    return 2;
}

int main(int argc, char** argv)
{
    static const struct option longOpts[] = {
        { "n", required_argument, NULL, 'n' },       { "msg-bytes", required_argument, NULL, 'm' },
        { "ctx-bytes", required_argument, NULL, 'x' }, { "out", required_argument, NULL, 'o' },
        { "allow-unlocked", no_argument, NULL, 'u' }, { "count-shake", no_argument, NULL, 's' },
        { NULL, 0, NULL, 0 },
    };
    static uint8_t msg[BENCH_MAX_MSG_BYTES];
    static uint8_t ctx[BENCH_MAX_CTX_BYTES];
    static uint8_t pk[OQS_SIG_ml_dsa_65_length_public_key];
    static uint8_t sk[OQS_SIG_ml_dsa_65_length_secret_key];
    static uint8_t sigBuf[OQS_SIG_ml_dsa_65_length_signature];
    uint64_t inputRng = 0x6372797074306F70ULL;      /* the message generator's seed of bench_crypto_ops */
    uint64_t startNs = bench_now_ns();
    uint64_t* wall;
    uint64_t* cpuNs;
    uint32_t* shake = NULL;
    unsigned long shakeMin = 0UL;
    unsigned long shakeStep = 0UL;
    int countShake = 0;
    OQS_SIG* sig;
    const char* outPath = NULL;
    const char* mlockStatus;
    unsigned long n = 0UL;
    unsigned long i;
    size_t msgLen = 0U;
    size_t ctxLen = 64U;
    size_t sigLen = 0U;
    int allowUnlocked = 0;
    int cpu;
    int c;
    FILE* out;
    FILE* f;

    while ((c = getopt_long(argc, argv, "", longOpts, NULL)) != -1) {
        switch (c) {
        case 'n': n = strtoul(optarg, NULL, 10); break;
        case 'm': msgLen = (size_t)strtoul(optarg, NULL, 10); break;
        case 'x': ctxLen = (size_t)strtoul(optarg, NULL, 10); break;
        case 'o': outPath = optarg; break;
        case 'u': allowUnlocked = 1; break;
        case 's': countShake = 1; break;
        default: return usage();
        }
    }
    if ((n == 0UL) || (msgLen == 0U) || (msgLen > BENCH_MAX_MSG_BYTES) || (ctxLen > BENCH_MAX_CTX_BYTES) ||
        (outPath == NULL) || (optind != argc)) {
        return usage();
    }
    bench_pdu_context(ctx, ctxLen);

    OQS_init();
    sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if ((sig == NULL) || (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS)) {
        (void)fprintf(stderr, "setup failed\n");
        return 1;
    }
    if (countShake != 0) {
        /* Is the count what a counter of rejection-loop rounds would look like? */
        unsigned long probes[BENCH_SHAKE_PROBES];
        unsigned k;
        Counting = sha3_default_callbacks;
        Counting.SHA3_shake256_inc_init = counting_shake256_inc_init;
        OQS_SHA3_set_callbacks(&Counting);
        for (k = 0U; k < BENCH_SHAKE_PROBES; k++) {
            bench_fill(msg, msgLen, &inputRng);
            ShakeCalls = 0UL;
            if (OQS_SIG_sign_with_ctx_str(sig, sigBuf, &sigLen, msg, msgLen, ctx, ctxLen, sk) != OQS_SUCCESS) {
                (void)fprintf(stderr, "--count-shake: signing with the counting table failed\n");
                return 3;
            }
            probes[k] = ShakeCalls;     /* the signing call alone; the verification below starts SHAKE too */
            if (OQS_SIG_verify_with_ctx_str(sig, msg, msgLen, sigBuf, sigLen, ctx, ctxLen, pk) != OQS_SUCCESS) {
                (void)fprintf(stderr, "--count-shake: a signature made with the counting table does not verify\n");
                return 3;
            }
            shakeMin = ((k == 0U) || (probes[k] < shakeMin)) ? probes[k] : shakeMin;
        }
        for (k = 0U; k < BENCH_SHAKE_PROBES; k++) {
            shakeStep = gcd(shakeStep, probes[k] - shakeMin);
        }
        if ((shakeMin == 0UL) || (shakeStep < 2UL)) {
            (void)fprintf(stderr, "--count-shake: %u signing calls gave counts from %lu in steps of %lu: not a round counter "
                                  "(this liboqs build may not call SHAKE-256 through the callback table)\n",
                          BENCH_SHAKE_PROBES, shakeMin, shakeStep);
            return 3;
        }
        shake = malloc(n * sizeof(*shake));
    }
    out = fopen(outPath, "w");
    wall = malloc(n * sizeof(*wall));
    cpuNs = malloc(n * sizeof(*cpuNs));
    if ((out == NULL) || (wall == NULL) || (cpuNs == NULL) || ((countShake != 0) && (shake == NULL))) {
        (void)fprintf(stderr, "cannot open %s or allocate %lu samples: %s\n", outPath, n, strerror(errno));
        return 1;
    }
    (void)memset(wall, 0, n * sizeof(*wall));       /* fault the pages in before the first sample */
    (void)memset(cpuNs, 0, n * sizeof(*cpuNs));
    if (shake != NULL) {
        (void)memset(shake, 0, n * sizeof(*shake));
    }
    mlockStatus = bench_lock_memory();
    if (bench_require_locked(mlockStatus, allowUnlocked) != 0) {
        return 1;
    }

    cpu = 0;
    for (c = 0; c < 2; c++) {
        f = (c == 0) ? stdout : out;
        cpu = bench_write_header(f, "bench_sign_attrib", mlockStatus);
        (void)fprintf(f, "# n=%lu\n# msg_bytes=%zu\n# ctx_bytes=%zu\n", n, msgLen, ctxLen);
#ifdef OQS_USE_OPENSSL
        (void)fprintf(f, "# rng=liboqs default (OpenSSL RAND_bytes, liboqs built with OQS_USE_OPENSSL)\n");
#else
        (void)fprintf(f, "# rng=liboqs default (system generator)\n");
#endif
        (void)fprintf(f, "# mldsa_signing=hedged (liboqs default)\n# clock_order=monotonic,thread_cpu,sign,thread_cpu,monotonic\n"
                         "# cpu_clock=CLOCK_THREAD_CPUTIME_ID\n# cpu_timer_overhead_ns=%" PRIu64 "\n", cpu_timer_overhead_ns());
        if (countShake != 0) {
            (void)fprintf(f, "# shake_counted=OQS_SHA3_shake256_inc_init, through OQS_SHA3_set_callbacks, forwarded to liboqs's own table\n"
                             "# shake_calls_min=%lu\n# shake_calls_step=%lu\n# shake_probes=%u\n", shakeMin, shakeStep, BENCH_SHAKE_PROBES);
        } else {
            (void)fprintf(f, "# shake_counted=off\n");
        }
    }
    (void)fputs((countShake != 0) ? "seq,wall_ns,cpu_ns,shake_calls\n" : "seq,wall_ns,cpu_ns\n", out);

    for (i = 0UL; i < n; i++) {
        uint64_t m0;
        uint64_t c0;
        uint64_t c1;
        uint64_t m1;
        OQS_STATUS rc;
        bench_fill(msg, msgLen, &inputRng);
        ShakeCalls = 0UL;
        m0 = bench_now_ns();
        c0 = cpu_now_ns();
        rc = OQS_SIG_sign_with_ctx_str(sig, sigBuf, &sigLen, msg, msgLen, ctx, ctxLen, sk);
        c1 = cpu_now_ns();
        m1 = bench_now_ns();
        if (rc != OQS_SUCCESS) {
            (void)fprintf(stderr, "mldsa_sign failed at seq %lu\n", i);
            return 1;
        }
        wall[i] = m1 - m0;
        cpuNs[i] = c1 - c0;
        if (shake != NULL) {
            shake[i] = (uint32_t)ShakeCalls;
        }
    }
    for (i = 0UL; i < n; i++) {
        if (shake != NULL) {
            (void)fprintf(out, "%lu,%" PRIu64 ",%" PRIu64 ",%u\n", i, wall[i], cpuNs[i], (unsigned)shake[i]);
        } else {
            (void)fprintf(out, "%lu,%" PRIu64 ",%" PRIu64 "\n", i, wall[i], cpuNs[i]);
        }
    }
    (void)printf("mldsa_sign: %lu samples\n", n);

    bench_write_footer(out, cpu, startNs);
    if ((ferror(out) != 0) || (fclose(out) != 0)) {
        (void)fprintf(stderr, "write to %s failed: %s\n", outPath, strerror(errno));
        return 1;
    }
    return 0;
}
