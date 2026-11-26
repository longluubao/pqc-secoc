/* Shared by the bench_* harnesses: clock, seedable generator, memory locking and the
 * "# key=value" comment block every CSV starts with (DATA_SCHEMA.md). */
#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <oqs/oqs.h>

/* Both come from bench/CMakeLists.txt, which refuses to configure without a commit stamp. */
#ifndef BENCH_GIT_COMMIT
#error "BENCH_GIT_COMMIT is not defined: build through bench/CMakeLists.txt"
#endif
#ifndef BENCH_C_FLAGS
#error "BENCH_C_FLAGS is not defined: build through bench/CMakeLists.txt"
#endif

#define BENCH_MAX_MSG_BYTES     4096U
#define BENCH_TIMER_PROBES      1001U

static inline uint64_t bench_now_ns(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

/* SplitMix64. Independent streams are different seeds, which is all the harnesses need. */
static inline uint64_t bench_rand64(uint64_t* state)
{
    uint64_t z;
    *state += 0x9E3779B97F4A7C15ULL;
    z = *state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static inline void bench_fill(uint8_t* buf, size_t len, uint64_t* state)
{
    size_t i = 0U;
    while (i < len) {
        uint64_t r = bench_rand64(state);
        unsigned k;
        for (k = 0U; (k < 8U) && (i < len); k++) {
            buf[i] = (uint8_t)(r >> (8U * k));
            i++;
        }
    }
}

/* Call after the result buffers are allocated and touched. A failure is recorded, not fatal:
 * an unprivileged run cannot lock a 16 MB buffer, and the header must say so. */
static inline const char* bench_lock_memory(void)
{
    static char status[96];
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0) {
        return "ok";
    }
    (void)snprintf(status, sizeof(status), "failed: %s", strerror(errno));
    return status;
}

/* FIPS 204 context of a PDU signature as the stack will use it: the label "PQC-SecOC-PDU-v1"
 * followed by the session transcript hash, which is all zero when there is no handshake.
 * Fills len bytes (0..BENCH_MAX_CTX_BYTES) of that string. */
#define BENCH_MAX_CTX_BYTES     255U
static inline void bench_pdu_context(uint8_t* ctx, size_t len)
{
    static const char label[] = "PQC-SecOC-PDU-v1";
    size_t i;
    for (i = 0U; i < len; i++) {
        ctx[i] = (i < (sizeof(label) - 1U)) ? (uint8_t)label[i] : 0U;
    }
}

/* A timing run whose pages can be swapped or faulted in late is not a measurement: refuse it
 * unless the caller says the run is not one. Returns 0 when the run may go on. */
static inline int bench_require_locked(const char* mlockStatus, int allowUnlocked)
{
    if ((strcmp(mlockStatus, "ok") == 0) || (allowUnlocked != 0)) {
        return 0;
    }
    (void)fprintf(stderr, "mlockall %s: raise the limit (sudo prlimit --pid $$ --memlock=unlimited:unlimited) "
                          "or pass --allow-unlocked for a run that is not a timing experiment\n", mlockStatus);
    return 1;
}

/* Median cost of one start/stop pair of the clock: the floor under every sample. */
static inline uint64_t bench_timer_overhead_ns(void)
{
    uint64_t d[BENCH_TIMER_PROBES];
    unsigned i;
    unsigned j;
    for (i = 0U; i < BENCH_TIMER_PROBES; i++) {
        uint64_t t0 = bench_now_ns();
        d[i] = bench_now_ns() - t0;
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

static inline void bench_cpufreq(int cpu, const char* leaf, char* out, size_t outLen)
{
    char path[96];
    FILE* f;
    (void)snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/%s", cpu, leaf);
    (void)snprintf(out, outLen, "unavailable");
    f = fopen(path, "r");
    if (f != NULL) {
        if (fgets(out, (int)outLen, f) != NULL) {
            out[strcspn(out, "\n")] = '\0';
        }
        (void)fclose(f);
    }
}

/* Writes the common header lines and returns the CPU they describe: the one the process is
 * pinned to, or the one it happens to run on if it is not pinned to a single CPU. */
static inline int bench_write_header(FILE* f, const char* tool, const char* mlockStatus)
{
    char host[64] = "unknown";
    char governor[32];
    char freq[32];
    cpu_set_t set;
    int cpu;
    int count = 0;
    int ref = sched_getcpu();

    (void)gethostname(host, sizeof(host) - 1U);
    (void)fprintf(f, "# tool=%s\n# commit=%s\n# host=%s\n# compile_flags=%s\n", tool, BENCH_GIT_COMMIT, host, BENCH_C_FLAGS);
    (void)fprintf(f, "# liboqs_version=%s\n# liboqs_build_target=%s\n# liboqs_opt_target=%s\n",
                  OQS_version(), OQS_COMPILE_BUILD_TARGET, OQS_OPT_TARGET);
    (void)fprintf(f, "# cpu_affinity=");
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof(set), &set) == 0) {
        for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
            if (CPU_ISSET((size_t)cpu, &set)) {
                (void)fprintf(f, "%s%d", (count > 0) ? " " : "", cpu);
                count++;
                if (count == 1) {
                    ref = cpu;
                }
            }
        }
    }
    if (count != 1) {
        ref = sched_getcpu();
    }
    bench_cpufreq(ref, "scaling_governor", governor, sizeof(governor));
    bench_cpufreq(ref, "scaling_cur_freq", freq, sizeof(freq));
    (void)fprintf(f, "\n# cpu_pinned=%s\n# cpu_sampled=%d\n# governor=%s\n# freq_khz_start=%s\n",
                  (count == 1) ? "yes" : "no", ref, governor, freq);
    (void)fprintf(f, "# mlockall=%s\n# clock=CLOCK_MONOTONIC\n# timer_overhead_ns=%" PRIu64 "\n",
                  mlockStatus, bench_timer_overhead_ns());
    return ref;
}

/* Closing lines: the frequency again, and whether the process had the core to itself. A pinned,
 * CPU-bound run uses nearly all of its wall time and is rarely preempted; a second busy task on
 * the same core shows as cpu_s well below wall_s and as many involuntary context switches. */
static inline void bench_write_footer(FILE* f, int cpu, uint64_t startNs)
{
    char freq[32];
    struct rusage ru;
    bench_cpufreq(cpu, "scaling_cur_freq", freq, sizeof(freq));
    (void)fprintf(f, "# freq_khz_end=%s\n", freq);
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        double cpuS = (double)(ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) +
                      ((double)(ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e6);
        (void)fprintf(f, "# wall_s=%.3f\n# cpu_s=%.3f\n# ctx_switches_involuntary=%ld\n# ctx_switches_voluntary=%ld\n",
                      (double)(bench_now_ns() - startNs) / 1e9, cpuS, ru.ru_nivcsw, ru.ru_nvcsw);
    }
}

#endif /* BENCH_COMMON_H */
