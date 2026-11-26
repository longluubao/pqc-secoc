/* bench_clock_probe: measures the offset between the clocks of two boards during a run, by a two-way
 * exchange over UDP, and on each board the relation of its two clocks (E9: end-to-end latency across
 * the boards; clock_probe.csv and clock_map_<a|b>.csv of DATA_SCHEMA.md, probe format 2). No stack, no
 * root, no clock is changed.
 *
 * The PDU stamps of the harnesses are CLOCK_MONOTONIC, which a time-synchronisation service steers;
 * CLOCK_MONOTONIC_RAW is not steered. The probe therefore reads RAW, MONOTONIC, RAW, with nothing in
 * between, wherever it takes a stamp. The raw read next to the datagram is the stamp of the exchange,
 * the monotonic read is kept beside it, and the distance of the two raw reads is the width of the point.
 *
 * The client (board A) sends one request every --interval-ms and stamps t1 right before the send (its
 * SECOND raw read) and t4 right after the reply is read (its FIRST raw read); the server (board B)
 * stamps t2 right after it has read the request (first raw read) and t3 right before it sends the
 * reply (second raw read). For every exchange, on the raw stamps,
 *     theta = ((t2 - t1) - (t4 - t3)) / 2     (clock B minus clock A)
 *     delta = (t4 - t1) - (t3 - t2)           (round trip without the server's own time)
 * and the true offset lies within theta +/- delta / 2 whatever the asymmetry of the two directions,
 * because t2 is not before the arrival and t3 not after the departure of the datagrams.
 *
 * A second thread in each process, on the same core, reads RAW, MONOTONIC, RAW every 5 ms (deadlines
 * on CLOCK_MONOTONIC that always advance by 5 ms) from the start of the process to its end, into
 * memory that exists before it starts (--map-samples, default one hour); a sample that finds the
 * memory full is counted as dropped. That is the board's clock map: CLOCK_MONOTONIC minus the raw
 * clock, by which a reader carries a CLOCK_MONOTONIC stamp of this board onto its raw clock.
 *
 * Server:  bench_clock_probe --server --port P [--cpu N] [--bind A.B.C.D] [--map-out FILE] [--map-samples N]
 * Client:  bench_clock_probe --client --peer A.B.C.D --port P --out FILE [--map-out FILE] [--cpu N]
 *                            [--interval-ms 100] [--max-rows N] [--map-samples N]
 * Both run until SIGTERM or SIGINT. The client then goes on to the end of the window of 5 s that is
 * running (windows are counted from its first completed exchange on the raw clock, as the offset
 * track counts them), so that the last anchor of the track is the best exchange of a whole window.
 * Then the sampler is stopped and the files are written, each under a temporary name that is renamed
 * when it is complete: FILE (only completed exchanges are rows, seq counts the exchanges sent, so a
 * lost one is a gap in seq) and the map (role a for the client, b for the server). The client prints
 * "first exchange completed" when the first reply has arrived. A reply that comes after the next
 * request has gone out is ignored. --cpu pins the process (Linux); -1 or no option leaves it unpinned.
 * A peer of probe format 1 (stamps of CLOCK_MONOTONIC only) is not served: the server says so; the
 * client gets no reply from such a server and says so when it ends.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sched.h>
#endif

#ifndef BENCH_GIT_COMMIT
#define BENCH_GIT_COMMIT "unknown"
#endif

#define PROBE_MAGIC             0x50514350UL    /* "PQCP" */
#define PROBE_FORMAT            2U
#define PROBE_REPLY_BYTES       100U            /* magic, format, seq, t2 and t3 as (mono, raw stamp, width), core, host name */
#define PROBE_REQUEST_BYTES     PROBE_REPLY_BYTES   /* magic, format, seq, then zeros: as long on the wire as the reply, so that
                                                     * the two directions take the same time on a slow link */
#define PROBE_FORMAT1_REQUEST   20U             /* what a client of format 1 sends */
#define PROBE_HOST_BYTES        32U
#define PROBE_WINDOW_NS         5000000000ULL   /* a window of the offset track (DATA_SCHEMA.md), from the first exchange on */
#define PROBE_END_MARGIN_NS     5000000ULL      /* no exchange is started this close before the end of the last window */
#define PROBE_MAP_INTERVAL_NS   5000000ULL
#define PROBE_MAP_SAMPLES       720000UL        /* one hour of map samples */
#define PROBE_MAP_PHASE_NS      500000ULL       /* the client's requests keep this far from the sampler's deadlines */

typedef struct {        /* one stamp point: the three reads in the order they were made */
    uint64_t raw1;
    uint64_t mono;
    uint64_t raw2;
} probe_triple_t;

typedef struct {        /* one completed exchange, points 1 to 4 */
    uint64_t seq;
    uint64_t mono[4];
    uint64_t raw[4];    /* the raw read next to the datagram */
    uint64_t width[4];  /* raw2 - raw1 of the point */
} probe_row_t;

static const char Commit[] = BENCH_GIT_COMMIT;
static volatile sig_atomic_t Stop;

/* The clock map. Map and MapSize are set before the sampler starts; MapCount and MapDropped are written by
 * the sampler alone and read by the main thread only after it has joined the sampler. */
static probe_triple_t* Map;
static unsigned long MapSize = PROBE_MAP_SAMPLES;
static unsigned long MapCount;
static unsigned long MapDropped;
static uint64_t MapEpochNs;             /* the sampler's first deadline, CLOCK_MONOTONIC */
static atomic_int SamplerStop;
static pthread_t SamplerThread;

static void on_signal(int sig)
{
    (void)sig;
    Stop = 1;
}

static uint64_t ts_ns(const struct timespec* ts)
{
    return ((uint64_t)ts->tv_sec * 1000000000ULL) + (uint64_t)ts->tv_nsec;
}

static uint64_t clock_ns(clockid_t id)
{
    struct timespec ts;
    (void)clock_gettime(id, &ts);
    return ts_ns(&ts);
}

/* RAW, MONOTONIC, RAW: the three reads back to back, converted only afterwards */
static inline void read_triple(probe_triple_t* t)
{
    struct timespec a;
    struct timespec m;
    struct timespec b;
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &a);
    (void)clock_gettime(CLOCK_MONOTONIC, &m);
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &b);
    t->raw1 = ts_ns(&a);
    t->mono = ts_ns(&m);
    t->raw2 = ts_ns(&b);
}

static void put_u32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24U);
    p[1] = (uint8_t)(v >> 16U);
    p[2] = (uint8_t)(v >> 8U);
    p[3] = (uint8_t)v;
}

static uint32_t get_u32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U) | ((uint32_t)p[2] << 8U) | (uint32_t)p[3];
}

static void put_u64(uint8_t* p, uint64_t v)
{
    put_u32(p, (uint32_t)(v >> 32U));
    put_u32(&p[4], (uint32_t)v);
}

static uint64_t get_u64(const uint8_t* p)
{
    return ((uint64_t)get_u32(p) << 32U) | (uint64_t)get_u32(&p[4]);
}

/* 0 on success; a core of -1 means "do not pin" */
static int pin_to(int cpu)
{
#ifdef __linux__
    if (cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET((size_t)cpu, &set);
        return sched_setaffinity(0, sizeof(set), &set);
    }
#else
    (void)cpu;
#endif
    return 0;
}

static int udp_socket(const char* bindAddr, uint16_t port)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        return -1;
    }
    (void)memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if ((bindAddr != NULL) && (inet_pton(AF_INET, bindAddr, &addr.sin_addr) != 1)) {
        (void)close(fd);
        return -1;
    }
    if (((bindAddr != NULL) || (port != 0U)) && (bind(fd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

/* Sleeps to an instant of CLOCK_MONOTONIC; a signal does not end it early. */
static void sleep_until_ns(uint64_t due)
{
#ifdef __linux__
    struct timespec ts;
    ts.tv_sec = (time_t)(due / 1000000000ULL);
    ts.tv_nsec = (long)(due % 1000000000ULL);
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {
    }
#else
    for (;;) {
        uint64_t now = clock_ns(CLOCK_MONOTONIC);
        struct timespec ts;
        if (now >= due) {
            break;
        }
        ts.tv_sec = (time_t)((due - now) / 1000000000ULL);
        ts.tv_nsec = (long)((due - now) % 1000000000ULL);
        (void)nanosleep(&ts, NULL);
    }
#endif
}

/* The sampler: one triple per deadline into memory that already exists. It allocates nothing, writes no file
 * and takes no lock; the two signals that end the process are blocked in it, so they reach the main thread. */
static void* sampler(void* arg)
{
    uint64_t due = MapEpochNs;

    (void)arg;
    while (atomic_load(&SamplerStop) == 0) {
        probe_triple_t t;
        sleep_until_ns(due);
        read_triple(&t);
        if (MapCount < MapSize) {
            Map[MapCount] = t;
            MapCount++;
        } else {
            MapDropped++;
        }
        due += PROBE_MAP_INTERVAL_NS;       /* always one interval on: a late sample is followed at once, none is skipped */
    }
    return NULL;
}

/* 0 on success. The memory is touched here, before the first sample. */
static int sampler_start(void)
{
    sigset_t block;
    sigset_t old;
    int rc;

    Map = calloc(MapSize, sizeof(*Map));
    if (Map == NULL) {
        return -1;
    }
    (void)memset(Map, 0, MapSize * sizeof(*Map));
    (void)sigemptyset(&block);
    (void)sigaddset(&block, SIGTERM);
    (void)sigaddset(&block, SIGINT);
    (void)pthread_sigmask(SIG_BLOCK, &block, &old);     /* the new thread starts with these blocked */
    MapEpochNs = clock_ns(CLOCK_MONOTONIC);
    rc = pthread_create(&SamplerThread, NULL, sampler, NULL);
    (void)pthread_sigmask(SIG_SETMASK, &old, NULL);
    return rc;
}

static void sampler_stop(void)
{
    atomic_store(&SamplerStop, 1);
    (void)pthread_join(SamplerThread, NULL);
}

/* The commit as the files carry it: its first 12 hex digits and whatever follows the hash ("-dirty") in full. */
static void write_commit(FILE* f)
{
    size_t hex = strspn(Commit, "0123456789abcdef");
    (void)fprintf(f, "# commit=%.12s%s\n", Commit, (hex >= 12U) ? &Commit[hex] : "");
}

/* A file is written under <path>.tmp and renamed when it is complete, so that no reader finds half of one. */
static FILE* open_tmp(const char* path, char* tmp, size_t tmpLen)
{
    if (snprintf(tmp, tmpLen, "%s.tmp", path) >= (int)tmpLen) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    return fopen(tmp, "w");
}

static int close_tmp(FILE* f, const char* tmp, const char* path)
{
    int bad = ferror(f);
    if (fclose(f) != 0) {       /* closed in any case */
        bad = 1;
    }
    if (bad != 0) {
        (void)fprintf(stderr, "write to %s failed: %s\n", tmp, strerror(errno));
        return 1;
    }
    if (rename(tmp, path) != 0) {
        (void)fprintf(stderr, "cannot rename %s to %s: %s\n", tmp, path, strerror(errno));
        return 1;
    }
    return 0;
}

/* The clock map of this process (the sampler has been joined). 0 on success. */
static int write_map(FILE* f, const char* tmp, const char* path, char role, int cpu)
{
    char host[64] = "unknown";
    unsigned long i;

    (void)gethostname(host, sizeof(host) - 1U);
    (void)fprintf(f, "# tool=bench_clock_probe\n");
    write_commit(f);
    (void)fprintf(f, "# host=%s\n# role=%c\n# clock=CLOCK_MONOTONIC\n# clock_raw=CLOCK_MONOTONIC_RAW\n# interval_ms=%u\n# cpu=%d\n",
                  host, role, (unsigned)(PROBE_MAP_INTERVAL_NS / 1000000ULL), cpu);
    (void)fprintf(f, "raw1_ns,mono_ns,raw2_ns\n");
    for (i = 0UL; i < MapCount; i++) {
        (void)fprintf(f, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n", Map[i].raw1, Map[i].mono, Map[i].raw2);
    }
    (void)fprintf(f, "# samples=%lu\n# samples_dropped=%lu\n", MapCount, MapDropped);
    return close_tmp(f, tmp, path);
}

static int run_server(const char* bindAddr, uint16_t port, int cpu, const char* mapPath)
{
    uint8_t in[PROBE_REQUEST_BYTES + 4U];
    uint8_t out[PROBE_REPLY_BYTES];
    char host[PROBE_HOST_BYTES];
    char mapTmp[1024];
    unsigned long answered = 0UL;
    unsigned long refused = 0UL;
    FILE* mapFile = (mapPath != NULL) ? open_tmp(mapPath, mapTmp, sizeof(mapTmp)) : NULL;     /* a path that cannot be written is found now */
    int fd = udp_socket(bindAddr, port);
    int rc = 0;

    if ((fd < 0) || ((mapPath != NULL) && (mapFile == NULL))) {
        (void)fprintf(stderr, "cannot bind UDP port %u or open %s.tmp: %s\n", (unsigned)port, (mapPath != NULL) ? mapPath : "(no map)",
                      strerror(errno));
        return 1;
    }
    if (sampler_start() != 0) {
        (void)fprintf(stderr, "cannot start the map sampler (%lu samples)\n", MapSize);
        return 1;
    }
    (void)memset(host, 0, sizeof(host));
    (void)gethostname(host, sizeof(host) - 1U);
    (void)memset(out, 0, sizeof(out));
    put_u32(out, (uint32_t)PROBE_MAGIC);
    put_u32(&out[4], PROBE_FORMAT);
    put_u32(&out[64], (uint32_t)cpu);
    (void)memcpy(&out[68], host, PROBE_HOST_BYTES);
    (void)printf("clock probe server on UDP port %u\n", (unsigned)port);
    (void)fflush(stdout);

    while (Stop == 0) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        struct sockaddr_in peer;
        socklen_t peerLen = sizeof(peer);
        probe_triple_t p2;
        probe_triple_t p3;
        ssize_t n;

        if (poll(&pfd, 1, 200) <= 0) {
            continue;       /* nothing came, or a signal: look at Stop */
        }
        n = recvfrom(fd, in, sizeof(in), 0, (struct sockaddr*)&peer, &peerLen);
        read_triple(&p2);                           /* t2: the first thing after the read; its first raw read is the stamp */
        if ((n < 8) || (get_u32(in) != (uint32_t)PROBE_MAGIC)) {
            continue;                               /* not a probe at all */
        }
        if ((n != (ssize_t)PROBE_REQUEST_BYTES) || (get_u32(&in[4]) != PROBE_FORMAT)) {
            if (refused == 0UL) {                   /* said once: a client that cannot use the answer gets none */
                (void)printf("a request of another probe format is not served (%ld bytes%s; this server is format %u)\n", (long)n,
                             (n == (ssize_t)PROBE_FORMAT1_REQUEST) ? ", a client of format 1" : "", PROBE_FORMAT);
                (void)fflush(stdout);
            }
            refused++;
            continue;
        }
        (void)memcpy(&out[8], &in[8], 8U);          /* seq goes back as it came */
        put_u64(&out[16], p2.mono);
        put_u64(&out[24], p2.raw1);
        put_u64(&out[32], p2.raw2 - p2.raw1);
        read_triple(&p3);                           /* t3: its second raw read is the stamp, the send follows */
        put_u64(&out[40], p3.mono);
        put_u64(&out[48], p3.raw2);
        put_u64(&out[56], p3.raw2 - p3.raw1);
        if (sendto(fd, out, sizeof(out), 0, (const struct sockaddr*)&peer, peerLen) == (ssize_t)sizeof(out)) {
            answered++;
        }
    }
    sampler_stop();
    (void)close(fd);
    if (mapFile != NULL) {
        rc = write_map(mapFile, mapTmp, mapPath, 'b', cpu);
    }
    (void)printf("requests_answered=%lu requests_of_another_format=%lu map_samples=%lu map_samples_dropped=%lu\n", answered, refused,
                 MapCount, MapDropped);
    return rc;
}

static int run_client(const char* peerAddr, uint16_t port, int cpu, uint64_t intervalMs, unsigned long maxRows,
                      const char* outPath, const char* mapPath)
{
    struct sockaddr_in peer;
    uint8_t out[PROBE_REQUEST_BYTES];
    uint8_t in[PROBE_REPLY_BYTES + 4U];
    char hostA[64] = "unknown";
    char hostB[PROBE_HOST_BYTES + 1U] = "unknown";
    char outTmp[1024];
    char mapTmp[1024];
    int cpuB = -1;
    probe_row_t* rows = calloc(maxRows, sizeof(*rows));
    unsigned long sent = 0UL;
    unsigned long completed = 0UL;
    unsigned long otherFormat = 0UL;
    unsigned long i;
    uint64_t start;
    uint64_t firstTauRaw = 0U;          /* (t1 + t4) / 2 of the first completed exchange on the raw clock: where the windows start */
    uint64_t endRaw = UINT64_MAX;       /* told to end: when, on the raw clock, the window that is running then is over */
    FILE* f = open_tmp(outPath, outTmp, sizeof(outTmp));    /* opened now: a path that cannot be written is found before the run */
    FILE* mapFile = (mapPath != NULL) ? open_tmp(mapPath, mapTmp, sizeof(mapTmp)) : NULL;
    int fd = udp_socket(NULL, 0U);
    int rc = 0;

    (void)memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(port);
    if ((rows == NULL) || (f == NULL) || ((mapPath != NULL) && (mapFile == NULL)) || (fd < 0) ||
        (inet_pton(AF_INET, peerAddr, &peer.sin_addr) != 1) || (connect(fd, (const struct sockaddr*)&peer, sizeof(peer)) != 0)) {
        (void)fprintf(stderr, "cannot open %s.tmp or the map's, allocate %lu rows or reach %s:%u: %s\n", outPath, maxRows, peerAddr,
                      (unsigned)port, strerror(errno));
        return 1;
    }
    (void)memset(rows, 0, maxRows * sizeof(*rows));     /* the pages exist before the first exchange */
    (void)gethostname(hostA, sizeof(hostA) - 1U);
    (void)memset(out, 0, sizeof(out));
    put_u32(out, (uint32_t)PROBE_MAGIC);
    put_u32(&out[4], PROBE_FORMAT);
    if (sampler_start() != 0) {
        (void)fprintf(stderr, "cannot start the map sampler (%lu samples)\n", MapSize);
        return 1;
    }

    /* The requests go out half a millisecond off the sampler's deadlines (both threads share the core): for an
     * interval of whole milliseconds they then never fall on one. */
    start = clock_ns(CLOCK_MONOTONIC);
    start = MapEpochNs + ((((start - MapEpochNs) / PROBE_MAP_INTERVAL_NS) + 1ULL) * PROBE_MAP_INTERVAL_NS) + PROBE_MAP_PHASE_NS;
    while (completed < maxRows) {
        uint64_t due = start + ((uint64_t)sent * intervalMs * 1000000ULL);
        uint64_t giveUp = due + ((intervalMs * 1000000ULL * 9ULL) / 10ULL);     /* before the next request */
        uint64_t seq = (uint64_t)sent;
        probe_triple_t p1;

        if (Stop != 0) {
            /* Told to end. A last window with the few exchanges that happened to precede the signal would give the
             * track an anchor that is not the best of 5 s (under load: a slow one): the window is completed. The
             * windows are those of the raw clock; this request would go out at `due` of CLOCK_MONOTONIC. */
            uint64_t nowMono = clock_ns(CLOCK_MONOTONIC);
            uint64_t nowRaw = clock_ns(CLOCK_MONOTONIC_RAW);
            uint64_t dueRaw = nowRaw + ((due > nowMono) ? (due - nowMono) : 0U);
            if (endRaw == UINT64_MAX) {
                endRaw = (completed == 0UL) ? nowRaw : (firstTauRaw + ((((nowRaw - firstTauRaw) / PROBE_WINDOW_NS) + 1ULL) * PROBE_WINDOW_NS));
            }
            if ((dueRaw + PROBE_END_MARGIN_NS) >= endRaw) {
                break;
            }
        }
        sleep_until_ns(due);
        put_u64(&out[8], seq);
        read_triple(&p1);                           /* t1: its second raw read is the stamp, the send follows */
        if (send(fd, out, sizeof(out), 0) != (ssize_t)sizeof(out)) {
            sent++;                                 /* counted as sent and lost: a gap in seq */
            continue;
        }
        sent++;
        for (;;) {
            struct pollfd pfd = { fd, POLLIN, 0 };
            uint64_t now = clock_ns(CLOCK_MONOTONIC);
            probe_triple_t p4;
            probe_row_t* row = &rows[completed];
            ssize_t n;
            int ready;

            if (now >= giveUp) {
                break;                              /* no reply in time: lost */
            }
            ready = poll(&pfd, 1, (int)(((giveUp - now) / 1000000ULL) + 1ULL));
            if ((ready < 0) && (errno == EINTR)) {
                continue;                           /* the signal that ends the run: this exchange still counts */
            }
            if (ready <= 0) {
                break;
            }
            n = recv(fd, in, sizeof(in), 0);
            read_triple(&p4);                       /* t4: the first thing after the read; its first raw read is the stamp */
            if ((n >= 8) && (get_u32(in) == (uint32_t)PROBE_MAGIC) &&
                ((n != (ssize_t)PROBE_REPLY_BYTES) || (get_u32(&in[4]) != PROBE_FORMAT))) {
                otherFormat++;                      /* a server of another probe format: its answer is not used */
                continue;
            }
            if ((n != (ssize_t)PROBE_REPLY_BYTES) || (get_u32(in) != (uint32_t)PROBE_MAGIC) || (get_u64(&in[8]) != seq)) {
                continue;                           /* a late reply to an earlier request, or not ours */
            }
            row->seq = seq;
            row->mono[0] = p1.mono;
            row->raw[0] = p1.raw2;
            row->width[0] = p1.raw2 - p1.raw1;
            row->mono[1] = get_u64(&in[16]);
            row->raw[1] = get_u64(&in[24]);
            row->width[1] = get_u64(&in[32]);
            row->mono[2] = get_u64(&in[40]);
            row->raw[2] = get_u64(&in[48]);
            row->width[2] = get_u64(&in[56]);
            row->mono[3] = p4.mono;
            row->raw[3] = p4.raw1;
            row->width[3] = p4.raw2 - p4.raw1;
            if (completed == 0UL) {
                firstTauRaw = row->raw[0] + ((row->raw[3] - row->raw[0]) / 2U);
                cpuB = (int)(int32_t)get_u32(&in[64]);
                (void)memcpy(hostB, &in[68], PROBE_HOST_BYTES);
                hostB[PROBE_HOST_BYTES] = '\0';
                (void)printf("first exchange completed\n");
                (void)fflush(stdout);
            }
            completed++;
            break;
        }
    }
    sampler_stop();     /* after the last exchange: the map covers every stamp of this process */
    (void)close(fd);

    (void)fprintf(f, "# tool=bench_clock_probe\n# format=%u\n", PROBE_FORMAT);
    write_commit(f);
    (void)fprintf(f, "# host_a=%s\n# host_b=%s\n# clock=CLOCK_MONOTONIC\n# clock_raw=CLOCK_MONOTONIC_RAW\n"
                     "# interval_ms=%" PRIu64 "\n# port=%u\n# cpu_a=%d\n# cpu_b=%d\n",
                  hostA, hostB, intervalMs, (unsigned)port, cpu, cpuB);
    (void)fprintf(f, "seq,t1_ns,t2_ns,t3_ns,t4_ns,t1r_ns,t2r_ns,t3r_ns,t4r_ns,w1_ns,w2_ns,w3_ns,w4_ns\n");
    for (i = 0UL; i < completed; i++) {
        const probe_row_t* r = &rows[i];
        (void)fprintf(f, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
                         ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                      r->seq, r->mono[0], r->mono[1], r->mono[2], r->mono[3], r->raw[0], r->raw[1], r->raw[2], r->raw[3],
                      r->width[0], r->width[1], r->width[2], r->width[3]);
    }
    (void)fprintf(f, "# exchanges_sent=%lu\n# exchanges_completed=%lu\n", sent, completed);
    rc = close_tmp(f, outTmp, outPath);
    if (mapFile != NULL) {
        rc |= write_map(mapFile, mapTmp, mapPath, 'a', cpu);
    }
    if (otherFormat != 0UL) {
        (void)printf("%lu replies of another probe format were not used (this client is format %u)\n", otherFormat, PROBE_FORMAT);
    }
    if (completed == 0UL) {
        (void)printf("no reply: no server at %s:%u, or a server of another probe format (this client is format %u)\n", peerAddr,
                     (unsigned)port, PROBE_FORMAT);
    }
    (void)printf("exchanges_sent=%lu exchanges_completed=%lu map_samples=%lu map_samples_dropped=%lu\n", sent, completed, MapCount,
                 MapDropped);
    free(rows);
    if (rc != 0) {
        return 1;
    }
    return (completed > 0UL) ? 0 : 3;       /* 3: the server never answered */
}

int main(int argc, char** argv)
{
    static const struct option longOpts[] = {
        { "server", no_argument, NULL, 's' },        { "client", no_argument, NULL, 'c' },
        { "peer", required_argument, NULL, 'p' },    { "port", required_argument, NULL, 'P' },
        { "bind", required_argument, NULL, 'b' },    { "cpu", required_argument, NULL, 'u' },
        { "out", required_argument, NULL, 'o' },     { "interval-ms", required_argument, NULL, 'i' },
        { "max-rows", required_argument, NULL, 'm' }, { "map-out", required_argument, NULL, 'M' },
        { "map-samples", required_argument, NULL, 'S' }, { NULL, 0, NULL, 0 }
    };
    struct sigaction sa;
    const char* peer = NULL;
    const char* bindAddr = NULL;
    const char* outPath = NULL;
    const char* mapPath = NULL;
    unsigned long port = 0UL;
    unsigned long intervalMs = 100UL;
    unsigned long maxRows = 72000UL;        /* two hours at ten exchanges per second; the map holds one */
    int server = 0;
    int client = 0;
    int cpu = -1;
    int c;

    while ((c = getopt_long(argc, argv, "", longOpts, NULL)) != -1) {
        switch (c) {
        case 's': server = 1; break;
        case 'c': client = 1; break;
        case 'p': peer = optarg; break;
        case 'P': port = strtoul(optarg, NULL, 10); break;
        case 'b': bindAddr = optarg; break;
        case 'u': cpu = atoi(optarg); break;
        case 'o': outPath = optarg; break;
        case 'i': intervalMs = strtoul(optarg, NULL, 10); break;
        case 'm': maxRows = strtoul(optarg, NULL, 10); break;
        case 'M': mapPath = optarg; break;
        case 'S': MapSize = strtoul(optarg, NULL, 10); break;
        default: port = 0UL; break;
        }
    }
    if ((server == client) || (port == 0UL) || (port > 65535UL) || (intervalMs < 10UL) || (maxRows == 0UL) || (MapSize == 0UL) ||
        ((client != 0) && ((peer == NULL) || (outPath == NULL)))) {
        (void)fprintf(stderr, "usage: bench_clock_probe --server --port P [--cpu N] [--bind A.B.C.D] [--map-out FILE] [--map-samples N]\n"
                              "       bench_clock_probe --client --peer A.B.C.D --port P --out FILE [--map-out FILE] [--cpu N]\n"
                              "                         [--interval-ms 100] [--max-rows N] [--map-samples N]\n");
        return 2;
    }
    if (pin_to(cpu) != 0) {
        (void)fprintf(stderr, "cannot run on cpu %d: %s\n", cpu, strerror(errno));
        return 1;
    }
    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;      /* no SA_RESTART: a poll ends and the loop sees Stop */
    (void)sigaction(SIGTERM, &sa, NULL);
    (void)sigaction(SIGINT, &sa, NULL);
    return (server != 0) ? run_server(bindAddr, (uint16_t)port, cpu, mapPath)
                         : run_client(peer, (uint16_t)port, cpu, (uint64_t)intervalMs, maxRows, outPath, mapPath);
}
