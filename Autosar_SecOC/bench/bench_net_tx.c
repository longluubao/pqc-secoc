/* bench_net_tx: open-loop transmitter for periodic streams and sustained load, through the real
 * transmit path (SecOC_TpTransmit -> SecOC -> Csm -> CryIf -> liboqs, then PduR -> SoAd -> TcpIp).
 *
 * Releases are absolute instants t0 + j * period on CLOCK_MONOTONIC and never wait for the job
 * before them. The released jobs of a stream wait in a FIFO queue of bounded length; a job released
 * while its queue is full is dropped. One worker thread, pinned to one CPU, serves the queues and
 * runs the BSW main functions, in one of two ways (--mainfunction):
 *   cyclic  (default) a fixed-period executive, 1 ms unless --mf-period-us says otherwise, on
 *           absolute CLOCK_MONOTONIC ticks. Each tick calls, in the order of the gateway's BSW
 *           cycle, SecOC_MainFunctionRx, the application step (for every stream: hand its next
 *           queued job to SecOC_TpTransmit if its previous one is confirmed), SecOC_MainFunctionTx,
 *           Csm_MainFunction, SoAd_MainFunctionTx, SoAd_MainFunctionRx: a job handed over in a
 *           tick is authenticated and sent in that tick. A tick that runs past the next ones
 *           (signing takes longer than 1 ms) skips them; skipped ticks are counted as overruns.
 *   event   no period: for each job, oldest release of all streams first, SecOC_TpTransmit, then
 *           SecOC_MainFunctionTx and SoAd_MainFunctionTx back to back until SoAd confirms the PDU.
 *           The lower bound, without tick quantisation.
 *
 * Before the first release the transmitter runs the handshake PQC-SecOC-HS-v1 as initiator, as the
 * transmitting gateway does (--no-handshake: no handshake component, session-less PDUs, for
 * development; a gateway receiver refuses those). It waits, with the main functions in the cycle
 * order and 1 ms apart, until its attempt has ended ok, and gives up after --hs-timeout-ms (15000).
 * The session identifier goes into the header (session_id); --handshake-out FILE gets the attempt
 * records as handshake.csv. --rekey-after N (cyclic mode) asks for one more handshake when N jobs are
 * done, under the running stream: the trigger of the handshake tests.
 *
 * SIGTERM or SIGINT ends the run cleanly (the driver's temperature limit): nothing is released
 * after it, what was released is finished, and the files are written with stopped_early=1.
 *
 * Output, written after the run from memory:
 *   --out      periodic_tx.csv   stream,seq,release_ns,start_ns,auth_done_ns,send_done_ns
 *              release nominal; start = worker took the job; auth_done = Csm_SignatureGenerate
 *              returned; send_done = SoAd confirmed after the last byte was accepted by the socket
 *   --samples  throughput.csv    one row per second (DATA_SCHEMA.md), only with --rate-pps
 *
 * Periodic run:  bench_net_tx --peer 10.10.10.2:50002 --key-dir DIR --cpu 3 --period-us 10000 --count 2000 --out FILE
 * Load step:     bench_net_tx --peer ... --key-dir DIR --cpu 3 --rate-pps 300 --ramp 15 --duration 60
 *                             --out FILE --samples FILE --rx-host NAME [--iface eth0]
 * Options:       --mainfunction cyclic|event  --mf-period-us T (cyclic, default 1000)
 *                --deadline-us D (default: the period)  --sched other|fifo  --priority P (fifo, default 80)
 *                --backlog JOBS (default 4)  --payload-bytes B (8..20, default 8)  --phase sync|staggered
 *                --streams K (1..8, default 1: the first K signature streams; every stream has
 *                the given period or rate, and --backlog counts per stream)
 *                --cores 1  --allow-unlocked
 *                --profile mldsa65|mac|both (default mldsa65: the signature streams; mac: the MAC stream,
 *                HMAC-SHA-256 with the session's key, so only with the handshake, one stream; both:
 *                --streams 2, stream 0 the first signature stream and stream 1 the MAC stream)
 *                --partition I --partitions N --rep K   (this process is partition I of N, repetition K
 *                of its rate step: header keys for the analysis, no effect on the run)
 */
#define _GNU_SOURCE
#include "bench_net.h"
#include "bench_tcpinfo.h"
#include "bsw_stamps.h"

#include <getopt.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include "Csm.h"
#include "PduR_SoAd.h"
#include "PqcHs.h"
#include "SecOC.h"
#include "SecOC_Lcfg.h"
#include "SoAd.h"

/* The streams of a run: the first NStreams signature streams of the tree's identifier table
 * (SoAd_PduIds.h), each its own Secured I-PDU with its own freshness counter, all on the one TCP
 * connection. */
#define BENCH_TX_MAX_CYCLES     4       /* one cycle confirms a PDU; more only while SoAd waits for the upper layer */
#define BENCH_CONFIRM_TICKS     2000UL  /* cyclic: a PDU not confirmed after this many ticks is given up, as App_Tx does */
#define BENCH_DRAIN_TIMEOUT_NS  5000000000ULL

typedef struct {
    uint64_t release;
    uint64_t start;
    uint64_t auth;
    uint64_t send;
} bench_job_t;

/* One stream: its releases so far, the released jobs waiting for SecOC (sequence numbers, oldest
 * first, at most Backlog), the job SecOC holds (one Authentic I-PDU per PDU), what the hooks saw. */
typedef struct {
    PduIdType     pdu;
    uint32_t*     queue;
    unsigned long head;
    unsigned long len;
    unsigned long next;
    bench_job_t*  flying;
    unsigned long flyingTicks;
    uint64_t      authNs;
    uint64_t      sendNs;
    unsigned long confirmed;
    unsigned long failed;
    unsigned long confirmedBefore;
    unsigned long failedBefore;
} bench_stream_t;

static bench_stream_t St[BENCH_NET_MAX_STREAMS];
static size_t NStreams = 1U;
static unsigned long SignCalls;
static unsigned long Confirmed;
static unsigned long ConfirmFailed;
static volatile unsigned long JobsDone;
static volatile unsigned long JobsLost;     /* dropped at release or not confirmed */
static volatile sig_atomic_t StopRequested;
static unsigned long RekeyAfter;            /* 0: never */

static void on_signal(int sig)
{
    (void)sig;
    StopRequested = 1;
}

static bench_stream_t* stream_of(PduIdType pdu)
{
    size_t s;
    for (s = 0U; s < NStreams; s++) {
        if (St[s].pdu == pdu) {
            return &St[s];
        }
    }
    return NULL;
}

/************************** what the timestamp hooks (bsw_stamps.c) report *************************/

/* auth_done_ns: the authenticator exists (Csm_SignatureGenerate returned to SecOC). */
static void on_signed(PduIdType pdu, uint64_t ns)
{
    bench_stream_t* st = stream_of(pdu);
    if (st != NULL) {
        st->authNs = ns;
    }
    SignCalls++;
}

/* send_done_ns: SoAd confirms right after TcpIp_TcpTransmit took the last bytes of the PDU. */
static void on_tx_confirmed(PduIdType pdu, Std_ReturnType result, uint64_t ns)
{
    bench_stream_t* st = stream_of(pdu);
    if (result == E_OK) {
        Confirmed++;
        if (st != NULL) {
            st->sendNs = ns;
            st->confirmed++;
        }
    } else {
        ConfirmFailed++;
        if (st != NULL) {
            st->failed++;
        }
    }
}

/********************************************* worker ********************************************/

static void sleep_until(uint64_t ns)
{
    struct timespec ts = { (time_t)(ns / 1000000000ULL), (long)(ns % 1000000000ULL) };
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {
    }
}

/* The run: release schedule, one row per job (row = seq * NStreams + stream). */
static bench_job_t* Jobs;
static unsigned long Backlog = 4UL;         /* per stream: four periods of jobs */
static unsigned long Count;
static unsigned long Started;
static unsigned long Dropped;
static unsigned long Overruns;
static uint64_t T0;
static uint64_t PeriodNs;
static int Staggered;
static size_t PayloadLen = 8U;

/* Admit every release whose instant has passed, oldest first, as a release timer would have done
 * while the worker was busy. Returns the instant of the next release, UINT64_MAX if there is none. */
static uint64_t admit(uint64_t now)
{
    if (StopRequested != 0) {
        /* asked to end: the run now has as many releases per stream as the furthest stream got */
        unsigned long most = 0UL;
        size_t s;
        for (s = 0U; s < NStreams; s++) {
            most = (St[s].next > most) ? St[s].next : most;
        }
        Count = (most < Count) ? most : Count;
    }
    for (;;) {
        uint64_t due = UINT64_MAX;
        bench_stream_t* st;
        size_t dueStream = 0U;
        size_t s;
        for (s = 0U; s < NStreams; s++) {
            uint64_t offset = (Staggered != 0) ? ((PeriodNs * s) / NStreams) : 0U;
            uint64_t release = T0 + offset + ((uint64_t)St[s].next * PeriodNs);
            if ((St[s].next < Count) && (release < due)) {
                due = release;
                dueStream = s;
            }
        }
        if (due > now) {
            return due;
        }
        st = &St[dueStream];
        Jobs[(st->next * NStreams) + dueStream].release = due;
        if (st->len < Backlog) {
            st->queue[(st->head + st->len) % Backlog] = (uint32_t)st->next;
            st->len++;
        } else {
            Dropped++;
            JobsLost++;
        }
        st->next++;
    }
}

/* Take the stream's oldest queued job and hand its Authentic I-PDU to SecOC. start_ns is this instant. */
static void submit(size_t s)
{
    uint8 payload[SECOC_AUTHPDU_MAX_LENGTH];
    PduInfoType info;
    bench_stream_t* st = &St[s];
    uint32_t seq = st->queue[st->head];
    bench_job_t* job = &Jobs[((unsigned long)seq * NStreams) + s];

    st->head = (st->head + 1UL) % Backlog;
    st->len--;
    Started++;
    /* Stream index in the first byte (as the gateway's App_Tx writes it), sequence number, big endian,
     * in the last four bytes: the receiver logs it as seq. */
    (void)memset(payload, 0, sizeof(payload));
    if (PayloadLen > 4U) {
        payload[0] = (uint8)s;
    }
    payload[PayloadLen - 4U] = (uint8)(seq >> 24U);
    payload[PayloadLen - 3U] = (uint8)(seq >> 16U);
    payload[PayloadLen - 2U] = (uint8)(seq >> 8U);
    payload[PayloadLen - 1U] = (uint8)seq;
    info.SduDataPtr = payload;
    info.MetaDataPtr = NULL;
    info.SduLength = (PduLengthType)PayloadLen;
    st->authNs = 0U;
    st->confirmedBefore = st->confirmed;
    st->failedBefore = st->failed;
    st->flyingTicks = 0UL;
    st->flying = job;
    job->start = bench_now_ns();
    /* The return value is not looked at: a refused request is a started job that never reaches the signing
     * hook, and the end check of main() (sign calls = started jobs) then ends the program with status 4. */
    (void)SecOC_TpTransmit(st->pdu, &info);
}

/* Close the stream's job in flight if SoAd confirmed it, or if it failed or is given up. */
static void settle(bench_stream_t* st, int giveUp)
{
    if (st->flying == NULL) {
        return;
    }
    if (st->confirmed != st->confirmedBefore) {
        st->flying->auth = st->authNs;
        st->flying->send = st->sendNs;
        JobsDone++;
        st->flying = NULL;
    } else if ((st->failed != st->failedBefore) || (giveUp != 0)) {
        st->flying->auth = st->authNs;
        JobsLost++;
        st->flying = NULL;
    } else {
        /* still with SecOC or SoAd */
    }
}

static void run_event(void)
{
    for (;;) {
        uint64_t due = admit(bench_now_ns());
        uint64_t oldest = UINT64_MAX;
        size_t pick = NStreams;
        size_t s;
        int cycle;

        /* the oldest released job of all streams */
        for (s = 0U; s < NStreams; s++) {
            if (St[s].len > 0UL) {
                uint64_t release = Jobs[((unsigned long)St[s].queue[St[s].head] * NStreams) + s].release;
                if (release < oldest) {
                    oldest = release;
                    pick = s;
                }
            }
        }
        if (pick == NStreams) {
            if (due == UINT64_MAX) {
                return;
            }
            sleep_until(due);
            continue;
        }
        submit(pick);
        for (cycle = 0; (cycle < BENCH_TX_MAX_CYCLES) && (St[pick].confirmed == St[pick].confirmedBefore) &&
                        (St[pick].failed == St[pick].failedBefore); cycle++) {
            SecOC_MainFunctionTx();
            SoAd_MainFunctionTx();
        }
        settle(&St[pick], 1);
    }
}

static void run_cyclic(uint64_t tickNs)
{
    uint64_t tick0 = bench_now_ns();
    uint64_t tick = 0U;

    for (;;) {
        uint64_t due;
        uint64_t nowTick;
        size_t s;
        int busy = 0;

        sleep_until(tick0 + (tick * tickNs));
        /* the data-path main functions, in the order of the gateway's BSW cycle (EcuM); the
         * application step hands over one job per stream that has none in flight, as App_Tx does */
        SecOC_MainFunctionRx();
        PqcHs_MainFunction();       /* nothing to do without the handshake component */
        (void)BenchNet_HsPoll();
        due = admit(bench_now_ns());
        for (s = 0U; s < NStreams; s++) {
            if ((St[s].flying == NULL) && (St[s].len > 0UL)) {
                submit(s);
            }
        }
        SecOC_MainFunctionTx();
        Csm_MainFunction();
        SoAd_MainFunctionTx();
        SoAd_MainFunctionRx();

        for (s = 0U; s < NStreams; s++) {
            if (St[s].flying != NULL) {
                St[s].flyingTicks++;
                settle(&St[s], (St[s].flyingTicks > BENCH_CONFIRM_TICKS) ? 1 : 0);
            }
            if ((St[s].flying != NULL) || (St[s].len > 0UL)) {
                busy = 1;
            }
        }
        if ((RekeyAfter != 0UL) && (JobsDone >= RekeyAfter)) {
            (void)PqcHs_Initiate(0U);       /* once: "initiate a handshake now", under the stream */
            RekeyAfter = 0UL;
        }
        if ((busy == 0) && (due == UINT64_MAX)) {
            return;
        }
        nowTick = ((bench_now_ns() - tick0) / tickNs) + 1U;
        if (nowTick > (tick + 1U)) {
            Overruns += (unsigned long)(nowTick - (tick + 1U));
        }
        tick = nowTick;
    }
}

static int usage(void)
{
    (void)fprintf(stderr,
                  "usage: bench_net_tx --peer A.B.C.D:PORT --key-dir DIR --cpu N --out FILE\n"
                  "                    (--period-us P --count N | --rate-pps R --duration S [--ramp S])\n"
                  "                    [--mainfunction cyclic|event] [--mf-period-us T] [--deadline-us D]\n"
                  "                    [--sched other|fifo] [--priority P] [--backlog JOBS] [--payload-bytes 8..%u]\n"
                  "                    [--phase sync|staggered] [--streams 1..8] [--cores 1] [--profile mldsa65|mac|both]\n"
                  "                    [--partition I --partitions N] [--rep K]\n"
                  "                    [--samples FILE --rx-host NAME [--iface eth0]] [--allow-unlocked]\n",
                  (unsigned)SECOC_AUTHPDU_MAX_LENGTH);
    return 2;
}

int main(int argc, char** argv)
{
    static const struct option longOpts[] = {
        { "peer", required_argument, NULL, 'p' },        { "key-dir", required_argument, NULL, 'k' },
        { "cpu", required_argument, NULL, 'c' },         { "out", required_argument, NULL, 'o' },
        { "period-us", required_argument, NULL, 'P' },   { "count", required_argument, NULL, 'n' },
        { "rate-pps", required_argument, NULL, 'r' },    { "duration", required_argument, NULL, 'd' },
        { "ramp", required_argument, NULL, 'R' },        { "deadline-us", required_argument, NULL, 'D' },
        { "sched", required_argument, NULL, 's' },       { "priority", required_argument, NULL, 'y' },
        { "backlog", required_argument, NULL, 'b' },     { "payload-bytes", required_argument, NULL, 'l' },
        { "phase", required_argument, NULL, 'h' },       { "cores", required_argument, NULL, 'C' },
        { "profile", required_argument, NULL, 'f' },     { "samples", required_argument, NULL, 'S' },
        { "rx-host", required_argument, NULL, 'x' },     { "iface", required_argument, NULL, 'i' },
        { "mainfunction", required_argument, NULL, 'M' }, { "mf-period-us", required_argument, NULL, 'T' },
        { "partition", required_argument, NULL, 'I' },   { "allow-unlocked", no_argument, NULL, 'u' },
        { "partitions", required_argument, NULL, 'N' },  { "rep", required_argument, NULL, 'K' },
        { "streams", required_argument, NULL, 'Z' },     { "no-handshake", no_argument, NULL, 'H' },
        { "handshake-out", required_argument, NULL, 'O' }, { "hs-timeout-ms", required_argument, NULL, 'W' },
        { "rekey-after", required_argument, NULL, 'A' },
        { NULL, 0, NULL, 0 },
    };
    static const BswStamps_ObserverType observer = { NULL, NULL, NULL, on_signed, on_tx_confirmed };
    BenchNet_ConfigType net = { NULL, { 0U, 0U, 0U, 0U }, 0U, 1 };
    BenchNet_SamplerConfigType sampler;
    const char* hsPath = NULL;
    const char* profile = "mldsa65";
    int prof;
    uint64_t hsTimeoutNs = 15000000000ULL;
    struct sigaction sa;
    struct rusage worker;
    const char* outPath = NULL;
    const char* samplesPath = NULL;
    const char* rxHost = NULL;
    const char* iface = "eth0";
    const char* sched = "other";
    const char* phase = "sync";
    const char* mainFunction = "cyclic";
    const char* mlockStatus;
    char host[64] = "unknown";
    double ratePps = 0.0;
    uint64_t deadlineNs = 0U;
    uint64_t tickNs = 1000000ULL;
    uint64_t mfPeriodUs;
    uint64_t startNs = bench_now_ns();
    unsigned long duration = 0UL;
    unsigned long ramp = 0UL;
    unsigned long n;
    BenchTcpInfo_Type tcpFirst, tcpEnd;
    unsigned long connectionsFirst;
    int cpu = -1;
    int priority = 80;
    int partition = 0;
    int partitions = 1;
    int rep = 1;
    int allowUnlocked = 0;
    int peerGiven = 0;
    int sampledCpu = 0;
    FILE* out;
    size_t s;
    int c;

    while ((c = getopt_long(argc, argv, "", longOpts, NULL)) != -1) {
        switch (c) {
        case 'p': peerGiven = (BenchNet_ParseEndpoint(optarg, net.peerIp, &net.port) == 0); break;
        case 'k': net.keyDir = optarg; break;
        case 'c': cpu = atoi(optarg); break;
        case 'o': outPath = optarg; break;
        case 'P': PeriodNs = strtoull(optarg, NULL, 10) * 1000ULL; break;
        case 'n': Count = strtoul(optarg, NULL, 10); break;
        case 'r': ratePps = strtod(optarg, NULL); break;
        case 'd': duration = strtoul(optarg, NULL, 10); break;
        case 'R': ramp = strtoul(optarg, NULL, 10); break;
        case 'D': deadlineNs = strtoull(optarg, NULL, 10) * 1000ULL; break;
        case 's': sched = optarg; break;
        case 'y': priority = atoi(optarg); break;
        case 'b': Backlog = strtoul(optarg, NULL, 10); break;
        case 'Z': NStreams = (size_t)strtoul(optarg, NULL, 10); break;
        case 'l': PayloadLen = (size_t)strtoul(optarg, NULL, 10); break;
        case 'h': phase = optarg; break;
        case 'M': mainFunction = optarg; break;
        case 'T': tickNs = strtoull(optarg, NULL, 10) * 1000ULL; break;
        case 'I': partition = atoi(optarg); break;
        case 'N': partitions = atoi(optarg); break;
        case 'K': rep = atoi(optarg); break;
        case 'H': net.handshake = 0; break;
        case 'O': hsPath = optarg; break;
        case 'W': hsTimeoutNs = strtoull(optarg, NULL, 10) * 1000000ULL; break;
        case 'A': RekeyAfter = strtoul(optarg, NULL, 10); break;
        case 'C':
            if (atoi(optarg) != 1) {
                (void)fprintf(stderr, "--cores %s: the BSW transmit path is single-threaded (one SecOC main function, "
                                      "one TCP connection); several cores are several processes, one per core\n", optarg);
                return 2;
            }
            break;
        case 'f':
            if (BenchNet_ProfileOf(optarg) < 0) {
                (void)fprintf(stderr, "--profile %s: mldsa65, mac or both\n", optarg);
                return 2;
            }
            profile = optarg;
            break;
        case 'S': samplesPath = optarg; break;
        case 'x': rxHost = optarg; break;
        case 'i': iface = optarg; break;
        case 'u': allowUnlocked = 1; break;
        default: return usage();
        }
    }
    if (ratePps > 0.0) {
        PeriodNs = (uint64_t)(1e9 / ratePps);
        Count = (unsigned long)((double)(ramp + duration) * ratePps);
    }
    if (deadlineNs == 0U) {
        deadlineNs = PeriodNs;
    }
    Staggered = (strcmp(phase, "staggered") == 0);
    mfPeriodUs = (strcmp(mainFunction, "cyclic") == 0) ? (uint64_t)(tickNs / 1000U) : (uint64_t)0U;
    if ((peerGiven == 0) || (net.keyDir == NULL) || (cpu < 0) || (outPath == NULL) || (PeriodNs == 0U) || (Count == 0UL) ||
        (Backlog == 0UL) || (NStreams == 0U) || (NStreams > BENCH_NET_MAX_STREAMS) || (PayloadLen < 8U) || (PayloadLen > SECOC_AUTHPDU_MAX_LENGTH) || (tickNs == 0U) || (optind != argc) ||
        ((strcmp(sched, "other") != 0) && (strcmp(sched, "fifo") != 0)) ||
        ((strcmp(phase, "sync") != 0) && (strcmp(phase, "staggered") != 0)) ||
        ((strcmp(mainFunction, "cyclic") != 0) && (strcmp(mainFunction, "event") != 0)) ||
        ((RekeyAfter != 0UL) && ((strcmp(mainFunction, "cyclic") != 0) || (net.handshake == 0))) ||
        ((strcmp(profile, "mac") == 0) && ((NStreams > BENCH_NET_MAC_STREAMS) || (net.handshake == 0))) ||
        ((strcmp(profile, "both") == 0) && ((NStreams != 2U) || (net.handshake == 0))) ||
        ((samplesPath != NULL) && ((rxHost == NULL) || (ratePps <= 0.0) || (duration == 0UL)))) {
        return usage();
    }
    prof = BenchNet_ProfileOf(profile);
    (void)gethostname(host, sizeof(host) - 1U);
    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    (void)sigaction(SIGTERM, &sa, NULL);
    (void)sigaction(SIGINT, &sa, NULL);

    out = fopen(outPath, "w");
    Jobs = calloc(Count * NStreams, sizeof(*Jobs));
    St[0].queue = calloc(Backlog * NStreams, sizeof(*St[0].queue));
    for (s = 0U; s < NStreams; s++) {
        St[s].pdu = (PduIdType)BenchNet_PduOfStream(prof, (uint32)s);
        St[s].queue = &St[0].queue[s * Backlog];
    }
    if ((out == NULL) || (Jobs == NULL) || (St[0].queue == NULL)) {
        (void)fprintf(stderr, "cannot open %s or allocate %lu jobs: %s\n", outPath, Count, strerror(errno));
        return 1;
    }
    (void)memset(Jobs, 0, Count * NStreams * sizeof(*Jobs));    /* fault the pages in */

    BswStamps_SetObserver(&observer);
    if (BenchNet_Init(&net) != 0) {
        return 1;
    }
    if ((BenchNet_ConnFd < 0) ||
        (getpeername(BenchNet_ConnFd, &(struct sockaddr){ 0 }, &(socklen_t){ sizeof(struct sockaddr) }) != 0)) {
        (void)fprintf(stderr, "no TCP connection to %u.%u.%u.%u:%u (is the receiver listening?)\n",
                      net.peerIp[0], net.peerIp[1], net.peerIp[2], net.peerIp[3], net.port);
        return 1;
    }

    mlockStatus = bench_lock_memory();
    if (bench_require_locked(mlockStatus, allowUnlocked) != 0) {
        return 1;
    }

    if (BenchNet_PinAndSchedule(cpu, (strcmp(sched, "fifo") == 0) ? priority : 0) != 0) {
        (void)fprintf(stderr, "cannot run on cpu %d with scheduler %s (SCHED_FIFO needs root or an rtprio limit)\n", cpu, sched);
        return 1;
    }
    /* No release without a session: the handshake first, on the pinned core, then the release schedule. */
    if (net.handshake != 0) {
        int hs = BenchNet_HsWait(1000000ULL, hsTimeoutNs);
        if (hs != 0) {
            if (hsPath != NULL) {
                /* pdu_stream=none is the mark of an E5 handshake file (DATA_SCHEMA.md); this is the record of a
                 * transmitter whose PDU stream did not start */
                (void)BenchNet_HsWriteFile(hsPath, "bench_net_tx", mlockStatus, mainFunction, mfPeriodUs, startNs, "# pdu_stream=periodic\n");
            }
            (void)fprintf(stderr, "no session with the peer (%s): nothing was released\n",
                          (hs == -1) ? "the handshake attempt failed, see the handshake records" : "no answer in time");
            return 5;
        }
    }

    /* The connection as the measured interval finds it (retransmissions so far, TCP_NODELAY as the stack
     * left it), read here and not in the worker's cycle: the first release is 200 ms away. */
    BenchTcpInfo_Read(BenchNet_ConnFd, &tcpFirst);
    BenchNet_TcpNoDelay = tcpFirst.noDelay;
    if (tcpFirst.noDelay != 1) {
        /* CAMPAIGN.md: a file is valid only with TCP_NODELAY = 1 on both ends; with Nagle's algorithm the
         * kernel holds PDUs back (39 ms median at 1,000 PDU/s in the dry run of 2026-11-23). Stop here,
         * before anything is released, instead of producing a run nobody may use. */
        (void)fprintf(stderr, "TCP_NODELAY of the connection reads back %d, not 1: nothing was released\n", tcpFirst.noDelay);
        return 6;
    }
    connectionsFirst = BenchNet_Connections;
    T0 = bench_now_ns() + 200000000ULL;
    if (samplesPath != NULL) {
        sampler.iface = iface;
        sampler.cpu = cpu;
        sampler.firstNs = T0 + ((uint64_t)ramp * 1000000000ULL);
        sampler.samples = (unsigned)duration + 1U;
        sampler.done = &JobsDone;
        sampler.drops = &JobsLost;
        sampler.sendQueue = 1;
        sampler.stop = &StopRequested;
        if (BenchNet_SamplerStart(&sampler) != 0) {
            (void)fprintf(stderr, "cannot start the sampler\n");
            return 1;
        }
    }

    /* The probe signature of BenchNet_Init() went through the hook as well. */
    SignCalls = 0UL;
    if (strcmp(mainFunction, "cyclic") == 0) {
        run_cyclic(tickNs);
    } else {
        run_event();
    }
    /* Context switches of this thread alone, the one that signs and sends: a preemption on the
     * pinned core is a platform event the run must show (the footer's other pair counts the
     * whole process, sampler thread included). */
    (void)memset(&worker, 0, sizeof(worker));
    (void)getrusage(RUSAGE_THREAD, &worker);

    /* Leave only when the kernel has nothing of ours left to send; closing through TcpIp_Close()
     * could reset the connection and lose the tail. */
    {
        uint64_t giveUp = bench_now_ns() + BENCH_DRAIN_TIMEOUT_NS;
        int queued = 1;
        while ((ioctl(BenchNet_ConnFd, SIOCOUTQ, &queued) == 0) && (queued > 0) && (bench_now_ns() < giveUp)) {
            sleep_until(bench_now_ns() + 1000000ULL);
        }
    }
    /* Retransmissions of THIS connection, reported and not judged (CAMPAIGN.md): the host-wide TCP
     * counters of the gate snapshots also count the other interfaces. */
    BenchTcpInfo_Read(BenchNet_ConnFd, &tcpEnd);
    if (samplesPath != NULL) {
        BenchNet_SamplerJoin();
    }

    n = Count * NStreams;
    sampledCpu = bench_write_header(out, "bench_net_tx", mlockStatus);
    (void)fprintf(out, "# period_ns=%" PRIu64 "\n# deadline_ns=%" PRIu64 "\n# streams=%zu\n# cores=1\n# profile=%s\n"
                       "# scheduler=%s\n# payload_bytes=%zu\n", PeriodNs, deadlineNs, NStreams, profile, sched, PayloadLen);
    (void)fprintf(out, "# mainfunction=%s\n# mf_period_us=%" PRIu64 "\n", mainFunction,
                  mfPeriodUs);
    (void)fprintf(out, "# mf_order=%s\n", (strcmp(mainFunction, "cyclic") == 0)
                  ? "SecOC_MainFunctionRx PqcHs_MainFunction application SecOC_MainFunctionTx Csm_MainFunction SoAd_MainFunctionTx SoAd_MainFunctionRx, once per tick"
                  : "per job: SecOC_TpTransmit, then SecOC_MainFunctionTx SoAd_MainFunctionTx until confirmed");
    (void)fprintf(out, "# partition=%d\n# partitions=%d\n# rep=%d\n# sched_priority=%d\n# phase=%s\n# backlog_jobs=%lu\n# releases_per_stream=%lu\n"
                       "# timer_slack_ns=%d\n# peer=%u.%u.%u.%u:%u\n# tcp_nodelay=%d\n",
                  partition, partitions, rep, (strcmp(sched, "fifo") == 0) ? priority : 0, phase, Backlog * NStreams, Count, prctl(PR_GET_TIMERSLACK),
                  net.peerIp[0], net.peerIp[1], net.peerIp[2], net.peerIp[3], net.port, tcpFirst.noDelay);
    (void)fprintf(out, "# hooks=Csm_SignatureGenerate or Csm_MacGenerate (auth_done_ns), PduR_SoAdTpTxConfirmation (send_done_ns); link-time wraps\n");
    BenchNet_WriteStreamIds(out, NStreams, prof);
    /* the handshake lies before the measured interval: established_ns < first_release_ns, and a
     * handshake record collected after the first release is listed (hs_records_in_run) */
    (void)fprintf(out, "# first_release_ns=%" PRIu64 "\n", T0);
    BenchNet_HsWriteKeys(out, net.handshake, T0);
    if ((net.handshake != 0) && (hsPath != NULL) &&
        (BenchNet_HsWriteFile(hsPath, "bench_net_tx", mlockStatus, mainFunction, mfPeriodUs, startNs, "# pdu_stream=periodic\n") != 0)) {
        (void)fprintf(stderr, "cannot write %s\n", hsPath);
    }
    (void)fprintf(out, "stream,seq,release_ns,start_ns,auth_done_ns,send_done_ns\n");
    for (c = 0; (unsigned long)c < Count; c++) {
        for (s = 0U; s < NStreams; s++) {
            const bench_job_t* job = &Jobs[((unsigned long)c * NStreams) + s];
            (void)fprintf(out, "%u,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n", (unsigned)s, c,
                          job->release, job->start, job->auth, job->send);
        }
    }
    (void)fprintf(out, "# jobs_released=%lu\n# jobs_dropped_at_release=%lu\n# jobs_started=%lu\n# jobs_confirmed=%lu\n"
                       "# sign_calls=%lu\n# tx_confirmations_ok=%lu\n# tx_confirmations_failed=%lu\n# mf_overruns=%lu\n"
                       "# tcp_total_retrans=%ld\n# stopped_early=%d\n"
                       "# worker_ctx_switches_involuntary=%ld\n# worker_ctx_switches_voluntary=%ld\n",
                  n, Dropped, Started, JobsDone, SignCalls, Confirmed, ConfirmFailed, Overruns, tcpEnd.totalRetrans,
                  (int)StopRequested, worker.ru_nivcsw, worker.ru_nvcsw);
    BenchTcpInfo_WriteFooter(out, &tcpFirst, &tcpEnd, connectionsFirst, BenchNet_Connections);
    bench_write_footer(out, sampledCpu, startNs);
    if ((ferror(out) != 0) || (fclose(out) != 0)) {
        (void)fprintf(stderr, "write to %s failed: %s\n", outPath, strerror(errno));
        return 1;
    }

    if (samplesPath != NULL) {
        FILE* sf = fopen(samplesPath, "w");
        if (sf == NULL) {
            (void)fprintf(stderr, "cannot open %s: %s\n", samplesPath, strerror(errno));
            return 1;
        }
        (void)bench_write_header(sf, "bench_net_tx", mlockStatus);
        (void)fprintf(sf, "# tx_host=%s\n# rx_host=%s\n# profile=%s\n# cores=1\n# partition=%d\n# partitions=%d\n# rep=%d\n# offered_pps=%g\n"
                          "# ramp_s=%lu\n# duration_s=%lu\n# iface=%s\n# sampled_cpu=%d\n# mainfunction=%s\n# mf_period_us=%" PRIu64 "\n"
                          "# tcp_nodelay=%d\n",
                  host, rxHost, profile, partition, partitions, rep, ratePps, ramp, duration, iface, cpu, mainFunction,
                  mfPeriodUs, tcpFirst.noDelay);
        (void)fprintf(sf, "t_ns,host,offered_pps,pdus_done,cpu_busy_jiffies,cpu_total_jiffies,if_tx_bytes,if_tx_packets,"
                          "if_rx_bytes,if_rx_packets,sendq_bytes,drops,proc_cpu_ns\n");
        BenchNet_SamplerWrite(sf, host, ratePps);
        /* the connection's counters of this process, as in its periodic_tx file: each file can be read alone */
        (void)fprintf(sf, "# tcp_total_retrans=%ld\n", tcpEnd.totalRetrans);
        BenchTcpInfo_WriteFooter(sf, &tcpFirst, &tcpEnd, connectionsFirst, BenchNet_Connections);
        (void)fprintf(sf, "# worker_ctx_switches_involuntary=%ld\n# worker_ctx_switches_voluntary=%ld\n",
                      worker.ru_nivcsw, worker.ru_nvcsw);
        bench_write_footer(sf, sampledCpu, startNs);
        if ((ferror(sf) != 0) || (fclose(sf) != 0)) {
            (void)fprintf(stderr, "write to %s failed: %s\n", samplesPath, strerror(errno));
            return 1;
        }
    }

    (void)printf("released=%lu dropped=%lu started=%lu confirmed=%lu sign_calls=%lu mf_overruns=%lu\n", n, Dropped,
                 Started, JobsDone, SignCalls, Overruns);
    /* Each started job must have passed each hook exactly once; anything else means the timestamps
     * do not belong to the jobs they are written next to. */
    if ((SignCalls != Started) || ((Confirmed + ConfirmFailed) > Started) || (Confirmed != JobsDone)) {
        (void)fprintf(stderr, "hook counts do not match the jobs: the run is invalid\n");
        return 4;
    }
    return 0;
}
