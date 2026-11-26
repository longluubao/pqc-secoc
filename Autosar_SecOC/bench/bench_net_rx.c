/* bench_net_rx: receiver for the networked harnesses, through the real receive path
 * (TcpIp -> SoAd stream reassembly -> PduR -> SecOC -> Csm -> CryIf -> liboqs -> upper layer).
 *
 * One thread, pinned to one CPU, runs the BSW main functions in one of two ways (--mainfunction):
 *   cyclic  (default) a fixed-period executive, 1 ms unless --mf-period-us says otherwise, on
 *           absolute CLOCK_MONOTONIC ticks; each tick calls, in the order of the gateway's BSW
 *           cycle, SecOC_MainFunctionRx, SecOC_MainFunctionTx, Csm_MainFunction, SoAd_MainFunctionTx,
 *           SoAd_MainFunctionRx. Ticks skipped because one ran long are counted as overruns.
 *   event   no period: the thread sleeps in poll() on the connection and, while there is work,
 *           calls SoAd_MainFunctionRx and SecOC_MainFunctionRx back to back.
 *
 * One row per received Secured I-PDU, written after the run from memory:
 *   --out          periodic_rx.csv  stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result
 *                  rx_done = SoAd handed the complete Secured I-PDU to SecOC; verify_done = SecOC's
 *                  verification status callout; deliver = Authentic I-PDU handed to the upper layer.
 *                  seq is read from the payload (last four bytes, as bench_net_tx writes it): from
 *                  the delivered bytes for ok rows, from the received bytes for rejected ones.
 *                  framing_fail rows (PDUs SoAd discarded) carry stream = seq = -1.
 *   --payload-out  rx_payload.csv   stream,seq,payload_hex of every delivered Authentic I-PDU
 *   --samples      throughput.csv   one row per second (DATA_SCHEMA.md)
 *
 * Usage: bench_net_rx --listen PORT --peer A.B.C.D --key-dir DIR --cpu N --out FILE [--payload-out FILE] [--max-rows N]
 *                     [--mainfunction cyclic|event] [--mf-period-us T] [--partition I --partitions N] [--rep K]
 *                     [--idle-exit-ms MS] [--sched other|fifo] [--priority P] [--allow-unlocked]
 *                     [--samples FILE --tx-host NAME --rate-pps R --duration S [--ramp S] [--iface eth0]]
 * --peer is the transmitter's address: SoAd accepts a connection from the configured peer only.
 * The receiver is the responder of the handshake PQC-SecOC-HS-v1 and accepts no Secured I-PDU
 * before a session exists (--no-handshake: no handshake component, session-less PDUs, development).
 * session_id in the header names the session; --handshake-out FILE gets the attempt records.
 * --profile mldsa65|mac|both labels the files (the receiver takes whatever stream arrives); with
 * both the MAC stream has the stream index 1, behind the one signature stream, as at the transmitter.
 * Another name is a usage error.
 * It ends when the transmitter closes the connection, or after --idle-exit-ms without traffic
 * (default 3000) once something was received, or on SIGTERM.
 */
#define _GNU_SOURCE
#include "bench_net.h"
#include "bench_tcpinfo.h"
#include "bsw_stamps.h"

#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdlib.h>

#include "Csm.h"
#include "Rte_SecOC.h"
#include "PqcHs.h"
#include "SecOC.h"
#include "SecOC_Lcfg.h"
#include "SoAd.h"

#define BENCH_RX_HEAD_BYTES     (1U + SECOC_AUTHPDU_MAX_LENGTH)     /* length byte + largest Authentic I-PDU */

typedef enum { RX_OK = 0, RX_FRESHNESS_FAIL, RX_AUTH_FAIL, RX_FRAMING_FAIL } bench_result_t;
static const char* const ResultNames[] = { "ok", "freshness_fail", "auth_fail", "framing_fail" };

typedef struct {
    int      stream;
    long     seq;
    uint64_t rxDone;
    uint64_t verifyDone;
    uint64_t deliver;
    uint8    result;
    uint8    payloadLen;
    uint8    payload[SECOC_AUTHPDU_MAX_LENGTH];
} bench_row_t;

static bench_row_t* Rows;
static unsigned long RowCount;
static unsigned long MaxRows = 200000UL;
static unsigned long RowsLost;
static volatile unsigned long Delivered;
static volatile unsigned long Rejected;
static unsigned long Events;                /* hook calls: any change means the last cycle made progress */
static unsigned long RxIndications;
static unsigned long Callouts;
static unsigned long HeadSeqMismatches;
static volatile sig_atomic_t Stop;

/* The Secured I-PDU of each PDU ID that is being received and verified: SoAd forwards one per PDU
 * ID and SecOC verifies it in a later main function, when PDUs of other streams may have arrived. */
typedef struct {
    uint8    head[BENCH_RX_HEAD_BYTES];
    uint32_t headLen;
    uint64_t rxDone;
    uint64_t verifyDone;
} bench_cur_t;
static bench_cur_t CurOf[SOAD_NUM_PDU_IDS];
static bench_cur_t* Cur = &CurOf[0];        /* the PDU the last verification callout was about */
static int CurStream;                       /* and its stream index */
static int Profile = BENCH_NET_PROFILE_SIG; /* which stream index a MAC PDU has (--profile) */
static uint64_t FirstRxDone;

static void on_signal(int sig)
{
    (void)sig;
    Stop = 1;
}

static uint32_t be32(const uint8* p)
{
    return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U) | ((uint32_t)p[2] << 8U) | (uint32_t)p[3];
}

/* Sequence number as it stands in the received bytes: [length byte][Authentic I-PDU ...]. */
static long head_seq(void)
{
    uint32_t len = (Cur->headLen > 0U) ? (uint32_t)Cur->head[0] : 0U;
    if ((len < 4U) || ((1U + len) > Cur->headLen)) {
        return 0L;
    }
    return (long)be32(&Cur->head[1U + len - 4U]);
}

static bench_cur_t* cur_of(uint32_t pdu)
{
    return &CurOf[(pdu < SOAD_NUM_PDU_IDS) ? pdu : 0U];
}

static bench_row_t* add_row(bench_result_t result, int stream, long seq, uint64_t rxDone, uint64_t verifyDone, uint64_t deliver)
{
    bench_row_t* row;
    if (RowCount >= MaxRows) {
        RowsLost++;
        return NULL;
    }
    row = &Rows[RowCount];
    RowCount++;
    row->stream = stream;
    row->seq = seq;
    row->rxDone = rxDone;
    row->verifyDone = verifyDone;
    row->deliver = deliver;
    row->result = (uint8)result;
    row->payloadLen = 0U;
    return row;
}

/**************************************** timestamp hooks ****************************************/

BufReq_ReturnType __real_PduR_SoAdStartOfReception(PduIdType id, const PduInfoType* info, PduLengthType TpSduLength,
                                                   PduLengthType* bufferSizePtr);
BufReq_ReturnType __real_PduR_SoAdTpCopyRxData(PduIdType id, const PduInfoType* info, PduLengthType* bufferSizePtr);

BufReq_ReturnType __wrap_PduR_SoAdStartOfReception(PduIdType id, const PduInfoType* info, PduLengthType TpSduLength,
                                                   PduLengthType* bufferSizePtr)
{
    cur_of(id)->headLen = 0U;
    return __real_PduR_SoAdStartOfReception(id, info, TpSduLength, bufferSizePtr);
}

/* Keeps the first bytes of the Secured I-PDU, so that a rejected PDU can still be attributed. */
BufReq_ReturnType __wrap_PduR_SoAdTpCopyRxData(PduIdType id, const PduInfoType* info, PduLengthType* bufferSizePtr)
{
    bench_cur_t* cur = cur_of(id);
    if ((info != NULL) && (info->SduDataPtr != NULL) && (cur->headLen < BENCH_RX_HEAD_BYTES)) {
        uint32_t take = BENCH_RX_HEAD_BYTES - cur->headLen;
        if (take > (uint32_t)info->SduLength) {
            take = (uint32_t)info->SduLength;
        }
        (void)memcpy(&cur->head[cur->headLen], info->SduDataPtr, take);
        cur->headLen += take;
    }
    return __real_PduR_SoAdTpCopyRxData(id, info, bufferSizePtr);
}

/* rx_done_ns (bsw_stamps.c): SoAd has passed the last byte of the Secured I-PDU up. */
static void on_rx_done(PduIdType pdu, uint64_t ns)
{
    cur_of(pdu)->rxDone = ns;
    cur_of(pdu)->verifyDone = 0U;
    if (RxIndications == 0UL) {
        FirstRxDone = ns;
    }
    RxIndications++;
    Events++;
}

/* verify_done_ns and the verdict [SWS_SecOC_00119]. A rejected PDU ends here. TRUE: the harness
 * is the upper layer, the call does not go on to the tree's callout. */
static boolean on_verified(PduIdType pdu, SecOC_VerificationResultType result, uint64_t ns)
{
    Callouts++;
    Events++;
    CurStream = BenchNet_StreamOfPdu(Profile, pdu);
    Cur = cur_of(pdu);
    if (result == SECOC_VERIFICATIONSUCCESS) {
        Cur->verifyDone = ns;
    } else {
        (void)add_row((result == SECOC_FRESHNESSFAILURE) ? RX_FRESHNESS_FAIL : RX_AUTH_FAIL,
                      CurStream, head_seq(), Cur->rxDone, ns, 0U);
        Rejected++;
    }
    return TRUE;
}

/* deliver_ns: the Authentic I-PDU reaches the upper layer, which here is the harness (TRUE: Com
 * does not get it). SecOC delivers right after the callout of the same PDU. */
static boolean on_delivered(PduIdType pdu, const PduInfoType* PduInfoPtr, uint64_t ns)
{
    uint32_t len = (uint32_t)PduInfoPtr->SduLength;
    long seq = (len >= 4U) ? (long)be32(&PduInfoPtr->SduDataPtr[len - 4U]) : 0L;
    bench_row_t* row = add_row(RX_OK, CurStream, seq, Cur->rxDone, Cur->verifyDone, ns);

    (void)pdu;
    Events++;
    Delivered++;
    if (seq != head_seq()) {
        HeadSeqMismatches++;
    }
    if (row != NULL) {
        row->payloadLen = (uint8)((len > sizeof(row->payload)) ? sizeof(row->payload) : len);
        (void)memcpy(row->payload, PduInfoPtr->SduDataPtr, row->payloadLen);
    }
    return TRUE;
}

/********************************************** main *********************************************/

static int usage(void)
{
    (void)fprintf(stderr,
                  "usage: bench_net_rx --listen PORT --peer A.B.C.D --key-dir DIR --cpu N --out FILE [--payload-out FILE] [--max-rows N]\n"
                  "                    [--mainfunction cyclic|event] [--mf-period-us T] [--partition I --partitions N] [--rep K]\n"
                  "                    [--idle-exit-ms MS] [--sched other|fifo] [--priority P] [--allow-unlocked]\n"
                  "                    [--samples FILE --tx-host NAME --rate-pps R --duration S [--ramp S] [--iface eth0]]\n");
    return 2;
}

int main(int argc, char** argv)
{
    static const struct option longOpts[] = {
        { "listen", required_argument, NULL, 'p' },      { "key-dir", required_argument, NULL, 'k' },
        { "cpu", required_argument, NULL, 'c' },         { "out", required_argument, NULL, 'o' },
        { "payload-out", required_argument, NULL, 'O' }, { "max-rows", required_argument, NULL, 'm' },
        { "idle-exit-ms", required_argument, NULL, 'I' }, { "sched", required_argument, NULL, 's' },
        { "priority", required_argument, NULL, 'y' },    { "samples", required_argument, NULL, 'S' },
        { "tx-host", required_argument, NULL, 'x' },     { "rate-pps", required_argument, NULL, 'r' },
        { "duration", required_argument, NULL, 'd' },    { "ramp", required_argument, NULL, 'R' },
        { "iface", required_argument, NULL, 'i' },       { "allow-unlocked", no_argument, NULL, 'u' },
        { "mainfunction", required_argument, NULL, 'M' }, { "mf-period-us", required_argument, NULL, 'T' },
        { "partition", required_argument, NULL, 'P' },   { "peer", required_argument, NULL, 'e' },
        { "partitions", required_argument, NULL, 'N' },  { "rep", required_argument, NULL, 'K' },
        { "no-handshake", no_argument, NULL, 'H' },      { "handshake-out", required_argument, NULL, 'Q' },
        { "profile", required_argument, NULL, 'f' },
        { NULL, 0, NULL, 0 },
    };
    static const BswStamps_ObserverType observer = { on_rx_done, on_verified, on_delivered, NULL, NULL };
    BenchNet_ConfigType net = { NULL, { 0U, 0U, 0U, 0U }, 0U, 1 };
    const char* hsPath = NULL;
    const char* profile = "mldsa65";
    BenchNet_SamplerConfigType sampler;
    struct sigaction sa;
    struct rusage worker;
    const char* outPath = NULL;
    const char* payloadPath = NULL;
    const char* samplesPath = NULL;
    const char* txHost = NULL;
    const char* iface = "eth0";
    const char* sched = "other";
    const char* mainFunction = "cyclic";
    const char* mlockStatus;
    char host[64] = "unknown";
    double ratePps = 0.0;
    uint64_t idleExitNs = 3000000000ULL;
    uint64_t tickNs = 1000000ULL;
    uint64_t tick0;
    uint64_t mfPeriodUs;
    uint64_t tick = 0U;
    unsigned long overruns = 0UL;
    int cyclic;
    int partition = 0;
    int partitions = 1;
    int rep = 1;
    uint64_t lastActivity;
    uint64_t startNs = bench_now_ns();
    unsigned long duration = 0UL;
    unsigned long ramp = 0UL;
    unsigned long framing = 0UL;
    unsigned long i;
    int cpu = -1;
    int priority = 80;
    int allowUnlocked = 0;
    int samplerRunning = 0;
    int samplerBegun = 0;
    BenchTcpInfo_Type tcp;
    int tcpRead = 0;
    int noDelayBad = 0;
    int peerGiven = 0;
    int sampledCpu;
    FILE* out;
    int c;

    while ((c = getopt_long(argc, argv, "", longOpts, NULL)) != -1) {
        switch (c) {
        case 'p': (void)BenchNet_ParseEndpoint(optarg, NULL, &net.port); break;
        case 'k': net.keyDir = optarg; break;
        case 'c': cpu = atoi(optarg); break;
        case 'o': outPath = optarg; break;
        case 'O': payloadPath = optarg; break;
        case 'm': MaxRows = strtoul(optarg, NULL, 10); break;
        case 'I': idleExitNs = strtoull(optarg, NULL, 10) * 1000000ULL; break;
        case 's': sched = optarg; break;
        case 'y': priority = atoi(optarg); break;
        case 'S': samplesPath = optarg; break;
        case 'x': txHost = optarg; break;
        case 'r': ratePps = strtod(optarg, NULL); break;
        case 'd': duration = strtoul(optarg, NULL, 10); break;
        case 'R': ramp = strtoul(optarg, NULL, 10); break;
        case 'i': iface = optarg; break;
        case 'u': allowUnlocked = 1; break;
        case 'M': mainFunction = optarg; break;
        case 'T': tickNs = strtoull(optarg, NULL, 10) * 1000ULL; break;
        case 'P': partition = atoi(optarg); break;
        case 'N': partitions = atoi(optarg); break;
        case 'K': rep = atoi(optarg); break;
        case 'H': net.handshake = 0; break;
        case 'Q': hsPath = optarg; break;
        case 'f':
            profile = optarg;
            Profile = BenchNet_ProfileOf(optarg);
            if (Profile < 0) {      /* the profile decides the stream index of a MAC PDU: no guessing */
                (void)fprintf(stderr, "--profile %s: mldsa65, mac or both\n", optarg);
                return 2;
            }
            break;
        case 'e': {
            unsigned q[4];
            char tail;
            if ((sscanf(optarg, "%u.%u.%u.%u%c", &q[0], &q[1], &q[2], &q[3], &tail) != 4) ||
                (q[0] > 255U) || (q[1] > 255U) || (q[2] > 255U) || (q[3] > 255U)) {
                return usage();
            }
            for (i = 0UL; i < 4UL; i++) {
                net.peerIp[i] = (uint8)q[i];
            }
            peerGiven = 1;
            break;
        }
        default: return usage();
        }
    }
    cyclic = (strcmp(mainFunction, "cyclic") == 0);
    mfPeriodUs = (cyclic != 0) ? (uint64_t)(tickNs / 1000U) : (uint64_t)0U;
    if ((net.port == 0U) || (peerGiven == 0) || (net.keyDir == NULL) || (cpu < 0) || (outPath == NULL) || (MaxRows == 0UL) || (optind != argc) ||
        ((strcmp(sched, "other") != 0) && (strcmp(sched, "fifo") != 0)) || (tickNs == 0U) ||
        ((cyclic == 0) && (strcmp(mainFunction, "event") != 0)) ||
        ((samplesPath != NULL) && ((txHost == NULL) || (ratePps <= 0.0) || (duration == 0UL)))) {
        return usage();
    }
    (void)gethostname(host, sizeof(host) - 1U);

    out = fopen(outPath, "w");
    Rows = calloc(MaxRows, sizeof(*Rows));
    if ((out == NULL) || (Rows == NULL)) {
        (void)fprintf(stderr, "cannot open %s or allocate %lu rows: %s\n", outPath, MaxRows, strerror(errno));
        return 1;
    }
    (void)memset(Rows, 0, MaxRows * sizeof(*Rows));     /* fault the pages in */

    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    (void)sigaction(SIGTERM, &sa, NULL);
    (void)sigaction(SIGINT, &sa, NULL);

    BswStamps_SetObserver(&observer);
    if (BenchNet_Init(&net) != 0) {
        return 1;
    }
    mlockStatus = bench_lock_memory();
    if (bench_require_locked(mlockStatus, allowUnlocked) != 0) {
        return 1;
    }
    if (BenchNet_PinAndSchedule(cpu, (strcmp(sched, "fifo") == 0) ? priority : 0) != 0) {
        (void)fprintf(stderr, "cannot run on cpu %d with scheduler %s (SCHED_FIFO needs root)\n", cpu, sched);
        return 1;
    }
    (void)printf("listening on port %u\n", (unsigned)net.port);
    (void)fflush(stdout);

    BenchTcpInfo_Read(-1, &tcp);    /* all fields "not known" until the connection is read */
    if (samplesPath != NULL) {
        /* The sampler's thread is created here and waits for the first PDU's instant. Created at the first
         * PDU (as until 2026-11-23) it stalled the receive loop for about 10 ms, and at the ceiling rate
         * that backlog stayed on every PDU of the step. */
        sampler.iface = iface;
        sampler.cpu = cpu;
        sampler.firstNs = 0U;
        sampler.samples = (unsigned)duration + 1U;
        sampler.done = &Delivered;
        sampler.drops = &Rejected;
        sampler.sendQueue = 0;
        sampler.stop = &Stop;
        if (BenchNet_SamplerStart(&sampler) != 0) {
            (void)fprintf(stderr, "cannot start the sampler\n");
            return 1;
        }
        samplerRunning = 1;
    }
    lastActivity = bench_now_ns();
    tick0 = lastActivity;
    while (Stop == 0) {
        uint64_t recvBefore = BenchNet_RecvCalls;
        unsigned long eventsBefore = Events;
        uint32 dropped = 0U;
        uint64_t now;

        if (cyclic != 0) {
            struct timespec ts;
            uint64_t due = tick0 + (tick * tickNs);
            ts.tv_sec = (time_t)(due / 1000000000ULL);
            ts.tv_nsec = (long)(due % 1000000000ULL);
            while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {
            }
            /* the data-path main functions, in the order of the gateway's BSW cycle (EcuM) */
            SecOC_MainFunctionRx();
            PqcHs_MainFunction();       /* nothing to do without the handshake component */
            SecOC_MainFunctionTx();
            Csm_MainFunction();
            SoAd_MainFunctionTx();
            SoAd_MainFunctionRx();
        } else {
            SoAd_MainFunctionRx();
            SecOC_MainFunctionRx();
            if (net.handshake != 0) {
                PqcHs_MainFunction();   /* the responder answers M1 and M3 */
                SoAd_MainFunctionTx();
            }
        }
        (void)BenchNet_HsPoll();
        /* TCP_NODELAY as the stack left it on the accepted connection, read once and outside the stamped
         * path: when the session stands (the first PDU is 200 ms away), or at the connection without one */
        if ((tcpRead == 0) && (BenchNet_ConnFd >= 0) && ((net.handshake == 0) || (PqcHs_IsEstablished(0U) == TRUE))) {
            BenchTcpInfo_Read(BenchNet_ConnFd, &tcp);
            BenchNet_TcpNoDelay = tcp.noDelay;
            tcpRead = 1;
            if (tcp.noDelay != 1) {     /* CAMPAIGN.md: valid only with TCP_NODELAY = 1 on both ends; stop at once */
                (void)fprintf(stderr, "TCP_NODELAY of the accepted connection reads back %d, not 1: stopping\n", tcp.noDelay);
                noDelayBad = 1;
                Stop = 1;
            }
        }
        now = bench_now_ns();

        /* PDUs discarded by SoAd never reach SecOC; its drop counter is the only trace of them. */
        if ((SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped) == E_OK) && (dropped > 0U)) {
            for (; dropped > 0U; dropped--) {
                (void)add_row(RX_FRAMING_FAIL, -1, -1L, now, 0U, 0U);
                framing++;
                Rejected++;
            }
            Events++;
        }
        if ((samplerRunning != 0) && (samplerBegun == 0) && (RxIndications > 0UL)) {
            BenchNet_SamplerBegin(FirstRxDone + ((uint64_t)ramp * 1000000000ULL));
            samplerBegun = 1;
        }

        if ((BenchNet_RecvCalls != recvBefore) || (Events != eventsBefore)) {
            lastActivity = now;
        } else if ((BenchNet_PeerClosed != 0) || ((RowCount > 0UL) && ((now - lastActivity) > idleExitNs))) {
            break;
        } else if (cyclic == 0) {
            if (BenchNet_ConnFd >= 0) {
                struct pollfd pfd = { BenchNet_ConnFd, POLLIN, 0 };
                (void)poll(&pfd, 1U, 100);
            } else {
                (void)poll(NULL, 0U, 1);    /* not connected yet: SoAd_MainFunctionRx accepts on the next pass */
            }
        } else {
            /* cyclic: the next tick comes anyway */
        }
        if (cyclic != 0) {
            uint64_t nowTick = ((bench_now_ns() - tick0) / tickNs) + 1U;
            if (nowTick > (tick + 1U)) {
                overruns += (unsigned long)(nowTick - (tick + 1U));
            }
            tick = nowTick;
        }
    }
    /* context switches of this thread alone, the one that receives and verifies */
    (void)memset(&worker, 0, sizeof(worker));
    (void)getrusage(RUSAGE_THREAD, &worker);
    if (samplerRunning != 0) {
        if (samplerBegun == 0) {
            BenchNet_SamplerCancel();   /* no PDU ever came */
        }
        BenchNet_SamplerJoin();
    }

    sampledCpu = bench_write_header(out, "bench_net_rx", mlockStatus);
    (void)fprintf(out, "# role=rx\n# profile=%s\n# scheduler=%s\n# sched_priority=%d\n# listen_port=%u\n# peer=%u.%u.%u.%u\n# tcp_nodelay=%d\n",
                  profile, sched, (strcmp(sched, "fifo") == 0) ? priority : 0, (unsigned)net.port,
                  net.peerIp[0], net.peerIp[1], net.peerIp[2], net.peerIp[3], tcp.noDelay);
    (void)fprintf(out, "# mainfunction=%s\n# mf_period_us=%" PRIu64 "\n# partition=%d\n# partitions=%d\n# rep=%d\n", mainFunction,
                  mfPeriodUs, partition, partitions, rep);
    (void)fprintf(out, "# mf_order=%s\n", (cyclic != 0)
                  ? "SecOC_MainFunctionRx PqcHs_MainFunction SecOC_MainFunctionTx Csm_MainFunction SoAd_MainFunctionTx SoAd_MainFunctionRx, once per tick"
                  : "SoAd_MainFunctionRx SecOC_MainFunctionRx (PqcHs_MainFunction SoAd_MainFunctionTx with the handshake) back to back while data or a PDU is pending, poll() otherwise");
    if (Profile == BENCH_NET_PROFILE_SIG) {
        BenchNet_WriteStreamIds(out, BENCH_NET_MAX_STREAMS, Profile);
    } else {    /* mac: the one MAC stream; both: the signature stream and the MAC stream */
        BenchNet_WriteStreamIds(out, (Profile == BENCH_NET_PROFILE_BOTH) ? 2U : BENCH_NET_MAC_STREAMS, Profile);
    }
    BenchNet_HsWriteKeys(out, net.handshake, FirstRxDone);      /* the interval starts with the first PDU received */
    if ((net.handshake != 0) && (hsPath != NULL) && (BenchNet_HsWriteFile(hsPath, "bench_net_rx", mlockStatus, mainFunction, mfPeriodUs, startNs,
                                                                         (RowCount > 0UL) ? "# pdu_stream=periodic\n" : "# pdu_stream=none\n") != 0)) {
        (void)fprintf(stderr, "cannot write %s\n", hsPath);
    }
    (void)fprintf(out, "# hooks=PduR_SoAdTpRxIndication (rx_done_ns), SecOC_VerificationStatusCallout (verify_done_ns, result), "
                       "Com_RxIndication (deliver_ns, payload), PduR_SoAdStartOfReception and PduR_SoAdTpCopyRxData "
                       "(first bytes, for seq of rejected PDUs); link-time wraps\n");
    (void)fprintf(out, "stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result\n");
    for (i = 0UL; i < RowCount; i++) {
        (void)fprintf(out, "%d,%ld,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%s\n", Rows[i].stream, Rows[i].seq, Rows[i].rxDone,
                      Rows[i].verifyDone, Rows[i].deliver, ResultNames[Rows[i].result]);
    }
    (void)fprintf(out, "# rows=%lu\n# rows_lost=%lu\n# delivered=%lu\n# rejected=%lu\n# framing_fail=%lu\n"
                       "# rx_indications=%lu\n# verification_callouts=%lu\n# head_seq_mismatches=%lu\n# peer_closed=%d\n"
                       "# mf_overruns=%lu\n# worker_ctx_switches_involuntary=%ld\n# worker_ctx_switches_voluntary=%ld\n",
                  RowCount, RowsLost, Delivered, Rejected, framing, RxIndications, Callouts, HeadSeqMismatches,
                  BenchNet_PeerClosed, overruns, worker.ru_nivcsw, worker.ru_nvcsw);
    bench_write_footer(out, sampledCpu, startNs);
    if ((ferror(out) != 0) || (fclose(out) != 0)) {
        (void)fprintf(stderr, "write to %s failed: %s\n", outPath, strerror(errno));
        return 1;
    }

    if (payloadPath != NULL) {
        FILE* pf = fopen(payloadPath, "w");
        if (pf == NULL) {
            (void)fprintf(stderr, "cannot open %s: %s\n", payloadPath, strerror(errno));
            return 1;
        }
        (void)fprintf(pf, "# tool=bench_net_rx\n# commit=%s\n# host=%s\nstream,seq,payload_hex\n", BENCH_GIT_COMMIT, host);
        for (i = 0UL; i < RowCount; i++) {
            if (Rows[i].result == (uint8)RX_OK) {
                (void)fprintf(pf, "%d,%ld,", Rows[i].stream, Rows[i].seq);
                for (c = 0; c < (int)Rows[i].payloadLen; c++) {
                    (void)fprintf(pf, "%02x", (unsigned)Rows[i].payload[c]);
                }
                (void)fprintf(pf, "\n");
            }
        }
        if ((ferror(pf) != 0) || (fclose(pf) != 0)) {
            (void)fprintf(stderr, "write to %s failed: %s\n", payloadPath, strerror(errno));
            return 1;
        }
    }

    if (samplesPath != NULL) {
        FILE* sf = fopen(samplesPath, "w");
        if (sf == NULL) {
            (void)fprintf(stderr, "cannot open %s: %s\n", samplesPath, strerror(errno));
            return 1;
        }
        (void)bench_write_header(sf, "bench_net_rx", mlockStatus);
        (void)fprintf(sf, "# tx_host=%s\n# rx_host=%s\n# profile=%s\n# cores=1\n# partition=%d\n# partitions=%d\n# rep=%d\n# offered_pps=%g\n"
                          "# ramp_s=%lu\n# duration_s=%lu\n# iface=%s\n# sampled_cpu=%d\n# mainfunction=%s\n# mf_period_us=%" PRIu64 "\n"
                          "# tcp_nodelay=%d\n",
                      txHost, host, profile, partition, partitions, rep, ratePps, ramp, duration, iface, cpu, mainFunction,
                      mfPeriodUs, tcp.noDelay);
        (void)fprintf(sf, "t_ns,host,offered_pps,pdus_done,cpu_busy_jiffies,cpu_total_jiffies,if_tx_bytes,if_tx_packets,"
                          "if_rx_bytes,if_rx_packets,sendq_bytes,drops,proc_cpu_ns\n");
        BenchNet_SamplerWrite(sf, host, ratePps);
        (void)fprintf(sf, "# worker_ctx_switches_involuntary=%ld\n# worker_ctx_switches_voluntary=%ld\n",
                      worker.ru_nivcsw, worker.ru_nvcsw);
        bench_write_footer(sf, sampledCpu, startNs);
        if ((ferror(sf) != 0) || (fclose(sf) != 0)) {
            (void)fprintf(stderr, "write to %s failed: %s\n", samplesPath, strerror(errno));
            return 1;
        }
    }

    (void)printf("delivered=%lu rejected=%lu framing_fail=%lu rows_lost=%lu head_seq_mismatches=%lu\n",
                 Delivered, Rejected, framing, RowsLost, HeadSeqMismatches);
    /* A row that could not be stored, or a delivered payload that is not the one that was received,
     * means the file does not describe the run. */
    if (noDelayBad != 0) {
        return 6;
    }
    return ((RowsLost == 0UL) && (HeadSeqMismatches == 0UL)) ? 0 : 4;
}
