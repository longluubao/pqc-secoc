/* Bring-up of the networked BSW path for the harnesses, and the hooks both roles need.
 *
 * Initialised: Det, BswM (state only: its main function is never called, so no mode action runs),
 * Csm, SecOC, TcpIp, SoAd. Not initialised and never called: EcuM, Os, Com, the CAN stack, NvM,
 * the UDP key-exchange channel. The gateway's BswM reaction to verification failures (it closes
 * the SoAd routing group) is therefore NOT part of what these harnesses exercise. */
#define _GNU_SOURCE
#include "bench_net.h"

#include <linux/sockios.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "BswM.h"
#include "Csm.h"
#include "Det.h"
#include "PQC.h"
#include "PqcHs.h"
#include "PqcHs_Cfg.h"
#include "SecOC.h"
#include "SecOC_Lcfg.h"
#include "SoAd.h"
#include "TcpIp.h"

int      BenchNet_ConnFd = -1;
uint64_t BenchNet_RecvCalls = 0U;
int      BenchNet_PeerClosed = 0;
unsigned long BenchNet_Connections = 0UL;
int      BenchNet_TcpNoDelay = -1;

static PQC_MLDSA_KeyPairType Identity;
static uint8 PeerPublicKey[PQC_MLDSA_PUBLIC_KEY_BYTES];

/**************************************** link-time hooks ****************************************/

/* TcpIp.c owns the sockets; the harness needs the connection's descriptor to sleep on it and to
 * read its send-queue depth. These wraps observe TcpIp.c's own calls and change nothing. */
int __real_connect(int fd, const struct sockaddr* addr, socklen_t len);
int __real_accept(int fd, struct sockaddr* addr, socklen_t* len);
ssize_t __real_recv(int fd, void* buf, size_t len, int flags);

int __wrap_connect(int fd, const struct sockaddr* addr, socklen_t len)
{
    BenchNet_ConnFd = fd;
    BenchNet_Connections++;     /* TcpIp.c connects non-blocking: every call is a new attempt */
    return __real_connect(fd, addr, len);
}

int __wrap_accept(int fd, struct sockaddr* addr, socklen_t* len)
{
    int conn = __real_accept(fd, addr, len);
    if (conn >= 0) {
        BenchNet_ConnFd = conn;
        BenchNet_Connections++;
    }
    return conn;
}

ssize_t __wrap_recv(int fd, void* buf, size_t len, int flags)
{
    ssize_t n = __real_recv(fd, buf, len, flags);
    if (n > 0) {
        BenchNet_RecvCalls++;
    } else if (n == 0) {
        BenchNet_PeerClosed = 1;
    }
    return n;
}

/* The harness is the upper layer of SecOC; Com is not initialised and must not be entered. */
void __wrap_Com_TxConfirmation(PduIdType TxPduId, Std_ReturnType result)
{
    (void)TxPduId;
    (void)result;
}

void __wrap_Com_TpTxConfirmation(PduIdType ComTxPduId, Std_ReturnType Result)
{
    (void)ComTxPduId;
    (void)Result;
}

/******************************************* bring-up ********************************************/

static int read_exact(const char* dir, const char* name, uint8* out, size_t len)
{
    char path[512];
    FILE* f;
    size_t got;
    int extra;

    (void)snprintf(path, sizeof(path), "%s/%s", dir, name);
    f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    got = fread(out, 1U, len, f);
    extra = fgetc(f);
    (void)fclose(f);
    return ((got == len) && (extra == EOF)) ? 0 : -1;
}

static Std_ReturnType load_identity(uint8* publicKeyPtr, uint32 publicKeyLength,
                                    uint8* secretKeyPtr, uint32 secretKeyLength)
{
    if ((publicKeyLength != sizeof(Identity.PublicKey)) || (secretKeyLength != sizeof(Identity.SecretKey))) {
        return E_NOT_OK;
    }
    (void)memcpy(publicKeyPtr, Identity.PublicKey, sizeof(Identity.PublicKey));
    (void)memcpy(secretKeyPtr, Identity.SecretKey, sizeof(Identity.SecretKey));
    return E_OK;
}

static PqcHs_TimersType HsTimers;       /* the handshake component's timer values, for the records */

int BenchNet_Init(const BenchNet_ConfigType* cfg)
{
    /* handshake messages M1..M4: PDU ID, PDU header ID, fixed length, stream gate after it */
    static const struct { PduIdType pdu; uint32 header; uint32 length; boolean gate; } hsRoute[4] = {
        { (PduIdType)SOAD_PDUID_HS_M1, SOAD_HEADERID_HS_M1, SOAD_HS_M1_LENGTH, FALSE },
        { (PduIdType)SOAD_PDUID_HS_M2, SOAD_HEADERID_HS_M2, SOAD_HS_M2_LENGTH, FALSE },
        { (PduIdType)SOAD_PDUID_HS_M3, SOAD_HEADERID_HS_M3, SOAD_HS_M3_LENGTH, TRUE },
        { (PduIdType)SOAD_PDUID_HS_M4, SOAD_HEADERID_HS_M4, SOAD_HS_M4_LENGTH, FALSE },
    };
    static SoAd_PduRouteConfigType route[BENCH_NET_MAX_STREAMS + BENCH_NET_MAC_STREAMS + 4U];
    static SoAd_SoConConfigType soCon;
    uint32 i;
    static SoAd_ConfigType soAd;
    Csm_ConfigType csm = { CSM_MLDSA_BOOTSTRAP_PROVISIONED, load_identity };
    uint8 probe[PQC_MLDSA_SIGNATURE_BYTES];
    uint32 probeLen = 0U;

    if ((read_exact(cfg->keyDir, BENCH_NET_KEY_FILE, Identity.SecretKey, sizeof(Identity.SecretKey)) != 0) ||
        (read_exact(cfg->keyDir, BENCH_NET_PUB_FILE, Identity.PublicKey, sizeof(Identity.PublicKey)) != 0)) {
        (void)fprintf(stderr, "cannot read %s and %s in %s (create them with bench_keygen)\n",
                      BENCH_NET_KEY_FILE, BENCH_NET_PUB_FILE, cfg->keyDir);
        return -1;
    }

    Det_Init(NULL);
    BswM_Init(NULL);
    Csm_Init(&csm);
    /* Csm_Init() returns nothing: a signature proves the identity is installed. */
    if (Csm_SignatureGenerate((uint32)CSM_JOBID, CRYPTO_OPERATIONMODE_SINGLECALL, Identity.PublicKey, 32U,
                              probe, &probeLen) != E_OK) {
        (void)fprintf(stderr, "Csm initialisation failed\n");
        return -2;
    }
    /* The pinned public key of the peer, as peer 0: the receiver verifies PDUs with it, and in the
     * handshake each side verifies the other's signature with it. */
    if (((SECOC_ROLE_RECEIVER == TRUE) || (cfg->handshake != 0)) &&
        ((read_exact(cfg->keyDir, BENCH_NET_PEER_PUB_FILE, PeerPublicKey, sizeof(PeerPublicKey)) != 0) ||
         (Csm_KeyElementSet(CSM_KEYID_PEER_PUBKEY_BASE, CSM_KEYELEMENT_MLDSA_PEER_PUBLIC, PeerPublicKey,
                            (uint32)sizeof(PeerPublicKey)) != E_OK) ||
         (Csm_KeySetValid(CSM_KEYID_PEER_PUBKEY_BASE) != E_OK))) {
        (void)fprintf(stderr, "cannot install %s/%s as the peer public key\n", cfg->keyDir, BENCH_NET_PEER_PUB_FILE);
        return -3;
    }

    SecOC_Init(&SecOC_Config);
    TcpIp_Init(NULL);

    /* The signature-stream routes and the socket connection of SoAd's built-in configuration,
     * with the address and port taken from the command line instead of the build. */
    for (i = 0U; i < BENCH_NET_MAX_STREAMS; i++) {
        route[i].SoAdPduId = (PduIdType)SECOC_PDUID_SIG(i);
        route[i].SoAdPduRouteType = SOAD_PDU_ROUTE_TP;
        route[i].SoAdRoutingGroupId = (SoAd_RoutingGroupIdType)SOAD_ROUTING_GROUP_NORMAL;
        route[i].SoAdPduHeaderId = SOAD_HEADERID_SIG(i);
        route[i].SoAdSoConId = 0U;
        route[i].SoAdUpperLayer = SOAD_UPPER_LAYER_PDUR;
        route[i].SoAdRxMinLength = 0U;
        route[i].SoAdRxMaxLength = 1U + SECOC_AUTHPDU_MAX_LENGTH + 4U + PQC_MLDSA_SIGNATURE_BYTES;
        route[i].SoAdRxGate = FALSE;
    }
    /* the MAC stream(s), as SoAd's built-in table has them */
    for (i = 0U; i < BENCH_NET_MAC_STREAMS; i++) {
        SoAd_PduRouteConfigType* r = &route[BENCH_NET_MAX_STREAMS + i];
        r->SoAdPduId = (PduIdType)SECOC_PDUID_MAC(i);
        r->SoAdPduRouteType = SOAD_PDU_ROUTE_TP;
        r->SoAdRoutingGroupId = (SoAd_RoutingGroupIdType)SOAD_ROUTING_GROUP_NORMAL;
        r->SoAdPduHeaderId = SOAD_HEADERID_MAC(i);
        r->SoAdSoConId = 0U;
        r->SoAdUpperLayer = SOAD_UPPER_LAYER_PDUR;
        r->SoAdRxMinLength = 0U;
        r->SoAdRxMaxLength = BENCH_NET_MAC_PDU_MAX;
        r->SoAdRxGate = FALSE;
    }
    /* the four handshake messages, with the values of SoAd's built-in table: fixed lengths, the
     * handshake component as upper layer, and the stream gate after M3 (nothing behind M3 is parsed
     * until the responder has installed its keys) */
    for (i = 0U; i < 4U; i++) {
        SoAd_PduRouteConfigType* r = &route[BENCH_NET_MAX_STREAMS + BENCH_NET_MAC_STREAMS + i];
        r->SoAdPduId = hsRoute[i].pdu;
        r->SoAdPduRouteType = SOAD_PDU_ROUTE_TP;
        r->SoAdRoutingGroupId = (SoAd_RoutingGroupIdType)SOAD_ROUTING_GROUP_HS;
        r->SoAdPduHeaderId = hsRoute[i].header;
        r->SoAdSoConId = 0U;
        r->SoAdUpperLayer = SOAD_UPPER_LAYER_HS;
        r->SoAdRxMinLength = hsRoute[i].length;
        r->SoAdRxMaxLength = hsRoute[i].length;
        r->SoAdRxGate = hsRoute[i].gate;
    }
    soCon.SoAdTxPduId = (PduIdType)SECOC_PDUID_SIG(0U);
    soCon.SoAdProtocol = TCPIP_IPPROTO_TCP;
    soCon.SoAdLocalAddrId = 0U;
#if (SECOC_ROLE_RECEIVER == TRUE)
    soCon.SoAdLocalPort = cfg->port;
#else
    soCon.SoAdLocalPort = 0U;
#endif
    soCon.SoAdRemoteAddr.domain = TCPIP_AF_INET;
    (void)memcpy(soCon.SoAdRemoteAddr.addr, cfg->peerIp, 4U);
    soCon.SoAdRemoteAddr.port = cfg->port;
    soCon.SoAdInitialMode = SOAD_SOCON_ONLINE;
    /* as the gateway's own table (SoAd.c): SoAd sets TCP_NODELAY on every socket of the connection; a
     * table written without the field has the parameter absent and the stack's default, Nagle on */
    soCon.SoAdSocketTcpNoDelay = SOAD_TCP_NODELAY_TRUE;
    soAd.SoAdPduRouteConfigPtr = route;
    soAd.SoAdPduRouteConfigCount = BENCH_NET_MAX_STREAMS + BENCH_NET_MAC_STREAMS + 4U;
    soAd.SoAdSoConConfigPtr = &soCon;
    soAd.SoAdSoConConfigCount = 1U;
    soAd.SoAdEnableUnauthApControl = FALSE;
    SoAd_Init(&soAd);
    if (SoAd_EnableRouting(0U) != E_OK) {
        (void)fprintf(stderr, "SoAd_EnableRouting failed\n");
        return -4;
    }
    /* As EcuM does: the handshake component after SoAd, Csm and SecOC; from here on no Secured I-PDU
     * is released or accepted without a session. The transmitter is the initiator and asks once. */
    if (cfg->handshake != 0) {
        HsTimers = PqcHs_Config.PqcHsTimers;    /* the shipped timers: the campaign measures with them */
        if (PqcHs_Init(NULL) != E_OK) {
            (void)fprintf(stderr, "PqcHs_Init failed\n");
            return -5;
        }
#if (SECOC_ROLE_SENDER == TRUE)
        (void)PqcHs_Initiate(0U);
#endif
    }
    return 0;
}

/******************************************** handshake ******************************************/


#define BENCH_NET_HS_ROWS   8192U
static PqcHs_AttemptInfoType HsRows[BENCH_NET_HS_ROWS];
static unsigned HsRowCount;
static unsigned HsRowsLost;
static uint8 HsFirstSid[PQCHS_SID_BYTES];      /* the session of the first attempt that ended ok */
static uint32 HsFirstInstalls;
static int HsFirstSeen;
static uint64_t HsSeenNs[BENCH_NET_HS_ROWS];    /* when each record was collected */
static uint64_t HsEstablishedNs;

int BenchNet_HsPoll(void)
{
    PqcHs_AttemptInfoType row;
    int seen = 0;
    while (PqcHs_ReadAttempt(0U, &row) == E_OK) {
        if (HsRowCount < BENCH_NET_HS_ROWS) {
            HsRows[HsRowCount] = row;
            HsSeenNs[HsRowCount] = bench_now_ns();
            HsRowCount++;
        } else {
            HsRowsLost++;
        }
        if (row.Result != PQCHS_RESULT_OK) {
            seen = -1;
        } else if (seen == 0) {
            seen = 1;
        } else {
            /* keep what was seen first */
        }
        if ((row.Result == PQCHS_RESULT_OK) && (HsFirstSeen == 0) &&
            (PqcHs_GetSession(0U, HsFirstSid, &HsFirstInstalls) == E_OK)) {
            HsFirstSeen = 1;
            HsEstablishedNs = bench_now_ns();
        }
    }
    return seen;
}

int BenchNet_HsCycle(uint64_t tickNs, uint64_t untilNs)
{
    uint64_t t0 = bench_now_ns();
    uint64_t tick;
    for (tick = 0U; ; tick++) {
        uint64_t due = t0 + (tick * tickNs);
        struct timespec ts = { (time_t)(due / 1000000000ULL), (long)(due % 1000000000ULL) };
        int seen;
        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {
        }
        SecOC_MainFunctionRx();
        PqcHs_MainFunction();
        SecOC_MainFunctionTx();
        Csm_MainFunction();
        SoAd_MainFunctionTx();
        SoAd_MainFunctionRx();
        seen = BenchNet_HsPoll();
        if (seen != 0) {
            return seen;
        }
        if (bench_now_ns() >= untilNs) {
            return 0;
        }
    }
}

int BenchNet_HsWait(uint64_t tickNs, uint64_t timeoutNs)
{
    int seen = BenchNet_HsCycle(tickNs, bench_now_ns() + timeoutNs);
    if (seen == 0) {
        return -2;
    }
    return ((seen > 0) && (PqcHs_IsEstablished(0U) == TRUE)) ? 0 : -1;
}

void BenchNet_HsWriteKeys(FILE* f, int handshake, uint64_t runStartNs)
{
    uint8 sid[PQCHS_SID_BYTES];
    uint32 installs = 0U;
    unsigned inRun = 0U;
    unsigned i;
    if ((handshake == 0) || (PqcHs_GetSession(0U, sid, &installs) != E_OK)) {
        (void)fprintf(f, "# handshake=off\n");
        return;
    }
    (void)fprintf(f, "# handshake=PQC-SecOC-HS-v1\n# session_id=");
    for (i = 0U; i < PQCHS_SID_BYTES; i++) {
        (void)fprintf(f, "%02x", (unsigned)sid[i]);
    }
    (void)fprintf(f, "\n# hs_installs=%u\n# hs_established=%d\n", (unsigned)installs, (PqcHs_IsEstablished(0U) == TRUE) ? 1 : 0);
    /* a run with more than one handshake: where it started (session_id and hs_installs are where it ended) */
    if (HsFirstSeen != 0) {
        (void)fprintf(f, "# session_id_first=");
        for (i = 0U; i < PQCHS_SID_BYTES; i++) {
            (void)fprintf(f, "%02x", (unsigned)HsFirstSid[i]);
        }
        (void)fprintf(f, "\n# hs_installs_first=%u\n", (unsigned)HsFirstInstalls);
    }
    (void)fprintf(f, "# established_ns=%" PRIu64 "\n# hs_record_in_run_ns=", HsEstablishedNs);
    for (i = 0U; i < HsRowCount; i++) {
        if ((runStartNs != 0U) && (HsSeenNs[i] >= runStartNs)) {
            (void)fprintf(f, "%s%" PRIu64, (inRun == 0U) ? "" : ",", HsSeenNs[i]);
            inRun++;
        }
    }
    (void)fprintf(f, "\n# hs_records_in_run=%u\n", inRun);
}

int BenchNet_HsWriteFile(const char* path, const char* tool, const char* mlockStatus, const char* mainFunction,
                         uint64_t mfPeriodUs, uint64_t startNs, const char* moreKeys)
{
    static const char* const resultName[] = { "ok", "bad_ver", "bad_len", "unknown_id", "sig_fail", "mac_fail", "timeout", "state" };
    FILE* f = fopen(path, "w");
    unsigned i;
    int cpu;
    if (f == NULL) {
        return -1;
    }
    cpu = bench_write_header(f, tool, mlockStatus);
    (void)fprintf(f, "# mainfunction=%s\n# mf_period_us=%" PRIu64 "\n"
                     "# t_min_ms=%u\n# t_pend_ms=%u\n# t_a_ms=%u\n# t_flush_ms=%u\n# rows=%u\n# rows_lost=%u\n",
                  mainFunction, mfPeriodUs,
                  (unsigned)HsTimers.PqcHsTMinMs, (unsigned)HsTimers.PqcHsTPendMs,
                  (unsigned)HsTimers.PqcHsTAMs, (unsigned)HsTimers.PqcHsTFlushMs,
                  HsRowCount, HsRowsLost);
    (void)fputs(moreKeys, f);
    (void)fprintf(f, "# tcp_nodelay=%d\n", BenchNet_TcpNoDelay);
    BenchNet_HsWriteKeys(f, 1, 0U);
    (void)fprintf(f, "seq,role,result,total_ns,bytes_tx,bytes_rx,keygen_ns,encaps_ns,decaps_ns,sign_ns,verify_ns,kdf_ns,hash_ns,mac_ns\n");
    for (i = 0U; i < HsRowCount; i++) {
        const PqcHs_AttemptInfoType* r = &HsRows[i];
        (void)fprintf(f, "%u,%s,%s,%llu,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n", (unsigned)r->Seq,
                      (r->Role == PQCHS_ROLE_INITIATOR) ? "initiator" : "responder",
                      ((unsigned)r->Result < (sizeof(resultName) / sizeof(resultName[0]))) ? resultName[r->Result] : "state",
                      (unsigned long long)r->TotalNs, (unsigned)r->BytesTx, (unsigned)r->BytesRx,
                      (unsigned long long)r->Times.KeygenNs, (unsigned long long)r->Times.EncapsNs,
                      (unsigned long long)r->Times.DecapsNs, (unsigned long long)r->Times.SignNs,
                      (unsigned long long)r->Times.VerifyNs, (unsigned long long)r->Times.KdfNs,
                      (unsigned long long)r->Times.HashNs, (unsigned long long)r->Times.MacNs);
    }
    bench_write_footer(f, cpu, startNs);
    return ((ferror(f) == 0) && (fclose(f) == 0)) ? 0 : -1;
}

int BenchNet_PinAndSchedule(int cpu, int fifoPriority)
{
    cpu_set_t set;
    struct sched_param param;
    int policy = SCHED_OTHER;

    CPU_ZERO(&set);
    CPU_SET((size_t)cpu, &set);
    if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0) {
        return -1;
    }
    (void)memset(&param, 0, sizeof(param));
    if (fifoPriority > 0) {
        param.sched_priority = fifoPriority;
        if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) != 0) {
            return -1;
        }
    }
    /* Read back: a silently ignored request would mislabel the whole run. */
    CPU_ZERO(&set);
    if ((pthread_getaffinity_np(pthread_self(), sizeof(set), &set) != 0) || (CPU_COUNT(&set) != 1) ||
        !CPU_ISSET((size_t)cpu, &set) || (pthread_getschedparam(pthread_self(), &policy, &param) != 0)) {
        return -1;
    }
    if (fifoPriority > 0) {
        return ((policy == SCHED_FIFO) && (param.sched_priority == fifoPriority)) ? 0 : -1;
    }
    return (policy == SCHED_OTHER) ? 0 : -1;
}

int BenchNet_ParseEndpoint(const char* text, uint8* ip, uint16* port)
{
    unsigned a = 0U;
    unsigned b = 0U;
    unsigned c = 0U;
    unsigned d = 0U;
    unsigned p = 0U;
    char tail = '\0';

    if (ip == NULL) {
        if ((sscanf(text, "%u%c", &p, &tail) != 1) || (p == 0U) || (p > 65535U)) {
            return -1;
        }
    } else {
        if ((sscanf(text, "%u.%u.%u.%u:%u%c", &a, &b, &c, &d, &p, &tail) != 5) ||
            (a > 255U) || (b > 255U) || (c > 255U) || (d > 255U) || (p == 0U) || (p > 65535U)) {
            return -1;
        }
        ip[0] = (uint8)a;
        ip[1] = (uint8)b;
        ip[2] = (uint8)c;
        ip[3] = (uint8)d;
    }
    *port = (uint16)p;
    return 0;
}

/******************************************** sampler ********************************************/

typedef struct {
    uint64_t           tNs;
    unsigned long      done;
    unsigned long      drops;
    unsigned long long busy;
    unsigned long long total;
    unsigned long long counters[4];     /* tx_bytes, tx_packets, rx_bytes, rx_packets */
    int                sendQueue;
    uint64_t           procCpuNs;       /* CLOCK_PROCESS_CPUTIME_ID, cumulative */
} BenchNet_SampleType;

static BenchNet_SamplerConfigType Sampler;
static BenchNet_SampleType* Samples = NULL;
static unsigned SampleCount = 0U;
static pthread_t SamplerThread;
/* The first sample's instant. The transmitter knows it at the start; the receiver learns it with its first
 * PDU and must not create a thread then (with locked memory that takes about 10 ms, in its receive loop). */
static volatile uint64_t SamplerFirstNs;
static volatile sig_atomic_t SamplerCancelled;

static unsigned long long read_counter(const char* iface, const char* name)
{
    char path[160];
    unsigned long long value = 0ULL;
    FILE* f;

    (void)snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/%s", iface, name);
    f = fopen(path, "r");
    if (f != NULL) {
        if (fscanf(f, "%llu", &value) != 1) {
            value = 0ULL;
        }
        (void)fclose(f);
    }
    return value;
}

static void read_cpu(int cpu, unsigned long long* busy, unsigned long long* total)
{
    char line[256];
    char want[16];
    FILE* f = fopen("/proc/stat", "r");

    *busy = 0ULL;
    *total = 0ULL;
    (void)snprintf(want, sizeof(want), "cpu%d ", cpu);
    while ((f != NULL) && (fgets(line, (int)sizeof(line), f) != NULL)) {
        unsigned long long v[8] = { 0ULL };
        if (strncmp(line, want, strlen(want)) == 0) {
            /* user nice system idle iowait irq softirq steal */
            (void)sscanf(line + strlen(want), "%llu %llu %llu %llu %llu %llu %llu %llu",
                         &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]);
            *busy = v[0] + v[1] + v[2] + v[5] + v[6] + v[7];
            *total = *busy + v[3] + v[4];
            break;
        }
    }
    if (f != NULL) {
        (void)fclose(f);
    }
}

static void* sampler_main(void* arg)
{
    static const char* const names[4] = { "tx_bytes", "tx_packets", "rx_bytes", "rx_packets" };
    cpu_set_t set;
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    unsigned i;
    int c;

    struct sched_param param;

    (void)arg;
    /* Anywhere but the measured CPU, and never with the worker's real-time priority. */
    CPU_ZERO(&set);
    for (c = 0; c < (int)cpus; c++) {
        if (c != Sampler.cpu) {
            CPU_SET((size_t)c, &set);
        }
    }
    (void)pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    (void)memset(&param, 0, sizeof(param));
    (void)pthread_setschedparam(pthread_self(), SCHED_OTHER, &param);

    while ((SamplerFirstNs == 0U) && (SamplerCancelled == 0) && (*Sampler.stop == 0)) {
        struct timespec nap = { 0, 1000000L };      /* waiting for BenchNet_SamplerBegin(), off the measured CPU */
        (void)clock_nanosleep(CLOCK_MONOTONIC, 0, &nap, NULL);
    }
    for (i = 0U; (i < Sampler.samples) && (SamplerCancelled == 0); i++) {
        uint64_t due = SamplerFirstNs + ((uint64_t)i * 1000000000ULL);
        struct timespec ts = { (time_t)(due / 1000000000ULL), (long)(due % 1000000000ULL) };
        BenchNet_SampleType* s = &Samples[i];
        int k;

        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {
        }
        if (*Sampler.stop != 0) {
            break;      /* the run was ended early: the join must not wait for the planned seconds */
        }
        s->tNs = bench_now_ns();
        s->done = *Sampler.done;
        s->drops = *Sampler.drops;
        read_cpu(Sampler.cpu, &s->busy, &s->total);
        for (k = 0; k < 4; k++) {
            s->counters[k] = read_counter(Sampler.iface, names[k]);
        }
        {   /* processor time of this process, all threads: /proc/stat's tick accounting misses work that
             * starts on a timer and ends before the next tick */
            struct timespec cpu = { 0, 0 };
            (void)clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu);
            s->procCpuNs = ((uint64_t)cpu.tv_sec * 1000000000ULL) + (uint64_t)cpu.tv_nsec;
        }
        s->sendQueue = 0;
        if ((Sampler.sendQueue != 0) && (BenchNet_ConnFd >= 0)) {
            (void)ioctl(BenchNet_ConnFd, SIOCOUTQ, &s->sendQueue);
        }
        SampleCount = i + 1U;
    }
    return NULL;
}

int BenchNet_SamplerStart(const BenchNet_SamplerConfigType* cfg)
{
    Sampler = *cfg;
    SamplerFirstNs = cfg->firstNs;
    SamplerCancelled = 0;
    Samples = calloc(cfg->samples, sizeof(*Samples));
    if (Samples == NULL) {
        return -1;
    }
    return (pthread_create(&SamplerThread, NULL, sampler_main, NULL) == 0) ? 0 : -1;
}

void BenchNet_SamplerBegin(uint64_t firstNs)
{
    SamplerFirstNs = firstNs;
}

void BenchNet_SamplerCancel(void)
{
    SamplerCancelled = 1;
}

void BenchNet_SamplerJoin(void)
{
    (void)pthread_join(SamplerThread, NULL);
}

void BenchNet_SamplerWrite(FILE* f, const char* host, double offeredPps)
{
    unsigned i;
    for (i = 0U; i < SampleCount; i++) {
        const BenchNet_SampleType* s = &Samples[i];
        (void)fprintf(f, "%" PRIu64 ",%s,%g,%lu,%llu,%llu,%llu,%llu,%llu,%llu,%d,%lu,%" PRIu64 "\n", s->tNs, host, offeredPps,
                      s->done, s->busy, s->total, s->counters[0], s->counters[1], s->counters[2], s->counters[3],
                      s->sendQueue, s->drops, s->procCpuNs);
    }
}
