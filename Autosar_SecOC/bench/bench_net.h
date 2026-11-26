/* Shared by the networked harnesses bench_net_tx and bench_net_rx.
 *
 * The harness is the application above SecOC: it brings up Csm, SecOC, TcpIp and SoAd and calls
 * their main functions itself, when there is work (no EcuM, Os, BswM or Com; see bench_net.c).
 * Timestamps come from link-time wraps (-Wl,--wrap) around calls the BSW already makes, so the
 * BSW sources are the production ones. */
#ifndef BENCH_NET_H
#define BENCH_NET_H

#include "bench_common.h"

#include <signal.h>
#include <string.h>

#include "Std_Types.h"
#include "ComStack_Types.h"

#include "SoAd_PduIds.h"

/* The streams of the tree's identifier table. Signature profile (mldsa65): stream i is SecOC PDU
 * SECOC_PDUID_SIG(i), PDU header ID SOAD_HEADERID_SIG(i). MAC profile (mac): SECOC_PDUID_MAC(i),
 * SOAD_HEADERID_MAC(i); the tree configures MAC stream 0. Both variants in one process (both): stream 0
 * is signature stream 0 and stream 1 is MAC stream 0, as in the gateway's PROFILE=both. The
 * SecOCDataId equals the PDU ID. */
#define BENCH_NET_PROFILE_SIG       0
#define BENCH_NET_PROFILE_MAC       1
#define BENCH_NET_PROFILE_BOTH      2
#define BENCH_NET_MAX_STREAMS       SECOC_PDUID_SIG_COUNT
#define BENCH_NET_MAC_STREAMS       1U
#define BENCH_NET_MAC_PDU_MAX       41U     /* header 1 + Authentic I-PDU up to 20 + freshness 4 + tag 16, as SoAd's table */

/* the profile of a name of --profile; -1: there is none */
static inline int BenchNet_ProfileOf(const char* name)
{
    return (strcmp(name, "mldsa65") == 0) ? BENCH_NET_PROFILE_SIG
         : (strcmp(name, "mac") == 0) ? BENCH_NET_PROFILE_MAC
         : (strcmp(name, "both") == 0) ? BENCH_NET_PROFILE_BOTH : -1;
}

/* Is stream i of the profile a MAC stream, and which one of its kind is it? */
static inline int BenchNet_StreamIsMac(int profile, uint32 i)
{
    return ((profile == BENCH_NET_PROFILE_MAC) || ((profile == BENCH_NET_PROFILE_BOTH) && (i == 1U))) ? 1 : 0;
}

static inline uint32 BenchNet_IndexInKind(int profile, uint32 i)
{
    return (profile == BENCH_NET_PROFILE_BOTH) ? 0U : i;
}

static inline uint32 BenchNet_PduOfStream(int profile, uint32 i)
{
    uint32 k = BenchNet_IndexInKind(profile, i);
    return (BenchNet_StreamIsMac(profile, i) != 0) ? (uint32)SECOC_PDUID_MAC(k) : (uint32)SECOC_PDUID_SIG(k);
}

static inline uint32 BenchNet_HeaderOfStream(int profile, uint32 i)
{
    uint32 k = BenchNet_IndexInKind(profile, i);
    return (BenchNet_StreamIsMac(profile, i) != 0) ? (uint32)SOAD_HEADERID_MAC(k) : (uint32)SOAD_HEADERID_SIG(k);
}

/* The stream column of the CSV files is the stream index 0..K-1, as in the gateway's logs; the
 * header lines stream_pdu_ids / stream_header_ids give the IDs behind each index. -1: not a stream. */
static inline int BenchNet_StreamOfPdu(int profile, uint32 pdu)
{
    uint32 i;
    for (i = 0U; i < BENCH_NET_MAX_STREAMS; i++) {
        if (SECOC_PDUID_SIG(i) == pdu) {
            return (int)i;
        }
    }
    for (i = 0U; i < SECOC_PDUID_MAC_COUNT; i++) {
        if (SECOC_PDUID_MAC(i) == pdu) {
            return (int)i + ((profile == BENCH_NET_PROFILE_BOTH) ? 1 : 0);      /* both: behind the one signature stream */
        }
    }
    return -1;
}

static inline void BenchNet_WriteStreamIds(FILE* f, size_t streams, int profile)
{
    size_t i;
    (void)fprintf(f, "# stream_pdu_ids=");
    for (i = 0U; i < streams; i++) {
        (void)fprintf(f, "%s%u", (i == 0U) ? "" : ",", (unsigned)BenchNet_PduOfStream(profile, (uint32)i));
    }
    (void)fprintf(f, "\n# stream_header_ids=");
    for (i = 0U; i < streams; i++) {
        (void)fprintf(f, "%s0x%02x", (i == 0U) ? "" : ",", (unsigned)BenchNet_HeaderOfStream(profile, (uint32)i));
    }
    (void)fprintf(f, "\n");
    if (profile == BENCH_NET_PROFILE_BOTH) {    /* the one profile whose streams differ in kind */
        (void)fprintf(f, "# stream_profiles=mldsa65,mac\n");
    }
}
#define BENCH_NET_KEY_FILE          "mldsa_secoc.key"
#define BENCH_NET_PUB_FILE          "mldsa_secoc.pub"
#define BENCH_NET_PEER_PUB_FILE     "mldsa_peer0.pub"

typedef struct {
    const char* keyDir;     /* mldsa_secoc.key, mldsa_secoc.pub; receiver also mldsa_peer0.pub */
    uint8       peerIp[4];  /* transmitter: address of the receiver (or of the proxy in front of it) */
    uint16      port;       /* transmitter: remote TCP port; receiver: local TCP port */
    int         handshake;  /* 1: PQC-SecOC-HS-v1 with the peer before any Secured I-PDU, as the gateway;
                               0: no handshake component, session-less PDUs (development) */
} BenchNet_ConfigType;

/* Written by the libc wraps in bench_net.c around TcpIp.c's own socket calls. */
extern int      BenchNet_ConnFd;        /* the TCP connection, -1 until connect() / accept() */
extern uint64_t BenchNet_RecvCalls;     /* recv() calls that returned data */
extern int      BenchNet_PeerClosed;    /* recv() returned 0 */
extern int      BenchNet_TcpNoDelay;    /* TCP_NODELAY of the connection as the program read it back; -1: not read */
extern unsigned long BenchNet_Connections;  /* connect() calls of the stack plus accepted connections */

/* Csm identity from keyDir, SecOC, TcpIp, SoAd with the address and port of cfg, routing group on.
 * Returns 0, or a negative step number after printing what failed. */
int BenchNet_Init(const BenchNet_ConfigType* cfg);

/* Pin the calling thread to one CPU and, if priority > 0, switch it to SCHED_FIFO; both are read
 * back. Returns 0 only if the thread really runs that way. */
int BenchNet_PinAndSchedule(int cpu, int fifoPriority);

/* The handshake as the harness sees it (the component itself does no output).
 * BenchNet_HsPoll: collect the attempt records the component has finished since the last call;
 *   1 when one of them ended ok, -1 when one ended otherwise, 0 when there was none. Once per cycle.
 * BenchNet_HsCycle: the data-path main functions in the gateway's order, one tick apart, until an
 *   attempt has ended (1 ok, -1 otherwise) or the instant untilNs is reached (0).
 * BenchNet_HsWait: the transmitter's wait before its first release: BenchNet_HsCycle until the
 *   handshake it asked for has ended. 0: session established; -1: an attempt failed; -2: nothing
 *   within timeoutNs.
 * BenchNet_HsWriteKeys: the header lines handshake=, session_id=, hs_installs= (the proof that two
 *   ends talk in the same session is the same session_id in both files), established_ns (the instant
 *   the first attempt that ended ok was collected), and hs_records_in_run with their instants: the
 *   attempt records collected at or after runStartNs, the start of the measured interval. A timing
 *   run has none: the handshake lies before the interval, and a later one must be visible.
 * BenchNet_HsWriteFile: handshake.csv of DATA_SCHEMA.md with this process's attempts, with the header
 *   and footer every harness file has (affinity, governor, frequency, mlockall, CPU time), the
 *   component's timer values, and moreKeys: further "# key=value" lines of the caller, among them
 *   pdu_stream (did a PDU stream run in this process while the handshakes took place). */
int  BenchNet_HsPoll(void);
int  BenchNet_HsCycle(uint64_t tickNs, uint64_t untilNs);
int  BenchNet_HsWait(uint64_t tickNs, uint64_t timeoutNs);
void BenchNet_HsWriteKeys(FILE* f, int handshake, uint64_t runStartNs);
int  BenchNet_HsWriteFile(const char* path, const char* tool, const char* mlockStatus, const char* mainFunction,
                          uint64_t mfPeriodUs, uint64_t startNs, const char* moreKeys);

/* Parse "a.b.c.d:port" (or just "port" when ip is NULL). Returns 0 on success. */
int BenchNet_ParseEndpoint(const char* text, uint8* ip, uint16* port);

/* Once-per-second sampler for throughput.csv (DATA_SCHEMA.md). It runs in its own thread, kept off
 * the measured CPU, stores its rows in memory and writes them when asked. */
typedef struct {
    const char*                  iface;         /* interface whose counters are sampled, e.g. eth0 */
    int                          cpu;           /* the pinned CPU whose /proc/stat line is sampled */
    uint64_t                     firstNs;       /* CLOCK_MONOTONIC instant of the first sample */
    unsigned                     samples;       /* number of samples, one second apart */
    const volatile unsigned long* done;         /* cumulative PDUs sent (Tx) or delivered (Rx) */
    const volatile unsigned long* drops;        /* cumulative PDUs not enqueued (Tx) or rejected (Rx) */
    int                          sendQueue;     /* 1: sample SIOCOUTQ of the connection (Tx host) */
    const volatile sig_atomic_t* stop;          /* the harness's "asked to end" flag: no sample after it is set */
} BenchNet_SamplerConfigType;

int  BenchNet_SamplerStart(const BenchNet_SamplerConfigType* cfg);
/* With cfg->firstNs == 0 the thread exists and waits: BenchNet_SamplerBegin() gives it the instant of the
 * first sample (one store, safe in a measured loop); BenchNet_SamplerCancel() ends a sampler that never began. */
void BenchNet_SamplerBegin(uint64_t firstNs);
void BenchNet_SamplerCancel(void);
void BenchNet_SamplerJoin(void);
/* Rows only; the caller writes the comment block and the column header. */
void BenchNet_SamplerWrite(FILE* f, const char* host, double offeredPps);

#endif /* BENCH_NET_H */
