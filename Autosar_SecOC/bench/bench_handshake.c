/* bench_handshake: n complete handshakes PQC-SecOC-HS-v1, one after the other, as the initiator,
 * through the real path (handshake component -> Csm -> liboqs, SoAd -> TcpIp), against a responder
 * on the other board: bench_net_rx (its --handshake-out gives the responder's rows) or the gateway.
 *
 * Every handshake uses a fresh ML-KEM key pair (the component makes one per attempt). The process
 * initialises the BSW as bench_net_tx does, pins itself, and runs the data-path main functions in
 * the gateway's cycle order, 1 ms apart unless --mf-period-us says otherwise. The first handshake
 * is the one the start-up asks for; each further one is asked for --gap-ms after the start of the
 * one before (default: the shipped T_min plus 50 ms; the responder drops an M1 that comes earlier
 * than T_min after the last one it accepted; the timers are the tree's, the campaign measures with
 * them, and the gap is in the header). No PDU stream runs meanwhile (pdu_stream=none). It stops at
 * the first attempt that does not end ok: exit 5, the rows so far are written.
 *
 * Output: handshake.csv of DATA_SCHEMA.md with the initiator's rows (the component's own records:
 * stage times, total from the start of the ML-KEM key generation to the installed keys, bytes).
 *
 * Usage: bench_handshake --peer A.B.C.D:PORT --key-dir DIR --cpu N --n COUNT --handshake-out FILE
 *                        [--gap-ms G] [--hs-timeout-ms T] [--mf-period-us T]
 *                        [--sched other|fifo] [--priority P] [--allow-unlocked]
 * (--mainfunction, --partition, --partitions and --profile are accepted and ignored, so that the
 * driver can start it in place of bench_net_tx.)
 */
#define _GNU_SOURCE
#include "bench_net.h"
#include "bench_tcpinfo.h"

#include <getopt.h>
#include <stdlib.h>

#include "PqcHs.h"
#include "PqcHs_Cfg.h"

int main(int argc, char** argv)
{
    static const struct option longOpts[] = {
        { "peer", required_argument, NULL, 'p' },         { "key-dir", required_argument, NULL, 'k' },
        { "cpu", required_argument, NULL, 'c' },          { "n", required_argument, NULL, 'n' },
        { "handshake-out", required_argument, NULL, 'o' }, { "gap-ms", required_argument, NULL, 'g' },
        { "hs-timeout-ms", required_argument, NULL, 'W' }, { "mf-period-us", required_argument, NULL, 'T' },
        { "sched", required_argument, NULL, 's' },        { "priority", required_argument, NULL, 'y' },
        { "allow-unlocked", no_argument, NULL, 'u' },     { "mainfunction", required_argument, NULL, 'M' },
        { "partition", required_argument, NULL, 'I' },    { "partitions", required_argument, NULL, 'N' },
        { "profile", required_argument, NULL, 'f' },
        { NULL, 0, NULL, 0 },
    };
    BenchNet_ConfigType net = { NULL, { 0U, 0U, 0U, 0U }, 0U, 1 };
    char moreKeys[128];
    const char* outPath = NULL;
    const char* sched = "other";
    const char* mlockStatus;
    uint64_t tickNs = 1000000ULL;
    uint64_t timeoutNs = 15000000000ULL;
    uint64_t gapNs = 0U;
    uint64_t lastStart;
    uint64_t startNs = bench_now_ns();
    unsigned long n = 0UL;
    unsigned long done = 0UL;
    int cpu = -1;
    int priority = 80;
    int allowUnlocked = 0;
    int peerGiven = 0;
    int rc = 0;
    int c;

    while ((c = getopt_long(argc, argv, "", longOpts, NULL)) != -1) {
        switch (c) {
        case 'p': peerGiven = (BenchNet_ParseEndpoint(optarg, net.peerIp, &net.port) == 0); break;
        case 'k': net.keyDir = optarg; break;
        case 'c': cpu = atoi(optarg); break;
        case 'n': n = strtoul(optarg, NULL, 10); break;
        case 'o': outPath = optarg; break;
        case 'g': gapNs = strtoull(optarg, NULL, 10) * 1000000ULL; break;
        case 'W': timeoutNs = strtoull(optarg, NULL, 10) * 1000000ULL; break;
        case 'T': tickNs = strtoull(optarg, NULL, 10) * 1000ULL; break;
        case 's': sched = optarg; break;
        case 'y': priority = atoi(optarg); break;
        case 'u': allowUnlocked = 1; break;
        case 'M': case 'I': case 'N': case 'f': break;
        default: n = 0UL; outPath = NULL; break;     /* unknown option: the usage text below */
        }
    }
    if ((peerGiven == 0) || (net.keyDir == NULL) || (cpu < 0) || (n == 0UL) || (outPath == NULL) || (tickNs == 0U) ||
        (optind != argc) || ((strcmp(sched, "other") != 0) && (strcmp(sched, "fifo") != 0))) {
        (void)fprintf(stderr, "usage: bench_handshake --peer A.B.C.D:PORT --key-dir DIR --cpu N --n COUNT --handshake-out FILE\n"
                              "                       [--gap-ms G] [--hs-timeout-ms T] [--mf-period-us T] [--sched other|fifo]\n"
                              "                       [--priority P] [--allow-unlocked]\n");
        return 2;
    }

    if (gapNs == 0U) {
        gapNs = ((uint64_t)PqcHs_Config.PqcHsTimers.PqcHsTMinMs + 50ULL) * 1000000ULL;
    }
    lastStart = bench_now_ns();
    if (BenchNet_Init(&net) != 0) {         /* asks for the first handshake */
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

    while (done < n) {
        if (done > 0UL) {
            /* the gap: keep the cycle running (timers, the connection), then ask again */
            if (BenchNet_HsCycle(tickNs, lastStart + gapNs) != 0) {
                rc = 5;         /* a record nobody asked for: an attempt of the component's own, or a failure */
                break;
            }
            lastStart = bench_now_ns();
            (void)PqcHs_Initiate(0U);
        }
        if ((BenchNet_HsCycle(tickNs, bench_now_ns() + timeoutNs) != 1) || (PqcHs_IsEstablished(0U) != TRUE)) {
            rc = 5;
            break;
        }
        done++;
        if (done == 1UL) {      /* TCP_NODELAY as the stack left it, read in the gap after the first handshake */
            BenchTcpInfo_Type tcp;
            BenchTcpInfo_Read(BenchNet_ConnFd, &tcp);
            BenchNet_TcpNoDelay = tcp.noDelay;
            if (tcp.noDelay != 1) {     /* CAMPAIGN.md: valid only with TCP_NODELAY = 1; stop at once */
                (void)fprintf(stderr, "TCP_NODELAY of the connection reads back %d, not 1: stopping\n", tcp.noDelay);
                rc = 6;
                break;
            }
        }
    }

    (void)snprintf(moreKeys, sizeof(moreKeys), "# pdu_stream=none\n# n=%lu\n# gap_ms=%" PRIu64 "\n", n, (uint64_t)(gapNs / 1000000ULL));
    if (BenchNet_HsWriteFile(outPath, "bench_handshake", mlockStatus, "cyclic", (uint64_t)(tickNs / 1000U), startNs, moreKeys) != 0) {
        (void)fprintf(stderr, "cannot write %s: %s\n", outPath, strerror(errno));
        return 1;
    }
    (void)printf("handshakes=%lu of %lu gap_ms=%" PRIu64 " mlockall=%s\n", done, n, (uint64_t)(gapNs / 1000000ULL), mlockStatus);
    if (rc != 0) {
        (void)fprintf(stderr, "handshake %lu did not end ok: see the last rows of %s\n", done, outPath);
    }
    return rc;
}
