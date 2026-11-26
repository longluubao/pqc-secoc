/* bench_tcpinfo.c: see bench_tcpinfo.h. This file alone includes <linux/tcp.h>: glibc's
 * <netinet/tcp.h> has a shorter struct tcp_info and cannot be included next to it. */
#include "bench_tcpinfo.h"

#include <stddef.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <linux/tcp.h>

/* the field is used only when the kernel filled it: it answers with the length it wrote */
#define FIELD(info, len, member) \
    (((size_t)(len) >= (offsetof(struct tcp_info, member) + sizeof((info).member))) ? (long)(info).member : -1L)

void BenchTcpInfo_Read(int fd, BenchTcpInfo_Type* out)
{
    struct tcp_info info;
    socklen_t len = sizeof(info);
    int noDelay = 0;
    socklen_t optLen = sizeof(noDelay);

    out->totalRetrans = out->dsackDups = out->totalRto = out->lost = out->retrans = out->rtoUs = out->rttUs = -1L;
    out->noDelay = -1;
    if (fd < 0) {
        return;
    }
    (void)memset(&info, 0, sizeof(info));
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) == 0) {
        out->totalRetrans = FIELD(info, len, tcpi_total_retrans);
        out->dsackDups = FIELD(info, len, tcpi_dsack_dups);
#ifdef BENCH_HAVE_TCPI_TOTAL_RTO
        out->totalRto = FIELD(info, len, tcpi_total_rto);
#endif
        out->lost = FIELD(info, len, tcpi_lost);
        out->retrans = FIELD(info, len, tcpi_retrans);
        out->rtoUs = FIELD(info, len, tcpi_rto);
        out->rttUs = FIELD(info, len, tcpi_rtt);
    }
    if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &noDelay, &optLen) == 0) {
        out->noDelay = (noDelay != 0) ? 1 : 0;
    }
}

static long in_window(long atFirstRelease, long atEnd)
{
    return ((atFirstRelease < 0L) || (atEnd < 0L)) ? -1L : (atEnd - atFirstRelease);
}

void BenchTcpInfo_WriteFooter(FILE* f, const BenchTcpInfo_Type* a, const BenchTcpInfo_Type* b,
                              unsigned long connectsAtFirstRelease, unsigned long connectsAtEnd)
{
    (void)fprintf(f, "# tcp_total_retrans_at_first_release=%ld\n# tcp_total_retrans_at_end=%ld\n# tcp_total_retrans_in_window=%ld\n",
                  a->totalRetrans, b->totalRetrans, in_window(a->totalRetrans, b->totalRetrans));
    (void)fprintf(f, "# tcp_dsack_dups_at_first_release=%ld\n# tcp_dsack_dups_at_end=%ld\n# tcp_dsack_dups_in_window=%ld\n",
                  a->dsackDups, b->dsackDups, in_window(a->dsackDups, b->dsackDups));
    (void)fprintf(f, "# tcp_total_rto_at_first_release=%ld\n# tcp_total_rto_at_end=%ld\n# tcp_total_rto_in_window=%ld\n",
                  a->totalRto, b->totalRto, in_window(a->totalRto, b->totalRto));
    (void)fprintf(f, "# tcp_lost_at_first_release=%ld\n# tcp_lost_at_end=%ld\n# tcp_retrans_at_first_release=%ld\n# tcp_retrans_at_end=%ld\n",
                  a->lost, b->lost, a->retrans, b->retrans);
    (void)fprintf(f, "# tcp_rto_us_at_first_release=%ld\n# tcp_rto_us_at_end=%ld\n# tcp_rtt_us_at_first_release=%ld\n# tcp_rtt_us_at_end=%ld\n",
                  a->rtoUs, b->rtoUs, a->rttUs, b->rttUs);
    (void)fprintf(f, "# tcp_connections_at_first_release=%lu\n# tcp_connections_at_end=%lu\n", connectsAtFirstRelease, connectsAtEnd);
}
