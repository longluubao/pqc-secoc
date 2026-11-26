/* bench_tcpinfo.h: what the kernel says about the harness's own TCP connection (getsockopt TCP_INFO
 * and TCP_NODELAY). A value of -1 means the kernel, or the kernel header of the board that built
 * this binary, did not give the field. */
#ifndef BENCH_TCPINFO_H
#define BENCH_TCPINFO_H

#include <stdio.h>

typedef struct {
    long totalRetrans;      /* cumulative: segments retransmitted */
    long dsackDups;         /* cumulative: duplicate-SACK reports received (the peer had the segment already) */
    long totalRto;          /* cumulative: retransmission time-outs (kernel header 6.7 or later) */
    long lost;              /* now: segments marked lost */
    long retrans;           /* now: segments retransmitted and not yet acknowledged */
    long rtoUs;             /* now: retransmission time-out */
    long rttUs;             /* now: smoothed round-trip time */
    int  noDelay;           /* TCP_NODELAY read back: 0 or 1 */
} BenchTcpInfo_Type;

/* All fields -1 when fd is not a connected TCP socket. */
void BenchTcpInfo_Read(int fd, BenchTcpInfo_Type* out);

/* Footer lines of the Tx file: every counter at the first release and at the end, and the difference
 * of the cumulative ones (-1 if either end is unknown). connects*: connect() calls of the stack. */
void BenchTcpInfo_WriteFooter(FILE* f, const BenchTcpInfo_Type* atFirstRelease, const BenchTcpInfo_Type* atEnd,
                              unsigned long connectsAtFirstRelease, unsigned long connectsAtEnd);

#endif /* BENCH_TCPINFO_H */
