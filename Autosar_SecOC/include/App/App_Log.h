/********************************************************************************************************/
/*  File:   include/App/App_Log.h                                                                         */
/*  Brief:  Run parameters (environment) and timestamps shared by App_Tx and App_Rx.                      */
/*                                                                                                        */
/*  SECOC_APP_CSV            path of the per-PDU CSV log (not set: no CSV)                                */
/*  SECOC_APP_PAYLOAD_CSV    Rx: path of the delivered-payload log, stream,seq,payload_hex (not set: none)*/
/*  SECOC_APP_COUNT          Tx: PDUs to send on each stream, Rx: outcomes to log in total, then the      */
/*                           process exits (0: no limit)                                                  */
/*  SECOC_APP_STREAMS        Tx: number of signature streams to send on, 1..8 (default 1). Stream i is    */
/*                           SecOC PDU SECOC_PDUID_SIG(i), PDU header ID 0x10 + i on the wire. The        */
/*                           receiver takes all eight.                                                    */
/*  SECOC_APP_PERIOD_CYCLES  Tx: BSW cycles between two PDUs (default APP_TX_PERIOD_CYCLES)               */
/*  SECOC_APP_PROFILE        variant of the run, on both sides: mldsa65 (default; the signature streams), */
/*                           mac (stream i is SecOC PDU SECOC_PDUID_MAC(i), PDU header ID 0x20 + i; one   */
/*                           MAC stream is configured), or both (stream 0 = signature stream 0, stream 1  */
/*                           = MAC stream 0, on the one connection). The logs are written for the PDUs    */
/*                           of that variant only.                                                        */
/*                           The MAC keys come from the handshake and from nowhere else: the gateway  */
/*                           reads no key file (a static key next to the session keys would be a      */
/*                           way around the session binding).                                         */
/*  SECOC_APP_IDLE_EXIT_MS   Rx: exit when nothing arrived for this long after the first PDU (0: never)   */
/*  SECOC_APP_REKEY_AT       Tx: ask the handshake component for a new handshake once stream 0 has had    */
/*                           this many PDUs confirmed (0: never)                                          */
/*  SECOC_APP_HS_CSV         both: path of handshake.csv (App_Hs.h)                                        */
/********************************************************************************************************/
#ifndef INCLUDE_APP_APP_LOG_H_
#define INCLUDE_APP_APP_LOG_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "Std_Types.h"
#include "SoAd/SoAd.h"
#include "SoAd/SoAd_PduIds.h"

/* MAC streams with a SecOC configuration row (SecOC_Lcfg.c) */
#define APP_MAC_STREAMS     (1U)

#ifndef SECOC_GIT_COMMIT
#define SECOC_GIT_COMMIT "unknown"
#endif

/* CLOCK_MONOTONIC of this host in nanoseconds (DATA_SCHEMA.md) */
static inline uint64 App_NowNs(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64)ts.tv_sec * 1000000000ULL) + (uint64)ts.tv_nsec;
}

static inline uint32 App_EnvU32(const char* Name, uint32 Default)
{
    const char* value = getenv(Name);
    return (value != NULL) ? (uint32)strtoul(value, NULL, 10) : Default;
}

#define APP_PROFILE_MLDSA65     (0)
#define APP_PROFILE_MAC         (1)
#define APP_PROFILE_BOTH        (2)

/* The variant of this run (SECOC_APP_PROFILE) */
static inline int App_Profile(void)
{
    /* read once: this is asked for every PDU, inside the intervals the logs time */
    static int profile = -1;

    if (profile < 0)
    {
        const char* value = getenv("SECOC_APP_PROFILE");
        profile = ((value != NULL) && (strcmp(value, "mac") == 0)) ? APP_PROFILE_MAC :
                  (((value != NULL) && (strcmp(value, "both") == 0)) ? APP_PROFILE_BOTH : APP_PROFILE_MLDSA65);
    }
    return profile;
}

static inline const char* App_ProfileName(void)
{
    static const char* const names[3] = { "mldsa65", "mac", "both" };
    return names[App_Profile()];
}

static inline uint32 App_MaxStreams(void)
{
    return (App_Profile() == APP_PROFILE_MAC) ? APP_MAC_STREAMS :
           ((App_Profile() == APP_PROFILE_BOTH) ? 2U : SECOC_PDUID_SIG_COUNT);
}

/* SecOC PDU ID (= Data ID) of stream i of the run's variant */
static inline uint32 App_PduOfStream(uint32 Stream)
{
    if (App_Profile() == APP_PROFILE_BOTH)
    {
        return (Stream == 0U) ? SECOC_PDUID_SIG(0U) : SECOC_PDUID_MAC(0U);
    }
    return (App_Profile() == APP_PROFILE_MAC) ? SECOC_PDUID_MAC(Stream) : SECOC_PDUID_SIG(Stream);
}

/* Stream of a SecOC PDU ID or Data ID in the run's variant; -1 if it is none of them. The "stream"
 * column of the logs is this index. */
static inline int App_StreamOfPdu(uint32 PduId)
{
    uint32 i;
    for (i = 0U; i < App_MaxStreams(); i++)
    {
        if (App_PduOfStream(i) == PduId)
        {
            return (int)i;
        }
    }
    return -1;
}

/* Evidence for every TCP connection of the gateway's socket connection: TCP_NODELAY as the connected
 * socket reports it (getsockopt, not the configured value), one comment line "# tcp_nodelay=<0|1>" in each
 * of the given logs. Called from an application's main function every cycle; it writes when it first sees
 * a connection, and again for each connection that replaces it. The logs' own header is written at
 * start-up, before any connection exists, so these lines stand behind the column line. */
static inline void App_LogTcpNoDelay(FILE* Csv, FILE* SecondCsv, uint32* SeenPtr, const char* Who)
{
    uint32 connections = 0U;
    uint8 noDelay = 0U;

    if ((SoAd_GetSoConTcpInfo(0U, &connections, &noDelay) == E_OK) && (connections != *SeenPtr))
    {
        *SeenPtr = connections;
        if (Csv != NULL)
        {
            (void)fprintf(Csv, "# tcp_nodelay=%u\n", (unsigned)noDelay);
        }
        if (SecondCsv != NULL)
        {
            (void)fprintf(SecondCsv, "# tcp_nodelay=%u\n", (unsigned)noDelay);
        }
        if (Who != NULL)
        {
            (void)printf("[%s] TCP connection %u: tcp_nodelay=%u (read back from the socket)\n",
                         Who, (unsigned)connections, (unsigned)noDelay);
        }
    }
}

#endif /* INCLUDE_APP_APP_LOG_H_ */
