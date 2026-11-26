/********************************************************************************************************/
/*  File:   source/App/App_Tx.c                                                                           */
/*  Brief:  Cyclic application driver that originates Authentic I-PDUs on 1 to 8 signature streams       */
/*          (SecOC PDU SECOC_PDUID_SIG(i), Ethernet/SoAd-TP), SECOC_APP_STREAMS of them.                  */
/*          AUTOSAR-equivalent of an SWC + Rte_Write + Com_SendSignal in a non-RTE build.                 */
/*          One CSV row per PDU, written when its transmission is confirmed (app_tx.csv):                 */
/*          stream,seq,submit_ns,start_ns,auth_done_ns,send_done_ns                                       */
/*          This is functional evidence, NOT the periodic_tx.csv of DATA_SCHEMA.md: the loop is closed    */
/*          (a PDU is submitted only after the previous one was confirmed, so submit_ns is not a nominal  */
/*          release instant and no deadline or throughput figure may be computed from it), an            */
/*          unconfirmed PDU has no row, and auth_done_ns is not instrumented (0; the file says so with    */
/*          "# not_recorded=auth_done_ns").                                                               */
/********************************************************************************************************/

#include "App/App_Tx.h"
#include "App/App_Log.h"
#include "SecOC/SecOC.h"
#include "SecOC/SecOC_Cfg.h"
#include "SecOC/SecOC_Debug.h"
#include "ComStack_Types.h"
#include "FVM.h"
#include "PqcHs/PqcHs.h"

#include <string.h>
#include <stdio.h>
#include <unistd.h>

#if (SECOC_ROLE_SENDER == TRUE)

#define APP_TX_MAX_STREAMS   (SECOC_PDUID_SIG_COUNT)

/* One signature stream: its own SecOC PDU, sequence numbers and closed loop. */
typedef struct
{
    boolean Pending;        /* submitted, not confirmed yet */
    uint32  Seq;            /* sequence number of the PDU in flight */
    uint32  Released;       /* PDUs submitted for the first time */
    uint32  Confirmed;
    uint32  CycleCount;     /* cycles since the last submission */
    uint32  PendingCycles;
    uint64  SubmitNs;
    uint64  StartNs;
} App_Tx_StreamType;

static boolean App_Tx_Initialised = FALSE;
static uint32  App_Tx_TcpSeen     = 0U;
static boolean App_Tx_Enabled     = TRUE;
static uint32  App_Tx_TxRequestCount = 0U;
static App_Tx_StreamType App_Tx_Stream[APP_TX_MAX_STREAMS];
static uint32  App_Tx_Streams      = 1U;

static FILE*   App_Tx_Csv          = NULL;
static uint32  App_Tx_Limit        = 0U;
static uint32  App_Tx_Period       = APP_TX_PERIOD_CYCLES;
static uint32  App_Tx_WarmupCycles = 0U;
static uint32  App_Tx_Retries      = 0U;
static uint32  App_Tx_RekeyAt      = 0U;      /* SECOC_APP_REKEY_AT: a second handshake after this many PDUs of stream 0 */
static boolean App_Tx_RekeyDue     = FALSE;

static void App_Tx_Submit(uint32 Stream)
{
    App_Tx_StreamType* st = &App_Tx_Stream[Stream];
    uint8 payload[APP_TX_PAYLOAD_LENGTH];
    PduInfoType PduInfo;
    Std_ReturnType Result;

    /* stream in the first byte, sequence number big-endian in the last four */
    (void)memset(payload, 0, APP_TX_PAYLOAD_LENGTH);
    payload[0] = (uint8)Stream;
    payload[4] = (uint8)(st->Seq >> 24U);
    payload[5] = (uint8)(st->Seq >> 16U);
    payload[6] = (uint8)(st->Seq >> 8U);
    payload[7] = (uint8)st->Seq;

    PduInfo.SduDataPtr  = payload;
    PduInfo.MetaDataPtr = NULL;
    PduInfo.SduLength   = (PduLengthType)APP_TX_PAYLOAD_LENGTH;

    st->StartNs = App_NowNs();
    st->PendingCycles = 0U;
    st->CycleCount = 0U;
    Result = SecOC_TpTransmit((PduIdType)App_PduOfStream(Stream), &PduInfo);

    if (Result == E_OK) {
        App_Tx_TxRequestCount++;
        st->Pending = TRUE;
    } else {
        (void)printf("[App_Tx] WARN: SecOC_TpTransmit returned %d for stream %u seq=%u\n",
                     (int)Result, (unsigned)Stream, (unsigned)st->Seq);
    }
}

void App_Tx_Init(void)
{
    const char* csvPath = getenv("SECOC_APP_CSV");

    App_Tx_Initialised    = TRUE;
    App_Tx_Enabled        = TRUE;
    App_Tx_TxRequestCount = 0U;
    (void)memset(App_Tx_Stream, 0, sizeof(App_Tx_Stream));

    App_Tx_Limit   = App_EnvU32("SECOC_APP_COUNT", 0U);
    App_Tx_Period  = App_EnvU32("SECOC_APP_PERIOD_CYCLES", APP_TX_PERIOD_CYCLES);
    App_Tx_Streams = App_EnvU32("SECOC_APP_STREAMS", 1U);
    App_Tx_RekeyAt = App_EnvU32("SECOC_APP_REKEY_AT", 0U);
    App_Tx_RekeyDue = FALSE;
    if ((App_Tx_Streams == 0U) || (App_Tx_Streams > App_MaxStreams()))
    {
        (void)printf("[App_Tx] WARN: SECOC_APP_STREAMS=%u is not 1..%u, using 1\n", (unsigned)App_Tx_Streams, (unsigned)App_MaxStreams());
        App_Tx_Streams = 1U;
    }
    if (csvPath != NULL)
    {
        App_Tx_Csv = fopen(csvPath, "w");
        if (App_Tx_Csv == NULL)
        {
            (void)printf("[App_Tx] WARN: cannot open %s\n", csvPath);
        }
        else
        {
            char host[64] = "unknown";
            (void)gethostname(host, sizeof(host) - 1U);

            /* line buffered: rows survive a kill */
            (void)setvbuf(App_Tx_Csv, NULL, _IOLBF, 0);
            (void)fprintf(App_Tx_Csv, "# loop=closed\n# commit=%s\n# host=%s\n# role=tx\n# profile=%s\n# streams=%u\n# payload_len=%u\n"
                          "# period_cycles=%u\n# count=%u\n# not_recorded=auth_done_ns\n",
                          SECOC_GIT_COMMIT, host, App_ProfileName(),
                          (unsigned)App_Tx_Streams, (unsigned)APP_TX_PAYLOAD_LENGTH,
                          (unsigned)App_Tx_Period, (unsigned)App_Tx_Limit);
            (void)fprintf(App_Tx_Csv, "stream,seq,submit_ns,start_ns,auth_done_ns,send_done_ns\n");
        }
    }

    (void)printf("[App_Tx] Initialised. Role=SENDER, Streams=%u, Period=%u cycles, PayloadLen=%u, Count=%u per stream, Csv=%s\n",
                 (unsigned)App_Tx_Streams,
                 (unsigned)App_Tx_Period,
                 (unsigned)APP_TX_PAYLOAD_LENGTH,
                 (unsigned)App_Tx_Limit,
                 (csvPath != NULL) ? csvPath : "(none)");
}

void App_Tx_DeInit(void)
{
    App_Tx_Initialised = FALSE;
    App_Tx_Enabled     = FALSE;
}

void App_Tx_Enable(boolean Enable)
{
    App_Tx_Enabled = Enable;
}

uint32 App_Tx_GetTxRequestCount(void)
{
    return App_Tx_TxRequestCount;
}

void App_Tx_MainFunction(void)
{
    uint32 s;
    uint32 total = 0U;
    boolean allDone = TRUE;

    if ((App_Tx_Initialised == FALSE) || (App_Tx_Enabled == FALSE)) {
        return;
    }

    App_LogTcpNoDelay(App_Tx_Csv, NULL, &App_Tx_TcpSeen, NULL);

    if (App_Tx_WarmupCycles < APP_TX_WARMUP_CYCLES) {
        App_Tx_WarmupCycles++;
        return;
    }

    /* no session with the peer yet: nothing is released (held here, above SecOC, so that no PDU is
     * abandoned by SecOC's build attempts) */
    if (FVM_NoSession() == TRUE) {
        return;
    }

    /* "initiate handshake now" of the tests: asked for here, not inside the confirmation call-back */
    if (App_Tx_RekeyDue == TRUE) {
        App_Tx_RekeyDue = FALSE;
        (void)printf("[App_Tx] rekey requested after %u PDUs of stream 0: %s\n", (unsigned)App_Tx_RekeyAt,
                     (PqcHs_Initiate(0U) == E_OK) ? "accepted" : "refused");
    }

    for (s = 0U; s < App_Tx_Streams; s++) {
        App_Tx_StreamType* st = &App_Tx_Stream[s];

        st->CycleCount++;
        total += st->Confirmed;

        /* SecOC holds one Authentic I-PDU per PDU id: the next one of a stream is submitted only
         * after the confirmation of the previous one, otherwise it would be overwritten unsent. */
        if (st->Pending == TRUE) {
            allDone = FALSE;
            st->PendingCycles++;
            if (st->PendingCycles >= APP_TX_CONFIRM_TIMEOUT_CYCLES) {
                App_Tx_Retries++;
                (void)printf("[App_Tx] WARN: stream %u seq=%u not confirmed after %u cycles, submitted again\n",
                             (unsigned)s, (unsigned)st->Seq, (unsigned)APP_TX_CONFIRM_TIMEOUT_CYCLES);
                App_Tx_Submit(s);
            }
        } else if ((App_Tx_Limit > 0U) && (st->Confirmed >= App_Tx_Limit)) {
            /* this stream is complete */
        } else {
            allDone = FALSE;
            if (st->CycleCount >= App_Tx_Period) {
                st->Seq = st->Released;     /* seq starts at 0 */
                st->Released++;
                st->SubmitNs = App_NowNs();
                App_Tx_Submit(s);
            }
        }
    }

    if ((App_Tx_Limit > 0U) && (allDone == TRUE)) {
        (void)printf("[App_Tx] done: sent=%u retries=%u streams=%u\n", (unsigned)total, (unsigned)App_Tx_Retries, (unsigned)App_Tx_Streams);
        if (App_Tx_Csv != NULL) {
            (void)fclose(App_Tx_Csv);
        }
        exit(0);
    }
}

void App_Tx_TxConfirmation(PduIdType TxPduId, Std_ReturnType Result)
{
    int stream = App_StreamOfPdu((uint32)TxPduId);
    App_Tx_StreamType* st;

    if ((stream < 0) || ((uint32)stream >= App_Tx_Streams) || (App_Tx_Stream[stream].Pending == FALSE)) {
        return;
    }
    st = &App_Tx_Stream[stream];

    if (Result != E_OK) {
        /* stays pending; the timeout in App_Tx_MainFunction submits it again */
        (void)printf("[App_Tx] WARN: transmission of stream %d seq=%u failed\n", stream, (unsigned)st->Seq);
        return;
    }

    st->Pending = FALSE;
    st->Confirmed++;
    if ((stream == 0) && (App_Tx_RekeyAt > 0U) && (st->Confirmed == App_Tx_RekeyAt)) {
        App_Tx_RekeyDue = TRUE;
    }
    if (App_Tx_Csv != NULL) {
        (void)fprintf(App_Tx_Csv, "%d,%lu,%llu,%llu,0,%llu\n", stream,
                      (unsigned long)st->Seq, (unsigned long long)st->SubmitNs,
                      (unsigned long long)st->StartNs, (unsigned long long)App_NowNs());
    }
}

#else  /* SECOC_ROLE_SENDER == FALSE — Rx-only build */

void   App_Tx_Init(void)              { }
void   App_Tx_DeInit(void)            { }
void   App_Tx_MainFunction(void)      { }
void   App_Tx_Enable(boolean Enable)  { (void)Enable; }
uint32 App_Tx_GetTxRequestCount(void) { return 0U; }
void   App_Tx_TxConfirmation(PduIdType TxPduId, Std_ReturnType Result) { (void)TxPduId; (void)Result; }

#endif /* SECOC_ROLE_SENDER */
