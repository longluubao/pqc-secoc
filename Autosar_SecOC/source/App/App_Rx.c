/********************************************************************************************************/
/*  File:   source/App/App_Rx.c                                                                           */
/*  Brief:  Receiver application for the SecOC PQC Ethernet path (RxPduId=2).                             */
/*          AUTOSAR-equivalent of an SWC with a Com Rx notification and the SecOC VerificationStatus      */
/*          service in a non-RTE build. One CSV row per outcome (app_rx.csv; the columns of the           */
/*          periodic_rx.csv of DATA_SCHEMA.md, but rx_done_ns is not instrumented):                       */
/*          stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result                                        */
/*            ok             verified and delivered (seq decoded from the authentic payload)              */
/*            freshness_fail rejected by SecOC, freshness                                                 */
/*            auth_fail      rejected by SecOC, signature or malformed Secured I-PDU                      */
/*            framing_fail   discarded by SoAd before SecOC (header ID, length, routing group)            */
/*          framing_fail rows have stream -1 and seq -1 as the schema says. freshness_fail and auth_fail  */
/*          rows carry the stream, and seq -1 (this file's choice: nothing in a rejected PDU is           */
/*          authentic). rx_done_ns is not instrumented yet ("# not_recorded=rx_done_ns" in the file): 0,  */
/*          except for framing_fail where it is the instant this application saw the drop.                */
/*          Delivered payloads go to a second file: stream,seq,payload_hex.                               */
/********************************************************************************************************/

#include "App/App_Rx.h"
#include "App/App_Log.h"
#include "SecOC/SecOC.h"
#include "SecOC/SecOC_Cfg.h"
#include "SoAd/SoAd.h"

#include <stdio.h>

#if (SECOC_ROLE_RECEIVER == TRUE)

static FILE*  App_Rx_Csv            = NULL;
static FILE*  App_Rx_PayloadCsv     = NULL;
static uint32 App_Rx_Limit          = 0U;
static uint32 App_Rx_IdleExitMs     = 0U;
static uint32 App_Rx_Ok             = 0U;
static uint32 App_Rx_VerifiedOk     = 0U;
static uint32 App_Rx_FreshnessFail  = 0U;
static uint32 App_Rx_AuthFail       = 0U;
static uint32 App_Rx_FramingFail    = 0U;
static uint32 App_Rx_TcpSeen        = 0U;
static uint64 App_Rx_VerifyDoneNs   = 0ULL;
static uint64 App_Rx_LastOutcomeNs  = 0ULL;

static void App_Rx_LogFailure(const char* Result, int Stream, uint64 RxDoneNs, uint64 VerifyDoneNs)
{
    App_Rx_LastOutcomeNs = App_NowNs();
    if (App_Rx_Csv != NULL)
    {
        (void)fprintf(App_Rx_Csv, "%d,-1,%llu,%llu,0,%s\n", Stream,
                      (unsigned long long)RxDoneNs, (unsigned long long)VerifyDoneNs, Result);
    }
}

static FILE* App_Rx_OpenCsv(const char* Path, const char* Header)
{
    FILE* csv = fopen(Path, "w");

    if (csv == NULL)
    {
        (void)printf("[App_Rx] WARN: cannot open %s\n", Path);
    }
    else
    {
        /* line buffered: rows survive a kill */
        (void)setvbuf(csv, NULL, _IOLBF, 0);
        (void)fprintf(csv, "# commit=%s\n# role=rx\n# profile=%s\n# count=%u\n%s\n",
                      SECOC_GIT_COMMIT, App_ProfileName(), (unsigned)App_Rx_Limit, Header);
    }
    return csv;
}

void App_Rx_Init(void)
{
    const char* csvPath = getenv("SECOC_APP_CSV");
    const char* payloadPath = getenv("SECOC_APP_PAYLOAD_CSV");

    App_Rx_Limit      = App_EnvU32("SECOC_APP_COUNT", 0U);
    App_Rx_IdleExitMs = App_EnvU32("SECOC_APP_IDLE_EXIT_MS", 0U);

    if (csvPath != NULL)
    {
        App_Rx_Csv = App_Rx_OpenCsv(csvPath, "# not_recorded=rx_done_ns\nstream,seq,rx_done_ns,verify_done_ns,deliver_ns,result");
    }
    if (payloadPath != NULL)
    {
        App_Rx_PayloadCsv = App_Rx_OpenCsv(payloadPath, "stream,seq,payload_hex");
    }

    (void)printf("[App_Rx] Initialised. Role=RECEIVER, %s streams 0..%u, Count=%u, IdleExitMs=%u, Csv=%s\n",
                 App_ProfileName(),
                 (unsigned)(App_MaxStreams() - 1U), (unsigned)App_Rx_Limit, (unsigned)App_Rx_IdleExitMs,
                 (csvPath != NULL) ? csvPath : "(none)");
}

void App_Rx_RxNotification(PduIdType RxPduId, const uint8* DataPtr, uint16 Length)
{
    uint64 now = App_NowNs();
    uint32 seq = 0U;
    uint16 i;
    int stream = App_StreamOfPdu((uint32)RxPduId);

    if (stream < 0)
    {
        return;
    }

    App_Rx_Ok++;
    App_Rx_LastOutcomeNs = now;

    /* seq: big-endian number in the last four payload bytes, as App_Tx writes it */
    for (i = (Length > 4U) ? (uint16)(Length - 4U) : 0U; i < Length; i++)
    {
        seq = (seq << 8U) | (uint32)DataPtr[i];
    }

    if (App_Rx_Csv != NULL)
    {
        (void)fprintf(App_Rx_Csv, "%d,%lu,0,%llu,%llu,ok\n", stream, (unsigned long)seq,
                      (unsigned long long)App_Rx_VerifyDoneNs, (unsigned long long)now);
    }
    if (App_Rx_PayloadCsv != NULL)
    {
        (void)fprintf(App_Rx_PayloadCsv, "%d,%lu,", stream, (unsigned long)seq);
        for (i = 0U; i < Length; i++)
        {
            (void)fprintf(App_Rx_PayloadCsv, "%02x", (unsigned)DataPtr[i]);
        }
        (void)fprintf(App_Rx_PayloadCsv, "\n");
    }
}

void App_Rx_MainFunction(void)
{
    uint32 dropped = 0U;
    uint32 total;

    App_LogTcpNoDelay(App_Rx_Csv, App_Rx_PayloadCsv, &App_Rx_TcpSeen, NULL);

    /* PDUs discarded by SoAd never reach SecOC; its measurement data is the only trace of them */
    if ((SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped) == E_OK) && (dropped > 0U))
    {
        App_Rx_FramingFail += dropped;
        while (dropped > 0U)
        {
            App_Rx_LogFailure("framing_fail", -1, App_NowNs(), 0ULL);
            dropped--;
        }
    }

    total = App_Rx_Ok + App_Rx_FreshnessFail + App_Rx_AuthFail + App_Rx_FramingFail;
    if (((App_Rx_Limit > 0U) && (total >= App_Rx_Limit)) ||
        ((App_Rx_IdleExitMs > 0U) && (total > 0U) &&
         ((App_NowNs() - App_Rx_LastOutcomeNs) >= ((uint64)App_Rx_IdleExitMs * 1000000ULL))))
    {
        (void)printf("[App_Rx] done: ok=%u freshness_fail=%u auth_fail=%u framing_fail=%u verified_ok=%u\n",
                     (unsigned)App_Rx_Ok, (unsigned)App_Rx_FreshnessFail, (unsigned)App_Rx_AuthFail,
                     (unsigned)App_Rx_FramingFail, (unsigned)App_Rx_VerifiedOk);
        if (App_Rx_Csv != NULL)
        {
            (void)fclose(App_Rx_Csv);
        }
        if (App_Rx_PayloadCsv != NULL)
        {
            (void)fclose(App_Rx_PayloadCsv);
        }
        exit(0);
    }
}

/* [SWS_SecOC_00119] status of each verification attempt */
void SecOC_VerificationStatusCallout(SecOC_VerificationStatusType verificationStatus)
{
    /* the Data ID of a signature stream is its SecOC PDU ID */
    int stream = App_StreamOfPdu((uint32)verificationStatus.secOCDataId);

    if (stream < 0)
    {
        return;
    }

    if (verificationStatus.verificationStatus == SECOC_VERIFICATIONSUCCESS)
    {
        /* the row is written when the payload arrives, right after this in the same main function */
        App_Rx_VerifiedOk++;
        App_Rx_VerifyDoneNs = App_NowNs();
    }
    else if (verificationStatus.verificationStatus == SECOC_FRESHNESSFAILURE)
    {
        App_Rx_FreshnessFail++;
        App_Rx_LogFailure("freshness_fail", stream, 0ULL, App_NowNs());
    }
    else
    {
        App_Rx_AuthFail++;
        App_Rx_LogFailure("auth_fail", stream, 0ULL, App_NowNs());
    }
}

#else  /* SECOC_ROLE_RECEIVER == FALSE — Tx-only build */

void App_Rx_Init(void)         { }
void App_Rx_MainFunction(void) { }
void App_Rx_RxNotification(PduIdType RxPduId, const uint8* DataPtr, uint16 Length)
{
    (void)RxPduId; (void)DataPtr; (void)Length;
}
void SecOC_VerificationStatusCallout(SecOC_VerificationStatusType verificationStatus)
{
    (void)verificationStatus;
}

#endif /* SECOC_ROLE_RECEIVER */
