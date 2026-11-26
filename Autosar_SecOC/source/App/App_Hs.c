/********************************************************************************************************/
/*  File:   source/App/App_Hs.c                                                                           */
/*  Brief:  Writes what the handshake component reports (it does no output itself): handshake.csv with   */
/*          the columns of DATA_SCHEMA.md, and "[App_Hs]" lines on the console. Functional record of the  */
/*          gateway; the handshake timing of the paper comes from the bench harness.                     */
/********************************************************************************************************/

#include "App/App_Hs.h"
#include "App/App_Log.h"
#include "Os/Os_Cfg.h"
#include "PqcHs/PqcHs.h"
#include "PqcHs/PqcHs_Cfg.h"

#include <stdio.h>
#include <unistd.h>

static FILE*  App_Hs_Csv = NULL;
static uint32 App_Hs_Installs = 0U;
static uint32 App_Hs_TcpSeen = 0U;

void App_Hs_Init(void)
{
    const char* csvPath = getenv("SECOC_APP_HS_CSV");

    App_Hs_Installs = 0U;
    if (csvPath != NULL)
    {
        App_Hs_Csv = fopen(csvPath, "w");
        if (App_Hs_Csv == NULL)
        {
            (void)printf("[App_Hs] WARN: cannot open %s\n", csvPath);
        }
        else
        {
            char host[64] = "unknown";
            (void)gethostname(host, sizeof(host) - 1U);

            /* line buffered: rows survive a kill */
            (void)setvbuf(App_Hs_Csv, NULL, _IOLBF, 0);
            (void)fprintf(App_Hs_Csv, "# tool=SecOC gateway\n# commit=%s\n# host=%s\n# mainfunction=cyclic\n# mf_period_us=%u\n# t_min_ms=%u\n",
                          SECOC_GIT_COMMIT, host, (unsigned)(OS_BSW_CYCLE_PERIOD_TICKS * OS_TICK_DURATION_MS * 1000U),
                          (unsigned)SOAD_PQC_HS_MIN_INTERVAL_MS);
            (void)fprintf(App_Hs_Csv, "seq,role,result,total_ns,bytes_tx,bytes_rx,keygen_ns,encaps_ns,decaps_ns,sign_ns,verify_ns,kdf_ns,hash_ns,mac_ns\n");
        }
    }
}

void App_Hs_MainFunction(void)
{
    static const char* const resultName[] = { "ok", "bad_ver", "bad_len", "unknown_id", "sig_fail", "mac_fail", "timeout", "state" };
    PqcHs_AttemptInfoType row;
    uint8 sid[PQCHS_SID_BYTES];
    uint32 installs = 0U;
    uint32 i;

    App_LogTcpNoDelay(App_Hs_Csv, NULL, &App_Hs_TcpSeen, "App_Hs");

    while (PqcHs_ReadAttempt(0U, &row) == E_OK)
    {
        const char* result = ((uint32)row.Result < (sizeof(resultName) / sizeof(resultName[0]))) ? resultName[row.Result] : "state";
        const char* role = (row.Role == PQCHS_ROLE_INITIATOR) ? "initiator" : "responder";

        (void)printf("[App_Hs] attempt %u (%s): %s\n", (unsigned)row.Seq, role, result);
        if (App_Hs_Csv != NULL)
        {
            (void)fprintf(App_Hs_Csv, "%u,%s,%s,%llu,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
                          (unsigned)row.Seq, role, result, (unsigned long long)row.TotalNs,
                          (unsigned)row.BytesTx, (unsigned)row.BytesRx,
                          (unsigned long long)row.Times.KeygenNs, (unsigned long long)row.Times.EncapsNs,
                          (unsigned long long)row.Times.DecapsNs, (unsigned long long)row.Times.SignNs,
                          (unsigned long long)row.Times.VerifyNs, (unsigned long long)row.Times.KdfNs,
                          (unsigned long long)row.Times.HashNs, (unsigned long long)row.Times.MacNs);
        }
    }

    /* every key installation: session identifier and installation counter */
    if ((PqcHs_GetSession(0U, sid, &installs) == E_OK) && (installs != App_Hs_Installs))
    {
        App_Hs_Installs = installs;
        (void)printf("[App_Hs] keys installed: installation %u, sid ", (unsigned)installs);
        for (i = 0U; i < PQCHS_SID_BYTES; i++)
        {
            (void)printf("%02x", (unsigned)sid[i]);
        }
        (void)printf("\n");
    }
}
