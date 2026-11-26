#include "EcuM/EcuM.h"
#include "Os/Os.h"
#include "SecOC/SecOC.h"
#include "SecOC/SecOC_Cfg.h"
#include "SecOC/SecOC_Debug.h"
#include "App/App_Tx.h"
#include "Csm/Csm.h"
#include "PQC/PQC.h"
#include "PqcHs/PqcHs_Cfg.h"
#include "Mcal/Mcal_Cfg.h"
#if MCAL_IS_PI4()
#include "Mcal/Wdg.h"
#endif
#include "Perf/SecOC_Perf.h"
#include <oqs/common.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#ifndef SECOC_GIT_COMMIT
#define SECOC_GIT_COMMIT "unknown"
#endif
#ifndef SECOC_BUILD_INFO
#define SECOC_BUILD_INFO "unknown"
#endif
#ifndef SECOC_ADDR_INFO
#define SECOC_ADDR_INFO "addresses from the source defaults"
#endif

/* Which implementations this liboqs build uses on this CPU. A non-distribution build selects them at
 * compile time; liboqs 0.15.0 has an AArch64 (NEON) ML-KEM-768 and only the portable C ML-DSA-65. */
#if defined(OQS_ENABLE_KEM_ml_kem_768_aarch64) && defined(OQS_USE_ARM_NEON_INSTRUCTIONS) && !defined(OQS_DIST_BUILD)
#define MAIN_MLKEM_IMPL "aarch64 NEON"
#elif defined(OQS_ENABLE_KEM_ml_kem_768_aarch64)
#define MAIN_MLKEM_IMPL "aarch64 NEON if the CPU has it (runtime dispatch)"
#else
#define MAIN_MLKEM_IMPL "portable C"
#endif
#if defined(OQS_ENABLE_SIG_ml_dsa_65_aarch64)
#define MAIN_MLDSA_IMPL "aarch64"
#else
#define MAIN_MLDSA_IMPL "portable C"
#endif

extern Std_ReturnType EcuM_StartupTwo(void);

static void main_cleanup(void)
{
#if MCAL_IS_PI4()
    (void)Wdg_SetMode(WDG_MODE_OFF);
    Wdg_DeInit();
#endif
    SecOC_Perf_Shutdown();   /* no-op when SECOC_PERF_INSTRUMENT not defined */
}

static void main_signal_handler(int sig)
{
    main_cleanup();
    _exit(128 + sig);
}

static void main_install_signal_handlers(void)
{
    struct sigaction sa;
    (void)sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = main_signal_handler;
    (void)sigaction(SIGTERM, &sa, NULL);
    (void)sigaction(SIGINT,  &sa, NULL);
    (void)sigaction(SIGHUP,  &sa, NULL);
}

int main(int argc, char* argv[])
{
    /* Force line-buffered stdout so printf flushes immediately even when
     * stdout is a pipe/file (sudo timeout ./SecOC > log). */
    (void)setvbuf(stdout, NULL, _IOLBF, 0);
    (void)setvbuf(stderr, NULL, _IOLBF, 0);

    /* OQS_version() is what the linked library says, OQS_VERSION_TEXT what the headers said */
    (void)printf("[main] PQC-SecOC commit %s, build %s, liboqs %s (headers %s; ML-KEM-768 %s, ML-DSA-65 %s)\n",
                 SECOC_GIT_COMMIT, SECOC_BUILD_INFO, OQS_version(), OQS_VERSION_TEXT, MAIN_MLKEM_IMPL, MAIN_MLDSA_IMPL);
    (void)printf("[main] %s\n", SECOC_ADDR_INFO);
    (void)printf("[main] handshake timers: T_pend %u ms, T_min %u ms, T_A %u ms, T_flush %u ms\n",
                 (unsigned)PQCHS_T_PEND_MS, (unsigned)SOAD_PQC_HS_MIN_INTERVAL_MS, (unsigned)PQCHS_T_A_MS, (unsigned)PQCHS_T_FLUSH_MS);
    if ((argc > 1) && (strcmp(argv[1], "--version") == 0))
    {
        return 0;
    }
    if ((argc > 1) && (strcmp(argv[1], "--keygen") == 0))
    {
        /* The gateway never creates its identity at start-up (strict bootstrap): this makes the
         * ML-DSA-65 key pair in the key directory of the build, once. An existing pair is kept. */
        static PQC_MLDSA_KeyPairType keyPair;

        if (PQC_MLDSA_LoadKeys(&keyPair, CSM_MLDSA_KEY_PREFIX) == E_OK)
        {
            (void)printf("[main] key pair exists, nothing written\n");
            return 0;
        }
        if ((PQC_Init() != E_OK) || (PQC_MLDSA_KeyGen(&keyPair) != E_OK) ||
            (PQC_MLDSA_SaveKeys(&keyPair, CSM_MLDSA_KEY_PREFIX) != E_OK))
        {
            (void)printf("[main] ERROR: key generation failed\n");
            return 1;
        }
        (void)printf("[main] key pair written\n");
        return 0;
    }

    main_install_signal_handlers();
    (void)atexit(main_cleanup);

    /* Initialise performance instrumentation FIRST, before any AUTOSAR init.
     * This guarantees /tmp/secoc_perf.csv exists with header + drain thread is
     * spawned even if EcuM_StartupTwo later fails or hangs. No-op when
     * SECOC_PERF_INSTRUMENT undefined. */
    if (SecOC_Perf_Init() != 0)
    {
        (void)printf("[main] WARN: SecOC_Perf_Init failed (continuing without probes)\n");
    }

    EcuM_Init(NULL);
    if (EcuM_StartupTwo() != E_OK)
    {
        (void)printf("EcuM startup failed\n");
        return 1;
    }

    Os_Init(&Os_Config);
    Os_SetStartupHook(Os_GatewayStartupHook);
    StartOS(OSDEFAULTAPPMODE);

    #if (SECOC_ROLE_SENDER == TRUE)
        (void)printf("[main] Role: SENDER -- App_Tx cyclic driver active (SecOC TxPduId=%u)\n",
                     (unsigned)APP_TX_SECOC_PDU_ID);
    #elif (SECOC_ROLE_RECEIVER == TRUE)
        (void)printf("[main] Role: RECEIVER -- Rx-only mode\n");
    #else
        (void)printf("[main] WARN: Neither SECOC_ROLE_SENDER nor SECOC_ROLE_RECEIVER set\n");
    #endif

    (void)printf("Program entered RUN state (BSW/MCAL startup complete)\n");

    for (;;)
    {
        Os_MainFunction();
    }
}
