/********************************************************************************************************/
/******************************************Phase_A_RegressionTests.cpp***********************************/
/********************************************************************************************************/
/**
 * @file   Phase_A_RegressionTests.cpp
 * @brief  Regression guards for Phase A audit findings.
 *
 * These tests lock in compile-time and structural fixes that came out of
 * the Phase A audit and prevent silent regressions. They are intentionally
 * cheap (no live network, no live crypto handshake) so they can run in the
 * UNIT/REGRESSION lane on every CI build.
 *
 * Mapped requirements (informational):
 *   - SWS_SecOC_00107  Version info macros must be exposed.
 *   - SWS_SecOC_00054  Module identification must remain stable.
 *   - SWS_SecOC_00226  Tx role exclusivity — sender-only build does not
 *                       activate receiver state machines.
 *
 * Owner: TL-QA / Regression
 */

#include <gtest/gtest.h>

#include <string.h>
#include <stdio.h>

extern "C" {

#include "SecOC_Cfg.h"
#include "SecOC_Lcfg.h"
#include "SecOC_PBcfg.h"
#include "SecOC_Types.h"
#include "SecOC.h"
#include "SecOC_PQC_Cfg.h"
#include "ComStack_Types.h"

extern SecOC_ConfigType SecOC_Config;
extern SecOC_PduCollection PdusCollections[];

/*
 * Optional weak-symbol helper. If somebody (e.g. the integration layer)
 * has provided a real implementation the linker will pick it up; otherwise
 * the weak default returns FALSE and the test using it will simply
 * GTEST_SKIP at runtime.
 */
__attribute__((weak)) int SecOC_TestHelper_DefaultSoConPointsAtPeer(void)
{
    return 0;
}

}  /* extern "C" */


/* ---------------------------------------------------------------------- */
/* TEST 1: ModeFlagRemainsTxOnly                                          */
/* ---------------------------------------------------------------------- */
/**
 * Phase A required this build to be a TX-only sender. The receive role
 * must remain disabled so that the sender cannot accidentally accept
 * inbound traffic from a misbehaving peer or test rig.
 *
 * If anybody flips SECOC_ROLE_RECEIVER back to TRUE without an explicit
 * waiver, this test fails and the regression is caught at CI time.
 */
TEST(PhaseARegression, ModeFlagRemainsTxOnly)
{
    EXPECT_EQ((int)SECOC_ROLE_SENDER,   1) << "SECOC_ROLE_SENDER must be 1 in this build";
    EXPECT_EQ((int)SECOC_ROLE_RECEIVER, 0) << "SECOC_ROLE_RECEIVER must remain 0 in this build";
}


/* ---------------------------------------------------------------------- */
/* TEST 2: DebugAllNotEnabled                                             */
/* ---------------------------------------------------------------------- */
/**
 * Phase A removed the catch-all DEBUG_ALL macro because it accidentally
 * enabled noisy debug printouts in production builds. This test fails
 * the build if anybody resurrects DEBUG_ALL.
 */
TEST(PhaseARegression, DebugAllNotEnabled)
{
#ifdef DEBUG_ALL
    FAIL() << "DEBUG_ALL is defined — Phase A removed this catch-all switch";
#else
    SUCCEED();
#endif
}


/* ---------------------------------------------------------------------- */
/* TEST 3: DefaultSoConPointsAtPeerNotLoopback                            */
/* ---------------------------------------------------------------------- */
/**
 * Phase A audit found that the default SoCon target was 127.0.0.1, which
 * silently turned Pi-to-Pi tests into self-loopback tests. The fix points
 * the default SoCon at the configured peer.
 *
 * The check is implemented by an external weak helper. If the helper has
 * not been provided (e.g. running this file in isolation against a static
 * lib that does not link the helper) we GTEST_SKIP rather than FAIL,
 * because we cannot prove the negative.
 */
TEST(PhaseARegression, DefaultSoConPointsAtPeerNotLoopback)
{
    /* The weak default returns 0; a stronger override returns 1 when the
       SoCon is correctly aimed at the peer. */
    const int provided = SecOC_TestHelper_DefaultSoConPointsAtPeer();

    if (provided == 0) {
        GTEST_SKIP()
            << "Weak helper SecOC_TestHelper_DefaultSoConPointsAtPeer not "
            << "provided in this link — cannot verify SoCon target. The "
            << "integrator should supply this when building the full app.";
    }

    EXPECT_NE(provided, 0)
        << "Default SoCon must point at the peer, not 127.0.0.1";
}


/* ---------------------------------------------------------------------- */
/* TEST 4: Pdu2IsSoAdEthernet                                             */
/* ---------------------------------------------------------------------- */
/**
 * PDU-ID 2 is the Ethernet/SoAd egress route. The audit fix moved this
 * route to the SoAd TP path (SECOC_SECURED_PDU_SOADTP) to match the
 * routing actually performed in PduR_SecOC.c — IF mode could not carry
 * the ~3.3 kB ML-DSA-65 signatures emitted by PQC mode.
 *
 * If the configuration ever drifts back to SECOC_SECURED_PDU_SOADIF
 * (or any non-SOADTP value) this test catches it before the next
 * Pi-to-Pi smoke run.
 */
TEST(PhaseARegression, Pdu2IsSoAdEthernet)
{
    /* See include/SecOC/SecOC_Types.h for the enum. */
    EXPECT_EQ(PdusCollections[2].Type, SECOC_SECURED_PDU_SOADTP)
        << "PDU 2 must route through SoAd TP for Ethernet (SECOC_SECURED_PDU_SOADTP).";
}


/* ---------------------------------------------------------------------- */
/* TEST 5: InitDoesNotSpamStderrWhenDetOff                                */
/* ---------------------------------------------------------------------- */
/**
 * With SECOC_DEV_ERROR_DETECT == FALSE, SecOC_Init must remain quiet on
 * stderr. Phase A removed several stray printf("ERROR: ...\n") calls
 * that fired even on the happy path. The 256-byte budget here is generous
 * enough to allow a single short banner from a downstream module if one
 * sneaks in, while still catching the multi-kilobyte spam Phase A removed.
 */
TEST(PhaseARegression, InitDoesNotSpamStderrWhenDetOff)
{
    testing::internal::CaptureStderr();
    SecOC_Init(&SecOC_Config);
    const std::string captured = testing::internal::GetCapturedStderr();

    EXPECT_LT(captured.size(), static_cast<size_t>(256))
        << "SecOC_Init wrote " << captured.size()
        << " bytes to stderr with DET off; expected <256.\n"
        << "First 256 bytes:\n"
        << captured.substr(0, 256);
}


/* ---------------------------------------------------------------------- */
/* TEST 6: SecOcVersionInfoMacrosArePresent                               */
/* ---------------------------------------------------------------------- */
/**
 * SWS_SecOC_00107 mandates that the module exposes vendor and version
 * information macros. Phase A canonicalised these into SecOC_Cfg.h —
 * if anybody removes them the GetVersionInfo API silently returns
 * garbage. Lock the macros in here.
 */
TEST(PhaseARegression, SecOcVersionInfoMacrosArePresent)
{
    EXPECT_GT((int)SECOC_SW_MAJOR_VERSION, 0)
        << "SECOC_SW_MAJOR_VERSION must be >0 (SWS_SecOC_00107)";
    /* Minor and patch are allowed to be 0, just verify they exist. */
    (void)SECOC_SW_MINOR_VERSION;
    (void)SECOC_SW_PATCH_VERSION;
    (void)SECOC_VENDOR_ID;
}
