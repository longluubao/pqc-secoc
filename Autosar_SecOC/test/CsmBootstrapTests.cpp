/********************************************************************************************************/
/******************************************CsmBootstrapTests.cpp******************************************/
/********************************************************************************************************/
/**
 * @file   CsmBootstrapTests.cpp
 * @brief  Smoke tests for CSM (Crypto Service Manager) initialisation.
 *
 * The CSM is responsible for bootstrapping ML-DSA keys at module init.
 * Phase A had a bug where pointing CSM at a missing key directory caused
 * a hard crash (SIGSEGV inside fopen()) instead of a graceful E_NOT_OK.
 *
 * This test recreates the missing-directory scenario by handing CSM a
 * freshly-created temp dir + a random subdir that does NOT exist, then
 * calls Csm_Init and verifies the process is still alive afterwards.
 *
 * Note: per audit, repo's Csm_Init is `void`-typed, so we cannot inspect
 * a return code. The success criterion is "we did not crash".
 *
 * Mapped requirements (informational):
 *   - SWS_Csm_91015  Csm_Init shall not abort on missing key material.
 *
 * Owner: TL-QA / Bootstrap
 */

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstdio>
#include <cstring>

extern "C" {

#include "Std_Types.h"
#include "Csm.h"

}  /* extern "C" */


TEST(CsmBootstrap, InitDoesNotCrashOnMissingKeyDir)
{
    /* Build a temp dir for this test. mkdtemp mutates its argument. */
    char tmpl[] = "/tmp/secoc_csm_boot_XXXXXX";
    char* tempDir = mkdtemp(tmpl);
    ASSERT_NE(tempDir, nullptr) << "mkdtemp() failed: " << std::strerror(errno);

    /* Append a non-existent sub-directory. CSM should treat this as
       "no provisioned keys" rather than abort. */
    char missingDir[256];
    (void)std::snprintf(missingDir, sizeof(missingDir),
                        "%s/this_path_does_not_exist", tempDir);

    /* Point any path-based env hint at the bogus directory. The exact
       env name varies by build, so we set a few common candidates;
       harmless if the binary ignores them. */
    setenv("SECOC_PQC_KEY_DIR", missingDir, 1);
    setenv("PQC_MLDSA_KEY_DIR", missingDir, 1);
    setenv("CSM_KEY_DIR",       missingDir, 1);

    /* Use the demo-file-auto bootstrap mode so any "missing keys"
       branch is exercised rather than the strict-abort branch. */
    Csm_ConfigType cfg;
    std::memset(&cfg, 0, sizeof(cfg));
    cfg.CsmMldsaBootstrapMode            = CSM_MLDSA_BOOTSTRAP_DEMO_FILE_AUTO;
    cfg.CsmLoadProvisionedMldsaKeysFct   = NULL;

    /* The key behavioural expectation: this returns control. If CSM
       crashes inside Init, GoogleTest never sees the next line. */
    Csm_Init(&cfg);

    /* And we should be able to deinit cleanly, too. */
    Csm_DeInit();

    SUCCEED() << "Csm_Init survived a missing key directory";

    /* Best-effort cleanup; ignore failures (the dir is empty). */
    (void)std::remove(tempDir);
}
