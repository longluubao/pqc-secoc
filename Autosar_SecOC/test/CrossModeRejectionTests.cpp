/********************************************************************************************************/
/******************************************CrossModeRejectionTests.cpp************************************/
/********************************************************************************************************/
/**
 * @file   CrossModeRejectionTests.cpp
 * @brief  Negative tests for cross-mode signature/MAC verification.
 *
 * The build supports two authentication modes:
 *   - Classic   : AES-CMAC (4 byte authenticator)
 *   - PQC       : ML-DSA-65 (~3309 byte signature)
 *
 * Mixing the two MUST fail verification — a PDU signed with PQC must
 * never validate against a classic verifier, and vice-versa. If the
 * dispatcher ever gets confused (e.g. ignores the configured mode or
 * trusts an attacker-supplied length field) this test catches it.
 *
 * Both directions are exercised through the same parameterised fixture.
 *
 * Mapped requirements (informational):
 *   - SWS_SecOC_00045  Verification must fail when MAC/signature does
 *                       not match the configured algorithm.
 *
 * Owner: TL-QA / Negative-path
 */

#include <gtest/gtest.h>

#include <stdint.h>
#include <string.h>

extern "C" {

#include "SecOC_Cfg.h"
#include "SecOC_Lcfg.h"
#include "SecOC_PBcfg.h"
#include "SecOC_Types.h"
#include "SecOC.h"
#include "SecOC_PQC_Cfg.h"
#include "ComStack_Types.h"
#include "Rte_SecOC.h"

extern SecOC_ConfigType SecOC_Config;
extern const SecOC_TxPduProcessingType *SecOCTxPduProcessing;
extern const SecOC_RxPduProcessingType *SecOCRxPduProcessing;

/* Classic and PQC sign/verify primitives. */
extern Std_ReturnType authenticate(const PduIdType TxPduId,
                                   PduInfoType* authPdu,
                                   PduInfoType* SecPdu);
extern Std_ReturnType verify(PduIdType RxPduId,
                             PduInfoType* SecPdu,
                             SecOC_VerificationResultType* verification_result);
extern Std_ReturnType authenticate_PQC(const PduIdType TxPduId,
                                       PduInfoType* authPdu,
                                       PduInfoType* SecPdu);
extern Std_ReturnType verify_PQC(PduIdType RxPduId,
                                 PduInfoType* SecPdu,
                                 SecOC_VerificationResultType* verification_result);

}  /* extern "C" */


/**
 * @brief One row in the cross-mode rejection truth table.
 *
 * Each row asserts that signing in mode A and verifying in mode B
 * (with A != B) MUST be rejected.
 */
struct CrossModeCase {
    bool signWithPqc;    /**< if true, sign with PQC; else classic */
    bool verifyWithPqc;  /**< if true, verify with PQC; else classic */
    const char* name;    /**< human-readable label for debug output */
};


class CrossModeRejection : public ::testing::TestWithParam<CrossModeCase> {};


TEST_P(CrossModeRejection, MismatchedSignerAndVerifierIsRejected)
{
    const CrossModeCase tc = GetParam();
    SCOPED_TRACE(tc.name);

    SecOC_Init(&SecOC_Config);

    const PduIdType pduId = 0;

    /* Build the auth PDU. */
    uint8 authBuf[16] = { 0xA1, 0xB2, 0xC3, 0xD4 };
    PduInfoType authPdu;
    authPdu.SduDataPtr  = authBuf;
    authPdu.MetaDataPtr = NULL;
    authPdu.SduLength   = 4;

    /* Provide a buffer big enough for either MAC or full ML-DSA-65. */
    uint8 secBuf[8192] = { 0 };
    PduInfoType secPdu;
    secPdu.SduDataPtr  = secBuf;
    secPdu.MetaDataPtr = NULL;
    secPdu.SduLength   = 0;

    /* Step 1: sign with the configured mode. */
    Std_ReturnType signRv;
    if (tc.signWithPqc) {
        signRv = authenticate_PQC(pduId, &authPdu, &secPdu);
    } else {
        signRv = authenticate(pduId, &authPdu, &secPdu);
    }

    if (signRv != E_OK) {
        /* Signing itself can fail in the unit-test environment if the
           required key material isn't loaded. We can't run the negative
           verification step without a signed buffer, so skip the case
           rather than declare it a win. */
        GTEST_SKIP() << "signer (" << (tc.signWithPqc ? "PQC" : "classic")
                     << ") returned E_NOT_OK — cannot exercise verify path";
    }
    ASSERT_GT(secPdu.SduLength, 0u) << "signer returned E_OK but empty PDU";

    /* Step 2: verify with the *opposite* mode. */
    SecOC_VerificationResultType verRes = E_NOT_OK;
    Std_ReturnType verRv;
    if (tc.verifyWithPqc) {
        verRv = verify_PQC(pduId, &secPdu, &verRes);
    } else {
        verRv = verify(pduId, &secPdu, &verRes);
    }

    /* Either the verifier reports E_NOT_OK as its return code, or it
       returns E_OK but signals failure via verification_result. Both are
       acceptable rejection paths; what's NOT acceptable is rv == E_OK
       AND verRes == E_OK, i.e. accepting the cross-mode artifact. */
    const bool accepted = (verRv == E_OK) && (verRes == E_OK);
    EXPECT_FALSE(accepted)
        << "Cross-mode verification accepted a mismatched authenticator: "
        << "signed_with_pqc=" << tc.signWithPqc
        << ", verified_with_pqc=" << tc.verifyWithPqc;
}


INSTANTIATE_TEST_SUITE_P(
    AllCrossPairs,
    CrossModeRejection,
    ::testing::Values(
        CrossModeCase{ true,  false, "PQC-signed -> classic-verify"   },
        CrossModeCase{ false, true,  "classic-signed -> PQC-verify"   }
    )
);
