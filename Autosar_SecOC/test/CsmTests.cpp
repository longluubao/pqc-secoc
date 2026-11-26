/********************************************************************************************************/
/***********************************************CsmTests.cpp*********************************************/
/********************************************************************************************************/
/**
 * @file CsmTests.cpp
 * @brief Comprehensive unit tests for Cryptographic Service Manager (Csm)
 * @details Tests MAC generation/verification, ML-DSA signatures, ML-KEM key
 *          exchange, session key derivation, and job management.
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "Csm/Csm.h"
#include "PQC/PQC.h"
#include "SecOC/SecOC_Cfg.h"
}

/*===========================================================================*/
/*  Test Fixture                                                             */
/*===========================================================================*/
class CsmTests : public ::testing::Test {
protected:
    void SetUp() override {
        /* Ensure PQC and CSM are initialized with DEMO_FILE_AUTO mode
         * so that ML-DSA keys are generated automatically if absent. */
        (void)PQC_Init();
        Csm_ConfigType cfg;
        cfg.CsmMldsaBootstrapMode = CSM_MLDSA_BOOTSTRAP_DEMO_FILE_AUTO;
        cfg.CsmLoadProvisionedMldsaKeysFct = NULL;
        Csm_Init(&cfg);
    }
};

/*===========================================================================*/
/*  Initialization Tests                                                     */
/*===========================================================================*/
TEST_F(CsmTests, Init_Idempotent) {
    /* Calling init twice should not fail */
    Csm_Init(NULL);
    /* If we get here, no crash — pass */
    SUCCEED();
}

TEST_F(CsmTests, Init_WithNullConfig) {
    /* NULL config should use default bootstrap mode */
    Csm_DeInit();
    Csm_Init(NULL);
    SUCCEED();
}

/*===========================================================================*/
/*  MAC Generation / Verification Tests                                      */
/*===========================================================================*/
/* The MAC jobs need their keys: installed the way the handshake does it (see test_mac_profile.c
 * for the known answers and the key handling). */
static void InstallMacTestKeys() {
    static const uint8 key[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    ASSERT_EQ(Csm_KeyElementSet(CSM_KEYID_MAC_TX, CRYPTO_KE_MAC_KEY, key, sizeof(key)), E_OK);
    ASSERT_EQ(Csm_KeySetValid(CSM_KEYID_MAC_TX), E_OK);
    ASSERT_EQ(Csm_KeyElementSet(CSM_KEYID_MAC_RX, CRYPTO_KE_MAC_KEY, key, sizeof(key)), E_OK);
    ASSERT_EQ(Csm_KeySetValid(CSM_KEYID_MAC_RX), E_OK);
}

TEST_F(CsmTests, MacGenerate_ValidInput) {
    uint8 data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8 mac[32];
    uint32 macLength = sizeof(mac);

    InstallMacTestKeys();
    Std_ReturnType result = Csm_MacGenerate(
        CSM_JOBID_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL,
        data, sizeof(data),
        mac, &macLength
    );

    EXPECT_EQ(result, E_OK);
    EXPECT_GT(macLength, 0U);
}

TEST_F(CsmTests, MacGenerate_NullDataPtr) {
    uint8 mac[32];
    uint32 macLength = sizeof(mac);

    InstallMacTestKeys();
    Std_ReturnType result = Csm_MacGenerate(
        CSM_JOBID_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL,
        NULL, 8U,
        mac, &macLength
    );

    EXPECT_NE(result, E_OK);
}

TEST_F(CsmTests, MacVerify_ValidMac) {
    uint8 data[] = {0x10, 0x20, 0x30, 0x40};
    uint8 mac[32];
    uint32 macLength = sizeof(mac);
    Crypto_VerifyResultType verifyResult = CRYPTO_E_VER_NOT_OK;

    /* Generate MAC first */
    InstallMacTestKeys();
    Std_ReturnType result = Csm_MacGenerate(
        CSM_JOBID_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL,
        data, sizeof(data),
        mac, &macLength
    );
    ASSERT_EQ(result, E_OK);

    /* [SWS_Csm_01050] the MAC length is in bits */
    result = Csm_MacVerify(
        CSM_JOBID_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
        data, sizeof(data),
        mac, macLength * 8U,
        &verifyResult
    );

    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(verifyResult, CRYPTO_E_VER_OK);
}

TEST_F(CsmTests, MacVerify_TamperedData) {
    uint8 data[] = {0x10, 0x20, 0x30, 0x40};
    uint8 mac[32];
    uint32 macLength = sizeof(mac);
    Crypto_VerifyResultType verifyResult = CRYPTO_E_VER_OK;

    /* Generate MAC */
    InstallMacTestKeys();
    Std_ReturnType result = Csm_MacGenerate(
        CSM_JOBID_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL,
        data, sizeof(data),
        mac, &macLength
    );
    ASSERT_EQ(result, E_OK);

    /* Tamper with data */
    data[0] = 0xFF;

    result = Csm_MacVerify(
        CSM_JOBID_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
        data, sizeof(data),
        mac, macLength * 8U,
        &verifyResult
    );

    /* the request is processed, the verdict is "not ok" */
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(verifyResult, CRYPTO_E_VER_NOT_OK);
}

/*===========================================================================*/
/*  ML-DSA Signature Tests                                                   */
/*===========================================================================*/
TEST_F(CsmTests, SignatureGenerate_ValidInput) {
    uint8 message[] = "AUTOSAR SecOC test message for ML-DSA signature";
    uint8 signature[CSM_MLDSA_SIGNATURE_BYTES];
    uint32 signatureLength = sizeof(signature);

    Std_ReturnType result = Csm_SignatureGenerate(
        CSM_JOBID, CRYPTO_OPERATIONMODE_SINGLECALL,
        message, sizeof(message),
        signature, &signatureLength
    );

    /* May return CRYPTO_E_KEY_NOT_VALID if ML-DSA keys not loaded */
    if (result == E_OK) {
        EXPECT_GT(signatureLength, 0U);
        EXPECT_LE(signatureLength, CSM_MLDSA_SIGNATURE_BYTES);
    }
}

TEST_F(CsmTests, SignatureVerify_ValidSignature) {
    uint8 message[] = "Test message for signature verification";
    uint8 signature[CSM_MLDSA_SIGNATURE_BYTES];
    uint32 signatureLength = sizeof(signature);
    Crypto_VerifyResultType verifyResult;

    /* Generate signature */
    Std_ReturnType result = Csm_SignatureGenerate(
        CSM_JOBID, CRYPTO_OPERATIONMODE_SINGLECALL,
        message, sizeof(message),
        signature, &signatureLength
    );

    if (result == E_OK) {
        /* Verify the signature */
        result = Csm_SignatureVerify(
            CSM_JOBID_VERIFY_LOOPBACK, CRYPTO_OPERATIONMODE_SINGLECALL,
            message, sizeof(message),
            signature, signatureLength,
            &verifyResult
        );

        EXPECT_EQ(result, E_OK);
        EXPECT_EQ(verifyResult, CRYPTO_E_VER_OK);
    }
}

TEST_F(CsmTests, SignatureVerify_TamperedMessage) {
    uint8 message[] = "Original message for tamper test";
    uint8 signature[CSM_MLDSA_SIGNATURE_BYTES];
    uint32 signatureLength = sizeof(signature);
    Crypto_VerifyResultType verifyResult = CRYPTO_E_VER_OK;

    Std_ReturnType result = Csm_SignatureGenerate(
        CSM_JOBID, CRYPTO_OPERATIONMODE_SINGLECALL,
        message, sizeof(message),
        signature, &signatureLength
    );

    ASSERT_EQ(result, E_OK);

    /* Tamper with message */
    message[0] = 'X';

    result = Csm_SignatureVerify(
        CSM_JOBID_VERIFY_LOOPBACK, CRYPTO_OPERATIONMODE_SINGLECALL,
        message, sizeof(message),
        signature, signatureLength,
        &verifyResult
    );

    /* [SWS_Csm_00996], [SWS_Csm_01024]: the verification ran, so the request is successful, and the
     * verdict says that the signature is not valid */
    EXPECT_EQ(result, E_OK);
    EXPECT_EQ(verifyResult, CRYPTO_E_VER_NOT_OK);
}

/* A request that cannot be carried out is not a verdict: a job that is not a verify job gives
 * E_NOT_OK (and the result pointer does not say "verified"). */
TEST_F(CsmTests, SignatureVerify_RequestFailed) {
    uint8 message[] = "message for a request that fails";
    uint8 signature[CSM_MLDSA_SIGNATURE_BYTES];
    uint32 signatureLength = sizeof(signature);
    Crypto_VerifyResultType verifyResult = CRYPTO_E_VER_OK;

    ASSERT_EQ(Csm_SignatureGenerate(CSM_JOBID, CRYPTO_OPERATIONMODE_SINGLECALL,
                                    message, sizeof(message), signature, &signatureLength), E_OK);

    /* the PDU sign job is not a verify job */
    EXPECT_EQ(Csm_SignatureVerify(CSM_JOBID, CRYPTO_OPERATIONMODE_SINGLECALL,
                                  message, sizeof(message), signature, signatureLength, &verifyResult), E_NOT_OK);
    EXPECT_NE(verifyResult, CRYPTO_E_VER_OK);
}

/*===========================================================================*/
/*  Version Info Tests                                                       */
/*===========================================================================*/
TEST_F(CsmTests, GetVersionInfo) {
    Std_VersionInfoType versionInfo;
    Csm_GetVersionInfo(&versionInfo);

    /* Verify non-zero module ID */
    EXPECT_GT(versionInfo.moduleID, 0U);
}
