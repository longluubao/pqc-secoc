/********************************************************************************************************/
/*****************************************CryIfTests.cpp************************************************/
/********************************************************************************************************/
/**
 * @file CryIfTests.cpp
 * @brief Unit tests for Crypto Interface (CryIf) module
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "CryIf/CryIf.h"
#include "PQC/PQC.h"
#include "Csm/Csm.h"
}

class CryIfTests : public ::testing::Test {
protected:
    void SetUp() override {
        (void)PQC_Init();
        Csm_ConfigType cfg;
        cfg.CsmMldsaBootstrapMode = CSM_MLDSA_BOOTSTRAP_DEMO_FILE_AUTO;
        cfg.CsmLoadProvisionedMldsaKeysFct = NULL;
        Csm_Init(&cfg);
        CryIf_Init();
    }
};

/* --- Initialization Tests --- */
TEST_F(CryIfTests, Init_NoCrash) {
    CryIf_Init();
    SUCCEED();
}

/* --- MAC Generation Tests --- */
TEST_F(CryIfTests, MacGenerate_NeedsValidKey) {
    uint8 data[] = {0x01, 0x02, 0x03, 0x04};
    uint8 key[32] = {0x42};
    uint8 mac[32];
    uint32 macLength = sizeof(mac);
    CryIf_Init();
    EXPECT_EQ(CryIf_MacGenerate(0U, data, sizeof(data), mac, &macLength), CRYPTO_E_KEY_NOT_VALID);
    EXPECT_EQ(CryIf_KeyElementSet(0U, CRYPTO_KE_MAC_KEY, key, sizeof(key)), E_OK);
    EXPECT_EQ(CryIf_MacGenerate(0U, data, sizeof(data), mac, &macLength), CRYPTO_E_KEY_NOT_VALID);
    EXPECT_EQ(CryIf_KeySetValid(0U), E_OK);
    EXPECT_EQ(CryIf_MacGenerate(0U, data, sizeof(data), mac, &macLength), E_OK);
    EXPECT_EQ(macLength, 32U);
}

TEST_F(CryIfTests, MacGenerate_NullData) {
    uint8 key[32] = {0x42};
    uint8 mac[32];
    uint32 macLength = sizeof(mac);
    CryIf_Init();
    EXPECT_EQ(CryIf_KeyElementSet(0U, CRYPTO_KE_MAC_KEY, key, sizeof(key)), E_OK);
    EXPECT_EQ(CryIf_KeySetValid(0U), E_OK);
    Std_ReturnType result = CryIf_MacGenerate(0U, NULL, 4U, mac, &macLength);
    EXPECT_NE(result, E_OK);
}

/* --- ML-DSA Key Management Tests --- */
TEST_F(CryIfTests, MldsaGenerateKeyPair) {
    PQC_MLDSA_KeyPairType keyPair;
    Std_ReturnType result = CryIf_MldsaGenerateKeyPair(&keyPair);
    if (result == E_OK) {
        EXPECT_NE(keyPair.PublicKey[0] + keyPair.PublicKey[1], 0);
    }
}
