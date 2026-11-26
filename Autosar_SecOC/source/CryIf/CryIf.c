/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/

#include "CryIf/CryIf.h"
#include "Encrypt/Crypto_Mac.h"
#include "PQC/PQC.h"
#include "PQC/PQC_KeyDerivation.h"

/********************************************************************************************************/
/**************************************ForwardDeclarations***********************************************/
/********************************************************************************************************/

extern Std_ReturnType CryIf_Init(void);
extern void CryIf_DeInit(void);
extern Std_ReturnType CryIf_MacGenerate(uint32 cryIfKeyId,
                                        const uint8* dataPtr, uint32 dataLength,
                                        uint8* macPtr, uint32* macLengthPtr);
extern Std_ReturnType CryIf_MacVerify(uint32 cryIfKeyId,
                                      const uint8* dataPtr, uint32 dataLength,
                                      const uint8* macPtr, uint32 macLength,
                                      Crypto_VerifyResultType* verifyPtr);
extern Std_ReturnType CryIf_KeyElementSet(uint32 cryIfKeyId, uint32 keyElementId,
                                          const uint8* keyPtr, uint32 keyLength);
extern Std_ReturnType CryIf_KeySetValid(uint32 cryIfKeyId);
extern Std_ReturnType CryIf_SignatureGenerate(CryIf_ProviderType provider,
                                             const uint8* dataPtr, uint32 dataLength,
                                             const uint8* contextPtr, uint32 contextLength,
                                             const uint8* secretKeyPtr,
                                             uint8* signaturePtr, uint32* signatureLengthPtr);
extern Std_ReturnType CryIf_SignatureVerify(CryIf_ProviderType provider,
                                           const uint8* dataPtr, uint32 dataLength,
                                           const uint8* contextPtr, uint32 contextLength,
                                           const uint8* signaturePtr, uint32 signatureLength,
                                           const uint8* publicKeyPtr,
                                           Crypto_VerifyResultType* verifyPtr);
extern Std_ReturnType CryIf_MldsaLoadKeys(PQC_MLDSA_KeyPairType* keyPairPtr,
                                          const char* filePrefixPtr);
extern Std_ReturnType CryIf_MldsaGenerateKeyPair(PQC_MLDSA_KeyPairType* keyPairPtr);
extern Std_ReturnType CryIf_MldsaSaveKeys(const PQC_MLDSA_KeyPairType* keyPairPtr,
                                          const char* filePrefixPtr);

/* MISRA C:2012 Rule 17.3 - Cross-module forward declarations */
extern Std_ReturnType PQC_KeyDerivation_Init(void);
extern Std_ReturnType PQC_MLDSA_Sign(const uint8* Message, uint32 MessageLength,
                                     const uint8* Context, uint32 ContextLength,
                                     const uint8* SecretKey, uint8* Signature, uint32* SignatureLength);
extern Std_ReturnType PQC_MLDSA_Verify(const uint8* Message, uint32 MessageLength,
                                       const uint8* Context, uint32 ContextLength,
                                       const uint8* Signature, uint32 SignatureLength, const uint8* PublicKey);

/********************************************************************************************************/
/********************************************PublicFunctions*********************************************/
/********************************************************************************************************/

Std_ReturnType CryIf_Init(void)
{
    Std_ReturnType result;

    result = PQC_Init();
    if (result != PQC_E_OK)
    {
        return E_NOT_OK;
    }

    if (PQC_KeyDerivation_Init() != E_OK)
    {
        return E_NOT_OK;
    }

    return Crypto_Mac_Init();
}

void CryIf_DeInit(void)
{
    /* the session key objects are erased by Csm_DeInit; here the MAC keys of the crypto driver are dropped */
    (void)Crypto_Mac_Init();
}

/* [SWS_CryIf_00044], [SWS_CryIf_00055], [SWS_CryIf_00058]: forwarded to the crypto driver, return value
 * passed on. CryIf key ids of the MAC keys are the driver's key ids. */
Std_ReturnType CryIf_MacGenerate(
    uint32 cryIfKeyId,
    const uint8* dataPtr,
    uint32 dataLength,
    uint8* macPtr,
    uint32* macLengthPtr)
{
    return Crypto_Mac_Generate(cryIfKeyId, dataPtr, dataLength, macPtr, macLengthPtr);
}

Std_ReturnType CryIf_MacVerify(
    uint32 cryIfKeyId,
    const uint8* dataPtr,
    uint32 dataLength,
    const uint8* macPtr,
    uint32 macLength,
    Crypto_VerifyResultType* verifyPtr)
{
    return Crypto_Mac_Verify(cryIfKeyId, dataPtr, dataLength, macPtr, macLength, verifyPtr);
}

Std_ReturnType CryIf_KeyElementSet(uint32 cryIfKeyId, uint32 keyElementId, const uint8* keyPtr, uint32 keyLength)
{
    return Crypto_Mac_KeyElementSet(cryIfKeyId, keyElementId, keyPtr, keyLength);
}

Std_ReturnType CryIf_KeySetValid(uint32 cryIfKeyId)
{
    return Crypto_Mac_KeySetValid(cryIfKeyId);
}

Std_ReturnType CryIf_SignatureGenerate(
    CryIf_ProviderType provider,
    const uint8* dataPtr,
    uint32 dataLength,
    const uint8* contextPtr,
    uint32 contextLength,
    const uint8* secretKeyPtr,
    uint8* signaturePtr,
    uint32* signatureLengthPtr)
{
    if ((provider != CRYIF_PROVIDER_PQC) ||
        (dataPtr == NULL) ||
        (secretKeyPtr == NULL) ||
        (signaturePtr == NULL) ||
        (signatureLengthPtr == NULL))
    {
        return E_NOT_OK;
    }

    if (PQC_MLDSA_Sign(dataPtr, dataLength, contextPtr, contextLength, secretKeyPtr, signaturePtr, signatureLengthPtr) != PQC_E_OK)
    {
        return E_NOT_OK;
    }

    return E_OK;
}

Std_ReturnType CryIf_SignatureVerify(
    CryIf_ProviderType provider,
    const uint8* dataPtr,
    uint32 dataLength,
    const uint8* contextPtr,
    uint32 contextLength,
    const uint8* signaturePtr,
    uint32 signatureLength,
    const uint8* publicKeyPtr,
    Crypto_VerifyResultType* verifyPtr)
{
    Std_ReturnType driverResult;

    if (verifyPtr == NULL)
    {
        return E_NOT_OK;
    }
    *verifyPtr = CRYPTO_E_VER_NOT_OK;

    if ((provider != CRYIF_PROVIDER_PQC) ||
        (dataPtr == NULL) ||
        (signaturePtr == NULL) ||
        (publicKeyPtr == NULL))
    {
        return E_NOT_OK;
    }

    driverResult = PQC_MLDSA_Verify(dataPtr, dataLength, contextPtr, contextLength, signaturePtr, signatureLength, publicKeyPtr);
    if (driverResult == PQC_E_OK)
    {
        *verifyPtr = CRYPTO_E_VER_OK;
        return E_OK;
    }
    /* the driver verified and the signature is not valid: the request succeeded, the verdict is negative */
    return (driverResult == PQC_E_VERIFY_FAILED) ? E_OK : E_NOT_OK;
}

Std_ReturnType CryIf_MldsaLoadKeys(PQC_MLDSA_KeyPairType* keyPairPtr, const char* filePrefixPtr)
{
    return PQC_MLDSA_LoadKeys(keyPairPtr, filePrefixPtr);
}

Std_ReturnType CryIf_MldsaGenerateKeyPair(PQC_MLDSA_KeyPairType* keyPairPtr)
{
    return PQC_MLDSA_KeyGen(keyPairPtr);
}

Std_ReturnType CryIf_MldsaSaveKeys(const PQC_MLDSA_KeyPairType* keyPairPtr, const char* filePrefixPtr)
{
    return PQC_MLDSA_SaveKeys(keyPairPtr, filePrefixPtr);
}
