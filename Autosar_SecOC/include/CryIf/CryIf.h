#ifndef INCLUDE_CRYIF_H_
#define INCLUDE_CRYIF_H_

/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/

#include "Std_Types.h"
#include "Encrypt/Crypto_GeneralTypes.h"
#include "PQC/PQC.h"
#include "PQC/PQC_KeyDerivation.h"

/********************************************************************************************************/
/*********************************************DefinesAndEnums********************************************/
/********************************************************************************************************/

#define CRYIF_MAX_PEERS                 PQC_MAX_PEERS
#define CRYIF_MLDSA_PUBLIC_KEY_BYTES    PQC_MLDSA_PUBLIC_KEY_BYTES
#define CRYIF_MLDSA_SECRET_KEY_BYTES    PQC_MLDSA_SECRET_KEY_BYTES
#define CRYIF_MLDSA_SIGNATURE_BYTES     PQC_MLDSA_SIGNATURE_BYTES
#define CRYIF_MLKEM_PUBLIC_KEY_BYTES    PQC_MLKEM_PUBLIC_KEY_BYTES
#define CRYIF_MLKEM_CIPHERTEXT_BYTES    PQC_MLKEM_CIPHERTEXT_BYTES
#define CRYIF_MLKEM_SHARED_SECRET_BYTES PQC_MLKEM_SHARED_SECRET_BYTES
#define CRYIF_DERIVED_KEY_LENGTH        PQC_DERIVED_KEY_LENGTH

typedef enum
{
    CRYIF_PROVIDER_PQC = 1U
} CryIf_ProviderType;

/********************************************************************************************************/
/*****************************************FunctionPrototype**********************************************/
/********************************************************************************************************/

Std_ReturnType CryIf_Init(void);
void CryIf_DeInit(void);

/* MAC services and their keys in the crypto driver; lengths as in Csm_MacGenerate / Csm_MacVerify */
Std_ReturnType CryIf_MacGenerate(
    uint32 cryIfKeyId,
    const uint8* dataPtr,
    uint32 dataLength,
    uint8* macPtr,
    uint32* macLengthPtr);

Std_ReturnType CryIf_MacVerify(
    uint32 cryIfKeyId,
    const uint8* dataPtr,
    uint32 dataLength,
    const uint8* macPtr,
    uint32 macLength,
    Crypto_VerifyResultType* verifyPtr);

/* [SWS_CryIf_91004], [SWS_CryIf_91005] */
Std_ReturnType CryIf_KeyElementSet(uint32 cryIfKeyId, uint32 keyElementId, const uint8* keyPtr, uint32 keyLength);
Std_ReturnType CryIf_KeySetValid(uint32 cryIfKeyId);

/* contextPtr / contextLength: FIPS 204 context string of the job (job data, no SWS parameter) */
Std_ReturnType CryIf_SignatureGenerate(
    CryIf_ProviderType provider,
    const uint8* dataPtr,
    uint32 dataLength,
    const uint8* contextPtr,
    uint32 contextLength,
    const uint8* secretKeyPtr,
    uint8* signaturePtr,
    uint32* signatureLengthPtr);

/* E_OK: the verification ran, its verdict is in *verifyPtr (CRYPTO_E_VER_OK or CRYPTO_E_VER_NOT_OK).
 * E_NOT_OK: it could not run (provider, parameters, driver not initialised); *verifyPtr is
 * CRYPTO_E_VER_NOT_OK then. */
Std_ReturnType CryIf_SignatureVerify(
    CryIf_ProviderType provider,
    const uint8* dataPtr,
    uint32 dataLength,
    const uint8* contextPtr,
    uint32 contextLength,
    const uint8* signaturePtr,
    uint32 signatureLength,
    const uint8* publicKeyPtr,
    Crypto_VerifyResultType* verifyPtr);

/* ML-KEM-768 and HKDF primitives of the crypto driver, used by the custom-service jobs. Keys are
 * written in place into the caller's key element storage. */
Std_ReturnType CryIf_KemKeyGen(uint8* publicKeyPtr, uint8* secretKeyPtr);
Std_ReturnType CryIf_KemEncapsulate(const uint8* publicKeyPtr, uint8* ciphertextPtr, uint8* sharedSecretPtr);
Std_ReturnType CryIf_KemDecapsulate(const uint8* ciphertextPtr, const uint8* secretKeyPtr, uint8* sharedSecretPtr);
Std_ReturnType CryIf_HkdfExtract(const uint8* saltPtr, uint32 saltLength, const uint8* ikmPtr, uint32 ikmLength, uint8* prkPtr);
Std_ReturnType CryIf_HkdfExpand(const uint8* prkPtr, const uint8* infoPtr, uint32 infoLength, uint8* okmPtr, uint32 okmLength);

Std_ReturnType CryIf_MldsaLoadKeys(PQC_MLDSA_KeyPairType* keyPairPtr, const char* filePrefixPtr);
Std_ReturnType CryIf_MldsaGenerateKeyPair(PQC_MLDSA_KeyPairType* keyPairPtr);
Std_ReturnType CryIf_MldsaSaveKeys(const PQC_MLDSA_KeyPairType* keyPairPtr, const char* filePrefixPtr);

#endif
