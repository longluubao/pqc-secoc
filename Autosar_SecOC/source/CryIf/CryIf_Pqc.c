/********************************************************************************************************/
/*  CryIf: ML-KEM-768 and HKDF primitives of the crypto driver for the Csm custom-service jobs.           */
/*  Forwarded to the driver, return value passed on.                                                      */
/********************************************************************************************************/

#include "CryIf/CryIf.h"

Std_ReturnType CryIf_KemKeyGen(uint8* publicKeyPtr, uint8* secretKeyPtr)
{
    return PQC_MLKEM_KeyGen(publicKeyPtr, secretKeyPtr);
}

Std_ReturnType CryIf_KemEncapsulate(const uint8* publicKeyPtr, uint8* ciphertextPtr, uint8* sharedSecretPtr)
{
    return PQC_MLKEM_Encapsulate(publicKeyPtr, ciphertextPtr, sharedSecretPtr);
}

Std_ReturnType CryIf_KemDecapsulate(const uint8* ciphertextPtr, const uint8* secretKeyPtr, uint8* sharedSecretPtr)
{
    return PQC_MLKEM_Decapsulate(ciphertextPtr, secretKeyPtr, sharedSecretPtr);
}

Std_ReturnType CryIf_HkdfExtract(const uint8* saltPtr, uint32 saltLength, const uint8* ikmPtr, uint32 ikmLength, uint8* prkPtr)
{
    return PQC_Hkdf_Extract(saltPtr, saltLength, ikmPtr, ikmLength, prkPtr);
}

Std_ReturnType CryIf_HkdfExpand(const uint8* prkPtr, const uint8* infoPtr, uint32 infoLength, uint8* okmPtr, uint32 okmLength)
{
    return PQC_Hkdf_Expand(prkPtr, infoPtr, infoLength, okmPtr, okmLength);
}
