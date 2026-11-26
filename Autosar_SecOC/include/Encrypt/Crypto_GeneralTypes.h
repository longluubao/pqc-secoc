#ifndef INCLUDE_CRYPTO_GENERALTYPES_H_
#define INCLUDE_CRYPTO_GENERALTYPES_H_

/********************************************************************************************************/
/*  Types the Csm, the CryIf and the crypto driver share (SWS Csm: "available via                         */
/*  Crypto_GeneralTypes.h"). Only what this stack uses; the values are the ones the SWS prints.           */
/********************************************************************************************************/

#include "Std_Types.h"

/* [SWS_Csm_91043] */
#define CRYPTO_E_KEY_NOT_VALID      ((Std_ReturnType)0x09)
#define CRYPTO_E_KEY_SIZE_MISMATCH  ((Std_ReturnType)0x0A)
#define CRYPTO_E_KEY_EMPTY          ((Std_ReturnType)0x0D)

/* [SWS_Csm_01024] */
typedef enum
{
    CRYPTO_E_VER_OK = 0x00,
    CRYPTO_E_VER_NOT_OK = 0x01
}Crypto_VerifyResultType;

/* [SWS_Csm_01031] */
typedef enum
{
    CRYPTO_MACGENERATE = 0x01,
    CRYPTO_MACVERIFY = 0x02,
    CRYPTO_SIGNATUREGENERATE = 0x07,
    CRYPTO_SIGNATUREVERIFY = 0x08
} Crypto_ServiceInfoType;

/* [SWS_Csm_01047] */
typedef enum
{
    CRYPTO_ALGOFAM_SHA2_256 = 0x03
} Crypto_AlgorithmFamilyType;

/* [SWS_Csm_01048] */
typedef enum
{
    CRYPTO_ALGOMODE_HMAC = 0x0f
} Crypto_AlgorithmModeType;

/* [SWS_Csm_01022] key material of a MAC key */
#define CRYPTO_KE_MAC_KEY           ((uint32)1U)

#endif
