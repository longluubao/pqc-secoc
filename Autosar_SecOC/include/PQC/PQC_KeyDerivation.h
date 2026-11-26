/********************************************************************************************************/
/*******************************************PQC_KeyDerivation.h*******************************************/
/********************************************************************************************************/
/**
 * @file PQC_KeyDerivation.h
 * @brief Key Derivation Functions for PQC Shared Secrets
 * @details Implements HKDF (HMAC-based Key Derivation Function) to derive
 *          session keys from ML-KEM shared secrets for AUTOSAR SecOC
 */

#ifndef PQC_KEYDERIVATION_H
#define PQC_KEYDERIVATION_H

/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/
#include "Std_Types.h"
#include "PQC.h"

/********************************************************************************************************/
/***********************************************DEFINES***************************************************/
/********************************************************************************************************/

#define PQC_DERIVED_KEY_LENGTH      32U     /* 256-bit keys */

/**
 * @brief Initialize the Key Derivation Module (creates the KDF context)
 * @return E_OK if successful, E_NOT_OK otherwise
 */
Std_ReturnType PQC_KeyDerivation_Init(void);

/********************************************************************************************************/
/*  HKDF with HMAC-SHA-256 (RFC 5869), the two steps separately. Every OpenSSL return value is checked;   */
/*  on failure the output is erased and E_NOT_OK returned.                                                */
/********************************************************************************************************/
#define PQC_HKDF_PRK_BYTES          32U

/* PRK = HKDF-Extract(Salt, Ikm); Prk has PQC_HKDF_PRK_BYTES. A NULL salt of length 0 is the empty salt. */
Std_ReturnType PQC_Hkdf_Extract(
    const uint8* Salt,
    uint32 SaltLength,
    const uint8* Ikm,
    uint32 IkmLength,
    uint8* Prk
);

/* OKM = HKDF-Expand(Prk, Info, OkmLength); Prk has PQC_HKDF_PRK_BYTES. */
Std_ReturnType PQC_Hkdf_Expand(
    const uint8* Prk,
    const uint8* Info,
    uint32 InfoLength,
    uint8* Okm,
    uint32 OkmLength
);

#endif /* PQC_KEYDERIVATION_H */
