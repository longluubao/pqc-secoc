/********************************************************************************************************/
/*******************************************PQC_KeyDerivation.c*******************************************/
/********************************************************************************************************/
/**
 * @file PQC_KeyDerivation.c
 * @brief HKDF with HMAC-SHA-256 (RFC 5869) through the OpenSSL KDF interface
 */

/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/
#include "PQC_KeyDerivation.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>

/********************************************************************************************************/
/******************************************GLOBAL VARIABLES**********************************************/
/********************************************************************************************************/
/* Created once in PQC_KeyDerivation_Init; reset after every derivation, which erases its copy of the key. */
static EVP_KDF_CTX* PQC_HkdfCtx = NULL;

/********************************************************************************************************/
/**********************************************FUNCTIONS**************************************************/
/********************************************************************************************************/

/**
 * @brief Initialize the Key Derivation Module
 */
Std_ReturnType PQC_KeyDerivation_Init(void)
{
    if (PQC_HkdfCtx == NULL)
    {
        EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
        if (kdf != NULL)
        {
            PQC_HkdfCtx = EVP_KDF_CTX_new(kdf);
            EVP_KDF_free(kdf);
        }
    }
    if (PQC_HkdfCtx == NULL)
    {
        (void)printf("ERROR: HKDF is not available in OpenSSL\n");
        return E_NOT_OK;
    }

    return E_OK;
}

/**
 * @brief One HKDF step (RFC 5869) with HMAC-SHA-256 through the OpenSSL KDF interface
 */
static Std_ReturnType PQC_Hkdf_Step(
    int Mode,
    const uint8* Key, uint32 KeyLength,
    const char* DataName, const uint8* Data, uint32 DataLength,
    uint8* Out, uint32 OutLength)
{
    static const uint8 empty = 0U;
    static char digest[] = "SHA256";
    OSSL_PARAM params[5];
    int mode = Mode;
    Std_ReturnType result = E_NOT_OK;

    if ((PQC_HkdfCtx == NULL) || (Key == NULL) || (Out == NULL) || (OutLength == 0U) ||
        ((Data == NULL) && (DataLength > 0U)))
    {
        return E_NOT_OK;
    }

    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0U);
    /* the parameter interface is not const-correct: the key and data are only read */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)(uintptr_t)Key, (size_t)KeyLength);
    params[3] = OSSL_PARAM_construct_octet_string(DataName,
                                                  (void*)(uintptr_t)((Data != NULL) ? Data : &empty),
                                                  (size_t)DataLength);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(PQC_HkdfCtx, Out, (size_t)OutLength, params) == 1)
    {
        result = E_OK;
    }
    else
    {
        OPENSSL_cleanse(Out, (size_t)OutLength);
    }

    EVP_KDF_CTX_reset(PQC_HkdfCtx);
    return result;
}

Std_ReturnType PQC_Hkdf_Extract(
    const uint8* Salt,
    uint32 SaltLength,
    const uint8* Ikm,
    uint32 IkmLength,
    uint8* Prk)
{
    return PQC_Hkdf_Step(EVP_KDF_HKDF_MODE_EXTRACT_ONLY, Ikm, IkmLength,
                         OSSL_KDF_PARAM_SALT, Salt, SaltLength, Prk, PQC_HKDF_PRK_BYTES);
}

Std_ReturnType PQC_Hkdf_Expand(
    const uint8* Prk,
    const uint8* Info,
    uint32 InfoLength,
    uint8* Okm,
    uint32 OkmLength)
{
    return PQC_Hkdf_Step(EVP_KDF_HKDF_MODE_EXPAND_ONLY, Prk, PQC_HKDF_PRK_BYTES,
                         OSSL_KDF_PARAM_INFO, Info, InfoLength, Okm, OkmLength);
}
