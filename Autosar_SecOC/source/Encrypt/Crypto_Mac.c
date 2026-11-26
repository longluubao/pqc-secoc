/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/

#include "Crypto_Mac.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

/********************************************************************************************************/
/******************************************GlobalVaribles************************************************/
/********************************************************************************************************/

typedef struct
{
    EVP_MAC_CTX* Ctx;                               /* created by Crypto_Mac_Init, holds the key schedule */
    uint8        Key[CRYPTO_MAC_KEY_MAX_BYTES];     /* key element 1 [SWS_Csm_01022] */
    uint32       KeyLength;                         /* bytes written; 0: no key material */
    boolean      Valid;                             /* [SWS_Crypto_00038] */
} Crypto_Mac_KeyType;

static Crypto_Mac_KeyType Crypto_Mac_Keys[CRYPTO_MAC_NUM_KEYS];

/********************************************************************************************************/
/****************************************StaticFunctions*************************************************/
/********************************************************************************************************/

/* The complete tag of one message. The context was keyed when the key element was written; a NULL
 * key starts the next message under the same key, so no context is created per call. */
static Std_ReturnType Crypto_Mac_Compute(const Crypto_Mac_KeyType* keyPtr, const uint8* dataPtr, uint32 dataLength, uint8* tagPtr)
{
    size_t tagLength = 0U;

    if ((EVP_MAC_init(keyPtr->Ctx, NULL, 0U, NULL) != 1) ||
        (EVP_MAC_update(keyPtr->Ctx, dataPtr, (size_t)dataLength) != 1) ||
        (EVP_MAC_final(keyPtr->Ctx, tagPtr, &tagLength, CRYPTO_MAC_RESULT_BYTES) != 1) ||
        (tagLength != CRYPTO_MAC_RESULT_BYTES))
    {
        return E_NOT_OK;
    }

    return E_OK;
}

/********************************************************************************************************/
/********************************************PublicFunctions*********************************************/
/********************************************************************************************************/

Std_ReturnType Crypto_Mac_Init(void)
{
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    Std_ReturnType result = (mac != NULL) ? E_OK : E_NOT_OK;
    uint32 keyId;

    for (keyId = 0U; keyId < CRYPTO_MAC_NUM_KEYS; keyId++)
    {
        /* freeing the context erases the key schedule it holds */
        EVP_MAC_CTX_free(Crypto_Mac_Keys[keyId].Ctx);
        OPENSSL_cleanse(Crypto_Mac_Keys[keyId].Key, sizeof(Crypto_Mac_Keys[keyId].Key));
        Crypto_Mac_Keys[keyId].KeyLength = 0U;
        Crypto_Mac_Keys[keyId].Valid = FALSE;
        Crypto_Mac_Keys[keyId].Ctx = (mac != NULL) ? EVP_MAC_CTX_new(mac) : NULL;
        if (Crypto_Mac_Keys[keyId].Ctx == NULL)
        {
            result = E_NOT_OK;
        }
    }
    EVP_MAC_free(mac);

    return result;
}

Std_ReturnType Crypto_Mac_KeyElementSet(uint32 cryptoKeyId, uint32 keyElementId, const uint8* keyPtr, uint32 keyLength)
{
    Crypto_Mac_KeyType* key;
    char digest[] = "SHA256";
    OSSL_PARAM params[2];

    if ((cryptoKeyId >= CRYPTO_MAC_NUM_KEYS) || (keyElementId != CRYPTO_KE_MAC_KEY) || (keyPtr == NULL) ||
        (Crypto_Mac_Keys[cryptoKeyId].Ctx == NULL))
    {
        return E_NOT_OK;
    }
    if ((keyLength == 0U) || (keyLength > CRYPTO_MAC_KEY_MAX_BYTES))
    {
        return CRYPTO_E_KEY_SIZE_MISMATCH;
    }

    key = &Crypto_Mac_Keys[cryptoKeyId];
    key->Valid = FALSE;
    OPENSSL_cleanse(key->Key, sizeof(key->Key));
    (void)memcpy(key->Key, keyPtr, keyLength);
    key->KeyLength = keyLength;

    /* keying the context here replaces the previous key inside OpenSSL as well */
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0U);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(key->Ctx, key->Key, (size_t)keyLength, params) != 1)
    {
        /* the context may still hold the previous key or part of the new one: freeing it erases
         * that; without a context the slot takes no key until the next Crypto_Mac_Init */
        EVP_MAC_CTX* fresh = EVP_MAC_CTX_new(EVP_MAC_CTX_get0_mac(key->Ctx));
        EVP_MAC_CTX_free(key->Ctx);
        key->Ctx = fresh;
        OPENSSL_cleanse(key->Key, sizeof(key->Key));
        key->KeyLength = 0U;
        return E_NOT_OK;
    }

    return E_OK;
}

Std_ReturnType Crypto_Mac_KeySetValid(uint32 cryptoKeyId)
{
    if ((cryptoKeyId >= CRYPTO_MAC_NUM_KEYS) || (Crypto_Mac_Keys[cryptoKeyId].KeyLength == 0U))
    {
        return E_NOT_OK;
    }

    Crypto_Mac_Keys[cryptoKeyId].Valid = TRUE;
    return E_OK;
}

Std_ReturnType Crypto_Mac_Generate(uint32 cryptoKeyId, const uint8* dataPtr, uint32 dataLength,
                                   uint8* macPtr, uint32* macLengthPtr)
{
    uint8 tag[CRYPTO_MAC_RESULT_BYTES];
    Std_ReturnType result;

    if ((cryptoKeyId >= CRYPTO_MAC_NUM_KEYS) || (dataPtr == NULL) || (macPtr == NULL) || (macLengthPtr == NULL) ||
        (*macLengthPtr == 0U))
    {
        return E_NOT_OK;
    }
    /* [SWS_Crypto_00039] */
    if (Crypto_Mac_Keys[cryptoKeyId].Valid == FALSE)
    {
        return CRYPTO_E_KEY_NOT_VALID;
    }

    result = Crypto_Mac_Compute(&Crypto_Mac_Keys[cryptoKeyId], dataPtr, dataLength, tag);
    if (result == E_OK)
    {
        if (*macLengthPtr > CRYPTO_MAC_RESULT_BYTES)
        {
            *macLengthPtr = CRYPTO_MAC_RESULT_BYTES;
        }
        (void)memcpy(macPtr, tag, *macLengthPtr);
    }
    OPENSSL_cleanse(tag, sizeof(tag));

    return result;
}

Std_ReturnType Crypto_Mac_Verify(uint32 cryptoKeyId, const uint8* dataPtr, uint32 dataLength,
                                 const uint8* macPtr, uint32 macLength, Crypto_VerifyResultType* verifyPtr)
{
    uint8 tag[CRYPTO_MAC_RESULT_BYTES];
    Std_ReturnType result;

    if (verifyPtr == NULL)
    {
        return E_NOT_OK;
    }
    *verifyPtr = CRYPTO_E_VER_NOT_OK;

    if ((cryptoKeyId >= CRYPTO_MAC_NUM_KEYS) || (dataPtr == NULL) || (macPtr == NULL) ||
        (macLength == 0U) || ((macLength % 8U) != 0U) || (macLength > (CRYPTO_MAC_RESULT_BYTES * 8U)))
    {
        return E_NOT_OK;
    }
    /* [SWS_Crypto_00039] */
    if (Crypto_Mac_Keys[cryptoKeyId].Valid == FALSE)
    {
        return CRYPTO_E_KEY_NOT_VALID;
    }

    result = Crypto_Mac_Compute(&Crypto_Mac_Keys[cryptoKeyId], dataPtr, dataLength, tag);
    /* CRYPTO_memcmp: the comparison time does not show where the tags differ */
    if ((result == E_OK) && (CRYPTO_memcmp(tag, macPtr, (size_t)(macLength / 8U)) == 0))
    {
        *verifyPtr = CRYPTO_E_VER_OK;
    }
    OPENSSL_cleanse(tag, sizeof(tag));

    return result;
}

#ifdef SECOC_TEST_ACCESS
void Crypto_Mac_TestStorage(const uint8** storagePtr, uint32* lengthPtr)
{
    *storagePtr = (const uint8*)Crypto_Mac_Keys;
    *lengthPtr = (uint32)sizeof(Crypto_Mac_Keys);
}
#endif
