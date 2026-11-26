#ifndef INCLUDE_CRYPTO_MAC_H_
#define INCLUDE_CRYPTO_MAC_H_

/********************************************************************************************************/
/*  Crypto driver primitive for the MAC services: HMAC-SHA-256 (OpenSSL EVP_MAC) and its key store.       */
/*  The driver functions are called by the CryIf only.                                                    */
/********************************************************************************************************/

#include "Std_Types.h"
#include "Crypto_GeneralTypes.h"

/* per peer of the Csm (CSM_MAC_NUM_PEERS, 2): send key, receive key, key-confirmation slot */
#define CRYPTO_MAC_NUM_KEYS         (6U)
/* CryptoKeyElementSize of key element 1; shorter key material may be written */
#define CRYPTO_MAC_KEY_MAX_BYTES    (32U)
#define CRYPTO_MAC_RESULT_BYTES     (32U)

/* Creates the MAC contexts. Called again, it drops every key. */
Std_ReturnType Crypto_Mac_Init(void);

/* SWS Crypto 7.2.4: writing the key element makes the key invalid until Crypto_Mac_KeySetValid */
Std_ReturnType Crypto_Mac_KeyElementSet(uint32 cryptoKeyId, uint32 keyElementId, const uint8* keyPtr, uint32 keyLength);
Std_ReturnType Crypto_Mac_KeySetValid(uint32 cryptoKeyId);

/* [SWS_Crypto_00065] *macLengthPtr: buffer size in bytes on call, bytes written on return; a buffer
 * shorter than the tag gets its most significant bytes */
Std_ReturnType Crypto_Mac_Generate(uint32 cryptoKeyId, const uint8* dataPtr, uint32 dataLength,
                                   uint8* macPtr, uint32* macLengthPtr);

/* macLength in bits, whole bytes only. E_OK means the comparison was made; its outcome is *verifyPtr */
Std_ReturnType Crypto_Mac_Verify(uint32 cryptoKeyId, const uint8* dataPtr, uint32 dataLength,
                                 const uint8* macPtr, uint32 macLength, Crypto_VerifyResultType* verifyPtr);

#ifdef SECOC_TEST_ACCESS
/* Tests only (not in a gateway build): where the static key table is, to search it for key bytes. */
void Crypto_Mac_TestStorage(const uint8** storagePtr, uint32* lengthPtr);
#endif

#endif
