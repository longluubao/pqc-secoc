#ifndef INCLUDE_CSM_H_
#define INCLUDE_CSM_H_

/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/

#include "Std_Types.h"
#include "SecOC/SecOC_Debug.h"
#include "CryIf/CryIf.h"


/********************************************************************************************************/
/*********************************************DefinesAndEnums********************************************/
/********************************************************************************************************/

#define CRYPTO_E_QUEUE_FULL         (QUEUE_FULL)

/* one context per job ID in use: the MAC jobs of two peers (8) next to the signature and handshake jobs */
#define CSM_MAX_JOB_CONTEXTS        ((uint8)32U)
#define CSM_MAX_JOB_QUEUE           ((uint8)16U)
#define CSM_MAX_STREAM_BUFFER       ((uint32)4096U)
#define CSM_MAX_KEY_ELEMENTS        ((uint8)16U)

#define CSM_MAX_PEERS                 CRYIF_MAX_PEERS
#define CSM_MLDSA_PUBLIC_KEY_BYTES    CRYIF_MLDSA_PUBLIC_KEY_BYTES
#define CSM_MLDSA_SECRET_KEY_BYTES    CRYIF_MLDSA_SECRET_KEY_BYTES
#define CSM_MLDSA_SIGNATURE_BYTES     CRYIF_MLDSA_SIGNATURE_BYTES
#define CSM_MLKEM_PUBLIC_KEY_BYTES    CRYIF_MLKEM_PUBLIC_KEY_BYTES
#define CSM_MLKEM_CIPHERTEXT_BYTES    CRYIF_MLKEM_CIPHERTEXT_BYTES
#define CSM_MLKEM_SHARED_SECRET_BYTES CRYIF_MLKEM_SHARED_SECRET_BYTES
#define CSM_DERIVED_KEY_LENGTH        CRYIF_DERIVED_KEY_LENGTH

#define CSM_MLDSA_KEY_PREFIX        ("mldsa_secoc")

#define CSM_MLDSA_KEY_PREFIX_LOCAL          ("mldsa_local")
#define CSM_MLDSA_KEY_PREFIX_PEER_FORMAT    ("mldsa_peer%u")

#define CSM_KEYID_MLDSA_LOCAL       ((uint32)1U)
#define CSM_KEYID_SESSION_BASE      ((uint32)100U)
#define CSM_KEYID_PEER_PUBKEY_BASE          ((uint32)200U)
#define CSM_KEYID_IS_PEER_PUBKEY(id)        (((id) >= CSM_KEYID_PEER_PUBKEY_BASE) && \
                                             ((id) < (CSM_KEYID_PEER_PUBKEY_BASE + (uint32)CSM_MAX_PEERS)))
#define CSM_PEER_FROM_PUBKEY_KEYID(id)      ((uint8)((id) - CSM_KEYID_PEER_PUBKEY_BASE))

#define CSM_KEYELEMENT_MLDSA_PUBLIC ((uint32)1U)
#define CSM_KEYELEMENT_MLDSA_SECRET ((uint32)2U)
#define CSM_KEYELEMENT_MLDSA_PEER_PUBLIC    ((uint32)5U)

#define CSM_JOBID_VERIFY_PEER_BASE          ((uint32)0x2000U)
#define CSM_JOBID_IS_VERIFY_PEER(id)        (((id) >= CSM_JOBID_VERIFY_PEER_BASE) && \
                                             ((id) < (CSM_JOBID_VERIFY_PEER_BASE + (uint32)CSM_MAX_PEERS)))
#define CSM_PEER_FROM_VERIFY_JOBID(id)      ((uint8)((id) - CSM_JOBID_VERIFY_PEER_BASE))

/* MAC jobs (HMAC-SHA-256) and their keys, key element CRYPTO_KE_MAC_KEY, for each peer p below
 * CSM_MAC_NUM_PEERS: one key for the PDUs this node sends to the peer, one for the PDUs it receives
 * from it, and the key-confirmation slot of the handshake, which no SecOC job refers to. Each key has
 * its fixed jobs: generate -> send key, verify -> receive key (128-bit compare length), and a
 * generate and a verify job on the confirmation slot (complete tag, 256-bit compare length).
 * No key material exists until it is installed with Csm_KeyElementSet and Csm_KeySetValid. */
#define CSM_MAC_NUM_PEERS                   (2U)
#define CSM_KEYID_MAC_TX_PEER(p)            ((uint32)(300U + (10U * (p))))
#define CSM_KEYID_MAC_RX_PEER(p)            ((uint32)(301U + (10U * (p))))
#define CSM_KEYID_HS_KC_PEER(p)             ((uint32)(302U + (10U * (p))))
#define CSM_JOBID_MAC_GENERATE_PEER(p)      ((uint32)(20U + (4U * (p))))
#define CSM_JOBID_MAC_VERIFY_PEER(p)        ((uint32)(21U + (4U * (p))))
#define CSM_JOBID_HS_KC_GENERATE_PEER(p)    ((uint32)(22U + (4U * (p))))
#define CSM_JOBID_HS_KC_VERIFY_PEER(p)      ((uint32)(23U + (4U * (p))))
/* peer 0, the one peer of the evaluated set-up */
#define CSM_JOBID_MAC_GENERATE              CSM_JOBID_MAC_GENERATE_PEER(0U)
#define CSM_JOBID_MAC_VERIFY                CSM_JOBID_MAC_VERIFY_PEER(0U)
#define CSM_JOBID_HS_KC_GENERATE            CSM_JOBID_HS_KC_GENERATE_PEER(0U)
#define CSM_JOBID_HS_KC_VERIFY              CSM_JOBID_HS_KC_VERIFY_PEER(0U)
#define CSM_KEYID_MAC_TX                    CSM_KEYID_MAC_TX_PEER(0U)
#define CSM_KEYID_MAC_RX                    CSM_KEYID_MAC_RX_PEER(0U)
#define CSM_KEYID_HS_KC                     CSM_KEYID_HS_KC_PEER(0U)

/* Crypto operation modes (AUTOSAR SWS_Csm) */
typedef enum
{
    CRYPTO_OPERATIONMODE_START = 0x01,
    CRYPTO_OPERATIONMODE_UPDATE = 0x02,
    CRYPTO_OPERATIONMODE_FINISH = 0x04
    ,
    CRYPTO_OPERATIONMODE_SINGLECALL = 0x07
}Crypto_OperationModeType;

typedef enum
{
    CSM_JOBSTATE_IDLE = 0,
    CSM_JOBSTATE_ACTIVE,
    CSM_JOBSTATE_QUEUED
} Csm_JobStateType;

typedef uint8 Csm_PeerIdType;

typedef enum
{
    CSM_MLDSA_BOOTSTRAP_DEMO_FILE_AUTO = 0U,
    CSM_MLDSA_BOOTSTRAP_FILE_STRICT = 1U,
    CSM_MLDSA_BOOTSTRAP_PROVISIONED = 2U,
    CSM_MLDSA_BOOTSTRAP_HSM_HANDLE = 3U
} Csm_MldsaBootstrapModeType;

typedef Std_ReturnType (*Csm_LoadProvisionedMldsaKeysFctType)(
    uint8* publicKeyPtr,
    uint32 publicKeyLength,
    uint8* secretKeyPtr,
    uint32 secretKeyLength);

typedef struct
{
    Csm_MldsaBootstrapModeType CsmMldsaBootstrapMode;
    Csm_LoadProvisionedMldsaKeysFctType CsmLoadProvisionedMldsaKeysFct;
} Csm_ConfigType;

typedef void (*Csm_JobCallbackType)(
    uint32 jobId,
    Std_ReturnType result,
    void* callbackContextPtr);


/********************************************************************************************************/
/*****************************************FunctionPrototype**********************************************/
/********************************************************************************************************/

void Csm_Init(const Csm_ConfigType* configPtr);
void Csm_DeInit(void);
void Csm_MainFunction(void);
void Csm_GetVersionInfo(Std_VersionInfoType* versioninfo);
Std_ReturnType Csm_RegisterJobCallback(uint32 jobId, Csm_JobCallbackType callbackFct, void* callbackContextPtr);
Std_ReturnType Csm_GetJobResult(uint32 jobId, Std_ReturnType* resultPtr, boolean* completedPtr);

Std_ReturnType Csm_MacGenerate ( 
    uint32 jobId, 
    Crypto_OperationModeType mode,
    const uint8* dataPtr,
    uint32 dataLength,
    uint8* macPtr,
    uint32* macLengthPtr );

/*******************************************************
 *          * Function Info *                           *
 *                                                      *
 * Function_Name        : Csm_MacVerify                 *
 * Function_Index       : 8.3.3.2 [SWS_Csm_01050]       *
 * Function_File        : SWS of CSM                    *
 * Function_Descripton  : Verifies the given MAC by     *
 * SecOC to obtain the current freshness value          *
 * comparing if the MAC is generated with the given data*
 *******************************************************/

Std_ReturnType Csm_MacVerify(
uint32 jobId,
Crypto_OperationModeType mode,
const uint8* dataPtr,
uint32 dataLength,
const uint8* macPtr,
uint32 macLength,
Crypto_VerifyResultType* verifyPtr
);

/*******************************************************
 *          * Function Info *                           *
 *                                                      *
 * Function_Name        : Csm_SignatureGenerate         *
 * Function_Descripton  : Generates a digital signature *
 * using ML-DSA-65 post-quantum algorithm               *
 *******************************************************/
Std_ReturnType Csm_SignatureGenerate(
    uint32 jobId,
    Crypto_OperationModeType mode,
    const uint8* dataPtr,
    uint32 dataLength,
    uint8* signaturePtr,
    uint32* signatureLengthPtr
);

/*******************************************************
 *          * Function Info *                           *
 *                                                      *
 * Function_Name        : Csm_SignatureVerify           *
 * Function_Descripton  : Verifies a digital signature  *
 * using ML-DSA-65 post-quantum algorithm               *
 *******************************************************/
Std_ReturnType Csm_SignatureVerify(
    uint32 jobId,
    Crypto_OperationModeType mode,
    const uint8* dataPtr,
    uint32 dataLength,
    const uint8* signaturePtr,
    uint32 signatureLength,
    Crypto_VerifyResultType* verifyPtr
);

/*******************************************************
 *          * Function Info *                           *
 *                                                      *
 * Function_Name        : Csm_KeyElementSet             *
 * Function_Index       : [SWS_Csm_01018]               *
 * Function_Descripton  : Sets a key element to the     *
 * key identified by keyId.                             *
 *******************************************************/
Std_ReturnType Csm_KeyElementSet(
    uint32 keyId,
    uint32 keyElementId,
    const uint8* keyPtr,
    uint32 keyLength
);

/*******************************************************
 *          * Function Info *                           *
 *                                                      *
 * Function_Name        : Csm_KeySetValid               *
 * Function_Index       : [SWS_Csm_01019]               *
 * Function_Descripton  : Sets the key state of the     *
 * key identified by keyId to valid.                    *
 *******************************************************/
Std_ReturnType Csm_KeySetValid(
    uint32 keyId
);

/*******************************************************
 *          * Function Info *                           *
 *                                                      *
 * Function_Name        : Csm_LoadPeerPublicKey         *
 * Function_Descripton  : Load an ML-DSA peer public    *
 * key from the configured key directory and bind it    *
 * to the peer-pubkey slot keyed by peerId.             *
 *******************************************************/
Std_ReturnType Csm_LoadPeerPublicKey(Csm_PeerIdType peerId, const char* keyFilePathOrPrefix);

/* vendor (post-quantum) jobs, key elements, Csm_CustomService, Csm_KeyElementGet */
#include "Csm/Csm_Pqc.h"

#endif