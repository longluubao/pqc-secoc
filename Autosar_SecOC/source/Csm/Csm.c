/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/

#include "CryIf/CryIf.h"
#include "Csm/Csm.h"
#include "SecOC/SecOC_Cfg.h"

#include <string.h>
#include <stdio.h>

/* MISRA C:2012 Rule 17.3 - Cross-module forward declarations */
extern Std_ReturnType CryIf_SignatureVerify(CryIf_ProviderType provider,
                                           const uint8* dataPtr, uint32 dataLength,
                                           const uint8* contextPtr, uint32 contextLength,
                                           const uint8* signaturePtr, uint32 signatureLength,
                                           const uint8* publicKeyPtr,
                                           Crypto_VerifyResultType* verifyPtr);
extern Std_ReturnType PQC_MLDSA_LoadPeerPublicKey(uint8 peerId, uint8* publicKeyOut, uint32 publicKeyOutLength);

/********************************************************************************************************/
/*********************************************Defines****************************************************/
/********************************************************************************************************/

#define CSM_VENDOR_ID                         ((uint16)0xFFFFU)
#define CSM_MODULE_ID                         ((uint16)0x0110U)
#define CSM_SW_MAJOR_VERSION                  ((uint8)1U)
#define CSM_SW_MINOR_VERSION                  ((uint8)0U)
#define CSM_SW_PATCH_VERSION                  ((uint8)0U)

#define CSM_KEYID_IS_SESSION(id)              (((id) >= CSM_KEYID_SESSION_BASE) && ((id) < (CSM_KEYID_SESSION_BASE + (uint32)CSM_MAX_PEERS)))
#define CSM_SESSION_PEER_FROM_KEYID(id)       ((uint8)((id) - CSM_KEYID_SESSION_BASE))
/* CsmKeyRef [ECUC_Csm_00016]: MAC key ID = 300 + 10 * peer + slot (0 send, 1 receive, 2 key
 * confirmation); the CryIf key is peer * 3 + slot */
#define CSM_MAC_KEY_SLOTS                     (3U)
#define CSM_MAC_KEY_OFFSET(id)                ((id) - CSM_KEYID_MAC_TX_PEER(0U))
#define CSM_KEYID_IS_MAC(id)                  (((id) >= CSM_KEYID_MAC_TX_PEER(0U)) && \
                                               ((id) < CSM_KEYID_MAC_TX_PEER(CSM_MAC_NUM_PEERS)) && \
                                               ((CSM_MAC_KEY_OFFSET(id) % 10U) < CSM_MAC_KEY_SLOTS))
#define CSM_CRYIF_KEY_FROM_MAC_KEYID(id)      (((CSM_MAC_KEY_OFFSET(id) / 10U) * CSM_MAC_KEY_SLOTS) + (CSM_MAC_KEY_OFFSET(id) % 10U))

typedef enum
{
    CSM_PENDING_NONE = 0U,
    CSM_PENDING_SIGNATURE_GENERATE,
    CSM_PENDING_SIGNATURE_VERIFY
} Csm_PendingOperationType;

typedef struct
{
    Csm_JobCallbackType CsmJobCallbackFct;
    void* CsmJobCallbackContextPtr;
} Csm_JobCallbackConfigType;

typedef struct
{
    uint32 CsmJobId;
    CryIf_ProviderType CsmSignatureProvider;
    CryIf_ProviderType CsmKeyExchangeProvider;
} Csm_JobRoutingType;

/* A MAC job: service [SWS_Csm_01031], algorithm family and mode [SWS_Csm_01047], [SWS_Csm_01048],
 * key reference [ECUC_Csm_00126] */
typedef struct
{
    uint32 CsmJobId;
    Crypto_ServiceInfoType CsmJobService;
    Crypto_AlgorithmFamilyType CsmMacAlgorithmFamily;
    Crypto_AlgorithmModeType CsmMacAlgorithmMode;
    uint32 CsmJobKeyRef;
    /* bits [ECUC_Csm_00142]. A shorter MAC is not verified: the SWS sets no lower limit, and a short
     * prefix of the right tag would otherwise pass. */
    uint32 CsmMacVerifyCompareLength;
} Csm_MacJobConfigType;

/********************************************************************************************************/
/**************************************ForwardDeclarations***********************************************/
/********************************************************************************************************/

extern void Csm_Init(const Csm_ConfigType* configPtr);
extern void Csm_DeInit(void);
extern void Csm_MainFunction(void);
extern Std_ReturnType Csm_RegisterJobCallback(uint32 jobId, Csm_JobCallbackType callbackFct, void* callbackContextPtr);
extern Std_ReturnType Csm_GetJobResult(uint32 jobId, Std_ReturnType* resultPtr, boolean* completedPtr);
extern void Csm_GetVersionInfo(Std_VersionInfoType* versioninfo);
extern Std_ReturnType Csm_MacGenerate(uint32 jobId, Crypto_OperationModeType mode,
                                      const uint8* dataPtr, uint32 dataLength,
                                      uint8* macPtr, uint32* macLengthPtr);
extern Std_ReturnType Csm_MacVerify(uint32 jobId, Crypto_OperationModeType mode,
                                    const uint8* dataPtr, uint32 dataLength,
                                    const uint8* macPtr, uint32 macLength,
                                    Crypto_VerifyResultType* verifyPtr);
extern Std_ReturnType Csm_SignatureGenerate(uint32 jobId, Crypto_OperationModeType mode,
                                           const uint8* dataPtr, uint32 dataLength,
                                           uint8* signaturePtr, uint32* signatureLengthPtr);
extern Std_ReturnType Csm_SignatureVerify(uint32 jobId, Crypto_OperationModeType mode,
                                         const uint8* dataPtr, uint32 dataLength,
                                         const uint8* signaturePtr, uint32 signatureLength,
                                         Crypto_VerifyResultType* verifyPtr);
extern Std_ReturnType Csm_KeyElementSet(uint32 keyId, uint32 keyElementId,
                                        const uint8* keyPtr, uint32 keyLength);
extern Std_ReturnType Csm_KeySetValid(uint32 keyId);

/********************************************************************************************************/
/*******************************************TypeDefinitions**********************************************/
/********************************************************************************************************/

typedef struct
{
    boolean CsmInUse;
    uint32 CsmJobId;
    Csm_JobStateType CsmJobState;
    uint32 CsmStreamLength;
    uint8 CsmStreamBuffer[CSM_MAX_STREAM_BUFFER];
    Csm_PendingOperationType CsmPendingOperation;
    const uint8* CsmPendingDataPtr;
    uint32 CsmPendingDataLength;
    const uint8* CsmPendingInputAuthenticatorPtr;
    uint32 CsmPendingInputAuthenticatorLength;
    uint8* CsmPendingOutputPtr;
    uint32* CsmPendingOutputLengthPtr;
    Crypto_VerifyResultType* CsmPendingVerifyResultPtr;
    boolean CsmPendingValid;
    Std_ReturnType CsmLastResult;
    boolean CsmLastResultValid;
    Csm_JobCallbackConfigType CsmCallbackConfig;
} Csm_JobContextType;

typedef struct
{
    boolean CsmMldsaPublicKeyValid;
    boolean CsmMldsaSecretKeyValid;
    uint8   CsmMldsaPublicKey[CSM_MLDSA_PUBLIC_KEY_BYTES];
    uint8   CsmMldsaSecretKey[CSM_MLDSA_SECRET_KEY_BYTES];
    boolean CsmMldsaPeerPublicKeyValid[CSM_MAX_PEERS];
    uint8   CsmMldsaPeerPublicKeys[CSM_MAX_PEERS][CSM_MLDSA_PUBLIC_KEY_BYTES];
} Csm_KeyStoreType;

/********************************************************************************************************/
/******************************************GlobalVariables***********************************************/
/********************************************************************************************************/

static boolean Csm_IsInitialized = FALSE;
static Csm_JobContextType Csm_JobContexts[CSM_MAX_JOB_CONTEXTS];
static uint32 Csm_JobQueue[CSM_MAX_JOB_QUEUE];
static uint8 Csm_JobQueueHead = 0U;
static uint8 Csm_JobQueueTail = 0U;
static uint8 Csm_JobQueueCount = 0U;
static Csm_KeyStoreType Csm_KeyStore;
static PQC_MLDSA_KeyPairType Csm_MLDSA_KeyPair;
static boolean Csm_PqcReady = FALSE;
static Csm_ConfigType Csm_RuntimeConfig =
{
    CSM_MLDSA_BOOTSTRAP_DEMO_FILE_AUTO,
    NULL
};

static const Csm_JobRoutingType Csm_JobRoutingTable[] =
{
    { (uint32)CSM_JOBID, CRYIF_PROVIDER_PQC, CRYIF_PROVIDER_PQC }
};

#define CSM_MAC_JOBS_OF_PEER(p) \
    { CSM_JOBID_MAC_GENERATE_PEER(p),   CRYPTO_MACGENERATE, CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_HMAC, CSM_KEYID_MAC_TX_PEER(p), 0U }, \
    { CSM_JOBID_MAC_VERIFY_PEER(p),     CRYPTO_MACVERIFY,   CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_HMAC, CSM_KEYID_MAC_RX_PEER(p), 128U }, \
    { CSM_JOBID_HS_KC_GENERATE_PEER(p), CRYPTO_MACGENERATE, CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_HMAC, CSM_KEYID_HS_KC_PEER(p), 0U }, \
    { CSM_JOBID_HS_KC_VERIFY_PEER(p),   CRYPTO_MACVERIFY,   CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_HMAC, CSM_KEYID_HS_KC_PEER(p), 256U }

static const Csm_MacJobConfigType Csm_MacJobs[] =
{
    CSM_MAC_JOBS_OF_PEER(0U),
    CSM_MAC_JOBS_OF_PEER(1U)
};
_Static_assert(CSM_MAC_NUM_PEERS == 2U, "one CSM_MAC_JOBS_OF_PEER row set per peer");

/********************************************************************************************************/
/****************************************StaticFunctions*************************************************/
/********************************************************************************************************/

static void Csm_ResetState(void)
{
    (void)memset(Csm_JobContexts, 0, sizeof(Csm_JobContexts));
    (void)memset(Csm_JobQueue, 0, sizeof(Csm_JobQueue));
    Csm_JobQueueHead = 0U;
    Csm_JobQueueTail = 0U;
    Csm_JobQueueCount = 0U;
    (void)memset(&Csm_KeyStore, 0, sizeof(Csm_KeyStore));
    (void)memset(&Csm_MLDSA_KeyPair, 0, sizeof(Csm_MLDSA_KeyPair));
    Csm_PqcReady = FALSE;
    Csm_Pqc_Reset();
}

static Std_ReturnType Csm_EnqueueJob(uint32 jobId)
{
    uint8 idx;

    for (idx = 0U; idx < Csm_JobQueueCount; idx++)
    {
        uint8 queueIdx = (uint8)((Csm_JobQueueHead + idx) % CSM_MAX_JOB_QUEUE);
        if (Csm_JobQueue[queueIdx] == jobId)
        {
            return E_OK;
        }
    }

    if (Csm_JobQueueCount >= CSM_MAX_JOB_QUEUE)
    {
        return CRYPTO_E_QUEUE_FULL;
    }

    Csm_JobQueue[Csm_JobQueueTail] = jobId;
    Csm_JobQueueTail = (uint8)((Csm_JobQueueTail + 1U) % CSM_MAX_JOB_QUEUE);
    Csm_JobQueueCount++;
    return E_OK;
}

static Std_ReturnType Csm_DequeueJob(uint32* jobIdPtr)
{
    if ((jobIdPtr == NULL) || (Csm_JobQueueCount == 0U))
    {
        return E_NOT_OK;
    }

    *jobIdPtr = Csm_JobQueue[Csm_JobQueueHead];
    Csm_JobQueueHead = (uint8)((Csm_JobQueueHead + 1U) % CSM_MAX_JOB_QUEUE);
    Csm_JobQueueCount--;
    return E_OK;
}

static Csm_JobContextType* Csm_GetJobContext(uint32 jobId)
{
    uint8 idx;

    for (idx = 0U; idx < CSM_MAX_JOB_CONTEXTS; idx++)
    {
        if ((Csm_JobContexts[idx].CsmInUse == TRUE) && (Csm_JobContexts[idx].CsmJobId == jobId))
        {
            return &Csm_JobContexts[idx];
        }
    }

    for (idx = 0U; idx < CSM_MAX_JOB_CONTEXTS; idx++)
    {
        if (Csm_JobContexts[idx].CsmInUse == FALSE)
        {
            Csm_JobContexts[idx].CsmInUse = TRUE;
            Csm_JobContexts[idx].CsmJobId = jobId;
            Csm_JobContexts[idx].CsmJobState = CSM_JOBSTATE_IDLE;
            Csm_JobContexts[idx].CsmStreamLength = 0U;
            return &Csm_JobContexts[idx];
        }
    }

    return NULL;
}

static Std_ReturnType Csm_AppendStreamData(Csm_JobContextType* contextPtr, const uint8* dataPtr, uint32 dataLength)
{
    if ((contextPtr == NULL) || ((dataPtr == NULL) && (dataLength > 0U)))
    {
        return E_NOT_OK;
    }

    if ((contextPtr->CsmStreamLength + dataLength) > CSM_MAX_STREAM_BUFFER)
    {
        return E_NOT_OK;
    }

    if (dataLength > 0U)
    {
        (void)memcpy(&contextPtr->CsmStreamBuffer[contextPtr->CsmStreamLength], dataPtr, dataLength);
        contextPtr->CsmStreamLength += dataLength;
    }

    return E_OK;
}

static CryIf_ProviderType Csm_SelectProvider(uint32 jobId, Csm_PendingOperationType operationType)
{
    uint8 idx;
    CryIf_ProviderType defaultProvider = CRYIF_PROVIDER_PQC;

    for (idx = 0U; idx < (uint8)(sizeof(Csm_JobRoutingTable) / sizeof(Csm_JobRoutingTable[0])); idx++)
    {
        if (Csm_JobRoutingTable[idx].CsmJobId != jobId)
        {
            continue;
        }

        if ((operationType == CSM_PENDING_SIGNATURE_GENERATE) || (operationType == CSM_PENDING_SIGNATURE_VERIFY))
        {
            return Csm_JobRoutingTable[idx].CsmSignatureProvider;
        }

        return Csm_JobRoutingTable[idx].CsmKeyExchangeProvider;
    }

    return defaultProvider;
}

static void Csm_ClearPendingOperation(Csm_JobContextType* contextPtr)
{
    if (contextPtr == NULL)
    {
        return;
    }

    contextPtr->CsmPendingOperation = CSM_PENDING_NONE;
    contextPtr->CsmPendingDataPtr = NULL;
    contextPtr->CsmPendingDataLength = 0U;
    contextPtr->CsmPendingInputAuthenticatorPtr = NULL;
    contextPtr->CsmPendingInputAuthenticatorLength = 0U;
    contextPtr->CsmPendingOutputPtr = NULL;
    contextPtr->CsmPendingOutputLengthPtr = NULL;
    contextPtr->CsmPendingVerifyResultPtr = NULL;
    contextPtr->CsmPendingValid = FALSE;
}

static Std_ReturnType Csm_QueuePendingOperation(
    Csm_JobContextType* contextPtr,
    Csm_PendingOperationType operationType,
    const uint8* dataPtr,
    uint32 dataLength,
    const uint8* inputAuthenticatorPtr,
    uint32 inputAuthenticatorLength,
    uint8* outputPtr,
    uint32* outputLengthPtr,
    Crypto_VerifyResultType* verifyResultPtr)
{
    Std_ReturnType queueResult;

    if (contextPtr == NULL)
    {
        return E_NOT_OK;
    }

    if (contextPtr->CsmPendingValid == TRUE)
    {
        return E_BUSY;
    }

    queueResult = Csm_EnqueueJob(contextPtr->CsmJobId);
    if (queueResult != E_OK)
    {
        return CRYPTO_E_QUEUE_FULL;
    }

    contextPtr->CsmPendingOperation = operationType;
    contextPtr->CsmPendingDataPtr = dataPtr;
    contextPtr->CsmPendingDataLength = dataLength;
    contextPtr->CsmPendingInputAuthenticatorPtr = inputAuthenticatorPtr;
    contextPtr->CsmPendingInputAuthenticatorLength = inputAuthenticatorLength;
    contextPtr->CsmPendingOutputPtr = outputPtr;
    contextPtr->CsmPendingOutputLengthPtr = outputLengthPtr;
    contextPtr->CsmPendingVerifyResultPtr = verifyResultPtr;
    contextPtr->CsmPendingValid = TRUE;
    contextPtr->CsmJobState = CSM_JOBSTATE_QUEUED;

    return E_BUSY;
}

static Std_ReturnType Csm_ExecutePendingOperation(Csm_JobContextType* contextPtr)
{
    CryIf_ProviderType provider;
    Csm_PqcSignatureJobType pqcJob;

    if ((contextPtr == NULL) || (contextPtr->CsmPendingValid == FALSE))
    {
        return E_NOT_OK;
    }

    provider = Csm_SelectProvider(contextPtr->CsmJobId, contextPtr->CsmPendingOperation);

    if (contextPtr->CsmPendingOperation == CSM_PENDING_SIGNATURE_GENERATE)
    {
        Std_ReturnType jobResult = Csm_Pqc_SignatureJob(contextPtr->CsmJobId, CSM_PQC_SERVICE_SIGNATUREGENERATE, &pqcJob);
        if (jobResult != E_OK)
        {
            return jobResult;
        }

        return CryIf_SignatureGenerate(
            provider,
            contextPtr->CsmPendingDataPtr,
            contextPtr->CsmPendingDataLength,
            pqcJob.CsmContextPtr,
            pqcJob.CsmContextLength,
            Csm_KeyStore.CsmMldsaSecretKey,
            contextPtr->CsmPendingOutputPtr,
            contextPtr->CsmPendingOutputLengthPtr);
    }

    if (contextPtr->CsmPendingOperation == CSM_PENDING_SIGNATURE_VERIFY)
    {
        const uint8* publicKeyToUse = Csm_KeyStore.CsmMldsaPublicKey;
        Std_ReturnType jobResult;

        if (contextPtr->CsmPendingVerifyResultPtr == NULL)
        {
            return E_NOT_OK;
        }

        *contextPtr->CsmPendingVerifyResultPtr = CRYPTO_E_VER_NOT_OK;
        jobResult = Csm_Pqc_SignatureJob(contextPtr->CsmJobId, CSM_PQC_SERVICE_SIGNATUREVERIFY, &pqcJob);
        if (jobResult != E_OK)
        {
            return jobResult;
        }

        /* Public key of the job: a job of a verify-peer group uses that peer's stored ML-DSA
         * public key, the loopback verify job this node's own. */
        if (pqcJob.CsmPeerKey == TRUE)
        {
            if (Csm_KeyStore.CsmMldsaPeerPublicKeyValid[pqcJob.CsmPeer] == TRUE)
            {
                publicKeyToUse = Csm_KeyStore.CsmMldsaPeerPublicKeys[pqcJob.CsmPeer];
            }
            else
            {
                return CRYPTO_E_KEY_NOT_VALID;
            }
        }

        if (CryIf_SignatureVerify(
                provider,
                contextPtr->CsmPendingDataPtr,
                contextPtr->CsmPendingDataLength,
                pqcJob.CsmContextPtr,
                pqcJob.CsmContextLength,
                contextPtr->CsmPendingInputAuthenticatorPtr,
                contextPtr->CsmPendingInputAuthenticatorLength,
                publicKeyToUse,
                contextPtr->CsmPendingVerifyResultPtr) == E_OK)
        {
            /* the verification ran: a successful request, the verdict is in the result pointer */
            return E_OK;
        }

        *contextPtr->CsmPendingVerifyResultPtr = CRYPTO_E_VER_NOT_OK;
        return E_NOT_OK;
    }

    return E_NOT_OK;
}

/* [SWS_Csm_01091] a job serves only the service it is configured for. HMAC-SHA-256 is the one MAC
 * primitive the crypto driver offers. */
static const Csm_MacJobConfigType* Csm_GetMacJob(uint32 jobId, Crypto_ServiceInfoType service)
{
    uint8 idx;

    for (idx = 0U; idx < (uint8)(sizeof(Csm_MacJobs) / sizeof(Csm_MacJobs[0])); idx++)
    {
        if ((Csm_MacJobs[idx].CsmJobId == jobId) &&
            (Csm_MacJobs[idx].CsmJobService == service) &&
            (Csm_MacJobs[idx].CsmMacAlgorithmFamily == CRYPTO_ALGOFAM_SHA2_256) &&
            (Csm_MacJobs[idx].CsmMacAlgorithmMode == CRYPTO_ALGOMODE_HMAC))
        {
            return &Csm_MacJobs[idx];
        }
    }

    return NULL;
}

static Std_ReturnType Csm_PQC_EnsureReady(void)
{
    Std_ReturnType result;

    if (Csm_PqcReady == TRUE)
    {
        return E_OK;
    }

    result = CryIf_Init();
    if (result != E_OK)
    {
        (void)printf("ERROR: CSM PQC init failed\n");
        return E_NOT_OK;
    }

    if (Csm_RuntimeConfig.CsmMldsaBootstrapMode == CSM_MLDSA_BOOTSTRAP_DEMO_FILE_AUTO)
    {
        result = CryIf_MldsaLoadKeys(&Csm_MLDSA_KeyPair, CSM_MLDSA_KEY_PREFIX);
        if (result != E_OK)
        {
            result = CryIf_MldsaGenerateKeyPair(&Csm_MLDSA_KeyPair);
            if (result != E_OK)
            {
                (void)printf("ERROR: CSM ML-DSA key generation failed\n");
                return E_NOT_OK;
            }

            (void)CryIf_MldsaSaveKeys(&Csm_MLDSA_KeyPair, CSM_MLDSA_KEY_PREFIX);
        }
    }
    else if (Csm_RuntimeConfig.CsmMldsaBootstrapMode == CSM_MLDSA_BOOTSTRAP_FILE_STRICT)
    {
        result = CryIf_MldsaLoadKeys(&Csm_MLDSA_KeyPair, CSM_MLDSA_KEY_PREFIX);
        if (result != E_OK)
        {
            (void)printf("ERROR: CSM strict key bootstrap failed (missing key files)\n");
            return E_NOT_OK;
        }
    }
    else
    {
        if (Csm_RuntimeConfig.CsmLoadProvisionedMldsaKeysFct == NULL)
        {
            (void)printf("ERROR: CSM provisioned/HSM bootstrap requires key loading callback\n");
            return E_NOT_OK;
        }

        result = Csm_RuntimeConfig.CsmLoadProvisionedMldsaKeysFct(
            Csm_MLDSA_KeyPair.PublicKey,
            CSM_MLDSA_PUBLIC_KEY_BYTES,
            Csm_MLDSA_KeyPair.SecretKey,
            CSM_MLDSA_SECRET_KEY_BYTES);
        if (result != E_OK)
        {
            (void)printf("ERROR: CSM provisioned/HSM key bootstrap failed\n");
            return E_NOT_OK;
        }
    }

    (void)memcpy(Csm_KeyStore.CsmMldsaPublicKey, Csm_MLDSA_KeyPair.PublicKey, CSM_MLDSA_PUBLIC_KEY_BYTES);
    (void)memcpy(Csm_KeyStore.CsmMldsaSecretKey, Csm_MLDSA_KeyPair.SecretKey, CSM_MLDSA_SECRET_KEY_BYTES);
    Csm_KeyStore.CsmMldsaPublicKeyValid = TRUE;
    Csm_KeyStore.CsmMldsaSecretKeyValid = TRUE;
    Csm_Pqc_SetKeyId(CSM_PQC_KEYID_SLOT_LOCAL, Csm_KeyStore.CsmMldsaPublicKey);

    /* Fail-soft attempt to load peer ML-DSA pubkeys from disk for verify-peer
     * jobs. Missing files are treated as "no peer pubkey provisioned yet" and
     * leave the slot invalid; callers that explicitly need a peer key get a
     * CRYPTO_E_KEY_NOT_VALID later, while local-only verification keeps
     * working. */
    {
        uint8 peerIdx;
        uint8 loaded = 0U;
        for (peerIdx = 0U; peerIdx < CSM_MAX_PEERS; peerIdx++)
        {
            if (Csm_LoadPeerPublicKey((Csm_PeerIdType)peerIdx, NULL) == E_OK)
            {
                loaded++;
            }
        }
        (void)printf("CSM ML-DSA peer pubkeys loaded: %u/%u\n",
                     (unsigned)loaded, (unsigned)CSM_MAX_PEERS);
    }

    Csm_PqcReady = TRUE;
    return E_OK;
}

static Std_ReturnType Csm_PrepareOperationInput(
    Csm_JobContextType* contextPtr,
    Crypto_OperationModeType mode,
    const uint8* dataPtr,
    uint32 dataLength,
    const uint8** preparedDataPtr,
    uint32* preparedLengthPtr)
{
    if ((contextPtr == NULL) || (preparedDataPtr == NULL) || (preparedLengthPtr == NULL))
    {
        return E_NOT_OK;
    }

    if (mode == CRYPTO_OPERATIONMODE_SINGLECALL)
    {
        *preparedDataPtr = dataPtr;
        *preparedLengthPtr = dataLength;
        return E_OK;
    }

    if (mode == CRYPTO_OPERATIONMODE_START)
    {
        contextPtr->CsmStreamLength = 0U;
        contextPtr->CsmJobState = CSM_JOBSTATE_ACTIVE;
        return Csm_AppendStreamData(contextPtr, dataPtr, dataLength);
    }

    if (mode == CRYPTO_OPERATIONMODE_UPDATE)
    {
        if (contextPtr->CsmJobState != CSM_JOBSTATE_ACTIVE)
        {
            return E_NOT_OK;
        }
        return Csm_AppendStreamData(contextPtr, dataPtr, dataLength);
    }

    if (mode == CRYPTO_OPERATIONMODE_FINISH)
    {
        if (contextPtr->CsmJobState != CSM_JOBSTATE_ACTIVE)
        {
            return E_NOT_OK;
        }

        if (Csm_AppendStreamData(contextPtr, dataPtr, dataLength) != E_OK)
        {
            return E_NOT_OK;
        }

        *preparedDataPtr = contextPtr->CsmStreamBuffer;
        *preparedLengthPtr = contextPtr->CsmStreamLength;
        contextPtr->CsmStreamLength = 0U;
        contextPtr->CsmJobState = CSM_JOBSTATE_IDLE;
        return E_OK;
    }

    return E_NOT_OK;
}

/********************************************************************************************************/
/********************************************PublicFunctions*********************************************/
/********************************************************************************************************/

void Csm_Init(const Csm_ConfigType* configPtr)
{
    if (configPtr != NULL)
    {
        Csm_RuntimeConfig = *configPtr;
    }
    else
    {
       Csm_RuntimeConfig.CsmMldsaBootstrapMode = CSM_MLDSA_BOOTSTRAP_DEMO_FILE_AUTO;
       Csm_RuntimeConfig.CsmLoadProvisionedMldsaKeysFct = NULL;
    }

    Csm_ResetState();
    if (Csm_PQC_EnsureReady() == E_OK)
    {
        Csm_IsInitialized = TRUE;
        Csm_Pqc_SetReady();
    }
    else
    {
        Csm_IsInitialized = FALSE;
    }
}

void Csm_DeInit(void)
{
    CryIf_DeInit();
    Csm_ResetState();
    Csm_IsInitialized = FALSE;
}

void Csm_MainFunction(void)
{
    uint32 queuedJobId = 0U;
    Csm_JobContextType* contextPtr;
    Std_ReturnType operationResult;

    if (Csm_IsInitialized == FALSE)
    {
        return;
    }

    if (Csm_DequeueJob(&queuedJobId) == E_OK)
    {
        contextPtr = Csm_GetJobContext(queuedJobId);
        if ((contextPtr != NULL) && (contextPtr->CsmPendingValid == TRUE))
        {
            operationResult = Csm_ExecutePendingOperation(contextPtr);
            contextPtr->CsmLastResult = operationResult;
            contextPtr->CsmLastResultValid = TRUE;
            contextPtr->CsmJobState = CSM_JOBSTATE_IDLE;
            Csm_ClearPendingOperation(contextPtr);

            if (contextPtr->CsmCallbackConfig.CsmJobCallbackFct != NULL)
            {
                contextPtr->CsmCallbackConfig.CsmJobCallbackFct(
                    contextPtr->CsmJobId,
                    operationResult,
                    contextPtr->CsmCallbackConfig.CsmJobCallbackContextPtr);
            }
        }
    }
}

Std_ReturnType Csm_RegisterJobCallback(uint32 jobId, Csm_JobCallbackType callbackFct, void* callbackContextPtr)
{
    Csm_JobContextType* contextPtr;

    if (Csm_IsInitialized == FALSE)
    {
        return E_NOT_OK;
    }

    contextPtr = Csm_GetJobContext(jobId);
    if (contextPtr == NULL)
    {
        return CRYPTO_E_QUEUE_FULL;
    }

    contextPtr->CsmCallbackConfig.CsmJobCallbackFct = callbackFct;
    contextPtr->CsmCallbackConfig.CsmJobCallbackContextPtr = callbackContextPtr;
    return E_OK;
}

Std_ReturnType Csm_GetJobResult(uint32 jobId, Std_ReturnType* resultPtr, boolean* completedPtr)
{
    Csm_JobContextType* contextPtr;

    if ((Csm_IsInitialized == FALSE) || (resultPtr == NULL) || (completedPtr == NULL))
    {
        return E_NOT_OK;
    }

    contextPtr = Csm_GetJobContext(jobId);
    if (contextPtr == NULL)
    {
        return E_NOT_OK;
    }

    if ((contextPtr->CsmPendingValid == TRUE) || (contextPtr->CsmLastResultValid == FALSE))
    {
        *completedPtr = FALSE;
        *resultPtr = E_BUSY;
        return E_OK;
    }

    *completedPtr = TRUE;
    *resultPtr = contextPtr->CsmLastResult;
    return E_OK;
}

void Csm_GetVersionInfo(Std_VersionInfoType* versioninfo)
{
    if (versioninfo == NULL)
    {
        return;
    }

    versioninfo->vendorID = CSM_VENDOR_ID;
    versioninfo->moduleID = CSM_MODULE_ID;
    versioninfo->sw_major_version = CSM_SW_MAJOR_VERSION;
    versioninfo->sw_minor_version = CSM_SW_MINOR_VERSION;
    versioninfo->sw_patch_version = CSM_SW_PATCH_VERSION;
}

/* [SWS_Csm_00982] *macLengthPtr: buffer size in bytes on call, bytes written on return; a buffer
 * shorter than the MAC gets the truncated MAC */
Std_ReturnType Csm_MacGenerate(
    uint32 jobId,
    Crypto_OperationModeType mode,
    const uint8* dataPtr,
    uint32 dataLength,
    uint8* macPtr,
    uint32* macLengthPtr)
{
    const Csm_MacJobConfigType* jobPtr = Csm_GetMacJob(jobId, CRYPTO_MACGENERATE);
    Csm_JobContextType* contextPtr;
    const uint8* preparedDataPtr = NULL;
    uint32 preparedLength = 0U;
    Std_ReturnType result;

    if ((Csm_IsInitialized == FALSE) || (jobPtr == NULL) || (macPtr == NULL) || (macLengthPtr == NULL))
    {
        return E_NOT_OK;
    }

    contextPtr = Csm_GetJobContext(jobId);
    if (contextPtr == NULL)
    {
        return CRYPTO_E_QUEUE_FULL;
    }

    result = Csm_PrepareOperationInput(
        contextPtr,
        mode,
        dataPtr,
        dataLength,
        &preparedDataPtr,
        &preparedLength);

    if ((mode == CRYPTO_OPERATIONMODE_START) || (mode == CRYPTO_OPERATIONMODE_UPDATE))
    {
        return result;
    }

    if ((result != E_OK) || (preparedDataPtr == NULL))
    {
        return E_NOT_OK;
    }

    result = CryIf_MacGenerate(
        CSM_CRYIF_KEY_FROM_MAC_KEYID(jobPtr->CsmJobKeyRef),
        preparedDataPtr,
        preparedLength,
        macPtr,
        macLengthPtr);
    contextPtr->CsmLastResult = result;
    contextPtr->CsmLastResultValid = TRUE;
    return result;
}

/* [SWS_Csm_01050] macLength in bits. E_OK: the MAC was compared, the outcome is *verifyPtr. */
Std_ReturnType Csm_MacVerify(
    uint32 jobId,
    Crypto_OperationModeType mode,
    const uint8* dataPtr,
    uint32 dataLength,
    const uint8* macPtr,
    uint32 macLength,
    Crypto_VerifyResultType* verifyPtr)
{
    const Csm_MacJobConfigType* jobPtr = Csm_GetMacJob(jobId, CRYPTO_MACVERIFY);
    Csm_JobContextType* contextPtr;
    const uint8* preparedDataPtr = NULL;
    uint32 preparedLength = 0U;
    Std_ReturnType result;

    if (verifyPtr == NULL)
    {
        return E_NOT_OK;
    }
    *verifyPtr = CRYPTO_E_VER_NOT_OK;

    if ((Csm_IsInitialized == FALSE) || (jobPtr == NULL) || (macPtr == NULL) ||
        (macLength < jobPtr->CsmMacVerifyCompareLength))
    {
        return E_NOT_OK;
    }

    contextPtr = Csm_GetJobContext(jobId);
    if (contextPtr == NULL)
    {
        return CRYPTO_E_QUEUE_FULL;
    }

    result = Csm_PrepareOperationInput(
        contextPtr,
        mode,
        dataPtr,
        dataLength,
        &preparedDataPtr,
        &preparedLength);

    if ((mode == CRYPTO_OPERATIONMODE_START) || (mode == CRYPTO_OPERATIONMODE_UPDATE))
    {
        return result;
    }

    if ((result != E_OK) || (preparedDataPtr == NULL))
    {
        return E_NOT_OK;
    }

    result = CryIf_MacVerify(
        CSM_CRYIF_KEY_FROM_MAC_KEYID(jobPtr->CsmJobKeyRef),
        preparedDataPtr,
        preparedLength,
        macPtr,
        macLength,
        verifyPtr);
    contextPtr->CsmLastResult = result;
    contextPtr->CsmLastResultValid = TRUE;
    return result;
}

Std_ReturnType Csm_SignatureGenerate(
    uint32 jobId,
    Crypto_OperationModeType mode,
    const uint8* dataPtr,
    uint32 dataLength,
    uint8* signaturePtr,
    uint32* signatureLengthPtr)
{
    Csm_JobContextType* contextPtr;
    const uint8* preparedDataPtr = NULL;
    uint32 preparedLength = 0U;
    Std_ReturnType prepareResult;
    CryIf_ProviderType provider;
    Csm_PqcSignatureJobType pqcJob;
    Std_ReturnType jobResult;

    if ((Csm_IsInitialized == FALSE) || (signaturePtr == NULL) || (signatureLengthPtr == NULL))
    {
        return E_NOT_OK;
    }

    /* The job table first, in every mode, as in the MAC services: an id that is in no row, or a job
     * of the other service, is refused before it gets a job context or its data is copied.
     * The FIPS 204 context is job data: the signature API has no parameter for it [SWS_Csm_00992]. */
    jobResult = Csm_Pqc_SignatureJob(jobId, CSM_PQC_SERVICE_SIGNATUREGENERATE, &pqcJob);
    if (jobResult == E_NOT_OK)
    {
        return E_NOT_OK;
    }

    if ((Csm_PQC_EnsureReady() != E_OK) || (Csm_KeyStore.CsmMldsaSecretKeyValid == FALSE))
    {
        return CRYPTO_E_KEY_NOT_VALID;
    }

    contextPtr = Csm_GetJobContext(jobId);
    if (contextPtr == NULL)
    {
        return CRYPTO_E_QUEUE_FULL;
    }

    prepareResult = Csm_PrepareOperationInput(
        contextPtr,
        mode,
        dataPtr,
        dataLength,
        &preparedDataPtr,
        &preparedLength);

    if ((mode == CRYPTO_OPERATIONMODE_START) || (mode == CRYPTO_OPERATIONMODE_UPDATE))
    {
        return prepareResult;
    }

    if ((prepareResult != E_OK) || (preparedDataPtr == NULL))
    {
        return E_NOT_OK;
    }

    if ((mode == CRYPTO_OPERATIONMODE_SINGLECALL) && (contextPtr->CsmJobState == CSM_JOBSTATE_ACTIVE))
    {
        return Csm_QueuePendingOperation(
            contextPtr,
            CSM_PENDING_SIGNATURE_GENERATE,
            preparedDataPtr,
            preparedLength,
            NULL,
            0U,
            signaturePtr,
            signatureLengthPtr,
            NULL);
    }

    provider = Csm_SelectProvider(jobId, CSM_PENDING_SIGNATURE_GENERATE);
    prepareResult = jobResult;      /* E_OK, or CRYPTO_E_KEY_NOT_VALID: the job's session context is not valid */
    if (prepareResult == E_OK)
    {
        prepareResult = CryIf_SignatureGenerate(
            provider,
            preparedDataPtr,
            preparedLength,
            pqcJob.CsmContextPtr,
            pqcJob.CsmContextLength,
            Csm_KeyStore.CsmMldsaSecretKey,
            signaturePtr,
            signatureLengthPtr);
    }
    contextPtr->CsmLastResult = prepareResult;
    contextPtr->CsmLastResultValid = TRUE;
    return prepareResult;
}

Std_ReturnType Csm_SignatureVerify(
    uint32 jobId,
    Crypto_OperationModeType mode,
    const uint8* dataPtr,
    uint32 dataLength,
    const uint8* signaturePtr,
    uint32 signatureLength,
    Crypto_VerifyResultType* verifyPtr)
{
    Csm_JobContextType* contextPtr;
    const uint8* preparedDataPtr = NULL;
    uint32 preparedLength = 0U;
    Std_ReturnType prepareResult;
    CryIf_ProviderType provider;
    Csm_PqcSignatureJobType pqcJob;
    Std_ReturnType jobResult;

    if ((Csm_IsInitialized == FALSE) || (verifyPtr == NULL) || (signaturePtr == NULL))
    {
        return E_NOT_OK;
    }

    /* the job table first, in every mode (see Csm_SignatureGenerate): key and FIPS 204 context of
     * the job [SWS_Csm_00996 has no parameter for the context] */
    jobResult = Csm_Pqc_SignatureJob(jobId, CSM_PQC_SERVICE_SIGNATUREVERIFY, &pqcJob);
    if (jobResult == E_NOT_OK)
    {
        *verifyPtr = CRYPTO_E_VER_NOT_OK;
        return E_NOT_OK;
    }

    if ((Csm_PQC_EnsureReady() != E_OK) || (Csm_KeyStore.CsmMldsaPublicKeyValid == FALSE))
    {
        *verifyPtr = CRYPTO_E_VER_NOT_OK;
        return CRYPTO_E_KEY_NOT_VALID;
    }

    contextPtr = Csm_GetJobContext(jobId);
    if (contextPtr == NULL)
    {
        *verifyPtr = CRYPTO_E_VER_NOT_OK;
        return CRYPTO_E_QUEUE_FULL;
    }

    prepareResult = Csm_PrepareOperationInput(
        contextPtr,
        mode,
        dataPtr,
        dataLength,
        &preparedDataPtr,
        &preparedLength);

    if ((mode == CRYPTO_OPERATIONMODE_START) || (mode == CRYPTO_OPERATIONMODE_UPDATE))
    {
        return prepareResult;
    }

    if ((prepareResult != E_OK) || (preparedDataPtr == NULL))
    {
        *verifyPtr = CRYPTO_E_VER_NOT_OK;
        return E_NOT_OK;
    }

    if ((mode == CRYPTO_OPERATIONMODE_SINGLECALL) && (contextPtr->CsmJobState == CSM_JOBSTATE_ACTIVE))
    {
        return Csm_QueuePendingOperation(
            contextPtr,
            CSM_PENDING_SIGNATURE_VERIFY,
            preparedDataPtr,
            preparedLength,
            signaturePtr,
            signatureLength,
            NULL,
            NULL,
            verifyPtr);
    }

    provider = Csm_SelectProvider(jobId, CSM_PENDING_SIGNATURE_VERIFY);

    {
        const uint8* publicKeyToUse = Csm_KeyStore.CsmMldsaPublicKey;

        prepareResult = jobResult;  /* E_OK, or CRYPTO_E_KEY_NOT_VALID: the job's session context is not valid */
        if (prepareResult != E_OK)
        {
            *verifyPtr = CRYPTO_E_VER_NOT_OK;
            contextPtr->CsmLastResult = prepareResult;
            contextPtr->CsmLastResultValid = TRUE;
            return prepareResult;
        }

        /* Public key of the job: a job of a verify-peer group uses that peer's stored ML-DSA
         * public key, the loopback verify job this node's own. */
        if (pqcJob.CsmPeerKey == TRUE)
        {
            if (Csm_KeyStore.CsmMldsaPeerPublicKeyValid[pqcJob.CsmPeer] == TRUE)
            {
                publicKeyToUse = Csm_KeyStore.CsmMldsaPeerPublicKeys[pqcJob.CsmPeer];
            }
            else
            {
                *verifyPtr = CRYPTO_E_VER_NOT_OK;
                contextPtr->CsmLastResult = CRYPTO_E_KEY_NOT_VALID;
                contextPtr->CsmLastResultValid = TRUE;
                return CRYPTO_E_KEY_NOT_VALID;
            }
        }

        if (CryIf_SignatureVerify(
                provider,
                preparedDataPtr,
                preparedLength,
                pqcJob.CsmContextPtr,
                pqcJob.CsmContextLength,
                signaturePtr,
                signatureLength,
                publicKeyToUse,
                verifyPtr) == E_OK)
        {
            /* [SWS_Csm_00996], [SWS_Csm_01024]: the verification ran, so the request was successful;
             * whether the signature is valid is the verdict in *verifyPtr (CRYPTO_E_VER_OK or
             * CRYPTO_E_VER_NOT_OK). E_NOT_OK below is for a request that could not be carried out. */
            contextPtr->CsmLastResult = E_OK;
            contextPtr->CsmLastResultValid = TRUE;
            return E_OK;
        }
    }

    *verifyPtr = CRYPTO_E_VER_NOT_OK;
    contextPtr->CsmLastResult = E_NOT_OK;
    contextPtr->CsmLastResultValid = TRUE;
    return E_NOT_OK;
}

Std_ReturnType Csm_KeyElementSet(
    uint32 keyId,
    uint32 keyElementId,
    const uint8* keyPtr,
    uint32 keyLength)
{
    uint8 peerId;

    if ((Csm_IsInitialized == FALSE) || (keyPtr == NULL))
    {
        return E_NOT_OK;
    }

    /* [SWS_Csm_01002] the MAC keys are kept by the crypto driver */
    if (CSM_KEYID_IS_MAC(keyId))
    {
        return CryIf_KeyElementSet(CSM_CRYIF_KEY_FROM_MAC_KEYID(keyId), keyElementId, keyPtr, keyLength);
    }

    if (keyId == CSM_KEYID_MLDSA_LOCAL)
    {
        if ((keyElementId == CSM_KEYELEMENT_MLDSA_PUBLIC) && (keyLength == CSM_MLDSA_PUBLIC_KEY_BYTES))
        {
            (void)memcpy(Csm_KeyStore.CsmMldsaPublicKey, keyPtr, CSM_MLDSA_PUBLIC_KEY_BYTES);
            Csm_KeyStore.CsmMldsaPublicKeyValid = FALSE;
            Csm_Pqc_SetKeyId(CSM_PQC_KEYID_SLOT_LOCAL, NULL);
            return E_OK;
        }

        if ((keyElementId == CSM_KEYELEMENT_MLDSA_SECRET) && (keyLength == CSM_MLDSA_SECRET_KEY_BYTES))
        {
            (void)memcpy(Csm_KeyStore.CsmMldsaSecretKey, keyPtr, CSM_MLDSA_SECRET_KEY_BYTES);
            Csm_KeyStore.CsmMldsaSecretKeyValid = FALSE;
            Csm_Pqc_SetKeyId(CSM_PQC_KEYID_SLOT_LOCAL, NULL);
            return E_OK;
        }
        return CRYPTO_E_KEY_SIZE_MISMATCH;
    }

    if (CSM_KEYID_IS_PEER_PUBKEY(keyId))
    {
        uint8 peerSlot = CSM_PEER_FROM_PUBKEY_KEYID(keyId);
        if (peerSlot >= CSM_MAX_PEERS)
        {
            return E_NOT_OK;
        }
        if ((keyElementId == CSM_KEYELEMENT_MLDSA_PEER_PUBLIC) &&
            (keyLength == CSM_MLDSA_PUBLIC_KEY_BYTES))
        {
            (void)memcpy(Csm_KeyStore.CsmMldsaPeerPublicKeys[peerSlot], keyPtr, CSM_MLDSA_PUBLIC_KEY_BYTES);
            Csm_KeyStore.CsmMldsaPeerPublicKeyValid[peerSlot] = FALSE;
            Csm_Pqc_SetKeyId(CSM_PQC_KEYID_SLOT_PEER(peerSlot), NULL);
            return E_OK;
        }
        return CRYPTO_E_KEY_SIZE_MISMATCH;
    }

    /* cppcheck-suppress misra-c2012-10.4 */
    if (CSM_KEYID_IS_SESSION(keyId) != 0)
    {
        peerId = CSM_SESSION_PEER_FROM_KEYID(keyId);
        if (peerId >= CSM_MAX_PEERS)
        {
            return E_NOT_OK;
        }

        /* session key object: vendor key elements, kept in Csm_Pqc.c */
        return Csm_Pqc_SessionKeyElementSet(peerId, keyElementId, keyPtr, keyLength);
    }

    return E_NOT_OK;
}

Std_ReturnType Csm_KeySetValid(uint32 keyId)
{
    uint8 peerId;

    if (Csm_IsInitialized == FALSE)
    {
        return E_NOT_OK;
    }

    /* [SWS_Csm_01003] */
    if (CSM_KEYID_IS_MAC(keyId))
    {
        return CryIf_KeySetValid(CSM_CRYIF_KEY_FROM_MAC_KEYID(keyId));
    }

    if (keyId == CSM_KEYID_MLDSA_LOCAL)
    {
        Csm_KeyStore.CsmMldsaPublicKeyValid = TRUE;
        Csm_KeyStore.CsmMldsaSecretKeyValid = TRUE;
        Csm_Pqc_SetKeyId(CSM_PQC_KEYID_SLOT_LOCAL, Csm_KeyStore.CsmMldsaPublicKey);
        return E_OK;
    }

    if (CSM_KEYID_IS_PEER_PUBKEY(keyId))
    {
        uint8 peerSlot = CSM_PEER_FROM_PUBKEY_KEYID(keyId);
        if (peerSlot >= CSM_MAX_PEERS)
        {
            return E_NOT_OK;
        }
        Csm_KeyStore.CsmMldsaPeerPublicKeyValid[peerSlot] = TRUE;
        Csm_Pqc_SetKeyId(CSM_PQC_KEYID_SLOT_PEER(peerSlot), Csm_KeyStore.CsmMldsaPeerPublicKeys[peerSlot]);
        return E_OK;
    }

    /* cppcheck-suppress misra-c2012-10.4 */
    if (CSM_KEYID_IS_SESSION(keyId) != 0)
    {
        peerId = CSM_SESSION_PEER_FROM_KEYID(keyId);
        if (peerId >= CSM_MAX_PEERS)
        {
            return E_NOT_OK;
        }

        return Csm_Pqc_SessionKeySetValid(peerId);
    }

    return E_NOT_OK;
}

Std_ReturnType Csm_LoadPeerPublicKey(Csm_PeerIdType peerId, const char* unusedPrefix)
{
    Std_ReturnType result;
    (void)unusedPrefix;
    if (peerId >= CSM_MAX_PEERS)
    {
        return E_NOT_OK;
    }
    result = PQC_MLDSA_LoadPeerPublicKey(peerId,
                                         Csm_KeyStore.CsmMldsaPeerPublicKeys[peerId],
                                         CSM_MLDSA_PUBLIC_KEY_BYTES);
    if (result != E_OK)
    {
        Csm_KeyStore.CsmMldsaPeerPublicKeyValid[peerId] = FALSE;
        Csm_Pqc_SetKeyId(CSM_PQC_KEYID_SLOT_PEER(peerId), NULL);
        return result;
    }
    Csm_KeyStore.CsmMldsaPeerPublicKeyValid[peerId] = TRUE;
    Csm_Pqc_SetKeyId(CSM_PQC_KEYID_SLOT_PEER(peerId), Csm_KeyStore.CsmMldsaPeerPublicKeys[peerId]);
    return E_OK;
}
