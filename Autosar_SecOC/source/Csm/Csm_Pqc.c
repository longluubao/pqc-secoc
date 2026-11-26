/********************************************************************************************************/
/*  Csm, vendor (post-quantum) part: the job table of the ML-DSA-65 signature jobs and of the             */
/*  custom-service jobs, the per-peer session key object (ML-KEM decapsulation key, shared secret, PDU    */
/*  signature context), Csm_CustomService [SWS_Csm_91107] and Csm_KeyElementGet [SWS_Csm_00959].          */
/*                                                                                                        */
/*  The decapsulation key and the shared secret never leave this file: they are written and consumed by   */
/*  the custom service, there is no read path, and they are erased as soon as they have been used.        */
/********************************************************************************************************/

#include "Csm/Csm.h"
#include "CryIf/CryIf.h"
#include "SecOC/SecOC_Cfg.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

#define CSM_PQC_KEYID_IS_SESSION(id)    (((id) >= CSM_KEYID_SESSION_BASE) && ((id) < (CSM_KEYID_SESSION_BASE + (uint32)CSM_MAX_PEERS)))
#define CSM_PQC_PEER_FROM_SESSION(id)   ((uint8)((id) - CSM_KEYID_SESSION_BASE))

#define CSM_PQC_KEY_LOCAL               ((uint8)0U)
#define CSM_PQC_KEY_PEER                ((uint8)1U)
#define CSM_PQC_KEY_SESSION             ((uint8)2U)     /* the session key object named by targetKeyId */

#define CSM_PQC_CTX_NONE                ((uint8)0U)
#define CSM_PQC_CTX_PDU                 ((uint8)1U)
#define CSM_PQC_CTX_HANDSHAKE           ((uint8)2U)

#define CSM_PQC_KDF_LABEL_MAX_BYTES     (8U)
#define CSM_PQC_KDF_INFO_MAX_BYTES      ((2U * CSM_HS_KDF_INFO_PART_MAX_BYTES) + CSM_PQC_KDF_LABEL_MAX_BYTES)

/* One row per job, or per group of jobs "base id + peer". A job serves the service it is listed with
 * and no other. The key is selected by the job id, not by a CsmJobKeyRef (simplification). */
typedef struct
{
    uint32 CsmJobId;
    boolean CsmJobPerPeer;      /* TRUE: CsmJobId + p is the job for peer p */
    uint8 CsmJobService;
    uint8 CsmAlgorithmFamily;
    uint8 CsmAlgorithmMode;
    uint8 CsmJobKey;
    uint8 CsmJobContext;
} Csm_PqcJobConfigType;

static const Csm_PqcJobConfigType Csm_PqcJobs[] =
{
    { (uint32)CSM_JOBID,             FALSE, CSM_PQC_SERVICE_SIGNATUREGENERATE, CSM_PQC_ALGOFAM_MLDSA65,  CSM_PQC_ALGOMODE_MLDSA_CTX,  CSM_PQC_KEY_LOCAL,   CSM_PQC_CTX_PDU },
    { CSM_JOBID_VERIFY_PEER_BASE,    TRUE,  CSM_PQC_SERVICE_SIGNATUREVERIFY,   CSM_PQC_ALGOFAM_MLDSA65,  CSM_PQC_ALGOMODE_MLDSA_CTX,  CSM_PQC_KEY_PEER,    CSM_PQC_CTX_PDU },
    { CSM_JOBID_VERIFY_LOOPBACK,     FALSE, CSM_PQC_SERVICE_SIGNATUREVERIFY,   CSM_PQC_ALGOFAM_MLDSA65,  CSM_PQC_ALGOMODE_MLDSA_CTX,  CSM_PQC_KEY_LOCAL,   CSM_PQC_CTX_PDU },
    { CSM_JOBID_HS_SIGN,             FALSE, CSM_PQC_SERVICE_SIGNATUREGENERATE, CSM_PQC_ALGOFAM_MLDSA65,  CSM_PQC_ALGOMODE_MLDSA_CTX,  CSM_PQC_KEY_LOCAL,   CSM_PQC_CTX_HANDSHAKE },
    { CSM_JOBID_HS_VERIFY_PEER_BASE, TRUE,  CSM_PQC_SERVICE_SIGNATUREVERIFY,   CSM_PQC_ALGOFAM_MLDSA65,  CSM_PQC_ALGOMODE_MLDSA_CTX,  CSM_PQC_KEY_PEER,    CSM_PQC_CTX_HANDSHAKE },
    { CSM_JOBID_KEM_KEYGEN,          FALSE, CSM_PQC_SERVICE_CUSTOM,            CSM_PQC_ALGOFAM_MLKEM768, CSM_PQC_ALGOMODE_KEM_KEYGEN, CSM_PQC_KEY_SESSION, CSM_PQC_CTX_NONE },
    { CSM_JOBID_KEM_ENCAPS,          FALSE, CSM_PQC_SERVICE_CUSTOM,            CSM_PQC_ALGOFAM_MLKEM768, CSM_PQC_ALGOMODE_KEM_ENCAPS, CSM_PQC_KEY_SESSION, CSM_PQC_CTX_NONE },
    { CSM_JOBID_KEM_DECAPS,          FALSE, CSM_PQC_SERVICE_CUSTOM,            CSM_PQC_ALGOFAM_MLKEM768, CSM_PQC_ALGOMODE_KEM_DECAPS, CSM_PQC_KEY_SESSION, CSM_PQC_CTX_NONE },
    { CSM_JOBID_HS_KDF,              FALSE, CSM_PQC_SERVICE_CUSTOM,            CSM_PQC_ALGOFAM_HS_KDF,   CSM_PQC_ALGOMODE_HS_KDF,     CSM_PQC_KEY_SESSION, CSM_PQC_CTX_NONE },
    { CSM_JOBID_KEM_DISCARD,         FALSE, CSM_PQC_SERVICE_CUSTOM,            CSM_PQC_ALGOFAM_MLKEM768, CSM_PQC_ALGOMODE_DISCARD,    CSM_PQC_KEY_SESSION, CSM_PQC_CTX_NONE }
};

/* Labels of the four keys of the handshake key derivation, in output order */
static const char* const Csm_PqcKdfLabels[CSM_HS_KDF_NUM_KEYS] = { "kc-r", "kc-i", "auth-i2r", "auth-r2i" };

typedef struct
{
    boolean CsmKeyValid;        /* key state; a PDU signature job on an invalid session key fails */
    boolean CsmDkSet;
    boolean CsmSsSet;
    uint8 CsmDk[CSM_MLKEM_SECRET_KEY_BYTES];
    uint8 CsmSs[CSM_MLKEM_SHARED_SECRET_BYTES];
    uint8 CsmPduSigCtx[CSM_PDU_SIG_CTX_BYTES];
} Csm_PqcSessionKeyType;

typedef struct
{
    boolean CsmIdValid;
    uint8 CsmId[CSM_KEY_ID_BYTES];
} Csm_PqcKeyIdType;

static boolean Csm_PqcReady = FALSE;
static Csm_PqcSessionKeyType Csm_PqcSessionKeys[CSM_MAX_PEERS];
static Csm_PqcKeyIdType Csm_PqcKeyIds[1U + CSM_MAX_PEERS];
static const uint8 Csm_PqcHandshakeCtx[CSM_HS_SIG_CTX_BYTES + 1U] = CSM_HS_SIG_CTX;

#ifdef SECOC_TEST_ACCESS
void Csm_Pqc_TestStorage(const uint8** storagePtr, uint32* lengthPtr)
{
    *storagePtr = (const uint8*)Csm_PqcSessionKeys;
    *lengthPtr = (uint32)sizeof(Csm_PqcSessionKeys);
}
#define CSM_PQC_TAP(kind, ptr, len)     Csm_Pqc_TestTap((kind), (ptr), (len))
#else
#define CSM_PQC_TAP(kind, ptr, len)     ((void)0)
#endif

/********************************************************************************************************/
/****************************************StaticFunctions*************************************************/
/********************************************************************************************************/

static const Csm_PqcJobConfigType* Csm_Pqc_FindJob(uint32 jobId, uint8* peerPtr)
{
    uint8 idx;

    for (idx = 0U; idx < (uint8)(sizeof(Csm_PqcJobs) / sizeof(Csm_PqcJobs[0])); idx++)
    {
        if (Csm_PqcJobs[idx].CsmJobPerPeer == TRUE)
        {
            if ((jobId >= Csm_PqcJobs[idx].CsmJobId) && (jobId < (Csm_PqcJobs[idx].CsmJobId + (uint32)CSM_MAX_PEERS)))
            {
                *peerPtr = (uint8)(jobId - Csm_PqcJobs[idx].CsmJobId);
                return &Csm_PqcJobs[idx];
            }
        }
        else if (Csm_PqcJobs[idx].CsmJobId == jobId)
        {
            *peerPtr = 0U;
            return &Csm_PqcJobs[idx];
        }
        else
        {
            /* next row */
        }
    }

    return NULL;
}

static void Csm_Pqc_DiscardKem(Csm_PqcSessionKeyType* keyPtr)
{
    OPENSSL_cleanse(keyPtr->CsmDk, sizeof(keyPtr->CsmDk));
    OPENSSL_cleanse(keyPtr->CsmSs, sizeof(keyPtr->CsmSs));
    keyPtr->CsmDkSet = FALSE;
    keyPtr->CsmSsSet = FALSE;
}

/* One HKDF-Extract with the shared secret as input keying material, then one HKDF-Expand per label.
 * The shared secret is erased right after the Extract, the pseudorandom key before the return. */
static Std_ReturnType Csm_Pqc_DeriveHandshakeKeys(
    Csm_PqcSessionKeyType* keyPtr,
    const uint8* saltPtr, uint32 saltLength,
    const uint8* infoHeadPtr, uint32 infoHeadLength,
    const uint8* infoTailPtr, uint32 infoTailLength,
    uint8* outputPtr)
{
    uint8 prk[PQC_HKDF_PRK_BYTES];
    uint8 info[CSM_PQC_KDF_INFO_MAX_BYTES];
    Std_ReturnType result;
    uint8 idx;

    result = CryIf_HkdfExtract(saltPtr, saltLength, keyPtr->CsmSs, CSM_MLKEM_SHARED_SECRET_BYTES, prk);
    OPENSSL_cleanse(keyPtr->CsmSs, sizeof(keyPtr->CsmSs));
    keyPtr->CsmSsSet = FALSE;

    if (result == E_OK)
    {
        CSM_PQC_TAP(CSM_PQC_TAP_PRK, prk, (uint32)sizeof(prk));
        (void)memcpy(info, infoHeadPtr, infoHeadLength);
    }

    for (idx = 0U; (idx < CSM_HS_KDF_NUM_KEYS) && (result == E_OK); idx++)
    {
        uint32 labelLength = (uint32)strlen(Csm_PqcKdfLabels[idx]);

        (void)memcpy(&info[infoHeadLength], Csm_PqcKdfLabels[idx], labelLength);
        (void)memcpy(&info[infoHeadLength + labelLength], infoTailPtr, infoTailLength);
        result = CryIf_HkdfExpand(prk, info, infoHeadLength + labelLength + infoTailLength,
                                  &outputPtr[(uint32)idx * CSM_DERIVED_KEY_LENGTH], CSM_DERIVED_KEY_LENGTH);
    }

    OPENSSL_cleanse(prk, sizeof(prk));

    if (result != E_OK)
    {
        OPENSSL_cleanse(outputPtr, CSM_HS_KDF_OUTPUT_BYTES);
        return CRYPTO_E_CUSTOM_ERROR;
    }

    CSM_PQC_TAP(CSM_PQC_TAP_OKM, outputPtr, CSM_HS_KDF_OUTPUT_BYTES);
    return E_OK;
}

/********************************************************************************************************/
/****************************************** used by Csm.c ***********************************************/
/********************************************************************************************************/

void Csm_Pqc_Reset(void)
{
    uint8 peer;

    Csm_PqcReady = FALSE;
    OPENSSL_cleanse(Csm_PqcSessionKeys, sizeof(Csm_PqcSessionKeys));
    (void)memset(Csm_PqcKeyIds, 0, sizeof(Csm_PqcKeyIds));

    /* No session yet: label || 48 zero bytes, a valid context (harnesses and builds without the
     * handshake sign and verify with it). */
    for (peer = 0U; peer < CSM_MAX_PEERS; peer++)
    {
        (void)memcpy(Csm_PqcSessionKeys[peer].CsmPduSigCtx, PQC_PDU_SIG_CTX_LABEL, PQC_PDU_SIG_CTX_LABEL_BYTES);
        Csm_PqcSessionKeys[peer].CsmKeyValid = TRUE;
    }
}

void Csm_Pqc_SetReady(void)
{
    Csm_PqcReady = TRUE;
}

void Csm_Pqc_SetKeyId(uint8 slot, const uint8* publicKeyPtr)
{
    if (slot > CSM_MAX_PEERS)
    {
        return;
    }

    Csm_PqcKeyIds[slot].CsmIdValid = FALSE;
    if ((publicKeyPtr != NULL) &&
        (SHA256(publicKeyPtr, CSM_MLDSA_PUBLIC_KEY_BYTES, Csm_PqcKeyIds[slot].CsmId) != NULL))
    {
        Csm_PqcKeyIds[slot].CsmIdValid = TRUE;
    }
}

Std_ReturnType Csm_Pqc_SignatureJob(uint32 jobId, uint8 service, Csm_PqcSignatureJobType* jobPtr)
{
    uint8 peer = 0U;
    const Csm_PqcJobConfigType* cfgPtr = Csm_Pqc_FindJob(jobId, &peer);
    uint8 context;

    /* the table is the only source: a job that is not listed, or listed for the other service, has
     * no key and no context */
    if ((cfgPtr == NULL) || (cfgPtr->CsmJobService != service))
    {
        return E_NOT_OK;
    }
    jobPtr->CsmPeerKey = (cfgPtr->CsmJobKey == CSM_PQC_KEY_PEER) ? TRUE : FALSE;
    jobPtr->CsmPeer = peer;
    context = cfgPtr->CsmJobContext;

    if (context == CSM_PQC_CTX_HANDSHAKE)
    {
        jobPtr->CsmContextPtr = Csm_PqcHandshakeCtx;
        jobPtr->CsmContextLength = CSM_HS_SIG_CTX_BYTES;
        return E_OK;
    }

    if (Csm_PqcSessionKeys[peer].CsmKeyValid == FALSE)
    {
        return CRYPTO_E_KEY_NOT_VALID;
    }
    jobPtr->CsmContextPtr = Csm_PqcSessionKeys[peer].CsmPduSigCtx;
    jobPtr->CsmContextLength = CSM_PDU_SIG_CTX_BYTES;
    return E_OK;
}

Std_ReturnType Csm_Pqc_SessionKeyElementSet(uint8 peer, uint32 keyElementId, const uint8* keyPtr, uint32 keyLength)
{
    if ((peer >= CSM_MAX_PEERS) || (keyPtr == NULL))
    {
        return E_NOT_OK;
    }

    if ((keyElementId == CSM_KE_VENDOR_KEM_DK) || (keyElementId == CSM_KE_VENDOR_KEM_SS))
    {
        return CRYPTO_E_KEY_WRITE_FAIL;
    }
    if (keyElementId != CSM_KE_VENDOR_PDU_SIG_CTX)
    {
        return CRYPTO_E_KEY_NOT_AVAILABLE;
    }
    if (keyLength != CSM_PDU_SIG_CTX_BYTES)
    {
        return CRYPTO_E_KEY_SIZE_MISMATCH;
    }

    /* Crypto Driver SWS 7.2.4: writing a key element makes the key invalid until it is set valid */
    Csm_PqcSessionKeys[peer].CsmKeyValid = FALSE;
    (void)memcpy(Csm_PqcSessionKeys[peer].CsmPduSigCtx, keyPtr, CSM_PDU_SIG_CTX_BYTES);
    return E_OK;
}

Std_ReturnType Csm_Pqc_SessionKeySetValid(uint8 peer)
{
    if (peer >= CSM_MAX_PEERS)
    {
        return E_NOT_OK;
    }

    Csm_PqcSessionKeys[peer].CsmKeyValid = TRUE;
    return E_OK;
}

/********************************************************************************************************/
/********************************************PublicFunctions*********************************************/
/********************************************************************************************************/

Std_ReturnType Csm_KeyElementGet(
    uint32 keyId,
    uint32 keyElementId,
    uint8* keyElementPtr,
    uint32* keyElementLengthPtr)
{
    uint8 slot;

    if ((Csm_PqcReady == FALSE) || (keyElementPtr == NULL) || (keyElementLengthPtr == NULL))
    {
        return E_NOT_OK;
    }

    /* cppcheck-suppress misra-c2012-10.4 */
    if (CSM_PQC_KEYID_IS_SESSION(keyId) != 0)
    {
        return CRYPTO_E_KEY_READ_FAIL;
    }

    if (keyId == CSM_KEYID_MLDSA_LOCAL)
    {
        slot = CSM_PQC_KEYID_SLOT_LOCAL;
    }
    else if (CSM_KEYID_IS_PEER_PUBKEY(keyId))
    {
        slot = CSM_PQC_KEYID_SLOT_PEER(CSM_PEER_FROM_PUBKEY_KEYID(keyId));
    }
    else
    {
        return CRYPTO_E_KEY_NOT_AVAILABLE;
    }

    if (keyElementId != CSM_KE_VENDOR_KEY_ID)
    {
        return CRYPTO_E_KEY_READ_FAIL;
    }
    if (Csm_PqcKeyIds[slot].CsmIdValid == FALSE)
    {
        return CRYPTO_E_KEY_EMPTY;
    }
    if (*keyElementLengthPtr < CSM_KEY_ID_BYTES)
    {
        return CRYPTO_E_KEY_SIZE_MISMATCH;
    }

    (void)memcpy(keyElementPtr, Csm_PqcKeyIds[slot].CsmId, CSM_KEY_ID_BYTES);
    *keyElementLengthPtr = CSM_KEY_ID_BYTES;
    return E_OK;
}

Std_ReturnType Csm_CustomService(
    uint32 jobId,
    Crypto_OperationModeType mode,
    uint32 targetKeyId,
    const uint8* inputPtr,
    uint32 inputLength,
    const uint8* secondaryInputPtr,
    uint32 secondaryInputLength,
    const uint8* tertiaryInputPtr,
    uint32 tertiaryInputLength,
    uint8* outputPtr,
    uint32* outputLengthPtr,
    uint8* secondaryOutputPtr,
    uint32* secondaryOutputLengthPtr,
    Crypto_VerifyResultType* verifyPtr)
{
    uint8 peer = 0U;
    const Csm_PqcJobConfigType* cfgPtr = Csm_Pqc_FindJob(jobId, &peer);
    Csm_PqcSessionKeyType* keyPtr;
    Std_ReturnType result = E_NOT_OK;

    /* no job of this module has a second output or a verification result */
    (void)secondaryOutputPtr;
    (void)secondaryOutputLengthPtr;
    (void)verifyPtr;

    /* cppcheck-suppress misra-c2012-10.4 */
    if ((Csm_PqcReady == FALSE) || (cfgPtr == NULL) || (cfgPtr->CsmJobService != CSM_PQC_SERVICE_CUSTOM) ||
        (mode != CRYPTO_OPERATIONMODE_SINGLECALL) || (CSM_PQC_KEYID_IS_SESSION(targetKeyId) == 0))
    {
        return E_NOT_OK;
    }
    keyPtr = &Csm_PqcSessionKeys[CSM_PQC_PEER_FROM_SESSION(targetKeyId)];

    switch (cfgPtr->CsmAlgorithmMode)
    {
        case CSM_PQC_ALGOMODE_KEM_KEYGEN:
            /* output: encapsulation key; the decapsulation key goes to element CSM_KE_VENDOR_KEM_DK */
            if ((outputPtr == NULL) || (outputLengthPtr == NULL) || (*outputLengthPtr < CSM_MLKEM_PUBLIC_KEY_BYTES))
            {
                break;
            }
            Csm_Pqc_DiscardKem(keyPtr);
            if (CryIf_KemKeyGen(outputPtr, keyPtr->CsmDk) != E_OK)
            {
                Csm_Pqc_DiscardKem(keyPtr);
                result = CRYPTO_E_CUSTOM_ERROR;
                break;
            }
            keyPtr->CsmDkSet = TRUE;
            CSM_PQC_TAP(CSM_PQC_TAP_DK, keyPtr->CsmDk, (uint32)sizeof(keyPtr->CsmDk));
            *outputLengthPtr = CSM_MLKEM_PUBLIC_KEY_BYTES;
            result = E_OK;
            break;

        case CSM_PQC_ALGOMODE_KEM_ENCAPS:
            /* input: encapsulation key; output: ciphertext; the shared secret goes to CSM_KE_VENDOR_KEM_SS */
            if ((inputPtr == NULL) || (inputLength != CSM_MLKEM_PUBLIC_KEY_BYTES) ||
                (outputPtr == NULL) || (outputLengthPtr == NULL) || (*outputLengthPtr < CSM_MLKEM_CIPHERTEXT_BYTES))
            {
                break;
            }
            Csm_Pqc_DiscardKem(keyPtr);
            if (CryIf_KemEncapsulate(inputPtr, outputPtr, keyPtr->CsmSs) != E_OK)
            {
                Csm_Pqc_DiscardKem(keyPtr);
                result = CRYPTO_E_CUSTOM_ERROR;
                break;
            }
            keyPtr->CsmSsSet = TRUE;
            CSM_PQC_TAP(CSM_PQC_TAP_SS, keyPtr->CsmSs, (uint32)sizeof(keyPtr->CsmSs));
            *outputLengthPtr = CSM_MLKEM_CIPHERTEXT_BYTES;
            result = E_OK;
            break;

        case CSM_PQC_ALGOMODE_KEM_DECAPS:
            /* input: ciphertext; uses and erases the decapsulation key; the shared secret goes to
             * CSM_KE_VENDOR_KEM_SS */
            if ((inputPtr == NULL) || (inputLength != CSM_MLKEM_CIPHERTEXT_BYTES))
            {
                break;
            }
            if (keyPtr->CsmDkSet == FALSE)
            {
                /* no decapsulation key: of the values [SWS_Csm_91107] lists, "custom processing failed" */
                result = CRYPTO_E_CUSTOM_ERROR;
                break;
            }
            result = CryIf_KemDecapsulate(inputPtr, keyPtr->CsmDk, keyPtr->CsmSs);
            OPENSSL_cleanse(keyPtr->CsmDk, sizeof(keyPtr->CsmDk));
            keyPtr->CsmDkSet = FALSE;
            if (result != E_OK)
            {
                Csm_Pqc_DiscardKem(keyPtr);
                result = CRYPTO_E_CUSTOM_ERROR;
                break;
            }
            keyPtr->CsmSsSet = TRUE;
            CSM_PQC_TAP(CSM_PQC_TAP_SS, keyPtr->CsmSs, (uint32)sizeof(keyPtr->CsmSs));
            break;

        case CSM_PQC_ALGOMODE_HS_KDF:
            if ((inputPtr == NULL) || (inputLength == 0U) ||
                (secondaryInputPtr == NULL) || (secondaryInputLength > CSM_HS_KDF_INFO_PART_MAX_BYTES) ||
                (tertiaryInputPtr == NULL) || (tertiaryInputLength > CSM_HS_KDF_INFO_PART_MAX_BYTES) ||
                (outputPtr == NULL) || (outputLengthPtr == NULL) || (*outputLengthPtr < CSM_HS_KDF_OUTPUT_BYTES))
            {
                break;
            }
            if (keyPtr->CsmSsSet == FALSE)
            {
                result = CRYPTO_E_CUSTOM_ERROR;     /* no shared secret */
                break;
            }
            result = Csm_Pqc_DeriveHandshakeKeys(keyPtr, inputPtr, inputLength,
                                                 secondaryInputPtr, secondaryInputLength,
                                                 tertiaryInputPtr, tertiaryInputLength, outputPtr);
            *outputLengthPtr = (result == E_OK) ? CSM_HS_KDF_OUTPUT_BYTES : 0U;
            break;

        case CSM_PQC_ALGOMODE_DISCARD:
            Csm_Pqc_DiscardKem(keyPtr);
            result = E_OK;
            break;

        default:
            break;
    }

    return result;
}
