#ifndef INCLUDE_CSM_PQC_H_
#define INCLUDE_CSM_PQC_H_

/********************************************************************************************************/
/*  Vendor (post-quantum) part of the Csm: job and key-element identifiers of the ML-DSA-65 signature     */
/*  jobs and of the custom-service jobs (ML-KEM-768, handshake key derivation), the per-peer session key  */
/*  object, Csm_CustomService and Csm_KeyElementGet. Included by Csm.h.                                   */
/********************************************************************************************************/

#include "Csm/Csm.h"

/* [SWS_Csm_91043] values this part returns in addition to the ones in Csm.h */
#ifndef CRYPTO_E_KEY_READ_FAIL
#define CRYPTO_E_KEY_READ_FAIL      ((Std_ReturnType)0x06)
#endif
#ifndef CRYPTO_E_KEY_WRITE_FAIL
#define CRYPTO_E_KEY_WRITE_FAIL     ((Std_ReturnType)0x07)
#endif
#ifndef CRYPTO_E_KEY_NOT_AVAILABLE
#define CRYPTO_E_KEY_NOT_AVAILABLE  ((Std_ReturnType)0x08)
#endif
#ifndef CRYPTO_E_CUSTOM_ERROR
#define CRYPTO_E_CUSTOM_ERROR       ((Std_ReturnType)0x0E)
#endif

/* Service of a job row, values of Crypto_ServiceInfoType [SWS_Csm_01031]; the custom service is not
 * in the enumeration of Crypto_GeneralTypes.h */
#define CSM_PQC_SERVICE_SIGNATUREGENERATE   ((uint8)CRYPTO_SIGNATUREGENERATE)
#define CSM_PQC_SERVICE_SIGNATUREVERIFY     ((uint8)CRYPTO_SIGNATUREVERIFY)
#define CSM_PQC_SERVICE_CUSTOM              ((uint8)0x15U)

/* Custom algorithm family and mode identifiers: none of these algorithms is in
 * Crypto_AlgorithmFamilyType [SWS_Csm_01047]; custom identifiers use 128..254 [SWS_Crypto_00240]
 * (0x80 is taken by CRYPTO_ALGOFAM_KEYM, Crypto Driver SWS 7.2.7.2). */
#define CSM_PQC_ALGOFAM_MLDSA65             ((uint8)0x81U)  /* FIPS 204 ML-DSA-65 */
#define CSM_PQC_ALGOFAM_MLKEM768            ((uint8)0x82U)  /* FIPS 203 ML-KEM-768 */
#define CSM_PQC_ALGOFAM_HS_KDF              ((uint8)0x83U)  /* HKDF-SHA-256 key schedule of PQC-SecOC-HS-v1 */
#define CSM_PQC_ALGOMODE_MLDSA_CTX          ((uint8)0x81U)  /* ML-DSA.Sign / Verify, hedged, with a context string */
#define CSM_PQC_ALGOMODE_KEM_KEYGEN         ((uint8)0x82U)
#define CSM_PQC_ALGOMODE_KEM_ENCAPS         ((uint8)0x83U)
#define CSM_PQC_ALGOMODE_KEM_DECAPS         ((uint8)0x84U)
#define CSM_PQC_ALGOMODE_HS_KDF             ((uint8)0x85U)  /* one Extract and four Expands */
#define CSM_PQC_ALGOMODE_DISCARD            ((uint8)0x86U)  /* erase the KEM elements of the session key */

/* Signature jobs. The key and the FIPS 204 context are selected by the job:
 *   CSM_JOBID (SecOC_Cfg.h)              PDU sign       local secret key   ctx_pdu of peer 0
 *   CSM_JOBID_VERIFY_PEER_BASE + p       PDU verify     public key of p    ctx_pdu of peer p
 *   CSM_JOBID_VERIFY_LOOPBACK            PDU verify     local public key   ctx_pdu of peer 0
 *   CSM_JOBID_HS_SIGN                    handshake sign local secret key   "PQC-SecOC-HS-v1"
 *   CSM_JOBID_HS_VERIFY_PEER_BASE + p    handshake verify public key of p  "PQC-SecOC-HS-v1"
 * A job id that is not listed is refused (E_NOT_OK). The loopback job verifies what this node signed
 * itself with CSM_JOBID: for single-node tests and harnesses, never for a PDU of a peer. */
#define CSM_JOBID_VERIFY_LOOPBACK           ((uint32)11U)
#define CSM_JOBID_HS_SIGN                   ((uint32)30U)
#define CSM_JOBID_HS_VERIFY_PEER_BASE       ((uint32)0x2100U)

/* Custom-service jobs [SWS_Csm_91107]; targetKeyId is the session key of the peer */
#define CSM_JOBID_KEM_KEYGEN                ((uint32)31U)
#define CSM_JOBID_KEM_ENCAPS                ((uint32)32U)
#define CSM_JOBID_KEM_DECAPS                ((uint32)33U)
#define CSM_JOBID_HS_KDF                    ((uint32)34U)
#define CSM_JOBID_KEM_DISCARD               ((uint32)35U)

/* Session key object of peer p: key id CSM_KEYID_SESSION_BASE + p. Vendor key elements, from 1000
 * [SWS_Csm_00952]. The two KEM elements are written and consumed by the custom service only: no
 * Csm_KeyElementSet, no Csm_KeyElementGet. No SecOC job references them. */
#define CSM_KE_VENDOR_KEM_DK                ((uint32)1000U) /* ML-KEM decapsulation key */
#define CSM_KE_VENDOR_KEM_SS                ((uint32)1001U) /* ML-KEM shared secret */
#define CSM_KE_VENDOR_PDU_SIG_CTX           ((uint32)1002U) /* FIPS 204 context of the PDU signatures */
/* Vendor element of an ML-DSA key (CSM_KEYID_MLDSA_LOCAL, CSM_KEYID_PEER_PUBKEY_BASE + p): SHA-256 of
 * the public key, the handle the handshake uses to name a pinned key. Read only. */
#define CSM_KE_VENDOR_KEY_ID                ((uint32)1003U)

#define CSM_MLKEM_SECRET_KEY_BYTES          PQC_MLKEM_SECRET_KEY_BYTES
#define CSM_KEY_ID_BYTES                    (32U)
#define CSM_PDU_SIG_CTX_BYTES               PQC_PDU_SIG_CTX_BYTES
#define CSM_HS_SIG_CTX                      "PQC-SecOC-HS-v1"
#define CSM_HS_SIG_CTX_BYTES                (15U)

/* Handshake key derivation (job CSM_JOBID_HS_KDF):
 *   inputPtr          HKDF salt
 *   secondaryInputPtr first part of every info string
 *   tertiaryInputPtr  last part of every info string
 *   outputPtr         four keys of CSM_DERIVED_KEY_LENGTH bytes, info = secondary || label || tertiary
 *                     with the labels "kc-r", "kc-i", "auth-i2r", "auth-r2i", in this order
 * The input keying material is the shared secret element of targetKeyId; it is erased by the call. */
#define CSM_HS_KDF_NUM_KEYS                 (4U)
#define CSM_HS_KDF_OUTPUT_BYTES             (CSM_HS_KDF_NUM_KEYS * CSM_DERIVED_KEY_LENGTH)
#define CSM_HS_KDF_INFO_PART_MAX_BYTES      (64U)

/* [SWS_Csm_91107] */
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
    Crypto_VerifyResultType* verifyPtr);

/* [SWS_Csm_00959] */
Std_ReturnType Csm_KeyElementGet(
    uint32 keyId,
    uint32 keyElementId,
    uint8* keyElementPtr,
    uint32* keyElementLengthPtr);

/******************************************* used by Csm.c only ******************************************/

typedef struct
{
    boolean CsmPeerKey;             /* TRUE: public key of CsmPeer; FALSE: local key pair */
    uint8 CsmPeer;
    const uint8* CsmContextPtr;
    uint32 CsmContextLength;
} Csm_PqcSignatureJobType;

#define CSM_PQC_KEYID_SLOT_LOCAL            (0U)
#define CSM_PQC_KEYID_SLOT_PEER(p)          ((uint8)(1U + (p)))

void Csm_Pqc_Reset(void);
void Csm_Pqc_SetReady(void);
/* publicKeyPtr NULL: the key of this slot is not valid any more */
void Csm_Pqc_SetKeyId(uint8 slot, const uint8* publicKeyPtr);
Std_ReturnType Csm_Pqc_SignatureJob(uint32 jobId, uint8 service, Csm_PqcSignatureJobType* jobPtr);
Std_ReturnType Csm_Pqc_SessionKeyElementSet(uint8 peer, uint32 keyElementId, const uint8* keyPtr, uint32 keyLength);
Std_ReturnType Csm_Pqc_SessionKeySetValid(uint8 peer);

#ifdef SECOC_TEST_ACCESS
/* Test builds only (erasure and known-answer tests): static storage of the session key objects, and a
 * tap the test implements to record secrets while they exist. Absent from gateway builds. */
#define CSM_PQC_TAP_DK      (0U)
#define CSM_PQC_TAP_SS      (1U)
#define CSM_PQC_TAP_PRK     (2U)
#define CSM_PQC_TAP_OKM     (3U)
void Csm_Pqc_TestStorage(const uint8** storagePtr, uint32* lengthPtr);
void Csm_Pqc_TestTap(uint8 kind, const uint8* dataPtr, uint32 length);
#endif

#endif
