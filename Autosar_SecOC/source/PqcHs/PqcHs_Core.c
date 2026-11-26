/********************************************************************************************************/
/*  PqcHs core: the handshake PQC-SecOC-HS-v1 of one instance (one pinned peer, one role).                */
/*                                                                                                        */
/*  Rules that shape this file:                                                                           */
/*  - Messages are only stored by the reception calls; they are processed, keys are installed and timers  */
/*    are evaluated in PqcHs_Core_MainFunction.                                                           */
/*  - Discard rule: a message with a wrong length, version, identity or signature, or one that matches    */
/*    no handshake state, changes nothing. A MAC failure behind a valid signature ends that handshake.    */
/*  - The only code that installs K_auth, the PDU signature context or "established" is                   */
/*    PqcHs_Install, reached from the acceptance of M2 (initiator, after M3 is handed over) and of M3     */
/*    (responder).                                                                                        */
/*  - No secret is held in a local buffer: the derived keys are written straight into the instance and    */
/*    erased there with OPENSSL_cleanse; dk, ss and PRK never leave the crypto layer.                     */
/********************************************************************************************************/

#include "PqcHs/PqcHs_Core.h"
#include "Csm/Csm.h"
#include "SecOC/SecOC.h"
#include "SecOC/FVM.h"

#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

/* field offsets */
#define PQCHS_OFF_ID                (1U)                                        /* M1, M2 */
#define PQCHS_M1_OFF_EK             (1U + PQCHS_ID_BYTES)
#define PQCHS_M2_OFF_CT             (1U + PQCHS_ID_BYTES)
#define PQCHS_M2_OFF_SIG            (PQCHS_M2_OFF_CT + PQCHS_CT_BYTES)          /* = bytes covered by th2 */
#define PQCHS_M2_OFF_MAC            (PQCHS_M2_OFF_SIG + PQCHS_SIG_BYTES)
#define PQCHS_M3_OFF_SIG            (1U)
#define PQCHS_M3_OFF_MAC            (PQCHS_M3_OFF_SIG + PQCHS_SIG_BYTES)
#define PQCHS_M4_OFF_MAC            (1U)

/* pending keys, in the output order of the key derivation */
#define PQCHS_KEY_KC_R              (0U)
#define PQCHS_KEY_KC_I              (1U)
#define PQCHS_KEY_AUTH_I2R          (2U)
#define PQCHS_KEY_AUTH_R2I          (3U)

#define PQCHS_SIGNED_BYTES          (1U + PQCHS_HASH_BYTES)     /* role byte || transcript hash */
#define PQCHS_ROLE_BYTE_INITIATOR   ((uint8)'I')
#define PQCHS_ROLE_BYTE_RESPONDER   ((uint8)'R')

#define PQCHS_SESSION_KEY(inst)     (CSM_KEYID_SESSION_BASE + (uint32)(inst)->Cfg->PqcHsPeer)
#define PQCHS_PEER_KEY(inst)        (CSM_KEYID_PEER_PUBKEY_BASE + (uint32)(inst)->Cfg->PqcHsPeer)
#define PQCHS_VERIFY_JOB(inst)      (CSM_JOBID_HS_VERIFY_PEER_BASE + (uint32)(inst)->Cfg->PqcHsPeer)
#define PQCHS_IS_INITIATOR(inst)    ((inst)->Cfg->PqcHsRole == PQCHS_ROLE_INITIATOR)

/* created once: no allocation while a handshake runs */
static EVP_MD* PqcHs_HashAlg = NULL;
static EVP_MD_CTX* PqcHs_HashCtx = NULL;
static const uint8 PqcHs_Zero[PQCHS_KEY_BYTES] = { 0U };

/********************************************************************************************************/
/******************************************** small helpers *********************************************/
/********************************************************************************************************/

static uint64 PqcHs_NowNs(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64)ts.tv_sec * 1000000000ULL) + (uint64)ts.tv_nsec;
}

static void PqcHs_AddTimes(PqcHs_StageTimesType* Sum, const PqcHs_StageTimesType* Part)
{
    Sum->KeygenNs += Part->KeygenNs;
    Sum->EncapsNs += Part->EncapsNs;
    Sum->DecapsNs += Part->DecapsNs;
    Sum->SignNs += Part->SignNs;
    Sum->VerifyNs += Part->VerifyNs;
    Sum->KdfNs += Part->KdfNs;
    Sum->HashNs += Part->HashNs;
    Sum->MacNs += Part->MacNs;
}

/* When the log is full the oldest row is dropped; the gap shows in Seq. */
static void PqcHs_Record(PqcHs_InstanceType* Inst, PqcHs_ResultType Result, uint64 TotalNs,
                         uint32 BytesTx, uint32 BytesRx, const PqcHs_StageTimesType* Times)
{
    PqcHs_AttemptInfoType* row;

    if (Inst->LogCount == PQCHS_ATTEMPT_LOG_SIZE)
    {
        Inst->LogHead = (uint8)((Inst->LogHead + 1U) % PQCHS_ATTEMPT_LOG_SIZE);
        Inst->LogCount--;
    }
    row = &Inst->Log[(Inst->LogHead + Inst->LogCount) % PQCHS_ATTEMPT_LOG_SIZE];
    Inst->LogCount++;

    row->Seq = Inst->NextSeq;
    Inst->NextSeq++;
    row->Role = Inst->Cfg->PqcHsRole;
    row->Result = Result;
    row->TotalNs = TotalNs;
    row->BytesTx = BytesTx;
    row->BytesRx = BytesRx;
    if (Times != NULL)
    {
        row->Times = *Times;
    }
    else
    {
        (void)memset(&row->Times, 0, sizeof(row->Times));
    }
}

static void PqcHs_AttemptBegin(PqcHs_InstanceType* Inst, uint64 StartNs)
{
    Inst->AttemptOpen = TRUE;
    Inst->AttemptInstalled = FALSE;
    Inst->AttemptStartNs = StartNs;
    Inst->AttemptTotalNs = 0U;
    Inst->AttemptBytesTx = 0U;
    Inst->AttemptBytesRx = 0U;
    (void)memset(&Inst->AttemptTimes, 0, sizeof(Inst->AttemptTimes));
}

static void PqcHs_AttemptEnd(PqcHs_InstanceType* Inst, PqcHs_ResultType Result)
{
    if (Inst->AttemptOpen == TRUE)
    {
        uint64 total = (Inst->AttemptInstalled == TRUE) ? Inst->AttemptTotalNs : (PqcHs_NowNs() - Inst->AttemptStartNs);

        PqcHs_Record(Inst, Result, total, Inst->AttemptBytesTx, Inst->AttemptBytesRx, &Inst->AttemptTimes);
        Inst->AttemptOpen = FALSE;
    }
}

/* The received message is dropped and nothing else changes */
static void PqcHs_Discard(PqcHs_InstanceType* Inst, PqcHs_ResultType Result, const PqcHs_StageTimesType* Work)
{
    PqcHs_Record(Inst, Result, PqcHs_NowNs() - Inst->RxDoneNs, 0U, Inst->RxLength + PQCHS_PDU_HEADER_BYTES, Work);
}

static void PqcHs_ReleaseGate(PqcHs_InstanceType* Inst)
{
    if (Inst->RxGated == TRUE)
    {
        Inst->RxGated = FALSE;
        SoAd_RxGateRelease(Inst->Cfg->PqcHsRxPduId[1]);
    }
}

static uint32 PqcHs_MessageLength(const PqcHs_InstanceType* Inst, boolean Transmit, uint8 Msg)
{
    /* initiator sends M1, M3 and receives M2, M4; responder the other way round */
    boolean firstPair = (PQCHS_IS_INITIATOR(Inst) == Transmit) ? TRUE : FALSE;     /* TRUE: M1 / M3 */

    if (firstPair == TRUE)
    {
        return (Msg == 0U) ? PQCHS_M1_BYTES : PQCHS_M3_BYTES;
    }
    return (Msg == 0U) ? PQCHS_M2_BYTES : PQCHS_M4_BYTES;
}

static const uint8* PqcHs_TxMessage(const PqcHs_InstanceType* Inst, uint8 TxMsg)
{
    if (PQCHS_IS_INITIATOR(Inst))
    {
        return (TxMsg == 0U) ? Inst->M1 : Inst->M3;
    }
    return (TxMsg == 0U) ? Inst->M2 : Inst->M4;
}

/********************************************************************************************************/
/********************************************* crypto steps *********************************************/
/********************************************************************************************************/

/* Out = SHA-384(L || M1 || P2 || P3): every transcript hash of the protocol starts with L || M1 */
static Std_ReturnType PqcHs_Hash(const PqcHs_InstanceType* Inst, const uint8* P2, uint32 N2,
                                 const uint8* P3, uint32 N3, uint8* Out, PqcHs_StageTimesType* Times)
{
    uint64 t0 = PqcHs_NowNs();
    unsigned int length = 0U;
    Std_ReturnType result = E_NOT_OK;

    if ((PqcHs_HashCtx != NULL) &&
        (EVP_DigestInit_ex2(PqcHs_HashCtx, PqcHs_HashAlg, NULL) == 1) &&
        (EVP_DigestUpdate(PqcHs_HashCtx, PQCHS_LABEL, PQCHS_LABEL_BYTES) == 1) &&
        (EVP_DigestUpdate(PqcHs_HashCtx, Inst->M1, PQCHS_M1_BYTES) == 1) &&
        ((N2 == 0U) || (EVP_DigestUpdate(PqcHs_HashCtx, P2, (size_t)N2) == 1)) &&
        ((N3 == 0U) || (EVP_DigestUpdate(PqcHs_HashCtx, P3, (size_t)N3) == 1)) &&
        (EVP_DigestFinal_ex(PqcHs_HashCtx, Out, &length) == 1) &&
        (length == PQCHS_HASH_BYTES))
    {
        result = E_OK;
    }
    Times->HashNs += PqcHs_NowNs() - t0;
    return result;
}

static Std_ReturnType PqcHs_Sign(uint8 RoleByte, const uint8* Hash, uint8* Signature, PqcHs_StageTimesType* Times)
{
    uint8 signedData[PQCHS_SIGNED_BYTES];
    uint32 length = PQCHS_SIG_BYTES;
    uint64 t0 = PqcHs_NowNs();
    Std_ReturnType result;

    signedData[0] = RoleByte;
    (void)memcpy(&signedData[1], Hash, PQCHS_HASH_BYTES);
    result = Csm_SignatureGenerate(CSM_JOBID_HS_SIGN, CRYPTO_OPERATIONMODE_SINGLECALL, signedData,
                                   PQCHS_SIGNED_BYTES, Signature, &length);
    Times->SignNs += PqcHs_NowNs() - t0;
    return ((result == E_OK) && (length == PQCHS_SIG_BYTES)) ? E_OK : E_NOT_OK;
}

/* E_OK only for "request done and signature valid" */
static Std_ReturnType PqcHs_Verify(const PqcHs_InstanceType* Inst, uint8 RoleByte, const uint8* Hash,
                                   const uint8* Signature, PqcHs_StageTimesType* Times)
{
    uint8 signedData[PQCHS_SIGNED_BYTES];
    Crypto_VerifyResultType verdict = CRYPTO_E_VER_NOT_OK;
    uint64 t0 = PqcHs_NowNs();
    Std_ReturnType result;

    signedData[0] = RoleByte;
    (void)memcpy(&signedData[1], Hash, PQCHS_HASH_BYTES);
    result = Csm_SignatureVerify(PQCHS_VERIFY_JOB(Inst), CRYPTO_OPERATIONMODE_SINGLECALL, signedData,
                                 PQCHS_SIGNED_BYTES, Signature, PQCHS_SIG_BYTES, &verdict);
    Times->VerifyNs += PqcHs_NowNs() - t0;
    return ((result == E_OK) && (verdict == CRYPTO_E_VER_OK)) ? E_OK : E_NOT_OK;
}

static Std_ReturnType PqcHs_KeyId(uint32 KeyId, uint8* Id)
{
    uint32 length = PQCHS_ID_BYTES;

    if ((Csm_KeyElementGet(KeyId, CSM_KE_VENDOR_KEY_ID, Id, &length) == E_OK) && (length == PQCHS_ID_BYTES))
    {
        return E_OK;
    }
    return E_NOT_OK;
}

static Std_ReturnType PqcHs_Custom(const PqcHs_InstanceType* Inst, uint32 JobId, const uint8* Input, uint32 InputLength,
                                   uint8* Output, uint32 OutputLength, uint64* TimeNs)
{
    uint32 length = OutputLength;
    uint64 t0 = PqcHs_NowNs();
    Std_ReturnType result;

    result = Csm_CustomService(JobId, CRYPTO_OPERATIONMODE_SINGLECALL, PQCHS_SESSION_KEY(Inst), Input, InputLength,
                               NULL, 0U, NULL, 0U, Output, (Output != NULL) ? &length : NULL, NULL, NULL, NULL);
    *TimeNs += PqcHs_NowNs() - t0;
    return ((result == E_OK) && (length == OutputLength)) ? E_OK : E_NOT_OK;
}

/* The four keys, HKDF-Expand(PRK, L || label || ID_A || ID_B) with PRK = HKDF-Extract(th2, ss), straight
 * into the instance */
static Std_ReturnType PqcHs_DeriveKeys(PqcHs_InstanceType* Inst, const uint8* Th2, PqcHs_StageTimesType* Times)
{
    uint8 ids[2U * PQCHS_ID_BYTES];
    uint32 length = (uint32)sizeof(Inst->Keys);
    uint64 t0 = PqcHs_NowNs();
    Std_ReturnType result;

    (void)memcpy(ids, &Inst->M1[PQCHS_OFF_ID], PQCHS_ID_BYTES);
    (void)memcpy(&ids[PQCHS_ID_BYTES], &Inst->M2[PQCHS_OFF_ID], PQCHS_ID_BYTES);
    result = Csm_CustomService(CSM_JOBID_HS_KDF, CRYPTO_OPERATIONMODE_SINGLECALL, PQCHS_SESSION_KEY(Inst),
                               Th2, PQCHS_HASH_BYTES, (const uint8*)PQCHS_LABEL, PQCHS_LABEL_BYTES,
                               ids, (uint32)sizeof(ids), (uint8*)Inst->Keys, &length, NULL, NULL, NULL);
    Times->KdfNs += PqcHs_NowNs() - t0;
    if ((result != E_OK) || (length != (uint32)sizeof(Inst->Keys)))
    {
        OPENSSL_cleanse(Inst->Keys, sizeof(Inst->Keys));
        return E_NOT_OK;
    }
    return E_OK;
}

/* Key-confirmation MAC over a transcript hash, through the Csm MAC jobs on the confirmation-key slot.
 * The slot holds the key only for the duration of the call. Verify == TRUE: Tag is the received tag.
 * PQCHS_RESULT_OK: tag made, or compared and right. PQCHS_RESULT_MAC_FAIL: compared and wrong.
 * PQCHS_RESULT_STATE: the Csm did not do its part, which includes erasing the key in the slot. */
static PqcHs_ResultType PqcHs_ConfirmMac(const PqcHs_InstanceType* Inst, boolean Verify, const uint8* Key,
                                         const uint8* Hash, uint8* Tag, PqcHs_StageTimesType* Times)
{
    const PqcHs_InstanceConfigType* cfg = Inst->Cfg;
    uint64 t0 = PqcHs_NowNs();
    PqcHs_ResultType result = PQCHS_RESULT_STATE;

    if ((Csm_KeyElementSet(cfg->PqcHsConfirmKeyId, CRYPTO_KE_MAC_KEY, Key, PQCHS_KEY_BYTES) == E_OK) &&
        (Csm_KeySetValid(cfg->PqcHsConfirmKeyId) == E_OK))
    {
        if (Verify == TRUE)
        {
            Crypto_VerifyResultType verdict = CRYPTO_E_VER_NOT_OK;

            if (Csm_MacVerify(cfg->PqcHsConfirmVerifyJobId, CRYPTO_OPERATIONMODE_SINGLECALL, Hash, PQCHS_HASH_BYTES,
                              Tag, PQCHS_MAC_BYTES * 8U, &verdict) == E_OK)
            {
                result = (verdict == CRYPTO_E_VER_OK) ? PQCHS_RESULT_OK : PQCHS_RESULT_MAC_FAIL;
            }
        }
        else
        {
            uint32 length = PQCHS_MAC_BYTES;

            if ((Csm_MacGenerate(cfg->PqcHsConfirmGenerateJobId, CRYPTO_OPERATIONMODE_SINGLECALL, Hash,
                                 PQCHS_HASH_BYTES, Tag, &length) == E_OK) && (length == PQCHS_MAC_BYTES))
            {
                result = PQCHS_RESULT_OK;
            }
        }
    }
    /* writing the element erases the key in the slot and leaves the slot invalid; a confirmation whose
     * key could not be erased does not count */
    if ((Csm_KeyElementSet(cfg->PqcHsConfirmKeyId, CRYPTO_KE_MAC_KEY, PqcHs_Zero, PQCHS_KEY_BYTES) != E_OK) &&
        (result == PQCHS_RESULT_OK))
    {
        result = PQCHS_RESULT_STATE;
    }
    Times->MacNs += PqcHs_NowNs() - t0;
    return result;
}

/* Pending secrets of this handshake: the keys here, and dk / ss in the crypto layer. Returns the result
 * the attempt ends with: a handshake whose secrets could not be erased does not end as OK. */
static PqcHs_ResultType PqcHs_WipeSecrets(PqcHs_InstanceType* Inst, PqcHs_ResultType Result)
{
    OPENSSL_cleanse(Inst->Keys, sizeof(Inst->Keys));
    if ((Csm_CustomService(CSM_JOBID_KEM_DISCARD, CRYPTO_OPERATIONMODE_SINGLECALL, PQCHS_SESSION_KEY(Inst),
                           NULL, 0U, NULL, 0U, NULL, 0U, NULL, NULL, NULL, NULL, NULL) != E_OK) &&
        (Result == PQCHS_RESULT_OK))
    {
        return PQCHS_RESULT_STATE;
    }
    return Result;
}

/* Key installation: one uninterrupted step, no Csm job in between. Both K_auth elements, both keys
 * valid, the PDU signature context of the peer's session key object, the session-bound freshness
 * values. If a call fails the session is torn down, not left half-switched: no K_auth key and no PDU
 * signature context is valid afterwards, in either variant, until the next installation. */
static Std_ReturnType PqcHs_Install(PqcHs_InstanceType* Inst)
{
    const PqcHs_InstanceConfigType* cfg = Inst->Cfg;
    const uint8* txKey = Inst->Keys[PQCHS_IS_INITIATOR(Inst) ? PQCHS_KEY_AUTH_I2R : PQCHS_KEY_AUTH_R2I];
    const uint8* rxKey = Inst->Keys[PQCHS_IS_INITIATOR(Inst) ? PQCHS_KEY_AUTH_R2I : PQCHS_KEY_AUTH_I2R];
    uint8 pduContext[CSM_PDU_SIG_CTX_BYTES];
    Std_ReturnType result = E_NOT_OK;
    uint8 idx;

    (void)memcpy(pduContext, PQC_PDU_SIG_CTX_LABEL, PQC_PDU_SIG_CTX_LABEL_BYTES);
    (void)memcpy(&pduContext[PQC_PDU_SIG_CTX_LABEL_BYTES], Inst->Sess, PQCHS_HASH_BYTES);

    if ((Csm_KeyElementSet(cfg->PqcHsTxAuthKeyId, CRYPTO_KE_MAC_KEY, txKey, PQCHS_KEY_BYTES) == E_OK) &&
        (Csm_KeyElementSet(cfg->PqcHsRxAuthKeyId, CRYPTO_KE_MAC_KEY, rxKey, PQCHS_KEY_BYTES) == E_OK) &&
        (Csm_KeySetValid(cfg->PqcHsTxAuthKeyId) == E_OK) &&
        (Csm_KeySetValid(cfg->PqcHsRxAuthKeyId) == E_OK) &&
        (Csm_KeyElementSet(PQCHS_SESSION_KEY(Inst), CSM_KE_VENDOR_PDU_SIG_CTX, pduContext, CSM_PDU_SIG_CTX_BYTES) == E_OK) &&
        (Csm_KeySetValid(PQCHS_SESSION_KEY(Inst)) == E_OK))
    {
        for (idx = 0U; idx < cfg->PqcHsNumFreshnessIds; idx++)
        {
            FVM_SessionInstall(cfg->PqcHsFreshnessIds[idx]);
        }
        Inst->Established = TRUE;
        (void)memcpy(Inst->Sid, Inst->Sess, PQCHS_SID_BYTES);
        Inst->InstallCount++;
        result = E_OK;
    }
    else
    {
        Inst->Established = FALSE;
        (void)memset(Inst->Sid, 0, sizeof(Inst->Sid));
        /* A written key element leaves its key invalid until it is set valid, and it is not set valid
         * here. The step has already failed; nothing further depends on these three results. */
        (void)memset(&pduContext[PQC_PDU_SIG_CTX_LABEL_BYTES], 0, PQCHS_HASH_BYTES);
        (void)Csm_KeyElementSet(cfg->PqcHsTxAuthKeyId, CRYPTO_KE_MAC_KEY, PqcHs_Zero, PQCHS_KEY_BYTES);
        (void)Csm_KeyElementSet(cfg->PqcHsRxAuthKeyId, CRYPTO_KE_MAC_KEY, PqcHs_Zero, PQCHS_KEY_BYTES);
        (void)Csm_KeyElementSet(PQCHS_SESSION_KEY(Inst), CSM_KE_VENDOR_PDU_SIG_CTX, pduContext, CSM_PDU_SIG_CTX_BYTES);
    }

    OPENSSL_cleanse(Inst->Keys[PQCHS_KEY_AUTH_I2R], PQCHS_KEY_BYTES);
    OPENSSL_cleanse(Inst->Keys[PQCHS_KEY_AUTH_R2I], PQCHS_KEY_BYTES);
    return result;
}

/* E_NOT_OK and nothing changed when a message of this side is still in transmission, or when SoAd
 * does not take the request (no connection, or it could not be opened) */
static Std_ReturnType PqcHs_Transmit(PqcHs_InstanceType* Inst, uint8 TxMsg)
{
    PduInfoType info;
    Std_ReturnType result;

    if (Inst->TxActive == TRUE)
    {
        return E_NOT_OK;
    }
    info.SduDataPtr = NULL;
    info.MetaDataPtr = NULL;
    info.SduLength = PqcHs_MessageLength(Inst, TRUE, TxMsg);

    Inst->TxActive = TRUE;
    Inst->TxDone = FALSE;
    Inst->TxMsg = TxMsg;
    Inst->TxLength = info.SduLength;
    Inst->TxPos = 0U;
    Inst->TxRequesting = TRUE;
    result = SoAd_TpTransmit(Inst->Cfg->PqcHsTxPduId[TxMsg], &info);
    Inst->TxRequesting = FALSE;
    if (result != E_OK)
    {
        Inst->TxActive = FALSE;
        Inst->TxDone = FALSE;
        return E_NOT_OK;
    }
    Inst->AttemptBytesTx += Inst->TxLength + PQCHS_PDU_HEADER_BYTES;
    return E_OK;
}

/********************************************************************************************************/
/********************************************** initiator ***********************************************/
/********************************************************************************************************/

/* The attempt ends without a new session; the next handshake starts T_A after its M1: by then the
 * responder has dropped what it kept of this one (T_A > T_pend) and takes an M1 again (T_A > T_min) */
static void PqcHs_I_Fail(PqcHs_InstanceType* Inst, PqcHs_ResultType Result)
{
    if (Inst->TxHeld == TRUE)
    {
        Inst->TxHeld = FALSE;
        SecOC_TxSessionHold(Inst->Cfg->PqcHsPeer, FALSE);
    }
    PqcHs_AttemptEnd(Inst, PqcHs_WipeSecrets(Inst, Result));
    Inst->DeadlineMs = Inst->RetryMs;
    Inst->State = PQCHS_STATE_I_RETRY;
}

/* A new handshake. M1 is requested first and built only when SoAd has taken the request (the bytes are
 * copied later, from SoAd's main function [SWS_SoAd_00552]): a request that is not taken costs no key
 * pair and no row, changes nothing and is repeated by the next main function. On the connecting side
 * the request is also what opens the connection. */
static void PqcHs_I_Start(PqcHs_InstanceType* Inst, uint64 NowMs)
{
    uint32 bytesTx = Inst->AttemptBytesTx;

    if (PqcHs_Transmit(Inst, 0U) != E_OK)
    {
        return;
    }
    Inst->InitiateRequest = FALSE;
    if (Inst->State != PQCHS_STATE_IDLE)
    {
        /* the attempt that still waited for its acknowledgement, or for its retry time, is over; the
         * M1 just requested is not one of its bytes */
        Inst->AttemptBytesTx = bytesTx;
        PqcHs_I_Fail(Inst, PQCHS_RESULT_STATE);
    }
    PqcHs_AttemptBegin(Inst, PqcHs_NowNs());
    Inst->AttemptBytesTx = PQCHS_M1_BYTES + PQCHS_PDU_HEADER_BYTES;
    Inst->RetryMs = NowMs + Inst->Timers->PqcHsTAMs;
    Inst->DeadlineMs = Inst->RetryMs;

    /* M1 = ver || ID_A || ek, with a fresh ek for every attempt */
    Inst->M1[0] = PQCHS_VERSION;
    if ((PqcHs_KeyId(CSM_KEYID_MLDSA_LOCAL, &Inst->M1[PQCHS_OFF_ID]) != E_OK) ||
        (PqcHs_Custom(Inst, CSM_JOBID_KEM_KEYGEN, NULL, 0U, &Inst->M1[PQCHS_M1_OFF_EK], PQCHS_EK_BYTES,
                      &Inst->AttemptTimes.KeygenNs) != E_OK))
    {
        /* SoAd holds a request and there is no message for it: the transmission is given up here, and
         * SoAd ends it, and the connection, when it asks for the bytes [SWS_SoAd_00651] */
        Inst->TxActive = FALSE;
        PqcHs_I_Fail(Inst, PQCHS_RESULT_STATE);
        return;
    }
    Inst->State = PQCHS_STATE_I_WAIT_M2;
}

static void PqcHs_I_OnM2(PqcHs_InstanceType* Inst, uint64 NowMs)
{
    const uint8* m2 = Inst->Rx;
    PqcHs_StageTimesType work;
    PqcHs_ResultType confirmed;
    uint8 id[PQCHS_ID_BYTES];
    uint8 hash[PQCHS_HASH_BYTES];

    (void)memset(&work, 0, sizeof(work));

    if (Inst->State != PQCHS_STATE_I_WAIT_M2)
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_STATE, &work);
        return;
    }
    if (m2[0] != PQCHS_VERSION)
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_BAD_VER, &work);
        return;
    }
    if ((PqcHs_KeyId(PQCHS_PEER_KEY(Inst), id) != E_OK) || (memcmp(&m2[PQCHS_OFF_ID], id, PQCHS_ID_BYTES) != 0))
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_UNKNOWN_ID, &work);
        return;
    }
    /* th2 = H(L || M1 || ver || ID_B || ct); sig_B over 'R' || th2. The signature is checked before the
     * decapsulation key is used, so a forged M2 leaves the attempt as it was. */
    if (PqcHs_Hash(Inst, m2, PQCHS_M2_OFF_SIG, NULL, 0U, hash, &work) != E_OK)
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_STATE, &work);
        return;
    }
    if (PqcHs_Verify(Inst, PQCHS_ROLE_BYTE_RESPONDER, hash, &m2[PQCHS_M2_OFF_SIG], &work) != E_OK)
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_SIG_FAIL, &work);
        return;
    }

    /* M2 is B's answer to this M1: from here every failure ends the handshake */
    (void)memcpy(Inst->M2, m2, PQCHS_M2_BYTES);
    Inst->AttemptBytesRx += PQCHS_M2_BYTES + PQCHS_PDU_HEADER_BYTES;
    PqcHs_AddTimes(&Inst->AttemptTimes, &work);

    if ((PqcHs_Custom(Inst, CSM_JOBID_KEM_DECAPS, &Inst->M2[PQCHS_M2_OFF_CT], PQCHS_CT_BYTES, NULL, 0U,
                      &Inst->AttemptTimes.DecapsNs) != E_OK) ||
        (PqcHs_DeriveKeys(Inst, hash, &Inst->AttemptTimes) != E_OK) ||
        (PqcHs_Hash(Inst, Inst->M2, PQCHS_M2_OFF_MAC, NULL, 0U, hash, &Inst->AttemptTimes) != E_OK))
    {
        PqcHs_I_Fail(Inst, PQCHS_RESULT_STATE);
        return;
    }
    /* mac_B = HMAC(K_kc_r, H(L || M1 || M2 without mac_B)) */
    confirmed = PqcHs_ConfirmMac(Inst, TRUE, Inst->Keys[PQCHS_KEY_KC_R], hash, &Inst->M2[PQCHS_M2_OFF_MAC],
                                 &Inst->AttemptTimes);
    if (confirmed != PQCHS_RESULT_OK)
    {
        PqcHs_I_Fail(Inst, confirmed);
        return;
    }

    /* M3 = ver || sig_A || mac_A: sig_A over 'I' || H(L || M1 || M2),
     * mac_A = HMAC(K_kc_i, H(L || M1 || M2 || ver || sig_A)); then sess = H(L || M1 || M2 || M3) */
    Inst->M3[0] = PQCHS_VERSION;
    if ((PqcHs_Hash(Inst, Inst->M2, PQCHS_M2_BYTES, NULL, 0U, hash, &Inst->AttemptTimes) != E_OK) ||
        (PqcHs_Sign(PQCHS_ROLE_BYTE_INITIATOR, hash, &Inst->M3[PQCHS_M3_OFF_SIG], &Inst->AttemptTimes) != E_OK) ||
        (PqcHs_Hash(Inst, Inst->M2, PQCHS_M2_BYTES, Inst->M3, PQCHS_M3_OFF_MAC, hash, &Inst->AttemptTimes) != E_OK) ||
        (PqcHs_ConfirmMac(Inst, FALSE, Inst->Keys[PQCHS_KEY_KC_I], hash, &Inst->M3[PQCHS_M3_OFF_MAC],
                          &Inst->AttemptTimes) != PQCHS_RESULT_OK) ||
        (PqcHs_Hash(Inst, Inst->M2, PQCHS_M2_BYTES, Inst->M3, PQCHS_M3_BYTES, Inst->Sess, &Inst->AttemptTimes) != E_OK))
    {
        PqcHs_I_Fail(Inst, PQCHS_RESULT_STATE);
        return;
    }
    OPENSSL_cleanse(Inst->Keys[PQCHS_KEY_KC_I], PQCHS_KEY_BYTES);

    /* Cut-over: no new Secured I-PDU is authenticated from now on; M3 goes out once everything
     * already handed down has left, and the keys are installed when M3 itself has been handed over.
     * The wait for M2 is over; the wait for the flush has its own bound. */
    Inst->TxHeld = TRUE;
    SecOC_TxSessionHold(Inst->Cfg->PqcHsPeer, TRUE);
    Inst->DeadlineMs = NowMs + Inst->Timers->PqcHsTFlushMs;
    Inst->State = PQCHS_STATE_I_CUTOVER;
}

static void PqcHs_I_OnM4(PqcHs_InstanceType* Inst)
{
    PqcHs_StageTimesType work;
    PqcHs_ResultType confirmed;

    (void)memset(&work, 0, sizeof(work));

    if (Inst->State != PQCHS_STATE_I_WAIT_M4)
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_STATE, &work);
        return;
    }
    if (Inst->Rx[0] != PQCHS_VERSION)
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_BAD_VER, &work);
        return;
    }
    /* mac_ack = HMAC(K_kc_r, sess). A wrong one is discarded; the initiator waits out T_A. */
    confirmed = PqcHs_ConfirmMac(Inst, TRUE, Inst->Keys[PQCHS_KEY_KC_R], Inst->Sess, &Inst->Rx[PQCHS_M4_OFF_MAC], &work);
    if (confirmed != PQCHS_RESULT_OK)
    {
        PqcHs_Discard(Inst, confirmed, &work);
        return;
    }

    Inst->AttemptBytesRx += PQCHS_M4_BYTES + PQCHS_PDU_HEADER_BYTES;
    PqcHs_AddTimes(&Inst->AttemptTimes, &work);
    PqcHs_AttemptEnd(Inst, PqcHs_WipeSecrets(Inst, PQCHS_RESULT_OK));
    Inst->State = PQCHS_STATE_IDLE;
}

static void PqcHs_I_TxDone(PqcHs_InstanceType* Inst, uint64 NowMs)
{
    if (Inst->TxMsg == 0U)
    {
        if ((Inst->TxResult != E_OK) && (Inst->State == PQCHS_STATE_I_WAIT_M2))
        {
            PqcHs_I_Fail(Inst, PQCHS_RESULT_STATE);
        }
    }
    else if (Inst->State == PQCHS_STATE_I_SEND_M3)
    {
        /* the session boundary on the stream is the last byte of M3 */
        if ((Inst->TxResult == E_OK) && (PqcHs_Install(Inst) == E_OK))
        {
            Inst->AttemptInstalled = TRUE;
            Inst->AttemptTotalNs = PqcHs_NowNs() - Inst->AttemptStartNs;
            Inst->TxHeld = FALSE;
            SecOC_TxSessionHold(Inst->Cfg->PqcHsPeer, FALSE);
            Inst->DeadlineMs = NowMs + Inst->Timers->PqcHsTAMs;
            Inst->State = PQCHS_STATE_I_WAIT_M4;
        }
        else
        {
            PqcHs_I_Fail(Inst, PQCHS_RESULT_STATE);
        }
    }
    else
    {
        /* confirmation of a transmission that no longer belongs to an attempt */
    }
}

/********************************************************************************************************/
/********************************************** responder ***********************************************/
/********************************************************************************************************/

static void PqcHs_R_Wipe(PqcHs_InstanceType* Inst, PqcHs_ResultType Result)
{
    PqcHs_AttemptEnd(Inst, PqcHs_WipeSecrets(Inst, Result));
    Inst->State = PQCHS_STATE_IDLE;
}

static void PqcHs_R_OnM1(PqcHs_InstanceType* Inst, uint64 NowMs)
{
    const uint8* m1 = Inst->Rx;
    PqcHs_StageTimesType work;
    uint8 id[PQCHS_ID_BYTES];
    uint8 hash[PQCHS_HASH_BYTES];

    (void)memset(&work, 0, sizeof(work));

    if (m1[0] != PQCHS_VERSION)
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_BAD_VER, &work);
        return;
    }
    if ((PqcHs_KeyId(PQCHS_PEER_KEY(Inst), id) != E_OK) || (memcmp(&m1[PQCHS_OFF_ID], id, PQCHS_ID_BYTES) != 0))
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_UNKNOWN_ID, &work);
        return;
    }
    /* one pending handshake per peer: a second M1 is dropped, not substituted; and not more often
     * than every T_min, counted from the last accepted M1. An M1 is not served either while an answer
     * of this side is still in transmission: that message must not change under SoAd. */
    if ((Inst->State != PQCHS_STATE_IDLE) || (Inst->TxActive == TRUE) ||
        ((Inst->LastM1Valid == TRUE) && ((NowMs - Inst->LastM1Ms) < Inst->Timers->PqcHsTMinMs)))
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_STATE, &work);
        return;
    }

    Inst->LastM1Ms = NowMs;
    Inst->LastM1Valid = TRUE;
    PqcHs_AttemptBegin(Inst, Inst->RxDoneNs);
    Inst->AttemptBytesRx = PQCHS_M1_BYTES + PQCHS_PDU_HEADER_BYTES;
    Inst->DeadlineMs = NowMs + Inst->Timers->PqcHsTPendMs;
    (void)memcpy(Inst->M1, m1, PQCHS_M1_BYTES);

    /* M2 = ver || ID_B || ct || sig_B || mac_B. An encapsulation error is a failure: nothing is signed
     * or sent. No key that a SecOC job uses, no session state and no freshness value is touched here:
     * the derived keys stay pending in this instance. */
    Inst->M2[0] = PQCHS_VERSION;
    if ((PqcHs_KeyId(CSM_KEYID_MLDSA_LOCAL, &Inst->M2[PQCHS_OFF_ID]) != E_OK) ||
        (PqcHs_Custom(Inst, CSM_JOBID_KEM_ENCAPS, &Inst->M1[PQCHS_M1_OFF_EK], PQCHS_EK_BYTES,
                      &Inst->M2[PQCHS_M2_OFF_CT], PQCHS_CT_BYTES, &Inst->AttemptTimes.EncapsNs) != E_OK) ||
        (PqcHs_Hash(Inst, Inst->M2, PQCHS_M2_OFF_SIG, NULL, 0U, hash, &Inst->AttemptTimes) != E_OK) ||
        (PqcHs_Sign(PQCHS_ROLE_BYTE_RESPONDER, hash, &Inst->M2[PQCHS_M2_OFF_SIG], &Inst->AttemptTimes) != E_OK) ||
        (PqcHs_DeriveKeys(Inst, hash, &Inst->AttemptTimes) != E_OK) ||
        (PqcHs_Hash(Inst, Inst->M2, PQCHS_M2_OFF_MAC, NULL, 0U, hash, &Inst->AttemptTimes) != E_OK) ||
        (PqcHs_ConfirmMac(Inst, FALSE, Inst->Keys[PQCHS_KEY_KC_R], hash, &Inst->M2[PQCHS_M2_OFF_MAC],
                          &Inst->AttemptTimes) != PQCHS_RESULT_OK) ||
        (PqcHs_Transmit(Inst, 0U) != E_OK))
    {
        PqcHs_R_Wipe(Inst, PQCHS_RESULT_STATE);
        return;
    }
    Inst->State = PQCHS_STATE_R_PENDING;
}

/* M3 is complete and the stream behind it is gated. Accepted: the instance waits in R_INSTALL with the
 * gate still closed. Rejected: the gate is released here. */
static void PqcHs_R_OnM3(PqcHs_InstanceType* Inst)
{
    const uint8* m3 = Inst->Rx;
    PqcHs_StageTimesType work;
    uint8 hash[PQCHS_HASH_BYTES];

    (void)memset(&work, 0, sizeof(work));

    if (Inst->State != PQCHS_STATE_R_PENDING)
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_STATE, &work);
    }
    else if (m3[0] != PQCHS_VERSION)
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_BAD_VER, &work);
    }
    else if ((PqcHs_Hash(Inst, Inst->M2, PQCHS_M2_BYTES, NULL, 0U, hash, &work) != E_OK) ||
             (PqcHs_Hash(Inst, Inst->M2, PQCHS_M2_BYTES, m3, PQCHS_M3_BYTES, Inst->Sess, &work) != E_OK))
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_STATE, &work);
    }
    /* sig_A over 'I' || H(L || M1 || M2), with the pinned key of this peer */
    else if (PqcHs_Verify(Inst, PQCHS_ROLE_BYTE_INITIATOR, hash, &m3[PQCHS_M3_OFF_SIG], &work) != E_OK)
    {
        PqcHs_Discard(Inst, PQCHS_RESULT_SIG_FAIL, &work);
    }
    else
    {
        /* mac_A = HMAC(K_kc_i, H(L || M1 || M2 || ver || sig_A)); a failure behind the valid
         * signature wipes the pending handshake */
        PqcHs_ResultType confirmed = PQCHS_RESULT_STATE;

        Inst->AttemptBytesRx += PQCHS_M3_BYTES + PQCHS_PDU_HEADER_BYTES;
        PqcHs_AddTimes(&Inst->AttemptTimes, &work);
        if (PqcHs_Hash(Inst, Inst->M2, PQCHS_M2_BYTES, m3, PQCHS_M3_OFF_MAC, hash, &Inst->AttemptTimes) == E_OK)
        {
            confirmed = PqcHs_ConfirmMac(Inst, TRUE, Inst->Keys[PQCHS_KEY_KC_I], hash, &Inst->Rx[PQCHS_M3_OFF_MAC],
                                         &Inst->AttemptTimes);
        }
        if (confirmed != PQCHS_RESULT_OK)
        {
            PqcHs_R_Wipe(Inst, confirmed);
        }
        else
        {
            OPENSSL_cleanse(Inst->Keys[PQCHS_KEY_KC_I], PQCHS_KEY_BYTES);
            Inst->State = PQCHS_STATE_R_INSTALL;
            return;
        }
    }
    PqcHs_ReleaseGate(Inst);
}

/* Everything received before M3 has been verified or dropped: install, set established, acknowledge,
 * reopen the stream */
static void PqcHs_R_Install(PqcHs_InstanceType* Inst)
{
    if (PqcHs_Install(Inst) == E_OK)
    {
        Inst->AttemptInstalled = TRUE;
        Inst->AttemptTotalNs = PqcHs_NowNs() - Inst->AttemptStartNs;

        /* M4 = ver || HMAC(K_kc_r, sess). Without it the initiator starts again after T_A; the keys
         * are installed either way, and the row says whether the acknowledgement was made. */
        Inst->M4[0] = PQCHS_VERSION;
        if (PqcHs_ConfirmMac(Inst, FALSE, Inst->Keys[PQCHS_KEY_KC_R], Inst->Sess, &Inst->M4[PQCHS_M4_OFF_MAC],
                             &Inst->AttemptTimes) == PQCHS_RESULT_OK)
        {
            (void)PqcHs_Transmit(Inst, 1U);
            PqcHs_R_Wipe(Inst, PQCHS_RESULT_OK);
        }
        else
        {
            PqcHs_R_Wipe(Inst, PQCHS_RESULT_STATE);
        }
    }
    else
    {
        PqcHs_R_Wipe(Inst, PQCHS_RESULT_STATE);
    }
    PqcHs_ReleaseGate(Inst);
}

/********************************************************************************************************/
/********************************************PublicFunctions*********************************************/
/********************************************************************************************************/

Std_ReturnType PqcHs_Core_Init(PqcHs_InstanceType* Inst, const PqcHs_InstanceConfigType* Cfg,
                               const PqcHs_TimersType* Timers)
{
    if ((Inst == NULL) || (Cfg == NULL) || (Timers == NULL) || (Cfg->PqcHsPeer >= CSM_MAX_PEERS) ||
        ((Cfg->PqcHsRole != PQCHS_ROLE_INITIATOR) && (Cfg->PqcHsRole != PQCHS_ROLE_RESPONDER)) ||
        ((Cfg->PqcHsNumFreshnessIds > 0U) && (Cfg->PqcHsFreshnessIds == NULL)) ||
        (Timers->PqcHsTAMs <= Timers->PqcHsTPendMs) || (Timers->PqcHsTAMs <= Timers->PqcHsTMinMs) ||
        (Timers->PqcHsTFlushMs >= Timers->PqcHsTPendMs))
    {
        return E_NOT_OK;
    }

    if (PqcHs_HashAlg == NULL)
    {
        PqcHs_HashAlg = EVP_MD_fetch(NULL, "SHA384", NULL);
    }
    if (PqcHs_HashCtx == NULL)
    {
        PqcHs_HashCtx = EVP_MD_CTX_new();
    }
    if ((PqcHs_HashAlg == NULL) || (PqcHs_HashCtx == NULL))
    {
        return E_NOT_OK;
    }

    OPENSSL_cleanse(Inst, sizeof(*Inst));
    Inst->Cfg = Cfg;
    Inst->Timers = Timers;
    Inst->State = PQCHS_STATE_IDLE;
    return E_OK;
}

Std_ReturnType PqcHs_Core_Initiate(PqcHs_InstanceType* Inst)
{
    if ((Inst == NULL) || (Inst->Cfg == NULL) || (!PQCHS_IS_INITIATOR(Inst)))
    {
        return E_NOT_OK;
    }
    Inst->InitiateRequest = TRUE;
    return E_OK;
}

void PqcHs_Core_SoConModeChg(PqcHs_InstanceType* Inst, SoAd_SoConModeType Mode)
{
    if ((Inst == NULL) || (Inst->Cfg == NULL))
    {
        return;
    }

    if (PQCHS_IS_INITIATOR(Inst))
    {
        /* The M1 request opens the connection, and SoAd reports that ONLINE from inside the request.
         * It belongs to the handshake that is just starting: it neither ends nor repeats it. */
        if ((Mode == SOAD_SOCON_ONLINE) && (Inst->TxRequesting == TRUE) && (Inst->TxMsg == 0U))
        {
            return;
        }
        /* nothing is carried over a change of the connection: not a message in transmission or in
         * reception, and not a complete one that still waits for the main function */
        if (Inst->TxActive == TRUE)
        {
            Inst->TxActive = FALSE;
            Inst->TxDone = TRUE;
            Inst->TxResult = E_NOT_OK;
        }
        Inst->RxActive = FALSE;
        Inst->RxReady = FALSE;
        Inst->ConnectionChanged = TRUE;
        /* a handshake each time the connection to the responder is established, started by the main
         * function, never from here; the session itself belongs to the pinned peer, not to the
         * connection, and stays as it is */
        if (Mode == SOAD_SOCON_ONLINE)
        {
            Inst->InitiateRequest = TRUE;
        }
        return;
    }

    /* responder: pending state is bound to the connection the M1 arrived on */
    Inst->RxActive = FALSE;
    Inst->RxReady = FALSE;
    Inst->TxActive = FALSE;
    Inst->TxDone = FALSE;
    PqcHs_ReleaseGate(Inst);
    if (Inst->State != PQCHS_STATE_IDLE)
    {
        PqcHs_R_Wipe(Inst, PQCHS_RESULT_STATE);
    }
}

void PqcHs_Core_MainFunction(PqcHs_InstanceType* Inst, uint64 NowMs)
{
    if ((Inst == NULL) || (Inst->Cfg == NULL))
    {
        return;
    }

    /* 0. The connection changed before M3 was handed to SoAd: the responder has wiped the handshake
     *    that was bound to the connection that is gone, so an M2 from it is not waited for, and an M3
     *    must not go out on another connection (the initiator would install a session the responder
     *    never holds). Once M3 is with SoAd its transmission result decides. */
    if (Inst->ConnectionChanged == TRUE)
    {
        Inst->ConnectionChanged = FALSE;
        if ((Inst->State == PQCHS_STATE_I_WAIT_M2) || (Inst->State == PQCHS_STATE_I_CUTOVER))
        {
            PqcHs_I_Fail(Inst, PQCHS_RESULT_STATE);
        }
    }

    /* 1. a finished transmission: the initiator installs after M3 */
    if (Inst->TxDone == TRUE)
    {
        Inst->TxDone = FALSE;
        if (PQCHS_IS_INITIATOR(Inst))
        {
            PqcHs_I_TxDone(Inst, NowMs);
        }
        else if ((Inst->TxMsg == 0U) && (Inst->TxResult != E_OK) && (Inst->State == PQCHS_STATE_R_PENDING))
        {
            PqcHs_R_Wipe(Inst, PQCHS_RESULT_STATE);
        }
        else
        {
            /* M2 went out, or the acknowledgement: nothing to do */
        }
    }

    /* 2. timers. Initiator: T_A (no valid M2 after M1, no valid M4 after M3) and the bound on the wait
     *    for the flush end the attempt; while M3 is with SoAd no timer runs, the result of that
     *    transmission decides. The next handshake, with a fresh ek, is due T_A after the M1 of the
     *    attempt that ended; installed keys stay in use meanwhile. Responder: T_pend. */
    if (PQCHS_IS_INITIATOR(Inst))
    {
        if (((Inst->State == PQCHS_STATE_I_WAIT_M2) || (Inst->State == PQCHS_STATE_I_CUTOVER) ||
             (Inst->State == PQCHS_STATE_I_WAIT_M4)) && (NowMs >= Inst->DeadlineMs))
        {
            PqcHs_I_Fail(Inst, PQCHS_RESULT_TIMEOUT);
        }
        if ((Inst->State == PQCHS_STATE_I_RETRY) && (NowMs >= Inst->DeadlineMs))
        {
            Inst->State = PQCHS_STATE_IDLE;
            Inst->InitiateRequest = TRUE;
        }
    }
    else if ((Inst->State != PQCHS_STATE_IDLE) && (NowMs >= Inst->DeadlineMs))
    {
        PqcHs_R_Wipe(Inst, PQCHS_RESULT_TIMEOUT);
        if (Inst->RxReady == FALSE)
        {
            PqcHs_ReleaseGate(Inst);
        }
    }
    else
    {
        /* no timer has run out */
    }

    /* 3. one received message. It stays locked (RxReady) until its handler has returned: nothing can
     *    be received into the buffer between the first check of the message and its last use. */
    if (Inst->RxReady == TRUE)
    {
        if (Inst->RxLength != Inst->RxExpected)
        {
            PqcHs_Discard(Inst, PQCHS_RESULT_BAD_LEN, NULL);
            PqcHs_ReleaseGate(Inst);
        }
        else if (PQCHS_IS_INITIATOR(Inst))
        {
            if (Inst->RxMsg == 0U)
            {
                PqcHs_I_OnM2(Inst, NowMs);
            }
            else
            {
                PqcHs_I_OnM4(Inst);
            }
        }
        else if (Inst->RxMsg == 0U)
        {
            PqcHs_R_OnM1(Inst, NowMs);
        }
        else
        {
            PqcHs_R_OnM3(Inst);
        }
        Inst->RxReady = FALSE;
    }

    /* 4. steps that wait for the data path */
    if ((Inst->State == PQCHS_STATE_I_CUTOVER) && (SecOC_TxSessionFlushed(Inst->Cfg->PqcHsPeer) == TRUE))
    {
        if (PqcHs_Transmit(Inst, 1U) == E_OK)
        {
            Inst->State = PQCHS_STATE_I_SEND_M3;
        }
        else
        {
            PqcHs_I_Fail(Inst, PQCHS_RESULT_STATE);
        }
    }
    else if ((Inst->State == PQCHS_STATE_R_INSTALL) && (SecOC_RxSessionDrained(Inst->Cfg->PqcHsPeer) == TRUE))
    {
        PqcHs_R_Install(Inst);
    }
    else
    {
        /* nothing is waiting */
    }

    /* 5. "initiate handshake now", connection established, or a retry that is due. A request is served
     *    only when no attempt is on its way to M3 (idle, waiting for the retry time, or installed and
     *    waiting for the acknowledgement); otherwise it stays until that attempt has ended. */
    if ((Inst->InitiateRequest == TRUE) &&
        ((Inst->State == PQCHS_STATE_IDLE) || (Inst->State == PQCHS_STATE_I_RETRY) || (Inst->State == PQCHS_STATE_I_WAIT_M4)))
    {
        PqcHs_I_Start(Inst, NowMs);
    }
}

Std_ReturnType PqcHs_Core_ReadAttempt(PqcHs_InstanceType* Inst, PqcHs_AttemptInfoType* AttemptPtr)
{
    if ((Inst == NULL) || (AttemptPtr == NULL) || (Inst->LogCount == 0U))
    {
        return E_NOT_OK;
    }
    *AttemptPtr = Inst->Log[Inst->LogHead];
    Inst->LogHead = (uint8)((Inst->LogHead + 1U) % PQCHS_ATTEMPT_LOG_SIZE);
    Inst->LogCount--;
    return E_OK;
}

BufReq_ReturnType PqcHs_Core_StartOfReception(PqcHs_InstanceType* Inst, uint8 RxMsg, PduLengthType TpSduLength,
                                              PduLengthType* bufferSizePtr)
{
    uint32 expected;

    if ((Inst == NULL) || (Inst->Cfg == NULL) || (RxMsg > 1U) || (bufferSizePtr == NULL))
    {
        return BUFREQ_E_NOT_OK;
    }

    /* a handshake PDU whose length is not exactly its table size is refused before any byte is read */
    expected = PqcHs_MessageLength(Inst, FALSE, RxMsg);
    if (TpSduLength != expected)
    {
        PqcHs_Record(Inst, PQCHS_RESULT_BAD_LEN, 0U, 0U, 0U, NULL);
        return BUFREQ_E_NOT_OK;
    }
    /* one message at a time: the previous one has not been processed yet */
    if ((Inst->RxActive == TRUE) || (Inst->RxReady == TRUE))
    {
        PqcHs_Record(Inst, PQCHS_RESULT_STATE, 0U, 0U, 0U, NULL);
        return BUFREQ_E_NOT_OK;
    }

    Inst->RxActive = TRUE;
    Inst->RxMsg = RxMsg;
    Inst->RxLength = 0U;
    Inst->RxExpected = expected;
    *bufferSizePtr = expected;
    return BUFREQ_OK;
}

BufReq_ReturnType PqcHs_Core_CopyRxData(PqcHs_InstanceType* Inst, uint8 RxMsg, const PduInfoType* info,
                                        PduLengthType* bufferSizePtr)
{
    if ((Inst == NULL) || (Inst->Cfg == NULL) || (RxMsg > 1U) || (info == NULL) || (bufferSizePtr == NULL))
    {
        return BUFREQ_E_NOT_OK;
    }

    /* Between two PDUs SoAd asks with length 0 how much room there is, and starts the next PDU of this
     * id only when the answer is at least what the last StartOfReception announced: the whole message
     * again once the previous one has been processed, nothing while it still waits in the buffer. */
    if ((Inst->RxActive == FALSE) && (info->SduLength == 0U))
    {
        *bufferSizePtr = (Inst->RxReady == TRUE) ? 0U : PqcHs_MessageLength(Inst, FALSE, RxMsg);
        return BUFREQ_OK;
    }

    if ((Inst->RxActive == FALSE) || (RxMsg != Inst->RxMsg) ||
        (info->SduLength > (Inst->RxExpected - Inst->RxLength)) ||
        ((info->SduLength > 0U) && (info->SduDataPtr == NULL)))
    {
        return BUFREQ_E_NOT_OK;
    }

    if (info->SduLength > 0U)
    {
        (void)memcpy(&Inst->Rx[Inst->RxLength], info->SduDataPtr, info->SduLength);
        Inst->RxLength += info->SduLength;
    }
    *bufferSizePtr = Inst->RxExpected - Inst->RxLength;
    return BUFREQ_OK;
}

void PqcHs_Core_RxIndication(PqcHs_InstanceType* Inst, uint8 RxMsg, Std_ReturnType result)
{
    if ((Inst == NULL) || (Inst->RxActive == FALSE) || (RxMsg != Inst->RxMsg))
    {
        return;
    }

    Inst->RxActive = FALSE;
    if (result == E_OK)
    {
        Inst->RxReady = TRUE;
        Inst->RxDoneNs = PqcHs_NowNs();
        /* responder, M3: SoAd parses nothing behind this PDU until PqcHs releases the stream */
        if ((!PQCHS_IS_INITIATOR(Inst)) && (RxMsg == 1U))
        {
            Inst->RxGated = TRUE;
        }
    }
}

BufReq_ReturnType PqcHs_Core_CopyTxData(PqcHs_InstanceType* Inst, uint8 TxMsg, const PduInfoType* info,
                                        PduLengthType* availableDataPtr)
{
    if ((Inst == NULL) || (info == NULL) || (availableDataPtr == NULL) || (Inst->TxActive == FALSE) ||
        (TxMsg != Inst->TxMsg) || (info->SduLength > (Inst->TxLength - Inst->TxPos)) ||
        ((info->SduLength > 0U) && (info->SduDataPtr == NULL)))
    {
        return BUFREQ_E_NOT_OK;
    }

    if (info->SduLength > 0U)
    {
        (void)memcpy(info->SduDataPtr, &PqcHs_TxMessage(Inst, TxMsg)[Inst->TxPos], info->SduLength);
        Inst->TxPos += info->SduLength;
    }
    *availableDataPtr = Inst->TxLength - Inst->TxPos;
    return BUFREQ_OK;
}

void PqcHs_Core_TxConfirmation(PqcHs_InstanceType* Inst, uint8 TxMsg, Std_ReturnType result)
{
    if ((Inst == NULL) || (Inst->TxActive == FALSE) || (TxMsg != Inst->TxMsg))
    {
        return;
    }

    Inst->TxActive = FALSE;
    Inst->TxDone = TRUE;
    /* handed over means every byte of the message */
    Inst->TxResult = ((result == E_OK) && (Inst->TxPos == Inst->TxLength)) ? E_OK : E_NOT_OK;
}
