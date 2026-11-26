/********************************************************************************************************/
/*  File:   test/test_pqchs.c                                                                             */
/*  Brief:  Handshake PQC-SecOC-HS-v1: an initiator instance A and a responder instance B back to back    */
/*          in ONE process over an in-memory wire, through the real PqcHs, Csm, CryIf and PQC code.       */
/*                                                                                                        */
/*  One Csm serves both sides: A names B as Csm peer 0 and B names A as Csm peer 1 (separate session key  */
/*  objects, pinned keys, MAC keys), and the local ML-DSA identity is switched to the acting side before   */
/*  each step. Everything PqcHs calls in SoAd, SecOC and FVM is replaced at link time (-Wl,--wrap) and    */
/*  recorded, so the order of the cut-over and installation steps can be asserted. The wire follows the   */
/*  rules of the SoAd of this project: a transmit request is taken only for a connection that exists and  */
/*  its bytes are copied later; the connecting side (A) opens the connection with the request and gets    */
/*  ONLINE from inside it; when the connection ends, every request is confirmed E_NOT_OK and a PDU in     */
/*  reception is ended before OFFLINE; between two PDUs of one id SoAd asks for the room. The Csm calls are */
/*  observed the same way and then served by the real Csm: the MAC jobs and keys are those of the Csm     */
/*  MAC part (HMAC-SHA-256 in the crypto driver), A with the keys and jobs of peer 0, B with peer 1.      */
/*                                                                                                        */
/*  H1  positive run: both sides install the same session, order of the steps on each side, rows          */
/*  H2  known-answer transcript (dump for test/kat_pqchs.py)                                              */
/*  H3  discard rule: a message with a wrong length, version, identity or signature changes nothing and   */
/*      the genuine message still completes; sig_B is checked before the decapsulation                    */
/*  H4  wipe rule: a MAC failure behind a valid signature ends that handshake                             */
/*  H5  pending: a second M1 is dropped, not substituted; T_min; T_pend; connection change                */
/*  H6  SPEC "Negative tests" 1 to 8                                                                      */
/*  H7  SPEC "Negative tests" 11 (M3 lost or altered) and 12 (M4 lost or altered), per side               */
/*  H8  local failures: transmission refused or failed, installation failed                               */
/*  H9  erasure: after success, failure, timeout and rekey no dk, ss, PRK, confirmation key or K_auth is  */
/*      left in the handshake state, the Csm session key objects or the key table of the MAC driver,      */
/*      except the active K_auth (checked after every scenario). What OpenSSL holds of a MAC key on the   */
/*      heap is the subject of test K10 in test_mac_profile.c, not of this test.                          */
/*  H10 PqcHs.c: PDU id mapping, fixed lengths at StartOfReception, public API                            */
/*  H11 restart of one side (its handshake instance and session state start empty): exactly one          */
/*      handshake brings traffic back, and a PDU recorded before the restart is not accepted             */
/*  H12 SoAd asks for the room between two PDUs of one id: the whole message at rest, nothing while a     */
/*      message waits for the main function                                                               */
/*  H14 guards of the TP interface: transmit bound, one reception at a time, lengths, failed confirmation */
/*  H13 hardening: the received message is locked while it is processed; a failed installation, at each  */
/*      of its six calls and on either side, leaves no usable session state; a confirmation or a          */
/*      handshake whose secrets could not be erased does not end as OK                                    */
/********************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "Std_Types.h"
#include "SecOC_Cfg.h"
#include "Csm.h"
#include "CryIf.h"
#include "PQC.h"
#include "Crypto_Mac.h"
#include "PqcHs_Core.h"
#include "SecOC.h"
#include "FVM.h"

static uint32 Failures = 0U;

#define CHECK(cond, ...) \
    do { if (!(cond)) { Failures++; (void)printf("  FAIL (line %d): ", __LINE__); (void)printf(__VA_ARGS__); (void)printf("\n"); } } while (0)

/************************************************ set-up *************************************************/

#define A   (0U)
#define B   (1U)
#define PEER_OF_A   (0U)        /* A's Csm peer index for B */
#define PEER_OF_B   (1U)        /* B's Csm peer index for A */

/* PDU ids: A sends M1 (1) and M3 (3), B sends M2 (2) and M4 (4); the receiver sees 10 + that id */
#define TXID_M1 (1U)
#define TXID_M2 (2U)
#define TXID_M3 (3U)
#define TXID_M4 (4U)
#define RXID(txid) ((PduIdType)(10U + (txid)))

/* MAC keys and jobs of the two sides: A uses those the Csm keeps for its peer 0, B those for peer 1 */
#define A_KEY_TX        CSM_KEYID_MAC_TX_PEER(PEER_OF_A)
#define A_KEY_RX        CSM_KEYID_MAC_RX_PEER(PEER_OF_A)
#define A_KEY_KC        CSM_KEYID_HS_KC_PEER(PEER_OF_A)
#define B_KEY_TX        CSM_KEYID_MAC_TX_PEER(PEER_OF_B)
#define B_KEY_RX        CSM_KEYID_MAC_RX_PEER(PEER_OF_B)
#define B_KEY_KC        CSM_KEYID_HS_KC_PEER(PEER_OF_B)
#define A_JOB_GEN       CSM_JOBID_MAC_GENERATE_PEER(PEER_OF_A)      /* K_auth A.tx */
#define A_JOB_VER       CSM_JOBID_MAC_VERIFY_PEER(PEER_OF_A)        /* K_auth A.rx */
#define A_JOB_KC_GEN    CSM_JOBID_HS_KC_GENERATE_PEER(PEER_OF_A)
#define A_JOB_KC_VER    CSM_JOBID_HS_KC_VERIFY_PEER(PEER_OF_A)
#define B_JOB_GEN       CSM_JOBID_MAC_GENERATE_PEER(PEER_OF_B)      /* K_auth B.tx */
#define B_JOB_VER       CSM_JOBID_MAC_VERIFY_PEER(PEER_OF_B)        /* K_auth B.rx */
#define B_JOB_KC_GEN    CSM_JOBID_HS_KC_GENERATE_PEER(PEER_OF_B)
#define B_JOB_KC_VER    CSM_JOBID_HS_KC_VERIFY_PEER(PEER_OF_B)

#define FRESHNESS_A (16U)
#define FRESHNESS_B (26U)

static const uint16 FreshnessA[1] = { FRESHNESS_A };
static const uint16 FreshnessB[1] = { FRESHNESS_B };

static const PqcHs_InstanceConfigType Cfg[2] =
{
    { PQCHS_ROLE_INITIATOR, PEER_OF_A, 0U, { TXID_M1, TXID_M3 }, { RXID(TXID_M2), RXID(TXID_M4) },
      A_KEY_TX, A_KEY_RX, A_KEY_KC, A_JOB_KC_GEN, A_JOB_KC_VER, FreshnessA, 1U },
    { PQCHS_ROLE_RESPONDER, PEER_OF_B, 1U, { TXID_M2, TXID_M4 }, { RXID(TXID_M1), RXID(TXID_M3) },
      B_KEY_TX, B_KEY_RX, B_KEY_KC, B_JOB_KC_GEN, B_JOB_KC_VER, FreshnessB, 1U }
};
static const PqcHs_TimersType Timers = { PQCHS_T_PEND_MS, SOAD_PQC_HS_MIN_INTERVAL_MS, PQCHS_T_A_MS, PQCHS_T_FLUSH_MS };

static PqcHs_InstanceType Inst[2];
static PQC_MLDSA_KeyPairType Key[2];
static PQC_MLDSA_KeyPairType KeyX;          /* an identity nobody has pinned */
static uint64 NowMs = 1000000U;
static uint8 Cur = A;                       /* side whose code is running */

/* environment behaviour the scenarios switch */
static boolean TxFlushed = TRUE;
static boolean RxDrained = TRUE;
static boolean GateClosed = FALSE;
static uint32 GateViolations = 0U;
static PduIdType FailConfirm = 0xFFFFU;     /* TcpIp does not take this PDU: E_NOT_OK and the connection ends */
static boolean Connected = FALSE;           /* the TCP connection between A and B exists */
static boolean Reachable = TRUE;            /* FALSE: A cannot open the connection */
static boolean ExpectTxAbort = FALSE;       /* the next transmission is expected to be given up by its sender */
static uint32 FailCustomJob = 0U;           /* Csm_CustomService of this job id fails once */
static uint32 FailKeySetValid = 0U;         /* Csm_KeySetValid of this key id fails once */
static uint32 FailKeyElementSet = 0U;       /* Csm_KeyElementSet of this key id fails once, */
static uint32 FailKeyElementSetAfter = 0U;  /* after this many writes of that key that still succeed */
static boolean EstablishedAtM4 = FALSE;

/************************************************ events *************************************************/

typedef enum
{
    EV_HOLD_ON = 1, EV_HOLD_OFF, EV_FLUSHED_Q, EV_DRAINED_Q, EV_GATE_CLOSED, EV_GATE_RELEASE,
    EV_TX_M1, EV_TX_M2, EV_TX_M3, EV_TX_M4, EV_TXCONF,
    EV_KEYSET_TX, EV_KEYSET_RX, EV_KEYVALID_TX, EV_KEYVALID_RX, EV_KEYSET_KC, EV_KEYVALID_KC,
    EV_CTXSET, EV_CTXVALID, EV_FVM,
    EV_SIGN, EV_VERIFY, EV_MACGEN, EV_MACVER, EV_KEYGEN, EV_ENCAPS, EV_DECAPS, EV_KDF, EV_DISCARD
} EventType;

#define MAX_EVENTS (16384U)
static uint8 EvCode[MAX_EVENTS];
static uint8 EvSide[MAX_EVENTS];
static uint32 EvCount = 0U;
static boolean EvLost = FALSE;

static void Ev(EventType Code)
{
    if (EvCount < MAX_EVENTS)
    {
        EvCode[EvCount] = (uint8)Code;
        EvSide[EvCount] = Cur;
        EvCount++;
    }
    else if (EvLost == FALSE)
    {
        /* "no such event" would be asserted on an incomplete log from here on */
        EvLost = TRUE;
        Failures++;
        (void)printf("  FAIL: event log full after %u events\n", (unsigned)MAX_EVENTS);
    }
    else
    {
        /* reported once */
    }
}

static uint32 Ev_Count(uint8 Side, uint32 From, EventType Code)
{
    uint32 i;
    uint32 n = 0U;
    for (i = From; i < EvCount; i++)
    {
        if ((EvSide[i] == Side) && (EvCode[i] == (uint8)Code)) { n++; }
    }
    return n;
}

/* TRUE when the events of Side since From that occur in Expected (a 0-terminated list) appear exactly
 * in the order of Expected, each once */
static boolean Ev_Order(uint8 Side, uint32 From, const uint8* Expected)
{
    uint32 i;
    uint32 next = 0U;
    for (i = From; i < EvCount; i++)
    {
        uint32 k;
        boolean listed = FALSE;
        if (EvSide[i] != Side) { continue; }
        for (k = 0U; Expected[k] != 0U; k++)
        {
            if (Expected[k] == EvCode[i]) { listed = TRUE; }
        }
        if (listed == TRUE)
        {
            if (Expected[next] != EvCode[i]) { return FALSE; }
            next++;
        }
    }
    return (Expected[next] == 0U) ? TRUE : FALSE;
}

/* TRUE when a Csm job (signature, MAC, custom service) of Side runs between its first K_auth write and
 * its freshness reset since From */
static boolean Ev_JobInsideInstall(uint8 Side, uint32 From)
{
    uint32 i;
    boolean inside = FALSE;
    for (i = From; i < EvCount; i++)
    {
        if (EvSide[i] != Side) { continue; }
        if (EvCode[i] == (uint8)EV_KEYSET_TX) { inside = TRUE; }
        else if (EvCode[i] == (uint8)EV_FVM) { inside = FALSE; }
        else if ((inside == TRUE) && (EvCode[i] >= (uint8)EV_SIGN)) { return TRUE; }
        else { /* other event */ }
    }
    return FALSE;
}

/****************************************** observed Csm calls *******************************************/

Std_ReturnType __real_Csm_KeyElementSet(uint32 keyId, uint32 keyElementId, const uint8* keyPtr, uint32 keyLength);
Std_ReturnType __real_Csm_KeySetValid(uint32 keyId);
Std_ReturnType __real_Csm_MacGenerate(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                      uint32 dataLength, uint8* macPtr, uint32* macLengthPtr);
Std_ReturnType __real_Csm_MacVerify(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                    uint32 dataLength, const uint8* macPtr, uint32 macLength,
                                    Crypto_VerifyResultType* verifyPtr);

/* 0 send key, 1 receive key, 2 confirmation-key slot of either side; -1: not a MAC key */
static sint32 Mac_KeyKind(uint32 KeyId)
{
    switch (KeyId)
    {
        case A_KEY_TX: case B_KEY_TX: return 0;
        case A_KEY_RX: case B_KEY_RX: return 1;
        case A_KEY_KC: case B_KEY_KC: return 2;
        default: return -1;
    }
}

/* the last PDU signature context each side wrote */
static uint8 CtxWritten[2][PQC_PDU_SIG_CTX_BYTES];
static uint32 CtxWrittenLen[2];

Std_ReturnType __wrap_Csm_KeyElementSet(uint32 keyId, uint32 keyElementId, const uint8* keyPtr, uint32 keyLength)
{
    sint32 kind = Mac_KeyKind(keyId);

    if (kind >= 0) { Ev((kind == 0) ? EV_KEYSET_TX : ((kind == 1) ? EV_KEYSET_RX : EV_KEYSET_KC)); }
    else if (keyElementId == CSM_KE_VENDOR_PDU_SIG_CTX)
    {
        Ev(EV_CTXSET);
        CtxWrittenLen[Cur] = keyLength;
        (void)memcpy(CtxWritten[Cur], keyPtr, (keyLength <= sizeof(CtxWritten[Cur])) ? keyLength : sizeof(CtxWritten[Cur]));
    }
    else { /* not a key the handshake installs */ }
    if (FailKeyElementSet == keyId)
    {
        if (FailKeyElementSetAfter == 0U)
        {
            FailKeyElementSet = 0U;
            return E_NOT_OK;
        }
        FailKeyElementSetAfter--;
    }
    return __real_Csm_KeyElementSet(keyId, keyElementId, keyPtr, keyLength);
}

Std_ReturnType __wrap_Csm_KeySetValid(uint32 keyId)
{
    sint32 kind = Mac_KeyKind(keyId);

    if (kind >= 0) { Ev((kind == 0) ? EV_KEYVALID_TX : ((kind == 1) ? EV_KEYVALID_RX : EV_KEYVALID_KC)); }
    else if ((keyId >= CSM_KEYID_SESSION_BASE) && (keyId < (CSM_KEYID_SESSION_BASE + CSM_MAX_PEERS))) { Ev(EV_CTXVALID); }
    else { /* not a key the handshake installs */ }
    if (FailKeySetValid == keyId)
    {
        FailKeySetValid = 0U;
        return E_NOT_OK;
    }
    return __real_Csm_KeySetValid(keyId);
}

Std_ReturnType __wrap_Csm_MacGenerate(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                      uint32 dataLength, uint8* macPtr, uint32* macLengthPtr)
{
    Ev(EV_MACGEN);
    return __real_Csm_MacGenerate(jobId, mode, dataPtr, dataLength, macPtr, macLengthPtr);
}

Std_ReturnType __wrap_Csm_MacVerify(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                    uint32 dataLength, const uint8* macPtr, uint32 macLength,
                                    Crypto_VerifyResultType* verifyPtr)
{
    Ev(EV_MACVER);
    return __real_Csm_MacVerify(jobId, mode, dataPtr, dataLength, macPtr, macLength, verifyPtr);
}

/* TRUE when the MAC job produces, or accepts, exactly the tag of Key: the key of that job is valid and
 * is this key. Probing a slot changes nothing in it. */
static const uint8 MacProbe[11] = { 'k', 'e', 'y', ' ', 'p', 'r', 'o', 'b', 'e', ' ', '1' };

static boolean Mac_TxKeyIs(uint32 GenerateJob, const uint8* KeyPtr)
{
    uint8 want[EVP_MAX_MD_SIZE];
    uint8 got[32];
    unsigned int wantLen = 0U;
    uint32 gotLen = sizeof(got);

    return ((HMAC(EVP_sha256(), KeyPtr, 32, MacProbe, sizeof(MacProbe), want, &wantLen) != NULL) && (wantLen == 32U) &&
            (__real_Csm_MacGenerate(GenerateJob, CRYPTO_OPERATIONMODE_SINGLECALL, MacProbe, sizeof(MacProbe), got, &gotLen) == E_OK) &&
            (gotLen == 32U) && (memcmp(want, got, 32U) == 0)) ? TRUE : FALSE;
}

static boolean Mac_RxKeyIs(uint32 VerifyJob, const uint8* KeyPtr)
{
    uint8 want[EVP_MAX_MD_SIZE];
    unsigned int wantLen = 0U;
    Crypto_VerifyResultType ver = CRYPTO_E_VER_NOT_OK;

    return ((HMAC(EVP_sha256(), KeyPtr, 32, MacProbe, sizeof(MacProbe), want, &wantLen) != NULL) && (wantLen == 32U) &&
            (__real_Csm_MacVerify(VerifyJob, CRYPTO_OPERATIONMODE_SINGLECALL, MacProbe, sizeof(MacProbe), want, 128U, &ver) == E_OK) &&
            (ver == CRYPTO_E_VER_OK)) ? TRUE : FALSE;
}

/* TRUE when the key of the job is not valid (no key, or erased) */
static boolean Mac_NoKey(uint32 GenerateJob)
{
    uint8 got[32];
    uint32 gotLen = sizeof(got);

    return (__real_Csm_MacGenerate(GenerateJob, CRYPTO_OPERATIONMODE_SINGLECALL, MacProbe, sizeof(MacProbe), got, &gotLen)
            == CRYPTO_E_KEY_NOT_VALID) ? TRUE : FALSE;
}

static boolean Mac_RxNoKey(uint32 VerifyJob)
{
    uint8 tag[16] = { 0U };
    Crypto_VerifyResultType ver = CRYPTO_E_VER_OK;

    return (__real_Csm_MacVerify(VerifyJob, CRYPTO_OPERATIONMODE_SINGLECALL, MacProbe, sizeof(MacProbe), tag, 128U, &ver)
            == CRYPTO_E_KEY_NOT_VALID) ? TRUE : FALSE;
}

Std_ReturnType __real_Csm_SignatureGenerate(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                            uint32 dataLength, uint8* signaturePtr, uint32* signatureLengthPtr);
Std_ReturnType __real_Csm_SignatureVerify(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                          uint32 dataLength, const uint8* signaturePtr, uint32 signatureLength,
                                          Crypto_VerifyResultType* verifyPtr);
Std_ReturnType __real_Csm_CustomService(uint32 jobId, Crypto_OperationModeType mode, uint32 targetKeyId,
                                        const uint8* inputPtr, uint32 inputLength,
                                        const uint8* secondaryInputPtr, uint32 secondaryInputLength,
                                        const uint8* tertiaryInputPtr, uint32 tertiaryInputLength,
                                        uint8* outputPtr, uint32* outputLengthPtr,
                                        uint8* secondaryOutputPtr, uint32* secondaryOutputLengthPtr,
                                        Crypto_VerifyResultType* verifyPtr);

/* the last message each side gave to the handshake sign job: role byte || transcript hash */
static uint8 Signed[2][1U + PQCHS_HASH_BYTES];
static uint32 SignedLen[2];

Std_ReturnType __wrap_Csm_SignatureGenerate(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                            uint32 dataLength, uint8* signaturePtr, uint32* signatureLengthPtr)
{
    Ev(EV_SIGN);
    if (jobId == CSM_JOBID_HS_SIGN)
    {
        SignedLen[Cur] = dataLength;
        (void)memcpy(Signed[Cur], dataPtr, (dataLength <= sizeof(Signed[Cur])) ? dataLength : sizeof(Signed[Cur]));
    }
    return __real_Csm_SignatureGenerate(jobId, mode, dataPtr, dataLength, signaturePtr, signatureLengthPtr);
}

/* A reception attempted while the main function is working on a received message (armed by ProbeRxLock) */
static boolean ProbeRxLock = FALSE;
static BufReq_ReturnType ProbeStart = BUFREQ_OK;
static PduLengthType ProbeRoom = 9999U;

Std_ReturnType __wrap_Csm_SignatureVerify(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                          uint32 dataLength, const uint8* signaturePtr, uint32 signatureLength,
                                          Crypto_VerifyResultType* verifyPtr)
{
    Ev(EV_VERIFY);
    if (ProbeRxLock == TRUE)
    {
        PduInfoType query = { NULL, NULL, 0U };
        PduLengthType room = 0U;

        ProbeRxLock = FALSE;
        (void)PqcHs_Core_CopyRxData(&Inst[Cur], Inst[Cur].RxMsg, &query, &ProbeRoom);
        ProbeStart = PqcHs_Core_StartOfReception(&Inst[Cur], Inst[Cur].RxMsg, Inst[Cur].RxExpected, &room);
    }
    return __real_Csm_SignatureVerify(jobId, mode, dataPtr, dataLength, signaturePtr, signatureLength, verifyPtr);
}

Std_ReturnType __wrap_Csm_CustomService(uint32 jobId, Crypto_OperationModeType mode, uint32 targetKeyId,
                                        const uint8* inputPtr, uint32 inputLength,
                                        const uint8* secondaryInputPtr, uint32 secondaryInputLength,
                                        const uint8* tertiaryInputPtr, uint32 tertiaryInputLength,
                                        uint8* outputPtr, uint32* outputLengthPtr,
                                        uint8* secondaryOutputPtr, uint32* secondaryOutputLengthPtr,
                                        Crypto_VerifyResultType* verifyPtr)
{
    Ev((jobId == CSM_JOBID_KEM_KEYGEN) ? EV_KEYGEN : ((jobId == CSM_JOBID_KEM_ENCAPS) ? EV_ENCAPS :
       ((jobId == CSM_JOBID_KEM_DECAPS) ? EV_DECAPS : ((jobId == CSM_JOBID_HS_KDF) ? EV_KDF : EV_DISCARD))));
    if (FailCustomJob == jobId)
    {
        FailCustomJob = 0U;
        return E_NOT_OK;
    }
    return __real_Csm_CustomService(jobId, mode, targetKeyId, inputPtr, inputLength, secondaryInputPtr,
                                    secondaryInputLength, tertiaryInputPtr, tertiaryInputLength, outputPtr,
                                    outputLengthPtr, secondaryOutputPtr, secondaryOutputLengthPtr, verifyPtr);
}

/* secrets as they exist inside the custom service, every one of the whole test run */
#define MAX_SECRETS (256U)
static uint8 SecDk[MAX_SECRETS][CSM_MLKEM_SECRET_KEY_BYTES];
static uint8 SecSs[MAX_SECRETS][32];
static uint8 SecPrk[MAX_SECRETS][32];
static uint8 SecOkm[MAX_SECRETS][CSM_HS_KDF_OUTPUT_BYTES];
static uint32 NumDk = 0U;
static uint32 NumSs = 0U;
static uint32 NumPrk = 0U;
static uint32 NumOkm = 0U;

void Csm_Pqc_TestTap(uint8 kind, const uint8* dataPtr, uint32 length)
{
    if ((kind == CSM_PQC_TAP_DK) && (NumDk < MAX_SECRETS)) { (void)memcpy(SecDk[NumDk], dataPtr, length); NumDk++; }
    else if ((kind == CSM_PQC_TAP_SS) && (NumSs < MAX_SECRETS)) { (void)memcpy(SecSs[NumSs], dataPtr, length); NumSs++; }
    else if ((kind == CSM_PQC_TAP_PRK) && (NumPrk < MAX_SECRETS)) { (void)memcpy(SecPrk[NumPrk], dataPtr, length); NumPrk++; }
    else if ((kind == CSM_PQC_TAP_OKM) && (NumOkm < MAX_SECRETS)) { (void)memcpy(SecOkm[NumOkm], dataPtr, length); NumOkm++; }
    else { CHECK(0, "secret tap overflow or unknown kind %u", (unsigned)kind); }
}

/* The key set of the latest derivation. A run in which no handshake got as far as the key derivation
 * fails here with a message instead of reading in front of the table. */
static const uint8* Okm_Last(void)
{
    CHECK(NumOkm > 0U, "no key derivation has been recorded");
    return SecOkm[(NumOkm > 0U) ? (NumOkm - 1U) : 0U];
}

/******************************************** SoAd, SecOC, FVM *******************************************/

static PduIdType TxQueue[8];
static uint32 TxQueueLen[8];
static uint32 TxQueued = 0U;
/* SoAd, per connection and PDU: what the last StartOfReception announced as free (0: no PDU yet) */
static uint32 RxAnnounced[2][2];
/* a PDU whose reception a scenario started and left open: its message index + 1 */
static uint8 RxOpen[2];

#define SIDE_OF_TX(id)  ((((id) == TXID_M1) || ((id) == TXID_M3)) ? A : B)
#define TXMSG_OF(id)    (((id) <= TXID_M2) ? 0U : 1U)

/* The connection is established (connect on A, accept on B): new streams, ONLINE on both sides */
static void Wire_Up(void)
{
    uint8 before = Cur;

    Connected = TRUE;
    (void)memset(RxAnnounced, 0, sizeof(RxAnnounced));
    Cur = A;
    PqcHs_Core_SoConModeChg(&Inst[A], SOAD_SOCON_ONLINE);
    Cur = B;
    PqcHs_Core_SoConModeChg(&Inst[B], SOAD_SOCON_ONLINE);
    Cur = before;
}

/* The connection ends, on each side in SoAd's order: a PDU in reception is ended, every transmit
 * request is confirmed E_NOT_OK, then OFFLINE. Nothing that was on its way arrives. */
static void Wire_Down(void)
{
    uint8 before = Cur;
    uint8 side;
    uint32 i;

    for (side = A; side <= B; side++)
    {
        Cur = side;
        if (RxOpen[side] != 0U)
        {
            PqcHs_Core_RxIndication(&Inst[side], (uint8)(RxOpen[side] - 1U), E_NOT_OK);
            RxOpen[side] = 0U;
        }
        for (i = 0U; i < TxQueued; i++)
        {
            if (SIDE_OF_TX(TxQueue[i]) == side)
            {
                PqcHs_Core_TxConfirmation(&Inst[side], TXMSG_OF(TxQueue[i]), E_NOT_OK);
            }
        }
        PqcHs_Core_SoConModeChg(&Inst[side], SOAD_SOCON_OFFLINE);
    }
    /* the gate was part of the stream that is gone; a release that PqcHs still owed would open the
     * gate of the next stream */
    CHECK(Inst[B].RxGated == FALSE, "B still owes a gate release for a stream that has ended");
    GateClosed = FALSE;
    TxQueued = 0U;
    Connected = FALSE;
    Cur = before;
}

Std_ReturnType __wrap_SoAd_TpTransmit(PduIdType TxPduId, const PduInfoType* PduInfoPtr)
{
    uint32 i;

    Ev((TxPduId == TXID_M1) ? EV_TX_M1 : ((TxPduId == TXID_M2) ? EV_TX_M2 : ((TxPduId == TXID_M3) ? EV_TX_M3 : EV_TX_M4)));
    /* one transmission per PDU id */
    for (i = 0U; i < TxQueued; i++)
    {
        if (TxQueue[i] == TxPduId) { return E_NOT_OK; }
    }
    if (TxQueued >= 8U)
    {
        return E_NOT_OK;
    }
    /* A request is taken only for a connection that exists. The connecting side opens it with the
     * request, and SoAd reports ONLINE from inside this call; the listening side has a peer or not. */
    if (Connected == FALSE)
    {
        if ((SIDE_OF_TX(TxPduId) != A) || (Reachable == FALSE))
        {
            return E_NOT_OK;
        }
        Wire_Up();
    }
    if (TxPduId == TXID_M4)
    {
        EstablishedAtM4 = Inst[B].Established;
    }
    TxQueue[TxQueued] = TxPduId;
    TxQueueLen[TxQueued] = PduInfoPtr->SduLength;
    TxQueued++;
    return E_OK;
}

static const SoAd_UpperLayerType* BoundLayer = NULL;
static uint32 BindCalls = 0U;
static boolean BindOnline = FALSE;          /* the connection is already up when the layer binds */
static SoAd_SoConIdType BindSoConId = 0U;

Std_ReturnType __wrap_SoAd_SetUpperLayer(SoAd_UpperLayerIdType Id, const SoAd_UpperLayerType* UpperLayerPtr)
{
    BindCalls++;
    CHECK(Id == SOAD_UPPER_LAYER_HS, "bound as upper layer %u", (unsigned)Id);
    BoundLayer = UpperLayerPtr;
    if ((BindOnline == TRUE) && (UpperLayerPtr != NULL) && (UpperLayerPtr->SoConModeChg != NULL))
    {
        /* SoAd tells a layer that binds while a connection is up at once, from inside this call */
        UpperLayerPtr->SoConModeChg(BindSoConId, SOAD_SOCON_ONLINE);
    }
    return E_OK;
}

void __wrap_SoAd_RxGateRelease(PduIdType RxPduId)
{
    Ev(EV_GATE_RELEASE);
    CHECK(RxPduId == RXID(TXID_M3), "gate released for PDU id %u", (unsigned)RxPduId);
    CHECK(GateClosed == TRUE, "gate released although it was not closed");
    GateClosed = FALSE;
}

boolean __wrap_SecOC_RxSessionDrained(uint8 Peer)
{
    Ev(EV_DRAINED_Q);
    CHECK(Peer == PEER_OF_B, "drained asked for peer %u", (unsigned)Peer);
    return RxDrained;
}

void __wrap_SecOC_TxSessionHold(uint8 Peer, boolean Hold)
{
    Ev((Hold == TRUE) ? EV_HOLD_ON : EV_HOLD_OFF);
    CHECK(Peer == PEER_OF_A, "hold for peer %u", (unsigned)Peer);
}

boolean __wrap_SecOC_TxSessionFlushed(uint8 Peer)
{
    Ev(EV_FLUSHED_Q);
    CHECK(Peer == PEER_OF_A, "flushed asked for peer %u", (unsigned)Peer);
    return TxFlushed;
}

void __wrap_FVM_SessionInstall(uint16 SecOCFreshnessValueID)
{
    Ev(EV_FVM);
    CHECK(SecOCFreshnessValueID == ((Cur == A) ? FRESHNESS_A : FRESHNESS_B), "freshness id %u reset by side %u",
          (unsigned)SecOCFreshnessValueID, (unsigned)Cur);
}

/************************************************* wire **************************************************/

/* A message on its way: Hook may change it, replace it or drop it (return FALSE), and may deliver
 * other messages first. MsgNo is 1..4. */
typedef boolean (*HookType)(uint8 MsgNo, uint8* Data, uint32* Length);
static HookType Hook = NULL;

static uint8 Last[5][PQCHS_M2_BYTES];       /* last message of each kind as transmitted */
static uint32 LastLen[5];
static uint8 Saved[5][PQCHS_M2_BYTES];      /* messages of an earlier run, for the replays */
static uint32 Refused = 0U;                 /* StartOfReception not accepted */

static void ActAs(uint8 Side)
{
    Cur = Side;
    (void)__real_Csm_KeyElementSet(CSM_KEYID_MLDSA_LOCAL, CSM_KEYELEMENT_MLDSA_PUBLIC, Key[Side].PublicKey, CSM_MLDSA_PUBLIC_KEY_BYTES);
    (void)__real_Csm_KeyElementSet(CSM_KEYID_MLDSA_LOCAL, CSM_KEYELEMENT_MLDSA_SECRET, Key[Side].SecretKey, CSM_MLDSA_SECRET_KEY_BYTES);
    (void)__real_Csm_KeySetValid(CSM_KEYID_MLDSA_LOCAL);
}

static void Step(uint8 Side)
{
    ActAs(Side);
    PqcHs_Core_MainFunction(&Inst[Side], NowMs);
}

/* Hand one complete message to a side, in TCP-segment-sized pieces. MsgNo 1..4. */
static BufReq_ReturnType Deliver(uint8 MsgNo, const uint8* Data, uint32 Length)
{
    uint8 side = ((MsgNo == 1U) || (MsgNo == 3U)) ? B : A;
    uint8 rxMsg = (MsgNo <= 2U) ? 0U : 1U;
    PduLengthType room = 0U;
    PduInfoType info;
    uint32 pos = 0U;
    BufReq_ReturnType rc;
    uint8 before = Cur;

    Cur = side;
    if ((side == B) && (GateClosed == TRUE))
    {
        GateViolations++;
    }
    info.MetaDataPtr = NULL;
    /* SoAd: before the second and every later PDU of one id it asks with length 0 how much room there
     * is, and starts the PDU only if that is at least what the last StartOfReception announced.
     * Otherwise the PDU waits in the stream (BUFREQ_E_BUSY here: the scenario delivers it again). */
    if (RxAnnounced[side][rxMsg] != 0U)
    {
        info.SduDataPtr = NULL;
        info.SduLength = 0U;
        if ((PqcHs_Core_CopyRxData(&Inst[side], rxMsg, &info, &room) != BUFREQ_OK) || (room < RxAnnounced[side][rxMsg]))
        {
            Cur = before;
            return BUFREQ_E_BUSY;
        }
    }
    rc = PqcHs_Core_StartOfReception(&Inst[side], rxMsg, Length, &room);
    if (rc != BUFREQ_OK)
    {
        Refused++;
        Cur = before;
        return rc;
    }
    RxAnnounced[side][rxMsg] = room;
    while (pos < Length)
    {
        uint32 n = ((Length - pos) > 1448U) ? 1448U : (Length - pos);
        info.SduDataPtr = (uint8*)(uintptr_t)&Data[pos];
        info.SduLength = n;
        rc = PqcHs_Core_CopyRxData(&Inst[side], rxMsg, &info, &room);
        CHECK(rc == BUFREQ_OK, "CopyRxData M%u at %u", (unsigned)MsgNo, (unsigned)pos);
        pos += n;
    }
    PqcHs_Core_RxIndication(&Inst[side], rxMsg, E_OK);
    if (MsgNo == 3U)
    {
        /* SoAd: nothing behind M3 is parsed until PqcHs releases the stream */
        Ev(EV_GATE_CLOSED);
        GateClosed = TRUE;
    }
    Cur = before;
    return BUFREQ_OK;
}

/* Carry every requested transmission to its receiver */
static void Pump(void)
{
    static uint8 buf[PQCHS_M2_BYTES];
    uint32 carried = 0U;

    while (TxQueued > 0U)
    {
        /* no scenario moves more than a few messages at once: anything else is a message loop */
        carried++;
        if (carried > 16U)
        {
            CHECK(0, "wire: message loop, %u transmissions still requested", (unsigned)TxQueued);
            TxQueued = 0U;
            break;
        }
        PduIdType id = TxQueue[0];
        uint32 len = TxQueueLen[0];
        uint8 msgNo = (uint8)id;
        uint8 side = SIDE_OF_TX(id);
        uint8 txMsg = TXMSG_OF(id);
        uint32 pos = 0U;
        PduLengthType left = 0U;
        PduInfoType info;
        boolean givenUp = FALSE;
        uint32 i;

        for (i = 1U; i < TxQueued; i++) { TxQueue[i - 1U] = TxQueue[i]; TxQueueLen[i - 1U] = TxQueueLen[i]; }
        TxQueued--;

        Cur = side;
        info.MetaDataPtr = NULL;
        while (pos < len)
        {
            uint32 n = ((len - pos) > 1448U) ? 1448U : (len - pos);
            info.SduDataPtr = &buf[pos];
            info.SduLength = n;
            if (PqcHs_Core_CopyTxData(&Inst[side], txMsg, &info, &left) != BUFREQ_OK)
            {
                givenUp = TRUE;
                break;
            }
            pos += n;
        }
        Ev(EV_TXCONF);
        if ((givenUp == TRUE) || (id == FailConfirm))
        {
            /* [SWS_SoAd_00651] the upper layer gave the transmission up, or TcpIp did not take the
             * data: the transmission is confirmed E_NOT_OK and SoAd closes the connection */
            CHECK((givenUp == FALSE) || (ExpectTxAbort == TRUE), "CopyTxData M%u refused at %u", (unsigned)msgNo, (unsigned)pos);
            ExpectTxAbort = FALSE;
            PqcHs_Core_TxConfirmation(&Inst[side], txMsg, E_NOT_OK);
            Wire_Down();
            continue;
        }
        CHECK(left == 0U, "M%u: %u bytes left after the announced length", (unsigned)msgNo, (unsigned)left);
        PqcHs_Core_TxConfirmation(&Inst[side], txMsg, E_OK);

        (void)memcpy(Last[msgNo], buf, len);
        LastLen[msgNo] = len;
        if ((Hook != NULL) && (Hook(msgNo, buf, &len) == FALSE))
        {
            continue;
        }
        CHECK(Deliver(msgNo, buf, len) != BUFREQ_E_BUSY, "wire: M%u has to wait although nothing is in its receiver's buffer",
              (unsigned)msgNo);
    }
}

static void Cycles(uint32 Count)
{
    uint32 i;
    for (i = 0U; i < Count; i++)
    {
        Step(A);
        Pump();
        Step(B);
        Pump();
    }
}

/************************************************ oracle *************************************************/

static uint8 SidBefore[2][PQCHS_SID_BYTES];
static uint32 InstallsBefore[2];
static boolean EstablishedBefore[2];

static void Oracle_Mark(void)
{
    (void)memcpy(SidBefore[A], Inst[A].Sid, PQCHS_SID_BYTES);
    (void)memcpy(SidBefore[B], Inst[B].Sid, PQCHS_SID_BYTES);
    InstallsBefore[A] = Inst[A].InstallCount;
    InstallsBefore[B] = Inst[B].InstallCount;
    EstablishedBefore[A] = Inst[A].Established;
    EstablishedBefore[B] = Inst[B].Established;
}

static boolean Oracle_Unchanged(uint8 Side)
{
    return ((Inst[Side].InstallCount == InstallsBefore[Side]) && (Inst[Side].Established == EstablishedBefore[Side]) &&
            (memcmp(Inst[Side].Sid, SidBefore[Side], PQCHS_SID_BYTES) == 0)) ? TRUE : FALSE;
}

static boolean Oracle_NewSession(uint8 Side)
{
    return ((Inst[Side].InstallCount == (InstallsBefore[Side] + 1U)) && (Inst[Side].Established == TRUE) &&
            (memcmp(Inst[Side].Sid, SidBefore[Side], PQCHS_SID_BYTES) != 0)) ? TRUE : FALSE;
}

/* A PDU authenticated by A is accepted by B in both variants: the PDU signature (A's sign job, context
 * of A's session; B's verify job for A, context of B's session) and the MAC under K_auth_i2r. The jobs
 * are called directly, past the gates that SecOC puts on "established", so that flag is part of the
 * answer: without it on both sides no PDU is released or accepted. */
static boolean SessionSigOk = FALSE;
static boolean SessionMacOk = FALSE;

static boolean Session_Works(void)
{
    static uint8 sig[PQC_MLDSA_SIGNATURE_BYTES];
    uint8 pdu[14] = { 0x00U, 0x02U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 0U, 0U, 0U, 1U };
    uint8 tag[16];
    uint32 sigLen = sizeof(sig);
    uint32 tagLen = sizeof(tag);
    Crypto_VerifyResultType ver = CRYPTO_E_VER_NOT_OK;
    boolean sigOk = FALSE;
    boolean macOk = FALSE;

    ActAs(A);
    if ((__real_Csm_SignatureGenerate((uint32)CSM_JOBID, CRYPTO_OPERATIONMODE_SINGLECALL, pdu, sizeof(pdu), sig, &sigLen) == E_OK) &&
        (__real_Csm_SignatureVerify(CSM_JOBID_VERIFY_PEER_BASE + PEER_OF_B, CRYPTO_OPERATIONMODE_SINGLECALL, pdu,
                                    sizeof(pdu), sig, sigLen, &ver) == E_OK) && (ver == CRYPTO_E_VER_OK))
    {
        sigOk = TRUE;
    }
    ver = CRYPTO_E_VER_NOT_OK;
    if ((__real_Csm_MacGenerate(A_JOB_GEN, CRYPTO_OPERATIONMODE_SINGLECALL, pdu, sizeof(pdu), tag, &tagLen) == E_OK) &&
        (__real_Csm_MacVerify(B_JOB_VER, CRYPTO_OPERATIONMODE_SINGLECALL, pdu, sizeof(pdu), tag, 128U, &ver) == E_OK) &&
        (ver == CRYPTO_E_VER_OK))
    {
        macOk = TRUE;
    }
    SessionSigOk = sigOk;
    SessionMacOk = macOk;
    return ((sigOk == TRUE) && (macOk == TRUE) && (Inst[A].Established == TRUE) && (Inst[B].Established == TRUE)) ? TRUE : FALSE;
}

/* next unread row of a side */
static boolean Row(uint8 Side, PqcHs_AttemptInfoType* RowPtr)
{
    return (PqcHs_Core_ReadAttempt(&Inst[Side], RowPtr) == E_OK) ? TRUE : FALSE;
}

static void Expect_Row(uint8 Side, PqcHs_ResultType Result, int Line)
{
    PqcHs_AttemptInfoType row;
    if (Row(Side, &row) == FALSE)
    {
        Failures++;
        (void)printf("  FAIL (line %d): side %u has no row, expected result %u\n", Line, (unsigned)Side, (unsigned)Result);
    }
    else if (row.Result != Result)
    {
        Failures++;
        (void)printf("  FAIL (line %d): side %u row result %u, expected %u\n", Line, (unsigned)Side,
                     (unsigned)row.Result, (unsigned)Result);
    }
    else
    {
        /* as expected */
    }
}

static void Expect_NoRow(uint8 Side, int Line)
{
    PqcHs_AttemptInfoType row;
    if (Row(Side, &row) == TRUE)
    {
        Failures++;
        (void)printf("  FAIL (line %d): side %u has an unexpected row with result %u\n", Line, (unsigned)Side, (unsigned)row.Result);
    }
}

#define EXPECT_ROW(side, result)    Expect_Row((side), (result), __LINE__)
#define EXPECT_NO_ROW(side)         Expect_NoRow((side), __LINE__)

/************************************************ erasure ************************************************/

static boolean Residue(const uint8* Storage, uint32 StorageLength, const uint8* Secret, uint32 SecretLength)
{
    uint32 block;
    uint32 pos;
    for (block = 0U; (block + 16U) <= SecretLength; block += 16U)
    {
        for (pos = 0U; (pos + 16U) <= StorageLength; pos++)
        {
            if ((Storage[pos] == Secret[block]) && (memcmp(&Storage[pos], &Secret[block], 16U) == 0))
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}

#define DK_PKE_BYTES    (1152U)     /* FIPS 203: dk = dk_PKE || ek || H(ek) || z; ek is public */
#define DK_Z_OFFSET     (CSM_MLKEM_SECRET_KEY_BYTES - 32U)

/* TRUE when the secret is in the handshake state of either side or in the Csm session key objects */
static boolean InStateOrCsm(const uint8* Secret, uint32 Length)
{
    const uint8* csm = NULL;
    uint32 csmLen = 0U;

    Csm_Pqc_TestStorage(&csm, &csmLen);
    return ((Residue((const uint8*)&Inst[A], (uint32)sizeof(Inst[A]), Secret, Length) == TRUE) ||
            (Residue((const uint8*)&Inst[B], (uint32)sizeof(Inst[B]), Secret, Length) == TRUE) ||
            (Residue(csm, csmLen, Secret, Length) == TRUE)) ? TRUE : FALSE;
}

/* TRUE when the secret is in the key table of the MAC driver */
static boolean InMacStore(const uint8* Secret, uint32 Length)
{
    const uint8* table = NULL;
    uint32 tableLen = 0U;

    Crypto_Mac_TestStorage(&table, &tableLen);
    return Residue(table, tableLen, Secret, Length);
}

/* TRUE when the secret is in the three key slots of one side (send key, receive key, confirmation key) */
static boolean InMacSlotsOf(uint8 Side, const uint8* Secret, uint32 Length)
{
    const uint8* table = NULL;
    uint32 tableLen = 0U;

    Crypto_Mac_TestStorage(&table, &tableLen);
    /* the table holds the slots of peer 0 (A's), then those of peer 1 (B's) */
    return Residue(&table[(Side == A) ? 0U : (tableLen / 2U)], tableLen / 2U, Secret, Length);
}

/* After a scenario has come to rest. The only secrets allowed anywhere are the K_auth keys in the
 * valid K_auth slots of the MAC key store. */
static void Erasure_Check(const char* When)
{
    /* dk, ss and PRK found absent once stay absent: nothing writes them again */
    static uint32 doneDk = 0U;
    static uint32 doneSs = 0U;
    static uint32 donePrk = 0U;
    uint32 i;
    uint32 k;
    uint32 bad = 0U;

    for (i = doneDk; i < NumDk; i++)
    {
        if ((InStateOrCsm(SecDk[i], DK_PKE_BYTES) == TRUE) || (InStateOrCsm(&SecDk[i][DK_Z_OFFSET], 32U) == TRUE) ||
            (InMacStore(SecDk[i], DK_PKE_BYTES) == TRUE)) { bad++; (void)printf("  residue: dk %u\n", (unsigned)i); }
    }
    for (i = doneSs; i < NumSs; i++)
    {
        if ((InStateOrCsm(SecSs[i], 32U) == TRUE) || (InMacStore(SecSs[i], 32U) == TRUE)) { bad++; (void)printf("  residue: ss %u\n", (unsigned)i); }
    }
    for (i = donePrk; i < NumPrk; i++)
    {
        if ((InStateOrCsm(SecPrk[i], 32U) == TRUE) || (InMacStore(SecPrk[i], 32U) == TRUE)) { bad++; (void)printf("  residue: PRK %u\n", (unsigned)i); }
    }
    for (i = 0U; i < NumOkm; i++)
    {
        /* K_kc_r, K_kc_i: nowhere */
        if ((InStateOrCsm(&SecOkm[i][0], 64U) == TRUE) || (InMacStore(&SecOkm[i][0], 64U) == TRUE)) { bad++; (void)printf("  residue: K_kc %u\n", (unsigned)i); }
        /* K_auth_i2r, K_auth_r2i: never in the handshake state or the Csm session objects */
        if (InStateOrCsm(&SecOkm[i][64], 64U) == TRUE) { bad++; (void)printf("  residue: K_auth %u outside the key store\n", (unsigned)i); }
    }
    /* the confirmation-key slots hold no valid key */
    if ((Mac_NoKey(A_JOB_KC_GEN) == FALSE) || (Mac_NoKey(B_JOB_KC_GEN) == FALSE)) { bad++; (void)printf("  confirmation-key slot left valid\n"); }
    /* every K_auth key ever derived that is still in the key table is the valid key of a K_auth job */
    for (i = 0U; i < NumOkm; i++)
    {
        for (k = 64U; k < 128U; k += 32U)
        {
            const uint8* key = &SecOkm[i][k];
            if (InMacStore(key, 32U) == FALSE) { continue; }
            if ((Mac_TxKeyIs(A_JOB_GEN, key) == FALSE) && (Mac_RxKeyIs(A_JOB_VER, key) == FALSE) &&
                (Mac_TxKeyIs(B_JOB_GEN, key) == FALSE) && (Mac_RxKeyIs(B_JOB_VER, key) == FALSE))
            {
                bad++;
                (void)printf("  residue: stale K_auth %u in the key store\n", (unsigned)i);
            }
        }
    }
    doneDk = NumDk;
    doneSs = NumSs;
    donePrk = NumPrk;
    CHECK(bad == 0U, "erasure after %s: %u finding(s)", When, (unsigned)bad);
}

/************************************************ helpers ************************************************/

static uint64 Test_NowNs(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64)ts.tv_sec * 1000000000ULL) + (uint64)ts.tv_nsec;
}

static void Flip(uint8* Data, uint32 Offset)
{
    Data[Offset] ^= 0x01U;
}

#define M2_OFF_ID       (1U)
#define M2_OFF_CT       (33U)
#define M2_OFF_SIG      (1121U)
#define M2_OFF_MAC      (4430U)
#define M3_OFF_SIG      (1U)
#define M3_OFF_MAC      (3310U)

/* SHA-384 of L || the given parts, as the transcript hashes are defined */
static void Transcript(uint8* Out, const uint8* P1, uint32 N1, const uint8* P2, uint32 N2)
{
    static uint8 buf[PQCHS_LABEL_BYTES + PQCHS_M1_BYTES + PQCHS_M2_BYTES];
    (void)memcpy(buf, PQCHS_LABEL, PQCHS_LABEL_BYTES);
    (void)memcpy(&buf[PQCHS_LABEL_BYTES], P1, N1);
    (void)memcpy(&buf[PQCHS_LABEL_BYTES + N1], P2, N2);
    (void)SHA384(buf, PQCHS_LABEL_BYTES + N1 + N2, Out);
}

/* Bring both sides to rest after a scenario: the pending handshake of B times out, A starts again at
 * T_A and this time nothing interferes. Both then hold one new session. */
static void Settle(const char* What)
{
    Hook = NULL;
    NowMs += PQCHS_T_PEND_MS;
    Cycles(2U);
    NowMs += (PQCHS_T_A_MS - PQCHS_T_PEND_MS);
    Cycles(6U);
    CHECK((Inst[A].State == PQCHS_STATE_IDLE) && (Inst[B].State == PQCHS_STATE_IDLE), "%s: not at rest (A %u, B %u)",
          What, (unsigned)Inst[A].State, (unsigned)Inst[B].State);
    CHECK(memcmp(Inst[A].Sid, Inst[B].Sid, PQCHS_SID_BYTES) == 0, "%s: sides on different sessions after settling", What);
    CHECK(Session_Works() == TRUE, "%s: session does not work after settling", What);
    CHECK(GateClosed == FALSE, "%s: stream gate left closed", What);
    Erasure_Check(What);
    /* rows of the settling are not part of the next scenario */
    {
        PqcHs_AttemptInfoType row;
        while (Row(A, &row) == TRUE) { }
        while (Row(B, &row) == TRUE) { }
    }
}

static void Start(void)
{
    Oracle_Mark();
    /* past T_min of the previous handshake */
    NowMs += SOAD_PQC_HS_MIN_INTERVAL_MS;
    CHECK(PqcHs_Core_Initiate(&Inst[A]) == E_OK, "initiate");
}

/************************************************* H1, H2 ************************************************/

static const char* KatPath = NULL;

static void Hex(FILE* f, const char* Name, const uint8* Data, uint32 Length)
{
    uint32 i;
    (void)fprintf(f, "%s=", Name);
    for (i = 0U; i < Length; i++) { (void)fprintf(f, "%02x", Data[i]); }
    (void)fprintf(f, "\n");
}

static void Test_H1_Positive(void)
{
    static const uint8 orderA[] = { EV_HOLD_ON, EV_TX_M3, EV_TXCONF, EV_KEYSET_TX, EV_KEYSET_RX, EV_KEYVALID_TX,
                                    EV_KEYVALID_RX, EV_CTXSET, EV_CTXVALID, EV_FVM, EV_HOLD_OFF, 0U };
    static const uint8 orderB[] = { EV_GATE_CLOSED, EV_KEYSET_TX, EV_KEYSET_RX, EV_KEYVALID_TX, EV_KEYVALID_RX,
                                    EV_CTXSET, EV_CTXVALID, EV_FVM, EV_TX_M4, EV_GATE_RELEASE, 0U };
    PqcHs_AttemptInfoType row;
    uint8 sess[PQCHS_HASH_BYTES];
    uint8 th[PQCHS_HASH_BYTES];
    static uint8 all[PQCHS_LABEL_BYTES + PQCHS_M1_BYTES + PQCHS_M2_BYTES + PQCHS_M3_BYTES];
    uint32 evStart;
    uint32 evCut;
    uint32 evM3;
    uint64 installedB;

    (void)Session_Works();
    CHECK((SessionSigOk == TRUE) && (SessionMacOk == FALSE),
          "before any handshake: the no-session signature context on both sides, no MAC key (sig %u, mac %u)",
          (unsigned)SessionSigOk, (unsigned)SessionMacOk);
    CHECK((Inst[A].Established == FALSE) && (Inst[B].Established == FALSE), "no session before the handshake");
    CHECK(PqcHs_Core_Initiate(&Inst[B]) == E_NOT_OK, "a responder does not initiate");

    Oracle_Mark();
    CHECK(PqcHs_Core_Initiate(&Inst[A]) == E_OK, "initiate");
    evStart = EvCount;

    /* cycle 1: M1 and M2 */
    Step(A);
    CHECK(Inst[A].State == PQCHS_STATE_I_WAIT_M2, "A waits for M2 (%u)", (unsigned)Inst[A].State);
    installedB = Test_NowNs();      /* B's attempt begins when M1 is completely received, in this Pump */
    Pump();
    Step(B);
    CHECK(Inst[B].State == PQCHS_STATE_R_PENDING, "B pending (%u)", (unsigned)Inst[B].State);
    CHECK((Inst[B].Established == FALSE) && (Inst[B].InstallCount == 0U), "B installs nothing on M1");
    CHECK(Ev_Count(B, evStart, EV_KEYSET_TX) + Ev_Count(B, evStart, EV_KEYSET_RX) + Ev_Count(B, evStart, EV_CTXSET) +
          Ev_Count(B, evStart, EV_FVM) == 0U, "B writes no K_auth, context or freshness on M1");
    Pump();

    /* cycle 2, A: M2 accepted, transmission held; M3 waits until SecOC has flushed */
    evCut = EvCount;
    TxFlushed = FALSE;
    Step(A);
    CHECK(Inst[A].State == PQCHS_STATE_I_CUTOVER, "A in cut-over (%u)", (unsigned)Inst[A].State);
    CHECK(Ev_Count(A, evStart, EV_HOLD_ON) == 1U, "A holds SecOC transmission");
    Step(A);
    CHECK((Ev_Count(A, evStart, EV_TX_M3) == 0U) && (Inst[A].InstallCount == 0U), "no M3 and no installation before the flush");
    TxFlushed = TRUE;
    Step(A);
    CHECK(Inst[A].State == PQCHS_STATE_I_SEND_M3, "A sends M3 (%u)", (unsigned)Inst[A].State);
    CHECK((Inst[A].InstallCount == 0U) && (Ev_Count(A, evStart, EV_HOLD_OFF) == 0U), "A not installed before M3 is confirmed");
    evM3 = EvCount;
    Pump();
    CHECK(GateClosed == TRUE, "stream gated behind M3");
    CHECK(Inst[A].InstallCount == 0U, "A does not install inside the confirmation");

    /* cycle 2, B: M3 accepted, installation waits until SecOC has verified what came before M3 */
    RxDrained = FALSE;
    Step(B);
    CHECK(Inst[B].State == PQCHS_STATE_R_INSTALL, "B waits for the drain (%u)", (unsigned)Inst[B].State);
    CHECK(Residue((const uint8*)&Inst[B], (uint32)sizeof(Inst[B]), &Okm_Last()[32], 32U) == FALSE,
          "B erased K_kc_i when mac_A was checked");
    CHECK(Residue((const uint8*)&Inst[B], (uint32)sizeof(Inst[B]), &Okm_Last()[0], 32U) == TRUE,
          "B keeps K_kc_r for the acknowledgement");
    Step(B);
    CHECK((Inst[B].InstallCount == 0U) && (GateClosed == TRUE) && (Ev_Count(B, evM3, EV_TX_M4) == 0U),
          "B neither installs nor answers nor reopens before the drain");
    RxDrained = TRUE;
    Step(B);
    installedB = Test_NowNs() - installedB;
    CHECK((Inst[B].Established == TRUE) && (Inst[B].InstallCount == 1U), "B installed");
    CHECK(GateClosed == FALSE, "B reopened the stream");
    Pump();
    CHECK(EstablishedAtM4 == TRUE, "B is established before it sends M4");

    /* cycle 3, A: installation after the M3 confirmation, then M4 */
    Step(A);
    CHECK((Inst[A].Established == TRUE) && (Inst[A].InstallCount == 1U), "A installed");
    CHECK(Inst[A].State == PQCHS_STATE_IDLE, "A complete after M4 (%u)", (unsigned)Inst[A].State);
    Step(B);
    CHECK(Inst[B].State == PQCHS_STATE_IDLE, "B at rest (%u)", (unsigned)Inst[B].State);
    /* there was no connection: the M1 request opened it and SoAd reported ONLINE from inside the request */
    CHECK(Connected == TRUE, "the M1 request opened the connection");
    Cycles(2U);
    CHECK((Ev_Count(A, evStart, EV_TX_M1) == 1U) && (Ev_Count(A, evStart, EV_KEYGEN) == 1U) && (Inst[A].State == PQCHS_STATE_IDLE),
          "the ONLINE reported from inside the M1 request starts no second handshake");

    /* order of the steps */
    CHECK(Ev_Order(A, evCut, orderA) == TRUE, "A: hold, M3 handed over and confirmed, K_auth written, valid, context, freshness, resume");
    CHECK(Ev_Order(B, evM3, orderB) == TRUE, "B: gate, K_auth written, valid, context, freshness, M4, reopen");
    CHECK(Ev_JobInsideInstall(A, evStart) == FALSE, "A: no Csm job inside the installation step");
    CHECK(Ev_JobInsideInstall(B, evStart) == FALSE, "B: no Csm job inside the installation step");
    CHECK(Ev_Count(A, evStart, EV_FVM) == 1U, "A resets its session-bound freshness value once");
    CHECK(Ev_Count(B, evStart, EV_FVM) == 1U, "B resets its session-bound freshness value once");
    CHECK(GateViolations == 0U, "nothing passed the closed gate");

    /* messages and session */
    CHECK((LastLen[1] == 1217U) && (LastLen[2] == 4462U) && (LastLen[3] == 3342U) && (LastLen[4] == 33U),
          "message lengths %u %u %u %u", (unsigned)LastLen[1], (unsigned)LastLen[2], (unsigned)LastLen[3], (unsigned)LastLen[4]);
    CHECK((Last[1][0] == 1U) && (Last[2][0] == 1U) && (Last[3][0] == 1U) && (Last[4][0] == 1U), "version byte");
    (void)SHA256(Key[A].PublicKey, sizeof(Key[A].PublicKey), th);
    CHECK(memcmp(&Last[1][1], th, 32U) == 0, "ID_A = SHA-256(pk_A)");
    (void)SHA256(Key[B].PublicKey, sizeof(Key[B].PublicKey), th);
    CHECK(memcmp(&Last[2][1], th, 32U) == 0, "ID_B = SHA-256(pk_B)");
    (void)memcpy(all, PQCHS_LABEL, PQCHS_LABEL_BYTES);
    (void)memcpy(&all[PQCHS_LABEL_BYTES], Last[1], PQCHS_M1_BYTES);
    (void)memcpy(&all[PQCHS_LABEL_BYTES + PQCHS_M1_BYTES], Last[2], PQCHS_M2_BYTES);
    (void)memcpy(&all[PQCHS_LABEL_BYTES + PQCHS_M1_BYTES + PQCHS_M2_BYTES], Last[3], PQCHS_M3_BYTES);
    (void)SHA384(all, sizeof(all), sess);
    CHECK(memcmp(Inst[A].Sid, sess, PQCHS_SID_BYTES) == 0, "sid of A = first bytes of H(L || M1 || M2 || M3)");
    CHECK(memcmp(Inst[B].Sid, sess, PQCHS_SID_BYTES) == 0, "sid of B");
    /* what exactly was signed: role byte || transcript hash, under the handshake context */
    {
        uint8 msg[1U + PQCHS_HASH_BYTES];
        Transcript(th, Last[1], PQCHS_M1_BYTES, Last[2], M2_OFF_SIG);
        msg[0] = (uint8)'R';
        (void)memcpy(&msg[1], th, sizeof(th));
        CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), (const uint8*)PQCHS_LABEL, PQCHS_LABEL_BYTES, &Last[2][M2_OFF_SIG],
                               PQCHS_SIG_BYTES, Key[B].PublicKey) == PQC_E_OK, "sig_B = Sign(sk_B, 'R' || th2, ctx = L)");
        msg[0] = (uint8)'I';
        CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), (const uint8*)PQCHS_LABEL, PQCHS_LABEL_BYTES, &Last[2][M2_OFF_SIG],
                               PQCHS_SIG_BYTES, Key[B].PublicKey) != PQC_E_OK, "sig_B does not verify with the initiator's role byte");
        Transcript(th, Last[1], PQCHS_M1_BYTES, Last[2], PQCHS_M2_BYTES);
        (void)memcpy(&msg[1], th, sizeof(th));
        CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), (const uint8*)PQCHS_LABEL, PQCHS_LABEL_BYTES, &Last[3][M3_OFF_SIG],
                               PQCHS_SIG_BYTES, Key[A].PublicKey) == PQC_E_OK, "sig_A = Sign(sk_A, 'I' || th3, ctx = L)");
        CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), NULL, 0U, &Last[3][M3_OFF_SIG],
                               PQCHS_SIG_BYTES, Key[A].PublicKey) != PQC_E_OK, "sig_A is not an empty-context signature");
    }
    CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE), "one installation on each side");
    CHECK(Session_Works() == TRUE, "A's PDUs verify at B in the new session");
    /* the PDU signature context of the session: "PQC-SecOC-PDU-v1" || sess, written by both sides
     * byte for byte and used by the PDU jobs */
    {
        static uint8 sigPdu[PQC_MLDSA_SIGNATURE_BYTES];
        uint8 ctx[PQC_PDU_SIG_CTX_BYTES];
        uint8 pdu[6] = { 0x00U, 0x02U, 0xAAU, 0xBBU, 0x00U, 0x01U };
        uint32 sigLen = sizeof(sigPdu);
        Crypto_VerifyResultType ver = CRYPTO_E_VER_NOT_OK;

        (void)memcpy(ctx, "PQC-SecOC-PDU-v1", 16U);
        (void)memcpy(&ctx[16], sess, PQCHS_HASH_BYTES);
        CHECK((CtxWrittenLen[A] == 64U) && (memcmp(CtxWritten[A], ctx, 64U) == 0), "A installs the context \"PQC-SecOC-PDU-v1\" || sess");
        CHECK((CtxWrittenLen[B] == 64U) && (memcmp(CtxWritten[B], ctx, 64U) == 0), "B installs the context \"PQC-SecOC-PDU-v1\" || sess");
        ActAs(A);
        CHECK((__real_Csm_SignatureGenerate((uint32)CSM_JOBID, CRYPTO_OPERATIONMODE_SINGLECALL, pdu, sizeof(pdu), sigPdu, &sigLen) == E_OK) &&
              (PQC_MLDSA_Verify(pdu, sizeof(pdu), ctx, sizeof(ctx), sigPdu, sigLen, Key[A].PublicKey) == PQC_E_OK),
              "A's PDU sign job signs under that context");
        sigLen = 0U;
        CHECK((PQC_MLDSA_Sign(pdu, sizeof(pdu), ctx, sizeof(ctx), Key[A].SecretKey, sigPdu, &sigLen) == PQC_E_OK) &&
              (__real_Csm_SignatureVerify(CSM_JOBID_VERIFY_PEER_BASE + PEER_OF_B, CRYPTO_OPERATIONMODE_SINGLECALL, pdu, sizeof(pdu),
                                          sigPdu, sigLen, &ver) == E_OK) && (ver == CRYPTO_E_VER_OK),
              "B's PDU verify job verifies under that context");
        ctx[63] ^= 0x01U;
        sigLen = 0U;
        ver = CRYPTO_E_VER_OK;
        CHECK((PQC_MLDSA_Sign(pdu, sizeof(pdu), ctx, sizeof(ctx), Key[A].SecretKey, sigPdu, &sigLen) == PQC_E_OK) &&
              (__real_Csm_SignatureVerify(CSM_JOBID_VERIFY_PEER_BASE + PEER_OF_B, CRYPTO_OPERATIONMODE_SINGLECALL, pdu, sizeof(pdu),
                                          sigPdu, sigLen, &ver) == E_OK) && (ver == CRYPTO_E_VER_NOT_OK),
              "a context that differs in its last byte does not verify (request successful, negative verdict)");
    }

    /* K_auth per direction, and against the derivation output */
    CHECK(NumOkm == 2U, "one key derivation on each side (%u)", (unsigned)NumOkm);
    CHECK(memcmp(SecOkm[0], SecOkm[1], CSM_HS_KDF_OUTPUT_BYTES) == 0, "both sides derived the same keys");
    CHECK(Mac_TxKeyIs(A_JOB_GEN, &SecOkm[0][64]) == TRUE, "A sends under K_auth_i2r");
    CHECK(Mac_RxKeyIs(A_JOB_VER, &SecOkm[0][96]) == TRUE, "A receives under K_auth_r2i");
    CHECK(Mac_TxKeyIs(B_JOB_GEN, &SecOkm[0][96]) == TRUE, "B sends under K_auth_r2i");
    CHECK(Mac_RxKeyIs(B_JOB_VER, &SecOkm[0][64]) == TRUE, "B receives under K_auth_i2r");
    CHECK((Mac_TxKeyIs(A_JOB_GEN, &SecOkm[0][96]) == FALSE) && (Mac_RxKeyIs(B_JOB_VER, &SecOkm[0][96]) == FALSE),
          "the two directions do not share a key");

    /* rows */
    CHECK(Row(A, &row) == TRUE, "A has a row");
    CHECK((row.Role == PQCHS_ROLE_INITIATOR) && (row.Result == PQCHS_RESULT_OK) && (row.Seq == 0U), "A row: initiator, ok, seq 0");
    CHECK((row.BytesTx == (1217U + 8U + 3342U + 8U)) && (row.BytesRx == (4462U + 8U + 33U + 8U)), "A bytes %u / %u",
          (unsigned)row.BytesTx, (unsigned)row.BytesRx);
    CHECK((row.Times.KeygenNs > 0U) && (row.Times.DecapsNs > 0U) && (row.Times.SignNs > 0U) && (row.Times.VerifyNs > 0U) &&
          (row.Times.KdfNs > 0U) && (row.Times.HashNs > 0U) && (row.Times.MacNs > 0U) && (row.Times.EncapsNs == 0U), "A stage times");
    CHECK(row.TotalNs >= (row.Times.KeygenNs + row.Times.DecapsNs + row.Times.SignNs + row.Times.VerifyNs + row.Times.KdfNs),
          "A total covers its stages");
    CHECK(Row(B, &row) == TRUE, "B has a row");
    CHECK((row.Role == PQCHS_ROLE_RESPONDER) && (row.Result == PQCHS_RESULT_OK) && (row.Seq == 0U), "B row: responder, ok, seq 0");
    CHECK((row.BytesRx == (1217U + 8U + 3342U + 8U)) && (row.BytesTx == (4462U + 8U + 33U + 8U)), "B bytes %u / %u",
          (unsigned)row.BytesTx, (unsigned)row.BytesRx);
    CHECK((row.Times.EncapsNs > 0U) && (row.Times.SignNs > 0U) && (row.Times.VerifyNs > 0U) && (row.Times.KdfNs > 0U) &&
          (row.Times.HashNs > 0U) && (row.Times.MacNs > 0U) && (row.Times.KeygenNs == 0U) && (row.Times.DecapsNs == 0U), "B stage times");
    /* the responder's total: from M1 received to its installation */
    CHECK((row.TotalNs >= (row.Times.EncapsNs + row.Times.SignNs + row.Times.VerifyNs + row.Times.KdfNs)) && (row.TotalNs <= installedB),
          "B total %llu ns covers its stages and ends at the installation (at most %llu ns)",
          (unsigned long long)row.TotalNs, (unsigned long long)installedB);
    EXPECT_NO_ROW(A);
    EXPECT_NO_ROW(B);

    Erasure_Check("success");

    /* H2: known-answer transcript for test/kat_pqchs.py, only of a run without a failed check */
    if ((KatPath != NULL) && (Failures == 0U))
    {
        FILE* f = fopen(KatPath, "w");
        CHECK(f != NULL, "cannot write %s", KatPath);
        if (f != NULL)
        {
            Hex(f, "m1", Last[1], LastLen[1]);
            Hex(f, "m2", Last[2], LastLen[2]);
            Hex(f, "m3", Last[3], LastLen[3]);
            Hex(f, "m4", Last[4], LastLen[4]);
            Hex(f, "ss", SecSs[0], 32U);
            Hex(f, "prk", SecPrk[0], 32U);
            Hex(f, "k_kc_r", &SecOkm[0][0], 32U);
            Hex(f, "k_kc_i", &SecOkm[0][32], 32U);
            Hex(f, "k_auth_i2r", &SecOkm[0][64], 32U);
            Hex(f, "k_auth_r2i", &SecOkm[0][96], 32U);
            Hex(f, "sid_a", Inst[A].Sid, PQCHS_SID_BYTES);
            Hex(f, "sid_b", Inst[B].Sid, PQCHS_SID_BYTES);
            Hex(f, "signed_b", Signed[B], SignedLen[B]);
            Hex(f, "signed_a", Signed[A], SignedLen[A]);
            Hex(f, "sess_a", Inst[A].Sess, PQCHS_HASH_BYTES);
            Hex(f, "sess_b", Inst[B].Sess, PQCHS_HASH_BYTES);
            (void)fclose(f);
            (void)printf("H2 known-answer transcript written to %s\n", KatPath);
        }
    }
    (void)memcpy(Saved, Last, sizeof(Saved));
    (void)printf("H1 positive run\n");
}

/************************************************* H3 ****************************************************/

static uint32 H3_Stage = 0U;
static uint32 H3_EvStart = 0U;

/* Before the genuine M2, M3 and M4 arrive, their receiver gets damaged copies. */
static boolean Hook_Discard(uint8 MsgNo, uint8* Data, uint32* Length)
{
    static uint8 bad[PQCHS_M2_BYTES];
    HookType self = Hook;

    Hook = NULL;        /* the deliveries below are not hooked again */
    if (MsgNo == 2U)
    {
        H3_Stage++;
        /* one byte short: refused before any byte is read */
        CHECK(Deliver(2U, Data, *Length - 1U) == BUFREQ_E_NOT_OK, "M2 one byte short is refused at StartOfReception");
        Step(A);
        EXPECT_ROW(A, PQCHS_RESULT_BAD_LEN);
        (void)memcpy(bad, Data, *Length); bad[0] = 0x02U;
        (void)Deliver(2U, bad, *Length); Step(A);
        EXPECT_ROW(A, PQCHS_RESULT_BAD_VER);
        (void)memcpy(bad, Data, *Length); Flip(bad, M2_OFF_ID + 5U);
        (void)Deliver(2U, bad, *Length); Step(A);
        EXPECT_ROW(A, PQCHS_RESULT_UNKNOWN_ID);
        (void)memcpy(bad, Data, *Length); Flip(bad, M2_OFF_SIG + 100U);
        (void)Deliver(2U, bad, *Length); Step(A);
        EXPECT_ROW(A, PQCHS_RESULT_SIG_FAIL);
        (void)memcpy(bad, Data, *Length); Flip(bad, M2_OFF_CT + 7U);
        (void)Deliver(2U, bad, *Length); Step(A);
        EXPECT_ROW(A, PQCHS_RESULT_SIG_FAIL);
        CHECK(Ev_Count(A, H3_EvStart, EV_DECAPS) == 0U, "no decapsulation before a valid sig_B");
        CHECK(Inst[A].State == PQCHS_STATE_I_WAIT_M2, "A still waits for M2");
    }
    else if (MsgNo == 3U)
    {
        uint32 releases = Ev_Count(B, H3_EvStart, EV_GATE_RELEASE);
        H3_Stage++;
        CHECK(Deliver(3U, Data, *Length + 1U) == BUFREQ_E_NOT_OK, "M3 one byte long is refused at StartOfReception");
        Step(B);
        EXPECT_ROW(B, PQCHS_RESULT_BAD_LEN);
        (void)memcpy(bad, Data, *Length); bad[0] = 0x00U;
        (void)Deliver(3U, bad, *Length); Step(B);
        EXPECT_ROW(B, PQCHS_RESULT_BAD_VER);
        (void)memcpy(bad, Data, *Length); Flip(bad, M3_OFF_SIG + 3000U);
        (void)Deliver(3U, bad, *Length); Step(B);
        EXPECT_ROW(B, PQCHS_RESULT_SIG_FAIL);
        CHECK(Ev_Count(B, H3_EvStart, EV_GATE_RELEASE) == (releases + 2U), "the gate is released after every rejected M3");
        CHECK((Inst[B].State == PQCHS_STATE_R_PENDING) && (Oracle_Unchanged(B) == TRUE), "B still pending, nothing installed");
    }
    else if (MsgNo == 4U)
    {
        H3_Stage++;
        (void)memcpy(bad, Data, *Length); bad[0] = 0x7FU;
        (void)Deliver(4U, bad, *Length); Step(A);
        EXPECT_ROW(A, PQCHS_RESULT_BAD_VER);
        (void)memcpy(bad, Data, *Length); Flip(bad, 20U);
        (void)Deliver(4U, bad, *Length); Step(A);
        EXPECT_ROW(A, PQCHS_RESULT_MAC_FAIL);
        CHECK(Inst[A].State == PQCHS_STATE_I_WAIT_M4, "A still waits for M4 after a wrong acknowledgement");
    }
    else
    {
        /* M1: a wrong length, a wrong version and an identity that is not the pinned one are dropped
         * without an encapsulation, and do not count as an accepted M1 for T_min */
        H3_Stage++;
        CHECK(Deliver(1U, Data, *Length - 1U) == BUFREQ_E_NOT_OK, "M1 one byte short is refused at StartOfReception");
        EXPECT_ROW(B, PQCHS_RESULT_BAD_LEN);
        (void)memcpy(bad, Data, *Length); bad[0] = 0x02U;
        (void)Deliver(1U, bad, *Length); Step(B);
        EXPECT_ROW(B, PQCHS_RESULT_BAD_VER);
        (void)memcpy(bad, Data, *Length); Flip(bad, 1U + 31U);
        (void)Deliver(1U, bad, *Length); Step(B);
        EXPECT_ROW(B, PQCHS_RESULT_UNKNOWN_ID);
        CHECK((Ev_Count(B, H3_EvStart, EV_ENCAPS) == 0U) && (Ev_Count(B, H3_EvStart, EV_SIGN) == 0U) &&
              (Inst[B].State == PQCHS_STATE_IDLE), "a discarded M1 costs no encapsulation and no signature");
    }
    Hook = self;
    return TRUE;
}

static void Test_H3_Discard(void)
{
    Start();
    H3_Stage = 0U;
    H3_EvStart = EvCount;
    Hook = Hook_Discard;
    Cycles(4U);
    Hook = NULL;
    CHECK(H3_Stage == 4U, "all four stages ran (%u)", (unsigned)H3_Stage);
    CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE), "the genuine messages complete the handshake");
    CHECK(memcmp(Inst[A].Sid, Inst[B].Sid, PQCHS_SID_BYTES) == 0, "same session on both sides");
    CHECK(Session_Works() == TRUE, "session works");
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    EXPECT_NO_ROW(A);
    EXPECT_NO_ROW(B);
    CHECK((Inst[A].State == PQCHS_STATE_IDLE) && (Inst[B].State == PQCHS_STATE_IDLE), "at rest");
    Erasure_Check("discarded messages");
    (void)printf("H3 discard rule\n");
}

/************************************************* H4 ****************************************************/

static boolean Hook_M2MacThenGenuine(uint8 MsgNo, uint8* Data, uint32* Length)
{
    static uint8 bad[PQCHS_M2_BYTES];
    HookType self = Hook;

    if (MsgNo != 2U) { return TRUE; }
    Hook = NULL;
    (void)memcpy(bad, Data, *Length); Flip(bad, M2_OFF_MAC + 31U);
    (void)Deliver(2U, bad, *Length); Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_MAC_FAIL);
    CHECK(Inst[A].State == PQCHS_STATE_I_RETRY, "the handshake of A is over (%u)", (unsigned)Inst[A].State);
    /* the genuine M2 comes too late */
    (void)Deliver(2U, Data, *Length); Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    Hook = self;
    return FALSE;
}

static boolean Hook_M3MacThenGenuine(uint8 MsgNo, uint8* Data, uint32* Length)
{
    static uint8 bad[PQCHS_M3_BYTES];
    HookType self = Hook;

    if (MsgNo != 3U) { return TRUE; }
    Hook = NULL;
    (void)memcpy(bad, Data, *Length); Flip(bad, M3_OFF_MAC);
    (void)Deliver(3U, bad, *Length); Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_MAC_FAIL);
    CHECK(Inst[B].State == PQCHS_STATE_IDLE, "the pending handshake of B is wiped (%u)", (unsigned)Inst[B].State);
    (void)Deliver(3U, Data, *Length); Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    Hook = self;
    return FALSE;
}

static void Test_H4_Wipe(void)
{
    uint32 ev;

    /* A: M2 with a valid signature and a wrong mac_B (SPEC negative test 4) */
    Start();
    ev = EvCount;
    Hook = Hook_M2MacThenGenuine;
    Cycles(3U);
    Hook = NULL;
    CHECK(Ev_Count(A, ev, EV_DECAPS) == 1U, "A decapsulated once, behind the valid signature");
    CHECK((Oracle_Unchanged(A) == TRUE) && (Oracle_Unchanged(B) == TRUE), "no key installed on either side");
    CHECK(Ev_Count(A, ev, EV_TX_M3) == 0U, "A sent no M3");
    CHECK(Session_Works() == TRUE, "the previous session still works");
    EXPECT_NO_ROW(A);
    NowMs += PQCHS_T_PEND_MS;
    Cycles(1U);
    EXPECT_ROW(B, PQCHS_RESULT_TIMEOUT);
    Erasure_Check("failure: wrong mac_B, responder timed out");
    Settle("H4 mac_B");

    /* B: M3 with a valid signature and a wrong mac_A */
    Start();
    Hook = Hook_M3MacThenGenuine;
    Cycles(3U);
    Hook = NULL;
    CHECK(Oracle_Unchanged(B) == TRUE, "B installed nothing");
    CHECK(Oracle_NewSession(A) == TRUE, "A has switched: it installs when M3 is handed over");
    (void)Session_Works();
    CHECK((SessionSigOk == FALSE) && (SessionMacOk == FALSE), "A's PDUs are rejected at B until the next handshake, in both variants");
    Settle("H4 mac_A");
    (void)printf("H4 wipe rule\n");
}

/************************************************* H5 ****************************************************/

static void Craft_M1(uint8* M1)
{
    static uint8 dk[PQC_MLKEM_SECRET_KEY_BYTES];
    M1[0] = PQCHS_VERSION;
    (void)SHA256(Key[A].PublicKey, sizeof(Key[A].PublicKey), &M1[1]);
    CHECK(PQC_MLKEM_KeyGen(&M1[33], dk) == PQC_E_OK, "attacker key generation");
}

static boolean Hook_SecondM1(uint8 MsgNo, uint8* Data, uint32* Length)
{
    static uint8 m1[PQCHS_M1_BYTES];
    HookType self = Hook;
    uint32 ev = EvCount;

    (void)Data;
    (void)Length;
    if (MsgNo != 2U) { return TRUE; }
    /* B is pending; another well-formed M1 with a fresh ek arrives before M3, later than T_min (so it
     * is the pending handshake that stops it) and before T_pend */
    Hook = NULL;
    NowMs += SOAD_PQC_HS_MIN_INTERVAL_MS;
    Craft_M1(m1);
    (void)Deliver(1U, m1, sizeof(m1)); Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    CHECK((Ev_Count(B, ev, EV_ENCAPS) == 0U) && (Ev_Count(B, ev, EV_SIGN) == 0U) && (Ev_Count(B, ev, EV_TX_M2) == 0U),
          "the second M1 costs no encapsulation, no signature and gets no M2");
    Hook = self;
    return TRUE;
}

static void Test_H5_Pending(void)
{
    static uint8 m1[PQCHS_M1_BYTES];
    uint32 ev;

    /* a second M1 while one is pending is dropped, and the first handshake completes */
    Start();
    Hook = Hook_SecondM1;
    Cycles(4U);
    Hook = NULL;
    CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE), "the pending handshake was not replaced: it completes");
    CHECK(Session_Works() == TRUE, "session works");
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    EXPECT_ROW(B, PQCHS_RESULT_OK);

    /* T_min: counted from the last accepted M1, here the one of a complete handshake */
    Start();
    Cycles(4U);
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    Oracle_Mark();
    ev = EvCount;
    NowMs += (SOAD_PQC_HS_MIN_INTERVAL_MS - 1U);
    Craft_M1(m1);
    (void)Deliver(1U, m1, sizeof(m1)); Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    CHECK(Ev_Count(B, ev, EV_ENCAPS) == 0U, "an M1 inside T_min costs no encapsulation");
    NowMs += 1U;
    (void)Deliver(1U, m1, sizeof(m1)); Step(B);
    CHECK((Inst[B].State == PQCHS_STATE_R_PENDING) && (Ev_Count(B, ev, EV_ENCAPS) == 1U), "an M1 at T_min is answered");
    Pump();     /* its M2 reaches A, which has no outstanding M1 */
    Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);

    /* T_pend: the pending handshake is wiped, an M3 after that matches nothing */
    NowMs += (PQCHS_T_PEND_MS - 1U);
    Step(B);
    CHECK(Inst[B].State == PQCHS_STATE_R_PENDING, "pending until T_pend");
    NowMs += 1U;
    Step(B);
    CHECK(Inst[B].State == PQCHS_STATE_IDLE, "wiped at T_pend");
    EXPECT_ROW(B, PQCHS_RESULT_TIMEOUT);
    (void)Deliver(3U, Saved[3], PQCHS_M3_BYTES); Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    CHECK(GateClosed == FALSE, "gate released after the unmatched M3");
    CHECK((Oracle_Unchanged(A) == TRUE) && (Oracle_Unchanged(B) == TRUE) && (Session_Works() == TRUE), "session untouched");
    Erasure_Check("timeout of a pending handshake");

    /* the connection ends while B is pending and A waits for M2: both attempts end with it */
    Start();
    Step(A);
    Pump();
    Step(B);
    CHECK((Inst[B].State == PQCHS_STATE_R_PENDING) && (TxQueued == 1U), "B pending, M2 in transmission");
    Wire_Down();
    CHECK(Inst[B].State == PQCHS_STATE_IDLE, "pending wiped when the connection ends");
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    CHECK(Inst[A].State == PQCHS_STATE_I_RETRY, "A does not wait for an M2 of the connection that is gone (%u)", (unsigned)Inst[A].State);
    Erasure_Check("both attempts ended with the connection");
    (void)Deliver(3U, Saved[3], PQCHS_M3_BYTES); Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    CHECK((Oracle_Unchanged(A) == TRUE) && (Oracle_Unchanged(B) == TRUE) && (Session_Works() == TRUE), "nothing installed, session untouched");
    Settle("H5 connection ended while pending");

    /* a connection that comes up makes A start a handshake; the session survives the reconnect */
    Oracle_Mark();
    NowMs += SOAD_PQC_HS_MIN_INTERVAL_MS;
    Wire_Down();
    Cycles(1U);
    CHECK((Inst[A].State == PQCHS_STATE_IDLE) && (Oracle_Unchanged(A) == TRUE) && (Inst[A].Established == TRUE) &&
          (Session_Works() == TRUE), "loss of the connection changes no session state");
    ev = EvCount;
    Wire_Up();      /* opened by something else than the handshake, for example the next Secured I-PDU */
    CHECK(Ev_Count(A, ev, EV_TX_M1) == 0U, "nothing is transmitted from inside the mode change");
    Cycles(4U);
    CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE) && (Session_Works() == TRUE),
          "ONLINE starts a handshake");
    CHECK(Ev_Count(A, ev, EV_TX_M1) == 1U, "one handshake for one ONLINE");
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    EXPECT_NO_ROW(A);
    EXPECT_NO_ROW(B);
    Erasure_Check("rekey");
    (void)printf("H5 pending state, T_min, T_pend, connection\n");
}

/************************************************* H6 ****************************************************/

static uint8 H6_Case = 0U;

static boolean Hook_Drop(uint8 MsgNo, uint8* Data, uint32* Length)
{
    (void)MsgNo;
    (void)Data;
    (void)Length;
    return FALSE;
}

static boolean Hook_Negative(uint8 MsgNo, uint8* Data, uint32* Length)
{
    static uint8 dk[PQC_MLKEM_SECRET_KEY_BYTES];
    static uint8 ss[32];
    uint8 th2[PQCHS_HASH_BYTES];
    uint8 msg[1U + PQCHS_HASH_BYTES];
    uint32 sigLen = 0U;

    (void)Length;
    if ((H6_Case == 1U) && (MsgNo == 1U))
    {
        /* substituted ek, a valid key generation output */
        CHECK(PQC_MLKEM_KeyGen(&Data[33], dk) == PQC_E_OK, "attacker key generation");
    }
    else if ((H6_Case == 2U) && (MsgNo == 2U))
    {
        /* substituted ct: the attacker encapsulates to the genuine ek */
        CHECK(PQC_MLKEM_Encapsulate(&Last[1][33], &Data[M2_OFF_CT], ss) == PQC_E_OK, "attacker encapsulation");
    }
    else if ((H6_Case == 3U) && (MsgNo == 2U))
    {
        /* M2 signed over the right transcript with a key that is not B's */
        Transcript(th2, Last[1], PQCHS_M1_BYTES, Data, M2_OFF_SIG);
        msg[0] = (uint8)'R';
        (void)memcpy(&msg[1], th2, sizeof(th2));
        CHECK(PQC_MLDSA_Sign(msg, sizeof(msg), (const uint8*)PQCHS_LABEL, PQCHS_LABEL_BYTES, KeyX.SecretKey,
                             &Data[M2_OFF_SIG], &sigLen) == PQC_E_OK, "attacker signature");
    }
    else if ((H6_Case == 4U) && (MsgNo == 2U))
    {
        Flip(Data, M2_OFF_MAC);
    }
    else
    {
        /* unchanged */
    }
    return TRUE;
}

static void Negative_End(const char* What, PqcHs_ResultType ResultA)
{
    Hook = NULL;
    CHECK((Oracle_Unchanged(A) == TRUE) && (Oracle_Unchanged(B) == TRUE), "%s: a key was installed", What);
    CHECK(Session_Works() == TRUE, "%s: the session does not work any more", What);
    EXPECT_ROW(A, ResultA);
    EXPECT_NO_ROW(A);
    EXPECT_NO_ROW(B);       /* B is pending: its row comes with T_pend */
    NowMs += PQCHS_T_PEND_MS;
    Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_TIMEOUT);
    Settle(What);
}

static void Test_H6_Negative(void)
{
    uint32 ev;

    /* 1 to 4: rejected by A at sig_B (1, 2, 3) or mac_B (4); B answered an M1 and never sees an M3 */
    for (H6_Case = 1U; H6_Case <= 4U; H6_Case++)
    {
        static const char* const names[5] = { "", "test 1 substituted ek", "test 2 substituted ct",
                                              "test 3 M2 signed with a wrong key", "test 4 mac_B altered" };
        Start();
        ev = EvCount;
        Hook = Hook_Negative;
        Cycles(3U);
        CHECK(Ev_Count(A, ev, EV_TX_M3) == 0U, "%s: A sent an M3", names[H6_Case]);
        CHECK(Ev_Count(A, ev, EV_DECAPS) == ((H6_Case == 4U) ? 1U : 0U), "%s: decapsulations", names[H6_Case]);
        Negative_End(names[H6_Case], (H6_Case == 4U) ? PQCHS_RESULT_MAC_FAIL : PQCHS_RESULT_SIG_FAIL);
    }

    /* 5: replayed M1 of an earlier run. B answers it; nothing follows and B wipes at T_pend. */
    Oracle_Mark();
    NowMs += SOAD_PQC_HS_MIN_INTERVAL_MS;
    (void)Deliver(1U, Saved[1], PQCHS_M1_BYTES); Step(B);
    CHECK(Inst[B].State == PQCHS_STATE_R_PENDING, "test 5: B answers the replayed M1");
    Pump(); Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);      /* its M2 matches no outstanding M1 at A */
    /* 7a: the M3 of that earlier run, replayed into this pending handshake */
    (void)Deliver(3U, Saved[3], PQCHS_M3_BYTES); Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_SIG_FAIL);
    CHECK(Inst[B].State == PQCHS_STATE_R_PENDING, "test 7: B stays pending after the replayed M3");
    NowMs += PQCHS_T_PEND_MS;
    Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_TIMEOUT);
    CHECK((Oracle_Unchanged(A) == TRUE) && (Oracle_Unchanged(B) == TRUE) && (Session_Works() == TRUE), "tests 5 and 7: session untouched");
    Erasure_Check("tests 5 and 7");

    /* 6: replayed M2 of an earlier run, with no outstanding M1 and into an outstanding one; and the
     * replayed M4 of that run with no outstanding M3: dropped for its state, before its MAC is looked at */
    (void)Deliver(2U, Saved[2], PQCHS_M2_BYTES); Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    ev = EvCount;
    (void)Deliver(4U, Saved[4], PQCHS_M4_BYTES); Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    CHECK(Ev_Count(A, ev, EV_MACVER) == 0U, "an M4 with no outstanding M3 costs no MAC");
    Start();
    Hook = Hook_Drop;                       /* M1 goes out and is lost */
    Step(A);
    Pump();
    Hook = NULL;
    (void)Deliver(2U, Saved[2], PQCHS_M2_BYTES); Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_SIG_FAIL);
    CHECK(Inst[A].State == PQCHS_STATE_I_WAIT_M2, "test 6: A keeps waiting for the genuine M2");
    /* 7b: replayed M3 with nothing pending */
    (void)Deliver(3U, Saved[3], PQCHS_M3_BYTES); Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    CHECK((Oracle_Unchanged(A) == TRUE) && (Oracle_Unchanged(B) == TRUE) && (Session_Works() == TRUE), "tests 6 and 7: session untouched");
    /* A gets no M2: T_A, then a new handshake with a fresh ek */
    {
        static uint8 firstM1[PQCHS_M1_BYTES];
        (void)memcpy(firstM1, Inst[A].M1, sizeof(firstM1));
        NowMs += PQCHS_T_A_MS;
        Cycles(5U);
        EXPECT_ROW(A, PQCHS_RESULT_TIMEOUT);
        CHECK(memcmp(&firstM1[33], &Last[1][33], PQCHS_EK_BYTES) != 0, "the new handshake uses a fresh ek");
        CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE) && (Session_Works() == TRUE),
              "A starts again after T_A and completes");
        EXPECT_ROW(A, PQCHS_RESULT_OK);
        EXPECT_ROW(B, PQCHS_RESULT_OK);
        Erasure_Check("timeout of the initiator");
    }

    /* an encapsulation key that fails the FIPS 203 Sec. 7.2 check: the encapsulation fails, nothing
     * is signed or sent (SPEC: added once the pinned liboqs build is seen to perform the check) */
    {
        static uint8 m1[PQCHS_M1_BYTES];
        Oracle_Mark();
        NowMs += SOAD_PQC_HS_MIN_INTERVAL_MS;
        Craft_M1(m1);
        (void)memset(&m1[33], 0xFF, 32U);
        ev = EvCount;
        (void)Deliver(1U, m1, sizeof(m1)); Step(B);
        EXPECT_ROW(B, PQCHS_RESULT_STATE);
        CHECK((Ev_Count(B, ev, EV_ENCAPS) == 1U) && (Ev_Count(B, ev, EV_SIGN) == 0U) && (Ev_Count(B, ev, EV_TX_M2) == 0U) &&
              (Inst[B].State == PQCHS_STATE_IDLE), "malformed ek: nothing signed, no M2, nothing pending");
        CHECK((Oracle_Unchanged(B) == TRUE) && (Session_Works() == TRUE), "malformed ek: session untouched");
        Erasure_Check("malformed ek");
    }

    /* 8: the initiator's key is not pinned at B */
    Start();
    (void)__real_Csm_KeyElementSet(CSM_KEYID_PEER_PUBKEY_BASE + PEER_OF_B, CSM_KEYELEMENT_MLDSA_PEER_PUBLIC,
                                   KeyX.PublicKey, CSM_MLDSA_PUBLIC_KEY_BYTES);
    (void)__real_Csm_KeySetValid(CSM_KEYID_PEER_PUBKEY_BASE + PEER_OF_B);
    ev = EvCount;
    Cycles(2U);
    EXPECT_ROW(B, PQCHS_RESULT_UNKNOWN_ID);
    CHECK((Ev_Count(B, ev, EV_ENCAPS) == 0U) && (Ev_Count(B, ev, EV_TX_M2) == 0U), "test 8: no encapsulation, no M2");
    CHECK((Oracle_Unchanged(A) == TRUE) && (Oracle_Unchanged(B) == TRUE), "test 8: no key installed");
    (void)__real_Csm_KeyElementSet(CSM_KEYID_PEER_PUBKEY_BASE + PEER_OF_B, CSM_KEYELEMENT_MLDSA_PEER_PUBLIC,
                                   Key[A].PublicKey, CSM_MLDSA_PUBLIC_KEY_BYTES);
    (void)__real_Csm_KeySetValid(CSM_KEYID_PEER_PUBKEY_BASE + PEER_OF_B);
    CHECK(Session_Works() == TRUE, "test 8: session untouched");
    Settle("test 8 initiator not pinned");

    (void)printf("H6 negative tests 1 to 8\n");
}

/************************************************* H7 ****************************************************/

static uint8 H7_Case = 0U;

static boolean Hook_M3M4(uint8 MsgNo, uint8* Data, uint32* Length)
{
    uint8 th3[PQCHS_HASH_BYTES];
    uint8 msg[1U + PQCHS_HASH_BYTES];
    uint32 sigLen = 0U;

    (void)Length;
    if (MsgNo == 3U)
    {
        switch (H7_Case)
        {
            case 1U: return FALSE;                                  /* M3 dropped */
            case 2U: Flip(Data, M3_OFF_SIG + 17U); break;           /* sig_A altered */
            case 3U: Flip(Data, M3_OFF_MAC + 9U); break;            /* mac_A altered */
            case 4U:                                                /* signed with a key that is not A's */
                Transcript(th3, Last[1], PQCHS_M1_BYTES, Last[2], PQCHS_M2_BYTES);
                msg[0] = (uint8)'I';
                (void)memcpy(&msg[1], th3, sizeof(th3));
                CHECK(PQC_MLDSA_Sign(msg, sizeof(msg), (const uint8*)PQCHS_LABEL, PQCHS_LABEL_BYTES, KeyX.SecretKey,
                                     &Data[M3_OFF_SIG], &sigLen) == PQC_E_OK, "attacker signature");
                break;
            default: break;
        }
    }
    else if (MsgNo == 4U)
    {
        if (H7_Case == 5U) { return FALSE; }                        /* M4 dropped */
        if (H7_Case == 6U) { Flip(Data, 1U); }                      /* mac_ack altered */
    }
    else
    {
        /* unchanged */
    }
    return TRUE;
}

static void Test_H7_M3M4(void)
{
    static const char* const names[7] = { "", "test 11 M3 dropped", "test 11 sig_A altered", "test 11 mac_A altered",
                                          "test 11 M3 signed with a wrong key", "test 12 M4 dropped", "test 12 M4 altered" };
    static const PqcHs_ResultType rowB[5] = { PQCHS_RESULT_OK, PQCHS_RESULT_TIMEOUT, PQCHS_RESULT_SIG_FAIL,
                                              PQCHS_RESULT_MAC_FAIL, PQCHS_RESULT_SIG_FAIL };

    for (H7_Case = 1U; H7_Case <= 6U; H7_Case++)
    {
        const char* name = names[H7_Case];
        uint8 sidSession1[PQCHS_SID_BYTES];
        uint32 ev;

        Start();
        ev = EvCount;
        (void)memcpy(sidSession1, Inst[B].Sid, PQCHS_SID_BYTES);
        Hook = Hook_M3M4;
        Cycles(4U);
        Hook = NULL;

        if (H7_Case <= 4U)
        {
            /* 11: B installs nothing and keeps its session; A has installed */
            CHECK(Oracle_Unchanged(B) == TRUE, "%s: B installed or changed its session", name);
            CHECK(Ev_Count(B, ev, EV_FVM) == 0U, "%s: B reset a freshness value", name);
            CHECK(Oracle_NewSession(A) == TRUE, "%s: A has not installed", name);
            (void)Session_Works();
            CHECK((SessionSigOk == FALSE) && (SessionMacOk == FALSE), "%s: PDUs of A are still accepted by B", name);
            CHECK(Ev_Count(B, ev, EV_TX_M4) == 0U, "%s: B sent an M4", name);
            CHECK(Inst[A].State == PQCHS_STATE_I_WAIT_M4, "%s: A waits for M4 (%u)", name, (unsigned)Inst[A].State);
            if (H7_Case == 1U)
            {
                NowMs += PQCHS_T_PEND_MS;
                Step(B);
            }
            EXPECT_ROW(B, rowB[H7_Case]);
            EXPECT_NO_ROW(A);
            /* no valid M4 inside T_A: A runs a new handshake and delivery resumes */
            NowMs += PQCHS_T_A_MS;
            Cycles(5U);
            EXPECT_ROW(A, PQCHS_RESULT_TIMEOUT);
            EXPECT_ROW(A, PQCHS_RESULT_OK);
            CHECK((Inst[A].InstallCount == (InstallsBefore[A] + 2U)) && (Inst[B].InstallCount == (InstallsBefore[B] + 1U)),
                  "%s: installations after the recovery (A %u, B %u)", name,
                  (unsigned)(Inst[A].InstallCount - InstallsBefore[A]), (unsigned)(Inst[B].InstallCount - InstallsBefore[B]));
        }
        else
        {
            /* 12: both sides hold the new session, delivery is not interrupted */
            CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE), "%s: both sides switch", name);
            CHECK(Session_Works() == TRUE, "%s: delivery interrupted", name);
            EXPECT_ROW(B, PQCHS_RESULT_OK);
            if (H7_Case == 6U) { EXPECT_ROW(A, PQCHS_RESULT_MAC_FAIL); }
            EXPECT_NO_ROW(A);
            CHECK(Inst[A].State == PQCHS_STATE_I_WAIT_M4, "%s: A waits out T_A (%u)", name, (unsigned)Inst[A].State);
            /* installed and waiting for M4: K_auth has left the handshake state, K_kc_r is still needed */
            CHECK(Residue((const uint8*)&Inst[A], (uint32)sizeof(Inst[A]), &Okm_Last()[0], 32U) == TRUE,
                  "%s: A holds K_kc_r until the acknowledgement or T_A", name);
            CHECK(InStateOrCsm(&Okm_Last()[64], 64U) == FALSE, "%s: K_auth left in the handshake state after installation", name);
            CHECK(InStateOrCsm(&Okm_Last()[32], 32U) == FALSE, "%s: K_kc_i left after mac_A", name);
            /* A runs one more handshake after T_A */
            NowMs += PQCHS_T_A_MS;
            Cycles(5U);
            EXPECT_ROW(A, PQCHS_RESULT_TIMEOUT);
            EXPECT_ROW(A, PQCHS_RESULT_OK);
            CHECK((Inst[A].InstallCount == (InstallsBefore[A] + 2U)) && (Inst[B].InstallCount == (InstallsBefore[B] + 2U)),
                  "%s: one more handshake on both sides", name);
        }
        CHECK(memcmp(Inst[A].Sid, Inst[B].Sid, PQCHS_SID_BYTES) == 0, "%s: same session after the recovery", name);
        CHECK(memcmp(Inst[B].Sid, sidSession1, PQCHS_SID_BYTES) != 0, "%s: a new session", name);
        CHECK(Session_Works() == TRUE, "%s: delivery resumes", name);
        CHECK((Inst[A].State == PQCHS_STATE_IDLE) && (Inst[B].State == PQCHS_STATE_IDLE), "%s: at rest", name);
        Erasure_Check(name);
        {
            PqcHs_AttemptInfoType row;
            while (Row(A, &row) == TRUE) { }
            while (Row(B, &row) == TRUE) { }
        }
    }
    (void)printf("H7 negative tests 11 and 12\n");
}

/************************************************* H8 ****************************************************/

static void Test_H8_LocalFailures(void)
{
    uint32 ev;
    uint64 installedNs = 0U;

    static uint8 firstM1[PQCHS_M1_BYTES];

    /* SoAd does not take M1 (no connection, and it cannot be opened yet): no key pair, no row, nothing
     * changes, and the request is repeated in every cycle until SoAd takes it */
    Start();
    ev = EvCount;
    Wire_Down();
    Reachable = FALSE;
    Cycles(3U);
    CHECK(Ev_Count(A, ev, EV_TX_M1) == 3U, "M1 requested in every cycle (%u)", (unsigned)Ev_Count(A, ev, EV_TX_M1));
    CHECK((Ev_Count(A, ev, EV_KEYGEN) == 0U) && (Inst[A].State == PQCHS_STATE_IDLE) && (Oracle_Unchanged(A) == TRUE),
          "a request that is not taken costs no key pair and starts no attempt");
    EXPECT_NO_ROW(A);
    Reachable = TRUE;
    Cycles(4U);
    CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE) && (Session_Works() == TRUE),
          "the handshake runs as soon as SoAd takes M1");
    Cycles(2U);
    CHECK((Ev_Count(A, ev, EV_KEYGEN) == 1U) && (Ev_Count(A, ev, EV_TX_M1) == 4U), "one key pair, and no M1 after the one SoAd took");
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    EXPECT_NO_ROW(A);
    EXPECT_NO_ROW(B);
    Erasure_Check("M1 not taken until the connection opens");

    /* the key generation fails after SoAd took the request: PqcHs gives the transmission up, SoAd ends
     * it and the connection when it asks for the bytes, and A tries again at T_A */
    Start();
    ev = EvCount;
    FailCustomJob = CSM_JOBID_KEM_KEYGEN;
    Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    CHECK((Inst[A].State == PQCHS_STATE_I_RETRY) && (TxQueued == 1U), "no attempt; SoAd still holds the request");
    ExpectTxAbort = TRUE;
    Pump();
    CHECK((ExpectTxAbort == FALSE) && (Connected == FALSE), "SoAd got no bytes and closed the connection");
    Cycles(2U);
    CHECK((Ev_Count(A, ev, EV_TX_M1) == 1U) && (Inst[B].State == PQCHS_STATE_IDLE), "nothing reached B, no M1 before T_A");
    EXPECT_NO_ROW(A);
    EXPECT_NO_ROW(B);
    CHECK((Oracle_Unchanged(A) == TRUE) && (Session_Works() == TRUE), "session untouched");
    Erasure_Check("key generation failed");
    Settle("H8 key generation failed");

    /* the connection ends while M1 is in transmission: SoAd will not finish it */
    Start();
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_WAIT_M2) && (TxQueued == 1U), "M1 in transmission");
    Wire_Down();
    Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    CHECK(Inst[A].State == PQCHS_STATE_I_RETRY, "the attempt ends with its connection (%u)", (unsigned)Inst[A].State);
    Wire_Up();
    Cycles(4U);
    CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE) && (Session_Works() == TRUE),
          "a handshake on the new connection, not blocked by the lost transmission");
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    Erasure_Check("connection lost during M1");

    /* the connection is replaced after M2 has arrived completely and before A has looked at it: that M2
     * belongs to the handshake B wiped with the old connection and must not be answered with an M3 */
    Start();
    ev = EvCount;
    Step(A);
    Pump();
    Step(B);
    Pump();
    CHECK((Inst[A].RxReady == TRUE) && (Inst[A].State == PQCHS_STATE_I_WAIT_M2), "M2 received, not processed yet");
    Wire_Down();
    Wire_Up();
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    EXPECT_NO_ROW(A);       /* the attempt ended; the M2 itself is dropped with the connection, unseen */
    CHECK((Ev_Count(A, ev, EV_VERIFY) == 0U) && (Ev_Count(A, ev, EV_DECAPS) == 0U) && (Ev_Count(A, ev, EV_HOLD_ON) == 0U) &&
          (Ev_Count(A, ev, EV_TX_M3) == 0U), "the M2 of the old connection is not processed");
    CHECK((Oracle_Unchanged(A) == TRUE) && (Session_Works() == TRUE), "nothing installed, the previous session works");
    CHECK((Ev_Count(A, ev, EV_TX_M1) == 2U) && (Inst[A].State == PQCHS_STATE_I_WAIT_M2), "the new connection gets its own handshake");
    Settle("H8 connection replaced behind M2");

    /* the connection ends while M3 waits for the flush: M3 must not go out on the next connection */
    Start();
    ev = EvCount;
    TxFlushed = FALSE;
    Cycles(2U);
    CHECK((Inst[A].State == PQCHS_STATE_I_CUTOVER) && (Inst[B].State == PQCHS_STATE_R_PENDING), "A in cut-over, B pending");
    Wire_Down();
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    TxFlushed = TRUE;
    Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    CHECK((Ev_Count(A, ev, EV_TX_M3) == 0U) && (Oracle_Unchanged(A) == TRUE), "no M3 and no installation after the connection ended");
    CHECK((Ev_Count(A, ev, EV_HOLD_ON) == 1U) && (Ev_Count(A, ev, EV_HOLD_OFF) == 1U), "transmission released");
    CHECK(Session_Works() == TRUE, "the previous session still works");
    Erasure_Check("connection lost during the cut-over");
    Wire_Up();
    NowMs += SOAD_PQC_HS_MIN_INTERVAL_MS;
    Cycles(4U);
    CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE) && (Session_Works() == TRUE),
          "one handshake on the new connection");
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    EXPECT_ROW(B, PQCHS_RESULT_OK);

    /* "initiate handshake now" while an attempt is running: the attempt is not restarted and M1, still
     * with SoAd, does not change; the request is served when the attempt has ended */
    Start();
    ev = EvCount;
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_WAIT_M2) && (TxQueued == 1U), "M1 in transmission");
    (void)memcpy(firstM1, Inst[A].M1, sizeof(firstM1));
    CHECK(PqcHs_Core_Initiate(&Inst[A]) == E_OK, "second request");
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_WAIT_M2) && (Ev_Count(A, ev, EV_TX_M1) == 1U) && (Ev_Count(A, ev, EV_KEYGEN) == 1U),
          "a request during an attempt does not restart it");
    EXPECT_NO_ROW(A);
    Pump();
    CHECK(memcmp(Last[1], firstM1, PQCHS_M1_BYTES) == 0, "the M1 that left is the one that was built");
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_WAIT_M2) && (Ev_Count(A, ev, EV_TX_M1) == 1U), "nor when its M1 has left");
    Step(B);
    Pump();
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_SEND_M3) && (Ev_Count(A, ev, EV_TX_M1) == 1U), "the request waits while M3 is on its way");
    Pump();
    Step(B);
    Pump();
    Step(A);
    CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE) && (Session_Works() == TRUE), "the first attempt completes");
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    CHECK((Ev_Count(A, ev, EV_TX_M1) == 2U) && (Inst[A].State == PQCHS_STATE_I_WAIT_M2), "then the second request is served");
    Settle("H8 request during an attempt");

    /* the same request while A waits for the flush (cut-over): it changes nothing there, M3 goes out,
     * the attempt completes, and only then the request is served */
    Start();
    ev = EvCount;
    TxFlushed = FALSE;
    Cycles(2U);
    CHECK(Inst[A].State == PQCHS_STATE_I_CUTOVER, "A in cut-over, waiting for the flush");
    CHECK(PqcHs_Core_Initiate(&Inst[A]) == E_OK, "request during the cut-over");
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_CUTOVER) && (Ev_Count(A, ev, EV_TX_M1) == 1U) && (Ev_Count(A, ev, EV_TX_M3) == 0U) &&
          (Ev_Count(A, ev, EV_HOLD_OFF) == 0U) && (Ev_Count(A, ev, EV_KEYGEN) == 1U), "a request during the cut-over changes nothing");
    EXPECT_NO_ROW(A);
    TxFlushed = TRUE;
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_SEND_M3) && (Ev_Count(A, ev, EV_TX_M1) == 1U), "M3 goes out; the request still waits");
    Pump();
    Step(B);
    Pump();
    Step(A);
    CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE) && (Session_Works() == TRUE), "the attempt of the cut-over completes");
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    CHECK((Ev_Count(A, ev, EV_TX_M1) == 2U) && (Inst[A].State == PQCHS_STATE_I_WAIT_M2), "then the request is served");
    Settle("H8 request during the cut-over");

    /* T_A passes while M1 is still with SoAd: the next attempt does not start, and builds nothing, until
     * that transmission has ended; the M1 that leaves is unchanged */
    Start();
    ev = EvCount;
    Step(A);
    (void)memcpy(firstM1, Inst[A].M1, sizeof(firstM1));
    NowMs += PQCHS_T_A_MS;
    Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_TIMEOUT);
    CHECK((Ev_Count(A, ev, EV_KEYGEN) == 1U) && (memcmp(Inst[A].M1, firstM1, PQCHS_M1_BYTES) == 0),
          "no key pair and no change of M1 while it is in transmission");
    Pump();
    CHECK(memcmp(Last[1], firstM1, PQCHS_M1_BYTES) == 0, "the M1 that left is the one that was built");
    Step(B);
    Step(A);
    CHECK((Ev_Count(A, ev, EV_KEYGEN) == 2U) && (Inst[A].State == PQCHS_STATE_I_WAIT_M2), "the next attempt starts when the transmission has ended");
    Cycles(2U);
    Settle("H8 timeout with M1 in transmission");

    /* B: an M1 while its acknowledgement is still with SoAd is not served, and the M4 that leaves is intact */
    Start();
    ev = EvCount;
    Step(A);
    Pump();
    Step(B);
    Pump();
    Step(A);
    Pump();
    Step(B);
    CHECK((Inst[B].State == PQCHS_STATE_IDLE) && (TxQueued == 1U) && (TxQueue[0] == TXID_M4), "B installed, M4 in transmission");
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    NowMs += SOAD_PQC_HS_MIN_INTERVAL_MS;
    Craft_M1(firstM1);
    (void)Deliver(1U, firstM1, PQCHS_M1_BYTES); Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    CHECK((Ev_Count(B, ev, EV_ENCAPS) == 1U) && (Inst[B].State == PQCHS_STATE_IDLE), "no encapsulation for an M1 while M4 is in transmission");
    Pump();
    Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    CHECK((Inst[A].State == PQCHS_STATE_IDLE) && (Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE) &&
          (Session_Works() == TRUE), "the acknowledgement arrived intact");
    Erasure_Check("M1 while M4 is in transmission");

    /* M3 is not confirmed: A must not install, and gives the transmission back */
    Start();
    ev = EvCount;
    FailConfirm = TXID_M3;
    Cycles(3U);
    FailConfirm = 0xFFFFU;
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    CHECK(Connected == FALSE, "the connection ended with the failed transmission");
    CHECK((Oracle_Unchanged(A) == TRUE) && (Oracle_Unchanged(B) == TRUE), "nothing installed when M3 did not go out");
    CHECK((Ev_Count(A, ev, EV_HOLD_ON) == 1U) && (Ev_Count(A, ev, EV_HOLD_OFF) == 1U), "transmission released again");
    CHECK(Session_Works() == TRUE, "previous session works");
    Settle("H8 M3 not confirmed");

    /* the flush never comes: A gives up T_flush after it accepted M2 and releases the transmission; the
     * next handshake is due T_A after the M1 */
    Start();
    ev = EvCount;
    TxFlushed = FALSE;
    Cycles(3U);
    CHECK(Inst[A].State == PQCHS_STATE_I_CUTOVER, "A waits for the flush");
    NowMs += (PQCHS_T_FLUSH_MS - 1U);
    Step(A);
    CHECK(Inst[A].State == PQCHS_STATE_I_CUTOVER, "A waits until T_flush");
    EXPECT_NO_ROW(A);
    NowMs += 1U;
    Step(A);
    TxFlushed = TRUE;
    EXPECT_ROW(A, PQCHS_RESULT_TIMEOUT);
    CHECK((Ev_Count(A, ev, EV_HOLD_ON) == 1U) && (Ev_Count(A, ev, EV_HOLD_OFF) == 1U), "transmission released at the timeout");
    CHECK((Ev_Count(A, ev, EV_TX_M3) == 0U) && (Oracle_Unchanged(A) == TRUE), "no M3, nothing installed");
    NowMs += ((PQCHS_T_A_MS - PQCHS_T_FLUSH_MS) - 1U);
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_RETRY) && (Ev_Count(A, ev, EV_TX_M1) == 1U), "no new M1 before T_A after the first");
    NowMs += 1U;
    Cycles(5U);     /* the handshake that is due now completes */
    CHECK((Ev_Count(A, ev, EV_TX_M1) == 2U) && (Oracle_NewSession(A) == TRUE) && (Session_Works() == TRUE),
          "A recovered with a new handshake T_A after its first M1");
    Settle("H8 no flush");

    /* the wait for M2 ends when M2 is accepted: accepted just before T_A, the attempt lives on and the
     * bound on the flush counts from the acceptance */
    Start();
    ev = EvCount;
    Step(A);
    Pump();
    Step(B);
    Pump();
    TxFlushed = FALSE;
    NowMs += (PQCHS_T_A_MS - 1U);
    Step(A);
    CHECK(Inst[A].State == PQCHS_STATE_I_CUTOVER, "M2 accepted one millisecond before T_A");
    NowMs += 1U;
    Step(A);
    CHECK(Inst[A].State == PQCHS_STATE_I_CUTOVER, "T_A after M1 does not end an attempt whose M2 was accepted");
    EXPECT_NO_ROW(A);
    NowMs += (PQCHS_T_FLUSH_MS - 2U);
    Step(A);
    CHECK(Inst[A].State == PQCHS_STATE_I_CUTOVER, "one millisecond before T_flush after the acceptance");
    NowMs += 1U;
    Step(A);
    TxFlushed = TRUE;
    EXPECT_ROW(A, PQCHS_RESULT_TIMEOUT);
    CHECK((Ev_Count(A, ev, EV_HOLD_OFF) == 1U) && (Ev_Count(A, ev, EV_TX_M3) == 0U) && (Oracle_Unchanged(A) == TRUE),
          "T_flush after the acceptance: released, no M3, nothing installed");
    CHECK(Ev_Count(A, ev, EV_TX_M1) == 2U, "T_A after M1 has passed: the next handshake starts at once");
    Settle("H8 flush bound from the acceptance of M2");

    /* while M3 is with SoAd no timer runs: the result of the transmission decides */
    Start();
    ev = EvCount;
    Step(A);
    Pump();
    Step(B);
    Pump();
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_SEND_M3) && (TxQueued == 1U), "M3 with SoAd");
    NowMs += (PQCHS_T_A_MS + PQCHS_T_FLUSH_MS);
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_SEND_M3) && (Ev_Count(A, ev, EV_HOLD_OFF) == 0U) && (Ev_Count(A, ev, EV_TX_M1) == 1U),
          "no timeout while M3 is in transmission");
    EXPECT_NO_ROW(A);
    Pump();
    Step(A);
    CHECK((Oracle_NewSession(A) == TRUE) && (Inst[A].State == PQCHS_STATE_I_WAIT_M4), "A installs when M3 is confirmed");
    Step(B);        /* B had dropped the handshake at T_pend: the late M3 matches nothing */
    EXPECT_ROW(B, PQCHS_RESULT_TIMEOUT);
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    CHECK((Oracle_Unchanged(B) == TRUE) && (GateClosed == FALSE), "B installed nothing and reopened the stream");
    Settle("H8 M3 confirmed late");

    /* T_A for the acknowledgement counts from M3, not from M1 */
    Start();
    ev = EvCount;
    H7_Case = 5U;       /* M4 is lost */
    Hook = Hook_M3M4;
    installedNs = Test_NowNs();
    Step(A);
    Pump();
    Step(B);
    Pump();
    NowMs += 700U;
    Step(A);
    Pump();
    Step(B);
    Pump();
    Step(A);
    installedNs = Test_NowNs() - installedNs;
    Hook = NULL;
    CHECK((Inst[A].State == PQCHS_STATE_I_WAIT_M4) && (Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE),
          "both installed, M4 lost");
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    NowMs += (PQCHS_T_A_MS - 700U);
    Step(A);
    CHECK(Inst[A].State == PQCHS_STATE_I_WAIT_M4, "T_A after M1 does not end the wait for M4");
    NowMs += 699U;
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_WAIT_M4) && (Ev_Count(A, ev, EV_TX_M1) == 1U), "one millisecond before T_A after M3");
    EXPECT_NO_ROW(A);
    NowMs += 1U;
    {
        /* the total of an attempt that installed ends at the installation: real time that passes
         * while A waits for the acknowledgement is not part of it */
        struct timespec pause = { 0, 30000000L };
        PqcHs_AttemptInfoType row;

        (void)nanosleep(&pause, NULL);
        Step(A);
        CHECK((Row(A, &row) == TRUE) && (row.Result == PQCHS_RESULT_TIMEOUT), "row for the missing acknowledgement");
        CHECK((row.TotalNs > 0U) && (row.TotalNs <= installedNs), "total %llu ns, attempt start to installation at most %llu ns",
              (unsigned long long)row.TotalNs, (unsigned long long)installedNs);
    }
    CHECK(Ev_Count(A, ev, EV_TX_M1) == 2U, "T_A after M3: a new handshake");
    Cycles(4U);
    CHECK((Inst[A].InstallCount == (InstallsBefore[A] + 2U)) && (Inst[B].InstallCount == (InstallsBefore[B] + 2U)) &&
          (Session_Works() == TRUE), "one more handshake on both sides");
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    Erasure_Check("M4 lost, T_A from M3");

    /* a request while A waits for the acknowledgement is served at once; the row of the attempt it
     * ends counts the bytes of that attempt only */
    Start();
    ev = EvCount;
    H7_Case = 5U;
    Hook = Hook_M3M4;
    Cycles(3U);
    Hook = NULL;
    CHECK((Inst[A].State == PQCHS_STATE_I_WAIT_M4) && (Oracle_NewSession(A) == TRUE), "A installed and waits for M4");
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    CHECK(PqcHs_Core_Initiate(&Inst[A]) == E_OK, "request during the wait for M4");
    Step(A);
    {
        PqcHs_AttemptInfoType row;
        CHECK((Row(A, &row) == TRUE) && (row.Result == PQCHS_RESULT_STATE), "row of the attempt the request ended");
        CHECK((row.BytesTx == (1217U + 8U + 3342U + 8U)) && (row.BytesRx == (4462U + 8U)), "its bytes: M1 and M3 out, M2 in (%u / %u)",
              (unsigned)row.BytesTx, (unsigned)row.BytesRx);
    }
    CHECK((Inst[A].State == PQCHS_STATE_I_WAIT_M2) && (Ev_Count(A, ev, EV_TX_M1) == 2U), "the new handshake has started");
    Settle("H8 request during the wait for M4");

    /* B: the connection ends while B waits for the drain behind the closed gate. The handshake goes
     * with the connection, and no release is owed for a stream that is gone (the wire checks that). */
    Start();
    RxDrained = FALSE;
    Cycles(3U);
    CHECK((Inst[B].State == PQCHS_STATE_R_INSTALL) && (GateClosed == TRUE), "B waits for the drain behind the closed gate");
    Wire_Down();
    RxDrained = TRUE;
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    CHECK((Inst[B].State == PQCHS_STATE_IDLE) && (Oracle_Unchanged(B) == TRUE) && (GateClosed == FALSE),
          "B dropped the handshake with its connection");
    Step(B);
    CHECK(Oracle_Unchanged(B) == TRUE, "a drain that finishes later installs nothing");
    Settle("H8 connection ended during the drain");

    /* B: the drain does not finish before T_pend. The handshake is dropped and the stream reopened;
     * A, which has switched, comes back with its next handshake. */
    Start();
    ev = EvCount;
    RxDrained = FALSE;
    Cycles(3U);
    CHECK((Inst[B].State == PQCHS_STATE_R_INSTALL) && (GateClosed == TRUE), "B waits for the drain behind the closed gate");
    NowMs += (PQCHS_T_PEND_MS - 1U);
    Step(B);
    CHECK((Inst[B].State == PQCHS_STATE_R_INSTALL) && (GateClosed == TRUE), "until T_pend");
    NowMs += 1U;
    Step(B);
    RxDrained = TRUE;
    EXPECT_ROW(B, PQCHS_RESULT_TIMEOUT);
    CHECK(GateClosed == FALSE, "the stream is reopened when the handshake is dropped");
    CHECK((Oracle_Unchanged(B) == TRUE) && (Ev_Count(B, ev, EV_TX_M4) == 0U) && (Inst[B].State == PQCHS_STATE_IDLE),
          "B installed nothing and sent no M4");
    Step(B);
    CHECK((Oracle_Unchanged(B) == TRUE) && (Inst[B].State == PQCHS_STATE_IDLE), "a drain that finishes later installs nothing");
    Settle("H8 drain not finished before T_pend");

    (void)printf("H8 local failures\n");
}

/************************************************* H11 ***************************************************/

/* A PDU as A authenticates it now: signature and MAC, kept for a later replay */
static uint8 OldPdu[14] = { 0x00U, 0x02U, 9U, 9U, 9U, 9U, 9U, 9U, 9U, 9U, 0U, 0U, 0U, 7U };
static uint8 OldSig[PQC_MLDSA_SIGNATURE_BYTES];
static uint8 OldTag[16];

static void Record_Pdu(void)
{
    uint32 sigLen = sizeof(OldSig);
    uint32 tagLen = sizeof(OldTag);

    ActAs(A);
    CHECK(__real_Csm_SignatureGenerate((uint32)CSM_JOBID, CRYPTO_OPERATIONMODE_SINGLECALL, OldPdu, sizeof(OldPdu),
                                       OldSig, &sigLen) == E_OK, "record: signature");
    CHECK(__real_Csm_MacGenerate(A_JOB_GEN, CRYPTO_OPERATIONMODE_SINGLECALL, OldPdu, sizeof(OldPdu), OldTag, &tagLen) == E_OK,
          "record: MAC");
}

/* TRUE when B accepts the recorded PDU in either variant */
static boolean Replay_Accepted(void)
{
    Crypto_VerifyResultType ver = CRYPTO_E_VER_NOT_OK;
    boolean accepted = FALSE;

    if ((__real_Csm_SignatureVerify(CSM_JOBID_VERIFY_PEER_BASE + PEER_OF_B, CRYPTO_OPERATIONMODE_SINGLECALL, OldPdu,
                                    sizeof(OldPdu), OldSig, PQC_MLDSA_SIGNATURE_BYTES, &ver) == E_OK) && (ver == CRYPTO_E_VER_OK))
    {
        accepted = TRUE;
    }
    ver = CRYPTO_E_VER_NOT_OK;
    if ((__real_Csm_MacVerify(B_JOB_VER, CRYPTO_OPERATIONMODE_SINGLECALL, OldPdu, sizeof(OldPdu), OldTag, 128U, &ver) == E_OK) &&
        (ver == CRYPTO_E_VER_OK))
    {
        accepted = TRUE;
    }
    return accepted;
}

/* What a restart leaves of one side: an empty handshake instance, the no-session signature context,
 * no MAC key */
static void Restart(uint8 Side)
{
    uint8 noSession[CSM_PDU_SIG_CTX_BYTES];
    uint32 sessionKey = CSM_KEYID_SESSION_BASE + ((Side == A) ? PEER_OF_A : PEER_OF_B);
    static const uint8 zero[32] = { 0U };

    (void)memset(noSession, 0, sizeof(noSession));
    (void)memcpy(noSession, PQC_PDU_SIG_CTX_LABEL, PQC_PDU_SIG_CTX_LABEL_BYTES);
    CHECK(PqcHs_Core_Init(&Inst[Side], &Cfg[Side], &Timers) == E_OK, "restart: instance");
    CHECK(__real_Csm_KeyElementSet(sessionKey, CSM_KE_VENDOR_PDU_SIG_CTX, noSession, sizeof(noSession)) == E_OK, "restart: context");
    CHECK(__real_Csm_KeySetValid(sessionKey) == E_OK, "restart: context valid");
    /* writing a key element leaves the key invalid: no MAC key after the restart */
    CHECK(__real_Csm_KeyElementSet((Side == A) ? A_KEY_TX : B_KEY_TX, CRYPTO_KE_MAC_KEY, zero, sizeof(zero)) == E_OK, "restart: send key");
    CHECK(__real_Csm_KeyElementSet((Side == A) ? A_KEY_RX : B_KEY_RX, CRYPTO_KE_MAC_KEY, zero, sizeof(zero)) == E_OK, "restart: receive key");
}

static void Test_H11_Restart(void)
{
    static const uint8 sides[2] = { B, A };
    uint32 i;

    for (i = 0U; i < 2U; i++)
    {
        uint8 side = sides[i];
        const char* name = (side == B) ? "restart of B" : "restart of A";
        uint32 installsOther = Inst[(side == A) ? B : A].InstallCount;

        CHECK(Session_Works() == TRUE, "%s: a session before the restart", name);
        Record_Pdu();
        CHECK(Replay_Accepted() == TRUE, "%s: the recorded PDU is valid in its own session", name);

        Wire_Down();
        Restart(side);
        CHECK(Inst[side].Established == FALSE, "%s: no session after the restart", name);
        if (side == B)
        {
            /* the restarted receiver has no session: nothing recorded earlier authenticates */
            CHECK(Replay_Accepted() == FALSE, "%s: recorded PDU accepted before the handshake", name);
        }
        else
        {
            /* the receiver did not restart and still holds the old session: until the new handshake a
             * replay is stopped by its freshness counter (not part of this test), not by the session */
            CHECK(Replay_Accepted() == TRUE, "%s: the receiver changed its session without a handshake", name);
        }
        CHECK(Session_Works() == FALSE, "%s: no traffic before the handshake", name);

        /* one handshake: after its own restart A is asked for it at start-up and opens the connection
         * with M1; after a restart of B the connection comes up again under A's traffic */
        NowMs += SOAD_PQC_HS_MIN_INTERVAL_MS;
        if (side == A)
        {
            CHECK(PqcHs_Core_Initiate(&Inst[A]) == E_OK, "%s: handshake requested at start-up", name);
        }
        else
        {
            Wire_Up();
        }
        Cycles(4U);
        CHECK((Inst[side].InstallCount == 1U) && (Inst[(side == A) ? B : A].InstallCount == (installsOther + 1U)),
              "%s: exactly one handshake", name);
        CHECK((Inst[A].Established == TRUE) && (Inst[B].Established == TRUE) &&
              (memcmp(Inst[A].Sid, Inst[B].Sid, PQCHS_SID_BYTES) == 0), "%s: both sides on the new session", name);
        CHECK(Session_Works() == TRUE, "%s: traffic resumes", name);
        CHECK(Replay_Accepted() == FALSE, "%s: recorded PDU accepted after the handshake", name);
        EXPECT_ROW(A, PQCHS_RESULT_OK);
        EXPECT_ROW(B, PQCHS_RESULT_OK);
        EXPECT_NO_ROW(A);
        EXPECT_NO_ROW(B);
        Erasure_Check(name);
    }
    (void)printf("H11 restart of one side\n");
}

/************************************************* H12 ***************************************************/

/* SoAd rule: between two PDUs of one id SoAd asks with length 0 how much room there is */
static void Test_H12_RoomQuery(void)
{
    static const uint32 lengths[2][2] = { { PQCHS_M2_BYTES, PQCHS_M4_BYTES }, { PQCHS_M1_BYTES, PQCHS_M3_BYTES } };
    static uint8 m1[2][PQCHS_M1_BYTES];
    static PqcHs_InstanceType blank;
    PduLengthType room = 0U;
    PduInfoType query = { NULL, NULL, 0U };
    uint8 side;
    uint8 msg;

    /* at rest every message id answers with the size StartOfReception announces for it */
    for (side = A; side <= B; side++)
    {
        for (msg = 0U; msg < 2U; msg++)
        {
            PduLengthType announced = 0U;
            room = 0U;
            CHECK((PqcHs_Core_CopyRxData(&Inst[side], msg, &query, &room) == BUFREQ_OK) && (room == lengths[side][msg]),
                  "side %u message %u: room %u at rest", (unsigned)side, (unsigned)msg, (unsigned)room);
            CHECK((PqcHs_Core_StartOfReception(&Inst[side], msg, lengths[side][msg], &announced) == BUFREQ_OK) &&
                  (announced == room), "side %u message %u: StartOfReception announces %u", (unsigned)side, (unsigned)msg, (unsigned)announced);
            PqcHs_Core_RxIndication(&Inst[side], msg, E_NOT_OK);
            CHECK((PqcHs_Core_CopyRxData(&Inst[side], msg, &query, &room) == BUFREQ_OK) && (room == announced),
                  "side %u message %u: the room is back after an aborted reception", (unsigned)side, (unsigned)msg);
        }
    }
    CHECK(PqcHs_Core_CopyRxData(&Inst[B], 2U, &query, &room) == BUFREQ_E_NOT_OK, "no third message id");
    CHECK(PqcHs_Core_CopyRxData(&blank, 0U, &query, &room) == BUFREQ_E_NOT_OK, "an instance that was never initialised has no room");
    {
        PqcHs_AttemptInfoType row;
        while (Row(A, &row) == TRUE) { }
        while (Row(B, &row) == TRUE) { }
    }

    /* a message that waits for the main function keeps the buffer: the next PDU of either id waits in
     * SoAd and is taken once the first has been processed */
    Oracle_Mark();
    NowMs += SOAD_PQC_HS_MIN_INTERVAL_MS;
    Craft_M1(m1[0]);
    Craft_M1(m1[1]);
    CHECK(Deliver(1U, m1[0], PQCHS_M1_BYTES) == BUFREQ_OK, "first M1 taken");
    CHECK(Deliver(1U, m1[1], PQCHS_M1_BYTES) == BUFREQ_E_BUSY, "the second M1 waits while the first is unprocessed");
    CHECK((PqcHs_Core_CopyRxData(&Inst[B], 1U, &query, &room) == BUFREQ_OK) && (room == 0U), "no room for an M3 either");
    CHECK(memcmp(&Inst[B].Rx[33], &m1[0][33], PQCHS_EK_BYTES) == 0, "the waiting message is untouched");
    Step(B);
    CHECK(Inst[B].State == PQCHS_STATE_R_PENDING, "the first M1 is answered");
    CHECK(Deliver(1U, m1[1], PQCHS_M1_BYTES) == BUFREQ_OK, "the second M1 is taken after the first was processed");
    Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_STATE);      /* a second M1 while one is pending */
    Pump();                                 /* the M2 for the first M1 matches nothing at A */
    Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    NowMs += PQCHS_T_PEND_MS;
    Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_TIMEOUT);
    CHECK((Oracle_Unchanged(A) == TRUE) && (Oracle_Unchanged(B) == TRUE) && (Session_Works() == TRUE), "session untouched");
    Erasure_Check("room query");
    (void)printf("H12 room query between two PDUs of one id\n");
}

/************************************************* H13 ***************************************************/

static void Test_H13_Hardening(void)
{
    /* a reception attempted while A is verifying M2 is refused, and the handshake completes on the
     * message that was checked */
    Start();
    Step(A);
    Pump();
    Step(B);
    Pump();
    CHECK(Inst[A].RxReady == TRUE, "M2 waits for the main function");
    ProbeRxLock = TRUE;
    ProbeStart = BUFREQ_OK;
    ProbeRoom = 9999U;
    Step(A);
    CHECK(ProbeRxLock == FALSE, "the signature of M2 was verified");
    CHECK((ProbeStart == BUFREQ_E_NOT_OK) && (ProbeRoom == 0U), "no reception and no room while the message is being processed (%u, %u)",
          (unsigned)ProbeStart, (unsigned)ProbeRoom);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);      /* the refused StartOfReception */
    CHECK(Inst[A].RxReady == FALSE, "the buffer is free again after the handler");
    Cycles(3U);
    CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE) && (Session_Works() == TRUE), "the handshake completes");
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    Erasure_Check("reception attempted during processing");

    /* a key installation that fails at any of its six calls tears the session down: no K_auth key and
     * no PDU signature context is left valid, and neither derived key stays in the slots */
    {
        static const char* const calls[6] = { "send key written", "receive key written", "send key set valid",
                                              "receive key set valid", "context written", "context set valid" };
        static uint8 sig[PQC_MLDSA_SIGNATURE_BYTES];
        static const uint8 noSid[PQCHS_SID_BYTES] = { 0U };
        uint8 pdu[4] = { 1U, 2U, 3U, 4U };
        uint32 i;

        for (i = 0U; i < 7U; i++)
        {
            /* cases 0 to 5 on the initiator, case 6 on the responder (its send key cannot be set valid) */
            uint8 side = (i < 6U) ? A : B;
            const char* name = (i < 6U) ? calls[i] : "responder";
            uint32 sessionKey = CSM_KEYID_SESSION_BASE + ((side == A) ? PEER_OF_A : PEER_OF_B);
            uint32 sigLen = sizeof(sig);
            Crypto_VerifyResultType ver = CRYPTO_E_VER_OK;
            uint32 ev;

            Start();
            ev = EvCount;
            FailKeyElementSetAfter = 0U;
            switch (i)
            {
                case 0U: FailKeyElementSet = A_KEY_TX; break;
                case 1U: FailKeyElementSet = A_KEY_RX; break;
                case 2U: FailKeySetValid = A_KEY_TX; break;
                case 3U: FailKeySetValid = A_KEY_RX; break;
                case 4U: FailKeyElementSet = sessionKey; break;
                case 5U: FailKeySetValid = sessionKey; break;
                default: FailKeySetValid = B_KEY_TX; break;
            }
            Cycles(4U);
            CHECK((FailKeyElementSet == 0U) && (FailKeySetValid == 0U), "%s: the failure was injected", name);
            EXPECT_ROW(side, PQCHS_RESULT_STATE);
            CHECK((Inst[side].Established == FALSE) && (Inst[side].InstallCount == InstallsBefore[side]),
                  "%s: established cleared, the failed installation not counted", name);
            CHECK(memcmp(Inst[side].Sid, noSid, PQCHS_SID_BYTES) == 0, "%s: a session id is still shown", name);
            CHECK((Mac_NoKey((side == A) ? A_JOB_GEN : B_JOB_GEN) == TRUE) && (Mac_RxNoKey((side == A) ? A_JOB_VER : B_JOB_VER) == TRUE),
                  "%s: a K_auth key of the torn-down side is still valid", name);
            CHECK(InMacSlotsOf(side, &Okm_Last()[64], 64U) == FALSE, "%s: a derived K_auth is left in the slots", name);
            if (side == A)
            {
                ActAs(A);
                CHECK(__real_Csm_SignatureGenerate((uint32)CSM_JOBID, CRYPTO_OPERATIONMODE_SINGLECALL, pdu, sizeof(pdu), sig, &sigLen)
                      == CRYPTO_E_KEY_NOT_VALID, "%s: the PDU signature job still has a context", name);
            }
            else
            {
                CHECK(__real_Csm_SignatureVerify(CSM_JOBID_VERIFY_PEER_BASE + PEER_OF_B, CRYPTO_OPERATIONMODE_SINGLECALL, pdu,
                      sizeof(pdu), sig, PQC_MLDSA_SIGNATURE_BYTES, &ver) == CRYPTO_E_KEY_NOT_VALID,
                      "%s: the PDU verification job still has a context", name);
            }
            CHECK(Session_Works() == FALSE, "%s: PDUs are still accepted", name);
            if (side == B)
            {
                CHECK((Ev_Count(B, ev, EV_TX_M4) == 0U) && (GateClosed == FALSE) && (Inst[B].State == PQCHS_STATE_IDLE),
                      "responder: no M4 after a failed installation, stream reopened");
                CHECK(Oracle_NewSession(A) == TRUE, "responder: the initiator has switched and waits for M4");
            }
            else
            {
                Erasure_Check(name);
            }
            Settle(name);
            CHECK((Inst[A].Established == TRUE) && (Inst[B].Established == TRUE), "%s: established again after the next handshake", name);
        }
    }

    /* a confirmation whose key could not be erased from the slot does not count */
    {
        uint32 ev;

        /* A, mac_B: right tag, the erasing write of the slot fails -> the attempt ends, no M3 */
        Start();
        ev = EvCount;
        FailKeyElementSet = A_KEY_KC;
        FailKeyElementSetAfter = 1U;        /* the first write loads K_kc_r, the second erases it */
        Cycles(3U);
        CHECK(FailKeyElementSet == 0U, "A: the failure was injected");
        EXPECT_ROW(A, PQCHS_RESULT_STATE);
        CHECK((Ev_Count(A, ev, EV_TX_M3) == 0U) && (Ev_Count(A, ev, EV_HOLD_ON) == 0U) && (Oracle_Unchanged(A) == TRUE) &&
              (Inst[A].State == PQCHS_STATE_I_RETRY), "A: no M3 after a confirmation whose key was not erased");
        Settle("H13 erase of the confirmation key failed at A");

        /* B, mac_ack: the tag is made, the erasing write fails -> no M4, the row is not OK */
        Start();
        ev = EvCount;
        FailKeyElementSet = B_KEY_KC;
        FailKeyElementSetAfter = 5U;        /* mac_B, mac_A and mac_ack: load and erase each */
        Cycles(3U);
        CHECK(FailKeyElementSet == 0U, "B: the failure was injected");
        EXPECT_ROW(B, PQCHS_RESULT_STATE);
        CHECK((Ev_Count(B, ev, EV_TX_M4) == 0U) && (Oracle_NewSession(B) == TRUE) && (GateClosed == FALSE),
              "B: installed, no acknowledgement, stream reopened");
        Settle("H13 erase of the confirmation key failed at B");

        /* the job that erases dk and ss fails at the end of a good handshake: the row is not OK */
        Start();
        FailCustomJob = CSM_JOBID_KEM_DISCARD;      /* B's comes first, when it has installed */
        Cycles(2U);
        CHECK(FailCustomJob == 0U, "B: the failure was injected");
        EXPECT_ROW(B, PQCHS_RESULT_STATE);
        FailCustomJob = CSM_JOBID_KEM_DISCARD;      /* A's, when the acknowledgement has been checked */
        Cycles(1U);
        CHECK(FailCustomJob == 0U, "A: the failure was injected");
        EXPECT_ROW(A, PQCHS_RESULT_STATE);
        CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE) && (Session_Works() == TRUE) &&
              (Inst[A].State == PQCHS_STATE_IDLE), "the session is installed and works");
        Settle("H13 erase of dk and ss failed");
    }

    (void)printf("H13 hardening: buffer lock, tear-down, erasure results\n");
}

/************************************************* H14 ***************************************************/

/* Guards of the TP interface, called the way a lower layer could call them */
static void Test_H14_TpGuards(void)
{
    static uint8 out[PQCHS_M3_BYTES + 64U];
    static uint8 m1[PQCHS_M1_BYTES];
    PduLengthType room = 0U;
    PduLengthType left = 0U;
    PduInfoType info;
    uint32 ev;

    info.MetaDataPtr = NULL;

    /* transmission: never more bytes than the message has. Behind M3 in the instance lie the
     * acknowledgement buffer, sess and the pending keys. */
    Start();
    Step(A);
    Pump();
    Step(B);
    Pump();
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_SEND_M3) && (TxQueued == 1U) && (TxQueue[0] == TXID_M3), "M3 with SoAd");
    (void)memset(out, 0xEEU, sizeof(out));
    info.SduDataPtr = out;
    info.SduLength = PQCHS_M3_BYTES + 1U;
    CHECK(PqcHs_Core_CopyTxData(&Inst[A], 1U, &info, &left) == BUFREQ_E_NOT_OK, "one byte more than M3 is refused");
    CHECK(out[0] == 0xEEU, "a refused copy writes nothing");
    info.SduLength = 3000U;
    CHECK((PqcHs_Core_CopyTxData(&Inst[A], 0U, &info, &left) == BUFREQ_E_NOT_OK) && (out[0] == 0xEEU), "M1 is not in transmission");
    CHECK((PqcHs_Core_CopyTxData(&Inst[A], 1U, &info, &left) == BUFREQ_OK) && (left == (PQCHS_M3_BYTES - 3000U)), "first part of M3");
    info.SduDataPtr = &out[3000];
    info.SduLength = (PQCHS_M3_BYTES - 3000U) + 1U;
    CHECK(PqcHs_Core_CopyTxData(&Inst[A], 1U, &info, &left) == BUFREQ_E_NOT_OK, "one byte more than the rest is refused");
    CHECK(out[3000] == 0xEEU, "a refused copy writes nothing");
    /* confirmed with bytes outstanding: not handed over, so A must not install */
    PqcHs_Core_TxConfirmation(&Inst[A], 0U, E_OK);
    CHECK(Inst[A].TxActive == TRUE, "a confirmation for another message is ignored");
    PqcHs_Core_TxConfirmation(&Inst[A], 1U, E_OK);
    TxQueued = 0U;
    Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    CHECK((Oracle_Unchanged(A) == TRUE) && (Inst[A].State == PQCHS_STATE_I_RETRY), "M3 confirmed short of its length is not handed over");
    Settle("H14 transmit bound");

    /* reception: one message at a time, bytes only for the message that was started */
    Oracle_Mark();
    NowMs += SOAD_PQC_HS_MIN_INTERVAL_MS;
    ev = EvCount;
    Craft_M1(m1);
    CHECK(PqcHs_Core_StartOfReception(&Inst[B], 0U, PQCHS_M1_BYTES, &room) == BUFREQ_OK, "M1 started");
    CHECK(PqcHs_Core_StartOfReception(&Inst[B], 0U, PQCHS_M1_BYTES, &room) == BUFREQ_E_NOT_OK, "a second M1 during the first is refused");
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    CHECK(PqcHs_Core_StartOfReception(&Inst[B], 1U, PQCHS_M3_BYTES, &room) == BUFREQ_E_NOT_OK, "an M3 during an M1 is refused");
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    info.SduDataPtr = m1;
    info.SduLength = 100U;
    CHECK(PqcHs_Core_CopyRxData(&Inst[B], 1U, &info, &room) == BUFREQ_E_NOT_OK, "bytes for the message that was not started are refused");
    CHECK((PqcHs_Core_CopyRxData(&Inst[B], 0U, &info, &room) == BUFREQ_OK) && (room == (PQCHS_M1_BYTES - 100U)), "first 100 bytes of M1");
    PqcHs_Core_RxIndication(&Inst[B], 1U, E_OK);
    CHECK((Inst[B].RxActive == TRUE) && (Inst[B].RxReady == FALSE), "an indication for the other message ends nothing");
    /* indicated as complete although bytes are missing: dropped by its length, nothing else happens */
    PqcHs_Core_RxIndication(&Inst[B], 0U, E_OK);
    Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_BAD_LEN);
    CHECK((Ev_Count(B, ev, EV_ENCAPS) == 0U) && (Inst[B].State == PQCHS_STATE_IDLE), "a short M1 is not answered");
    /* the same for M3, behind which SoAd has closed the stream gate: it is released */
    CHECK(PqcHs_Core_StartOfReception(&Inst[B], 1U, PQCHS_M3_BYTES, &room) == BUFREQ_OK, "M3 started");
    PqcHs_Core_RxIndication(&Inst[B], 1U, E_OK);
    Cur = B;
    Ev(EV_GATE_CLOSED);
    GateClosed = TRUE;
    Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_BAD_LEN);
    CHECK(GateClosed == FALSE, "the gate behind a short M3 is released");
    EXPECT_NO_ROW(B);

    /* B: M2 is not handed over (confirmed E_NOT_OK, the connection stays): the pending handshake ends */
    Start();
    Step(A);
    Pump();
    Step(B);
    CHECK((Inst[B].State == PQCHS_STATE_R_PENDING) && (TxQueued == 1U) && (TxQueue[0] == TXID_M2), "M2 with SoAd");
    Cur = B;
    PqcHs_Core_TxConfirmation(&Inst[B], 0U, E_NOT_OK);
    TxQueued = 0U;
    Step(B);
    EXPECT_ROW(B, PQCHS_RESULT_STATE);
    CHECK((Inst[B].State == PQCHS_STATE_IDLE) && (Oracle_Unchanged(B) == TRUE), "pending handshake wiped when M2 did not go out");
    Settle("H14 M2 not handed over");

    /* A: M1 is not handed over (confirmed E_NOT_OK, the connection stays): the attempt ends */
    Start();
    Step(A);
    CHECK((Inst[A].State == PQCHS_STATE_I_WAIT_M2) && (TxQueued == 1U), "M1 with SoAd");
    Cur = A;
    PqcHs_Core_TxConfirmation(&Inst[A], 0U, E_NOT_OK);
    TxQueued = 0U;
    Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    CHECK(Inst[A].State == PQCHS_STATE_I_RETRY, "the attempt ends when M1 did not go out");
    Settle("H14 M1 not handed over");

    /* A: the connection changes while M1 is with SoAd, and SoAd confirms nothing: PqcHs ends the
     * transmission itself, so the next request is not refused for ever */
    Start();
    Step(A);
    CHECK(Inst[A].TxActive == TRUE, "M1 with SoAd");
    Cur = A;
    PqcHs_Core_SoConModeChg(&Inst[A], SOAD_SOCON_OFFLINE);
    CHECK(Inst[A].TxActive == FALSE, "a message with SoAd does not survive its connection");
    TxQueued = 0U;
    Connected = FALSE;
    Step(A);
    EXPECT_ROW(A, PQCHS_RESULT_STATE);
    Settle("H14 connection changed under M1");

    /* a message half received when the connection changes is dropped by PqcHs itself, whether or not
     * SoAd ends the reception first; the next message is taken */
    Oracle_Mark();
    CHECK(PqcHs_Core_StartOfReception(&Inst[A], 0U, PQCHS_M2_BYTES, &room) == BUFREQ_OK, "A: M2 started");
    CHECK(PqcHs_Core_StartOfReception(&Inst[B], 0U, PQCHS_M1_BYTES, &room) == BUFREQ_OK, "B: M1 started");
    Cur = A;
    PqcHs_Core_SoConModeChg(&Inst[A], SOAD_SOCON_OFFLINE);
    Cur = B;
    PqcHs_Core_SoConModeChg(&Inst[B], SOAD_SOCON_OFFLINE);
    CHECK((Inst[A].RxActive == FALSE) && (Inst[B].RxActive == FALSE), "the half-received messages are dropped");
    Connected = FALSE;
    Cycles(1U);
    EXPECT_NO_ROW(A);
    EXPECT_NO_ROW(B);
    Start();
    Cycles(4U);
    CHECK((Oracle_NewSession(A) == TRUE) && (Oracle_NewSession(B) == TRUE) && (Session_Works() == TRUE),
          "a handshake after a reception was cut off");
    EXPECT_ROW(A, PQCHS_RESULT_OK);
    EXPECT_ROW(B, PQCHS_RESULT_OK);
    Erasure_Check("reception cut off by a connection change");

    (void)printf("H14 guards of the TP interface\n");
}

/************************************************* H10 ***************************************************/

static void Test_H10_Module(void)
{
    static const PqcHs_InstanceConfigType moduleCfg[1] =
    {
        { PQCHS_ROLE_RESPONDER, PEER_OF_B, 7U, { TXID_M2, TXID_M4 }, { RXID(TXID_M1), RXID(TXID_M3) },
          B_KEY_TX, B_KEY_RX, B_KEY_KC, B_JOB_KC_GEN, B_JOB_KC_VER, FreshnessB, 1U }
    };
    static const PqcHs_ConfigType moduleConfig = { moduleCfg, 1U, { PQCHS_T_PEND_MS, SOAD_PQC_HS_MIN_INTERVAL_MS, PQCHS_T_A_MS, PQCHS_T_FLUSH_MS } };
    static const PqcHs_ConfigType badTimers = { moduleCfg, 1U, { 2000U, 1000U, 2000U, 1000U } };
    static const PqcHs_ConfigType badFlush = { moduleCfg, 1U, { 2000U, 1000U, 3000U, 2000U } };
    static const PqcHs_InstanceConfigType initiatorCfg[1] =
    {
        { PQCHS_ROLE_INITIATOR, PEER_OF_A, 4U, { TXID_M1, TXID_M3 }, { RXID(TXID_M2), RXID(TXID_M4) },
          A_KEY_TX, A_KEY_RX, A_KEY_KC, A_JOB_KC_GEN, A_JOB_KC_VER, FreshnessA, 1U }
    };
    static const PqcHs_ConfigType initiatorConfig = { initiatorCfg, 1U, { PQCHS_T_PEND_MS, SOAD_PQC_HS_MIN_INTERVAL_MS, PQCHS_T_A_MS, PQCHS_T_FLUSH_MS } };
    PduInfoType query = { NULL, NULL, 0U };
    static const PqcHs_ConfigType badMin = { moduleCfg, 1U, { 500U, 3000U, 3000U, 100U } };
    static uint8 m1[PQCHS_M1_BYTES];
    static uint8 m2[PQCHS_M2_BYTES];
    uint8 idB[32];
    uint8 sid[PQCHS_SID_BYTES];
    uint32 installs = 99U;
    PduLengthType room = 0U;
    PduLengthType left = 0U;
    PduInfoType info;
    PqcHs_AttemptInfoType row;

    CHECK(PqcHs_Init(&badTimers) == E_NOT_OK, "T_A must exceed T_pend");
    CHECK(PqcHs_Init(&badMin) == E_NOT_OK, "T_A must exceed T_min");
    CHECK(PqcHs_Init(&badFlush) == E_NOT_OK, "T_flush must stay below T_pend");
    CHECK(BindCalls == 0U, "a refused configuration is not bound to SoAd");
    CHECK(PqcHs_Init(&moduleConfig) == E_OK, "module initialised");
    CHECK((BindCalls == 1U) && (BoundLayer != NULL), "bound to SoAd once, at the end of the initialisation");
    if (BoundLayer != NULL)
    {
        CHECK((BoundLayer->StartOfReception == PqcHs_SoAdTpStartOfReception) && (BoundLayer->CopyRxData == PqcHs_SoAdTpCopyRxData) &&
              (BoundLayer->RxIndication == PqcHs_SoAdTpRxIndication) && (BoundLayer->CopyTxData == PqcHs_SoAdTpCopyTxData) &&
              (BoundLayer->TxConfirmation == PqcHs_SoAdTpTxConfirmation) && (BoundLayer->SoConModeChg == PqcHs_SoConModeChg),
              "the six upper-layer functions, each in its place");
    }
    TxQueued = 0U;
    Connected = TRUE;       /* the instance of this test is not one of the two the wire reports to */
    Cur = B;

    CHECK(PqcHs_IsEstablished(PEER_OF_B) == FALSE, "not established after initialisation");
    CHECK(PqcHs_IsEstablished(5U) == FALSE, "unknown peer is not established");
    CHECK(PqcHs_Initiate(PEER_OF_B) == E_NOT_OK, "a responder does not initiate");
    CHECK(PqcHs_Initiate(5U) == E_NOT_OK, "unknown peer");
    CHECK((PqcHs_GetSession(PEER_OF_B, sid, &installs) == E_OK) && (installs == 0U), "oracle of the module instance");
    CHECK(PqcHs_GetSession(5U, sid, &installs) == E_NOT_OK, "no session data for an unknown peer");

    /* fixed length per message id, checked before any byte is read; ids of the other role are unknown */
    CHECK(PqcHs_SoAdTpStartOfReception(RXID(TXID_M1), NULL, PQCHS_M1_BYTES - 1U, &room) == BUFREQ_E_NOT_OK, "short M1 refused");
    CHECK(PqcHs_SoAdTpStartOfReception(RXID(TXID_M3), NULL, PQCHS_M1_BYTES, &room) == BUFREQ_E_NOT_OK, "M3 id with the M1 length refused");
    CHECK(PqcHs_SoAdTpStartOfReception(RXID(TXID_M2), NULL, PQCHS_M2_BYTES, &room) == BUFREQ_E_NOT_OK, "M2 is not for a responder");
    CHECK(PqcHs_SoAdTpStartOfReception(RXID(TXID_M4), NULL, PQCHS_M4_BYTES, &room) == BUFREQ_E_NOT_OK, "M4 is not for a responder");
    CHECK((PqcHs_ReadAttempt(PEER_OF_B, &row) == E_OK) && (row.Result == PQCHS_RESULT_BAD_LEN), "row for the short M1");
    CHECK((PqcHs_ReadAttempt(PEER_OF_B, &row) == E_OK) && (row.Result == PQCHS_RESULT_BAD_LEN), "row for the wrong M3 length");
    CHECK(PqcHs_ReadAttempt(PEER_OF_B, &row) == E_NOT_OK, "no row for ids of the other role");

    /* SoAd's room query between two PDUs, with no reception in progress, reaches the instance */
    CHECK((PqcHs_SoAdTpCopyRxData(RXID(TXID_M1), &query, &room) == BUFREQ_OK) && (room == PQCHS_M1_BYTES), "room for an M1 at rest");
    CHECK((PqcHs_SoAdTpCopyRxData(RXID(TXID_M3), &query, &room) == BUFREQ_OK) && (room == PQCHS_M3_BYTES), "room for an M3 at rest");
    CHECK(PqcHs_SoAdTpCopyRxData(RXID(TXID_M2), &query, &room) == BUFREQ_E_NOT_OK, "no room for a message of the other role");

    /* an M1 through the SoAd upper-layer interface, in two pieces */
    Craft_M1(m1);
    CHECK(PqcHs_SoAdTpStartOfReception(RXID(TXID_M1), NULL, PQCHS_M1_BYTES, &room) == BUFREQ_OK, "M1 accepted");
    CHECK(room == PQCHS_M1_BYTES, "room announced %u", (unsigned)room);
    info.MetaDataPtr = NULL;
    info.SduDataPtr = m1;
    info.SduLength = 0U;
    CHECK((PqcHs_SoAdTpCopyRxData(RXID(TXID_M1), &info, &room) == BUFREQ_OK) && (room == PQCHS_M1_BYTES), "length 0 asks for the room");
    info.SduLength = 1000U;
    CHECK((PqcHs_SoAdTpCopyRxData(RXID(TXID_M1), &info, &room) == BUFREQ_OK) && (room == 217U), "first piece");
    info.SduDataPtr = &m1[1000];
    info.SduLength = 218U;
    CHECK(PqcHs_SoAdTpCopyRxData(RXID(TXID_M1), &info, &room) == BUFREQ_E_NOT_OK, "more bytes than announced are refused");
    info.SduLength = 217U;
    CHECK((PqcHs_SoAdTpCopyRxData(RXID(TXID_M1), &info, &room) == BUFREQ_OK) && (room == 0U), "second piece");
    PqcHs_SoAdTpRxIndication(RXID(TXID_M1), E_OK);
    CHECK(TxQueued == 0U, "nothing is processed inside the SoAd indication");

    ActAs(B);
    PqcHs_MainFunction();
    CHECK((TxQueued == 1U) && (TxQueue[0] == TXID_M2) && (TxQueueLen[0] == PQCHS_M2_BYTES), "M2 requested from the main function");
    info.SduDataPtr = m2;
    info.SduLength = PQCHS_M2_BYTES;
    CHECK((PqcHs_SoAdTpCopyTxData(TXID_M2, &info, NULL, &left) == BUFREQ_OK) && (left == 0U), "M2 copied out");
    CHECK(PqcHs_SoAdTpCopyTxData(TXID_M4, &info, NULL, &left) == BUFREQ_E_NOT_OK, "no M4 in transmission");
    PqcHs_SoAdTpTxConfirmation(TXID_M2, E_OK);
    (void)SHA256(Key[B].PublicKey, sizeof(Key[B].PublicKey), idB);
    CHECK((m2[0] == PQCHS_VERSION) && (memcmp(&m2[1], idB, 32U) == 0), "M2 of the module instance carries ID_B");
    TxQueued = 0U;

    /* connection events are routed by socket connection */
    PqcHs_SoConModeChg(3U, SOAD_SOCON_OFFLINE);
    CHECK(PqcHs_ReadAttempt(PEER_OF_B, &row) == E_NOT_OK, "another socket connection changes nothing");
    PqcHs_SoConModeChg(7U, SOAD_SOCON_OFFLINE);
    CHECK((PqcHs_ReadAttempt(PEER_OF_B, &row) == E_OK) && (row.Result == PQCHS_RESULT_STATE), "pending handshake wiped with its connection");
    CHECK(PqcHs_IsEstablished(PEER_OF_B) == FALSE, "still not established");
    (void)__real_Csm_CustomService(CSM_JOBID_KEM_DISCARD, CRYPTO_OPERATIONMODE_SINGLECALL, CSM_KEYID_SESSION_BASE + PEER_OF_B,
                                   NULL, 0U, NULL, 0U, NULL, 0U, NULL, NULL, NULL, NULL, NULL);
    /* An initiator whose connection is already up when it binds: SoAd reports ONLINE from inside
     * SoAd_SetUpperLayer, the start-up code asks for the first handshake as well, and the main function
     * starts one handshake, not two */
    BindOnline = TRUE;
    BindSoConId = 4U;
    CHECK(PqcHs_Init(&initiatorConfig) == E_OK, "initiator module initialised with the connection up");
    BindOnline = FALSE;
    CHECK(TxQueued == 0U, "nothing is transmitted from inside the bind");
    CHECK(PqcHs_Initiate(PEER_OF_A) == E_OK, "first handshake asked for at start-up");
    ActAs(A);
    PqcHs_MainFunction();
    CHECK((TxQueued == 1U) && (TxQueue[0] == TXID_M1), "M1 requested by the main function");
    PqcHs_MainFunction();
    PqcHs_MainFunction();
    CHECK(TxQueued == 1U, "one handshake for the ONLINE at the bind and the request together");
    TxQueued = 0U;
    (void)__real_Csm_CustomService(CSM_JOBID_KEM_DISCARD, CRYPTO_OPERATIONMODE_SINGLECALL, CSM_KEYID_SESSION_BASE + PEER_OF_A,
                                   NULL, 0U, NULL, 0U, NULL, 0U, NULL, NULL, NULL, NULL, NULL);
    /* the same without a connection at the bind and without the request: nothing starts by itself */
    CHECK(PqcHs_Init(&initiatorConfig) == E_OK, "initiator module initialised without a connection");
    PqcHs_MainFunction();
    CHECK(TxQueued == 0U, "no handshake without ONLINE and without a request");

    /* The configuration of the evaluated set-up: one peer. Its role follows the build: the sender
     * build (the transmitting gateway) is the initiator, every other build the responder. */
    CHECK(PqcHs_Init(NULL) == E_OK, "default configuration");
#if (SECOC_ROLE_SENDER == TRUE)
    CHECK((PqcHs_Config.PqcHsNumInstances == 1U) && (PqcHs_Config.PqcHsInstances[0].PqcHsPeer == 0U) &&
          (PqcHs_Config.PqcHsInstances[0].PqcHsRole == PQCHS_ROLE_INITIATOR), "one initiator instance for peer 0");
    CHECK((PqcHs_Config.PqcHsInstances[0].PqcHsTxPduId[0] == SOAD_PDUID_HS_M1) &&
          (PqcHs_Config.PqcHsInstances[0].PqcHsTxPduId[1] == SOAD_PDUID_HS_M3) &&
          (PqcHs_Config.PqcHsInstances[0].PqcHsRxPduId[0] == SOAD_PDUID_HS_M2) &&
          (PqcHs_Config.PqcHsInstances[0].PqcHsRxPduId[1] == SOAD_PDUID_HS_M4), "the initiator sends M1, M3 and receives M2, M4");
    {
        static const uint16 txIds[SECOC_SESSION_TX_FRESHNESS_COUNT] = { SECOC_SESSION_TX_FRESHNESS_IDS };
        CHECK((PqcHs_Config.PqcHsInstances[0].PqcHsNumFreshnessIds == SECOC_SESSION_TX_FRESHNESS_COUNT) &&
              (PqcHs_Config.PqcHsInstances[0].PqcHsNumFreshnessIds == 16U) &&
              (memcmp(PqcHs_Config.PqcHsInstances[0].PqcHsFreshnessIds, txIds, sizeof(txIds)) == 0),
              "the initiator restarts the 16 transmit counters of the session-bound streams");
    }
#else
    CHECK((PqcHs_Config.PqcHsNumInstances == 1U) && (PqcHs_Config.PqcHsInstances[0].PqcHsPeer == 0U) &&
          (PqcHs_Config.PqcHsInstances[0].PqcHsRole == PQCHS_ROLE_RESPONDER), "one responder instance for peer 0");
    CHECK((PqcHs_Config.PqcHsInstances[0].PqcHsRxPduId[0] == SOAD_PDUID_HS_M1) &&
          (PqcHs_Config.PqcHsInstances[0].PqcHsRxPduId[1] == SOAD_PDUID_HS_M3) &&
          (PqcHs_Config.PqcHsInstances[0].PqcHsTxPduId[0] == SOAD_PDUID_HS_M2) &&
          (PqcHs_Config.PqcHsInstances[0].PqcHsTxPduId[1] == SOAD_PDUID_HS_M4), "the responder receives M1, M3 and sends M2, M4");
    {
        static const uint16 rxIds[SECOC_SESSION_RX_FRESHNESS_COUNT] = { SECOC_SESSION_RX_FRESHNESS_IDS };
        CHECK((PqcHs_Config.PqcHsInstances[0].PqcHsNumFreshnessIds == SECOC_SESSION_RX_FRESHNESS_COUNT) &&
              (PqcHs_Config.PqcHsInstances[0].PqcHsNumFreshnessIds == 16U) &&
              (memcmp(PqcHs_Config.PqcHsInstances[0].PqcHsFreshnessIds, rxIds, sizeof(rxIds)) == 0),
              "the responder restarts the 16 receive counters of the session-bound streams");
    }
#endif
    CHECK((PqcHs_Config.PqcHsTimers.PqcHsTPendMs == 2000U) && (PqcHs_Config.PqcHsTimers.PqcHsTMinMs == 1000U) &&
          (PqcHs_Config.PqcHsTimers.PqcHsTAMs == 3000U) && (PqcHs_Config.PqcHsTimers.PqcHsTFlushMs == 1000U),
          "T_pend 2 s, T_min 1 s, T_A 3 s, T_flush 1 s");
#if (SECOC_ROLE_SENDER == TRUE)
    /* the initiator takes no M1; nothing is asked of it here, so nothing starts */
    CHECK(PqcHs_IsEstablished(0U) == FALSE, "default instance: no session");
    CHECK(PqcHs_SoAdTpStartOfReception(SOAD_PDUID_HS_M1, NULL, PQCHS_M1_BYTES, &room) != BUFREQ_OK, "the default initiator instance accepted an M1");
    PqcHs_MainFunction();
    CHECK(PqcHs_ReadAttempt(0U, &row) == E_NOT_OK, "no attempt row without a request");
#else
    CHECK((PqcHs_IsEstablished(0U) == FALSE) && (PqcHs_Initiate(0U) == E_NOT_OK), "default instance: no session, no initiative");
    CHECK(PqcHs_SoAdTpStartOfReception(SOAD_PDUID_HS_M1, NULL, PQCHS_M1_BYTES, &room) == BUFREQ_OK, "default instance accepts an M1");
    PqcHs_SoAdTpRxIndication(SOAD_PDUID_HS_M1, E_NOT_OK);
    PqcHs_MainFunction();
    CHECK(PqcHs_ReadAttempt(0U, &row) == E_NOT_OK, "an aborted reception leaves no row");
#endif
    (void)printf("H10 module layer\n");
}

/************************************************* main **************************************************/

static Std_ReturnType Test_LoadProvisionedKeys(uint8* publicKeyPtr, uint32 publicKeyLength,
                                               uint8* secretKeyPtr, uint32 secretKeyLength)
{
    (void)memcpy(publicKeyPtr, Key[A].PublicKey, publicKeyLength);
    (void)memcpy(secretKeyPtr, Key[A].SecretKey, secretKeyLength);
    return E_OK;
}

int main(int argc, char** argv)
{
    Csm_ConfigType cfg;

    (void)setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 1)
    {
        /* a transcript of an earlier run must not survive a run that does not reach the dump */
        KatPath = argv[1];
        (void)remove(KatPath);
    }

    CHECK(PQC_Init() == PQC_E_OK, "PQC_Init");
    CHECK(PQC_MLDSA_KeyGen(&Key[A]) == PQC_E_OK, "identity A");
    CHECK(PQC_MLDSA_KeyGen(&Key[B]) == PQC_E_OK, "identity B");
    CHECK(PQC_MLDSA_KeyGen(&KeyX) == PQC_E_OK, "identity X");

    cfg.CsmMldsaBootstrapMode = CSM_MLDSA_BOOTSTRAP_PROVISIONED;
    cfg.CsmLoadProvisionedMldsaKeysFct = Test_LoadProvisionedKeys;
    Csm_Init(&cfg);
    /* A pins B as peer 0, B pins A as peer 1 */
    CHECK(__real_Csm_KeyElementSet(CSM_KEYID_PEER_PUBKEY_BASE + PEER_OF_A, CSM_KEYELEMENT_MLDSA_PEER_PUBLIC,
                                   Key[B].PublicKey, CSM_MLDSA_PUBLIC_KEY_BYTES) == E_OK, "pin B");
    CHECK(__real_Csm_KeySetValid(CSM_KEYID_PEER_PUBKEY_BASE + PEER_OF_A) == E_OK, "pin B valid");
    CHECK(__real_Csm_KeyElementSet(CSM_KEYID_PEER_PUBKEY_BASE + PEER_OF_B, CSM_KEYELEMENT_MLDSA_PEER_PUBLIC,
                                   Key[A].PublicKey, CSM_MLDSA_PUBLIC_KEY_BYTES) == E_OK, "pin A");
    CHECK(__real_Csm_KeySetValid(CSM_KEYID_PEER_PUBKEY_BASE + PEER_OF_B) == E_OK, "pin A valid");

    CHECK(PqcHs_Core_Init(&Inst[A], &Cfg[A], &Timers) == E_OK, "instance A");
    CHECK(PqcHs_Core_Init(&Inst[B], &Cfg[B], &Timers) == E_OK, "instance B");

    Test_H1_Positive();
    Test_H3_Discard();
    Test_H4_Wipe();
    Test_H5_Pending();
    Test_H6_Negative();
    Test_H7_M3M4();
    Test_H8_LocalFailures();
    Test_H11_Restart();
    Test_H12_RoomQuery();
    Test_H13_Hardening();
    Test_H14_TpGuards();
    CHECK(GateViolations == 0U, "%u message(s) were delivered through a closed stream gate", (unsigned)GateViolations);
    (void)printf("H9 erasure checked after every scenario (%u dk, %u ss, %u PRK, %u key sets recorded; %u of %u events)\n",
                 (unsigned)NumDk, (unsigned)NumSs, (unsigned)NumPrk, (unsigned)NumOkm, (unsigned)EvCount, (unsigned)MAX_EVENTS);
    Test_H10_Module();

    if (Failures == 0U)
    {
        (void)printf("PASS: 0 failed check(s)\n");
        return 0;
    }
    (void)printf("FAIL: %u failed check(s)\n", (unsigned)Failures);
    return 1;
}
