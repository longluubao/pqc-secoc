/********************************************************************************************************/
/*  File:   test/test_txrx_e2e.c                                                                          */
/*  Brief:  Transmit path -> wire bytes -> receive path in ONE process, through the real SecOC, PduR,     */
/*          SoAd, Csm, CryIf and PQC code. TcpIp is replaced at link time (-Wl,--wrap) by an in-memory    */
/*          wire; the Csm signature calls and Com_RxIndication are observed the same way, so no           */
/*          production code is changed for the test.                                                      */
/*                                                                                                        */
/*  The transmitter signs with key pair A. Before reception the Csm is re-initialised with key pair B     */
/*  (the receiver's own identity) and A's public key is provisioned as peer 0, as on two gateways.        */
/*                                                                                                        */
/*  Checks: C1 DataToAuthenticator layout on Tx (SWS_SecOC_00034)                                         */
/*          C2 Rx DataToAuthenticator bytes identical to Tx for every PDU (SWS_SecOC_00046)               */
/*          C3 every signature verifies with the peer public key (SWS SecOC 7.1.4)                        */
/*          C4 every PDU delivered once, in order, byte-exact, whatever the TCP segmentation              */
/*             (SWS_SoAd_00197/00198/00771)                                                               */
/*          C5 rejected PDUs (unknown header ID, too long, tampered, replayed, truncated) are not         */
/*             delivered, are counted, and do not block or desynchronise the PDUs behind them. BswM       */
/*             runs for real in every receive cycle (mode requests as in the gateway, routing groups      */
/*             under its control), and the tampered PDU is followed by idle cycles before the next one.   */
/*          C6 freshness sent in full: a gap of lost PDUs is accepted, a rejected PDU whose counter has   */
/*             low byte 0xFF does not desynchronise the receiver, an older value is rejected              */
/*          C7 one TCP connection at a time and only from the configured peer; a connection closed in the */
/*             middle of a PDU ends that PDU and is followed by a new connection; a header with an        */
/*             implausible length closes the connection                                                   */
/*          C8 a second upper layer on the same connection (a stand-in for the handshake component):      */
/*             its PDUs are dispatched by header ID, a wrong length is discarded, nothing behind a gated   */
/*             PDU is parsed until the gate is released or the connection ends, transmissions of both      */
/*             upper layers go out whole and in the order they were requested, mode changes are reported   */
/*          C9 four signature streams (four Secured I-PDUs, each with its own freshness counter) on the   */
/*             one connection, interleaved, over every segmentation: each stream complete and in order;   */
/*             a rejected PDU of one stream, an unknown header ID and an over-long PDU between them        */
/*             disturb no other PDU                                                                       */
/*          C10 session boundaries: transmission held and resumed, "flushed" and "drained" as the          */
/*             handshake component will ask for them, freshness counters restarted by FVM_SessionInstall   */
/*          C12 the counter of a session-bound PDU: 32 bits in full in every signature row, nothing       */
/*             accepted at or below the last accepted value (0 before the first), nothing sent after      */
/*             2^32 - 1 until FVM_SessionInstall                                                          */
/*          C13 binding to the session through the signature context: the driver signs 14 bytes under a  */
/*             64-byte context; a PDU of one session is an authentication failure in another, and so is   */
/*             a PDU signed with no session (the context the Csm starts with)                             */
/*          C14 no session: once the handshake component is initialised, a valid Secured I-PDU is a       */
/*             freshness failure until a session is established, also after a failed key installation,   */
/*             on the TP and on the IF reception path; a context that is not valid verifies nothing       */
/*          C15 a SecOC row of a CAN PDU (row 0) signs with the PDU sign job and verifies with the        */
/*             listed loopback verify job                                                                 */
/*          C16 the MAC variant and its session: a PDU authenticated under a static key is refused while   */
/*             no session exists and fails verification in a session; a PDU of one session fails in the    */
/*             next one                                                                                    */
/*          C11 the C5 sequence with BswM configured to the reaction as found                             */
/*             (SecOCFailureDisablesRouting): the PDUs behind the tampered one are discarded by SoAd      */
/*          V1 what SecOC does with each answer of the Csm verify call (the Csm is replaced by a stub     */
/*             for these PDUs): only E_OK together with CRYPTO_E_VER_OK delivers; every other pair is     */
/*             one reported SECOC_VERIFICATIONFAILURE at the first attempt, nothing delivered, the next   */
/*             PDU accepted; a busy Csm is retried SecOCAuthenticationBuildAttempts times and then        */
/*             reported as SECOC_AUTHENTICATIONBUILDFAILURE, for every PDU anew (SWS_SecOC_00235, 00237,  */
/*             00240, 00241, 00278). verify() and verify_PQC() are also called directly.                  */
/*          V2 a receiver whose Csm has no valid key for the peer: N PDUs, N reported failures, none      */
/*             delivered (review 2.1)                                                                     */
/*          V3 transmit: whatever the Csm generate call returns other than E_OK, no Secured I-PDU is      */
/*             built or handed down and no freshness value is used up (SWS_SecOC_00227 to 00229)          */
/*          V4 a Secured I-PDU whose header byte does not fit its length and one that is a byte short     */
/*             are each one reported failure before any Csm call. A header byte above the Authentic       */
/*             I-PDU maximum is refused by SecOC_StartOfReception when that byte has arrived with the     */
/*             PDU header (SWS_SecOC_00263: SoAd counts a dropped PDU, no verification status) and is a   */
/*             reported failure when the PDU header arrived alone. The PDU behind them is delivered.      */
/*                                                                                                        */
/*  MAC variant (SecOC PDU 13, HMAC-SHA-256, 128-bit tag), same process and same socket connection:       */
/*          M1 without a valid MAC key nothing is transmitted and the freshness value is not used up; a   */
/*             receiver without a valid key reports one verification failure per PDU and delivers nothing */
/*          M2 the authenticator service is chosen per PDU: PDU 2 carries a complete signature, PDU 13 a  */
/*             16-byte tag, each through its own Csm job; with the jobs swapped neither is accepted       */
/*          M3 direction keys: a MAC PDU presented to its sender's own receive path is rejected           */
/*          M4 every MAC PDU delivered once, in order, byte-exact, whatever the TCP segmentation          */
/*             (the chunk sizes of C4, and reads of exactly one PDU: a sender with TCP no-delay)          */
/*          M5 signature and MAC PDUs interleaved on one connection: each stream complete, in order       */
/*          M6 rejected MAC PDUs (tampered, replayed, repeated, truncated) are not delivered and do not   */
/*             block                                                                                      */
/*          M7 the V1 answers of the Csm for the MAC PDU, through SoAd and verify()                       */
/*          M8 a MAC PDU whose header byte is above the Authentic I-PDU maximum or does not fit its       */
/*             length, or that is a byte too long, is refused before it is parsed (the outcomes of V4);   */
/*             MAC bytes under the signature PDU's header ID and the reverse are refused; the next PDU    */
/*             is delivered                                                                               */
/*          M9 transmit: a Csm generate call that returns E_OK with fewer bytes than                      */
/*             SecOCAuthInfoTruncLength asks for gives no Secured I-PDU, on both paths                    */
/*          M10 a PDU row without a Csm job reference, or with a job of the wrong service, is a           */
/*             configuration error: nothing is transmitted, a received PDU is a reported failure, and     */
/*             the Csm is not called                                                                      */
/********************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Std_Types.h"
#include "ComStack_Types.h"
#include "SecOC.h"
#include "SecOC_Cfg.h"
#include "SecOC_Lcfg.h"
#include "SoAd.h"
#include "TcpIp.h"
#include "CanIF.h"
#include "Csm.h"
#include "PQC.h"
#include "BswM.h"
#include "FVM.h"
#include "EcuM.h"
#include "ComM.h"
#include "PqcHs/PqcHs.h"

#define TEST_PDU_ID            ((PduIdType)2U)
#define TEST_DATA_ID           (2U)             /* SecOCDataId of PDU 2 in SecOC_Lcfg.c */
#define TEST_PAYLOAD_LEN       (8U)
#define TEST_FRESHNESS_BYTES   (4U)             /* SecOCFreshnessValueLength = 32 bit */
#define TEST_D2A_LEN           (2U + TEST_PAYLOAD_LEN + TEST_FRESHNESS_BYTES)
#define TEST_PDUS_PER_SEGMENT  (45U)
#define TEST_WIRE_PDU_MAX      (3400U)
#define TEST_MAC_PDU_ID        ((PduIdType)SECOC_PDUID_MAC(0U))
#define TEST_MAC_DATA_ID       (SECOC_PDUID_MAC(0U))    /* SecOCDataId = SecOC PDU ID (SoAd_PduIds.h) */
#define TEST_MAC_LOG           (512U)
#define TEST_MIXED_PAIRS       (40U)
#define TEST_SOAD_HEADER_LEN   (8U)
#define TEST_EXTRA_PDUS        (96U + TEST_MIXED_PAIRS + 10U)  /* room for the PDUs of the negative and the MAC cases */

/* TCP segmentations: 1 byte at a time, around the 8-byte PDU header, an Ethernet MSS, a full read, random */
static const uint32 Test_ChunkSizes[] = { 1U, 7U, 8U, 9U, 1448U, 4096U, 0U /* random */ };
#define TEST_SEGMENTS          (sizeof(Test_ChunkSizes) / sizeof(Test_ChunkSizes[0]))
#define TEST_NUM_PDUS          (TEST_SEGMENTS * TEST_PDUS_PER_SEGMENT)   /* 315: crosses the 8-bit freshness wrap */

static uint8  Wire[(TEST_NUM_PDUS + TEST_EXTRA_PDUS) * TEST_WIRE_PDU_MAX];
static uint32 WireLen = 0U;

static uint8  TxD2A[TEST_NUM_PDUS][64];
static uint32 TxD2ALen[TEST_NUM_PDUS];
static uint32 TxSigned = 0U;

static uint8  RxD2A[TEST_NUM_PDUS + TEST_EXTRA_PDUS][64];
static uint32 RxD2ALen[TEST_NUM_PDUS + TEST_EXTRA_PDUS];
static uint32 RxVerifyCalls = 0U;
static uint32 RxVerifyOk = 0U;
static Std_ReturnType LastVerifyResult = E_OK;              /* what the real Csm_SignatureVerify answered last */
static Crypto_VerifyResultType LastVerifyVerdict = CRYPTO_E_VER_OK;

static uint8  Delivered[TEST_NUM_PDUS + TEST_EXTRA_PDUS][TEST_PAYLOAD_LEN];
static uint32 DeliveredLen[TEST_NUM_PDUS + TEST_EXTRA_PDUS];
static uint32 DeliveredCount = 0U;

/* per-PDU delivery tracking for the multi-stream case: every delivery must carry the next sequence
 * number of its stream and the stream number in the first payload byte */
static boolean StreamTrack = FALSE;
static uint32  StreamDelivered[SECOC_NUM_OF_RX_PDU_PROCESSING];
static uint32  StreamNextSeq[SECOC_NUM_OF_RX_PDU_PROCESSING];
static uint8   StreamByte[SECOC_NUM_OF_RX_PDU_PROCESSING];
static uint32  StreamErrors = 0U;

static uint32 StatusOk = 0U;
static uint32 StatusFreshnessFail = 0U;
static uint32 StatusAuthFail = 0U;
static SecOC_VerificationResultType LastStatus = SECOC_NO_VERIFICATION;

/* V cases: the Csm answers of the next calls are dictated instead of computed */
static boolean ForceVerify = FALSE;
static Std_ReturnType ForceVerifyResult = E_OK;
static Crypto_VerifyResultType ForceVerifyVerdict = CRYPTO_E_VER_OK;
static uint32 ForceVerifyLimit = 0U;        /* 0: every call, n: the first n calls */
static uint32 ForceVerifyCalls = 0U;
static boolean ForceGenerate = FALSE;
static Std_ReturnType ForceGenerateResult = E_OK;
static uint32 ForceGenerateLimit = 0U;
static uint32 ForceGenerateCalls = 0U;
static uint32 ForceGenerateLength = 0U;     /* bytes the stub says it wrote (0: the length is left alone) */

/* MAC variant: Csm MAC calls, deliveries and verification status of the MAC PDU */
static uint8  TxMacD2A[TEST_MAC_LOG][64];
static uint32 TxMacD2ALen[TEST_MAC_LOG];
static uint32 TxMacCalls = 0U;
static uint32 TxMacJob = 0U;
static Std_ReturnType TxMacResult = E_OK;
static uint8  RxMacD2A[TEST_MAC_LOG][64];
static uint32 RxMacD2ALen[TEST_MAC_LOG];
static uint32 RxMacCalls = 0U;
static uint32 RxMacOk = 0U;
static uint32 RxMacJob = 0U;
static uint32 RxMacBits = 0U;
static uint32 TxSigJob = 0U;
static uint32 RxSigJob = 0U;
static uint8  MacDelivered[TEST_MAC_LOG][TEST_PAYLOAD_LEN];
static uint32 MacDeliveredLen[TEST_MAC_LOG];
static uint32 MacDeliveredCount = 0U;
static uint32 MacStatusOk = 0U;
static uint32 MacStatusFreshnessFail = 0U;
static uint32 MacStatusAuthFail = 0U;

/* the two direction keys of a session; A = initiator (i2r is its transmit key), B = responder */
static const uint8 KeyI2R[32] =
{
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};
static const uint8 KeyR2I[32] =
{
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};

#define TEST_NEG_PDUS          (5U)
/* composed byte streams of the negative cases; the longest is the disturbance round of C9 (8 PDUs,
 * a 13-byte and a 9,008-byte PDU). Test_Feed stops the test if a composition is longer. */
static uint8  NegWire[((TEST_NEG_PDUS + 4U) * TEST_WIRE_PDU_MAX) + 9100U];

static PQC_MLDSA_KeyPairType KeyA;
static PQC_MLDSA_KeyPairType KeyB;
static const PQC_MLDSA_KeyPairType* ProvisionedKey = NULL;

static uint32 Failures = 0U;

#define CHECK(cond, ...) \
    do { if (!(cond)) { Failures++; (void)printf("  FAIL: " __VA_ARGS__); (void)printf("\n"); } } while (0)

/******************************************** link-time seams ********************************************/

Std_ReturnType __real_Csm_SignatureGenerate(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                            uint32 dataLength, uint8* signaturePtr, uint32* signatureLengthPtr);
Std_ReturnType __real_Csm_SignatureVerify(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                          uint32 dataLength, const uint8* signaturePtr, uint32 signatureLength,
                                          Crypto_VerifyResultType* verifyPtr);

Std_ReturnType __real_Csm_MacVerify(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                    uint32 dataLength, const uint8* macPtr, uint32 macLength,
                                    Crypto_VerifyResultType* verifyPtr);

static boolean Test_ForcedVerify(Crypto_VerifyResultType* verifyPtr, Std_ReturnType* resultPtr)
{
    if ((ForceVerify == FALSE) || ((ForceVerifyLimit != 0U) && (ForceVerifyCalls >= ForceVerifyLimit)))
    {
        return FALSE;
    }
    ForceVerifyCalls++;
    *verifyPtr = ForceVerifyVerdict;
    *resultPtr = ForceVerifyResult;
    return TRUE;
}

Std_ReturnType __real_Csm_MacGenerate(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                      uint32 dataLength, uint8* macPtr, uint32* macLengthPtr);

static boolean Test_ForcedGenerate(uint32* lengthPtr, Std_ReturnType* resultPtr)
{
    if ((ForceGenerate == FALSE) || ((ForceGenerateLimit != 0U) && (ForceGenerateCalls >= ForceGenerateLimit)))
    {
        return FALSE;
    }
    ForceGenerateCalls++;
    if (ForceGenerateLength != 0U)
    {
        *lengthPtr = ForceGenerateLength;
    }
    *resultPtr = ForceGenerateResult;
    return TRUE;
}

Std_ReturnType __wrap_Csm_MacGenerate(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                      uint32 dataLength, uint8* macPtr, uint32* macLengthPtr)
{
    Std_ReturnType forced;

    if (Test_ForcedGenerate(macLengthPtr, &forced) == TRUE)
    {
        return forced;
    }
    if ((TxMacCalls < TEST_MAC_LOG) && (dataLength <= sizeof(TxMacD2A[0])))
    {
        (void)memcpy(TxMacD2A[TxMacCalls], dataPtr, dataLength);
        TxMacD2ALen[TxMacCalls] = dataLength;
    }
    TxMacCalls++;
    TxMacJob = jobId;
    TxMacResult = __real_Csm_MacGenerate(jobId, mode, dataPtr, dataLength, macPtr, macLengthPtr);
    return TxMacResult;
}

Std_ReturnType __wrap_Csm_MacVerify(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                    uint32 dataLength, const uint8* macPtr, uint32 macLength,
                                    Crypto_VerifyResultType* verifyPtr)
{
    Std_ReturnType result;

    if (Test_ForcedVerify(verifyPtr, &result) == TRUE)
    {
        return result;
    }
    result = __real_Csm_MacVerify(jobId, mode, dataPtr, dataLength, macPtr, macLength, verifyPtr);
    if ((RxMacCalls < TEST_MAC_LOG) && (dataLength <= sizeof(RxMacD2A[0])))
    {
        (void)memcpy(RxMacD2A[RxMacCalls], dataPtr, dataLength);
        RxMacD2ALen[RxMacCalls] = dataLength;
    }
    RxMacCalls++;
    RxMacJob = jobId;
    RxMacBits = macLength;
    if ((result == E_OK) && (*verifyPtr == CRYPTO_E_VER_OK))
    {
        RxMacOk++;
    }
    return result;
}

Std_ReturnType __wrap_Csm_SignatureGenerate(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                            uint32 dataLength, uint8* signaturePtr, uint32* signatureLengthPtr)
{
    Std_ReturnType forced;

    if (Test_ForcedGenerate(signatureLengthPtr, &forced) == TRUE)
    {
        return forced;
    }
    if ((TxSigned < TEST_NUM_PDUS) && (dataLength <= sizeof(TxD2A[0])))
    {
        (void)memcpy(TxD2A[TxSigned], dataPtr, dataLength);
        TxD2ALen[TxSigned] = dataLength;
    }
    TxSigned++;
    TxSigJob = jobId;
    return __real_Csm_SignatureGenerate(jobId, mode, dataPtr, dataLength, signaturePtr, signatureLengthPtr);
}

Std_ReturnType __wrap_Csm_SignatureVerify(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                          uint32 dataLength, const uint8* signaturePtr, uint32 signatureLength,
                                          Crypto_VerifyResultType* verifyPtr)
{
    Std_ReturnType result;

    if (Test_ForcedVerify(verifyPtr, &result) == TRUE)
    {
        return result;
    }
    result = __real_Csm_SignatureVerify(jobId, mode, dataPtr, dataLength, signaturePtr,
                                        signatureLength, verifyPtr);
    if ((RxVerifyCalls < (TEST_NUM_PDUS + TEST_EXTRA_PDUS)) && (dataLength <= sizeof(RxD2A[0])))
    {
        (void)memcpy(RxD2A[RxVerifyCalls], dataPtr, dataLength);
        RxD2ALen[RxVerifyCalls] = dataLength;
    }
    RxVerifyCalls++;
    RxSigJob = jobId;
    LastVerifyResult = result;
    LastVerifyVerdict = *verifyPtr;
    /* a verification that ran is a successful request; "verified" needs the verdict as well */
    if ((result == E_OK) && (*verifyPtr == CRYPTO_E_VER_OK))
    {
        RxVerifyOk++;
    }
    return result;
}

/* what reaches the ML-DSA driver: message and FIPS 204 context of every signature and verification */
Std_ReturnType __real_PQC_MLDSA_Sign(const uint8* Message, uint32 MessageLength, const uint8* Context, uint32 ContextLength,
                                     const uint8* SecretKey, uint8* Signature, uint32* SignatureLength);
Std_ReturnType __real_PQC_MLDSA_Verify(const uint8* Message, uint32 MessageLength, const uint8* Context, uint32 ContextLength,
                                       const uint8* Signature, uint32 SignatureLength, const uint8* PublicKey);
static uint32 DriverSignCalls = 0U;
static uint32 DriverLengthErrors = 0U;      /* calls with a message that is not 14 bytes or a context that is not 64 */
static uint8  DriverSignContext[PQC_PDU_SIG_CTX_BYTES];
static uint8  DriverVerifyContext[PQC_PDU_SIG_CTX_BYTES];

static void Test_DriverCall(uint32 MessageLength, const uint8* Context, uint32 ContextLength, uint8* Copy)
{
    if ((MessageLength != TEST_D2A_LEN) || (ContextLength != PQC_PDU_SIG_CTX_BYTES) || (Context == NULL))
    {
        DriverLengthErrors++;
    }
    else
    {
        (void)memcpy(Copy, Context, PQC_PDU_SIG_CTX_BYTES);
    }
}

Std_ReturnType __wrap_PQC_MLDSA_Sign(const uint8* Message, uint32 MessageLength, const uint8* Context, uint32 ContextLength,
                                     const uint8* SecretKey, uint8* Signature, uint32* SignatureLength)
{
    DriverSignCalls++;
    Test_DriverCall(MessageLength, Context, ContextLength, DriverSignContext);
    return __real_PQC_MLDSA_Sign(Message, MessageLength, Context, ContextLength, SecretKey, Signature, SignatureLength);
}

Std_ReturnType __wrap_PQC_MLDSA_Verify(const uint8* Message, uint32 MessageLength, const uint8* Context, uint32 ContextLength,
                                       const uint8* Signature, uint32 SignatureLength, const uint8* PublicKey)
{
    Test_DriverCall(MessageLength, Context, ContextLength, DriverVerifyContext);
    return __real_PQC_MLDSA_Verify(Message, MessageLength, Context, ContextLength, Signature, SignatureLength, PublicKey);
}

/* the handshake component's "session established": its own answer, or what case C14 sets */
boolean __real_PqcHs_IsEstablished(uint8 Peer);
static sint8 EstablishedOverride = -1;
boolean __wrap_PqcHs_IsEstablished(uint8 Peer)
{
    return (EstablishedOverride < 0) ? __real_PqcHs_IsEstablished(Peer) : (boolean)EstablishedOverride;
}

void __wrap_Com_RxIndication(PduIdType RxPduId, const PduInfoType* PduInfoPtr)
{
    if (StreamTrack == TRUE)
    {
        if ((RxPduId < (PduIdType)SECOC_NUM_OF_RX_PDU_PROCESSING) && (PduInfoPtr->SduLength == TEST_PAYLOAD_LEN))
        {
            const uint8* d = PduInfoPtr->SduDataPtr;
            uint32 seq = ((uint32)d[4] << 24U) | ((uint32)d[5] << 16U) | ((uint32)d[6] << 8U) | (uint32)d[7];
            if ((seq != StreamNextSeq[RxPduId]) || (d[0] != StreamByte[RxPduId]))
            {
                StreamErrors++;
            }
            StreamNextSeq[RxPduId] = seq + 1U;
            StreamDelivered[RxPduId]++;
        }
        else
        {
            StreamErrors++;
        }
        return;
    }
    if (RxPduId == TEST_MAC_PDU_ID)
    {
        if (MacDeliveredCount < TEST_MAC_LOG)
        {
            MacDeliveredLen[MacDeliveredCount] = PduInfoPtr->SduLength;
            (void)memcpy(MacDelivered[MacDeliveredCount], PduInfoPtr->SduDataPtr,
                         (PduInfoPtr->SduLength < TEST_PAYLOAD_LEN) ? PduInfoPtr->SduLength : TEST_PAYLOAD_LEN);
        }
        MacDeliveredCount++;
        return;
    }
    if ((RxPduId == TEST_PDU_ID) && (DeliveredCount < (TEST_NUM_PDUS + TEST_EXTRA_PDUS)))
    {
        DeliveredLen[DeliveredCount] = PduInfoPtr->SduLength;
        (void)memcpy(Delivered[DeliveredCount], PduInfoPtr->SduDataPtr,
                     (PduInfoPtr->SduLength < TEST_PAYLOAD_LEN) ? PduInfoPtr->SduLength : TEST_PAYLOAD_LEN);
    }
    DeliveredCount++;
}

void __wrap_SecOC_VerificationStatusCallout(SecOC_VerificationStatusType verificationStatus)
{
    LastStatus = verificationStatus.verificationStatus;
    if (verificationStatus.secOCDataId == TEST_MAC_DATA_ID)
    {
        if (verificationStatus.verificationStatus == SECOC_VERIFICATIONSUCCESS)
        {
            MacStatusOk++;
        }
        else if (verificationStatus.verificationStatus == SECOC_FRESHNESSFAILURE)
        {
            MacStatusFreshnessFail++;
        }
        else
        {
            MacStatusAuthFail++;
        }
        return;
    }
    if (verificationStatus.verificationStatus == SECOC_VERIFICATIONSUCCESS)
    {
        StatusOk++;
    }
    else if (verificationStatus.verificationStatus == SECOC_FRESHNESSFAILURE)
    {
        StatusFreshnessFail++;
    }
    else
    {
        StatusAuthFail++;
    }
}

/* TcpIp replaced by an in-memory wire */
static TcpIp_SocketIdType NextSocketId = 0U;

Std_ReturnType __wrap_TcpIp_GetSocketId(TcpIp_DomainType Domain, TcpIp_ProtocolType Protocol, TcpIp_SocketIdType* SocketIdPtr)
{
    (void)Domain; (void)Protocol;
    *SocketIdPtr = NextSocketId;
    NextSocketId++;
    return E_OK;
}
Std_ReturnType __wrap_TcpIp_Bind(TcpIp_SocketIdType SocketId, TcpIp_LocalAddrIdType LocalAddrId, uint16* PortPtr)
{ (void)SocketId; (void)LocalAddrId; (void)PortPtr; return E_OK; }
/* [SWS_SoAd_00689]: the socket parameters SoAd asks for, in order */
#define TEST_PARAM_LOG         (256U)
static struct { TcpIp_SocketIdType Socket; TcpIp_ParamIdType Id; uint8 Value; } ParamLog[TEST_PARAM_LOG];
static uint32 ParamCalls = 0U;
static boolean FailChangeParameter = FALSE;     /* the stack cannot set the parameter */

Std_ReturnType __wrap_TcpIp_ChangeParameter(TcpIp_SocketIdType SocketId, TcpIp_ParamIdType ParameterId, const uint8* ParameterValue)
{
    if (ParamCalls < TEST_PARAM_LOG)
    {
        ParamLog[ParamCalls].Socket = SocketId;
        ParamLog[ParamCalls].Id = ParameterId;
        ParamLog[ParamCalls].Value = (ParameterValue != NULL) ? *ParameterValue : 0xFFU;
    }
    ParamCalls++;
    return (FailChangeParameter == TRUE) ? E_NOT_OK : E_OK;
}

/* how often a socket was asked for "Nagle's algorithm off" (TCPIP_PARAMID_TCP_NAGLE, value 0x00) */
static uint32 Test_NoDelayAsked(TcpIp_SocketIdType Socket)
{
    uint32 i;
    uint32 n = 0U;

    for (i = 0U; (i < ParamCalls) && (i < TEST_PARAM_LOG); i++)
    {
        if ((ParamLog[i].Socket == Socket) && (ParamLog[i].Id == TCPIP_PARAMID_TCP_NAGLE) && (ParamLog[i].Value == 0x00U))
        {
            n++;
        }
    }
    return n;
}

static uint32 ConnectCalls = 0U;
static uint32 ConnectsWithoutNoDelay = 0U;      /* a socket connected before it had been asked, or asked twice */

Std_ReturnType __wrap_TcpIp_TcpConnect(TcpIp_SocketIdType SocketId, const TcpIp_SockAddrType* RemoteAddrPtr)
{
    (void)RemoteAddrPtr;
    ConnectCalls++;
    if (Test_NoDelayAsked(SocketId) != 1U)
    {
        ConnectsWithoutNoDelay++;
    }
    return E_OK;
}
Std_ReturnType __wrap_TcpIp_TcpListen(TcpIp_SocketIdType SocketId, uint16 MaxChannels)
{ (void)SocketId; (void)MaxChannels; return E_OK; }
static uint32 ClosedCount = 0U;
static TcpIp_SocketIdType LastClosedSocket = 0U;
Std_ReturnType __wrap_TcpIp_Close(TcpIp_SocketIdType SocketId, boolean Abort)
{ (void)Abort; ClosedCount++; LastClosedSocket = SocketId; return E_OK; }

/* The receive direction of the wire: like the real TcpIp_MainFunction, each call reads at most one
 * chunk from the "socket" and hands it to SoAd. SoAd calls it only while it has room (flow control). */
static TcpIp_SocketIdType FeedSocket = 0U;
static const uint8* FeedData = NULL;
static uint32 FeedLength = 0U;
static uint32 FeedPos = 0U;
static uint32 FeedChunkSize = 0U;
static uint32 FeedLcg = 12345U;

void __wrap_TcpIp_MainFunction(void)
{
    TcpIp_SockAddrType peer;
    uint32 n = FeedChunkSize;

    if (FeedPos >= FeedLength)
    {
        return;
    }
    if (n == 0U)
    {
        FeedLcg = ((FeedLcg * 1103515245U) + 12345U) & 0x7FFFFFFFU;
        n = 1U + (FeedLcg % TCPIP_RX_BUFFER_SIZE);
    }
    if (n > (FeedLength - FeedPos))
    {
        n = FeedLength - FeedPos;
    }
    (void)memset(&peer, 0, sizeof(peer));
    peer.domain = TCPIP_AF_INET;
    SoAd_RxIndication(FeedSocket, &peer, &FeedData[FeedPos], (uint16)n);
    FeedPos += n;
}

static boolean FailTransmit = FALSE;     /* the next transmissions fail, as on a lost connection */

Std_ReturnType __wrap_TcpIp_TcpTransmit(TcpIp_SocketIdType SocketId, const uint8* DataPtr, uint32 AvailableLength, boolean ForceRetrieve)
{
    (void)SocketId; (void)ForceRetrieve;
    if ((FailTransmit == TRUE) || ((WireLen + AvailableLength) > sizeof(Wire)))
    {
        return E_NOT_OK;
    }
    (void)memcpy(&Wire[WireLen], DataPtr, AvailableLength);
    WireLen += AvailableLength;
    return E_OK;
}

/************************************************ helpers ************************************************/

static Std_ReturnType Test_LoadProvisionedKeys(uint8* publicKeyPtr, uint32 publicKeyLength,
                                               uint8* secretKeyPtr, uint32 secretKeyLength)
{
    if ((ProvisionedKey == NULL) || (publicKeyLength != sizeof(ProvisionedKey->PublicKey)) ||
        (secretKeyLength != sizeof(ProvisionedKey->SecretKey)))
    {
        return E_NOT_OK;
    }
    (void)memcpy(publicKeyPtr, ProvisionedKey->PublicKey, publicKeyLength);
    (void)memcpy(secretKeyPtr, ProvisionedKey->SecretKey, secretKeyLength);
    return E_OK;
}

static void Test_CsmIdentity(const PQC_MLDSA_KeyPairType* KeyPair)
{
    Csm_ConfigType cfg;
    cfg.CsmMldsaBootstrapMode = CSM_MLDSA_BOOTSTRAP_PROVISIONED;
    cfg.CsmLoadProvisionedMldsaKeysFct = Test_LoadProvisionedKeys;
    ProvisionedKey = KeyPair;
    Csm_Init(&cfg);
}

static void Test_Payload(uint8* Payload, uint32 Seq)
{
    (void)memset(Payload, 0, TEST_PAYLOAD_LEN);
    Payload[4] = (uint8)(Seq >> 24U);
    Payload[5] = (uint8)(Seq >> 16U);
    Payload[6] = (uint8)(Seq >> 8U);
    Payload[7] = (uint8)Seq;
}

static void Test_TransmitPdu(PduIdType PduId, uint32 Seq)
{
    uint8 payload[TEST_PAYLOAD_LEN];
    PduInfoType pdu;

    Test_Payload(payload, Seq);
    pdu.SduDataPtr = payload;
    pdu.MetaDataPtr = NULL;
    pdu.SduLength = TEST_PAYLOAD_LEN;
    (void)SecOC_TpTransmit(PduId, &pdu);
    SecOC_MainFunctionTx();
    SoAd_MainFunctionTx();
}

static void Test_Transmit(uint32 Seq)
{
    Test_TransmitPdu(TEST_PDU_ID, Seq);
}

/* receiver identity B, with the transmitter's public key provisioned as peer 0 */
static void Test_ReceiverIdentity(void)
{
    Test_CsmIdentity(&KeyB);
    (void)Csm_KeyElementSet(CSM_KEYID_PEER_PUBKEY_BASE, CSM_KEYELEMENT_MLDSA_PEER_PUBLIC,
                            KeyA.PublicKey, (uint32)sizeof(KeyA.PublicKey));
    (void)Csm_KeySetValid(CSM_KEYID_PEER_PUBKEY_BASE);
}

/* the configured peer address of this build, or (Configured == FALSE) another one */
static void Test_Peer(TcpIp_SockAddrType* Peer, boolean Configured)
{
    static const uint8 addr[4] = {
#ifdef SECOC_CFG_PEER_IPV4
        SECOC_CFG_PEER_IPV4
#else
        192U, 168U, 1U, 3U
#endif
    };
    (void)memset(Peer, 0, sizeof(*Peer));
    Peer->domain = TCPIP_AF_INET;
    (void)memcpy(Peer->addr, addr, sizeof(addr));
    if (Configured == FALSE)
    {
        Peer->addr[3] ^= 0x55U;
    }
}

static void Test_PutBe32(uint8* Ptr, uint32 Value)
{
    Ptr[0] = (uint8)(Value >> 24U);
    Ptr[1] = (uint8)(Value >> 16U);
    Ptr[2] = (uint8)(Value >> 8U);
    Ptr[3] = (uint8)Value;
}

static void Test_RxCycle(void)
{
    SoAd_MainFunctionRx();
    SecOC_MainFunctionRx();
    BswM_MainFunction();
}

/* BswM as in the running gateway: EcuM in RUN, full communication requested and granted, the AP
 * bridge ready. BswM then enables the normal routing group itself; nothing here calls
 * SoAd_EnableRouting. */
static void Test_StartBswM(boolean SecOCFailureDisablesRouting)
{
    BswM_ConfigType cfg;
    uint8 i;

    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.SecOCFailureDisablesRouting = SecOCFailureDisablesRouting;
    BswM_Deinit();
    BswM_Init(&cfg);
    (void)BswM_RequestMode((uint16)ECUM_MODULE_ID, (BswM_ModeType)ECUM_STATE_RUN);
    (void)BswM_RequestMode((uint16)COMM_MODULE_ID, (BswM_ModeType)COMM_FULL_COMMUNICATION);
    (void)BswM_RequestMode(BSWM_REQUESTER_ID_COMM_DESIRED, (BswM_ModeType)COMM_FULL_COMMUNICATION);
    /* SoAd reports the bridge state to BswM only when it changes */
    (void)SoAd_SetApBridgeState(SOAD_AP_BRIDGE_NOT_READY);
    (void)SoAd_SetApBridgeState(SOAD_AP_BRIDGE_READY);
    for (i = 0U; i < 10U; i++)
    {
        BswM_MainFunction();
    }
}

/* Run BSW cycles until the receiver has read Length bytes from the wire in chunks of ChunkSize. */
static void Test_Feed(TcpIp_SocketIdType Socket, const uint8* Data, uint32 Length, uint32 ChunkSize)
{
    uint32 cycles = 0U;
    uintptr_t negOffset = (uintptr_t)Data - (uintptr_t)NegWire;

    /* The negative cases compose their bytes with open-coded copies. A composition longer than
     * NegWire has already overwritten the variables behind it (it was the key pair in a Debug
     * build and a recording buffer in a Release build), so nothing after it can be trusted. */
    if ((negOffset <= sizeof(NegWire)) && ((negOffset + Length) > sizeof(NegWire)))
    {
        (void)printf("FAIL: %u bytes composed in NegWire, which holds %u: the test overwrote its own variables\n",
                     (unsigned)(negOffset + Length), (unsigned)sizeof(NegWire));
        exit(1);
    }

    FeedSocket = Socket;
    FeedData = Data;
    FeedLength = Length;
    FeedPos = 0U;
    FeedChunkSize = ChunkSize;

    while ((FeedPos < FeedLength) && (cycles < (2U * Length)))
    {
        Test_RxCycle();
        cycles++;
    }
    CHECK(FeedPos == FeedLength, "receiver stopped reading after %u of %u bytes", (unsigned)FeedPos, (unsigned)Length);
}

/* C5 / C6: five more PDUs a..e are signed; the receiver gets
 *   a | unknown header ID | PDU longer than SecOC accepts | b with a flipped signature bit |
 *   ... idle cycles ... | c | a again (replay) | d one byte short | e
 * BswM default: exactly a, c, e are delivered. BswM with SecOCFailureDisablesRouting (as found): a is
 * delivered, the failure of b closes the routing group, and c, a, d, e are discarded by SoAd. */
static void Test_RejectedPdus(TcpIp_SocketIdType Socket, uint32 FirstSeq, boolean Latch)
{
    uint32 wireStart = WireLen;
    uint32 deliveredBefore = DeliveredCount;
    uint32 okBefore = StatusOk;
    uint32 pduLen;
    uint32 n = 0U;
    uint32 part1;
    uint32 seq;
    uint32 i;
    uint32 dropped = 0U;
    const uint8* pdu;
    const uint32 expectSeq[3] = { FirstSeq, FirstSeq + 2U, FirstSeq + 4U };
    const uint32 expectDelivered = (Latch == TRUE) ? 1U : 3U;

    Test_CsmIdentity(&KeyA);
    for (seq = FirstSeq; seq < (FirstSeq + TEST_NEG_PDUS); seq++)
    {
        Test_Transmit(seq);
    }
    Test_ReceiverIdentity();
    pduLen = (WireLen - wireStart) / TEST_NEG_PDUS;
    pdu = &Wire[wireStart];
    if (pduLen <= 16U)
    {
        CHECK(FALSE, "the %u PDUs of the rejected-PDU case were not transmitted", (unsigned)TEST_NEG_PDUS);
        return;
    }

    (void)memcpy(&NegWire[n], &pdu[0U * pduLen], pduLen);               /* a */
    n += pduLen;
    Test_PutBe32(&NegWire[n], 0xDEADU);                                 /* unknown header ID, 5 bytes */
    Test_PutBe32(&NegWire[n + 4U], 5U);
    (void)memset(&NegWire[n + 8U], 0xEE, 5U);
    n += 13U;
    (void)memcpy(&NegWire[n], pdu, 4U);                                 /* known ID, 9000 bytes */
    Test_PutBe32(&NegWire[n + 4U], 9000U);
    (void)memset(&NegWire[n + 8U], 0xEE, 9000U);
    n += 9008U;
    (void)memcpy(&NegWire[n], &pdu[1U * pduLen], pduLen);               /* b, last signature bit flipped */
    n += pduLen;
    NegWire[n - 1U] ^= 0x01U;
    part1 = n;
    (void)memcpy(&NegWire[n], &pdu[2U * pduLen], pduLen);               /* c */
    n += pduLen;
    (void)memcpy(&NegWire[n], &pdu[0U * pduLen], pduLen);               /* a again */
    n += pduLen;
    (void)memcpy(&NegWire[n], &pdu[3U * pduLen], pduLen - 1U);          /* d, one byte short */
    Test_PutBe32(&NegWire[n + 4U], pduLen - 8U - 1U);
    n += pduLen - 1U;
    (void)memcpy(&NegWire[n], &pdu[4U * pduLen], pduLen);               /* e */
    n += pduLen;

    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK(dropped == 0U, "SoAd had dropped %u PDUs before the rejected-PDU case", (unsigned)dropped);
    StatusFreshnessFail = 0U;
    StatusAuthFail = 0U;

    /* up to the tampered PDU, then nothing for longer than BswM's failure threshold (5 cycles) */
    Test_Feed(Socket, NegWire, part1, 0U);
    for (i = 0U; i < 12U; i++)
    {
        Test_RxCycle();
    }
    CHECK(StatusAuthFail == 1U, "%u authentication failures reported after the tampered PDU, expected 1", (unsigned)StatusAuthFail);

    Test_Feed(Socket, &NegWire[part1], n - part1, 0U);
    Test_RxCycle();
    Test_RxCycle();

    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    if (Latch == TRUE)
    {
        CHECK(dropped == 6U, "SoAd dropped %u PDUs, expected 6 (unknown header ID, too long, and the 4 behind the tampered PDU)", (unsigned)dropped);
        CHECK(StatusAuthFail == 1U, "%u authentication failures reported, expected 1 (tampered)", (unsigned)StatusAuthFail);
        CHECK(StatusFreshnessFail == 0U, "%u freshness failures reported, expected 0", (unsigned)StatusFreshnessFail);
    }
    else
    {
        CHECK(dropped == 2U, "SoAd dropped %u PDUs, expected 2 (unknown header ID, too long)", (unsigned)dropped);
        CHECK(StatusAuthFail == 2U, "%u authentication failures reported, expected 2 (tampered, truncated)", (unsigned)StatusAuthFail);
        CHECK(StatusFreshnessFail == 1U, "%u freshness failures reported, expected 1 (replay)", (unsigned)StatusFreshnessFail);
    }
    CHECK((StatusOk - okBefore) == expectDelivered, "%u successful verifications reported, expected %u",
          (unsigned)(StatusOk - okBefore), (unsigned)expectDelivered);
    CHECK((DeliveredCount - deliveredBefore) == expectDelivered, "%u PDUs delivered, expected %u",
          (unsigned)(DeliveredCount - deliveredBefore), (unsigned)expectDelivered);
    for (seq = 0U; (seq < expectDelivered) && (seq < (DeliveredCount - deliveredBefore)); seq++)
    {
        uint8 expect[TEST_PAYLOAD_LEN];
        Test_Payload(expect, expectSeq[seq]);
        CHECK(memcmp(Delivered[deliveredBefore + seq], expect, TEST_PAYLOAD_LEN) == 0,
              "delivery %u after the rejected PDUs is not sequence number %u", (unsigned)seq, (unsigned)expectSeq[seq]);
    }
}

/* Sign one PDU and return its bytes on the wire (SoAd header included). */
static const uint8* Test_TransmitOne(uint32 Seq, uint32* LengthPtr)
{
    uint32 wireStart = WireLen;

    Test_CsmIdentity(&KeyA);
    Test_Transmit(Seq);
    Test_ReceiverIdentity();
    *LengthPtr = WireLen - wireStart;
    return &Wire[wireStart];
}

/* C6 [review 1.3]: PDUs that never reach the receiver bring the transmitter's counter to 509; then
 * x (510), y (511 = 0x1FF), z (512 = 0x200) are signed and the receiver gets
 *   x | y with a flipped signature bit | z | y
 * It must deliver x (a gap of about 190 lost PDUs) and z (although the PDU with low byte 0xFF was
 * rejected) and reject the late y as older than z. With 8 of 32 bits on the wire z was rejected. */
static void Test_FreshnessInFull(TcpIp_SocketIdType Socket, uint32 FirstSeq)
{
    uint32 wireStart = WireLen;
    uint32 deliveredBefore = DeliveredCount;
    uint32 pduLen;
    uint32 n = 0U;
    uint32 dropped = 0U;
    const uint8* pdu;

    Test_CsmIdentity(&KeyA);
    while (TxSigned < 509U)
    {
        Test_Transmit(0U);
        WireLen = wireStart;        /* lost on the way */
    }
    Test_Transmit(FirstSeq);
    Test_Transmit(FirstSeq + 1U);
    Test_Transmit(FirstSeq + 2U);
    Test_ReceiverIdentity();
    pduLen = (WireLen - wireStart) / 3U;
    pdu = &Wire[wireStart];
    if (pduLen <= 32U)
    {
        CHECK(FALSE, "the 3 PDUs of the freshness case were not transmitted");
        return;
    }
    /* complete counter on the wire, after SoAd header (8), SecOC header (1) and payload */
    CHECK(memcmp(&pdu[pduLen + 9U + TEST_PAYLOAD_LEN], "\x00\x00\x01\xFF", 4U) == 0,
          "freshness bytes of the second PDU on the wire are %02X %02X %02X %02X, expected 00 00 01 FF",
          pdu[pduLen + 17U], pdu[pduLen + 18U], pdu[pduLen + 19U], pdu[pduLen + 20U]);

    (void)memcpy(&NegWire[n], &pdu[0U], pduLen);                        /* x */
    n += pduLen;
    (void)memcpy(&NegWire[n], &pdu[pduLen], pduLen);                    /* y, last signature bit flipped */
    n += pduLen;
    NegWire[n - 1U] ^= 0x01U;
    (void)memcpy(&NegWire[n], &pdu[2U * pduLen], pduLen);               /* z */
    n += pduLen;
    (void)memcpy(&NegWire[n], &pdu[pduLen], pduLen);                    /* y, genuine but late */
    n += pduLen;

    StatusFreshnessFail = 0U;
    StatusAuthFail = 0U;
    Test_Feed(Socket, NegWire, n, 0U);
    Test_RxCycle();
    Test_RxCycle();

    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK(dropped == 0U, "SoAd dropped %u PDUs in the freshness case, expected 0", (unsigned)dropped);
    CHECK(StatusAuthFail == 1U, "%u authentication failures, expected 1 (tampered PDU with counter 0x1FF)", (unsigned)StatusAuthFail);
    CHECK(StatusFreshnessFail == 1U, "%u freshness failures, expected 1 (the late PDU with counter 0x1FF)", (unsigned)StatusFreshnessFail);
    CHECK((DeliveredCount - deliveredBefore) == 2U, "%u PDUs delivered, expected 2 (counters 510 and 512)",
          (unsigned)(DeliveredCount - deliveredBefore));
    if ((DeliveredCount - deliveredBefore) == 2U)
    {
        uint8 expect[TEST_PAYLOAD_LEN];
        Test_Payload(expect, FirstSeq);
        CHECK(memcmp(Delivered[deliveredBefore], expect, TEST_PAYLOAD_LEN) == 0, "first delivery is not the PDU with counter 510");
        Test_Payload(expect, FirstSeq + 2U);
        CHECK(memcmp(Delivered[deliveredBefore + 1U], expect, TEST_PAYLOAD_LEN) == 0, "second delivery is not the PDU with counter 512");
    }
}

/* A new connection after the previous one ended. Returns the socket the receiver reads from.
 * Listening side: the peer connects again. Connecting side: SoAd connects again with the next
 * transmit request, on the socket id TcpIp hands out next. */
static TcpIp_SocketIdType Test_NewConnection(void)
{
#if (SECOC_ROLE_RECEIVER == TRUE)
    TcpIp_SockAddrType peer;

    Test_Peer(&peer, TRUE);
    NextSocketId++;
    CHECK(SoAd_TcpAccepted(0U, NextSocketId, &peer) == E_OK, "a connection from the peer is not accepted after the previous one ended");
    CHECK(Test_NoDelayAsked(NextSocketId) == 1U, "the accepted socket %u was asked for TCP no-delay %u time(s), expected once",
          (unsigned)NextSocketId, (unsigned)Test_NoDelayAsked(NextSocketId));
#endif
    return NextSocketId;
}

/* C18 [SWS_SoAd_00689] item 3, [ECUC_SoAd_00023]: the request follows the configuration of the socket
 * connection. SoAd is initialised with a configuration of this test, so the case runs last. */
static void Test_TcpNoDelayConfig(void)
{
    static const SoAd_PduRouteConfigType route[1] =
    {
        { (PduIdType)SECOC_PDUID_SIG(0U), SOAD_PDU_ROUTE_TP, (SoAd_RoutingGroupIdType)0U, SOAD_HEADERID_SIG(0U),
          0U, SOAD_UPPER_LAYER_PDUR, 0U, 0U, FALSE }
    };
    static const struct { SoAd_TcpNoDelayType Config; uint32 Calls; uint8 Value; const char* Name; } cases[3] =
    {
        { SOAD_TCP_NODELAY_TRUE, 1U, 0x00U, "TRUE" },
        { SOAD_TCP_NODELAY_FALSE, 1U, 0x01U, "FALSE" },
        { SOAD_TCP_NODELAY_ABSENT, 0U, 0x00U, "absent" }
    };
    static SoAd_SoConConfigType soCon;      /* SoAd keeps the pointer */
    SoAd_ConfigType config;
    uint32 c;

    for (c = 0U; c < 3U; c++)
    {
        const uint32 callsBefore = ParamCalls;
        TcpIp_SocketIdType sock;

        (void)memset(&soCon, 0, sizeof(soCon));
        soCon.SoAdTxPduId = (PduIdType)SECOC_PDUID_SIG(0U);
        soCon.SoAdProtocol = TCPIP_IPPROTO_TCP;
        Test_Peer(&soCon.SoAdRemoteAddr, TRUE);
        soCon.SoAdRemoteAddr.port = 50002U;
        soCon.SoAdInitialMode = SOAD_SOCON_ONLINE;
        soCon.SoAdSocketTcpNoDelay = cases[c].Config;
        (void)memset(&config, 0, sizeof(config));
        config.SoAdPduRouteConfigPtr = route;
        config.SoAdPduRouteConfigCount = 1U;
        config.SoAdSoConConfigPtr = &soCon;
        config.SoAdSoConConfigCount = 1U;

#if (SECOC_ROLE_RECEIVER == TRUE)
        {
            /* SoAd listens on the socket id TcpIp hands out next; the test accepts a connection on a further one */
            const TcpIp_SocketIdType listening = NextSocketId;
            TcpIp_SockAddrType peer;

            soCon.SoAdLocalPort = 50002U;
            SoAd_Init(&config);
            Test_Peer(&peer, TRUE);
            NextSocketId++;
            sock = NextSocketId;
            CHECK(SoAd_TcpAccepted(listening, sock, &peer) == E_OK, "SoAdSocketTcpNoDelay %s: the connection was not accepted", cases[c].Name);
        }
#else
        /* SoAd connects in SoAd_Init, on the socket id TcpIp hands out next */
        sock = NextSocketId;
        SoAd_Init(&config);
#endif
        CHECK((ParamCalls - callsBefore) == cases[c].Calls, "SoAdSocketTcpNoDelay %s: %u parameter request(s), expected %u",
              cases[c].Name, (unsigned)(ParamCalls - callsBefore), (unsigned)cases[c].Calls);
        if ((cases[c].Calls == 1U) && (ParamCalls > callsBefore) && (ParamCalls <= TEST_PARAM_LOG))
        {
            CHECK((ParamLog[ParamCalls - 1U].Socket == sock) && (ParamLog[ParamCalls - 1U].Id == TCPIP_PARAMID_TCP_NAGLE) &&
                  (ParamLog[ParamCalls - 1U].Value == cases[c].Value),
                  "SoAdSocketTcpNoDelay %s: asked socket %u for (id 0x%02X, value 0x%02X); expected socket %u, (TCPIP_PARAMID_TCP_NAGLE, 0x%02X)",
                  cases[c].Name, (unsigned)ParamLog[ParamCalls - 1U].Socket, (unsigned)ParamLog[ParamCalls - 1U].Id,
                  (unsigned)ParamLog[ParamCalls - 1U].Value, (unsigned)sock, (unsigned)cases[c].Value);
        }
    }
}

/* C19 [review of the as-found receive paths]: CanIf forwards a frame to SecOC only for a PDU that is routed
 * over CAN. A frame with the ID of an Ethernet row is dropped: forwarded, as found, it overwrote the start
 * and the length of that row's secured-PDU buffer and marked it received. */
static void Test_CanFrameOnEthernetRow(TcpIp_SocketIdType Socket, uint32 Seq)
{
    static uint8 frame[8] = { 0xC0U, 0xC1U, 0xC2U, 0xC3U, 0xC4U, 0xC5U, 0xC6U, 0xC7U };
    PduInfoType* ethBuf = &(SecOCRxPduProcessing[TEST_PDU_ID].SecOCRxSecuredPduLayer->SecOCRxSecuredPdu->SecOCRxSecuredLayerPduRef);
    PduInfoType* canBuf = &(SecOCRxPduProcessing[0].SecOCRxSecuredPduLayer->SecOCRxSecuredPdu->SecOCRxSecuredLayerPduRef);
    PduInfoType can;
    const uint8* pdu;
    uint32 pduLen = 0U;
    uint32 deliveredBefore = DeliveredCount;
    uint32 failuresBefore;
    PduLengthType lengthBefore;
    uint8 before[sizeof(frame)];

    CanIf_Init();
    can.SduDataPtr = frame;
    can.MetaDataPtr = NULL;
    can.SduLength = (PduLengthType)sizeof(frame);

    /* nothing is being received on the Ethernet row: its buffer and length stay as they are, and nothing
     * of it is verified in the cycles that follow */
    (void)memcpy(before, ethBuf->SduDataPtr, sizeof(before));
    lengthBefore = ethBuf->SduLength;
    failuresBefore = StatusAuthFail + StatusFreshnessFail;
    CanIf_RxIndication(TEST_PDU_ID, &can);
    CHECK((ethBuf->SduLength == lengthBefore) && (memcmp(before, ethBuf->SduDataPtr, sizeof(before)) == 0),
          "a CAN frame with the ID of the Ethernet row changed that row's secured-PDU buffer (length %u, was %u)",
          (unsigned)ethBuf->SduLength, (unsigned)lengthBefore);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((StatusAuthFail + StatusFreshnessFail) == failuresBefore,
          "a CAN frame with the ID of the Ethernet row was taken for a received PDU of that row (%u status report(s))",
          (unsigned)((StatusAuthFail + StatusFreshnessFail) - failuresBefore));

    /* the frame arrives in the middle of the TCP reception of that row's PDU: the PDU is delivered */
    pdu = Test_TransmitOne(Seq, &pduLen);
    CHECK(pduLen > 200U, "no PDU of the Ethernet row was transmitted (%u bytes)", (unsigned)pduLen);
    if (pduLen > 200U)
    {
        Test_Feed(Socket, pdu, 100U, 0U);
        CanIf_RxIndication(TEST_PDU_ID, &can);
        Test_Feed(Socket, &pdu[100], pduLen - 100U, 0U);
        Test_RxCycle();
        Test_RxCycle();
    }
    CHECK((DeliveredCount - deliveredBefore) == 1U,
          "the Ethernet PDU was not delivered after a CAN frame with its row's ID arrived during its reception");
    CHECK((StatusAuthFail + StatusFreshnessFail) == failuresBefore, "%u verification failure(s) reported for that PDU",
          (unsigned)((StatusAuthFail + StatusFreshnessFail) - failuresBefore));

    /* a PDU that is routed over CAN still receives: the frame is in row 0's buffer. (Eight arbitrary bytes
     * are no Secured I-PDU of that row; SecOC disposes of them in the cycles below.) */
    CanIf_RxIndication(0U, &can);
    CHECK((canBuf->SduLength == (PduLengthType)sizeof(frame)) && (memcmp(canBuf->SduDataPtr, frame, sizeof(frame)) == 0),
          "a CAN frame with the ID of a CAN row did not reach SecOC (%u bytes in the row's buffer)", (unsigned)canBuf->SduLength);
    Test_RxCycle();
    Test_RxCycle();
}

/* C17 [SWS_SoAd_00689] item 3, [ECUC_SoAd_00023] */
static TcpIp_SocketIdType Test_TcpNoDelay(TcpIp_SocketIdType Socket, uint32 Seq)
{
    const uint8* pdu;
    uint32 pduLen = 0U;
    uint32 deliveredBefore = DeliveredCount;
    uint32 closedBefore;
    uint32 other = 0U;
    uint32 i;
    TcpIp_SocketIdType refused;

    /* Up to here: SoAdSocketTcpNoDelay is TRUE in the default configuration, so every request SoAd made is
     * the Nagle parameter with the value 0x00; no socket was connected before it had been asked; the socket
     * in use was asked once. */
    for (i = 0U; (i < ParamCalls) && (i < TEST_PARAM_LOG); i++)
    {
        if ((ParamLog[i].Id != TCPIP_PARAMID_TCP_NAGLE) || (ParamLog[i].Value != 0x00U))
        {
            other++;
        }
    }
    CHECK((ParamCalls > 0U) && (ParamCalls <= TEST_PARAM_LOG) && (other == 0U),
          "%u socket parameter request(s), %u of them not (TCPIP_PARAMID_TCP_NAGLE, 0x00)", (unsigned)ParamCalls, (unsigned)other);
    CHECK(ConnectsWithoutNoDelay == 0U, "%u TCP connect(s) on a socket that had not been asked for no-delay exactly once before",
          (unsigned)ConnectsWithoutNoDelay);
    CHECK(Test_NoDelayAsked(Socket) == 1U, "the socket in use (%u) was asked for TCP no-delay %u time(s), expected once",
          (unsigned)Socket, (unsigned)Test_NoDelayAsked(Socket));
#if (SECOC_ROLE_RECEIVER == TRUE)
    CHECK(Test_NoDelayAsked(0U) == 0U, "the listening socket was asked; the accepted socket is the one that carries the data");
#endif

    /* A socket that cannot be given the parameter is not used: an accepted connection is refused, a
     * connecting socket is closed without a connect. */
    SoAd_TcpIpEvent(Socket, TCPIP_TCP_CLOSED);
    Test_RxCycle();
    Test_RxCycle();
    closedBefore = ClosedCount;
    FailChangeParameter = TRUE;
#if (SECOC_ROLE_RECEIVER == TRUE)
    {
        TcpIp_SockAddrType peer;

        Test_Peer(&peer, TRUE);
        NextSocketId++;
        refused = NextSocketId;
        CHECK(SoAd_TcpAccepted(0U, refused, &peer) == E_NOT_OK, "a connection was accepted although its socket could not be set");
        (void)closedBefore;
    }
#else
    {
        uint32 connectsBefore = ConnectCalls;

        refused = NextSocketId;
        CHECK(SoAd_OpenSoCon(0U) == E_NOT_OK, "the socket connection was opened although its socket could not be set");
        CHECK((ConnectCalls == connectsBefore) && (ClosedCount == (closedBefore + 1U)) && (LastClosedSocket == refused),
              "a socket that could not be set: %u connect(s), %u close(s), last closed socket %u; expected 0, 1 and socket %u",
              (unsigned)(ConnectCalls - connectsBefore), (unsigned)(ClosedCount - closedBefore), (unsigned)LastClosedSocket,
              (unsigned)refused);
    }
#endif
    FailChangeParameter = FALSE;
    CHECK(Test_NoDelayAsked(refused) == 1U, "the socket that could not be set (%u) was asked %u time(s), expected once",
          (unsigned)refused, (unsigned)Test_NoDelayAsked(refused));

    /* the next connection is taken and carries a PDU */
    Socket = Test_NewConnection();
    pdu = Test_TransmitOne(Seq, &pduLen);
    CHECK(pduLen > 32U, "nothing was transmitted on the connection after the refused one");
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((DeliveredCount - deliveredBefore) == 1U, "the PDU on the connection after the refused one was not delivered");
    CHECK(Test_NoDelayAsked(Socket) == 1U, "the socket of the new connection (%u) was asked %u time(s), expected once",
          (unsigned)Socket, (unsigned)Test_NoDelayAsked(Socket));
    return Socket;
}

/* C7 [review 1.2, 1.4, 1.7, 2.13] */
static TcpIp_SocketIdType Test_Connections(TcpIp_SocketIdType Socket, uint32 FirstSeq)
{
    TcpIp_SockAddrType peer;
    const uint8* pdu;
    uint32 pduLen = 0U;
    uint32 dropped = 0U;
    uint32 deliveredBefore = DeliveredCount;
    uint32 closedBefore;
    uint8 header[8];

    /* a second connection while the stream is active is refused, and the stream goes on */
    Test_Peer(&peer, TRUE);
    CHECK(SoAd_TcpAccepted(0U, (TcpIp_SocketIdType)(NextSocketId + 1U), &peer) == E_NOT_OK,
          "a second TCP connection was accepted while the first is active");
    pdu = Test_TransmitOne(FirstSeq, &pduLen);
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((DeliveredCount - deliveredBefore) == 1U, "the PDU after a refused second connection was not delivered");

    /* the connection closes inside a PDU: that PDU ends, counted, nothing delivered */
    pdu = Test_TransmitOne(FirstSeq + 1U, &pduLen);
    Test_Feed(Socket, pdu, 100U, 0U);
    SoAd_TcpIpEvent(Socket, TCPIP_TCP_CLOSED);
    Test_RxCycle();
    Test_RxCycle();
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK(dropped == 1U, "%u drops counted for a PDU cut off by the end of the connection, expected 1", (unsigned)dropped);
    CHECK((DeliveredCount - deliveredBefore) == 1U, "a PDU cut off by the end of the connection was delivered");

#if (SECOC_ROLE_RECEIVER == TRUE)
    /* only the configured peer address may connect */
    Test_Peer(&peer, FALSE);
    CHECK(SoAd_TcpAccepted(0U, (TcpIp_SocketIdType)(NextSocketId + 1U), &peer) == E_NOT_OK,
          "a TCP connection from another address than the configured peer was accepted");
#endif

    /* a new connection carries PDUs again */
    Socket = Test_NewConnection();
    pdu = Test_TransmitOne(FirstSeq + 2U, &pduLen);
    CHECK(pduLen > 32U, "nothing was transmitted on the new connection");
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((DeliveredCount - deliveredBefore) == 2U, "the PDU on the new connection was not delivered");

    /* a header whose length cannot be a PDU: counted, and the connection is closed */
    closedBefore = ClosedCount;
    Test_PutBe32(&header[0], SOAD_HEADERID_SIG(0U));
    Test_PutBe32(&header[4], 0xFFFFFFFFU);
    Test_Feed(Socket, header, sizeof(header), 0U);
    Test_RxCycle();
    Test_RxCycle();
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK(dropped == 1U, "%u drops counted for a header with length 0xFFFFFFFF, expected 1", (unsigned)dropped);
    CHECK((ClosedCount == (closedBefore + 1U)) && (LastClosedSocket == Socket),
          "the connection was not closed after a header with length 0xFFFFFFFF (%u closes, last socket %u, expected socket %u)",
          (unsigned)(ClosedCount - closedBefore), (unsigned)LastClosedSocket, (unsigned)Socket);

    Socket = Test_NewConnection();
    pdu = Test_TransmitOne(FirstSeq + 3U, &pduLen);
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((DeliveredCount - deliveredBefore) == 3U, "the PDU after the closed connection was not delivered");
    return Socket;
}

/************************************ stand-in for the handshake layer ************************************/

static uint8  HsRx[SOAD_HS_M2_LENGTH];
static uint32 HsRxLen = 0U;
static uint32 HsRxStarted = 0U;
static uint32 HsRxDone = 0U;
static boolean HsRxInProgress = FALSE;
static PduIdType HsRxLastId = 0U;
static uint32 HsTxConfirmed = 0U;
static uint32 HsTxFailed = 0U;
static uint32 HsOnline = 0U;
static uint32 HsOffline = 0U;

static BufReq_ReturnType TestHs_StartOfReception(PduIdType id, const PduInfoType* info, PduLengthType TpSduLength, PduLengthType* bufferSizePtr)
{
    (void)info;
    HsRxStarted++;
    HsRxLastId = id;
    HsRxLen = 0U;
    HsRxInProgress = TRUE;
    *bufferSizePtr = (PduLengthType)sizeof(HsRx);
    return (TpSduLength <= sizeof(HsRx)) ? BUFREQ_OK : BUFREQ_E_NOT_OK;
}
static BufReq_ReturnType TestHs_CopyRxData(PduIdType id, const PduInfoType* info, PduLengthType* bufferSizePtr)
{
    (void)id;
    if ((HsRxLen + info->SduLength) > sizeof(HsRx))
    {
        return BUFREQ_E_NOT_OK;
    }
    if (info->SduLength > 0U)
    {
        (void)memcpy(&HsRx[HsRxLen], info->SduDataPtr, info->SduLength);
        HsRxLen += info->SduLength;
    }
    /* between two PDUs the whole buffer is free again (SoAd asks before it starts the next one) */
    *bufferSizePtr = (PduLengthType)((HsRxInProgress == TRUE) ? (sizeof(HsRx) - HsRxLen) : sizeof(HsRx));
    return BUFREQ_OK;
}
static void TestHs_RxIndication(PduIdType id, Std_ReturnType result)
{
    (void)id;
    HsRxInProgress = FALSE;
    if (result == E_OK)
    {
        HsRxDone++;
    }
}
/* transmitted bytes: a pattern that depends on the PDU and on the position */
static uint32 HsTxPos = 0U;
static boolean HsTxBusyOnce = FALSE;    /* not ready once, after the first chunk of a PDU */
static BufReq_ReturnType TestHs_CopyTxData(PduIdType id, const PduInfoType* info, const RetryInfoType* retry, PduLengthType* availableDataPtr)
{
    PduLengthType i;
    (void)retry;
    if ((HsTxBusyOnce == TRUE) && (HsTxPos > 0U))
    {
        HsTxBusyOnce = FALSE;
        return BUFREQ_E_BUSY;
    }
    for (i = 0U; i < info->SduLength; i++)
    {
        info->SduDataPtr[i] = (uint8)(id + HsTxPos);
        HsTxPos++;
    }
    *availableDataPtr = 0U;
    return BUFREQ_OK;
}
static void TestHs_TxConfirmation(PduIdType id, Std_ReturnType result)
{
    (void)id;
    HsTxPos = 0U;
    if (result == E_OK) { HsTxConfirmed++; } else { HsTxFailed++; }
}
static void TestHs_SoConModeChg(SoAd_SoConIdType SoConId, SoAd_SoConModeType Mode)
{
    (void)SoConId;
    if (Mode == SOAD_SOCON_ONLINE) { HsOnline++; } else { HsOffline++; }
}
static const SoAd_UpperLayerType TestHs_Layer =
{
    TestHs_StartOfReception, TestHs_CopyRxData, TestHs_RxIndication, TestHs_CopyTxData, TestHs_TxConfirmation, TestHs_SoConModeChg
};

/* a handshake-layer PDU on the wire: header and a payload of Length bytes filled with Fill */
static uint32 Test_HsPdu(uint8* Out, uint32 HeaderId, uint32 Length, uint8 Fill)
{
    Test_PutBe32(&Out[0], HeaderId);
    Test_PutBe32(&Out[4], Length);
    (void)memset(&Out[8], Fill, Length);
    return 8U + Length;
}

/* C8 [T4c]: a second upper layer on the connection */
static TcpIp_SocketIdType Test_SecondUpperLayer(TcpIp_SocketIdType Socket, uint32 FirstSeq)
{
    const uint8* pdu;
    uint32 pduLen = 0U;
    uint32 n;
    uint32 i;
    uint32 dropped = 0U;
    uint32 deliveredBefore = DeliveredCount;
    uint32 wireBefore;
    PduInfoType txInfo;

    /* not bound yet: its header IDs are discarded like unknown ones, its transmit request is refused */
    n = Test_HsPdu(NegWire, SOAD_HEADERID_HS_M1, SOAD_HS_M1_LENGTH, 0xA1U);
    Test_Feed(Socket, NegWire, n, 0U);
    Test_RxCycle();
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK(dropped == 1U, "%u drops for a PDU whose upper layer is not bound, expected 1", (unsigned)dropped);
    txInfo.SduDataPtr = NULL;
    txInfo.MetaDataPtr = NULL;
    txInfo.SduLength = SOAD_HS_M4_LENGTH;
    CHECK(SoAd_TpTransmit((PduIdType)SOAD_PDUID_HS_M4, &txInfo) == E_NOT_OK, "a transmit request for an unbound upper layer was accepted");

    /* binding reports the connection that is already up */
    CHECK(SoAd_SetUpperLayer(SOAD_UPPER_LAYER_HS, &TestHs_Layer) == E_OK, "SoAd_SetUpperLayer failed");
    CHECK((HsOnline == 1U) && (HsOffline == 0U), "mode changes after binding: %u online, %u offline, expected 1, 0", (unsigned)HsOnline, (unsigned)HsOffline);

    /* M1 with its length is delivered to the layer, byte for byte; with another length it is discarded */
    n = Test_HsPdu(NegWire, SOAD_HEADERID_HS_M1, SOAD_HS_M1_LENGTH, 0xA1U);
    n += Test_HsPdu(&NegWire[n], SOAD_HEADERID_HS_M1, SOAD_HS_M1_LENGTH - 1U, 0xA2U);
    Test_Feed(Socket, NegWire, n, 0U);
    Test_RxCycle();
    Test_RxCycle();
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK((HsRxStarted == 1U) && (HsRxDone == 1U) && (HsRxLastId == (PduIdType)SOAD_PDUID_HS_M1) && (HsRxLen == SOAD_HS_M1_LENGTH),
          "handshake PDU M1: %u started, %u completed, id %u, %u bytes", (unsigned)HsRxStarted, (unsigned)HsRxDone, (unsigned)HsRxLastId, (unsigned)HsRxLen);
    for (i = 0U; (i < HsRxLen) && (HsRx[i] == 0xA1U); i++) { }
    CHECK(i == SOAD_HS_M1_LENGTH, "handshake PDU M1 payload differs at byte %u", (unsigned)i);
    CHECK(dropped == 1U, "%u drops for a handshake PDU with a wrong length, expected 1", (unsigned)dropped);

    /* gate: M3, then a Secured I-PDU in the same segment. The Secured I-PDU is not touched until release. */
    pdu = Test_TransmitOne(FirstSeq, &pduLen);
    n = Test_HsPdu(NegWire, SOAD_HEADERID_HS_M3, SOAD_HS_M3_LENGTH, 0xA3U);
    (void)memcpy(&NegWire[n], pdu, pduLen);
    n += pduLen;
    Test_Feed(Socket, NegWire, n, 0U);
    for (i = 0U; i < 6U; i++)
    {
        Test_RxCycle();
    }
    CHECK((HsRxDone == 2U) && (HsRxLastId == (PduIdType)SOAD_PDUID_HS_M3), "the gated PDU M3 was not delivered to its upper layer");
    CHECK(DeliveredCount == deliveredBefore, "a Secured I-PDU behind the gated PDU was processed before the gate was released");
    SoAd_RxGateRelease((PduIdType)SOAD_PDUID_HS_M3);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((DeliveredCount - deliveredBefore) == 1U, "the Secured I-PDU behind the gate was not delivered after the release");

    /* transmissions of both layers, whole and in request order: M4 is requested first, then a Secured
     * I-PDU (whose PDU ID is the lower one), in one cycle */
    wireBefore = WireLen;
    Test_CsmIdentity(&KeyA);
    txInfo.SduLength = SOAD_HS_M4_LENGTH;
    CHECK(SoAd_TpTransmit((PduIdType)SOAD_PDUID_HS_M4, &txInfo) == E_OK, "the transmit request of the second upper layer was refused");
    Test_Transmit(FirstSeq + 1U);
    Test_ReceiverIdentity();
    CHECK(HsTxConfirmed == 1U, "%u transmissions confirmed to the second upper layer, expected 1", (unsigned)HsTxConfirmed);
    CHECK((WireLen - wireBefore) == (8U + SOAD_HS_M4_LENGTH + pduLen), "%u bytes on the wire for M4 and one Secured I-PDU, expected %u",
          (unsigned)(WireLen - wireBefore), (unsigned)(8U + SOAD_HS_M4_LENGTH + pduLen));
    if ((WireLen - wireBefore) == (8U + SOAD_HS_M4_LENGTH + pduLen))
    {
        uint8 expectHeader[8];
        Test_PutBe32(&expectHeader[0], SOAD_HEADERID_HS_M4);
        Test_PutBe32(&expectHeader[4], SOAD_HS_M4_LENGTH);
        CHECK(memcmp(&Wire[wireBefore], expectHeader, 8U) == 0, "the PDU requested first (M4) is not first on the wire");
        for (i = 0U; (i < SOAD_HS_M4_LENGTH) && (Wire[wireBefore + 8U + i] == (uint8)(SOAD_PDUID_HS_M4 + i)); i++) { }
        CHECK(i == SOAD_HS_M4_LENGTH, "M4 payload on the wire differs at byte %u", (unsigned)i);
        /* the Secured I-PDU behind it is intact: the receiver delivers it */
        Test_Feed(Socket, &Wire[wireBefore + 8U + SOAD_HS_M4_LENGTH], pduLen, 0U);
        Test_RxCycle();
        Test_RxCycle();
        CHECK((DeliveredCount - deliveredBefore) == 2U, "the Secured I-PDU transmitted behind M4 was not delivered");
    }

    /* a PDU longer than one transmit chunk (M2) whose upper layer is not ready after the first chunk,
     * while a Secured I-PDU waits: M2 is finished first, whole, then the Secured I-PDU */
    wireBefore = WireLen;
    Test_CsmIdentity(&KeyA);
    HsTxBusyOnce = TRUE;
    txInfo.SduLength = SOAD_HS_M2_LENGTH;
    CHECK(SoAd_TpTransmit((PduIdType)SOAD_PDUID_HS_M2, &txInfo) == E_OK, "the transmit request for M2 was refused");
    Test_Transmit(FirstSeq + 4U);
    CHECK((WireLen - wireBefore) == 4096U, "%u bytes on the wire after the first chunk of M2 with its upper layer busy, expected 4096",
          (unsigned)(WireLen - wireBefore));
    SoAd_MainFunctionTx();
    Test_ReceiverIdentity();
    CHECK(HsTxConfirmed == 2U, "%u transmissions confirmed to the second upper layer, expected 2", (unsigned)HsTxConfirmed);
    CHECK((WireLen - wireBefore) == (8U + SOAD_HS_M2_LENGTH + pduLen), "%u bytes on the wire for M2 and one Secured I-PDU, expected %u",
          (unsigned)(WireLen - wireBefore), (unsigned)(8U + SOAD_HS_M2_LENGTH + pduLen));
    if ((WireLen - wireBefore) == (8U + SOAD_HS_M2_LENGTH + pduLen))
    {
        uint8 expectHeader[8];
        Test_PutBe32(&expectHeader[0], SOAD_HEADERID_HS_M2);
        Test_PutBe32(&expectHeader[4], SOAD_HS_M2_LENGTH);
        CHECK(memcmp(&Wire[wireBefore], expectHeader, 8U) == 0, "M2 does not start with its header");
        for (i = 0U; (i < SOAD_HS_M2_LENGTH) && (Wire[wireBefore + 8U + i] == (uint8)(SOAD_PDUID_HS_M2 + i)); i++) { }
        CHECK(i == SOAD_HS_M2_LENGTH, "M2 is not whole on the wire: its payload differs at byte %u", (unsigned)i);
        Test_Feed(Socket, &Wire[wireBefore + 8U + SOAD_HS_M2_LENGTH], pduLen, 0U);
        Test_RxCycle();
        Test_RxCycle();
        CHECK((DeliveredCount - deliveredBefore) == 3U, "the Secured I-PDU transmitted behind M2 was not delivered");
    }

    /* a transmit request that waits when the connection ends is ended with it, and does not go out on
     * the next connection; a fresh request does */
    txInfo.SduLength = SOAD_HS_M4_LENGTH;
    CHECK(SoAd_TpTransmit((PduIdType)SOAD_PDUID_HS_M4, &txInfo) == E_OK, "the transmit request for M4 was refused");
    SoAd_TcpIpEvent(Socket, TCPIP_TCP_CLOSED);
    Test_RxCycle();
    CHECK(HsTxFailed == 1U, "%u failed transmissions reported for a request whose connection ended, expected 1", (unsigned)HsTxFailed);
    CHECK(HsOffline == 1U, "%u offline mode changes, expected 1", (unsigned)HsOffline);
#if (SECOC_ROLE_RECEIVER == TRUE)
    CHECK(SoAd_TpTransmit((PduIdType)SOAD_PDUID_HS_M4, &txInfo) == E_NOT_OK, "a transmit request was accepted on the listening side without a connection");
#endif
    wireBefore = WireLen;
    Socket = Test_NewConnection();
    CHECK(SoAd_TpTransmit((PduIdType)SOAD_PDUID_HS_M4, &txInfo) == E_OK, "a fresh transmit request was refused after the connection ended");
    SoAd_MainFunctionTx();
    SoAd_MainFunctionTx();
    CHECK((WireLen - wireBefore) == (8U + SOAD_HS_M4_LENGTH), "%u bytes on the new connection, expected one M4 (%u)",
          (unsigned)(WireLen - wireBefore), (unsigned)(8U + SOAD_HS_M4_LENGTH));
    CHECK(HsOnline == 2U, "%u online mode changes, expected 2 (binding, new connection)", (unsigned)HsOnline);

    /* gate shut and the peer closes: the stream ends at once, nothing behind the gate is delivered */
    pdu = Test_TransmitOne(FirstSeq + 2U, &pduLen);
    n = Test_HsPdu(NegWire, SOAD_HEADERID_HS_M3, SOAD_HS_M3_LENGTH, 0xA3U);
    (void)memcpy(&NegWire[n], pdu, pduLen);
    n += pduLen;
    Test_Feed(Socket, NegWire, n, 0U);
    Test_RxCycle();
    Test_RxCycle();
    SoAd_TcpIpEvent(Socket, TCPIP_TCP_CLOSED);
    Test_RxCycle();
    CHECK(HsOffline == 2U, "%u offline mode changes after the peer closed behind a shut gate, expected 2", (unsigned)HsOffline);
    CHECK((DeliveredCount - deliveredBefore) == 3U, "a Secured I-PDU behind a shut gate was delivered after the connection ended");
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);

    /* the next connection is reported and starts with an open gate */
    Socket = Test_NewConnection();
    pdu = Test_TransmitOne(FirstSeq + 3U, &pduLen);
    CHECK(HsOnline == 3U, "%u online mode changes, expected 3 (binding, two new connections)", (unsigned)HsOnline);
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((DeliveredCount - deliveredBefore) == 4U, "the Secured I-PDU on the connection after a shut gate was not delivered");
    return Socket;
}

/* C9 [T4c]: four signature streams on the one connection */
#define TEST_STREAMS            (4U)
#define TEST_STREAM_ROUNDS      (6U)    /* PDUs per stream in each segmentation */

static void Test_StreamRequest(uint32 Stream, uint32 Seq)
{
    uint8 payload[TEST_PAYLOAD_LEN];
    PduInfoType pdu;

    Test_Payload(payload, Seq);
    payload[0] = (uint8)Stream;
    pdu.SduDataPtr = payload;
    pdu.MetaDataPtr = NULL;
    pdu.SduLength = TEST_PAYLOAD_LEN;
    (void)SecOC_TpTransmit((PduIdType)SECOC_PDUID_SIG(Stream), &pdu);
}

static void Test_Streams(TcpIp_SocketIdType Socket)
{
    const uint32 perSegment = TEST_STREAMS * TEST_STREAM_ROUNDS;
    uint32 seg;
    uint32 round;
    uint32 st;
    uint32 i;
    uint32 pduLen;
    uint32 n = 0U;
    uint32 dropped = 0U;
    uint32 wrongOrder = 0U;
    const uint8* extra;

    /* the wire buffer is free: every earlier case has consumed what it put there */
    WireLen = 0U;
    Test_CsmIdentity(&KeyA);
    for (seg = 0U; seg < TEST_SEGMENTS; seg++)
    {
        for (round = 0U; round < TEST_STREAM_ROUNDS; round++)
        {
            /* the four streams submit in the same cycle; SoAd sends them in that order, each whole */
            for (st = 0U; st < TEST_STREAMS; st++)
            {
                Test_StreamRequest(st, (seg * TEST_STREAM_ROUNDS) + round);
            }
            SecOC_MainFunctionTx();
            SoAd_MainFunctionTx();
        }
    }
    pduLen = WireLen / (TEST_SEGMENTS * perSegment);
    CHECK((pduLen > 32U) && (WireLen == (pduLen * TEST_SEGMENTS * perSegment)),
          "%u bytes on the wire for %u PDUs of %u streams", (unsigned)WireLen, (unsigned)(TEST_SEGMENTS * perSegment), (unsigned)TEST_STREAMS);
    if (pduLen <= 32U)
    {
        return;
    }
    for (i = 0U; i < (TEST_SEGMENTS * perSegment); i++)
    {
        uint8 expectHeader[4];
        Test_PutBe32(expectHeader, SOAD_HEADERID_SIG(i % TEST_STREAMS));
        if (memcmp(&Wire[i * pduLen], expectHeader, 4U) != 0)
        {
            wrongOrder++;
        }
    }
    CHECK(wrongOrder == 0U, "%u PDUs on the wire are not in the order the streams requested them (header IDs 0x10..0x13 in turn)", (unsigned)wrongOrder);

    /* two more PDUs per stream for the disturbance round: sequence numbers 42 and 43 */
    extra = &Wire[WireLen];
    for (round = 0U; round < 2U; round++)
    {
        for (st = 0U; st < TEST_STREAMS; st++)
        {
            Test_StreamRequest(st, (TEST_SEGMENTS * TEST_STREAM_ROUNDS) + round);
        }
        SecOC_MainFunctionTx();
        SoAd_MainFunctionTx();
    }
    Test_ReceiverIdentity();

    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    StatusFreshnessFail = 0U;
    StatusAuthFail = 0U;
    StreamErrors = 0U;
    for (st = 0U; st < TEST_STREAMS; st++)
    {
        StreamDelivered[SECOC_PDUID_SIG(st)] = 0U;
        StreamNextSeq[SECOC_PDUID_SIG(st)] = 0U;
        StreamByte[SECOC_PDUID_SIG(st)] = (uint8)st;
    }
    StreamTrack = TRUE;

    for (seg = 0U; seg < TEST_SEGMENTS; seg++)
    {
        Test_Feed(Socket, &Wire[seg * perSegment * pduLen], perSegment * pduLen, Test_ChunkSizes[seg]);
        Test_RxCycle();
        Test_RxCycle();
    }
    for (st = 0U; st < TEST_STREAMS; st++)
    {
        CHECK(StreamDelivered[SECOC_PDUID_SIG(st)] == (TEST_SEGMENTS * TEST_STREAM_ROUNDS), "stream %u: %u PDUs delivered, expected %u",
              (unsigned)st, (unsigned)StreamDelivered[SECOC_PDUID_SIG(st)], (unsigned)(TEST_SEGMENTS * TEST_STREAM_ROUNDS));
    }
    CHECK(StreamErrors == 0U, "%u deliveries out of order or with the payload of another stream", (unsigned)StreamErrors);
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK((dropped == 0U) && (StatusAuthFail == 0U) && (StatusFreshnessFail == 0U),
          "interleaved streams: %u dropped, %u authentication failures, %u freshness failures, expected none",
          (unsigned)dropped, (unsigned)StatusAuthFail, (unsigned)StatusFreshnessFail);

    /* disturbance round: stream 0's PDU 42 tampered | stream 1 | unknown header ID | stream 2 |
     * a PDU with stream 2's header ID and 9000 bytes | stream 3 | PDU 43 of all four streams */
    (void)memcpy(&NegWire[n], &extra[0U * pduLen], pduLen);
    n += pduLen;
    NegWire[n - 1U] ^= 0x01U;
    (void)memcpy(&NegWire[n], &extra[1U * pduLen], pduLen);
    n += pduLen;
    Test_PutBe32(&NegWire[n], 0xDEADU);
    Test_PutBe32(&NegWire[n + 4U], 5U);
    (void)memset(&NegWire[n + 8U], 0xEE, 5U);
    n += 13U;
    (void)memcpy(&NegWire[n], &extra[2U * pduLen], pduLen);
    n += pduLen;
    Test_PutBe32(&NegWire[n], SOAD_HEADERID_SIG(2U));
    Test_PutBe32(&NegWire[n + 4U], 9000U);
    (void)memset(&NegWire[n + 8U], 0xEE, 9000U);
    n += 9008U;
    (void)memcpy(&NegWire[n], &extra[3U * pduLen], pduLen);
    n += pduLen;
    (void)memcpy(&NegWire[n], &extra[4U * pduLen], 4U * pduLen);
    n += 4U * pduLen;
    StreamNextSeq[SECOC_PDUID_SIG(0U)] = (TEST_SEGMENTS * TEST_STREAM_ROUNDS) + 1U;    /* 42 of stream 0 is the tampered one */

    Test_Feed(Socket, NegWire, n, 0U);
    Test_RxCycle();
    Test_RxCycle();
    StreamTrack = FALSE;

    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK(dropped == 2U, "%u PDUs dropped by SoAd in the disturbance round, expected 2 (unknown header ID, over-long PDU)", (unsigned)dropped);
    CHECK((StatusAuthFail == 1U) && (StatusFreshnessFail == 0U), "%u authentication and %u freshness failures in the disturbance round, expected 1 and 0",
          (unsigned)StatusAuthFail, (unsigned)StatusFreshnessFail);
    CHECK(StreamDelivered[SECOC_PDUID_SIG(0U)] == ((TEST_SEGMENTS * TEST_STREAM_ROUNDS) + 1U), "stream 0: %u PDUs delivered, expected %u (one was tampered)",
          (unsigned)StreamDelivered[SECOC_PDUID_SIG(0U)], (unsigned)((TEST_SEGMENTS * TEST_STREAM_ROUNDS) + 1U));
    for (st = 1U; st < TEST_STREAMS; st++)
    {
        CHECK(StreamDelivered[SECOC_PDUID_SIG(st)] == ((TEST_SEGMENTS * TEST_STREAM_ROUNDS) + 2U), "stream %u: %u PDUs delivered, expected %u",
              (unsigned)st, (unsigned)StreamDelivered[SECOC_PDUID_SIG(st)], (unsigned)((TEST_SEGMENTS * TEST_STREAM_ROUNDS) + 2U));
    }
    CHECK(StreamErrors == 0U, "%u deliveries out of order or with the payload of another stream in the disturbance round", (unsigned)StreamErrors);
}

/* C10 [T4c]: what the handshake component needs from SecOC and the freshness manager at a session
 * boundary. Stream 0 (SecOC PDU 2) stands for the session-bound PDUs. */
static TcpIp_SocketIdType Test_SessionBoundaries(TcpIp_SocketIdType Socket, uint32 FirstSeq)
{
    uint32 wireStart = WireLen;
    uint32 deliveredBefore = DeliveredCount;
    uint32 pduLen;
    const uint8* pdu;
    uint8 payload[TEST_PAYLOAD_LEN];
    PduInfoType info;

    Test_CsmIdentity(&KeyA);
    Test_Payload(payload, FirstSeq);
    info.SduDataPtr = payload;
    info.MetaDataPtr = NULL;
    info.SduLength = TEST_PAYLOAD_LEN;

    /* held: a submitted PDU is not authenticated, nothing is in transmission */
    SecOC_TxSessionHold(0U, TRUE);
    (void)SecOC_TpTransmit(TEST_PDU_ID, &info);
    SecOC_MainFunctionTx();
    SoAd_MainFunctionTx();
    CHECK(WireLen == wireStart, "a PDU was transmitted while the session was held");
    CHECK(SecOC_TxSessionFlushed(0U) == TRUE, "not flushed although nothing was authenticated while held");

    /* released: it is authenticated; between the transmit request and the confirmation it is not flushed */
    SecOC_TxSessionHold(0U, FALSE);
    SecOC_MainFunctionTx();
    CHECK(SecOC_TxSessionFlushed(0U) == FALSE, "flushed although a Secured I-PDU waits for its confirmation");
    SoAd_MainFunctionTx();
    CHECK(SecOC_TxSessionFlushed(0U) == TRUE, "not flushed after the confirmation");
    pduLen = WireLen - wireStart;
    CHECK(pduLen > 32U, "the PDU submitted while held was not transmitted after the release");

    /* a Secured I-PDU that still waits in SoAd when its connection ends is ended with it: flushed,
     * and it does not go out on the next connection */
    Test_Payload(payload, FirstSeq + 1U);
    (void)SecOC_TpTransmit(TEST_PDU_ID, &info);
    SecOC_MainFunctionTx();
    CHECK(SecOC_TxSessionFlushed(0U) == FALSE, "flushed although a Secured I-PDU waits in SoAd");
    SoAd_TcpIpEvent(Socket, TCPIP_TCP_CLOSED);
    Test_RxCycle();
    CHECK(SecOC_TxSessionFlushed(0U) == TRUE, "not flushed although the connection of a waiting Secured I-PDU ended");
    wireStart = WireLen;
    Socket = Test_NewConnection();
    SoAd_MainFunctionTx();
    CHECK(WireLen == wireStart, "a Secured I-PDU requested on the previous connection went out on the next one");

    /* a transmission that fails (connection lost) leaves nothing behind either */
    FailTransmit = TRUE;
    Test_Payload(payload, FirstSeq + 1U);
    (void)SecOC_TpTransmit(TEST_PDU_ID, &info);
    SecOC_MainFunctionTx();
    SoAd_MainFunctionTx();
    FailTransmit = FALSE;
    CHECK(SecOC_TxSessionFlushed(0U) == TRUE, "not flushed after a failed transmission");
    Test_ReceiverIdentity();
    /* SoAd closed the connection on the failed transmission; the PDU sent before it is not used */
    Socket = Test_NewConnection();
    pdu = Test_TransmitOne(FirstSeq + 1U, &pduLen);
    CHECK(pduLen > 32U, "nothing was transmitted on the connection after a failed transmission");

    /* received but not verified yet (SoAd has run, SecOC has not): not drained; verified: drained */
    FeedSocket = Socket;
    FeedData = pdu;
    FeedLength = pduLen;
    FeedPos = 0U;
    FeedChunkSize = TCPIP_RX_BUFFER_SIZE;
    SoAd_MainFunctionRx();
    SoAd_MainFunctionRx();
    CHECK(FeedPos == FeedLength, "SoAd did not read the PDU of the session-boundary case");
    CHECK(SecOC_RxSessionDrained(0U) == FALSE, "drained although a Secured I-PDU waits for verification");
    Test_RxCycle();
    Test_RxCycle();
    CHECK(SecOC_RxSessionDrained(0U) == TRUE, "not drained after the Secured I-PDU was verified");
    CHECK((DeliveredCount - deliveredBefore) == 1U, "the PDU of the session-boundary case was not delivered");

    /* a new session: both counters restart; the next PDU carries 1 and is accepted, its copy is not */
    FVM_SessionInstall((uint16)SECOC_FRESHNESS_ID_TX(TEST_PDU_ID));
    FVM_SessionInstall((uint16)SECOC_FRESHNESS_ID_RX(TEST_PDU_ID));
    pdu = Test_TransmitOne(FirstSeq + 2U, &pduLen);
    CHECK((pduLen > 32U) && (memcmp(&pdu[9U + TEST_PAYLOAD_LEN], "\x00\x00\x00\x01", 4U) == 0),
          "the first PDU after FVM_SessionInstall does not carry the counter 1");
    StatusFreshnessFail = 0U;
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((DeliveredCount - deliveredBefore) == 2U, "the first PDU of the new session (counter 1) was not delivered");
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    CHECK(((DeliveredCount - deliveredBefore) == 2U) && (StatusFreshnessFail == 1U),
          "a repeated PDU of the new session was not rejected by the freshness check");
    return Socket;
}

/* C12 [T5b]: the freshness counter of a session-bound PDU: 32 bits sent in full, nothing accepted
 * that is not above the last accepted value (0 before the first), nothing sent after 2^32 - 1 until
 * the next session. */
static void Test_SessionCounter(TcpIp_SocketIdType Socket, uint32 FirstSeq)
{
    static const uint8 zero[4] = { 0x00U, 0x00U, 0x00U, 0x00U };
    static const uint8 one[4] = { 0x00U, 0x00U, 0x00U, 0x01U };
    uint8 nearEnd[4] = { 0xFFU, 0xFFU, 0xFFU, 0xFEU };
    uint8 full[8];
    uint32 fullLen = 0U;
    const uint16 txId = (uint16)SECOC_FRESHNESS_ID_TX(TEST_PDU_ID);
    const uint16 rxId = (uint16)SECOC_FRESHNESS_ID_RX(TEST_PDU_ID);
    /* the receive counter of the last MAC stream: no PDU of this test uses it */
    const uint16 untouchedRxId = (uint16)SECOC_FRESHNESS_ID_RX(SECOC_PDUID_MAC(SECOC_PDUID_MAC_COUNT - 1U));
    uint32 deliveredBefore = DeliveredCount;
    uint32 wireBefore;
    uint32 pduLen = 0U;
    uint32 lastLen = 0U;
    const uint8* pdu;
    const uint8* last;
    uint32 i;

    for (i = 0U; i < SECOC_PDUID_SIG_COUNT; i++)
    {
        const PduIdType id = (PduIdType)SECOC_PDUID_SIG(i);
        CHECK((SecOCTxPduProcessing[id].SecOCFreshnessValueId == SECOC_FRESHNESS_ID_TX(id)) &&
              (SecOCTxPduProcessing[id].SecOCFreshnessValueLength == 32U) &&
              (SecOCTxPduProcessing[id].SecOCFreshnessValueTruncLength == 32U),
              "transmit row of signature stream %u: freshness ID %u, length %u, transmitted %u bits; expected the table's ID and 32 / 32",
              (unsigned)i, (unsigned)SecOCTxPduProcessing[id].SecOCFreshnessValueId,
              (unsigned)SecOCTxPduProcessing[id].SecOCFreshnessValueLength,
              (unsigned)SecOCTxPduProcessing[id].SecOCFreshnessValueTruncLength);
        CHECK((SecOCRxPduProcessing[id].SecOCFreshnessValueId == SECOC_FRESHNESS_ID_RX(id)) &&
              (SecOCRxPduProcessing[id].SecOCFreshnessValueLength == 32U) &&
              (SecOCRxPduProcessing[id].SecOCFreshnessValueTruncLength == 32U),
              "receive row of signature stream %u: freshness ID %u, length %u, transmitted %u bits; expected the table's ID and 32 / 32",
              (unsigned)i, (unsigned)SecOCRxPduProcessing[id].SecOCFreshnessValueId,
              (unsigned)SecOCRxPduProcessing[id].SecOCFreshnessValueLength,
              (unsigned)SecOCRxPduProcessing[id].SecOCFreshnessValueTruncLength);
    }

    /* a receive counter that has accepted nothing yet */
    CHECK(FVM_GetRxFreshness(untouchedRxId, zero, 32U, 0U, full, &fullLen) == E_NOT_OK,
          "a session-bound receive counter that has accepted nothing takes the value 0");
    CHECK(FVM_GetRxFreshness(untouchedRxId, one, 32U, 0U, full, &fullLen) == E_OK,
          "a session-bound receive counter that has accepted nothing refuses the value 1");

    /* the last two values of a session are sent and accepted */
    FVM_SessionInstall(rxId);
    (void)FVM_UpdateCounter(txId, nearEnd, 32U);
    pdu = Test_TransmitOne(FirstSeq, &pduLen);
    CHECK((pduLen > 32U) && (memcmp(&pdu[9U + TEST_PAYLOAD_LEN], "\xFF\xFF\xFF\xFE", 4U) == 0),
          "the PDU sent at counter 2^32 - 2 does not carry that value");
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    last = Test_TransmitOne(FirstSeq + 1U, &lastLen);
    CHECK((lastLen > 32U) && (memcmp(&last[9U + TEST_PAYLOAD_LEN], "\xFF\xFF\xFF\xFF", 4U) == 0),
          "the PDU sent at counter 2^32 - 1 does not carry that value");
    Test_Feed(Socket, last, lastLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((DeliveredCount - deliveredBefore) == 2U, "%u of the last 2 PDUs of a session delivered",
          (unsigned)(DeliveredCount - deliveredBefore));

    /* then the sender stops: no Secured I-PDU, nothing left in transmission */
    (void)Test_TransmitOne(FirstSeq + 2U, &pduLen);
    CHECK(pduLen == 0U, "%u bytes were transmitted after the counter had reached 2^32 - 1", (unsigned)pduLen);
    CHECK(SecOC_TxSessionFlushed(0U) == TRUE, "not flushed after a PDU was refused at the end of the counter");

    /* the last PDU again: not above the last accepted value */
    StatusFreshnessFail = 0U;
    Test_Feed(Socket, last, lastLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((StatusFreshnessFail == 1U) && ((DeliveredCount - deliveredBefore) == 2U),
          "the replayed last PDU of a session: %u freshness failures, %u deliveries, expected 1 and 2",
          (unsigned)StatusFreshnessFail, (unsigned)(DeliveredCount - deliveredBefore));

    /* a new session: the refused PDU is gone, the next one carries 1 and is accepted */
    FVM_SessionInstall(txId);
    FVM_SessionInstall(rxId);
    wireBefore = WireLen;
    Test_CsmIdentity(&KeyA);
    SecOC_MainFunctionTx();
    SoAd_MainFunctionTx();
    Test_ReceiverIdentity();
    CHECK(WireLen == wireBefore, "the PDU refused at the end of the old session went out in the new one");
    pdu = Test_TransmitOne(FirstSeq + 3U, &pduLen);
    CHECK((pduLen > 32U) && (memcmp(&pdu[9U + TEST_PAYLOAD_LEN], "\x00\x00\x00\x01", 4U) == 0),
          "the first PDU of the session after the stop does not carry the counter 1");
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((DeliveredCount - deliveredBefore) == 3U, "the first PDU of the session after the stop was not delivered");
}

/* The PDU signature context of peer 0 as the handshake component installs it: label || 48 bytes that
 * stand for the session (here one repeated byte). Csm_Init, which every change of identity in this
 * test runs, puts the no-session context back (label || zeros). */
static void Test_InstallPduContext(uint8 Session)
{
    uint8 context[PQC_PDU_SIG_CTX_BYTES];

    (void)memcpy(context, PQC_PDU_SIG_CTX_LABEL, PQC_PDU_SIG_CTX_LABEL_BYTES);
    (void)memset(&context[PQC_PDU_SIG_CTX_LABEL_BYTES], Session, sizeof(context) - PQC_PDU_SIG_CTX_LABEL_BYTES);
    CHECK((Csm_KeyElementSet(CSM_KEYID_SESSION_BASE, CSM_KE_VENDOR_PDU_SIG_CTX, context, sizeof(context)) == E_OK) &&
          (Csm_KeySetValid(CSM_KEYID_SESSION_BASE) == E_OK), "the PDU signature context of session 0x%02X was not installed", Session);
}

/* one PDU signed under the context of <Session> (0: no session installed) */
static const uint8* Test_TransmitInSession(uint8 Session, uint32 Seq, uint32* LengthPtr)
{
    uint32 wireStart = WireLen;

    Test_CsmIdentity(&KeyA);
    if (Session != 0U)
    {
        Test_InstallPduContext(Session);
    }
    Test_Transmit(Seq);
    *LengthPtr = WireLen - wireStart;
    return &Wire[wireStart];
}

/* the receiver, with the context of <Session> installed (0: none), gets the bytes */
static void Test_ReceiveInSession(uint8 Session, TcpIp_SocketIdType Socket, const uint8* Pdu, uint32 Length)
{
    Test_ReceiverIdentity();
    if (Session != 0U)
    {
        Test_InstallPduContext(Session);
    }
    Test_Feed(Socket, Pdu, Length, 0U);
    Test_RxCycle();
    Test_RxCycle();
}

/* C13 [T5b]: a Secured I-PDU is bound to its session by the signature context. Every PDU here carries
 * the counter 1 of a new session, so the freshness check accepts it and the verdict is the signature's. */
static void Test_SessionContext(TcpIp_SocketIdType Socket, uint32 FirstSeq)
{
    static const uint8 zeros[PQC_PDU_SIG_CTX_BYTES - PQC_PDU_SIG_CTX_LABEL_BYTES] = { 0U };
    const uint16 txId = (uint16)SECOC_FRESHNESS_ID_TX(TEST_PDU_ID);
    const uint16 rxId = (uint16)SECOC_FRESHNESS_ID_RX(TEST_PDU_ID);
    uint32 deliveredBefore = DeliveredCount;
    uint32 lengthErrorsBefore = DriverLengthErrors;
    uint32 len1 = 0U;
    uint32 len0 = 0U;
    uint32 len2 = 0U;
    const uint8* pdu1;
    const uint8* pdu0;
    const uint8* pdu2;

    /* session 1 on both sides */
    FVM_SessionInstall(txId);
    FVM_SessionInstall(rxId);
    pdu1 = Test_TransmitInSession(0x11U, FirstSeq, &len1);
    CHECK((len1 > 32U) && (memcmp(DriverSignContext, PQC_PDU_SIG_CTX_LABEL, PQC_PDU_SIG_CTX_LABEL_BYTES) == 0) &&
          (DriverSignContext[PQC_PDU_SIG_CTX_LABEL_BYTES] == 0x11U) && (DriverSignContext[PQC_PDU_SIG_CTX_BYTES - 1U] == 0x11U),
          "the PDU of session 1 was not signed under the label and the session bytes that were installed");
    Test_ReceiveInSession(0x11U, Socket, pdu1, len1);
    CHECK((DeliveredCount - deliveredBefore) == 1U, "the PDU of session 1 was not delivered in session 1");
    CHECK(memcmp(DriverVerifyContext, DriverSignContext, PQC_PDU_SIG_CTX_BYTES) == 0,
          "the receiver did not verify under the context the transmitter signed under");

    /* session 2 on the receiver: the recorded PDU of session 1 again */
    FVM_SessionInstall(rxId);
    StatusAuthFail = 0U;
    StatusFreshnessFail = 0U;
    Test_ReceiveInSession(0x22U, Socket, pdu1, len1);
    CHECK((StatusAuthFail == 1U) && (StatusFreshnessFail == 0U) && ((DeliveredCount - deliveredBefore) == 1U),
          "a PDU of session 1 replayed into session 2: %u authentication failures, %u freshness failures, %u deliveries; expected 1, 0, 1",
          (unsigned)StatusAuthFail, (unsigned)StatusFreshnessFail, (unsigned)(DeliveredCount - deliveredBefore));
    /* the Csm's answer for a signature that does not verify: the request succeeded, the verdict is
     * negative ([SWS_Csm_00996], [SWS_Csm_01024]); SecOC has reported the failure above */
    CHECK((LastVerifyResult == E_OK) && (LastVerifyVerdict == CRYPTO_E_VER_NOT_OK),
          "Csm_SignatureVerify for a wrong signature returned %u with verdict %u, expected E_OK with CRYPTO_E_VER_NOT_OK",
          (unsigned)LastVerifyResult, (unsigned)LastVerifyVerdict);

    /* a PDU signed with no session, fed into session 2 */
    FVM_SessionInstall(txId);
    pdu0 = Test_TransmitInSession(0U, FirstSeq + 1U, &len0);
    CHECK((len0 > 32U) && (memcmp(DriverSignContext, PQC_PDU_SIG_CTX_LABEL, PQC_PDU_SIG_CTX_LABEL_BYTES) == 0) &&
          (memcmp(&DriverSignContext[PQC_PDU_SIG_CTX_LABEL_BYTES], zeros, sizeof(zeros)) == 0),
          "with no session the PDU was not signed under the label followed by zeros");
    Test_ReceiveInSession(0x22U, Socket, pdu0, len0);
    CHECK((StatusAuthFail == 2U) && (StatusFreshnessFail == 0U) && ((DeliveredCount - deliveredBefore) == 1U),
          "a PDU signed with no session, in session 2: %u authentication failures, %u freshness failures, %u deliveries; expected 2, 0, 1",
          (unsigned)StatusAuthFail, (unsigned)StatusFreshnessFail, (unsigned)(DeliveredCount - deliveredBefore));

    /* session 2's own PDU is delivered: the receiver is still able to verify */
    FVM_SessionInstall(txId);
    pdu2 = Test_TransmitInSession(0x22U, FirstSeq + 2U, &len2);
    Test_ReceiveInSession(0x22U, Socket, pdu2, len2);
    CHECK((DeliveredCount - deliveredBefore) == 2U, "the PDU of session 2 was not delivered in session 2");

    CHECK(DriverLengthErrors == lengthErrorsBefore, "%u driver calls of this case were not over %u bytes under a %u-byte context",
          (unsigned)(DriverLengthErrors - lengthErrorsBefore), (unsigned)TEST_D2A_LEN, (unsigned)PQC_PDU_SIG_CTX_BYTES);
}

/* the Secured I-PDU of a wire PDU through the IF entry of SecOC (no SoAd, no TP reception) */
static void Test_FeedIf(const uint8* WirePdu, uint32 WireLength)
{
    PduInfoType info;

    /* cppcheck-suppress misra-c2012-11.8 */
    info.SduDataPtr = (uint8*)&WirePdu[8];
    info.MetaDataPtr = NULL;
    info.SduLength = (PduLengthType)(WireLength - 8U);
    SecOC_RxIndication(TEST_PDU_ID, &info);
    SecOC_MainFunctionRx();
    SecOC_MainFunctionRx();
}

/* C14 [T5b]: no session. The handshake component is initialised with its default configuration (as
 * EcuM does); no handshake runs in this test, so "established" is the component's own answer (FALSE)
 * or what the test sets. Both reception paths: TP (from SoAd) and IF (SecOC_RxIndication). */
static void Test_NoSessionGate(TcpIp_SocketIdType Socket, uint32 FirstSeq)
{
    uint8 context[PQC_PDU_SIG_CTX_BYTES];
    uint32 deliveredBefore = DeliveredCount;
    uint32 pduLen = 0U;
    uint32 secondLen = 0U;
    const uint8* pdu;
    const uint8* second;

    CHECK(FVM_NoSession() == FALSE, "FVM_NoSession is TRUE although the handshake component is not initialised");
    CHECK(PqcHs_Init(NULL) == E_OK, "PqcHs_Init with the default configuration failed");
    CHECK(FVM_NoSession() == TRUE, "FVM_NoSession is FALSE although the handshake component has no session");

    /* before establishment: a genuine, fresh PDU is refused by the freshness function on both paths */
    pdu = Test_TransmitOne(FirstSeq, &pduLen);
    StatusFreshnessFail = 0U;
    StatusAuthFail = 0U;
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((StatusFreshnessFail == 1U) && (StatusAuthFail == 0U) && (DeliveredCount == deliveredBefore),
          "TP, no session: %u freshness failures, %u authentication failures, %u deliveries; expected 1, 0, 0",
          (unsigned)StatusFreshnessFail, (unsigned)StatusAuthFail, (unsigned)(DeliveredCount - deliveredBefore));
    Test_FeedIf(pdu, pduLen);
    CHECK((StatusFreshnessFail == 2U) && (StatusAuthFail == 0U) && (DeliveredCount == deliveredBefore),
          "IF, no session: %u freshness failures, %u authentication failures, %u deliveries; expected 2, 0, 0",
          (unsigned)StatusFreshnessFail, (unsigned)StatusAuthFail, (unsigned)(DeliveredCount - deliveredBefore));

    /* after a failed key installation: the component is not established and has written a PDU signature
     * context that it did not set valid. Still refused by the freshness function ... */
    (void)memcpy(context, PQC_PDU_SIG_CTX_LABEL, PQC_PDU_SIG_CTX_LABEL_BYTES);
    (void)memset(&context[PQC_PDU_SIG_CTX_LABEL_BYTES], 0, sizeof(context) - PQC_PDU_SIG_CTX_LABEL_BYTES);
    CHECK(Csm_KeyElementSet(CSM_KEYID_SESSION_BASE, CSM_KE_VENDOR_PDU_SIG_CTX, context, sizeof(context)) == E_OK,
          "the PDU signature context could not be written");
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    Test_FeedIf(pdu, pduLen);
    CHECK((StatusFreshnessFail == 4U) && (StatusAuthFail == 0U) && (DeliveredCount == deliveredBefore),
          "after a failed installation: %u freshness failures, %u authentication failures, %u deliveries; expected 4, 0, 0",
          (unsigned)StatusFreshnessFail, (unsigned)StatusAuthFail, (unsigned)(DeliveredCount - deliveredBefore));

    /* ... and, with the gate out of the way (the test says "established"), not verifiable either: the
     * context that was not set valid gives no verification, on both paths */
    EstablishedOverride = 1;
    CHECK(FVM_NoSession() == FALSE, "FVM_NoSession is TRUE although a session is established");
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    Test_FeedIf(pdu, pduLen);
    CHECK((StatusFreshnessFail == 4U) && (StatusAuthFail == 2U) && (DeliveredCount == deliveredBefore),
          "context not valid: %u freshness failures, %u authentication failures, %u deliveries; expected 4, 2, 0",
          (unsigned)StatusFreshnessFail, (unsigned)StatusAuthFail, (unsigned)(DeliveredCount - deliveredBefore));
    /* here the request itself failed (no valid context): not E_OK, and no positive verdict. SecOC
     * treats it like a wrong signature: a reported failure, nothing delivered (checked above). */
    CHECK((LastVerifyResult != E_OK) && (LastVerifyVerdict != CRYPTO_E_VER_OK),
          "Csm_SignatureVerify without a valid context returned %u with verdict %u, expected a failed request",
          (unsigned)LastVerifyResult, (unsigned)LastVerifyVerdict);

    /* established with a valid context: the same PDU is delivered (TP), and the next one (IF) */
    CHECK(Csm_KeySetValid(CSM_KEYID_SESSION_BASE) == E_OK, "the PDU signature context could not be set valid");
    Test_Feed(Socket, pdu, pduLen, 0U);
    Test_RxCycle();
    Test_RxCycle();
    CHECK((DeliveredCount - deliveredBefore) == 1U, "TP: the PDU was not delivered once the session was established");
    second = Test_TransmitOne(FirstSeq + 1U, &secondLen);
    Test_FeedIf(second, secondLen);
    CHECK((DeliveredCount - deliveredBefore) == 2U, "IF: the PDU was not delivered once the session was established");
    /* the rest of the test runs with a session established */
}

Std_ReturnType authenticate_PQC(const PduIdType TxPduId, PduInfoType* AuthPdu, PduInfoType* SecPdu);
Std_ReturnType verify_PQC(PduIdType RxPduId, PduInfoType* SecPdu, SecOC_VerificationResultType* verification_result);

/* C15: the SecOC rows of the CAN PDUs (0, 1, 3, 4, 5) are outside the evaluated Ethernet set-up, but
 * they still verify what the same node signed: the transmit row with the PDU sign job, the receive
 * row with the listed loopback verify job (the sign job verifies nothing any more). Row 0, through
 * the SecOC functions that the main functions call. */
static void Test_CanRowLoopback(void)
{
    static uint8 copy[TEST_WIRE_PDU_MAX];
    PduInfoType* authPdu = &(SecOCTxPduProcessing[0].SecOCTxAuthenticPduLayer->SecOCTxAuthenticLayerPduRef);
    PduInfoType* secPdu = &(SecOCTxPduProcessing[0].SecOCTxSecuredPduLayer->SecOCTxSecuredPdu->SecOCTxSecuredLayerPduRef);
    SecOC_VerificationResultType status;
    PduInfoType rx;
    uint32 round;

    Test_CsmIdentity(&KeyA);        /* one node: it verifies with its own public key */
    for (round = 0U; round < 2U; round++)
    {
        authPdu->SduDataPtr[0] = 100U;
        authPdu->SduDataPtr[1] = (uint8)(200U + round);
        authPdu->SduLength = 2U;
        if ((authenticate_PQC(0U, authPdu, secPdu) != E_OK) || (secPdu->SduLength <= PQC_MLDSA_SIGNATURE_BYTES) ||
            (secPdu->SduLength > sizeof(copy)))
        {
            CHECK(FALSE, "row 0: no Secured I-PDU was built (%u bytes)", (unsigned)secPdu->SduLength);
            break;
        }
        (void)FVM_IncreaseCounter(SecOCTxPduProcessing[0].SecOCFreshnessValueId);
        (void)memcpy(copy, secPdu->SduDataPtr, secPdu->SduLength);
        rx.SduDataPtr = copy;
        rx.MetaDataPtr = NULL;
        rx.SduLength = secPdu->SduLength;
        secPdu->SduLength = 0U;         /* nothing is left for a transmission */
        status = SECOC_NO_VERIFICATION;
        if (round == 0U)
        {
            CHECK((verify_PQC(0U, &rx, &status) == E_OK) && (status == SECOC_VERIFICATIONSUCCESS),
                  "row 0: a PDU signed by this node was not verified with the loopback job (status %d)", (int)status);
        }
        else
        {
            copy[rx.SduLength - 1U] ^= 0x01U;
            CHECK((verify_PQC(0U, &rx, &status) != E_OK) && (status == SECOC_VERIFICATIONFAILURE),
                  "row 0: a PDU with a flipped signature bit was not rejected (status %d)", (int)status);
        }
    }
    Test_ReceiverIdentity();
}

/************************************************* main *************************************************/

/**************************************** V: Csm results in SecOC ****************************************/

Std_ReturnType verify(PduIdType RxPduId, PduInfoType* SecPdu, SecOC_VerificationResultType* verification_result);
Std_ReturnType verify_PQC(PduIdType RxPduId, PduInfoType* SecPdu, SecOC_VerificationResultType* verification_result);

typedef struct
{
    Std_ReturnType Result;
    Crypto_VerifyResultType Verdict;
} Test_CsmOutcomeType;

/* Every answer of a Csm verify call that must not deliver, the two retry codes aside. 0x0E and 0xFF
 * stand for return values SecOC has no branch for. */
static const Test_CsmOutcomeType Test_RejectOutcomes[] =
{
    { E_OK,                   CRYPTO_E_VER_NOT_OK },
    { E_NOT_OK,               CRYPTO_E_VER_OK },    { E_NOT_OK,               CRYPTO_E_VER_NOT_OK },
    { CRYPTO_E_KEY_NOT_VALID, CRYPTO_E_VER_OK },    { CRYPTO_E_KEY_NOT_VALID, CRYPTO_E_VER_NOT_OK },
    { CRYPTO_E_KEY_EMPTY,     CRYPTO_E_VER_OK },    { CRYPTO_E_KEY_EMPTY,     CRYPTO_E_VER_NOT_OK },
    { (Std_ReturnType)0x0EU,  CRYPTO_E_VER_OK },    { (Std_ReturnType)0x0EU,  CRYPTO_E_VER_NOT_OK },
    { (Std_ReturnType)0xFFU,  CRYPTO_E_VER_OK },    { (Std_ReturnType)0xFFU,  CRYPTO_E_VER_NOT_OK }
};
#define TEST_REJECT_OUTCOMES   (sizeof(Test_RejectOutcomes) / sizeof(Test_RejectOutcomes[0]))

static const Std_ReturnType Test_TxErrors[] =
{
    E_NOT_OK, CRYPTO_E_KEY_NOT_VALID, CRYPTO_E_KEY_EMPTY, (Std_ReturnType)0x0EU, (Std_ReturnType)0xFFU
};
#define TEST_TX_ERRORS         (sizeof(Test_TxErrors) / sizeof(Test_TxErrors[0]))

typedef struct
{
    uint32 Delivered;
    uint32 Ok;
    uint32 Failed;          /* reported through the callout, freshness failures not included */
    uint32 Forced;          /* Csm verify calls answered by the stub */
    SecOC_VerificationResultType Last;
} Test_SeenType;

static void Test_ForceVerifyOn(Std_ReturnType Result, Crypto_VerifyResultType Verdict, uint32 Limit)
{
    ForceVerifyResult = Result;
    ForceVerifyVerdict = Verdict;
    ForceVerifyLimit = Limit;
    ForceVerifyCalls = 0U;
    ForceVerify = TRUE;
}

/* Hand Length bytes to the receiver and run more main functions than any attempt limit needs. */
static void Test_ReceiveChunked(TcpIp_SocketIdType Socket, const uint8* Data, uint32 Length, uint32 Pdus,
                                uint32 ChunkSize, Test_SeenType* Seen)
{
    uint32 delivered = DeliveredCount;
    uint32 ok = StatusOk;
    uint32 failed = StatusAuthFail;
    uint32 i;

    LastStatus = SECOC_NO_VERIFICATION;
    Test_Feed(Socket, Data, Length, ChunkSize);
    for (i = 0U; i < (4U * (Pdus + 1U)); i++)
    {
        Test_RxCycle();
    }
    Seen->Delivered = DeliveredCount - delivered;
    Seen->Ok = StatusOk - ok;
    Seen->Failed = StatusAuthFail - failed;
    Seen->Forced = ForceVerifyCalls;
    Seen->Last = LastStatus;
}

static void Test_Receive(TcpIp_SocketIdType Socket, const uint8* Data, uint32 Length, uint32 Pdus, Test_SeenType* Seen)
{
    Test_ReceiveChunked(Socket, Data, Length, Pdus, 0U, Seen);
}

/* A PDU the Csm verifies for real must be delivered: the stream is not blocked by what came before. */
static void Test_ExpectDelivered(TcpIp_SocketIdType Socket, uint32 Seq, const char* After)
{
    Test_SeenType seen;
    uint32 len;
    const uint8* pdu = Test_TransmitOne(Seq, &len);
    uint8 expect[TEST_PAYLOAD_LEN];

    ForceVerify = FALSE;
    Test_Receive(Socket, pdu, len, 1U, &seen);
    Test_Payload(expect, Seq);
    CHECK((seen.Delivered == 1U) && (seen.Ok == 1U) && (seen.Failed == 0U) &&
          (DeliveredCount <= (TEST_NUM_PDUS + TEST_EXTRA_PDUS)) &&
          (memcmp(Delivered[DeliveredCount - 1U], expect, TEST_PAYLOAD_LEN) == 0),
          "the PDU after %s: delivered=%u ok=%u failed=%u, expected the PDU delivered once and reported ok",
          After, (unsigned)seen.Delivered, (unsigned)seen.Ok, (unsigned)seen.Failed);
}

/* One of the two verify functions called directly, each time on a new Secured I-PDU that is in order. */
static void Test_VerdictsDirect(const char* Name,
                                Std_ReturnType (*Verify)(PduIdType, PduInfoType*, SecOC_VerificationResultType*),
                                uint32* SeqPtr)
{
    static uint8 buffer[TEST_WIRE_PDU_MAX];
    PduInfoType pdu;
    SecOC_VerificationResultType status;
    Std_ReturnType result;
    Std_ReturnType expect;
    SecOC_VerificationResultType expectStatus;
    Test_CsmOutcomeType outcome;
    uint32 len;
    uint32 i;
    const uint8* wire;

    for (i = 0U; i < (TEST_REJECT_OUTCOMES + 3U); i++)
    {
        if (i < TEST_REJECT_OUTCOMES)
        {
            outcome = Test_RejectOutcomes[i];
            expect = E_NOT_OK;
            expectStatus = SECOC_VERIFICATIONFAILURE;
        }
        else if (i < (TEST_REJECT_OUTCOMES + 2U))
        {
            /* a first attempt that the Csm could not take: kept for the next main function */
            outcome.Result = (i == TEST_REJECT_OUTCOMES) ? E_BUSY : QUEUE_FULL;
            outcome.Verdict = CRYPTO_E_VER_OK;
            expect = outcome.Result;
            expectStatus = SECOC_NO_VERIFICATION;
        }
        else
        {
            outcome.Result = E_OK;
            outcome.Verdict = CRYPTO_E_VER_OK;
            expect = E_OK;
            expectStatus = SECOC_VERIFICATIONSUCCESS;
        }

        wire = Test_TransmitOne(*SeqPtr, &len);
        (*SeqPtr)++;
        if ((len <= 8U) || ((len - 8U) > sizeof(buffer)))
        {
            CHECK(FALSE, "%s: no PDU to verify", Name);
            return;
        }
        (void)memcpy(buffer, &wire[8], len - 8U);
        pdu.SduDataPtr = buffer;
        pdu.MetaDataPtr = NULL;
        pdu.SduLength = len - 8U;
        SecOC_RxCounters[TEST_PDU_ID].AuthenticationCounter = 0U;
        SecOC_RxCounters[TEST_PDU_ID].VerificationCounter = 0U;
        status = (expectStatus == SECOC_VERIFICATIONSUCCESS) ? SECOC_NO_VERIFICATION : SECOC_VERIFICATIONSUCCESS;
        Test_ForceVerifyOn(outcome.Result, outcome.Verdict, 0U);
        result = Verify(TEST_PDU_ID, &pdu, &status);
        ForceVerify = FALSE;
        CHECK((result == expect) && (status == expectStatus) && (ForceVerifyCalls == 1U),
              "%s: Csm result 0x%02X with verdict %u gives return 0x%02X and status %u after %u Csm call(s), expected return 0x%02X, status %u, 1 call",
              Name, (unsigned)outcome.Result, (unsigned)outcome.Verdict, (unsigned)result, (unsigned)status,
              (unsigned)ForceVerifyCalls, (unsigned)expect, (unsigned)expectStatus);
    }
}

static uint32 Test_WireFreshness(const uint8* Pdu)
{
    const uint8* f = &Pdu[8U + 1U + TEST_PAYLOAD_LEN];     /* PDU header | SecOC header | payload | freshness */
    return ((uint32)f[0] << 24U) | ((uint32)f[1] << 16U) | ((uint32)f[2] << 8U) | (uint32)f[3];
}

static void Test_TxCycle(void)
{
    SecOC_MainFunctionTx();
    SoAd_MainFunctionTx();
}

static void Test_Verdicts(TcpIp_SocketIdType Socket, uint32 FirstSeq)
{
    const uint32 attempts = SecOC_RxPduProcessing[TEST_PDU_ID].SecOCAuthenticationBuildAttempts;
    const PduInfoType* txSecured = &SecOC_TxPduProcessing[TEST_PDU_ID].SecOCTxSecuredPduLayer->SecOCTxSecuredPdu->SecOCTxSecuredLayerPduRef;
    const PduInfoType* txAuthentic = &SecOC_TxPduProcessing[TEST_PDU_ID].SecOCTxAuthenticPduLayer->SecOCTxAuthenticLayerPduRef;
    Test_SeenType seen;
    uint32 seq = FirstSeq;
    uint32 len;
    uint32 i;
    uint32 n;
    uint32 wireStart;
    uint32 freshness;
    uint32 verifyCalls;
    const uint8* pdu;

    /* the wire buffer is free: every earlier case has consumed what it put there */
    WireLen = 0U;

    (void)printf("V1 only E_OK with CRYPTO_E_VER_OK delivers; any other Csm answer is one reported failure, a busy Csm is retried and then reported\n");
    Test_VerdictsDirect("verify_PQC", verify_PQC, &seq);
    Test_VerdictsDirect("verify", verify, &seq);

    for (i = 0U; i < TEST_REJECT_OUTCOMES; i++)
    {
        pdu = Test_TransmitOne(seq, &len);
        seq++;
        Test_ForceVerifyOn(Test_RejectOutcomes[i].Result, Test_RejectOutcomes[i].Verdict, 0U);
        Test_Receive(Socket, pdu, len, 1U, &seen);
        CHECK((seen.Delivered == 0U) && (seen.Ok == 0U) && (seen.Failed == 1U) && (seen.Forced == 1U) &&
              (seen.Last == SECOC_VERIFICATIONFAILURE),
              "Csm result 0x%02X with verdict %u: delivered=%u ok=%u failures reported=%u (last status %u) verify calls=%u, expected 0, 0, 1 (SECOC_VERIFICATIONFAILURE), 1",
              (unsigned)Test_RejectOutcomes[i].Result, (unsigned)Test_RejectOutcomes[i].Verdict, (unsigned)seen.Delivered,
              (unsigned)seen.Ok, (unsigned)seen.Failed, (unsigned)seen.Last, (unsigned)seen.Forced);
        Test_ExpectDelivered(Socket, seq, "a rejected one");
        seq++;
    }

    /* a Csm that stays busy: every PDU gets its own SecOCAuthenticationBuildAttempts attempts and one report */
    for (i = 0U; i < 3U; i++)
    {
        pdu = Test_TransmitOne(seq, &len);
        seq++;
        Test_ForceVerifyOn((i < 2U) ? E_BUSY : QUEUE_FULL, CRYPTO_E_VER_OK, 0U);
        Test_Receive(Socket, pdu, len, 1U, &seen);
        CHECK((seen.Delivered == 0U) && (seen.Ok == 0U) && (seen.Failed == 1U) && (seen.Forced == attempts) &&
              (seen.Last == SECOC_AUTHENTICATIONBUILDFAILURE),
              "busy Csm, PDU %u: delivered=%u ok=%u failures reported=%u (last status %u) verify calls=%u, expected 0, 0, 1 (SECOC_AUTHENTICATIONBUILDFAILURE), %u",
              (unsigned)i, (unsigned)seen.Delivered, (unsigned)seen.Ok, (unsigned)seen.Failed, (unsigned)seen.Last,
              (unsigned)seen.Forced, (unsigned)attempts);
    }
    /* busy once: the same PDU is verified in the next main function */
    pdu = Test_TransmitOne(seq, &len);
    seq++;
    Test_ForceVerifyOn(E_BUSY, CRYPTO_E_VER_OK, 1U);
    Test_Receive(Socket, pdu, len, 1U, &seen);
    CHECK((seen.Delivered == 1U) && (seen.Ok == 1U) && (seen.Failed == 0U) && (seen.Forced == 1U),
          "Csm busy once: delivered=%u ok=%u failures reported=%u forced calls=%u, expected 1, 1, 0, 1",
          (unsigned)seen.Delivered, (unsigned)seen.Ok, (unsigned)seen.Failed, (unsigned)seen.Forced);
    ForceVerify = FALSE;

    (void)printf("V2 no valid key for the peer: every PDU is a reported verification failure, none is delivered\n");
    wireStart = WireLen;
    Test_CsmIdentity(&KeyA);
    for (i = 0U; i < 5U; i++)
    {
        Test_Transmit(seq);
        seq++;
    }
    Test_ReceiverIdentity();
    /* what Csm_SignatureVerify answers for a peer slot that holds no valid key (Csm.c) */
    Test_ForceVerifyOn(CRYPTO_E_KEY_NOT_VALID, CRYPTO_E_VER_NOT_OK, 0U);
    Test_Receive(Socket, &Wire[wireStart], WireLen - wireStart, 5U, &seen);
    CHECK((seen.Delivered == 0U) && (seen.Ok == 0U) && (seen.Failed == 5U) && (seen.Forced == 5U) &&
          (seen.Last == SECOC_VERIFICATIONFAILURE),
          "5 PDUs without a valid peer key: delivered=%u ok=%u failures reported=%u (last status %u) verify calls=%u, expected 0, 0, 5 (SECOC_VERIFICATIONFAILURE), 5",
          (unsigned)seen.Delivered, (unsigned)seen.Ok, (unsigned)seen.Failed, (unsigned)seen.Last, (unsigned)seen.Forced);
    Test_ExpectDelivered(Socket, seq, "the key became valid");
    freshness = Test_WireFreshness(&Wire[WireLen - ((WireLen - wireStart) / 6U)]);     /* of that PDU, the last of six */
    seq++;

    (void)printf("V3 transmit: no Secured I-PDU unless the Csm generate call returned E_OK\n");
    Test_CsmIdentity(&KeyA);
    for (i = 0U; i < (TEST_TX_ERRORS + 2U); i++)
    {
        const Std_ReturnType code = (i < TEST_TX_ERRORS) ? Test_TxErrors[i] : ((i == TEST_TX_ERRORS) ? E_BUSY : QUEUE_FULL);
        const uint32 calls = (i < TEST_TX_ERRORS) ? 1U : SecOC_TxPduProcessing[TEST_PDU_ID].SecOCAuthenticationBuildAttempts;

        wireStart = WireLen;
        ForceGenerateResult = code;
        ForceGenerateLimit = 0U;
        ForceGenerateCalls = 0U;
        ForceGenerate = TRUE;
        Test_Transmit(seq);
        Test_TxCycle();
        Test_TxCycle();
        Test_TxCycle();
        ForceGenerate = FALSE;
        Test_TxCycle();
        CHECK((WireLen == wireStart) && (txSecured->SduLength == 0U) && (txAuthentic->SduLength == 0U) &&
              (ForceGenerateCalls == calls),
              "Csm generate result 0x%02X: %u bytes on the wire, Secured I-PDU buffer %u bytes, Authentic I-PDU buffer %u bytes, generate calls=%u, expected 0, 0, 0, %u",
              (unsigned)code, (unsigned)(WireLen - wireStart), (unsigned)txSecured->SduLength,
              (unsigned)txAuthentic->SduLength, (unsigned)ForceGenerateCalls, (unsigned)calls);
    }
    /* busy once: the same Authentic I-PDU goes out with the next main function, with the next freshness value */
    wireStart = WireLen;
    ForceGenerateResult = E_BUSY;
    ForceGenerateLimit = 1U;
    ForceGenerateCalls = 0U;
    ForceGenerate = TRUE;
    Test_Transmit(seq);
    CHECK(WireLen == wireStart, "Csm generate busy: %u bytes on the wire in the same main function", (unsigned)(WireLen - wireStart));
    Test_TxCycle();
    ForceGenerate = FALSE;
    Test_ReceiverIdentity();
    len = WireLen - wireStart;
    CHECK((len > 32U) && (Test_WireFreshness(&Wire[wireStart]) == (freshness + 1U)),
          "after the failed transmissions the next PDU is %u bytes with freshness value %u, expected the value after %u",
          (unsigned)len, (unsigned)((len > 32U) ? Test_WireFreshness(&Wire[wireStart]) : 0U), (unsigned)freshness);
    Test_Receive(Socket, &Wire[wireStart], len, 1U, &seen);
    CHECK((seen.Delivered == 1U) && (seen.Ok == 1U) && (seen.Failed == 0U),
          "the PDU sent after the failed transmissions: delivered=%u ok=%u failed=%u, expected 1, 1, 0",
          (unsigned)seen.Delivered, (unsigned)seen.Ok, (unsigned)seen.Failed);
    seq++;

    (void)printf("V4 a Secured I-PDU that does not fit its configured layout is refused before any Csm call\n");
    pdu = Test_TransmitOne(seq, &len);
    if ((len <= 32U) || ((4U * len) > sizeof(NegWire)))
    {
        CHECK(FALSE, "no PDU for the layout case");
        return;
    }
    verifyCalls = RxVerifyCalls;
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &n);

    /* header byte above the maximum, in the same TCP segment as the PDU header [SWS_SecOC_00263] */
    (void)memcpy(NegWire, pdu, len);
    NegWire[8] = (uint8)(SECOC_AUTHPDU_MAX_LENGTH + 1U);
    Test_ReceiveChunked(Socket, NegWire, len, 1U, 4096U, &seen);
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &n);
    CHECK((seen.Delivered == 0U) && (seen.Ok == 0U) && (seen.Failed == 0U) && (n == 1U),
          "header byte above the maximum, arriving with the PDU header: delivered=%u ok=%u failures reported=%u dropped by SoAd=%u, expected 0, 0, 0, 1",
          (unsigned)seen.Delivered, (unsigned)seen.Ok, (unsigned)seen.Failed, (unsigned)n);

    /* the same PDU with the PDU header in a TCP segment of its own: SecOC sees the byte only at verification */
    Test_ReceiveChunked(Socket, NegWire, len, 1U, 8U, &seen);
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &n);
    CHECK((seen.Delivered == 0U) && (seen.Ok == 0U) && (seen.Failed == 1U) && (seen.Last == SECOC_VERIFICATIONFAILURE) && (n == 0U),
          "header byte above the maximum, PDU header arriving alone: delivered=%u ok=%u failures reported=%u (last status %u) dropped by SoAd=%u, expected 0, 0, 1 (SECOC_VERIFICATIONFAILURE), 0",
          (unsigned)seen.Delivered, (unsigned)seen.Ok, (unsigned)seen.Failed, (unsigned)seen.Last, (unsigned)n);

    /* header byte one more than the payload: within the maximum, but the lengths do not add up */
    NegWire[8] = (uint8)(TEST_PAYLOAD_LEN + 1U);
    Test_Receive(Socket, NegWire, len, 1U, &seen);
    CHECK((seen.Delivered == 0U) && (seen.Ok == 0U) && (seen.Failed == 1U) && (seen.Last == SECOC_VERIFICATIONFAILURE),
          "header byte one above the payload length: delivered=%u ok=%u failures reported=%u (last status %u), expected 0, 0, 1 (SECOC_VERIFICATIONFAILURE)",
          (unsigned)seen.Delivered, (unsigned)seen.Ok, (unsigned)seen.Failed, (unsigned)seen.Last);

    /* one byte short */
    (void)memcpy(NegWire, pdu, len - 1U);
    Test_PutBe32(&NegWire[4], len - 8U - 1U);
    Test_Receive(Socket, NegWire, len - 1U, 1U, &seen);
    CHECK((seen.Delivered == 0U) && (seen.Ok == 0U) && (seen.Failed == 1U) && (seen.Last == SECOC_VERIFICATIONFAILURE),
          "one byte short: delivered=%u ok=%u failures reported=%u (last status %u), expected 0, 0, 1 (SECOC_VERIFICATIONFAILURE)",
          (unsigned)seen.Delivered, (unsigned)seen.Ok, (unsigned)seen.Failed, (unsigned)seen.Last);
    CHECK(RxVerifyCalls == verifyCalls, "%u Csm verify call(s) for the four malformed PDUs, expected 0", (unsigned)(RxVerifyCalls - verifyCalls));

    /* as transmitted */
    Test_Receive(Socket, pdu, len, 1U, &seen);
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &n);
    CHECK((seen.Delivered == 1U) && (seen.Ok == 1U) && (seen.Failed == 0U) && (n == 0U),
          "the PDU as transmitted, after the malformed ones: delivered=%u ok=%u failures reported=%u dropped by SoAd=%u, expected 1, 1, 0, 0",
          (unsigned)seen.Delivered, (unsigned)seen.Ok, (unsigned)seen.Failed, (unsigned)n);
}

/********************************************** MAC variant **********************************************/

static void Test_InstallMacKeys(const uint8* TxKey, const uint8* RxKey)
{
    (void)Csm_KeyElementSet(CSM_KEYID_MAC_TX, CRYPTO_KE_MAC_KEY, TxKey, 32U);
    (void)Csm_KeySetValid(CSM_KEYID_MAC_TX);
    (void)Csm_KeyElementSet(CSM_KEYID_MAC_RX, CRYPTO_KE_MAC_KEY, RxKey, 32U);
    (void)Csm_KeySetValid(CSM_KEYID_MAC_RX);
}

/* gateway A (initiator): signs with key pair A, transmits MAC PDUs under K_i2r */
static void Test_NodeA(void)
{
    Test_CsmIdentity(&KeyA);
    Test_InstallMacKeys(KeyI2R, KeyR2I);
}

/* gateway B (responder): A's public key as peer 0, receives MAC PDUs under K_i2r */
static void Test_NodeB(void)
{
    Test_ReceiverIdentity();
    Test_InstallMacKeys(KeyR2I, KeyI2R);
}

/* bytes of one PDU on the TCP stream, from its configuration */
static uint32 Test_WireLength(PduIdType PduId)
{
    return TEST_SOAD_HEADER_LEN
         + (uint32)SecOC_TxPduProcessing[PduId].SecOCTxSecuredPduLayer->SecOCTxSecuredPdu->SecOCAuthPduHeaderLength
         + TEST_PAYLOAD_LEN
         + BIT_TO_BYTES(SecOC_TxPduProcessing[PduId].SecOCFreshnessValueTruncLength)
         + BIT_TO_BYTES(SecOC_TxPduProcessing[PduId].SecOCAuthInfoTruncLength);
}

static uint32 Test_GetBe(const uint8* Ptr, uint32 Length)
{
    uint32 value = 0U;
    uint32 i;
    for (i = 0U; i < Length; i++)
    {
        value = (value << 8U) | (uint32)Ptr[i];
    }
    return value;
}

static boolean Test_IsPayload(const uint8* Data, uint32 Seq)
{
    uint8 expect[TEST_PAYLOAD_LEN];
    Test_Payload(expect, Seq);
    return (memcmp(Data, expect, TEST_PAYLOAD_LEN) == 0) ? TRUE : FALSE;
}

/* SoAd hands one PDU per PDU id and BSW cycle to SecOC, and one TCP read can hold many 37-byte MAC
 * PDUs: after the last read the receiver needs up to one more cycle per PDU. */
static void Test_Drain(uint32 Pdus)
{
    uint32 cycle;
    for (cycle = 0U; cycle < (Pdus + 2U); cycle++)
    {
        Test_RxCycle();
    }
}

/* the receiver reads everything from Wire[Start] on, in random chunks */
static void Test_FeedAll(TcpIp_SocketIdType Socket, uint32 Start)
{
    Test_Feed(Socket, &Wire[Start], WireLen - Start, 0U);
    Test_Drain((WireLen - Start) / Test_WireLength(TEST_MAC_PDU_ID));
}

static void Test_MacKeyNotValid(TcpIp_SocketIdType Socket)
{
    uint32 wireBefore = WireLen;
    uint32 callsBefore = TxMacCalls;
    uint32 deliveredBefore = MacDeliveredCount;
    uint32 verifyBefore = RxMacCalls;
    uint32 acceptedBefore = RxMacOk;
    uint32 authFailBefore = MacStatusAuthFail;
    uint32 freshnessBytes = BIT_TO_BYTES(SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCFreshnessValueLength);

    (void)printf("M1 without a valid MAC key nothing is transmitted and nothing is accepted\n");
    Test_CsmIdentity(&KeyA);                    /* gateway A before any MAC key is installed */
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9001U);
    CHECK(((TxMacCalls - callsBefore) == 1U) && (TxMacJob == CSM_JOBID_MAC_GENERATE),
          "Csm_MacGenerate called %u times, last job %u", (unsigned)(TxMacCalls - callsBefore), (unsigned)TxMacJob);
    CHECK(TxMacResult == CRYPTO_E_KEY_NOT_VALID, "Csm_MacGenerate returned %d, expected CRYPTO_E_KEY_NOT_VALID", (int)TxMacResult);
    CHECK(WireLen == wireBefore, "%u bytes transmitted without a valid key", (unsigned)(WireLen - wireBefore));

    /* [SWS_SecOC_00229] the request is cancelled, not kept until a key arrives */
    Test_InstallMacKeys(KeyI2R, KeyR2I);
    SecOC_MainFunctionTx();
    SoAd_MainFunctionTx();
    CHECK(((TxMacCalls - callsBefore) == 1U) && (WireLen == wireBefore), "the failed PDU was sent once the key became valid");

    /* the next PDU gets the freshness value the failed one did not use */
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9002U);
    CHECK((WireLen - wireBefore) == Test_WireLength(TEST_MAC_PDU_ID), "%u bytes on the wire, expected %u",
          (unsigned)(WireLen - wireBefore), (unsigned)Test_WireLength(TEST_MAC_PDU_ID));
    CHECK(((TxMacCalls - callsBefore) == 2U) &&
          (memcmp(&TxMacD2A[callsBefore][2U + TEST_PAYLOAD_LEN], &TxMacD2A[callsBefore + 1U][2U + TEST_PAYLOAD_LEN], freshnessBytes) == 0),
          "the failed attempt used up a freshness value");
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9003U);
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9004U);

    /* a receiver without a valid MAC key (the real Csm, no key installed): every PDU is one reported
     * verification failure at its first attempt, none is delivered [review 2.1] */
    Test_ReceiverIdentity();
    LastStatus = SECOC_NO_VERIFICATION;
    Test_FeedAll(Socket, wireBefore);
    CHECK(((RxMacCalls - verifyBefore) == 3U) && (RxMacOk == acceptedBefore) && (MacDeliveredCount == deliveredBefore) &&
          ((MacStatusAuthFail - authFailBefore) == 3U) && (LastStatus == SECOC_VERIFICATIONFAILURE),
          "3 MAC PDUs to a receiver without key: %u Csm_MacVerify calls, %u accepted, %u delivered, %u failures reported (last status %u), expected 3, 0, 0, 3 (SECOC_VERIFICATIONFAILURE)",
          (unsigned)(RxMacCalls - verifyBefore), (unsigned)(RxMacOk - acceptedBefore), (unsigned)(MacDeliveredCount - deliveredBefore),
          (unsigned)(MacStatusAuthFail - authFailBefore), (unsigned)LastStatus);

    /* the same bytes once the key is there */
    Test_NodeB();
    Test_FeedAll(Socket, wireBefore);
    CHECK(((MacDeliveredCount - deliveredBefore) == 3U) && (Test_IsPayload(MacDelivered[deliveredBefore], 9002U) == TRUE) &&
          (Test_IsPayload(MacDelivered[deliveredBefore + 2U], 9004U) == TRUE),
          "%u MAC PDUs delivered, expected sequence numbers 9002 to 9004", (unsigned)(MacDeliveredCount - deliveredBefore));
}

static void Test_MacPerPduSelection(TcpIp_SocketIdType Socket)
{
    uint32 start = WireLen;
    uint32 mid;
    uint32 sigGen = TxSigned;
    uint32 macGen = TxMacCalls;
    uint32 sigVer = RxVerifyCalls;
    uint32 macVer = RxMacCalls;
    uint32 sigDelivered = DeliveredCount;
    uint32 macDelivered = MacDeliveredCount;
    uint32 sigAuthFail;
    uint32 macAuthFail;
    SecOC_RxAuthServiceConfigRefType* sigRef = SecOC_RxPduProcessing[TEST_PDU_ID].SecOCRxAuthServiceConfigRef;
    SecOC_RxAuthServiceConfigRefType* macRef = SecOC_RxPduProcessing[TEST_MAC_PDU_ID].SecOCRxAuthServiceConfigRef;

    (void)printf("M2 authenticator chosen per PDU: signature on PDU %u, MAC on PDU %u\n", (unsigned)TEST_PDU_ID, (unsigned)TEST_MAC_PDU_ID);
    CHECK(BIT_TO_BYTES(SecOC_TxPduProcessing[TEST_PDU_ID].SecOCAuthInfoTruncLength) == PQC_MLDSA_SIGNATURE_BYTES,
          "SecOCAuthInfoTruncLength of the signature PDU is %u bytes", (unsigned)BIT_TO_BYTES(SecOC_TxPduProcessing[TEST_PDU_ID].SecOCAuthInfoTruncLength));
    CHECK(SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCAuthInfoTruncLength == 128U,
          "SecOCAuthInfoTruncLength of the MAC PDU is %u bit", (unsigned)SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCAuthInfoTruncLength);
    /* the MAC PDU has the freshness configuration of the signature PDU; they change together */
    CHECK((SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCFreshnessValueLength == SecOC_TxPduProcessing[TEST_PDU_ID].SecOCFreshnessValueLength) &&
          (SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCFreshnessValueTruncLength == SecOC_TxPduProcessing[TEST_PDU_ID].SecOCFreshnessValueTruncLength) &&
          (SecOC_RxPduProcessing[TEST_MAC_PDU_ID].SecOCFreshnessValueLength == SecOC_RxPduProcessing[TEST_PDU_ID].SecOCFreshnessValueLength) &&
          (SecOC_RxPduProcessing[TEST_MAC_PDU_ID].SecOCFreshnessValueTruncLength == SecOC_RxPduProcessing[TEST_PDU_ID].SecOCFreshnessValueTruncLength),
          "freshness configuration of PDU %u differs from PDU %u", (unsigned)TEST_MAC_PDU_ID, (unsigned)TEST_PDU_ID);

    CHECK((SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCFreshnessValueLength == 32U) &&
          (SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCFreshnessValueTruncLength == 32U) &&
          (SecOC_RxPduProcessing[TEST_MAC_PDU_ID].SecOCFreshnessValueLength == 32U) &&
          (SecOC_RxPduProcessing[TEST_MAC_PDU_ID].SecOCFreshnessValueTruncLength == 32U) &&
          (SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCFreshnessValueId == SECOC_FRESHNESS_ID_TX(TEST_MAC_PDU_ID)) &&
          (SecOC_RxPduProcessing[TEST_MAC_PDU_ID].SecOCFreshnessValueId == SECOC_FRESHNESS_ID_RX(TEST_MAC_PDU_ID)),
          "the MAC row does not send the complete 32-bit freshness value under the freshness IDs of the table");

    Test_NodeA();
    Test_TransmitPdu(TEST_PDU_ID, 9101U);
    mid = WireLen;
    CHECK((mid - start) == Test_WireLength(TEST_PDU_ID), "signature PDU: %u bytes on the wire, expected %u",
          (unsigned)(mid - start), (unsigned)Test_WireLength(TEST_PDU_ID));
    CHECK(((TxSigned - sigGen) == 1U) && (TxSigJob == CSM_JOBID) && (TxMacCalls == macGen),
          "signature PDU: %u signature and %u MAC calls, job %u", (unsigned)(TxSigned - sigGen), (unsigned)(TxMacCalls - macGen), (unsigned)TxSigJob);
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9102U);
    CHECK((WireLen - mid) == Test_WireLength(TEST_MAC_PDU_ID), "MAC PDU: %u bytes on the wire, expected %u",
          (unsigned)(WireLen - mid), (unsigned)Test_WireLength(TEST_MAC_PDU_ID));
    CHECK(((TxMacCalls - macGen) == 1U) && (TxMacJob == CSM_JOBID_MAC_GENERATE) && ((TxSigned - sigGen) == 1U),
          "MAC PDU: %u MAC and %u signature calls, job %u", (unsigned)(TxMacCalls - macGen), (unsigned)(TxSigned - sigGen), (unsigned)TxMacJob);
    (void)printf("   on the wire: signature PDU %u bytes (authenticator %u), MAC PDU %u bytes (authenticator %u)\n",
                 (unsigned)(mid - start), (unsigned)BIT_TO_BYTES(SecOC_TxPduProcessing[TEST_PDU_ID].SecOCAuthInfoTruncLength),
                 (unsigned)(WireLen - mid), (unsigned)BIT_TO_BYTES(SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCAuthInfoTruncLength));

    Test_NodeB();
    Test_FeedAll(Socket, start);
    CHECK(((RxVerifyCalls - sigVer) == 1U) && (RxSigJob == CSM_JOBID_VERIFY_PEER_BASE),
          "signature PDU: %u Csm_SignatureVerify calls, job %u", (unsigned)(RxVerifyCalls - sigVer), (unsigned)RxSigJob);
    CHECK(((RxMacCalls - macVer) == 1U) && (RxMacJob == CSM_JOBID_MAC_VERIFY) && (RxMacBits == 128U),
          "MAC PDU: %u Csm_MacVerify calls, job %u, %u bit", (unsigned)(RxMacCalls - macVer), (unsigned)RxMacJob, (unsigned)RxMacBits);
    CHECK(((DeliveredCount - sigDelivered) == 1U) && (Test_IsPayload(Delivered[sigDelivered], 9101U) == TRUE),
          "signature PDU not delivered as sequence number 9101");
    CHECK(((MacDeliveredCount - macDelivered) == 1U) && (Test_IsPayload(MacDelivered[macDelivered], 9102U) == TRUE),
          "MAC PDU not delivered as sequence number 9102");

    /* each authenticator verifies only with its own job: with the two references swapped, neither does */
    Test_NodeA();
    start = WireLen;
    Test_TransmitPdu(TEST_PDU_ID, 9103U);
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9104U);
    Test_NodeB();
    sigDelivered = DeliveredCount;
    macDelivered = MacDeliveredCount;
    sigAuthFail = StatusAuthFail;
    macAuthFail = MacStatusAuthFail;
    SecOC_RxPduProcessing[TEST_PDU_ID].SecOCRxAuthServiceConfigRef = macRef;
    SecOC_RxPduProcessing[TEST_MAC_PDU_ID].SecOCRxAuthServiceConfigRef = sigRef;
    Test_FeedAll(Socket, start);
    SecOC_RxPduProcessing[TEST_PDU_ID].SecOCRxAuthServiceConfigRef = sigRef;
    SecOC_RxPduProcessing[TEST_MAC_PDU_ID].SecOCRxAuthServiceConfigRef = macRef;
    CHECK((DeliveredCount == sigDelivered) && ((StatusAuthFail - sigAuthFail) == 1U),
          "signature PDU under the MAC job: %u delivered, %u failures reported", (unsigned)(DeliveredCount - sigDelivered), (unsigned)(StatusAuthFail - sigAuthFail));
    CHECK((MacDeliveredCount == macDelivered) && ((MacStatusAuthFail - macAuthFail) == 1U),
          "MAC PDU under the signature job: %u delivered, %u failures reported", (unsigned)(MacDeliveredCount - macDelivered), (unsigned)(MacStatusAuthFail - macAuthFail));
}

static void Test_MacDirectionKeys(TcpIp_SocketIdType Socket)
{
    uint32 start = WireLen;
    uint32 macVer = RxMacCalls;
    uint32 macOk = RxMacOk;
    uint32 delivered = MacDeliveredCount;
    uint32 authFail = MacStatusAuthFail;

    (void)printf("M3 a MAC PDU presented to its sender's own receive path is rejected\n");
    Test_NodeA();
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9201U);
    Test_FeedAll(Socket, start);                /* still gateway A: its receive key is K_r2i */
    CHECK(((RxMacCalls - macVer) == 1U) && (RxMacOk == macOk), "%u Csm_MacVerify calls, %u accepted",
          (unsigned)(RxMacCalls - macVer), (unsigned)(RxMacOk - macOk));
    CHECK((MacDeliveredCount == delivered) && ((MacStatusAuthFail - authFail) == 1U),
          "%u delivered, %u authentication failures reported", (unsigned)(MacDeliveredCount - delivered), (unsigned)(MacStatusAuthFail - authFail));

    Test_NodeB();                               /* the same bytes are good for the peer */
    Test_FeedAll(Socket, start);
    CHECK(((MacDeliveredCount - delivered) == 1U) && (Test_IsPayload(MacDelivered[delivered], 9201U) == TRUE),
          "the peer did not accept the same PDU");
}

static void Test_MacSegmentations(TcpIp_SocketIdType Socket)
{
    uint32 start = WireLen;
    uint32 txStart = TxMacCalls;
    uint32 rxStart;
    uint32 macOk;
    uint32 delivered = MacDeliveredCount;
    uint32 statusOk = MacStatusOk;
    uint32 statusFail = MacStatusFreshnessFail + MacStatusAuthFail;
    uint32 pduLen = Test_WireLength(TEST_MAC_PDU_ID);
    /* one more group of PDUs behind those of Test_ChunkSizes, read exactly one PDU at a time: what a
     * sender with TCP no-delay puts on the wire, every MAC PDU in a segment of its own */
    const uint32 total = TEST_NUM_PDUS + TEST_PDUS_PER_SEGMENT;
    uint32 freshnessBytes = BIT_TO_BYTES(SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCFreshnessValueLength);
    uint32 d2aLen = 2U + TEST_PAYLOAD_LEN + freshnessBytes;
    uint32 firstFreshness;
    uint32 segLen;
    uint32 seq;
    uint32 i;

    (void)printf("M4 MAC PDUs over every TCP segmentation\n");
    Test_NodeA();
    for (seq = 1U; seq <= total; seq++)
    {
        Test_TransmitPdu(TEST_MAC_PDU_ID, seq);
    }
    (void)printf("Tx: %u MAC PDUs, %u bytes on the wire (%u per PDU)\n", (unsigned)(TxMacCalls - txStart),
                 (unsigned)(WireLen - start), (unsigned)((WireLen - start) / total));
    CHECK(((TxMacCalls - txStart) == total) && ((WireLen - start) == (total * pduLen)),
          "%u MAC PDUs, %u bytes, expected %u PDUs of %u bytes", (unsigned)(TxMacCalls - txStart), (unsigned)(WireLen - start),
          (unsigned)total, (unsigned)pduLen);

    /* DataToAuthenticator = Data Id (16 bit, big endian) | Authentic I-PDU | complete freshness value, counting up */
    firstFreshness = Test_GetBe(&TxMacD2A[txStart][2U + TEST_PAYLOAD_LEN], freshnessBytes);
    for (i = 0U; i < total; i++)
    {
        const uint8* d2a = TxMacD2A[txStart + i];
        if ((TxMacD2ALen[txStart + i] != d2aLen) || (d2a[0] != (uint8)(TEST_MAC_DATA_ID >> 8U)) || (d2a[1] != (uint8)TEST_MAC_DATA_ID) ||
            (Test_IsPayload(&d2a[2], i + 1U) == FALSE) ||
            (Test_GetBe(&d2a[2U + TEST_PAYLOAD_LEN], freshnessBytes) != (firstFreshness + i)))
        {
            CHECK(FALSE, "MAC PDU %u: Tx DataToAuthenticator len=%u starts %02X %02X", (unsigned)(i + 1U),
                  (unsigned)TxMacD2ALen[txStart + i], d2a[0], d2a[1]);
            break;
        }
    }

    Test_NodeB();
    rxStart = RxMacCalls;
    macOk = RxMacOk;
    segLen = pduLen * TEST_PDUS_PER_SEGMENT;
    for (i = 0U; i <= TEST_SEGMENTS; i++)
    {
        const uint32 chunk = (i < TEST_SEGMENTS) ? Test_ChunkSizes[i] : pduLen;
        uint32 before = MacDeliveredCount;
        Test_Feed(Socket, &Wire[start + (i * segLen)], segLen, chunk);
        Test_Drain(TEST_PDUS_PER_SEGMENT);
        (void)printf("Rx: chunk size %4u%s -> %u of %u MAC PDUs delivered\n", (unsigned)chunk, (i < TEST_SEGMENTS) ? "" : " (one PDU per read)",
                     (unsigned)(MacDeliveredCount - before), (unsigned)TEST_PDUS_PER_SEGMENT);
    }

    CHECK((RxMacCalls - rxStart) == total, "Csm_MacVerify called %u times, expected %u",
          (unsigned)(RxMacCalls - rxStart), (unsigned)total);
    for (i = 0U; (i < (RxMacCalls - rxStart)) && (i < total); i++)
    {
        if ((RxMacD2ALen[rxStart + i] != TxMacD2ALen[txStart + i]) ||
            (memcmp(RxMacD2A[rxStart + i], TxMacD2A[txStart + i], TxMacD2ALen[txStart + i]) != 0))
        {
            CHECK(FALSE, "MAC PDU %u: Rx DataToAuthenticator differs from Tx", (unsigned)(i + 1U));
            break;
        }
    }
    CHECK((RxMacOk - macOk) == total, "%u of %u tags accepted", (unsigned)(RxMacOk - macOk), (unsigned)total);
    CHECK((MacDeliveredCount - delivered) == total, "%u MAC PDUs delivered, expected %u",
          (unsigned)(MacDeliveredCount - delivered), (unsigned)total);
    for (i = 0U; (i < (MacDeliveredCount - delivered)) && (i < total); i++)
    {
        if ((MacDeliveredLen[delivered + i] != TEST_PAYLOAD_LEN) || (Test_IsPayload(MacDelivered[delivered + i], i + 1U) == FALSE))
        {
            CHECK(FALSE, "MAC delivery %u: payload is not sequence number %u", (unsigned)i, (unsigned)(i + 1U));
            break;
        }
    }
    CHECK(((MacStatusOk - statusOk) == total) && ((MacStatusFreshnessFail + MacStatusAuthFail) == statusFail),
          "verification status reported for the MAC PDU: ok=%u, failures=%u", (unsigned)(MacStatusOk - statusOk),
          (unsigned)((MacStatusFreshnessFail + MacStatusAuthFail) - statusFail));
}

static void Test_MixedStream(TcpIp_SocketIdType Socket)
{
    uint32 start = WireLen;
    uint32 sigDelivered = DeliveredCount;
    uint32 macDelivered = MacDeliveredCount;
    uint32 i;

    (void)printf("M5 signature and MAC PDUs interleaved on one connection: each stream complete and in order\n");
    Test_NodeA();
    for (i = 0U; i < TEST_MIXED_PAIRS; i++)
    {
        Test_TransmitPdu(TEST_PDU_ID, 9300U + i);
        Test_TransmitPdu(TEST_MAC_PDU_ID, 9300U + i);
    }
    CHECK((WireLen - start) == (TEST_MIXED_PAIRS * (Test_WireLength(TEST_PDU_ID) + Test_WireLength(TEST_MAC_PDU_ID))),
          "%u bytes on the wire for %u pairs", (unsigned)(WireLen - start), (unsigned)TEST_MIXED_PAIRS);

    Test_NodeB();
    Test_FeedAll(Socket, start);
    CHECK(((DeliveredCount - sigDelivered) == TEST_MIXED_PAIRS) && ((MacDeliveredCount - macDelivered) == TEST_MIXED_PAIRS),
          "%u signature and %u MAC PDUs delivered, expected %u each", (unsigned)(DeliveredCount - sigDelivered),
          (unsigned)(MacDeliveredCount - macDelivered), (unsigned)TEST_MIXED_PAIRS);
    /* each stream in its own order; between the two streams the order of delivery is not fixed (PDUs
     * that are complete in the same BSW cycle are verified in the order of their SecOC PDU IDs) */
    for (i = 0U; (i < TEST_MIXED_PAIRS) && (i < (DeliveredCount - sigDelivered)) && (i < (MacDeliveredCount - macDelivered)); i++)
    {
        if ((Test_IsPayload(Delivered[sigDelivered + i], 9300U + i) == FALSE) ||
            (Test_IsPayload(MacDelivered[macDelivered + i], 9300U + i) == FALSE))
        {
            CHECK(FALSE, "delivery %u of the signature or of the MAC stream is not sequence number %u", (unsigned)i, (unsigned)(9300U + i));
            break;
        }
    }
}

/* five MAC PDUs a..e; the receiver gets
 *   a | b with a flipped tag bit | c | c again | a again (replay) | d one tag byte short | e | e again */
static void Test_MacRejectedPdus(TcpIp_SocketIdType Socket)
{
    uint32 start = WireLen;
    uint32 delivered = MacDeliveredCount;
    uint32 statusOk = MacStatusOk;
    uint32 pduLen = Test_WireLength(TEST_MAC_PDU_ID);
    uint32 dropped = 0U;
    uint32 n = 0U;
    uint32 i;
    const uint8* pdu = &Wire[start];
    static const uint32 expectSeq[3] = { 9401U, 9403U, 9405U };

    (void)printf("M6 rejected MAC PDUs are counted and do not block the ones behind them\n");
    Test_NodeA();
    for (i = 0U; i < TEST_NEG_PDUS; i++)
    {
        Test_TransmitPdu(TEST_MAC_PDU_ID, 9401U + i);
    }
    Test_NodeB();

    (void)memcpy(&NegWire[n], &pdu[0U * pduLen], pduLen);               /* a */
    n += pduLen;
    (void)memcpy(&NegWire[n], &pdu[1U * pduLen], pduLen);               /* b, last tag bit flipped */
    n += pduLen;
    NegWire[n - 1U] ^= 0x01U;
    (void)memcpy(&NegWire[n], &pdu[2U * pduLen], pduLen);               /* c */
    n += pduLen;
    (void)memcpy(&NegWire[n], &pdu[2U * pduLen], pduLen);               /* c again: the counter just accepted */
    n += pduLen;
    (void)memcpy(&NegWire[n], &pdu[0U * pduLen], pduLen);               /* a again: an older counter */
    n += pduLen;
    (void)memcpy(&NegWire[n], &pdu[3U * pduLen], pduLen - 1U);          /* d, 15 of 16 tag bytes */
    Test_PutBe32(&NegWire[n + 4U], pduLen - TEST_SOAD_HEADER_LEN - 1U);
    n += pduLen - 1U;
    (void)memcpy(&NegWire[n], &pdu[4U * pduLen], pduLen);               /* e */
    n += pduLen;
    (void)memcpy(&NegWire[n], &pdu[4U * pduLen], pduLen);               /* e again */
    n += pduLen;

    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    MacStatusFreshnessFail = 0U;
    MacStatusAuthFail = 0U;

    Test_Feed(Socket, NegWire, n, 0U);
    Test_Drain(TEST_NEG_PDUS + 3U);

    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK(dropped == 0U, "SoAd dropped %u PDUs, expected 0", (unsigned)dropped);
    CHECK(MacStatusAuthFail == 2U, "%u authentication failures reported, expected 2 (tampered, truncated)", (unsigned)MacStatusAuthFail);
    CHECK(MacStatusFreshnessFail == 3U, "%u freshness failures reported, expected 3 (c again, a again, e again)", (unsigned)MacStatusFreshnessFail);
    CHECK((MacStatusOk - statusOk) == 3U, "%u successful verifications reported, expected 3", (unsigned)(MacStatusOk - statusOk));
    CHECK((MacDeliveredCount - delivered) == 3U, "%u MAC PDUs delivered, expected 3", (unsigned)(MacDeliveredCount - delivered));
    for (i = 0U; (i < 3U) && (i < (MacDeliveredCount - delivered)); i++)
    {
        CHECK(Test_IsPayload(MacDelivered[delivered + i], expectSeq[i]) == TRUE,
              "MAC delivery %u after the rejected PDUs is not sequence number %u", (unsigned)i, (unsigned)expectSeq[i]);
    }
}

/* M7: the answers of V1 for the MAC PDU, through SoAd, SecOC_MainFunctionRx and verify() */
static void Test_MacVerdicts(TcpIp_SocketIdType Socket)
{
    const uint32 attempts = SecOC_RxPduProcessing[TEST_MAC_PDU_ID].SecOCAuthenticationBuildAttempts;
    uint32 start;
    uint32 delivered;
    uint32 authFail;
    uint32 ok;
    uint32 i;

    (void)printf("M7 MAC PDU: only E_OK with CRYPTO_E_VER_OK delivers; any other Csm answer is one reported failure\n");
    for (i = 0U; i < (TEST_REJECT_OUTCOMES + 2U); i++)
    {
        const boolean busy = (i >= TEST_REJECT_OUTCOMES) ? TRUE : FALSE;
        const Std_ReturnType result = (busy == TRUE) ? ((i == TEST_REJECT_OUTCOMES) ? E_BUSY : QUEUE_FULL) : Test_RejectOutcomes[i].Result;
        const Crypto_VerifyResultType verdict = (busy == TRUE) ? CRYPTO_E_VER_OK : Test_RejectOutcomes[i].Verdict;
        const uint32 calls = (busy == TRUE) ? attempts : 1U;
        const SecOC_VerificationResultType status = (busy == TRUE) ? SECOC_AUTHENTICATIONBUILDFAILURE : SECOC_VERIFICATIONFAILURE;

        start = WireLen;
        Test_NodeA();
        Test_TransmitPdu(TEST_MAC_PDU_ID, 9500U + i);
        Test_NodeB();
        delivered = MacDeliveredCount;
        authFail = MacStatusAuthFail;
        ok = MacStatusOk;
        LastStatus = SECOC_NO_VERIFICATION;
        Test_ForceVerifyOn(result, verdict, 0U);
        Test_FeedAll(Socket, start);
        Test_Drain(4U);
        ForceVerify = FALSE;
        CHECK((MacDeliveredCount == delivered) && (MacStatusOk == ok) && ((MacStatusAuthFail - authFail) == 1U) &&
              (ForceVerifyCalls == calls) && (LastStatus == status),
              "MAC PDU, Csm result 0x%02X with verdict %u: delivered=%u ok=%u failures reported=%u (last status %u) verify calls=%u, expected 0, 0, 1 (status %u), %u",
              (unsigned)result, (unsigned)verdict, (unsigned)(MacDeliveredCount - delivered), (unsigned)(MacStatusOk - ok),
              (unsigned)(MacStatusAuthFail - authFail), (unsigned)LastStatus, (unsigned)ForceVerifyCalls, (unsigned)status, (unsigned)calls);
    }

    /* the stream is not blocked by any of them */
    start = WireLen;
    Test_NodeA();
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9599U);
    Test_NodeB();
    delivered = MacDeliveredCount;
    Test_FeedAll(Socket, start);
    CHECK(((MacDeliveredCount - delivered) == 1U) && (Test_IsPayload(MacDelivered[delivered], 9599U) == TRUE),
          "the MAC PDU after the rejected ones: %u delivered, expected sequence number 9599", (unsigned)(MacDeliveredCount - delivered));
}

/* M8: one MAC PDU, with its Secured I-PDU header byte changed; then as transmitted */
static void Test_MacLayout(TcpIp_SocketIdType Socket)
{
    uint32 start = WireLen;
    uint32 pduLen = Test_WireLength(TEST_MAC_PDU_ID);
    uint32 delivered;
    uint32 authFail;
    uint32 verifyCalls;
    uint32 dropped = 0U;
    uint32 sigStart;
    uint32 sigFail;
    uint32 sigDelivered;
    uint32 sigVerify;
    PduInfoType ifPdu;

    (void)printf("M8 MAC PDU: a header byte above the maximum or not fitting the length, a byte too many, the other PDU's header ID: refused before parsing\n");
    Test_NodeA();
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9601U);
    sigStart = WireLen;
    Test_TransmitPdu(TEST_PDU_ID, 9602U);
    Test_NodeB();
    if (((sigStart - start) != pduLen) || ((pduLen + 1U) > sizeof(NegWire)) || (WireLen <= sigStart))
    {
        CHECK(FALSE, "no MAC PDU and signature PDU for the layout case");
        return;
    }
    delivered = MacDeliveredCount;
    authFail = MacStatusAuthFail;
    verifyCalls = RxMacCalls;
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);

    /* above the maximum, in the TCP segment of the PDU header: refused by SecOC_StartOfReception [SWS_SecOC_00263] */
    (void)memcpy(NegWire, &Wire[start], pduLen);
    NegWire[TEST_SOAD_HEADER_LEN] = (uint8)(SECOC_AUTHPDU_MAX_LENGTH + 1U);
    Test_Feed(Socket, NegWire, pduLen, 4096U);
    Test_Drain(2U);
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK((dropped == 1U) && (MacStatusAuthFail == authFail) && (MacDeliveredCount == delivered),
          "header byte above the maximum, arriving with the PDU header: dropped by SoAd=%u failures reported=%u delivered=%u, expected 1, 0, 0",
          (unsigned)dropped, (unsigned)(MacStatusAuthFail - authFail), (unsigned)(MacDeliveredCount - delivered));

    /* the largest value the header byte can carry, PDU header in a segment of its own: the layout check
     * refuses it before parseSecuredPdu copies with that length */
    NegWire[TEST_SOAD_HEADER_LEN] = 0xFFU;
    LastStatus = SECOC_NO_VERIFICATION;
    Test_Feed(Socket, NegWire, pduLen, 8U);
    Test_Drain(2U);
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK((dropped == 0U) && ((MacStatusAuthFail - authFail) == 1U) && (LastStatus == SECOC_VERIFICATIONFAILURE) && (MacDeliveredCount == delivered),
          "header byte 0xFF, PDU header arriving alone: dropped by SoAd=%u failures reported=%u (last status %u) delivered=%u, expected 0, 1 (SECOC_VERIFICATIONFAILURE), 0",
          (unsigned)dropped, (unsigned)(MacStatusAuthFail - authFail), (unsigned)LastStatus, (unsigned)(MacDeliveredCount - delivered));

    /* one more than the payload: within the maximum, but the lengths do not add up */
    NegWire[TEST_SOAD_HEADER_LEN] = (uint8)(TEST_PAYLOAD_LEN + 1U);
    Test_Feed(Socket, NegWire, pduLen, 0U);
    Test_Drain(2U);
    CHECK(((MacStatusAuthFail - authFail) == 2U) && (MacDeliveredCount == delivered),
          "header byte one above the payload length: %u failures reported in all, %u delivered, expected 2 and 0",
          (unsigned)(MacStatusAuthFail - authFail), (unsigned)(MacDeliveredCount - delivered));

    /* one byte behind the tag (still within the longest PDU SoAd takes for this stream) */
    (void)memcpy(NegWire, &Wire[start], pduLen);
    NegWire[pduLen] = 0x00U;
    Test_PutBe32(&NegWire[4], pduLen - TEST_SOAD_HEADER_LEN + 1U);
    Test_Feed(Socket, NegWire, pduLen + 1U, 0U);
    Test_Drain(2U);
    CHECK(((MacStatusAuthFail - authFail) == 3U) && (MacDeliveredCount == delivered),
          "one byte too long: %u failures reported in all, %u delivered, expected 3 and 0",
          (unsigned)(MacStatusAuthFail - authFail), (unsigned)(MacDeliveredCount - delivered));

    /* the same over-long Secured I-PDU through the IF entry of SecOC: the same rule, the received length */
    ifPdu.SduDataPtr = &NegWire[TEST_SOAD_HEADER_LEN];
    ifPdu.MetaDataPtr = NULL;
    ifPdu.SduLength = (PduLengthType)(pduLen - TEST_SOAD_HEADER_LEN + 1U);
    SecOC_RxIndication(TEST_MAC_PDU_ID, &ifPdu);
    Test_Drain(2U);
    CHECK(((MacStatusAuthFail - authFail) == 4U) && (MacDeliveredCount == delivered),
          "one byte too long, received through SecOC_RxIndication: %u failures reported in all, %u delivered, expected 4 and 0",
          (unsigned)(MacStatusAuthFail - authFail), (unsigned)(MacDeliveredCount - delivered));

    /* the MAC PDU's bytes under the PDU header ID of the signature PDU: refused by the layout of that
     * PDU, reported for its Data ID, no Csm call */
    sigFail = StatusAuthFail;
    sigDelivered = DeliveredCount;
    sigVerify = RxVerifyCalls;
    (void)memcpy(NegWire, &Wire[start], pduLen);
    Test_PutBe32(&NegWire[0], SOAD_HEADERID_SIG(0U));
    Test_Feed(Socket, NegWire, pduLen, 0U);
    Test_Drain(2U);
    CHECK(((StatusAuthFail - sigFail) == 1U) && (DeliveredCount == sigDelivered) && (RxVerifyCalls == sigVerify) &&
          ((MacStatusAuthFail - authFail) == 4U),
          "MAC bytes under the signature PDU's header ID: %u failure(s) reported for the signature PDU, %u delivered, %u Csm_SignatureVerify call(s), expected 1, 0, 0",
          (unsigned)(StatusAuthFail - sigFail), (unsigned)(DeliveredCount - sigDelivered), (unsigned)(RxVerifyCalls - sigVerify));

    /* a signature PDU's bytes under the PDU header ID of the MAC PDU: longer than any PDU of that
     * stream, discarded by SoAd */
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    Test_PutBe32(&Wire[sigStart], SOAD_HEADERID_MAC(0U));
    Test_Feed(Socket, &Wire[sigStart], WireLen - sigStart, 0U);
    Test_Drain(2U);
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK((dropped == 1U) && ((MacStatusAuthFail - authFail) == 4U) && (MacDeliveredCount == delivered) && (DeliveredCount == sigDelivered),
          "signature bytes under the MAC PDU's header ID: dropped by SoAd=%u, MAC failures reported in all=%u, expected 1 and 4",
          (unsigned)dropped, (unsigned)(MacStatusAuthFail - authFail));

    CHECK(RxMacCalls == verifyCalls, "%u Csm_MacVerify call(s) for the malformed MAC PDUs, expected 0", (unsigned)(RxMacCalls - verifyCalls));

    /* as transmitted, through the IF entry: the valid PDU behind the over-long one is accepted there */
    ifPdu.SduDataPtr = &Wire[start + TEST_SOAD_HEADER_LEN];
    ifPdu.SduLength = (PduLengthType)(pduLen - TEST_SOAD_HEADER_LEN);
    SecOC_RxIndication(TEST_MAC_PDU_ID, &ifPdu);
    Test_Drain(2U);
    (void)SoAd_GetAndResetMeasurementData(SOAD_MEAS_DROP_TCP, TRUE, &dropped);
    CHECK(((MacDeliveredCount - delivered) == 1U) && (Test_IsPayload(MacDelivered[delivered], 9601U) == TRUE) && (dropped == 0U),
          "the MAC PDU as transmitted, received through SecOC_RxIndication after the malformed ones: %u delivered, %u dropped by SoAd, expected 1 and 0",
          (unsigned)(MacDeliveredCount - delivered), (unsigned)dropped);
}

/* M9: the Csm generate call says E_OK but wrote fewer bytes than the PDU's SecOCAuthInfoTruncLength */
static void Test_TxShortAuthenticator(void)
{
    static const PduIdType pduIds[2] = { TEST_MAC_PDU_ID, TEST_PDU_ID };
    uint32 i;

    (void)printf("M9 transmit: a Csm that returns fewer authenticator bytes than configured gives no Secured I-PDU\n");
    Test_NodeA();
    for (i = 0U; i < 2U; i++)
    {
        const PduInfoType* txSecured = &SecOC_TxPduProcessing[pduIds[i]].SecOCTxSecuredPduLayer->SecOCTxSecuredPdu->SecOCTxSecuredLayerPduRef;
        const uint32 wireBefore = WireLen;

        ForceGenerateResult = E_OK;
        ForceGenerateLength = BIT_TO_BYTES(SecOC_TxPduProcessing[pduIds[i]].SecOCAuthInfoTruncLength) - 1U;
        ForceGenerateLimit = 0U;
        ForceGenerateCalls = 0U;
        ForceGenerate = TRUE;
        Test_TransmitPdu(pduIds[i], 9700U + i);
        SecOC_MainFunctionTx();
        SoAd_MainFunctionTx();
        ForceGenerate = FALSE;
        ForceGenerateLength = 0U;
        CHECK((WireLen == wireBefore) && (txSecured->SduLength == 0U) && (ForceGenerateCalls == 1U),
              "PDU %u, authenticator one byte short: %u bytes on the wire, Secured I-PDU buffer %u bytes, generate calls=%u, expected 0, 0, 1",
              (unsigned)pduIds[i], (unsigned)(WireLen - wireBefore), (unsigned)txSecured->SduLength, (unsigned)ForceGenerateCalls);
    }
    Test_NodeB();
}

/* M10: the MAC row without a Csm job reference, and with a job of the wrong service */
static void Test_JobReference(TcpIp_SocketIdType Socket)
{
    SecOC_TxAuthServiceConfigRefType* txRef = SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCTxAuthServiceConfigRef;
    SecOC_RxAuthServiceConfigRefType* rxRef = SecOC_RxPduProcessing[TEST_MAC_PDU_ID].SecOCRxAuthServiceConfigRef;
    static Csm_JobType generateJob = { CSM_JOBID_MAC_VERIFY, CRYPTO_MACGENERATE };     /* a verify job id labelled as a generate job */
    static SecOC_RxAuthServiceConfigRefType wrongServiceRef = { &generateJob };
    SecOC_RxAuthServiceConfigRefType* rxRefs[2] = { NULL, &wrongServiceRef };
    uint32 start = WireLen;
    uint32 good;
    uint32 calls;
    uint32 delivered;
    uint32 authFail;
    uint32 i;

    (void)printf("M10 a row without a Csm job of the right service is a configuration error: nothing sent, received PDUs reported as failures\n");

    /* transmit side */
    Test_NodeA();
    calls = TxMacCalls + TxSigned;
    SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCTxAuthServiceConfigRef = NULL;
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9801U);
    SecOC_MainFunctionTx();
    SoAd_MainFunctionTx();
    SecOC_TxPduProcessing[TEST_MAC_PDU_ID].SecOCTxAuthServiceConfigRef = txRef;
    SecOC_MainFunctionTx();
    SoAd_MainFunctionTx();
    CHECK((WireLen == start) && ((TxMacCalls + TxSigned) == calls),
          "Tx row without a job reference: %u bytes on the wire, %u Csm generate call(s), expected 0 and 0",
          (unsigned)(WireLen - start), (unsigned)((TxMacCalls + TxSigned) - calls));

    /* receive side: one PDU in order, presented under each wrong reference, then under the right one */
    good = WireLen;
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9802U);
    Test_NodeB();
    for (i = 0U; i < 2U; i++)
    {
        calls = RxMacCalls + RxVerifyCalls;
        delivered = MacDeliveredCount;
        authFail = MacStatusAuthFail;
        LastStatus = SECOC_NO_VERIFICATION;
        SecOC_RxPduProcessing[TEST_MAC_PDU_ID].SecOCRxAuthServiceConfigRef = rxRefs[i];
        Test_FeedAll(Socket, good);
        SecOC_RxPduProcessing[TEST_MAC_PDU_ID].SecOCRxAuthServiceConfigRef = rxRef;
        CHECK((MacDeliveredCount == delivered) && ((MacStatusAuthFail - authFail) == 1U) && (LastStatus == SECOC_VERIFICATIONFAILURE) &&
              ((RxMacCalls + RxVerifyCalls) == calls),
              "Rx row %s: delivered=%u failures reported=%u (last status %u) Csm verify calls=%u, expected 0, 1 (SECOC_VERIFICATIONFAILURE), 0",
              (i == 0U) ? "without a job reference" : "with a job of a generate service", (unsigned)(MacDeliveredCount - delivered),
              (unsigned)(MacStatusAuthFail - authFail), (unsigned)LastStatus, (unsigned)((RxMacCalls + RxVerifyCalls) - calls));
    }
    delivered = MacDeliveredCount;
    Test_FeedAll(Socket, good);
    CHECK(((MacDeliveredCount - delivered) == 1U) && (Test_IsPayload(MacDelivered[delivered], 9802U) == TRUE),
          "with its job reference back the same PDU is not delivered (%u deliveries)", (unsigned)(MacDeliveredCount - delivered));
}

/* C16 [T5b]: the MAC variant is bound to its session by the key, and the handshake is the only source
 * of that key. A PDU authenticated under a static key (what a key file would give) is refused while
 * no session exists, although the receiver holds the same key, and is an authentication failure once
 * the keys of a session are installed; a PDU of one session is an authentication failure in the next.
 * Every PDU here carries the counter 1 of a new session, so freshness accepts it where it can. */
static void Test_MacSessionBinding(TcpIp_SocketIdType Socket)
{
    static const uint8 staticKey[32] = {
        0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU,
        0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU, 0x4BU };
    uint8 sessionB[32];
    uint8 sessionC[32];
    const uint16 txId = (uint16)SECOC_FRESHNESS_ID_TX(TEST_MAC_PDU_ID);
    const uint16 rxId = (uint16)SECOC_FRESHNESS_ID_RX(TEST_MAC_PDU_ID);
    uint32 deliveredBefore = MacDeliveredCount;
    uint32 start;
    uint32 startB;

    (void)memset(sessionB, 0xB2, sizeof(sessionB));
    (void)memset(sessionC, 0xC3, sizeof(sessionC));

    /* authenticated under the static key */
    FVM_SessionInstall(txId);
    FVM_SessionInstall(rxId);
    Test_CsmIdentity(&KeyA);
    Test_InstallMacKeys(staticKey, staticKey);
    start = WireLen;
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9901U);
    CHECK((WireLen - start) == Test_WireLength(TEST_MAC_PDU_ID), "no MAC PDU was transmitted under the static key");

    /* no session: refused by the freshness function, although the receiver holds the same key */
    Test_ReceiverIdentity();
    Test_InstallMacKeys(staticKey, staticKey);
    EstablishedOverride = 0;
    MacStatusFreshnessFail = 0U;
    MacStatusAuthFail = 0U;
    Test_FeedAll(Socket, start);
    CHECK((MacStatusFreshnessFail == 1U) && (MacStatusAuthFail == 0U) && (MacDeliveredCount == deliveredBefore),
          "MAC PDU without a session: %u freshness failures, %u authentication failures, %u deliveries; expected 1, 0, 0",
          (unsigned)MacStatusFreshnessFail, (unsigned)MacStatusAuthFail, (unsigned)(MacDeliveredCount - deliveredBefore));
    EstablishedOverride = 1;

    /* a session exists: its keys are in the slots, and the tag made with the static key fails */
    Test_InstallMacKeys(sessionB, sessionB);
    Test_Feed(Socket, &Wire[start], WireLen - start, 0U);
    Test_Drain(1U);
    CHECK((MacStatusFreshnessFail == 1U) && (MacStatusAuthFail == 1U) && (MacDeliveredCount == deliveredBefore),
          "MAC PDU under the static key, in a session: %u freshness failures, %u authentication failures, %u deliveries; expected 1, 1, 0",
          (unsigned)MacStatusFreshnessFail, (unsigned)MacStatusAuthFail, (unsigned)(MacDeliveredCount - deliveredBefore));

    /* session B's own PDU is delivered in session B ... */
    FVM_SessionInstall(txId);
    Test_CsmIdentity(&KeyA);
    Test_InstallMacKeys(sessionB, sessionB);
    startB = WireLen;
    Test_TransmitPdu(TEST_MAC_PDU_ID, 9902U);
    Test_ReceiverIdentity();
    Test_InstallMacKeys(sessionB, sessionB);
    Test_Feed(Socket, &Wire[startB], WireLen - startB, 0U);
    Test_Drain(1U);
    CHECK((MacDeliveredCount - deliveredBefore) == 1U, "the MAC PDU of session B was not delivered in session B");

    /* ... and replayed into session C (new keys, counters restarted) it is an authentication failure */
    FVM_SessionInstall(rxId);
    Test_InstallMacKeys(sessionC, sessionC);
    Test_Feed(Socket, &Wire[startB], WireLen - startB, 0U);
    Test_Drain(1U);
    CHECK((MacStatusFreshnessFail == 1U) && (MacStatusAuthFail == 2U) && ((MacDeliveredCount - deliveredBefore) == 1U),
          "MAC PDU of session B replayed into session C: %u freshness failures, %u authentication failures, %u deliveries; expected 1, 2, 1",
          (unsigned)MacStatusFreshnessFail, (unsigned)MacStatusAuthFail, (unsigned)(MacDeliveredCount - deliveredBefore));
}

int main(void)
{
    TcpIp_SocketIdType rxSocket = 0U;
    uint32 seq;
    uint32 i;
    uint32 segLen;

    (void)setvbuf(stdout, NULL, _IOLBF, 0);

    if ((PQC_Init() != PQC_E_OK) || (PQC_MLDSA_KeyGen(&KeyA) != PQC_E_OK) || (PQC_MLDSA_KeyGen(&KeyB) != PQC_E_OK))
    {
        (void)printf("FATAL: ML-DSA key generation failed\n");
        return 2;
    }

    /* ---------------- transmitter: identity A ---------------- */
    Test_CsmIdentity(&KeyA);
    SecOC_Init(&SecOC_Config);
    SoAd_Init(NULL);
    Test_StartBswM(FALSE);
#if (SECOC_ROLE_RECEIVER == TRUE)
    {
        TcpIp_SockAddrType peer;
        Test_Peer(&peer, TRUE);
        rxSocket = 1U;
        NextSocketId = 2U;
        CHECK(SoAd_TcpAccepted(0U, rxSocket, &peer) == E_OK, "the connection from the configured peer is not accepted");
        CHECK(Test_NoDelayAsked(rxSocket) == 1U, "the first accepted socket was asked for TCP no-delay %u time(s), expected once",
              (unsigned)Test_NoDelayAsked(rxSocket));
    }
#endif

    for (seq = 1U; seq <= TEST_NUM_PDUS; seq++)
    {
        Test_Transmit(seq);
    }

    (void)printf("Tx: %u PDUs signed, %u bytes on the wire (%u per PDU)\n",
                 (unsigned)TxSigned, (unsigned)WireLen, (unsigned)(WireLen / TEST_NUM_PDUS));
    CHECK(TxSigned == TEST_NUM_PDUS, "Tx signed %u PDUs, expected %u", (unsigned)TxSigned, (unsigned)TEST_NUM_PDUS);
    CHECK((WireLen > 0U) && ((WireLen % TEST_NUM_PDUS) == 0U), "wire length %u is not a multiple of %u PDUs",
          (unsigned)WireLen, (unsigned)TEST_NUM_PDUS);

    (void)printf("C1 DataToAuthenticator on Tx = DataId(16 bit, big endian) | Authentic I-PDU | Freshness (big endian)\n");
    for (i = 0U; (i < TEST_NUM_PDUS) && (i < TxSigned); i++)
    {
        uint8 expect[TEST_D2A_LEN];
        expect[0] = (uint8)(TEST_DATA_ID >> 8U);
        expect[1] = (uint8)TEST_DATA_ID;
        Test_Payload(&expect[2], i + 1U);
        expect[10] = (uint8)((i + 1U) >> 24U);
        expect[11] = (uint8)((i + 1U) >> 16U);
        expect[12] = (uint8)((i + 1U) >> 8U);
        expect[13] = (uint8)(i + 1U);
        if ((TxD2ALen[i] != TEST_D2A_LEN) || (memcmp(TxD2A[i], expect, TEST_D2A_LEN) != 0))
        {
            CHECK(FALSE, "PDU %u: Tx DataToAuthenticator len=%u first bytes %02X %02X, expected len=%u %02X %02X",
                  (unsigned)(i + 1U), (unsigned)TxD2ALen[i], TxD2A[i][0], TxD2A[i][1],
                  (unsigned)TEST_D2A_LEN, expect[0], expect[1]);
            break;
        }
    }

    CHECK((DriverSignCalls == TEST_NUM_PDUS) && (DriverLengthErrors == 0U),
          "the ML-DSA driver signed %u times, %u of them not over %u bytes under a %u-byte context; expected %u and 0",
          (unsigned)DriverSignCalls, (unsigned)DriverLengthErrors, (unsigned)TEST_D2A_LEN,
          (unsigned)PQC_PDU_SIG_CTX_BYTES, (unsigned)TEST_NUM_PDUS);

    /* ---------------- receiver: identity B, A's public key provisioned as peer 0 ---------------- */
    Test_ReceiverIdentity();

    segLen = (WireLen / TEST_NUM_PDUS) * TEST_PDUS_PER_SEGMENT;
    for (i = 0U; i < TEST_SEGMENTS; i++)
    {
        uint32 before = DeliveredCount;
        Test_Feed(rxSocket, &Wire[i * segLen], segLen, Test_ChunkSizes[i]);
        Test_RxCycle();
        Test_RxCycle();
        (void)printf("Rx: chunk size %4u -> %u of %u PDUs delivered\n", (unsigned)Test_ChunkSizes[i],
                     (unsigned)(DeliveredCount - before), (unsigned)TEST_PDUS_PER_SEGMENT);
    }

    (void)printf("C2 Rx DataToAuthenticator identical to Tx\n");
    CHECK(RxVerifyCalls == TEST_NUM_PDUS, "Csm_SignatureVerify called %u times, expected %u",
          (unsigned)RxVerifyCalls, (unsigned)TEST_NUM_PDUS);
    for (i = 0U; (i < RxVerifyCalls) && (i < TEST_NUM_PDUS); i++)
    {
        if ((RxD2ALen[i] != TxD2ALen[i]) || (memcmp(RxD2A[i], TxD2A[i], TxD2ALen[i]) != 0))
        {
            CHECK(FALSE, "PDU %u: Rx DataToAuthenticator differs from Tx (len %u vs %u)",
                  (unsigned)(i + 1U), (unsigned)RxD2ALen[i], (unsigned)TxD2ALen[i]);
            break;
        }
    }

    (void)printf("C3 signatures verify with the peer public key\n");
    CHECK(RxVerifyOk == TEST_NUM_PDUS, "%u of %u verifications succeeded", (unsigned)RxVerifyOk, (unsigned)TEST_NUM_PDUS);

    (void)printf("C4 every PDU delivered once, in order, byte-exact\n");
    CHECK(DeliveredCount == TEST_NUM_PDUS, "%u PDUs delivered, expected %u", (unsigned)DeliveredCount, (unsigned)TEST_NUM_PDUS);
    for (i = 0U; (i < DeliveredCount) && (i < TEST_NUM_PDUS); i++)
    {
        uint8 expect[TEST_PAYLOAD_LEN];
        Test_Payload(expect, i + 1U);
        if ((DeliveredLen[i] != TEST_PAYLOAD_LEN) || (memcmp(Delivered[i], expect, TEST_PAYLOAD_LEN) != 0))
        {
            CHECK(FALSE, "delivery %u: payload is not sequence number %u", (unsigned)i, (unsigned)(i + 1U));
            break;
        }
    }

    CHECK((StatusOk == TEST_NUM_PDUS) && (StatusFreshnessFail == 0U) && (StatusAuthFail == 0U),
          "verification status reported: ok=%u freshness_fail=%u auth_fail=%u", (unsigned)StatusOk,
          (unsigned)StatusFreshnessFail, (unsigned)StatusAuthFail);

    (void)printf("C5 rejected PDUs are counted and do not block the ones behind them (BswM running, default configuration)\n");
    Test_RejectedPdus(rxSocket, TEST_NUM_PDUS + 1U, FALSE);

    (void)printf("C6 freshness in full: a gap is accepted, a rejected PDU at low byte 0xFF does not desynchronise, an older value is rejected\n");
    Test_FreshnessInFull(rxSocket, TEST_NUM_PDUS + 10U);

    (void)printf("C7 one connection at a time from the configured peer; a closed or implausible stream ends cleanly and a new connection works\n");
    rxSocket = Test_Connections(rxSocket, TEST_NUM_PDUS + 20U);

    (void)printf("C17 TCP no-delay: asked for on every TCP socket taken into use, before a connect and on the accepted socket; a socket that cannot be set is not used\n");
    rxSocket = Test_TcpNoDelay(rxSocket, TEST_NUM_PDUS + 24U);

    (void)printf("C19 a CAN frame with the ID of an Ethernet row is dropped by CanIf: that row's buffer is untouched, its PDU is delivered; a CAN row still receives\n");
    Test_CanFrameOnEthernetRow(rxSocket, TEST_NUM_PDUS + 25U);

    (void)printf("C8 a second upper layer on the connection: dispatch by header ID, exact length, gate, request order, mode changes\n");
    rxSocket = Test_SecondUpperLayer(rxSocket, TEST_NUM_PDUS + 30U);

    (void)printf("C9 four signature streams interleaved on the connection: complete, in order, undisturbed by rejected and unroutable PDUs\n");
    Test_Streams(rxSocket);

    (void)printf("C10 session boundaries: hold and release, flushed, drained, counters restarted\n");
    rxSocket = Test_SessionBoundaries(rxSocket, TEST_NUM_PDUS + 40U);

    (void)printf("C12 session counter: sent in full, nothing accepted at or below the last value, nothing sent after 2^32 - 1\n");
    Test_SessionCounter(rxSocket, TEST_NUM_PDUS + 60U);

    (void)printf("C13 session context: 14 bytes signed under 64; a PDU of another session or of no session is an authentication failure\n");
    Test_SessionContext(rxSocket, TEST_NUM_PDUS + 70U);

    (void)printf("C14 no session: a genuine PDU is a freshness failure until a session is established (TP and IF, also after a failed installation)\n");
    Test_NoSessionGate(rxSocket, TEST_NUM_PDUS + 80U);

    (void)printf("C15 a CAN row (0) verifies what the same node signed, with the loopback verify job\n");
    Test_CanRowLoopback();

    Test_Verdicts(rxSocket, TEST_NUM_PDUS + 100U);

    /* MAC variant on the same connection, BswM in its default configuration */
    WireLen = 0U;
    Test_MacKeyNotValid(rxSocket);
    Test_MacPerPduSelection(rxSocket);
    Test_MacDirectionKeys(rxSocket);
    Test_MacSegmentations(rxSocket);
    Test_MixedStream(rxSocket);
    Test_MacRejectedPdus(rxSocket);
    Test_MacVerdicts(rxSocket);
    Test_MacLayout(rxSocket);
    Test_TxShortAuthenticator();
    Test_JobReference(rxSocket);

    (void)printf("C16 MAC variant bound to its session: a static key is refused without a session and fails in one; a PDU of one session fails in the next\n");
    Test_MacSessionBinding(rxSocket);

    (void)printf("C11 with BswM configured as found, the PDUs behind a tampered one are discarded\n");
    Test_StartBswM(TRUE);
    Test_RejectedPdus(rxSocket, TEST_NUM_PDUS + 50U, TRUE);

    (void)printf("C18 SoAdSocketTcpNoDelay TRUE, FALSE and absent: the Nagle parameter is asked for with 0x00, with 0x01, and not at all\n");
    Test_TcpNoDelayConfig();

    (void)printf("%s: %u failed check(s)\n", (Failures == 0U) ? "PASS" : "FAIL", (unsigned)Failures);
    return (Failures == 0U) ? 0 : 1;
}
