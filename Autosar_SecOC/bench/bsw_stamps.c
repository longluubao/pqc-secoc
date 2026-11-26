/* bsw_stamps.c: see bsw_stamps.h. Self-contained: needs the BSW headers and nothing of the bench. */
#define _GNU_SOURCE
#include "bsw_stamps.h"

#include <stddef.h>
#include <time.h>

#include "Csm.h"
#if __has_include("Csm_Pqc.h")
#include "Csm_Pqc.h"
#endif
#include "SoAd_PduIds.h"

typedef struct {
    uint64_t rxDone;
    uint64_t verifyDone;
    uint64_t deliver;
    uint64_t authDone;
    uint64_t sendDone;
} stamps_t;

static stamps_t Stamps[SOAD_NUM_PDU_IDS];
static PduIdType LastVerdictPdu;
static BswStamps_ObserverType Observer;

void __real_PduR_SoAdTpRxIndication(PduIdType id, Std_ReturnType result);
void __real_SecOC_VerificationStatusCallout(SecOC_VerificationStatusType verificationStatus);
void __real_Com_RxIndication(PduIdType RxPduId, const PduInfoType* PduInfoPtr);
Std_ReturnType __real_Csm_SignatureGenerate(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                            uint32 dataLength, uint8* signaturePtr, uint32* signatureLengthPtr);
Std_ReturnType __real_Csm_MacGenerate(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                      uint32 dataLength, uint8* macPtr, uint32* macLengthPtr);
void __real_PduR_SoAdTpTxConfirmation(PduIdType TxPduId, Std_ReturnType result);

static uint64_t now_ns(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

/* an ID outside the table shares slot 0 with nothing real: PDU 0 is not an Ethernet PDU */
static stamps_t* of(PduIdType pdu)
{
    return &Stamps[((uint32)pdu < SOAD_NUM_PDU_IDS) ? (uint32)pdu : 0U];
}

uint64_t BswStamps_RxDoneNs(PduIdType pdu)     { return of(pdu)->rxDone; }
uint64_t BswStamps_VerifyDoneNs(PduIdType pdu) { return of(pdu)->verifyDone; }
uint64_t BswStamps_DeliverNs(PduIdType pdu)    { return of(pdu)->deliver; }
uint64_t BswStamps_AuthDoneNs(PduIdType pdu)   { return of(pdu)->authDone; }
uint64_t BswStamps_SendDoneNs(PduIdType pdu)   { return of(pdu)->sendDone; }

void BswStamps_SetObserver(const BswStamps_ObserverType* observer)
{
    static const BswStamps_ObserverType none = { NULL, NULL, NULL, NULL, NULL };
    Observer = (observer != NULL) ? *observer : none;
}

void __wrap_PduR_SoAdTpRxIndication(PduIdType id, Std_ReturnType result)
{
    uint64_t now = now_ns();
    stamps_t* s = of(id);
    s->rxDone = now;
    s->verifyDone = 0U;
    s->deliver = 0U;
    if (Observer.RxDone != NULL) {
        Observer.RxDone(id, now);
    }
    __real_PduR_SoAdTpRxIndication(id, result);
}

void __wrap_SecOC_VerificationStatusCallout(SecOC_VerificationStatusType verificationStatus)
{
    uint64_t now = now_ns();
    PduIdType pdu = (PduIdType)verificationStatus.secOCDataId;
    of(pdu)->verifyDone = now;
    LastVerdictPdu = pdu;
    if ((Observer.Verified != NULL) && (Observer.Verified(pdu, verificationStatus.verificationStatus, now) == TRUE)) {
        return;
    }
    __real_SecOC_VerificationStatusCallout(verificationStatus);
}

void __wrap_Com_RxIndication(PduIdType RxPduId, const PduInfoType* PduInfoPtr)
{
    uint64_t now = now_ns();
    of(LastVerdictPdu)->deliver = now;
    if ((Observer.Delivered != NULL) && (Observer.Delivered(LastVerdictPdu, PduInfoPtr, now) == TRUE)) {
        return;
    }
    __real_Com_RxIndication(RxPduId, PduInfoPtr);
}

Std_ReturnType __wrap_Csm_SignatureGenerate(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                            uint32 dataLength, uint8* signaturePtr, uint32* signatureLengthPtr)
{
    Std_ReturnType result = __real_Csm_SignatureGenerate(jobId, mode, dataPtr, dataLength, signaturePtr,
                                                         signatureLengthPtr);
    uint64_t now = now_ns();
#ifdef CSM_JOBID_HS_SIGN
    if (jobId == CSM_JOBID_HS_SIGN) {
        return result;      /* the handshake's signature: no PDU, and its first bytes are no Data ID */
    }
#endif
    if ((dataPtr != NULL) && (dataLength >= 2U)) {
        PduIdType pdu = (PduIdType)(((uint32)dataPtr[0] << 8U) | (uint32)dataPtr[1]);
        of(pdu)->authDone = now;
        if (Observer.Signed != NULL) {
            Observer.Signed(pdu, now);
        }
    }
    return result;
}

/* auth_done of a MAC stream. The handshake's confirmation MACs use jobs of their own and are no PDU
 * authenticators: only the peers' PDU MAC jobs count. */
Std_ReturnType __wrap_Csm_MacGenerate(uint32 jobId, Crypto_OperationModeType mode, const uint8* dataPtr,
                                      uint32 dataLength, uint8* macPtr, uint32* macLengthPtr)
{
    Std_ReturnType result = __real_Csm_MacGenerate(jobId, mode, dataPtr, dataLength, macPtr, macLengthPtr);
    uint64_t now = now_ns();
    uint32 peer;
    for (peer = 0U; peer < (uint32)CSM_MAX_PEERS; peer++) {
        if ((jobId == CSM_JOBID_MAC_GENERATE_PEER(peer)) && (dataPtr != NULL) && (dataLength >= 2U)) {
            PduIdType pdu = (PduIdType)(((uint32)dataPtr[0] << 8U) | (uint32)dataPtr[1]);
            of(pdu)->authDone = now;
            if (Observer.Signed != NULL) {
                Observer.Signed(pdu, now);
            }
            break;
        }
    }
    return result;
}

void __wrap_PduR_SoAdTpTxConfirmation(PduIdType TxPduId, Std_ReturnType result)
{
    uint64_t now = now_ns();
    if (result == E_OK) {
        of(TxPduId)->sendDone = now;
    }
    if (Observer.TxConfirmed != NULL) {
        Observer.TxConfirmed(TxPduId, result, now);
    }
    __real_PduR_SoAdTpTxConfirmation(TxPduId, result);
}
