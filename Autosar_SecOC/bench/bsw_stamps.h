/* bsw_stamps: the instants of the BSW data path, taken by link-time wraps. No BSW source is edited.
 *
 * Link bsw_stamps.c into a binary that contains the BSW and give the linker all six options,
 * whatever the role of the binary (the file refers to the six real functions):
 *   -Wl,--wrap=PduR_SoAdTpRxIndication -Wl,--wrap=SecOC_VerificationStatusCallout
 *   -Wl,--wrap=Com_RxIndication -Wl,--wrap=Csm_SignatureGenerate -Wl,--wrap=PduR_SoAdTpTxConfirmation
 *   -Wl,--wrap=Csm_MacGenerate
 * Each wrap takes one CLOCK_MONOTONIC reading, stores it under the PDU ID, tells the observer if
 * there is one, and passes the call on unchanged.
 *
 *   rx_done      PduR_SoAdTpRxIndication: SoAd has handed the last byte of the Secured I-PDU up
 *   verify_done  SecOC_VerificationStatusCallout: SecOC's verdict [SWS_SecOC_00119], for accepted
 *                and for rejected PDUs. The callout names the PDU by its Data ID, which for the
 *                streams of SoAd_PduIds.h is the PDU ID.
 *   deliver      Com_RxIndication: the Authentic I-PDU reaches the upper layer. Com numbers its
 *                PDUs differently; the instant is stored for the PDU of the last verdict, because
 *                SecOC delivers a PDU right after its callout.
 *   auth_done    Csm_SignatureGenerate has returned, or Csm_MacGenerate for a MAC stream (the PDU
 *                MAC jobs only, not the handshake's confirmation MACs). The PDU is read from the
 *                Data ID in the first two bytes of the data to authenticate.
 *   send_done    PduR_SoAdTpTxConfirmation with E_OK: TcpIp has taken the last byte of the PDU
 *
 * A getter returns the most recent instant of that kind for the PDU, 0 if there is none. A new
 * reception of a PDU clears its verify_done and deliver; the transmit instants are not cleared, so
 * compare them with the instant the job was handed over to know that they belong to it.
 */
#ifndef BSW_STAMPS_H
#define BSW_STAMPS_H

#include <stdint.h>

#include "Std_Types.h"
#include "ComStack_Types.h"
#include "Rte_SecOC.h"

uint64_t BswStamps_RxDoneNs(PduIdType pdu);
uint64_t BswStamps_VerifyDoneNs(PduIdType pdu);
uint64_t BswStamps_DeliverNs(PduIdType pdu);
uint64_t BswStamps_AuthDoneNs(PduIdType pdu);
uint64_t BswStamps_SendDoneNs(PduIdType pdu);

/* Optional: functions called from inside the wraps, after the instant is stored and before the
 * call goes on. Any member may be NULL. Verified and Delivered return TRUE when the call must NOT
 * go on to the BSW function: for a harness that is itself the upper layer. */
typedef struct {
    void    (*RxDone)(PduIdType pdu, uint64_t ns);
    boolean (*Verified)(PduIdType pdu, SecOC_VerificationResultType result, uint64_t ns);
    boolean (*Delivered)(PduIdType pdu, const PduInfoType* info, uint64_t ns);
    void    (*Signed)(PduIdType pdu, uint64_t ns);
    void    (*TxConfirmed)(PduIdType pdu, Std_ReturnType result, uint64_t ns);
} BswStamps_ObserverType;

void BswStamps_SetObserver(const BswStamps_ObserverType* observer);

#endif /* BSW_STAMPS_H */
