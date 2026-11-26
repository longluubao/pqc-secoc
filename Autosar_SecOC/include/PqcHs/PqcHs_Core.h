#ifndef INCLUDE_PQCHS_CORE_H_
#define INCLUDE_PQCHS_CORE_H_

/********************************************************************************************************/
/*  PqcHs core: one handshake instance as a state object passed by pointer. Used by PqcHs.c (which maps   */
/*  PDU ids and the clock onto instances) and by the in-process tests (an initiator and a responder       */
/*  instance back to back). Time for the timers is passed in; nothing here reads a PDU id table.          */
/********************************************************************************************************/

#include "PqcHs/PqcHs.h"

#define PQCHS_ATTEMPT_LOG_SIZE      (8U)

typedef enum
{
    PQCHS_STATE_IDLE = 0U,
    /* initiator */
    PQCHS_STATE_I_WAIT_M2,          /* M1 on its way, decapsulation key in the crypto layer */
    PQCHS_STATE_I_RETRY,            /* attempt ended without a session; a new one starts at the deadline */
    PQCHS_STATE_I_CUTOVER,          /* M2 accepted, M3 built: transmission held until SecOC has flushed */
    PQCHS_STATE_I_SEND_M3,          /* M3 handed to SoAd, keys not installed yet */
    PQCHS_STATE_I_WAIT_M4,          /* keys installed, waiting for the acknowledgement */
    /* responder */
    PQCHS_STATE_R_PENDING,          /* M2 sent, derived keys pending */
    PQCHS_STATE_R_INSTALL           /* M3 accepted: installs when SecOC has verified what came before M3 */
} PqcHs_StateType;

typedef struct
{
    const PqcHs_InstanceConfigType* Cfg;
    const PqcHs_TimersType* Timers;
    PqcHs_StateType State;
    boolean InitiateRequest;
    boolean ConnectionChanged;      /* initiator: seen by the next main function */

    /* session, per pinned peer; changed only by a key installation */
    boolean Established;
    uint8 Sid[PQCHS_SID_BYTES];
    uint32 InstallCount;

    /* timers, milliseconds of the time passed to the main function */
    uint64 DeadlineMs;              /* the timer of the present state; responder: T_pend */
    uint64 RetryMs;                 /* initiator: T_A after the M1 of the present attempt */
    uint64 LastM1Ms;
    boolean LastM1Valid;

    /* reception: one message at a time, processed in the main function */
    uint8 RxMsg;                    /* index into PqcHsRxPduId */
    boolean RxActive;
    boolean RxReady;
    boolean RxGated;                /* M3 complete: SoAd has closed the stream gate, a release is owed */
    uint32 RxLength;
    uint32 RxExpected;
    uint64 RxDoneNs;
    uint8 Rx[PQCHS_M2_BYTES];

    /* transmission */
    boolean TxActive;
    boolean TxRequesting;           /* inside SoAd_TpTransmit: an ONLINE reported now comes from that request */
    boolean TxDone;
    Std_ReturnType TxResult;
    uint8 TxMsg;                    /* index into PqcHsTxPduId */
    uint32 TxLength;
    uint32 TxPos;
    boolean TxHeld;                 /* SecOC transmission of this peer is held (cut-over) */

    /* transcript (public) */
    uint8 M1[PQCHS_M1_BYTES];
    uint8 M2[PQCHS_M2_BYTES];
    uint8 M3[PQCHS_M3_BYTES];
    uint8 M4[PQCHS_M4_BYTES];
    uint8 Sess[PQCHS_HASH_BYTES];

    /* pending keys K_kc_r, K_kc_i, K_auth_i2r, K_auth_r2i (the output of the key derivation), each
     * erased when used, installed, failed or timed out */
    uint8 Keys[4][PQCHS_KEY_BYTES];

    /* current attempt and the rows not yet read */
    boolean AttemptOpen;
    boolean AttemptInstalled;
    uint64 AttemptStartNs;
    uint64 AttemptTotalNs;
    uint32 AttemptBytesTx;
    uint32 AttemptBytesRx;
    PqcHs_StageTimesType AttemptTimes;
    uint32 NextSeq;
    uint8 LogHead;
    uint8 LogCount;
    PqcHs_AttemptInfoType Log[PQCHS_ATTEMPT_LOG_SIZE];
} PqcHs_InstanceType;

Std_ReturnType PqcHs_Core_Init(PqcHs_InstanceType* Inst, const PqcHs_InstanceConfigType* Cfg,
                               const PqcHs_TimersType* Timers);
void PqcHs_Core_MainFunction(PqcHs_InstanceType* Inst, uint64 NowMs);
Std_ReturnType PqcHs_Core_Initiate(PqcHs_InstanceType* Inst);
void PqcHs_Core_SoConModeChg(PqcHs_InstanceType* Inst, SoAd_SoConModeType Mode);
Std_ReturnType PqcHs_Core_ReadAttempt(PqcHs_InstanceType* Inst, PqcHs_AttemptInfoType* AttemptPtr);

/* RxMsg / TxMsg: index of the message in the instance's PqcHsRxPduId / PqcHsTxPduId */
BufReq_ReturnType PqcHs_Core_StartOfReception(PqcHs_InstanceType* Inst, uint8 RxMsg, PduLengthType TpSduLength,
                                              PduLengthType* bufferSizePtr);
BufReq_ReturnType PqcHs_Core_CopyRxData(PqcHs_InstanceType* Inst, uint8 RxMsg, const PduInfoType* info,
                                        PduLengthType* bufferSizePtr);
void PqcHs_Core_RxIndication(PqcHs_InstanceType* Inst, uint8 RxMsg, Std_ReturnType result);
BufReq_ReturnType PqcHs_Core_CopyTxData(PqcHs_InstanceType* Inst, uint8 TxMsg, const PduInfoType* info,
                                        PduLengthType* availableDataPtr);
void PqcHs_Core_TxConfirmation(PqcHs_InstanceType* Inst, uint8 TxMsg, Std_ReturnType result);

#endif
