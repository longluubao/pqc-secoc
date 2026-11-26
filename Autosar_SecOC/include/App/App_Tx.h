/********************************************************************************************************/
/*  File:   include/App/App_Tx.h                                                                          */
/*  Brief:  Application-layer cyclic Tx driver for the SecOC PQC Ethernet path.                           */
/*          Drives SecOC_TpTransmit on TxPduId=2 once per period, gated on SECOC_ROLE_SENDER, and logs    */
/*          every PDU when its transmission is confirmed. Run parameters: see App_Log.h.                  */
/********************************************************************************************************/
#ifndef INCLUDE_APP_APP_TX_H_
#define INCLUDE_APP_APP_TX_H_

#include "Std_Types.h"
#include "ComStack_Types.h"
#include "SecOC/SecOC_Cfg.h"

/* TxPduId for the Ethernet/SoAd-TP path; also used as the stream id in the CSV (its SecOCDataId is 2 too). */
#define APP_TX_SECOC_PDU_ID                ((PduIdType)2U)

/* Cyclic period in BSW cycles. With Os_TaskBswCycle ~1ms, 1000 = 1 second. */
#ifndef APP_TX_PERIOD_CYCLES
#define APP_TX_PERIOD_CYCLES               (1000U)
#endif

/* No PDU during the first second: the socket connection and the routing group come up first. */
#define APP_TX_WARMUP_CYCLES               (1000U)
/* A PDU not confirmed after this many cycles is submitted again. */
#define APP_TX_CONFIRM_TIMEOUT_CYCLES      (2000U)

/* 8 bytes: the sequence number, big endian, in the last four. */
#define APP_TX_PAYLOAD_LENGTH              (8U)

void   App_Tx_Init(void);
void   App_Tx_DeInit(void);
void   App_Tx_MainFunction(void);
void   App_Tx_Enable(boolean Enable);
uint32 App_Tx_GetTxRequestCount(void);

/* Com Tx notification: the transmission of an I-PDU has been confirmed (or has failed). */
void   App_Tx_TxConfirmation(PduIdType TxPduId, Std_ReturnType Result);

#endif /* INCLUDE_APP_APP_TX_H_ */
