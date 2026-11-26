/********************************************************************************************************/
/*  File:   include/App/App_Rx.h                                                                          */
/*  Brief:  Receiver application for the SecOC PQC Ethernet path: takes the authentic payload from Com    */
/*          and logs every reception outcome. Counterpart of App_Tx, active when SECOC_ROLE_RECEIVER.     */
/********************************************************************************************************/
#ifndef INCLUDE_APP_APP_RX_H_
#define INCLUDE_APP_APP_RX_H_

#include "Std_Types.h"
#include "ComStack_Types.h"

/* RxPduId of the Ethernet/SoAd-TP path and its SecOCDataId (SecOC_Lcfg.c); the Data Id is the stream id in the CSV. */
#define APP_RX_SECOC_PDU_ID                ((PduIdType)2U)
#define APP_RX_SECOC_DATA_ID               ((uint16)2U)

void App_Rx_Init(void);
void App_Rx_MainFunction(void);

/* Com Rx notification: an authentic I-PDU has been delivered to Com. */
void App_Rx_RxNotification(PduIdType RxPduId, const uint8* DataPtr, uint16 Length);

#endif /* INCLUDE_APP_APP_RX_H_ */
