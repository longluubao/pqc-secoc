/********************************************************************************************************/
/*  PqcHs: the module layer over the core. Maps SoAd PDU ids, socket connections and peers onto the       */
/*  handshake instances and supplies the time for the timers. No protocol logic here.                     */
/********************************************************************************************************/

#include "PqcHs/PqcHs.h"
#include "PqcHs/PqcHs_Core.h"

#include <time.h>

#ifndef PQCHS_MAX_INSTANCES
#define PQCHS_MAX_INSTANCES     CSM_MAX_PEERS
#endif

static const PqcHs_ConfigType* PqcHs_ConfigPtr = NULL;
static PqcHs_InstanceType PqcHs_Instances[PQCHS_MAX_INSTANCES];

/* SoAd reaches this component through its table of upper layers (routes of the handshake PDUs) */
static const SoAd_UpperLayerType PqcHs_SoAdUpperLayer =
{
    PqcHs_SoAdTpStartOfReception,
    PqcHs_SoAdTpCopyRxData,
    PqcHs_SoAdTpRxIndication,
    PqcHs_SoAdTpCopyTxData,
    PqcHs_SoAdTpTxConfirmation,
    PqcHs_SoConModeChg
};

/********************************************************************************************************/
/****************************************StaticFunctions*************************************************/
/********************************************************************************************************/

static uint8 PqcHs_NumInstances(void)
{
    return (PqcHs_ConfigPtr != NULL) ? PqcHs_ConfigPtr->PqcHsNumInstances : 0U;
}

/* Instance and message index of a PDU id; Transmit selects the Tx or the Rx ids. A message of the
 * other role has no id here and is dropped by the caller. */
static PqcHs_InstanceType* PqcHs_FindPdu(PduIdType Id, boolean Transmit, uint8* MsgPtr)
{
    uint8 idx;
    uint8 msg;

    for (idx = 0U; idx < PqcHs_NumInstances(); idx++)
    {
        const PqcHs_InstanceConfigType* cfg = &PqcHs_ConfigPtr->PqcHsInstances[idx];

        for (msg = 0U; msg < 2U; msg++)
        {
            if (((Transmit == TRUE) ? cfg->PqcHsTxPduId[msg] : cfg->PqcHsRxPduId[msg]) == Id)
            {
                *MsgPtr = msg;
                return &PqcHs_Instances[idx];
            }
        }
    }
    return NULL;
}

static PqcHs_InstanceType* PqcHs_FindPeer(uint8 Peer)
{
    uint8 idx;

    for (idx = 0U; idx < PqcHs_NumInstances(); idx++)
    {
        if (PqcHs_ConfigPtr->PqcHsInstances[idx].PqcHsPeer == Peer)
        {
            return &PqcHs_Instances[idx];
        }
    }
    return NULL;
}

/********************************************************************************************************/
/********************************************PublicFunctions*********************************************/
/********************************************************************************************************/

Std_ReturnType PqcHs_Init(const PqcHs_ConfigType* ConfigPtr)
{
    const PqcHs_ConfigType* config = (ConfigPtr != NULL) ? ConfigPtr : &PqcHs_Config;
    uint8 idx;

    PqcHs_ConfigPtr = NULL;
    if ((config->PqcHsInstances == NULL) || (config->PqcHsNumInstances > PQCHS_MAX_INSTANCES))
    {
        return E_NOT_OK;
    }
    for (idx = 0U; idx < config->PqcHsNumInstances; idx++)
    {
        if (PqcHs_Core_Init(&PqcHs_Instances[idx], &config->PqcHsInstances[idx], &config->PqcHsTimers) != E_OK)
        {
            return E_NOT_OK;
        }
    }
    PqcHs_ConfigPtr = config;

    /* Last: SoAd reports a connection that is already up at once (the connecting side connects in
     * SoAd_Init), and that call needs the instances. */
    return SoAd_SetUpperLayer(SOAD_UPPER_LAYER_HS, &PqcHs_SoAdUpperLayer);
}

void PqcHs_MainFunction(void)
{
    struct timespec ts;
    uint64 nowMs;
    uint8 idx;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    nowMs = ((uint64)ts.tv_sec * 1000ULL) + ((uint64)ts.tv_nsec / 1000000ULL);

    for (idx = 0U; idx < PqcHs_NumInstances(); idx++)
    {
        PqcHs_Core_MainFunction(&PqcHs_Instances[idx], nowMs);
    }
}

Std_ReturnType PqcHs_Initiate(uint8 Peer)
{
    return PqcHs_Core_Initiate(PqcHs_FindPeer(Peer));
}

boolean PqcHs_IsEstablished(uint8 Peer)
{
    const PqcHs_InstanceType* inst = PqcHs_FindPeer(Peer);

    return ((inst != NULL) && (inst->Established == TRUE)) ? TRUE : FALSE;
}

Std_ReturnType PqcHs_GetSession(uint8 Peer, uint8* SidPtr, uint32* InstallCountPtr)
{
    const PqcHs_InstanceType* inst = PqcHs_FindPeer(Peer);
    uint8 idx;

    if ((inst == NULL) || (SidPtr == NULL) || (InstallCountPtr == NULL))
    {
        return E_NOT_OK;
    }
    for (idx = 0U; idx < PQCHS_SID_BYTES; idx++)
    {
        SidPtr[idx] = inst->Sid[idx];
    }
    *InstallCountPtr = inst->InstallCount;
    return E_OK;
}

Std_ReturnType PqcHs_ReadAttempt(uint8 Peer, PqcHs_AttemptInfoType* AttemptPtr)
{
    return PqcHs_Core_ReadAttempt(PqcHs_FindPeer(Peer), AttemptPtr);
}

BufReq_ReturnType PqcHs_SoAdTpStartOfReception(PduIdType id, const PduInfoType* info, PduLengthType TpSduLength,
                                               PduLengthType* bufferSizePtr)
{
    uint8 msg = 0U;
    PqcHs_InstanceType* inst = PqcHs_FindPdu(id, FALSE, &msg);

    (void)info;
    return PqcHs_Core_StartOfReception(inst, msg, TpSduLength, bufferSizePtr);
}

BufReq_ReturnType PqcHs_SoAdTpCopyRxData(PduIdType id, const PduInfoType* info, PduLengthType* bufferSizePtr)
{
    uint8 msg = 0U;
    PqcHs_InstanceType* inst = PqcHs_FindPdu(id, FALSE, &msg);

    return PqcHs_Core_CopyRxData(inst, msg, info, bufferSizePtr);
}

void PqcHs_SoAdTpRxIndication(PduIdType id, Std_ReturnType result)
{
    uint8 msg = 0U;
    PqcHs_InstanceType* inst = PqcHs_FindPdu(id, FALSE, &msg);

    PqcHs_Core_RxIndication(inst, msg, result);
}

BufReq_ReturnType PqcHs_SoAdTpCopyTxData(PduIdType id, const PduInfoType* info, const RetryInfoType* retry,
                                         PduLengthType* availableDataPtr)
{
    uint8 msg = 0U;
    PqcHs_InstanceType* inst = PqcHs_FindPdu(id, TRUE, &msg);

    /* a TCP socket connection: no retransmission by the upper layer */
    (void)retry;
    return PqcHs_Core_CopyTxData(inst, msg, info, availableDataPtr);
}

void PqcHs_SoAdTpTxConfirmation(PduIdType id, Std_ReturnType result)
{
    uint8 msg = 0U;
    PqcHs_InstanceType* inst = PqcHs_FindPdu(id, TRUE, &msg);

    PqcHs_Core_TxConfirmation(inst, msg, result);
}

void PqcHs_SoConModeChg(SoAd_SoConIdType SoConId, SoAd_SoConModeType Mode)
{
    uint8 idx;

    for (idx = 0U; idx < PqcHs_NumInstances(); idx++)
    {
        if (PqcHs_ConfigPtr->PqcHsInstances[idx].PqcHsSoConId == SoConId)
        {
            PqcHs_Core_SoConModeChg(&PqcHs_Instances[idx], Mode);
        }
    }
}
