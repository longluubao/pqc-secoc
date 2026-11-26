/**
 * @file SoAd.c
 * @brief AUTOSAR Socket Adapter Module Implementation
 * @details Routes PDU transmissions through TcpIp module instead of raw ethernet.
 *          Manages socket connections and routing groups per AUTOSAR SWS_SoAd.
 */

/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/

#include "ApBridge/ApBridge.h"
#include "BswM/BswM.h"
#include "Det/Det.h"
#include "PduR/PduR_SoAd.h"
#include "PQC/PQC.h"
#include "SecOC/SecOC.h"
#include "SecOC/SecOC_Cfg.h"
#include "SecOC/SecOC_Debug.h"
#include "SecOC/SecOC_PQC_Cfg.h"
#include "SoAd/SoAd.h"
#include "Std_Types.h"
#include "TcpIp/TcpIp.h"
#include "Perf/SecOC_Perf.h"
#if (SOAD_TCPIP_PAYLOAD_BACKEND == SOAD_TCPIP_PAYLOAD_BACKEND_ETHIF)
    #include "EthIf/EthIf.h"
#endif

#ifdef SCHEDULER_ON
    #include <pthread.h>
#endif

#include <string.h>

/* MISRA C:2012 Rule 8.4 - Forward declarations for external linkage functions */
extern void SoAd_Init(const SoAd_ConfigType* ConfigPtr);
extern void SoAd_DeInit(void);
extern Std_ReturnType SoAd_IfTransmit(PduIdType TxPduId, const PduInfoType* PduInfoPtr);
extern Std_ReturnType SoAd_TpTransmit(PduIdType SoAdTxSduId, const PduInfoType* SoAdTxInfoPtr);
extern Std_ReturnType SoAd_GetSoConId(PduIdType TxPduId, SoAd_SoConIdType* SoConIdPtr);
extern Std_ReturnType SoAd_OpenSoCon(SoAd_SoConIdType SoConId);
extern Std_ReturnType SoAd_CloseSoCon(SoAd_SoConIdType SoConId, boolean Abort);
extern Std_ReturnType SoAd_GetLocalAddr(SoAd_SoConIdType SoConId, TcpIp_SockAddrType* LocalAddrPtr, uint8* NetmaskPtr, TcpIp_SockAddrType* DefaultRouterPtr);
extern Std_ReturnType SoAd_GetRemoteAddr(SoAd_SoConIdType SoConId, TcpIp_SockAddrType* IpAddrPtr);
extern Std_ReturnType SoAd_SetRemoteAddr(SoAd_SoConIdType SoConId, const TcpIp_SockAddrType* RemoteAddrPtr);
extern Std_ReturnType SoAd_EnableRouting(SoAd_RoutingGroupIdType RoutingGroupId);
extern Std_ReturnType SoAd_DisableRouting(SoAd_RoutingGroupIdType RoutingGroupId);
extern void SoAd_GetVersionInfo(Std_VersionInfoType* VersionInfoPtr);
extern void SoAd_RxIndication(TcpIp_SocketIdType SocketId, const TcpIp_SockAddrType* RemoteAddrPtr, const uint8* BufPtr, uint16 Length);
extern void SoAdTp_RxIndication(PduIdType RxPduId, const PduInfoType* PduInfoPtr);
extern void SoAdTp_TxConfirmation(PduIdType TxPduId, Std_ReturnType result);
extern void SoAd_MainFunctionTx(void);
extern void SoAd_MainFunctionRx(void);
extern Std_ReturnType SoAd_SetApBridgeState(SoAd_ApBridgeStateType State);


/* Forward declarations for cross-module AUTOSAR functions called herein */
extern Std_ReturnType TcpIp_GetSocketId(TcpIp_DomainType Domain, TcpIp_ProtocolType Protocol, TcpIp_SocketIdType* SocketIdPtr);
extern Std_ReturnType TcpIp_Bind(TcpIp_SocketIdType SocketId, TcpIp_LocalAddrIdType LocalAddrId, uint16* PortPtr);
extern Std_ReturnType TcpIp_TcpConnect(TcpIp_SocketIdType SocketId, const TcpIp_SockAddrType* RemoteAddrPtr);

#if (SOAD_TCPIP_PAYLOAD_BACKEND == SOAD_TCPIP_PAYLOAD_BACKEND_ETHIF)
#define SOAD_ETHIF_CTRL_IDX                  ((uint8)0U)
#define SOAD_ETHIF_FRAME_TYPE_BASE           ((Eth_FrameType)0x9000U)
#endif
#define SOAD_ROUTING_GROUP_GATEWAY           ((SoAd_RoutingGroupIdType)0U)
#define SOAD_ROUTING_GROUP_DIAG              ((SoAd_RoutingGroupIdType)1U)
#define SOAD_AP_CTRL_MAGIC0                  ((uint8)0xA5U)
#define SOAD_AP_CTRL_MAGIC1                  ((uint8)0x5AU)
#define SOAD_AP_CTRL_VERSION                 ((uint8)0x01U)
#define SOAD_AP_CTRL_PDU_LENGTH              ((uint16)6U)
#define SOAD_ENABLE_UNAUTH_AP_CONTROL        STD_OFF
#define SOAD_DEFAULT_ETH_GATEWAY_PDU_ID      ((PduIdType)2U)
/* TCP port of the gateway PDUs: the receiver listens on it, the transmitter connects to it
 * (CMake -DSECOC_PORT). */
#ifndef SECOC_CFG_PORT
#define SECOC_CFG_PORT                       50002U
#endif
/* [SWS_SoAd_00198] PDU header: 4-byte ID + 4-byte length, both big endian. Always used on TCP socket
 * connections, never on UDP (SoAdPduHeaderEnable is not a configuration parameter here). */
#define SOAD_PDU_HEADER_LENGTH               (8U)
/* One header, one largest PDU and one TcpIp read fit, so a waiting PDU never blocks the next read. */
#define SOAD_RX_STREAM_BUFFER_SIZE           (SOAD_PDU_HEADER_LENGTH + SECOC_SECPDU_MAX_LENGTH + TCPIP_RX_BUFFER_SIZE)
/* SoAd PDU IDs: the SecOC PDUs and the handshake PDUs (SoAd_PduIds.h) */
#define SOAD_MAX_PDU_PROCESSING              (SOAD_NUM_PDU_IDS)
/* longest Secured I-PDU of a signature stream: header, authentic PDU, 32-bit freshness, ML-DSA-65 signature */
#define SOAD_SIG_PDU_MAX_LENGTH              (1U + SECOC_AUTHPDU_MAX_LENGTH + 4U + PQC_MLDSA_SIGNATURE_BYTES)

/********************************************************************************************************/
/******************************************GlobalVaribles************************************************/
/********************************************************************************************************/

static boolean SoAd_Initialized = FALSE;

/* TP buffers (preserved from original) */
static PduInfoType SoAdTp_Buffer[SOAD_BUFFERLENGTH];

/* Receive side of a TCP socket connection: the byte stream is buffered here by SoAd_RxIndication and
 * cut into PDUs by SoAd_RxStreamProcess. */
typedef struct {
    TcpIp_SocketIdType SocketId;        /* connected socket that feeds the stream */
    boolean            Active;
    boolean            Discard;         /* the PDU in progress is dropped, not forwarded */
    PduIdType          RxPduId;         /* upper-layer PDU of the PDU in progress */
    uint32             Fill;            /* bytes held in Data */
    uint32             Remaining;       /* bytes of the PDU in progress still to come; 0: a PDU header is next */
    boolean            PeerClosed;      /* TcpIp released the socket; what is buffered is still processed */
    boolean            Gated;           /* parsing stopped after a gated PDU until SoAd_RxGateRelease */
    boolean            RxGate;          /* the PDU in progress is a gated one */
    PduIdType          GatePduId;       /* the PDU that shut the gate */
    const SoAd_UpperLayerType* RxUpper; /* upper layer of the PDU in progress */
    /* per PDU: free upper-layer buffer reported by its last StartOfReception (0: none yet) */
    PduLengthType      UpperBufferSize[SOAD_MAX_PDU_PROCESSING];
    uint8              Data[SOAD_RX_STREAM_BUFFER_SIZE];
} SoAd_RxStreamType;

static SoAd_RxStreamType SoAd_RxStreams[SOAD_MAX_SOCKET_CONNECTIONS];
static uint32 SoAd_MeasDropTcp = 0U;    /* [SWS_SoAd_00758] PDUs received over TCP and not forwarded */

/* TL-Network: TP Tx session state */
#define SOAD_TP_TX_SESSION_IDLE        ((uint8)0U)
#define SOAD_TP_TX_SESSION_PENDING     ((uint8)1U)
#define SOAD_TP_TX_SESSION_ACTIVE      ((uint8)2U)
#define SOAD_TP_TX_CHUNK_BYTES         ((PduLengthType)4096U)
#define SOAD_TP_TX_RETRY_BUDGET        ((uint8)3U)

typedef struct {
    uint8         State;
    uint8         RetryBudget;
    PduLengthType TotalLength;
    PduLengthType BytesSent;
    uint32        RequestSeq;           /* order of the SoAd_TpTransmit calls */
    const SoAd_UpperLayerType* Upper;   /* upper layer that requested the transmission */
    uint8         WorkBuf[SOAD_TP_TX_CHUNK_BYTES];
} SoAdTp_TxSessionType;

static SoAdTp_TxSessionType SoAdTp_TxSessions[SOAD_NUM_PDU_IDS];
static uint32 SoAd_TxRequestCounter = 0U;

/* Upper layers by SoAd_UpperLayerIdType. PduR is built in; the handshake component binds itself. */
static const SoAd_UpperLayerType SoAd_PduRUpperLayer =
{
    PduR_SoAdStartOfReception,
    PduR_SoAdTpCopyRxData,
    PduR_SoAdTpRxIndication,
    PduR_SoAdTpCopyTxData,
    PduR_SoAdTpTxConfirmation,
    NULL
};
static const SoAd_UpperLayerType* SoAd_UpperLayers[SOAD_NUM_UPPER_LAYERS] = { &SoAd_PduRUpperLayer, NULL };

/* Socket connection table */
static SoAd_SoConStateType SoAd_SoConStates[SOAD_MAX_SOCKET_CONNECTIONS];

/* Routing group table */
static SoAd_RoutingGroupStateType SoAd_RoutingGroupStates[SOAD_MAX_ROUTING_GROUPS];
static SoAd_ApBridgeStateType SoAd_ApBridgeState = SOAD_AP_BRIDGE_NOT_READY;
static boolean SoAd_ApBridgeExternalControl = FALSE;
static boolean SoAd_UnauthApControlEnabled = SOAD_ENABLE_UNAUTH_AP_CONTROL;

/* One TCP socket connection carries all of these, each PDU whole, told apart by the PDU header ID.
 *   signature stream i: SecOC PDU SECOC_PDUID_SIG(i), header ID 0x10 + i, to PduR (SecOC)
 *   handshake M1..M4:   header ID 0x30..0x33, one fixed length each, to the handshake upper layer, in
 *                       a routing group of their own; nothing behind M3 is parsed until the handshake
 *                       component has decided (gate)
 * Length limits are a project decision: the SWS has none for the PDU header length over TCP. */
#define SOAD_SIG_ROUTE(i) \
    { (PduIdType)SECOC_PDUID_SIG(i), SOAD_PDU_ROUTE_TP, SOAD_ROUTING_GROUP_GATEWAY, SOAD_HEADERID_SIG(i), \
      0U, SOAD_UPPER_LAYER_PDUR, 0U, SOAD_SIG_PDU_MAX_LENGTH, FALSE }
#define SOAD_HS_ROUTE(pdu, header, length, gate) \
    { (PduIdType)(pdu), SOAD_PDU_ROUTE_TP, (SoAd_RoutingGroupIdType)SOAD_ROUTING_GROUP_HS, (header), \
      0U, SOAD_UPPER_LAYER_HS, (length), (length), (gate) }

static const SoAd_PduRouteConfigType SoAd_DefaultPduRouteConfig[] =
{
    SOAD_SIG_ROUTE(0U), SOAD_SIG_ROUTE(1U), SOAD_SIG_ROUTE(2U), SOAD_SIG_ROUTE(3U),
    SOAD_SIG_ROUTE(4U), SOAD_SIG_ROUTE(5U), SOAD_SIG_ROUTE(6U), SOAD_SIG_ROUTE(7U),
    /* MAC stream 0: Secured I-PDU header 1 + Authentic I-PDU up to 20 + freshness 4 + tag 16 bytes */
    { (PduIdType)SECOC_PDUID_MAC(0U), SOAD_PDU_ROUTE_TP, SOAD_ROUTING_GROUP_GATEWAY, SOAD_HEADERID_MAC(0U),
      0U, SOAD_UPPER_LAYER_PDUR, 0U, 41U, FALSE },
    /* further MAC streams i (rows from the MAC profile): one line per stream,
     * { (PduIdType)SECOC_PDUID_MAC(i), SOAD_PDU_ROUTE_TP, SOAD_ROUTING_GROUP_GATEWAY, SOAD_HEADERID_MAC(i),
     *   0U, SOAD_UPPER_LAYER_PDUR, 0U, <longest Secured I-PDU>, FALSE }, */
    SOAD_HS_ROUTE(SOAD_PDUID_HS_M1, SOAD_HEADERID_HS_M1, SOAD_HS_M1_LENGTH, FALSE),
    SOAD_HS_ROUTE(SOAD_PDUID_HS_M2, SOAD_HEADERID_HS_M2, SOAD_HS_M2_LENGTH, FALSE),
    SOAD_HS_ROUTE(SOAD_PDUID_HS_M3, SOAD_HEADERID_HS_M3, SOAD_HS_M3_LENGTH, TRUE),
    SOAD_HS_ROUTE(SOAD_PDUID_HS_M4, SOAD_HEADERID_HS_M4, SOAD_HS_M4_LENGTH, FALSE)
};

static const SoAd_SoConConfigType SoAd_DefaultSoConConfig[] =
{
    {
        SOAD_DEFAULT_ETH_GATEWAY_PDU_ID,
        TCPIP_IPPROTO_TCP,            /* TCP for reliable PQC sig transport */
        0U,                           /* LocalAddrId 0 = INADDR_ANY */
#if (SECOC_ROLE_SENDER == TRUE)
        0U,                           /* TCP client: ephemeral local port, so both roles can run on one host */
#else
        SECOC_CFG_PORT,               /* Local port */
#endif
        {
            TCPIP_AF_INET,
#ifdef SECOC_CFG_PEER_IPV4
            { SECOC_CFG_PEER_IPV4 },  /* peer gateway, from CMake -DSECOC_PEER_IP */
#else
            { 192U, 168U, 1U, 3U },   /* peer Rx Pi */
#endif
            SECOC_CFG_PORT
        },
        SOAD_SOCON_ONLINE,
        SOAD_TCP_NODELAY_TRUE         /* SoAdSocketTcpNoDelay: a PDU leaves when it is written, not with the next ones */
    }
};

static SoAd_ConfigType SoAd_ActiveConfig = {
    SoAd_DefaultPduRouteConfig,
    (uint16)(sizeof(SoAd_DefaultPduRouteConfig) / sizeof(SoAd_DefaultPduRouteConfig[0])),
    SoAd_DefaultSoConConfig,
    (uint16)(sizeof(SoAd_DefaultSoConConfig) / sizeof(SoAd_DefaultSoConConfig[0])),
    SOAD_ENABLE_UNAUTH_AP_CONTROL
};

static boolean SoAd_IsRoutingAllowedForPdu(PduIdType PduId);
static Std_ReturnType SoAd_GetPduRouteConfig(PduIdType PduId, const SoAd_PduRouteConfigType** RouteCfgPtr);
static void SoAd_UpdateApReadinessStatus(void);

#ifdef SCHEDULER_ON
    extern pthread_mutex_t lock;
#endif

/********************************************************************************************************/
/**************************************Static Helper Functions*******************************************/
/********************************************************************************************************/

/**
 * @brief Find socket connection for a given TxPduId.
 * @details Searches the connection table for a connection mapped to TxPduId.
 *          If none exists and there is a free slot, allocates a default UDP connection.
 */
static SoAd_SoConIdType SoAd_FindOrCreateSoCon(PduIdType TxPduId)
{
    SoAd_SoConIdType idx;

    for (idx = 0U; idx < SOAD_MAX_SOCKET_CONNECTIONS; idx++)
    {
        if ((SoAd_SoConStates[idx].IsAllocated == TRUE) &&
            (SoAd_SoConStates[idx].TxPduId == TxPduId))
        {
            return idx;
        }
    }

    /* several PDUs share a socket connection: the PDU's route names it */
    {
        const SoAd_PduRouteConfigType* routeCfgPtr = NULL;

        if ((SoAd_GetPduRouteConfig(TxPduId, &routeCfgPtr) == E_OK) &&
            (routeCfgPtr->SoAdSoConId < SOAD_MAX_SOCKET_CONNECTIONS) &&
            (SoAd_SoConStates[routeCfgPtr->SoAdSoConId].IsAllocated == TRUE))
        {
            return routeCfgPtr->SoAdSoConId;
        }
    }

    return SOAD_MAX_SOCKET_CONNECTIONS;
}

/* Upper layer of a route; NULL while that layer is not bound. */
static const SoAd_UpperLayerType* SoAd_GetUpperLayer(const SoAd_PduRouteConfigType* RouteCfgPtr)
{
    return (RouteCfgPtr->SoAdUpperLayer < SOAD_NUM_UPPER_LAYERS) ? SoAd_UpperLayers[RouteCfgPtr->SoAdUpperLayer] : NULL;
}

/* Tell every upper layer that asked for it that the TCP connection of a socket connection is up or gone. */
static void SoAd_NotifySoConMode(SoAd_SoConIdType SoConId, SoAd_SoConModeType Mode)
{
    uint8 idx;

    for (idx = 0U; idx < SOAD_NUM_UPPER_LAYERS; idx++)
    {
        if ((SoAd_UpperLayers[idx] != NULL) && (SoAd_UpperLayers[idx]->SoConModeChg != NULL))
        {
            SoAd_UpperLayers[idx]->SoConModeChg(SoConId, Mode);
        }
    }
}

static void SoAd_UpdateApReadinessStatus(void)
{
    SoAd_SoConIdType idx;
    SoAd_ApBridgeStateType DerivedState = SOAD_AP_BRIDGE_NOT_READY;

    if (SoAd_ApBridgeExternalControl == TRUE)
    {
        return;
    }

    for (idx = 0U; idx < SOAD_MAX_SOCKET_CONNECTIONS; idx++)
    {
        if ((SoAd_SoConStates[idx].IsAllocated == TRUE) &&
            (SoAd_SoConStates[idx].Mode == SOAD_SOCON_ONLINE))
        {
            DerivedState = SOAD_AP_BRIDGE_READY;
            break;
        }
    }

    if (DerivedState != SoAd_ApBridgeState)
    {
        SoAd_ApBridgeState = DerivedState;
        (void)BswM_RequestMode(BSWM_REQUESTER_ID_AP_READY,
                               (BswM_ModeType)SoAd_ApBridgeState);
    }
}

static boolean SoAd_IsApControlPdu(const uint8* BufPtr, uint16 Length)
{
    if ((BufPtr == NULL) || (Length != SOAD_AP_CTRL_PDU_LENGTH))
    {
        return FALSE;
    }

    if ((BufPtr[0] != SOAD_AP_CTRL_MAGIC0) ||
        (BufPtr[1] != SOAD_AP_CTRL_MAGIC1) ||
        (BufPtr[2] != SOAD_AP_CTRL_VERSION))
    {
        return FALSE;
    }

    if (BufPtr[3] > (uint8)SOAD_AP_BRIDGE_DEGRADED)
    {
        return FALSE;
    }

    if ((uint8)(BufPtr[0] ^ BufPtr[1] ^ BufPtr[2] ^ BufPtr[3] ^ BufPtr[4]) != BufPtr[5])
    {
        return FALSE;
    }

    return TRUE;
}

static void SoAd_HandleApControlPdu(const uint8* BufPtr)
{
    SoAd_ApBridgeStateType ControlState;

    if (BufPtr == NULL)
    {
        return;
    }

    ControlState = (SoAd_ApBridgeStateType)BufPtr[3];
    ApBridge_ReportHeartbeat(TRUE);

    if (ControlState == SOAD_AP_BRIDGE_READY)
    {
        ApBridge_ReportServiceStatus(TRUE);
    }
    else
    {
        ApBridge_ReportServiceStatus(FALSE);
    }

    (void)SoAd_SetApBridgeState(ControlState);
}

/**
 * @brief Transmit data via TcpIp using the socket connection for TxPduId.
 */
static Std_ReturnType SoAd_TcpIpTransmit(PduIdType TxPduId, const uint8* DataPtr, uint16 Length)
{
    SoAd_SoConIdType soConId;
    Std_ReturnType result;

    soConId = SoAd_FindOrCreateSoCon(TxPduId);
    if (soConId >= SOAD_MAX_SOCKET_CONNECTIONS)
    {
        return E_NOT_OK;
    }

    if (SoAd_SoConStates[soConId].Mode != SOAD_SOCON_ONLINE)
    {
        return E_NOT_OK;
    }

    if (SoAd_SoConStates[soConId].Protocol == TCPIP_IPPROTO_UDP)
    {
        result = TcpIp_UdpTransmit(
            SoAd_SoConStates[soConId].SocketId,
            DataPtr,
            &SoAd_SoConStates[soConId].RemoteAddr,
            Length
        );
    }
    else
    {
        /* shortcut: IF transmission over TCP is refused, it would put bytes without PDU header into
         * the stream; the only TCP route is TP. Add the header here when an IF PDU needs TCP. */
        result = E_NOT_OK;
    }

    return result;
}

#if (SOAD_TCPIP_PAYLOAD_BACKEND == SOAD_TCPIP_PAYLOAD_BACKEND_ETHIF)
static Std_ReturnType SoAd_EthIfTransmit(PduIdType TxPduId, const uint8* DataPtr, uint16 Length)
{
    Eth_BufIdxType BufIdx = 0U;
    uint8* BufPtr = NULL;
    uint16 RequestedLength = Length;
    Eth_FrameType FrameType;

    if ((Length == 0U) || (Length > ETHIF_TX_BUF_SIZE))
    {
        return E_NOT_OK;
    }

    FrameType = (Eth_FrameType)(SOAD_ETHIF_FRAME_TYPE_BASE + (Eth_FrameType)TxPduId);
    if (EthIf_ProvideTxBuffer(SOAD_ETHIF_CTRL_IDX,
                              FrameType,
                              0U,
                              &BufIdx,
                              &BufPtr,
                              &RequestedLength) != BUFREQ_OK)
    {
        return E_NOT_OK;
    }

    if ((BufPtr == NULL) || (RequestedLength < Length))
    {
        return E_NOT_OK;
    }

    (void)memcpy(BufPtr, DataPtr, Length);
    return EthIf_Transmit(SOAD_ETHIF_CTRL_IDX, BufIdx, FrameType, TRUE, Length, NULL);
}

static void SoAd_EthIfRxIndicationCbk(uint8 CtrlIdx,
                                      Eth_FrameType FrameType,
                                      boolean IsBroadcast,
                                      const uint8* PhysAddrPtr,
                                      const uint8* DataPtr,
                                      uint16 LenByte)
{
    PduIdType RxPduId;
    PduInfoType pduInfo;
    const SoAd_PduRouteConfigType* RouteCfgPtr = NULL;
    (void)CtrlIdx;
    (void)IsBroadcast;
    (void)PhysAddrPtr;

    if ((DataPtr == NULL) || (LenByte == 0U))
    {
        return;
    }
    if ((FrameType < SOAD_ETHIF_FRAME_TYPE_BASE) ||
        (FrameType >= (Eth_FrameType)(SOAD_ETHIF_FRAME_TYPE_BASE + SECOC_NUM_OF_RX_PDU_PROCESSING)))
    {
        return;
    }

    RxPduId = (PduIdType)(FrameType - SOAD_ETHIF_FRAME_TYPE_BASE);
    if (SoAd_IsRoutingAllowedForPdu(RxPduId) == FALSE)
    {
        return;
    }
    if (SoAd_GetPduRouteConfig(RxPduId, &RouteCfgPtr) != E_OK)
    {
        return;
    }
    pduInfo.SduDataPtr = (uint8*)DataPtr;
    pduInfo.MetaDataPtr = NULL;
    pduInfo.SduLength = (PduLengthType)LenByte;

    if (RouteCfgPtr->SoAdPduRouteType == SOAD_PDU_ROUTE_TP)
    {
        SoAdTp_RxIndication(RxPduId, &pduInfo);
    }
    else if (RouteCfgPtr->SoAdPduRouteType == SOAD_PDU_ROUTE_IF)
    {
        PduR_SoAdIfRxIndication(RxPduId, &pduInfo);
    }
    else
    {
        /* Ignore non-SoAd routed types. */
    }
}
#endif

/**
 * @brief Find mapped Rx PDU ID for an incoming socket.
 */
static Std_ReturnType SoAd_FindRxPduIdBySocket(
    TcpIp_SocketIdType SocketId,
    PduIdType* RxPduIdPtr,
    SoAd_SoConIdType* SoConIdPtr
)
{
    SoAd_SoConIdType idx;

    for (idx = 0U; idx < SOAD_MAX_SOCKET_CONNECTIONS; idx++)
    {
        if ((SoAd_SoConStates[idx].IsAllocated == TRUE) &&
            (SoAd_SoConStates[idx].SocketId == SocketId))
        {
            if (RxPduIdPtr != NULL)
            {
                *RxPduIdPtr = SoAd_SoConStates[idx].TxPduId;
            }
            if (SoConIdPtr != NULL)
            {
                *SoConIdPtr = idx;
            }
            return E_OK;
        }
    }

    return E_NOT_OK;
}

static Std_ReturnType SoAd_GetPduRouteConfig(PduIdType PduId, const SoAd_PduRouteConfigType** RouteCfgPtr)
{
    uint16 idx;

    if (RouteCfgPtr == NULL)
    {
        return E_NOT_OK;
    }

    for (idx = 0U; idx < SoAd_ActiveConfig.SoAdPduRouteConfigCount; idx++)
    {
        if (SoAd_ActiveConfig.SoAdPduRouteConfigPtr[idx].SoAdPduId == PduId)
        {
            *RouteCfgPtr = &SoAd_ActiveConfig.SoAdPduRouteConfigPtr[idx];
            return E_OK;
        }
    }

    return E_NOT_OK;
}

static boolean SoAd_IsRoutingGroupEnabled(SoAd_RoutingGroupIdType RoutingGroupId)
{
    if (RoutingGroupId >= SOAD_MAX_ROUTING_GROUPS)
    {
        return FALSE;
    }

    return SoAd_RoutingGroupStates[RoutingGroupId].Enabled;
}

static boolean SoAd_IsRoutingAllowedForPdu(PduIdType PduId)
{
    const SoAd_PduRouteConfigType* RouteCfgPtr = NULL;

    if (PduId >= (PduIdType)SOAD_NUM_PDU_IDS)
    {
        return FALSE;
    }

    if (SoAd_GetPduRouteConfig(PduId, &RouteCfgPtr) != E_OK)
    {
        return FALSE;
    }
    if (RouteCfgPtr->SoAdPduRouteType == SOAD_PDU_ROUTE_NONE)
    {
        return FALSE;
    }

    return SoAd_IsRoutingGroupEnabled(RouteCfgPtr->SoAdRoutingGroupId);
}

static Std_ReturnType SoAd_GetPduRouteConfigByHeaderId(uint32 HeaderId, const SoAd_PduRouteConfigType** RouteCfgPtr)
{
    uint16 idx;

    for (idx = 0U; idx < SoAd_ActiveConfig.SoAdPduRouteConfigCount; idx++)
    {
        if (SoAd_ActiveConfig.SoAdPduRouteConfigPtr[idx].SoAdPduHeaderId == HeaderId)
        {
            *RouteCfgPtr = &SoAd_ActiveConfig.SoAdPduRouteConfigPtr[idx];
            return E_OK;
        }
    }

    return E_NOT_OK;
}

static uint32 SoAd_GetBe32(const uint8* Ptr)
{
    return ((uint32)Ptr[0] << 24U) | ((uint32)Ptr[1] << 16U) | ((uint32)Ptr[2] << 8U) | (uint32)Ptr[3];
}

static void SoAd_PutBe32(uint8* Ptr, uint32 Value)
{
    Ptr[0] = (uint8)(Value >> 24U);
    Ptr[1] = (uint8)(Value >> 16U);
    Ptr[2] = (uint8)(Value >> 8U);
    Ptr[3] = (uint8)Value;
}

/* TCP connections each socket connection has had since SoAd_Init (SoAd_GetSoConTcpInfo) */
static uint32 SoAd_TcpConnectionCount[SOAD_MAX_SOCKET_CONNECTIONS];

/* [SWS_SoAd_00689] item 3: when SoAd takes a TCP socket into use (a socket it connects, and every socket
 * of an accepted connection) it sets TCPIP_PARAMID_TCP_NAGLE from SoAdSocketTcpNoDelay of the socket
 * connection: 0x00 for TRUE, 0x01 for FALSE, no call when the optional parameter is absent
 * [ECUC_SoAd_00023]. The caller does not use a socket for which the call fails: a project decision,
 * neither specification says what the caller does with E_NOT_OK. */
static Std_ReturnType SoAd_ApplyTcpNoDelay(SoAd_SoConIdType SoConId, TcpIp_SocketIdType SocketId)
{
    const SoAd_TcpNoDelayType noDelay = (SoConId < SoAd_ActiveConfig.SoAdSoConConfigCount)
                                        ? SoAd_ActiveConfig.SoAdSoConConfigPtr[SoConId].SoAdSocketTcpNoDelay
                                        : SOAD_TCP_NODELAY_ABSENT;
    uint8 nagle;

    if (noDelay == SOAD_TCP_NODELAY_ABSENT)
    {
        return E_OK;
    }
    nagle = (noDelay == SOAD_TCP_NODELAY_TRUE) ? 0x00U : 0x01U;
    return TcpIp_ChangeParameter(SocketId, TCPIP_PARAMID_TCP_NAGLE, &nagle);
}

/**
 * @brief A TCP connection is established on SocketId: its byte stream starts with a PDU header.
 */
static void SoAd_RxStreamStart(SoAd_SoConIdType SoConId, TcpIp_SocketIdType SocketId)
{
    SoAd_RxStreamType* stream = &SoAd_RxStreams[SoConId];

    SoAd_TcpConnectionCount[SoConId]++;
    stream->SocketId = SocketId;
    stream->Active = TRUE;
    stream->PeerClosed = FALSE;
    stream->Discard = FALSE;
    stream->Fill = 0U;
    stream->Remaining = 0U;
    stream->Gated = FALSE;
    stream->RxGate = FALSE;
    stream->RxUpper = NULL;
    (void)memset(stream->UpperBufferSize, 0, sizeof(stream->UpperBufferSize));
    SoAd_NotifySoConMode(SoConId, SOAD_SOCON_ONLINE);
}

/**
 * @brief The TCP connection behind a stream is over: closed by the peer, lost, or closed here because
 *        the byte stream can no longer be trusted. [SWS_SoAd_00637] (1), (3), [SWS_SoAd_00646].
 * @param CloseSocket TRUE: the connected socket is still open and is closed (never the listening one).
 */
static void SoAd_RxStreamEnd(SoAd_SoConIdType SoConId, boolean CloseSocket)
{
    SoAd_RxStreamType* stream = &SoAd_RxStreams[SoConId];
    PduIdType txPduId;

    if (stream->Active == FALSE)
    {
        return;
    }

    if (stream->Remaining != 0U)
    {
        /* ended inside a PDU */
        if ((stream->Discard == FALSE) && (stream->RxUpper != NULL))
        {
            stream->RxUpper->RxIndication(stream->RxPduId, E_NOT_OK);
            SoAd_MeasDropTcp++;
        }
    }
    else if (stream->Fill != 0U)
    {
        /* shortcut: bytes still buffered (a partial header, or PDUs the upper layer had no room for)
         * are counted as one dropped PDU, not parsed; count per PDU if this path ever carries load */
        SoAd_MeasDropTcp++;
    }
    else
    {
        /* ended between two PDUs */
    }

    if (CloseSocket == TRUE)
    {
        (void)TcpIp_Close(stream->SocketId, TRUE);
    }

    /* [SWS_SoAd_00637] (1): every TP transmission of this connection ends with it, whether it has
     * bytes on the wire or is still waiting its turn. A request must not go out on a later
     * connection that its upper layer knows nothing about. */
    for (txPduId = 0U; txPduId < (PduIdType)SOAD_NUM_PDU_IDS; txPduId++)
    {
        if ((SoAdTp_TxSessions[txPduId].State != SOAD_TP_TX_SESSION_IDLE) &&
            (SoAd_SoConStates[SoConId].Protocol == TCPIP_IPPROTO_TCP) &&
            (SoAd_FindOrCreateSoCon(txPduId) == SoConId))
        {
            SoAdTp_TxSessions[txPduId].State = SOAD_TP_TX_SESSION_IDLE;
            SoAdTp_TxSessions[txPduId].TotalLength = 0U;
            SoAdTp_TxSessions[txPduId].BytesSent = 0U;
            if (SoAdTp_TxSessions[txPduId].Upper != NULL)
            {
                SoAdTp_TxSessions[txPduId].Upper->TxConfirmation(txPduId, E_NOT_OK);
            }
        }
    }

    stream->Active = FALSE;
    stream->PeerClosed = FALSE;
    stream->Gated = FALSE;
    stream->Fill = 0U;
    stream->Remaining = 0U;

    if (SoAd_SoConStates[SoConId].SocketId == stream->SocketId)
    {
        /* connecting side: the socket connection's own socket is gone; SoAd_OpenSoCon, called by
         * the next transmit request, connects again. (The listening side keeps its listening
         * socket and stays as it is until the next SoAd_TcpAccepted.) */
        SoAd_SoConStates[SoConId].SocketId = TCPIP_SOCKET_ID_INVALID;
        SoAd_SoConStates[SoConId].Mode = SOAD_SOCON_OFFLINE;
        SoAd_UpdateApReadinessStatus();
    }
    SoAd_NotifySoConMode(SoConId, SOAD_SOCON_OFFLINE);
}

/**
 * @brief Start the PDU whose header is at HeaderPtr [SWS_SoAd_00771] (4), [SWS_SoAd_00571] 1(a).
 * @return FALSE if the upper layer is still busy with the previous PDU (the header stays in the
 *         buffer), or if the header was implausible and the connection has been closed.
 */
static boolean SoAd_RxStreamBeginPdu(SoAd_RxStreamType* Stream, const uint8* HeaderPtr, uint32 DataAvailable)
{
    const SoAd_PduRouteConfigType* routeCfgPtr = NULL;
    const SoAd_UpperLayerType* upper = NULL;
    uint32 pduLength = SoAd_GetBe32(&HeaderPtr[4]);
    PduLengthType bufferSize = 0U;
    PduInfoType info;

    info.SduDataPtr = NULL;
    info.MetaDataPtr = NULL;
    info.SduLength = 0U;

    if (pduLength > SOAD_RX_STREAM_BUFFER_SIZE)
    {
        /* Project decision: the SWS gives no plausibility limit for the length field and no way to
         * find the next header again. No PDU of this configuration is that long, so the byte stream
         * is not trusted any further: the PDU is counted as dropped and the connection is closed. */
        SoAd_RxStreamEnd((SoAd_SoConIdType)(Stream - SoAd_RxStreams), TRUE);
        return FALSE;
    }

    Stream->Discard = TRUE;

    if (SoAd_GetPduRouteConfigByHeaderId(SoAd_GetBe32(HeaderPtr), &routeCfgPtr) == E_OK)
    {
        upper = SoAd_GetUpperLayer(routeCfgPtr);
    }

    if (upper == NULL)
    {
        /* unknown header ID [SWS_SoAd_00771] (4), or a PDU whose upper layer is not bound */
        (void)Det_ReportRuntimeError(SOAD_MODULE_ID, 0U, SOAD_SID_RX_INDICATION, SOAD_E_INV_PDUHEADER_ID);
    }
    else if ((pduLength < routeCfgPtr->SoAdRxMinLength) ||
             ((routeCfgPtr->SoAdRxMaxLength != 0U) && (pduLength > routeCfgPtr->SoAdRxMaxLength)))
    {
        /* not a length this PDU can have (project decision): discarded like a PDU nobody takes; the
         * stream stays aligned because the length is below the receive buffer limit checked above */
    }
    else if ((pduLength != 0U) &&
             (routeCfgPtr->SoAdPduRouteType == SOAD_PDU_ROUTE_TP) &&
             (SoAd_IsRoutingAllowedForPdu(routeCfgPtr->SoAdPduId) == TRUE))
    {
        /* The upper layer holds one PDU at a time. Starting the next one while the previous one is
         * still in its buffer would overwrite it, so wait until the buffer is as free as it was at
         * the last StartOfReception; the bytes stay here and TCP flow control slows the sender. */
        if ((Stream->UpperBufferSize[routeCfgPtr->SoAdPduId] != 0U) &&
            ((upper->CopyRxData(routeCfgPtr->SoAdPduId, &info, &bufferSize) != BUFREQ_OK) ||
             (bufferSize < Stream->UpperBufferSize[routeCfgPtr->SoAdPduId])))
        {
            return FALSE;
        }

        /* cppcheck-suppress misra-c2012-11.8 */
        info.SduDataPtr = (uint8*)&HeaderPtr[SOAD_PDU_HEADER_LENGTH];
        info.SduLength = (DataAvailable < pduLength) ? DataAvailable : pduLength;
        if (upper->StartOfReception(routeCfgPtr->SoAdPduId, &info, (PduLengthType)pduLength, &bufferSize) == BUFREQ_OK)
        {
            Stream->Discard = FALSE;
            Stream->RxUpper = upper;
            Stream->RxGate = routeCfgPtr->SoAdRxGate;
            Stream->RxPduId = routeCfgPtr->SoAdPduId;
            Stream->UpperBufferSize[routeCfgPtr->SoAdPduId] = bufferSize;
        }
        /* else [SWS_SoAd_00572]: all data of this PDU is discarded */
    }
    else
    {
        /* zero length [SWS_SoAd_00562] (4), not a TP route, or routing group disabled: nothing to forward */
    }

    if (Stream->Discard == TRUE)
    {
        SoAd_MeasDropTcp++;
    }
    Stream->Remaining = pduLength;
    return TRUE;
}

/**
 * @brief Cut the buffered stream into PDUs and forward them through the TP API
 *        [SWS_SoAd_00771], [SWS_SoAd_00571], [SWS_SoAd_00573], [SWS_SoAd_00574].
 */
static void SoAd_RxStreamProcess(SoAd_RxStreamType* Stream)
{
    uint32 pos = 0U;
    boolean stop = FALSE;

    while ((stop == FALSE) && (Stream->Gated == FALSE) && (pos < Stream->Fill))
    {
        uint32 avail = Stream->Fill - pos;

        if (Stream->Remaining == 0U)
        {
            /* a header split over two segments waits for the rest; so does a busy upper layer */
            if ((avail < SOAD_PDU_HEADER_LENGTH) ||
                (SoAd_RxStreamBeginPdu(Stream, &Stream->Data[pos], avail - SOAD_PDU_HEADER_LENGTH) == FALSE))
            {
                stop = TRUE;
            }
            else
            {
                pos += SOAD_PDU_HEADER_LENGTH;
            }
        }
        else
        {
            uint32 n = (avail < Stream->Remaining) ? avail : Stream->Remaining;

            if (Stream->Discard == FALSE)
            {
                PduInfoType info;
                PduLengthType bufferSize = 0U;

                info.SduDataPtr = &Stream->Data[pos];
                info.MetaDataPtr = NULL;
                info.SduLength = (PduLengthType)n;
                if (Stream->RxUpper->CopyRxData(Stream->RxPduId, &info, &bufferSize) != BUFREQ_OK)
                {
                    Stream->RxUpper->RxIndication(Stream->RxPduId, E_NOT_OK);
                    Stream->Discard = TRUE;
                    SoAd_MeasDropTcp++;
                }
            }

            pos += n;
            Stream->Remaining -= n;
            if ((Stream->Remaining == 0U) && (Stream->Discard == FALSE))
            {
                Stream->RxUpper->RxIndication(Stream->RxPduId, E_OK);
                if (Stream->RxGate == TRUE)
                {
                    /* what follows this PDU in the byte stream is not looked at before the upper
                     * layer has released the gate */
                    Stream->Gated = TRUE;
                    Stream->GatePduId = Stream->RxPduId;
                }
            }
        }
    }

    if (Stream->Active == FALSE)
    {
        /* the connection was closed on an implausible header; the buffer is already empty */
        return;
    }

    Stream->Fill -= pos;
    if ((pos > 0U) && (Stream->Fill > 0U))
    {
        (void)memmove(Stream->Data, &Stream->Data[pos], Stream->Fill);
    }
}

static Std_ReturnType SoAd_RecreateSoConSocket(SoAd_SoConIdType SoConId)
{
    TcpIp_SocketIdType SockId = TCPIP_SOCKET_ID_INVALID;
    uint16 BindPort;

    if (SoConId >= SOAD_MAX_SOCKET_CONNECTIONS)
    {
        return E_NOT_OK;
    }

    if (TcpIp_GetSocketId(TCPIP_AF_INET, SoAd_SoConStates[SoConId].Protocol, &SockId) != E_OK)
    {
        return E_NOT_OK;
    }

    SoAd_SoConStates[SoConId].SocketId = SockId;

    if (SoAd_SoConStates[SoConId].LocalPort == 0U)
    {
        SoAd_SoConStates[SoConId].LocalPort = (uint16)(50000U + SoAd_SoConStates[SoConId].TxPduId);
    }

    BindPort = SoAd_SoConStates[SoConId].LocalPort;
    if (TcpIp_Bind(SockId, SoAd_SoConStates[SoConId].LocalAddrId, &BindPort) != E_OK)
    {
        (void)TcpIp_Close(SockId, TRUE);
        SoAd_SoConStates[SoConId].SocketId = TCPIP_SOCKET_ID_INVALID;
        return E_NOT_OK;
    }

    SoAd_SoConStates[SoConId].LocalPort = BindPort;

    /* TL-Network: TCP requires explicit connect before transmit. */
    if (SoAd_SoConStates[SoConId].Protocol == TCPIP_IPPROTO_TCP)
    {
        if ((SoAd_ApplyTcpNoDelay(SoConId, SockId) != E_OK) ||
            (TcpIp_TcpConnect(SockId, &SoAd_SoConStates[SoConId].RemoteAddr) != E_OK))
        {
            (void)TcpIp_Close(SockId, TRUE);
            SoAd_SoConStates[SoConId].SocketId = TCPIP_SOCKET_ID_INVALID;
            return E_NOT_OK;
        }
        SoAd_RxStreamStart(SoConId, SockId);
    }

    return E_OK;
}

/********************************************************************************************************/
/********************************************Functions***************************************************/
/********************************************************************************************************/

void SoAd_Init(const SoAd_ConfigType* ConfigPtr)
{
    uint16 idx;

    if ((ConfigPtr != NULL) &&
        (ConfigPtr->SoAdPduRouteConfigPtr != NULL) &&
        (ConfigPtr->SoAdSoConConfigPtr != NULL))
    {
        SoAd_ActiveConfig = *ConfigPtr;
    }
    else
    {
        SoAd_ActiveConfig.SoAdPduRouteConfigPtr = SoAd_DefaultPduRouteConfig;
        SoAd_ActiveConfig.SoAdPduRouteConfigCount =
            (uint16)(sizeof(SoAd_DefaultPduRouteConfig) / sizeof(SoAd_DefaultPduRouteConfig[0]));
        SoAd_ActiveConfig.SoAdSoConConfigPtr = SoAd_DefaultSoConConfig;
        SoAd_ActiveConfig.SoAdSoConConfigCount =
            (uint16)(sizeof(SoAd_DefaultSoConConfig) / sizeof(SoAd_DefaultSoConConfig[0]));
        SoAd_ActiveConfig.SoAdEnableUnauthApControl = SOAD_ENABLE_UNAUTH_AP_CONTROL;
    }
    SoAd_UnauthApControlEnabled = SoAd_ActiveConfig.SoAdEnableUnauthApControl;

    /* Initialize socket connection table */
    for (idx = 0U; idx < SOAD_MAX_SOCKET_CONNECTIONS; idx++)
    {
        SoAd_SoConStates[idx].SocketId    = TCPIP_SOCKET_ID_INVALID;
        SoAd_SoConStates[idx].Protocol    = TCPIP_IPPROTO_UDP;
        SoAd_SoConStates[idx].LocalAddrId = 0U;
        SoAd_SoConStates[idx].LocalPort   = 0U;
        SoAd_SoConStates[idx].Mode        = SOAD_SOCON_OFFLINE;
        SoAd_SoConStates[idx].IsAllocated = FALSE;
        SoAd_SoConStates[idx].TxPduId     = 0U;
        (void)memset(&SoAd_SoConStates[idx].RemoteAddr, 0, sizeof(TcpIp_SockAddrType));
        SoAd_RxStreams[idx].Active = FALSE;
        SoAd_RxStreams[idx].Fill = 0U;
        SoAd_RxStreams[idx].Remaining = 0U;
        SoAd_TcpConnectionCount[idx] = 0U;
    }
    SoAd_MeasDropTcp = 0U;

    for (idx = 0U;
         (idx < SoAd_ActiveConfig.SoAdSoConConfigCount) && (idx < SOAD_MAX_SOCKET_CONNECTIONS);
         idx++)
    {
        TcpIp_SocketIdType SockId = TCPIP_SOCKET_ID_INVALID;
        uint16 BindPort = SoAd_ActiveConfig.SoAdSoConConfigPtr[idx].SoAdLocalPort;

        if (TcpIp_GetSocketId(TCPIP_AF_INET,
                              SoAd_ActiveConfig.SoAdSoConConfigPtr[idx].SoAdProtocol,
                              &SockId) != E_OK)
        {
            continue;
        }
        if (TcpIp_Bind(SockId,
                       SoAd_ActiveConfig.SoAdSoConConfigPtr[idx].SoAdLocalAddrId,
                       &BindPort) != E_OK)
        {
            (void)TcpIp_Close(SockId, TRUE);
            continue;
        }

        SoAd_SoConStates[idx].SocketId = SockId;
        SoAd_SoConStates[idx].Protocol = SoAd_ActiveConfig.SoAdSoConConfigPtr[idx].SoAdProtocol;
        SoAd_SoConStates[idx].LocalAddrId = SoAd_ActiveConfig.SoAdSoConConfigPtr[idx].SoAdLocalAddrId;
        SoAd_SoConStates[idx].LocalPort = BindPort;
        SoAd_SoConStates[idx].IsAllocated = TRUE;
        SoAd_SoConStates[idx].TxPduId = SoAd_ActiveConfig.SoAdSoConConfigPtr[idx].SoAdTxPduId;
        SoAd_SoConStates[idx].RemoteAddr = SoAd_ActiveConfig.SoAdSoConConfigPtr[idx].SoAdRemoteAddr;

        /* TL-Network: TCP needs an explicit connect (CLIENT side) or listen
         * (SERVER side) to bring the SoCon online. The role is gated by the
         * AUTOSAR SECOC_ROLE_RECEIVER macro: Rx is the TCP server (App_Tx is
         * Tx-only, so the Rx side just listens for incoming secured PDUs). */
        if (SoAd_ActiveConfig.SoAdSoConConfigPtr[idx].SoAdProtocol == TCPIP_IPPROTO_TCP)
        {
#if (SECOC_ROLE_RECEIVER == TRUE)
            if (TcpIp_TcpListen(SockId, 1U) != E_OK)
            {
                (void)TcpIp_Close(SockId, TRUE);
                SoAd_SoConStates[idx].SocketId = TCPIP_SOCKET_ID_INVALID;
                SoAd_SoConStates[idx].Mode = SOAD_SOCON_OFFLINE;
                continue;
            }
            (void)printf("[SoAd] TCP listening on port %u for incoming secured PDUs (Rx role)\n",
                         (unsigned)SoAd_SoConStates[idx].LocalPort);
#else
            if ((SoAd_ApplyTcpNoDelay((SoAd_SoConIdType)idx, SockId) != E_OK) ||
                (TcpIp_TcpConnect(SockId, &SoAd_SoConStates[idx].RemoteAddr) != E_OK))
            {
                (void)TcpIp_Close(SockId, TRUE);
                SoAd_SoConStates[idx].SocketId = TCPIP_SOCKET_ID_INVALID;
                /* Mark offline; SoAd_OpenSoCon will retry the connect later. */
                SoAd_SoConStates[idx].Mode = SOAD_SOCON_OFFLINE;
                continue;
            }
            SoAd_RxStreamStart((SoAd_SoConIdType)idx, SockId);
#endif
        }

        SoAd_SoConStates[idx].Mode = SoAd_ActiveConfig.SoAdSoConConfigPtr[idx].SoAdInitialMode;
    }

    /* Initialize routing groups disabled until BswM arbitration opens paths. */
    for (idx = 0U; idx < SOAD_MAX_ROUTING_GROUPS; idx++)
    {
        SoAd_RoutingGroupStates[idx].Enabled = FALSE;
    }
    /* the handshake messages are not under BswM: their group is open from here on */
    SoAd_RoutingGroupStates[SOAD_ROUTING_GROUP_HS].Enabled = TRUE;

    /* Initialize TP buffers */
    (void)memset(SoAdTp_Buffer, 0, sizeof(SoAdTp_Buffer));

    /* TL-Network: clear TP Tx sessions. */
    (void)memset(SoAdTp_TxSessions, 0, sizeof(SoAdTp_TxSessions));

#if (SOAD_TCPIP_PAYLOAD_BACKEND == SOAD_TCPIP_PAYLOAD_BACKEND_ETHIF)
    EthIf_SetRxIndicationCallback(SoAd_EthIfRxIndicationCbk);
#endif

    SoAd_Initialized = TRUE;
    SoAd_ApBridgeState = SOAD_AP_BRIDGE_NOT_READY;
    SoAd_ApBridgeExternalControl = FALSE;
    (void)BswM_RequestMode(BSWM_REQUESTER_ID_AP_READY, (BswM_ModeType)SOAD_AP_BRIDGE_NOT_READY);

    /* Re-evaluate AP readiness now that all SoCons have been bound/connected
     * and their `Mode` fields reflect their initial state. Without this call
     * BswM stays at NOT_READY → BswM_Action_GatewayComFull never enables
     * BSWM_ROUTING_GROUP_NORMAL → SoAd_TpTransmit's IsRoutingAllowedForPdu
     * gate fails → no PDU is ever dispatched even though the TCP socket has
     * already connected to the peer at SoAd_Init time. */
    SoAd_UpdateApReadinessStatus();

    #ifdef SOAD_DEBUG
        (void)printf("######## SoAd_Init completed\n");
    #endif
}

void SoAd_DeInit(void)
{
    SoAd_SoConIdType idx;

#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_DEINIT, SOAD_E_NOTINIT);
        return;
    }
#endif

    for (idx = 0U; idx < SOAD_MAX_SOCKET_CONNECTIONS; idx++)
    {
        if ((SoAd_SoConStates[idx].IsAllocated == TRUE) &&
            (SoAd_SoConStates[idx].SocketId != TCPIP_SOCKET_ID_INVALID))
        {
            (void)TcpIp_Close(SoAd_SoConStates[idx].SocketId, TRUE);
        }
        SoAd_SoConStates[idx].SocketId = TCPIP_SOCKET_ID_INVALID;
        SoAd_SoConStates[idx].Mode = SOAD_SOCON_OFFLINE;
        SoAd_SoConStates[idx].IsAllocated = FALSE;
    }

    SoAd_ApBridgeState = SOAD_AP_BRIDGE_NOT_READY;
    SoAd_ApBridgeExternalControl = FALSE;
    (void)BswM_RequestMode(BSWM_REQUESTER_ID_AP_READY, (BswM_ModeType)SOAD_AP_BRIDGE_NOT_READY);
    SoAd_Initialized = FALSE;
}

/****************************************************
 *          * Function Info *                       *
 *                                                  *
 * Function_Name        : SoAd_IfTransmit           *
 * Function_Descripton  : Requests transmission     *
 *              of an IF PDU via TcpIp              *
 ***************************************************/
Std_ReturnType SoAd_IfTransmit(PduIdType TxPduId, const PduInfoType* PduInfoPtr)
{
    #ifdef SOAD_DEBUG
        (void)printf("######## in SoAd_IfTransmit \n");
    #endif

    Std_ReturnType result = E_OK;
    const SoAd_PduRouteConfigType* RouteCfgPtr = NULL;

#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_IF_TRANSMIT, SOAD_E_NOTINIT);
        return E_NOT_OK;
    }
    if (PduInfoPtr == NULL)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_IF_TRANSMIT, SOAD_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (TxPduId >= (PduIdType)SECOC_NUM_OF_TX_PDU_PROCESSING)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_IF_TRANSMIT, SOAD_E_INV_PDUID);
        return E_NOT_OK;
    }
#else
    if ((PduInfoPtr == NULL) || (TxPduId >= (PduIdType)SECOC_NUM_OF_TX_PDU_PROCESSING))
    {
        return E_NOT_OK;
    }
#endif

    if ((PduInfoPtr->SduLength > 0U) && (PduInfoPtr->SduDataPtr == NULL))
    {
        return E_NOT_OK;
    }

#if (SOAD_TCPIP_PAYLOAD_BACKEND == SOAD_TCPIP_PAYLOAD_BACKEND_SOCKETS)
    {
        SoAd_SoConIdType soConId = SoAd_FindOrCreateSoCon(TxPduId);
        if (soConId >= SOAD_MAX_SOCKET_CONNECTIONS)
        {
            return E_NOT_OK;
        }
    }
#endif
    SoAd_UpdateApReadinessStatus();
    if (SoAd_GetPduRouteConfig(TxPduId, &RouteCfgPtr) != E_OK)
    {
        return E_NOT_OK;
    }

    if (SoAd_IsRoutingAllowedForPdu(TxPduId) == FALSE)
    {
        return E_NOT_OK;
    }

    #ifdef SOAD_DEBUG
        (void)printf("Secure PDU -->\n");
        {
            PduLengthType i;
            for (i = 0U; i < PduInfoPtr->SduLength; i++)
            {
                (void)printf("%d ", PduInfoPtr->SduDataPtr[i]);
            }
            (void)printf("\n");
        }
    #endif

    /* Transmit through the selected payload backend. */
    PERF_PROBE_BEGIN(soad);
#if (SOAD_TCPIP_PAYLOAD_BACKEND == SOAD_TCPIP_PAYLOAD_BACKEND_ETHIF)
    result = SoAd_EthIfTransmit(TxPduId, PduInfoPtr->SduDataPtr, (uint16)PduInfoPtr->SduLength);
#else
    result = SoAd_TcpIpTransmit(TxPduId, PduInfoPtr->SduDataPtr, (uint16)PduInfoPtr->SduLength);
#endif
    PERF_PROBE_END(soad, TxPduId, SECOC_PERF_STAGE_SOAD_DISPATCH);

    ApBridge_ReportServiceStatus((result == E_OK) ? TRUE : FALSE);

    /* Confirmation callbacks (preserved from original) */
    if (RouteCfgPtr->SoAdPduRouteType == SOAD_PDU_ROUTE_TP)
    {
        SoAdTp_TxConfirmation(TxPduId, result);
    }
    else if (RouteCfgPtr->SoAdPduRouteType == SOAD_PDU_ROUTE_IF)
    {
        PduR_SoAdIfTxConfirmation(TxPduId, result);
    }
    else
    {
        /* No action for other types */
    }

    return result;
}

Std_ReturnType SoAd_TpTransmit(PduIdType SoAdTxSduId, const PduInfoType* SoAdTxInfoPtr)
{
    #ifdef SOAD_DEBUG
        (void)printf("######## in SoAd_TpTransmit\n");
    #endif

    /* SOAD_DISPATCH probe (TP path). The IF-mode probe in SoAd_IfTransmit
     * does not fire for App_Tx → SecOC_TpTransmit → PduR → SoAd_TpTransmit
     * data flow. This probe captures the Tp dispatch latency on the same
     * stage_id so per_stage_table aggregates both paths. */
    PERF_PROBE_BEGIN(soad_tp);

#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        PERF_PROBE_END(soad_tp, SoAdTxSduId, SECOC_PERF_STAGE_SOAD_DISPATCH);
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_TP_TRANSMIT, SOAD_E_NOTINIT);
        return E_NOT_OK;
    }
    if (SoAdTxInfoPtr == NULL)
    {
        PERF_PROBE_END(soad_tp, SoAdTxSduId, SECOC_PERF_STAGE_SOAD_DISPATCH);
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_TP_TRANSMIT, SOAD_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (SoAdTxSduId >= (PduIdType)SOAD_NUM_PDU_IDS)
    {
        PERF_PROBE_END(soad_tp, SoAdTxSduId, SECOC_PERF_STAGE_SOAD_DISPATCH);
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_TP_TRANSMIT, SOAD_E_INV_PDUID);
        return E_NOT_OK;
    }
#else
    if ((SoAdTxInfoPtr == NULL) || (SoAdTxSduId >= (PduIdType)SOAD_NUM_PDU_IDS))
    {
        PERF_PROBE_END(soad_tp, SoAdTxSduId, SECOC_PERF_STAGE_SOAD_DISPATCH);
        return E_NOT_OK;
    }
#endif

    /* TL-Network: reject zero-length and missing routing. */
    if (SoAdTxInfoPtr->SduLength == 0U)
    {
        PERF_PROBE_END(soad_tp, SoAdTxSduId, SECOC_PERF_STAGE_SOAD_DISPATCH);
        return E_NOT_OK;
    }

    if (SoAd_IsRoutingAllowedForPdu(SoAdTxSduId) == FALSE)
    {
        PERF_PROBE_END(soad_tp, SoAdTxSduId, SECOC_PERF_STAGE_SOAD_DISPATCH);
        return E_NOT_OK;
    }


    /* Reject if a session is already in flight for this PduId. */
    if (SoAdTp_TxSessions[SoAdTxSduId].State != SOAD_TP_TX_SESSION_IDLE)
    {
        PERF_PROBE_END(soad_tp, SoAdTxSduId, SECOC_PERF_STAGE_SOAD_DISPATCH);
        return E_NOT_OK;
    }

    /* Ensure socket connection exists and is online. */
    {
        SoAd_SoConIdType soConId = SoAd_FindOrCreateSoCon(SoAdTxSduId);
        if (soConId >= SOAD_MAX_SOCKET_CONNECTIONS)
        {
            PERF_PROBE_END(soad_tp, SoAdTxSduId, SECOC_PERF_STAGE_SOAD_DISPATCH);
            return E_NOT_OK;
        }
        if (SoAd_SoConStates[soConId].Mode != SOAD_SOCON_ONLINE)
        {
            if (SoAd_OpenSoCon(soConId) != E_OK)
            {
                PERF_PROBE_END(soad_tp, SoAdTxSduId, SECOC_PERF_STAGE_SOAD_DISPATCH);
                return E_NOT_OK;
            }
        }
        /* TCP: a request is accepted only for a connection that exists (the connecting side has
         * just tried to connect above; the listening side has a peer or not) */
        if ((SoAd_SoConStates[soConId].Protocol == TCPIP_IPPROTO_TCP) &&
            ((SoAd_RxStreams[soConId].Active == FALSE) || (SoAd_RxStreams[soConId].PeerClosed == TRUE)))
        {
            PERF_PROBE_END(soad_tp, SoAdTxSduId, SECOC_PERF_STAGE_SOAD_DISPATCH);
            return E_NOT_OK;
        }
    }

    /* Stage the request; actual byte pulls happen in SoAd_MainFunctionTx, one PDU at a time per
     * connection, in the order of these calls. (Not [SWS_SoAd_00650]: a request made while another
     * PDU is in transmission on the socket is queued, not rejected.) */
    {
        const SoAd_PduRouteConfigType* routeCfgPtr = NULL;
        const SoAd_UpperLayerType* upper = NULL;

        if (SoAd_GetPduRouteConfig(SoAdTxSduId, &routeCfgPtr) == E_OK)
        {
            upper = SoAd_GetUpperLayer(routeCfgPtr);
        }
        if (upper == NULL)
        {
            PERF_PROBE_END(soad_tp, SoAdTxSduId, SECOC_PERF_STAGE_SOAD_DISPATCH);
            return E_NOT_OK;
        }
        SoAdTp_TxSessions[SoAdTxSduId].Upper = upper;
    }
    SoAd_TxRequestCounter++;
    SoAdTp_TxSessions[SoAdTxSduId].RequestSeq  = SoAd_TxRequestCounter;
    SoAdTp_TxSessions[SoAdTxSduId].TotalLength = SoAdTxInfoPtr->SduLength;
    SoAdTp_TxSessions[SoAdTxSduId].BytesSent   = 0U;
    SoAdTp_TxSessions[SoAdTxSduId].RetryBudget = SOAD_TP_TX_RETRY_BUDGET;
    SoAdTp_TxSessions[SoAdTxSduId].State       = SOAD_TP_TX_SESSION_PENDING;

    PERF_PROBE_END(soad_tp, SoAdTxSduId, SECOC_PERF_STAGE_SOAD_DISPATCH);
    return E_OK;
}

Std_ReturnType SoAd_GetSoConId(PduIdType TxPduId, SoAd_SoConIdType* SoConIdPtr)
{
    SoAd_SoConIdType idx;

#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_GET_SOCON_ID, SOAD_E_NOTINIT);
        return E_NOT_OK;
    }
    if (SoConIdPtr == NULL)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_GET_SOCON_ID, SOAD_E_PARAM_POINTER);
        return E_NOT_OK;
    }
#else
    if (SoConIdPtr == NULL)
    {
        return E_NOT_OK;
    }
#endif

    for (idx = 0U; idx < SOAD_MAX_SOCKET_CONNECTIONS; idx++)
    {
        if ((SoAd_SoConStates[idx].IsAllocated == TRUE) &&
            (SoAd_SoConStates[idx].TxPduId == TxPduId))
        {
            *SoConIdPtr = idx;
            return E_OK;
        }
    }

    return E_NOT_OK;
}

Std_ReturnType SoAd_OpenSoCon(SoAd_SoConIdType SoConId)
{
#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_OPEN_SOCON, SOAD_E_NOTINIT);
        return E_NOT_OK;
    }
    if (SoConId >= SOAD_MAX_SOCKET_CONNECTIONS)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_OPEN_SOCON, SOAD_E_INV_SOCON_ID);
        return E_NOT_OK;
    }
#else
    if (SoConId >= SOAD_MAX_SOCKET_CONNECTIONS)
    {
        return E_NOT_OK;
    }
#endif

    if (SoAd_SoConStates[SoConId].IsAllocated == FALSE)
    {
        return E_NOT_OK;
    }

    if (SoAd_SoConStates[SoConId].SocketId == TCPIP_SOCKET_ID_INVALID)
    {
        if (SoAd_RecreateSoConSocket(SoConId) != E_OK)
        {
            return E_NOT_OK;
        }
    }

    SoAd_SoConStates[SoConId].Mode = SOAD_SOCON_ONLINE;
    SoAd_UpdateApReadinessStatus();

    #ifdef SOAD_DEBUG
        (void)printf("######## SoAd_OpenSoCon: SoConId=%u now ONLINE\n", SoConId);
    #endif

    return E_OK;
}

Std_ReturnType SoAd_CloseSoCon(SoAd_SoConIdType SoConId, boolean Abort)
{
#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_CLOSE_SOCON, SOAD_E_NOTINIT);
        return E_NOT_OK;
    }
    if (SoConId >= SOAD_MAX_SOCKET_CONNECTIONS)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_CLOSE_SOCON, SOAD_E_INV_SOCON_ID);
        return E_NOT_OK;
    }
#else
    if (SoConId >= SOAD_MAX_SOCKET_CONNECTIONS)
    {
        return E_NOT_OK;
    }
#endif

    if (SoAd_SoConStates[SoConId].IsAllocated == FALSE)
    {
        return E_NOT_OK;
    }

    /* Close the underlying TcpIp socket */
    if (SoAd_SoConStates[SoConId].SocketId != TCPIP_SOCKET_ID_INVALID)
    {
        (void)TcpIp_Close(SoAd_SoConStates[SoConId].SocketId, Abort);
        SoAd_SoConStates[SoConId].SocketId = TCPIP_SOCKET_ID_INVALID;
    }

    SoAd_SoConStates[SoConId].Mode = SOAD_SOCON_OFFLINE;
    SoAd_UpdateApReadinessStatus();

    #ifdef SOAD_DEBUG
        (void)printf("######## SoAd_CloseSoCon: SoConId=%u now OFFLINE\n", SoConId);
    #endif

    return E_OK;
}

Std_ReturnType SoAd_GetLocalAddr(
    SoAd_SoConIdType SoConId,
    TcpIp_SockAddrType* LocalAddrPtr,
    uint8* NetmaskPtr,
    TcpIp_SockAddrType* DefaultRouterPtr)
{
#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_GET_LOCAL_ADDR, SOAD_E_NOTINIT);
        return E_NOT_OK;
    }
    if ((LocalAddrPtr == NULL) || (NetmaskPtr == NULL) || (DefaultRouterPtr == NULL))
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_GET_LOCAL_ADDR, SOAD_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (SoConId >= SOAD_MAX_SOCKET_CONNECTIONS)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_GET_LOCAL_ADDR, SOAD_E_INV_SOCON_ID);
        return E_NOT_OK;
    }
#else
    if ((SoConId >= SOAD_MAX_SOCKET_CONNECTIONS) ||
        (LocalAddrPtr == NULL) || (NetmaskPtr == NULL) || (DefaultRouterPtr == NULL))
    {
        return E_NOT_OK;
    }
#endif

    if (SoAd_SoConStates[SoConId].IsAllocated == FALSE)
    {
        return E_NOT_OK;
    }

    return TcpIp_GetIpAddr(
        SoAd_SoConStates[SoConId].LocalAddrId,
        LocalAddrPtr,
        NetmaskPtr,
        DefaultRouterPtr
    );
}

Std_ReturnType SoAd_GetRemoteAddr(SoAd_SoConIdType SoConId, TcpIp_SockAddrType* IpAddrPtr)
{
#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_GET_REMOTE_ADDR, SOAD_E_NOTINIT);
        return E_NOT_OK;
    }
    if (IpAddrPtr == NULL)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_GET_REMOTE_ADDR, SOAD_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (SoConId >= SOAD_MAX_SOCKET_CONNECTIONS)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_GET_REMOTE_ADDR, SOAD_E_INV_SOCON_ID);
        return E_NOT_OK;
    }
#else
    if ((SoConId >= SOAD_MAX_SOCKET_CONNECTIONS) || (IpAddrPtr == NULL))
    {
        return E_NOT_OK;
    }
#endif

    if (SoAd_SoConStates[SoConId].IsAllocated == FALSE)
    {
        return E_NOT_OK;
    }

    *IpAddrPtr = SoAd_SoConStates[SoConId].RemoteAddr;
    return E_OK;
}

Std_ReturnType SoAd_SetRemoteAddr(SoAd_SoConIdType SoConId, const TcpIp_SockAddrType* RemoteAddrPtr)
{
#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_SET_REMOTE_ADDR, SOAD_E_NOTINIT);
        return E_NOT_OK;
    }
    if (RemoteAddrPtr == NULL)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_SET_REMOTE_ADDR, SOAD_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (SoConId >= SOAD_MAX_SOCKET_CONNECTIONS)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_SET_REMOTE_ADDR, SOAD_E_INV_SOCON_ID);
        return E_NOT_OK;
    }
#else
    if ((SoConId >= SOAD_MAX_SOCKET_CONNECTIONS) || (RemoteAddrPtr == NULL))
    {
        return E_NOT_OK;
    }
#endif

    if (SoAd_SoConStates[SoConId].IsAllocated == FALSE)
    {
        return E_NOT_OK;
    }

    SoAd_SoConStates[SoConId].RemoteAddr = *RemoteAddrPtr;
    return E_OK;
}

Std_ReturnType SoAd_EnableRouting(SoAd_RoutingGroupIdType RoutingGroupId)
{
#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_ENABLE_ROUTING, SOAD_E_NOTINIT);
        return E_NOT_OK;
    }
    if (RoutingGroupId >= SOAD_MAX_ROUTING_GROUPS)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_ENABLE_ROUTING, SOAD_E_INV_ROUTING_GROUP_ID);
        return E_NOT_OK;
    }
#else
    if (RoutingGroupId >= SOAD_MAX_ROUTING_GROUPS)
    {
        return E_NOT_OK;
    }
#endif

    SoAd_RoutingGroupStates[RoutingGroupId].Enabled = TRUE;
    return E_OK;
}

Std_ReturnType SoAd_DisableRouting(SoAd_RoutingGroupIdType RoutingGroupId)
{
#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_DISABLE_ROUTING, SOAD_E_NOTINIT);
        return E_NOT_OK;
    }
    if (RoutingGroupId >= SOAD_MAX_ROUTING_GROUPS)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_DISABLE_ROUTING, SOAD_E_INV_ROUTING_GROUP_ID);
        return E_NOT_OK;
    }
#else
    if (RoutingGroupId >= SOAD_MAX_ROUTING_GROUPS)
    {
        return E_NOT_OK;
    }
#endif

    SoAd_RoutingGroupStates[RoutingGroupId].Enabled = FALSE;
    return E_OK;
}

void SoAd_GetVersionInfo(Std_VersionInfoType* VersionInfoPtr)
{
#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (VersionInfoPtr == NULL)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_GET_VERSION_INFO, SOAD_E_PARAM_POINTER);
        return;
    }
#else
    if (VersionInfoPtr == NULL)
    {
        return;
    }
#endif

    VersionInfoPtr->vendorID         = SOAD_VENDOR_ID;
    VersionInfoPtr->moduleID         = SOAD_MODULE_ID;
    VersionInfoPtr->sw_major_version = SOAD_SW_MAJOR_VERSION;
    VersionInfoPtr->sw_minor_version = SOAD_SW_MINOR_VERSION;
    VersionInfoPtr->sw_patch_version = SOAD_SW_PATCH_VERSION;
}

void SoAd_RxIndication(
    TcpIp_SocketIdType SocketId,
    const TcpIp_SockAddrType* RemoteAddrPtr,
    const uint8* BufPtr,
    uint16 Length
)
{
    PduIdType rxPduId = 0U;
    SoAd_SoConIdType soConId = 0U;
    PduInfoType pduInfo;
    const SoAd_PduRouteConfigType* RouteCfgPtr = NULL;

#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_RX_INDICATION, SOAD_E_NOTINIT);
        return;
    }
    if ((RemoteAddrPtr == NULL) || (BufPtr == NULL))
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_RX_INDICATION, SOAD_E_PARAM_POINTER);
        return;
    }
#else
    if ((RemoteAddrPtr == NULL) || (BufPtr == NULL))
    {
        return;
    }
#endif

    /* TCP socket connection: every byte passes through the stream buffer. PDU boundaries, routing
     * and drop decisions are taken per PDU in SoAd_MainFunctionRx; a segment dropped here would put
     * the stream out of step for good. */
    for (soConId = 0U; soConId < SOAD_MAX_SOCKET_CONNECTIONS; soConId++)
    {
        SoAd_RxStreamType* stream = &SoAd_RxStreams[soConId];

        if ((stream->Active == TRUE) && (stream->SocketId == SocketId))
        {
            if ((uint32)Length > (SOAD_RX_STREAM_BUFFER_SIZE - stream->Fill))
            {
                /* [SWS_SoAd_00693]. Not reached from TcpIp, which SoAd_MainFunctionRx polls only
                 * while there is room.
                 * shortcut: the data is dropped and the stream is then out of step; close the
                 * connection here if a TcpIp is used that delivers without being polled. */
                (void)Det_ReportRuntimeError(SOAD_MODULE_ID, 0U, SOAD_SID_RX_INDICATION, SOAD_E_NOBUFS);
                SoAd_MeasDropTcp++;
            }
            else
            {
                (void)memcpy(&stream->Data[stream->Fill], BufPtr, Length);
                stream->Fill += Length;
            }
            return;
        }
    }

    if ((Length == 0U) || (Length > (uint16)SECOC_SECPDU_MAX_LENGTH))
    {
        return;
    }

    if ((SoAd_UnauthApControlEnabled == TRUE) &&
        (SoAd_IsApControlPdu(BufPtr, Length) == TRUE))
    {
        SoAd_HandleApControlPdu(BufPtr);
        return;
    }

    if (SoAd_FindRxPduIdBySocket(SocketId, &rxPduId, &soConId) != E_OK)
    {
        return;
    }

    if (rxPduId >= (PduIdType)SECOC_NUM_OF_RX_PDU_PROCESSING)
    {
        return;
    }
    if (SoAd_IsRoutingAllowedForPdu(rxPduId) == FALSE)
    {
        return;
    }
    if (SoAd_GetPduRouteConfig(rxPduId, &RouteCfgPtr) != E_OK)
    {
        return;
    }

    /* Keep latest remote peer associated with the socket connection. */
    SoAd_SoConStates[soConId].RemoteAddr = *RemoteAddrPtr;

    /* cppcheck-suppress misra-c2012-11.8 */
    pduInfo.SduDataPtr = (uint8*)BufPtr;
    pduInfo.MetaDataPtr = NULL;
    pduInfo.SduLength = (PduLengthType)Length;

    if (RouteCfgPtr->SoAdPduRouteType == SOAD_PDU_ROUTE_TP)
    {
        SoAdTp_RxIndication(rxPduId, &pduInfo);
    }
    else if (RouteCfgPtr->SoAdPduRouteType == SOAD_PDU_ROUTE_IF)
    {
        PduR_SoAdIfRxIndication(rxPduId, &pduInfo);
    }
    else
    {
        /* Ignore non-SoAd routed types. */
    }
}

void SoAdTp_RxIndication(PduIdType RxPduId, const PduInfoType* PduInfoPtr)
{
    PduLengthType bufferSize = 0U;

    #ifdef SOAD_DEBUG
        (void)printf("######## in SoAdTp_RxIndication\n");
    #endif

    /* One complete PDU (a UDP datagram, or a PDU injected by the GUI interface): forwarded as is. */
    if ((PduInfoPtr == NULL) || (PduInfoPtr->SduDataPtr == NULL) || (PduInfoPtr->SduLength == 0U))
    {
        return;
    }

    if (PduR_SoAdStartOfReception(RxPduId, PduInfoPtr, PduInfoPtr->SduLength, &bufferSize) != BUFREQ_OK)
    {
        return;
    }

    if (PduR_SoAdTpCopyRxData(RxPduId, PduInfoPtr, &bufferSize) == BUFREQ_OK)
    {
        PduR_SoAdTpRxIndication(RxPduId, E_OK);
    }
    else
    {
        PduR_SoAdTpRxIndication(RxPduId, E_NOT_OK);
    }
}

/* The transmit sessions in the order they are served: one that is inside a PDU first, then by the
 * order of the SoAd_TpTransmit calls (wrap-safe). Returns the number of entries written to Order. */
static uint8 SoAd_TxOrder(PduIdType* Order)
{
    uint8 count = 0U;
    uint8 i;
    PduIdType id;

    for (id = 0U; id < (PduIdType)SOAD_NUM_PDU_IDS; id++)
    {
        if (SoAdTp_TxSessions[id].State != SOAD_TP_TX_SESSION_IDLE)
        {
            const SoAdTp_TxSessionType* sess = &SoAdTp_TxSessions[id];

            i = count;
            while (i > 0U)
            {
                const SoAdTp_TxSessionType* other = &SoAdTp_TxSessions[Order[i - 1U]];
                boolean before = ((sess->BytesSent > 0U) && (other->BytesSent == 0U)) ? TRUE : FALSE;

                if ((before == FALSE) && ((sess->BytesSent > 0U) == (other->BytesSent > 0U)) &&
                    ((sint32)(sess->RequestSeq - other->RequestSeq) < 0))
                {
                    before = TRUE;
                }
                if (before == FALSE)
                {
                    break;
                }
                Order[i] = Order[i - 1U];
                i--;
            }
            Order[i] = id;
            count++;
        }
    }
    return count;
}

void SoAd_MainFunctionTx(void)
{
    #ifdef SOAD_DEBUG
        (void)printf("######## in SoAd_MainFunctionTx\n");
    #endif

    PduIdType TxPduId;
    PduIdType order[SOAD_NUM_PDU_IDS];
    uint8 orderCount = SoAd_TxOrder(order);
    uint8 orderIdx;

    for (orderIdx = 0U; orderIdx < orderCount; orderIdx++)
    {
        SoAdTp_TxSessionType* sess = &SoAdTp_TxSessions[order[orderIdx]];
        const SoAd_PduRouteConfigType* RouteCfgPtr = NULL;
        SoAd_SoConIdType soConId;
        boolean sessionFailed = FALSE;
        boolean streamBroken = FALSE;

        TxPduId = order[orderIdx];
        if ((sess->State == SOAD_TP_TX_SESSION_IDLE) || (sess->Upper == NULL))
        {
            continue;
        }

        /* Routing must remain enabled for the duration of the session. */
        if (SoAd_IsRoutingAllowedForPdu(TxPduId) == FALSE)
        {
            sess->State = SOAD_TP_TX_SESSION_IDLE;
            sess->TotalLength = 0U;
            sess->BytesSent = 0U;
            sess->Upper->TxConfirmation(TxPduId, E_NOT_OK);
            continue;
        }

        soConId = SoAd_FindOrCreateSoCon(TxPduId);
        if (soConId >= SOAD_MAX_SOCKET_CONNECTIONS)
        {
            sess->State = SOAD_TP_TX_SESSION_IDLE;
            sess->TotalLength = 0U;
            sess->BytesSent = 0U;
            sess->Upper->TxConfirmation(TxPduId, E_NOT_OK);
            continue;
        }

        if (SoAd_SoConStates[soConId].Mode != SOAD_SOCON_ONLINE)
        {
            /* Wait for the connection to come up; do not consume retry budget. */
            continue;
        }
        if ((SoAd_SoConStates[soConId].Protocol == TCPIP_IPPROTO_TCP) &&
            ((SoAd_RxStreams[soConId].Active == FALSE) || (SoAd_RxStreams[soConId].PeerClosed == TRUE)))
        {
            /* no TCP connection at the moment (listening side without a peer, or the peer just
             * closed): the request waits for the next connection */
            continue;
        }


        if (sess->State == SOAD_TP_TX_SESSION_PENDING)
        {
            sess->State = SOAD_TP_TX_SESSION_ACTIVE;
        }

        /* Pull from upper layer and push to TcpIp until the session is drained
         * or the upper layer signals it is busy. */
        while (sess->BytesSent < sess->TotalLength)
        {
            PduLengthType remaining = sess->TotalLength - sess->BytesSent;
            PduLengthType headerLength = 0U;
            PduLengthType chunk;
            PduInfoType info;
            RetryInfoType retry;
            PduLengthType availableDataPtr = 0U;
            BufReq_ReturnType copyResult;
            Std_ReturnType txResult;

            /* [SWS_SoAd_00197] the PDU header goes directly before the PDU data, in the same
             * TcpIp_TcpTransmit call as the first chunk. */
            if ((sess->BytesSent == 0U) &&
                (SoAd_SoConStates[soConId].Protocol == TCPIP_IPPROTO_TCP) &&
                (SoAd_GetPduRouteConfig(TxPduId, &RouteCfgPtr) == E_OK))
            {
                SoAd_PutBe32(&sess->WorkBuf[0], RouteCfgPtr->SoAdPduHeaderId);
                SoAd_PutBe32(&sess->WorkBuf[4], (uint32)sess->TotalLength);
                headerLength = SOAD_PDU_HEADER_LENGTH;
            }

            chunk = (remaining > (SOAD_TP_TX_CHUNK_BYTES - headerLength))
                    ? (SOAD_TP_TX_CHUNK_BYTES - headerLength)
                    : remaining;

            info.SduDataPtr  = &sess->WorkBuf[headerLength];
            info.MetaDataPtr = NULL;
            info.SduLength   = chunk;

            retry.TpDataState = TP_DATACONF;
            retry.TxTpDataCnt = 0U;

            copyResult = sess->Upper->CopyTxData(TxPduId, &info, &retry, &availableDataPtr);

            if (copyResult == BUFREQ_E_BUSY)
            {
                /* Upper layer not ready - try again next cycle. */
                if (sess->RetryBudget == 0U)
                {
                    sessionFailed = TRUE;
                }
                else
                {
                    sess->RetryBudget--;
                }
                break;
            }

            if (copyResult != BUFREQ_OK)
            {
                /* [SWS_SoAd_00651] the upper layer gave up: the connection is closed below */
                sessionFailed = TRUE;
                streamBroken = TRUE;
                break;
            }

            /* Refresh the retry budget on a successful pull. */
            sess->RetryBudget = SOAD_TP_TX_RETRY_BUDGET;

            if (SoAd_SoConStates[soConId].Protocol == TCPIP_IPPROTO_UDP)
            {
                txResult = TcpIp_UdpTransmit(
                    SoAd_SoConStates[soConId].SocketId,
                    sess->WorkBuf,
                    &SoAd_SoConStates[soConId].RemoteAddr,
                    (uint16)chunk
                );
            }
            else
            {
                /* the connected socket: the socket connection's own on the connecting side, the
                 * accepted one on the listening side */
                txResult = TcpIp_TcpTransmit(
                    SoAd_RxStreams[soConId].SocketId,
                    sess->WorkBuf,
                    (uint32)(headerLength + chunk),
                    TRUE
                );
            }

            if (txResult != E_OK)
            {
                /* part of the chunk may have gone out */
                sessionFailed = TRUE;
                streamBroken = TRUE;
                break;
            }

            sess->BytesSent += chunk;
        }

        if (sessionFailed == TRUE)
        {
            /* The header goes out with the first chunk, so bytes sent means the receiver is inside
             * this PDU: it would take the next PDU for the rest of this one. */
            if (sess->BytesSent > 0U)
            {
                streamBroken = TRUE;
            }
            sess->State = SOAD_TP_TX_SESSION_IDLE;
            sess->TotalLength = 0U;
            sess->BytesSent = 0U;
            sess->Upper->TxConfirmation(TxPduId, E_NOT_OK);
            ApBridge_ReportServiceStatus(FALSE);
            if ((streamBroken == TRUE) && (SoAd_SoConStates[soConId].Protocol == TCPIP_IPPROTO_TCP))
            {
                /* close the connected socket, never the listening one; the connecting side
                 * reconnects with the next transmit request */
                SoAd_RxStreamEnd(soConId, TRUE);
            }
        }
        else if (sess->BytesSent >= sess->TotalLength)
        {
            sess->State = SOAD_TP_TX_SESSION_IDLE;
            sess->TotalLength = 0U;
            sess->BytesSent = 0U;
            sess->Upper->TxConfirmation(TxPduId, E_OK);
            ApBridge_ReportServiceStatus(TRUE);
        }
        else
        {
            /* Session remains active; resume next cycle. */
        }

        if ((sess->State == SOAD_TP_TX_SESSION_ACTIVE) && (sess->BytesSent > 0U))
        {
            /* the stream is inside this PDU: nothing else goes out before its last byte
             * shortcut: this stops the other socket connections for this cycle too; keep one
             * "inside a PDU" marker per connection if more than one TCP connection is configured */
            break;
        }
    }

    SoAd_UpdateApReadinessStatus();
}

void SoAdTp_TxConfirmation(PduIdType TxPduId, Std_ReturnType result)
{
    (void)TxPduId;
    (void)result;

    #ifdef SOAD_DEBUG
        (void)printf("######## in SoAd_TxConfirmation \n");
    #endif
}

void SoAd_MainFunctionRx(void)
{
    SoAd_SoConIdType idx;
    boolean roomForIndication = TRUE;

    #ifdef SOAD_DEBUG
        (void)printf("######## in SoAd_MainFunctionRx\n");
    #endif

    /* Poll the backend only while every stream buffer can take one more indication. Data that is
     * not read stays in the TCP stack, so a slow upper layer slows the sender (TCP flow control)
     * instead of losing PDUs. */
    for (idx = 0U; idx < SOAD_MAX_SOCKET_CONNECTIONS; idx++)
    {
        if ((SoAd_RxStreams[idx].Active == TRUE) &&
            ((SOAD_RX_STREAM_BUFFER_SIZE - SoAd_RxStreams[idx].Fill) < TCPIP_RX_BUFFER_SIZE))
        {
            roomForIndication = FALSE;
        }
    }

#if (SOAD_TCPIP_PAYLOAD_BACKEND == SOAD_TCPIP_PAYLOAD_BACKEND_ETHIF)
    /* EthIf polling is handled by EcuM main path; keep SoAd side callback-driven. */
    (void)roomForIndication;
#else
    if (roomForIndication == TRUE)
    {
        TcpIp_MainFunction();
    }
#endif

    for (idx = 0U; idx < SOAD_MAX_SOCKET_CONNECTIONS; idx++)
    {
        if (SoAd_RxStreams[idx].Active == TRUE)
        {
            SoAd_RxStreamProcess(&SoAd_RxStreams[idx]);
        }
        /* The peer closed: end the stream once nothing more can be made of the buffered bytes
         * (empty, a partial header, inside a PDU, or behind a shut gate). Complete PDUs waiting for
         * the upper layer are still delivered first. */
        if ((SoAd_RxStreams[idx].Active == TRUE) && (SoAd_RxStreams[idx].PeerClosed == TRUE) &&
            ((SoAd_RxStreams[idx].Fill < SOAD_PDU_HEADER_LENGTH) || (SoAd_RxStreams[idx].Remaining != 0U) ||
             (SoAd_RxStreams[idx].Gated == TRUE)))
        {
            SoAd_RxStreamEnd(idx, FALSE);
        }
    }

    SoAd_UpdateApReadinessStatus();
}

/* [SWS_SoAd_00099], [SWS_SoAd_00636] */
Std_ReturnType SoAd_TcpAccepted(
    TcpIp_SocketIdType SocketId,
    TcpIp_SocketIdType SocketIdConnected,
    const TcpIp_SockAddrType* RemoteAddrPtr)
{
    SoAd_SoConIdType idx;

    if (RemoteAddrPtr == NULL)
    {
        return E_NOT_OK;
    }

    for (idx = 0U; idx < SOAD_MAX_SOCKET_CONNECTIONS; idx++)
    {
        if ((SoAd_SoConStates[idx].IsAllocated == TRUE) &&
            (SoAd_SoConStates[idx].Protocol == TCPIP_IPPROTO_TCP) &&
            (SoAd_SoConStates[idx].SocketId == SocketId))
        {
            const uint8* peer = (idx < SoAd_ActiveConfig.SoAdSoConConfigCount)
                                ? SoAd_ActiveConfig.SoAdSoConConfigPtr[idx].SoAdRemoteAddr.addr : NULL;

            /* One connection at a time: while a stream is active a further connection is refused
             * (TcpIp closes it), whoever it comes from; it must not take the stream over. The
             * precondition "not online" of [SWS_SoAd_00636], keyed on the stream because the
             * listening socket connection is ONLINE from init. */
            if (SoAd_RxStreams[idx].Active == TRUE)
            {
                return E_NOT_OK;
            }
            /* Message acceptance filter [SWS_SoAd_00524]: only the configured peer address (the
             * port is not compared, the peer connects from an ephemeral one). An availability
             * measure, not authentication. */
            if ((peer != NULL) && (memcmp(peer, RemoteAddrPtr->addr, sizeof(RemoteAddrPtr->addr)) != 0))
            {
                return E_NOT_OK;
            }

            /* the accepted socket is the one that carries the data: its own parameter change, not the
             * listening socket's (refused like any other connection that is not taken) */
            if (SoAd_ApplyTcpNoDelay(idx, SocketIdConnected) != E_OK)
            {
                return E_NOT_OK;
            }

            SoAd_SoConStates[idx].RemoteAddr = *RemoteAddrPtr;
            SoAd_SoConStates[idx].Mode = SOAD_SOCON_ONLINE;
            SoAd_RxStreamStart(idx, SocketIdConnected);
            return E_OK;
        }
    }

    return E_NOT_OK;
}

Std_ReturnType SoAd_GetSoConTcpInfo(SoAd_SoConIdType SoConId, uint32* ConnectionCountPtr, uint8* NoDelayPtr)
{
    if ((SoConId >= SOAD_MAX_SOCKET_CONNECTIONS) || (ConnectionCountPtr == NULL) || (NoDelayPtr == NULL) ||
        (SoAd_RxStreams[SoConId].Active == FALSE))
    {
        return E_NOT_OK;
    }

    *ConnectionCountPtr = SoAd_TcpConnectionCount[SoConId];
    return TcpIp_GetTcpNoDelay(SoAd_RxStreams[SoConId].SocketId, NoDelayPtr);
}

Std_ReturnType SoAd_SetUpperLayer(SoAd_UpperLayerIdType Id, const SoAd_UpperLayerType* UpperLayerPtr)
{
    SoAd_SoConIdType idx;

    if ((Id == SOAD_UPPER_LAYER_PDUR) || (Id >= SOAD_NUM_UPPER_LAYERS) || (UpperLayerPtr == NULL) ||
        (UpperLayerPtr->StartOfReception == NULL) || (UpperLayerPtr->CopyRxData == NULL) ||
        (UpperLayerPtr->RxIndication == NULL) || (UpperLayerPtr->CopyTxData == NULL) ||
        (UpperLayerPtr->TxConfirmation == NULL))
    {
        return E_NOT_OK;
    }

    SoAd_UpperLayers[Id] = UpperLayerPtr;

    /* a connection made before the layer was bound (the connecting side connects in SoAd_Init) */
    if (UpperLayerPtr->SoConModeChg != NULL)
    {
        for (idx = 0U; idx < SOAD_MAX_SOCKET_CONNECTIONS; idx++)
        {
            if ((SoAd_RxStreams[idx].Active == TRUE) && (SoAd_RxStreams[idx].PeerClosed == FALSE))
            {
                UpperLayerPtr->SoConModeChg(idx, SOAD_SOCON_ONLINE);
            }
        }
    }
    return E_OK;
}

void SoAd_RxGateRelease(PduIdType RxPduId)
{
    SoAd_SoConIdType idx;

    for (idx = 0U; idx < SOAD_MAX_SOCKET_CONNECTIONS; idx++)
    {
        if ((SoAd_RxStreams[idx].Active == TRUE) && (SoAd_RxStreams[idx].Gated == TRUE) &&
            (SoAd_RxStreams[idx].GatePduId == RxPduId))
        {
            SoAd_RxStreams[idx].Gated = FALSE;
        }
    }
}

/* [SWS_SoAd_00146], [SWS_SoAd_00646]: the socket is already released by TcpIp. What the stream still
 * holds is processed by SoAd_MainFunctionRx, which then ends the stream. */
void SoAd_TcpIpEvent(TcpIp_SocketIdType SocketId, TcpIp_EventType Event)
{
    SoAd_SoConIdType idx;

    if (Event == TCPIP_UDP_CLOSED)
    {
        return;
    }

    for (idx = 0U; idx < SOAD_MAX_SOCKET_CONNECTIONS; idx++)
    {
        if ((SoAd_RxStreams[idx].Active == TRUE) && (SoAd_RxStreams[idx].SocketId == SocketId))
        {
            SoAd_RxStreams[idx].PeerClosed = TRUE;
        }
    }
}

/* [SWS_SoAd_00010], [SWS_SoAd_00749]; SOAD_MEAS_DROP_UDP is not counted */
Std_ReturnType SoAd_GetAndResetMeasurementData(
    SoAd_MeasurementIdxType MeasurementIdx,
    boolean MeasurementResetNeeded,
    uint32* MeasurementDataPtr)
{
    if ((MeasurementIdx != SOAD_MEAS_DROP_TCP) && (MeasurementIdx != SOAD_MEAS_ALL))
    {
        return E_NOT_OK;
    }

    if ((MeasurementIdx == SOAD_MEAS_DROP_TCP) && (MeasurementDataPtr != NULL))
    {
        *MeasurementDataPtr = SoAd_MeasDropTcp;
    }
    if (MeasurementResetNeeded == TRUE)
    {
        SoAd_MeasDropTcp = 0U;
    }

    return E_OK;
}

Std_ReturnType SoAd_SetApBridgeState(SoAd_ApBridgeStateType State)
{
#if (SOAD_DEV_ERROR_DETECT == STD_ON)
    if (SoAd_Initialized == FALSE)
    {
        (void)Det_ReportError(SOAD_MODULE_ID, 0U, SOAD_SID_SET_AP_BRIDGE_STATE, SOAD_E_NOTINIT);
        return E_NOT_OK;
    }
#endif

    if (State > SOAD_AP_BRIDGE_DEGRADED)
    {
        return E_NOT_OK;
    }

    SoAd_ApBridgeExternalControl = TRUE;

    if (SoAd_ApBridgeState != State)
    {
        SoAd_ApBridgeState = State;
        (void)BswM_RequestMode(BSWM_REQUESTER_ID_AP_READY, (BswM_ModeType)State);
    }

    return E_OK;
}
