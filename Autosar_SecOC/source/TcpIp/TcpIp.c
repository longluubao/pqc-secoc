/**
 * @file TcpIp.c
 * @brief AUTOSAR TcpIp Module - TCP/IP Stack Abstraction Implementation
 * @details Wraps platform sockets (Winsock2 / POSIX) with AUTOSAR-compliant API.
 *          Conforms to AUTOSAR CP R24-11 SWS_TcpIp.
 */

/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/

#include "Det/Det.h"
#include "EthSM/EthSM.h"
#include "SoAd/SoAd.h"
#include "TcpIp/TcpIp.h"
#include "Perf/SecOC_Perf.h"
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_ETHIF)
    #include "EthIf/EthIf.h"
#endif
#include <string.h>

#ifdef WINDOWS
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET PlatformSocketType;
    #define TCPIP_PLATFORM_INVALID_SOCKET  INVALID_SOCKET
    #define TCPIP_PLATFORM_SOCKET_ERROR    SOCKET_ERROR
#else
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    typedef int PlatformSocketType;
    #define TCPIP_PLATFORM_INVALID_SOCKET  (-1)
    #define TCPIP_PLATFORM_SOCKET_ERROR    (-1)
#endif

/* Socket prototypes provided by ethernet.h (Rule 8.5 - no duplicate declarations) */
#if !defined(_FCNTL_H) && !defined(__FCNTL_H__)
extern int fcntl(int fd, int cmd, ...);
#endif

/* MISRA C:2012 Rule 8.4 - Forward declarations for external linkage functions */
extern void TcpIp_Init(const TcpIp_ConfigType* ConfigPtr);
extern void TcpIp_Shutdown(void);
extern Std_ReturnType TcpIp_GetSocketId(TcpIp_DomainType Domain, TcpIp_ProtocolType Protocol, TcpIp_SocketIdType* SocketIdPtr);
extern Std_ReturnType TcpIp_Close(TcpIp_SocketIdType SocketId, boolean Abort);
extern Std_ReturnType TcpIp_Bind(TcpIp_SocketIdType SocketId, TcpIp_LocalAddrIdType LocalAddrId, uint16* PortPtr);
extern Std_ReturnType TcpIp_TcpConnect(TcpIp_SocketIdType SocketId, const TcpIp_SockAddrType* RemoteAddrPtr);
extern Std_ReturnType TcpIp_TcpListen(TcpIp_SocketIdType SocketId, uint16 MaxChannels);
extern Std_ReturnType TcpIp_UdpTransmit(TcpIp_SocketIdType SocketId, const uint8* DataPtr, const TcpIp_SockAddrType* RemoteAddrPtr, uint16 TotalLength);
extern Std_ReturnType TcpIp_TcpTransmit(TcpIp_SocketIdType SocketId, const uint8* DataPtr, uint32 AvailableLength, boolean ForceRetrieve);
extern void TcpIp_RxIndication(TcpIp_SocketIdType SocketId, const TcpIp_SockAddrType* RemoteAddrPtr, const uint8* BufPtr, uint16 Length);
extern void TcpIp_MainFunction(void);
extern void TcpIp_GetVersionInfo(Std_VersionInfoType* VersionInfoPtr);
extern Std_ReturnType TcpIp_RequestIpAddrAssignment(TcpIp_LocalAddrIdType LocalAddrId, TcpIp_IpAddrAssignmentType Type, const TcpIp_SockAddrType* LocalIpAddrPtr);
extern Std_ReturnType TcpIp_GetIpAddr(TcpIp_LocalAddrIdType LocalAddrId, TcpIp_SockAddrType* IpAddrPtr, uint8* NetmaskPtr, TcpIp_SockAddrType* DefaultRouterPtr);

/********************************************************************************************************/
/************************************************Defines*************************************************/
/********************************************************************************************************/

#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_ETHIF)
#define TCPIP_ETHIF_CTRL_IDX        ((uint8)0U)
#define TCPIP_ETHIF_FRAME_TYPE_BASE ((Eth_FrameType)0x9100U)
#endif

/********************************************************************************************************/
/*******************************************TypeDefinitions**********************************************/
/********************************************************************************************************/

/** @brief Internal socket entry */
typedef struct
{
    PlatformSocketType     platformSocket;
    TcpIp_SocketStateType  state;
    TcpIp_DomainType       domain;
    TcpIp_ProtocolType     protocol;
    TcpIp_LocalAddrIdType  localAddrId;
    uint16                 localPort;
    TcpIp_SockAddrType     remoteAddr;
} TcpIp_SocketEntryType;

/** @brief Local address entry */
typedef struct
{
    TcpIp_SockAddrType         ipAddr;
    uint8                      netmask;
    TcpIp_SockAddrType         defaultRouter;
    boolean                    assigned;
    TcpIp_IpAddrAssignmentType assignmentType;
} TcpIp_LocalAddrEntryType;

/********************************************************************************************************/
/******************************************GlobalVariables**********************************************/
/********************************************************************************************************/

static TcpIp_StateType TcpIp_ModuleState = TCPIP_STATE_UNINIT;

static TcpIp_SocketEntryType TcpIp_SocketTable[TCPIP_MAX_SOCKETS];

static TcpIp_LocalAddrEntryType TcpIp_LocalAddrTable[TCPIP_MAX_LOCAL_ADDR];

#ifdef WINDOWS
static WSADATA TcpIp_WsaData;
static boolean TcpIp_WinsockInitialized = FALSE;
#endif

static uint8 TcpIp_RxBuffer[TCPIP_RX_BUFFER_SIZE];

/********************************************************************************************************/
/**************************************StaticFunctionPrototypes******************************************/
/********************************************************************************************************/

static void TcpIp_SockAddrToSockAddrIn(const TcpIp_SockAddrType* SrcAddr, struct sockaddr_in* DstAddr);
static void TcpIp_SockAddrInToSockAddr(const struct sockaddr_in* SrcAddr, TcpIp_SockAddrType* DstAddr);
static Std_ReturnType TcpIp_SetNonBlocking(PlatformSocketType Sock);
static void TcpIp_ClosePlatformSocket(PlatformSocketType Sock);
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_ETHIF)
static void TcpIp_EthIfRxIndicationCbk(uint8 CtrlIdx,
                                       Eth_FrameType FrameType,
                                       boolean IsBroadcast,
                                       const uint8* PhysAddrPtr,
                                       const uint8* DataPtr,
                                       uint16 LenByte);
#endif

/********************************************************************************************************/
/****************************************StaticFunctions*************************************************/
/********************************************************************************************************/

static void TcpIp_SockAddrToSockAddrIn(const TcpIp_SockAddrType* SrcAddr, struct sockaddr_in* DstAddr)
{
    (void)memset(DstAddr, 0, sizeof(struct sockaddr_in));
    DstAddr->sin_family = AF_INET;
    DstAddr->sin_port   = htons(SrcAddr->port);
    (void)memcpy(&DstAddr->sin_addr.s_addr, SrcAddr->addr, 4U);
}

static void TcpIp_SockAddrInToSockAddr(const struct sockaddr_in* SrcAddr, TcpIp_SockAddrType* DstAddr)
{
    DstAddr->domain = TCPIP_AF_INET;
    DstAddr->port   = ntohs(SrcAddr->sin_port);
    (void)memcpy(DstAddr->addr, &SrcAddr->sin_addr.s_addr, 4U);
}

static Std_ReturnType TcpIp_SetNonBlocking(PlatformSocketType Sock)
{
#ifdef WINDOWS
    u_long mode = 1U;
    if (ioctlsocket(Sock, (long)FIONBIO, &mode) != 0)
    {
        return E_NOT_OK;
    }
#else
    int flags = fcntl(Sock, F_GETFL, 0);
    if (flags == -1)
    {
        return E_NOT_OK;
    }
    if (fcntl(Sock, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        return E_NOT_OK;
    }
#endif
    return E_OK;
}

/* Connected TCP sockets: keep-alive with short timers and a bound on unacknowledged data
 * (SoAd parameters SoAdSocketTcpKeepAlive*, [SWS_SoAd_00689]; fixed values here, TcpIp.h). */
static void TcpIp_SetTcpTimers(PlatformSocketType Sock)
{
#ifdef WINDOWS
    (void)Sock;
#else
    int on = 1;
    int idle = TCPIP_TCP_KEEPALIVE_TIME_S;
    int interval = TCPIP_TCP_KEEPALIVE_INTERVAL_S;
    int probes = TCPIP_TCP_KEEPALIVE_PROBES;
    unsigned int userTimeout = TCPIP_TCP_USER_TIMEOUT_MS;

    (void)setsockopt(Sock, SOL_SOCKET, SO_KEEPALIVE, &on, (socklen_t)sizeof(on));
    (void)setsockopt(Sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, (socklen_t)sizeof(idle));
    (void)setsockopt(Sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, (socklen_t)sizeof(interval));
    (void)setsockopt(Sock, IPPROTO_TCP, TCP_KEEPCNT, &probes, (socklen_t)sizeof(probes));
    (void)setsockopt(Sock, IPPROTO_TCP, TCP_USER_TIMEOUT, &userTimeout, (socklen_t)sizeof(userTimeout));
#endif
}

static void TcpIp_ClosePlatformSocket(PlatformSocketType Sock)
{
#ifdef WINDOWS
    (void)closesocket(Sock);
#else
    (void)close(Sock);
#endif
}

#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_ETHIF)
static void TcpIp_EthIfRxIndicationCbk(uint8 CtrlIdx,
                                       Eth_FrameType FrameType,
                                       boolean IsBroadcast,
                                       const uint8* PhysAddrPtr,
                                       const uint8* DataPtr,
                                       uint16 LenByte)
{
    TcpIp_SocketIdType SocketId;
    TcpIp_SockAddrType RemoteAddr;
    (void)CtrlIdx;
    (void)IsBroadcast;
    (void)PhysAddrPtr;

    if ((DataPtr == NULL) || (LenByte == 0U))
    {
        return;
    }
    if ((FrameType < TCPIP_ETHIF_FRAME_TYPE_BASE) ||
        (FrameType >= (Eth_FrameType)(TCPIP_ETHIF_FRAME_TYPE_BASE + TCPIP_MAX_SOCKETS)))
    {
        return;
    }

    SocketId = (TcpIp_SocketIdType)(FrameType - TCPIP_ETHIF_FRAME_TYPE_BASE);
    if ((SocketId >= TCPIP_MAX_SOCKETS) ||
        (TcpIp_SocketTable[SocketId].state == TCPIP_SOCKET_STATE_UNUSED))
    {
        return;
    }

    /* EthIf backend has no IP peer metadata; preserve latest socket peer snapshot. */
    RemoteAddr = TcpIp_SocketTable[SocketId].remoteAddr;
    TcpIp_RxIndication(SocketId, &RemoteAddr, DataPtr, LenByte);
}
#endif

/********************************************************************************************************/
/********************************************Functions***************************************************/
/********************************************************************************************************/

void TcpIp_Init(const TcpIp_ConfigType* ConfigPtr)
{
    uint16 idx;

    (void)ConfigPtr;

#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState == TCPIP_STATE_ONLINE)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_INIT, TCPIP_E_ALREADY_INIT);
        return;
    }
#endif

#ifdef WINDOWS
    if (TcpIp_WinsockInitialized == FALSE)
    {
        if (WSAStartup(MAKEWORD(2, 2), &TcpIp_WsaData) != 0)
        {
            return;
        }
        TcpIp_WinsockInitialized = TRUE;
    }
#endif

#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_ETHIF)
    EthIf_SetRxIndicationCallback(TcpIp_EthIfRxIndicationCbk);
#endif

    /* Initialize socket table */
    for (idx = 0U; idx < TCPIP_MAX_SOCKETS; idx++)
    {
        TcpIp_SocketTable[idx].platformSocket = TCPIP_PLATFORM_INVALID_SOCKET;
        TcpIp_SocketTable[idx].state          = TCPIP_SOCKET_STATE_UNUSED;
        TcpIp_SocketTable[idx].domain         = TCPIP_AF_INET;
        TcpIp_SocketTable[idx].protocol       = TCPIP_IPPROTO_TCP;
        TcpIp_SocketTable[idx].localAddrId    = 0U;
        TcpIp_SocketTable[idx].localPort      = 0U;
        (void)memset(&TcpIp_SocketTable[idx].remoteAddr, 0, sizeof(TcpIp_SockAddrType));
    }

    /* Initialize local address table */
    for (idx = 0U; idx < TCPIP_MAX_LOCAL_ADDR; idx++)
    {
        (void)memset(&TcpIp_LocalAddrTable[idx], 0, sizeof(TcpIp_LocalAddrEntryType));
        TcpIp_LocalAddrTable[idx].assigned = FALSE;
    }

    /* Set default local address 0 to INADDR_ANY */
    TcpIp_LocalAddrTable[0].ipAddr.domain = TCPIP_AF_INET;
    (void)memset(TcpIp_LocalAddrTable[0].ipAddr.addr, 0, 4U);
    TcpIp_LocalAddrTable[0].ipAddr.port   = 0U;
    TcpIp_LocalAddrTable[0].netmask       = 0U;
    TcpIp_LocalAddrTable[0].assigned      = TRUE;
    TcpIp_LocalAddrTable[0].assignmentType = TCPIP_IPADDR_ASSIGNMENT_STATIC;

    TcpIp_ModuleState = TCPIP_STATE_ONLINE;
}

void TcpIp_Shutdown(void)
{
    uint16 idx;

#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_SHUTDOWN, TCPIP_E_NOTINIT);
        return;
    }
#endif

    /* Close all open sockets */
    for (idx = 0U; idx < TCPIP_MAX_SOCKETS; idx++)
    {
        if (TcpIp_SocketTable[idx].state != TCPIP_SOCKET_STATE_UNUSED)
        {
            if (TcpIp_SocketTable[idx].platformSocket != TCPIP_PLATFORM_INVALID_SOCKET)
            {
                TcpIp_ClosePlatformSocket(TcpIp_SocketTable[idx].platformSocket);
            }
            TcpIp_SocketTable[idx].platformSocket = TCPIP_PLATFORM_INVALID_SOCKET;
            TcpIp_SocketTable[idx].state          = TCPIP_SOCKET_STATE_UNUSED;
        }
    }

#ifdef WINDOWS
    if (TcpIp_WinsockInitialized == TRUE)
    {
        WSACleanup();
        TcpIp_WinsockInitialized = FALSE;
    }
#endif

#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_ETHIF)
    EthIf_SetRxIndicationCallback(NULL);
#endif

    TcpIp_ModuleState = TCPIP_STATE_OFFLINE;
    EthSM_TcpIpModeIndication(0U, TCPIP_STATE_OFFLINE);
}

Std_ReturnType TcpIp_GetSocketId(
    TcpIp_DomainType Domain,
    TcpIp_ProtocolType Protocol,
    TcpIp_SocketIdType* SocketIdPtr
)
{
    uint16 idx;
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    int sockType;
    int sockProto;
#endif
    PlatformSocketType newSock;

#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_GET_SOCKET, TCPIP_E_NOTINIT);
        return E_NOT_OK;
    }
    if (SocketIdPtr == NULL)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_GET_SOCKET, TCPIP_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if ((Domain != TCPIP_AF_INET) && (Domain != TCPIP_AF_INET6))
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_GET_SOCKET, TCPIP_E_INV_ARG);
        return E_NOT_OK;
    }
    if ((Protocol != TCPIP_IPPROTO_TCP) && (Protocol != TCPIP_IPPROTO_UDP))
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_GET_SOCKET, TCPIP_E_INV_ARG);
        return E_NOT_OK;
    }
#endif

    /* Find free slot */
    for (idx = 0U; idx < TCPIP_MAX_SOCKETS; idx++)
    {
        if (TcpIp_SocketTable[idx].state == TCPIP_SOCKET_STATE_UNUSED)
        {
            break;
        }
    }

    if (idx >= TCPIP_MAX_SOCKETS)
    {
#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_GET_SOCKET, TCPIP_E_NORESOURCE);
#endif
        return E_NOT_OK;
    }

    /* Map protocol to platform socket type */
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    if (Protocol == TCPIP_IPPROTO_TCP)
    {
        sockType  = SOCK_STREAM;
        sockProto = IPPROTO_TCP;
    }
    else
    {
        sockType  = SOCK_DGRAM;
        sockProto = IPPROTO_UDP;
    }
#endif

    newSock = TCPIP_PLATFORM_INVALID_SOCKET;
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    newSock = socket(AF_INET, sockType, sockProto);
    if (newSock == TCPIP_PLATFORM_INVALID_SOCKET)
    {
        return E_NOT_OK;
    }
    /* CRITICAL: set every new socket non-blocking immediately. Otherwise
     * subsequent recv/recvfrom/accept calls in TcpIp_MainFunction block
     * indefinitely when no data/connection is pending — that hangs the OS
     * task and starves App_Tx of cycles. Connected/accepted sockets inherit
     * the non-blocking flag from the listening parent on Linux. */
    (void)TcpIp_SetNonBlocking(newSock);
#endif

    TcpIp_SocketTable[idx].platformSocket = newSock;
    TcpIp_SocketTable[idx].state          = TCPIP_SOCKET_STATE_ALLOCATED;
    TcpIp_SocketTable[idx].domain         = Domain;
    TcpIp_SocketTable[idx].protocol       = Protocol;
    TcpIp_SocketTable[idx].localPort      = 0U;
    (void)memset(&TcpIp_SocketTable[idx].remoteAddr, 0, sizeof(TcpIp_SockAddrType));

    *SocketIdPtr = (TcpIp_SocketIdType)idx;
    return E_OK;
}

Std_ReturnType TcpIp_Close(TcpIp_SocketIdType SocketId, boolean Abort)
{
    (void)Abort;

#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_CLOSE, TCPIP_E_NOTINIT);
        return E_NOT_OK;
    }
    if (SocketId >= TCPIP_MAX_SOCKETS)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_CLOSE, TCPIP_E_INV_SOCKETID);
        return E_NOT_OK;
    }
    if (TcpIp_SocketTable[SocketId].state == TCPIP_SOCKET_STATE_UNUSED)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_CLOSE, TCPIP_E_INV_SOCKETID);
        return E_NOT_OK;
    }
#endif

    if (Abort == TRUE)
    {
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
        /* Set SO_LINGER with timeout 0 for immediate RST */
        struct linger lingerOpt;
        lingerOpt.l_onoff  = 1;
        lingerOpt.l_linger = 0;
        (void)setsockopt(
            TcpIp_SocketTable[SocketId].platformSocket,
            SOL_SOCKET, SO_LINGER,
            (const char*)&lingerOpt, sizeof(lingerOpt)
        );
#endif
    }

    if (TcpIp_SocketTable[SocketId].platformSocket != TCPIP_PLATFORM_INVALID_SOCKET)
    {
        TcpIp_ClosePlatformSocket(TcpIp_SocketTable[SocketId].platformSocket);
    }
    TcpIp_SocketTable[SocketId].platformSocket = TCPIP_PLATFORM_INVALID_SOCKET;
    TcpIp_SocketTable[SocketId].state          = TCPIP_SOCKET_STATE_UNUSED;
    TcpIp_SocketTable[SocketId].localPort      = 0U;
    (void)memset(&TcpIp_SocketTable[SocketId].remoteAddr, 0, sizeof(TcpIp_SockAddrType));

    return E_OK;
}

Std_ReturnType TcpIp_Bind(
    TcpIp_SocketIdType SocketId,
    TcpIp_LocalAddrIdType LocalAddrId,
    uint16* PortPtr
)
{
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    struct sockaddr_in bindAddr;
    int optVal = 1;
#endif

#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_BIND, TCPIP_E_NOTINIT);
        return E_NOT_OK;
    }
    if (SocketId >= TCPIP_MAX_SOCKETS)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_BIND, TCPIP_E_INV_SOCKETID);
        return E_NOT_OK;
    }
    if (TcpIp_SocketTable[SocketId].state == TCPIP_SOCKET_STATE_UNUSED)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_BIND, TCPIP_E_INV_SOCKETID);
        return E_NOT_OK;
    }
    if (PortPtr == NULL)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_BIND, TCPIP_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (LocalAddrId >= TCPIP_MAX_LOCAL_ADDR)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_BIND, TCPIP_E_INV_ARG);
        return E_NOT_OK;
    }
#endif

    /* Set SO_REUSEADDR */
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    (void)setsockopt(
        TcpIp_SocketTable[SocketId].platformSocket,
        SOL_SOCKET, SO_REUSEADDR,
        (const char*)&optVal, sizeof(optVal)
    );

    /* Build bind address from local address table */
    (void)memset(&bindAddr, 0, sizeof(bindAddr));
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port   = htons(*PortPtr);

    if (TcpIp_LocalAddrTable[LocalAddrId].assigned == TRUE)
    {
        (void)memcpy(&bindAddr.sin_addr.s_addr, TcpIp_LocalAddrTable[LocalAddrId].ipAddr.addr, 4U);
    }
    else
    {
        bindAddr.sin_addr.s_addr = INADDR_ANY;
    }

    /* cppcheck-suppress misra-c2012-17.3 */
    if (bind(TcpIp_SocketTable[SocketId].platformSocket,
             (struct sockaddr*)&bindAddr, sizeof(bindAddr)) == TCPIP_PLATFORM_SOCKET_ERROR)
    {
        return E_NOT_OK;
    }

    /* If port was 0 (auto-assign), retrieve the assigned port */
    if (*PortPtr == 0U)
    {
        struct sockaddr_in assignedAddr;
#ifdef WINDOWS
        int addrLen = (int)sizeof(assignedAddr);
#else
        socklen_t addrLen = sizeof(assignedAddr);
#endif
        /* cppcheck-suppress misra-c2012-17.3 */
        if (getsockname(TcpIp_SocketTable[SocketId].platformSocket,
                        (struct sockaddr*)&assignedAddr, &addrLen) == 0)
        {
            *PortPtr = ntohs(assignedAddr.sin_port);
        }
    }
#endif

    TcpIp_SocketTable[SocketId].localAddrId = LocalAddrId;
    TcpIp_SocketTable[SocketId].localPort   = *PortPtr;
    TcpIp_SocketTable[SocketId].state       = TCPIP_SOCKET_STATE_BOUND;

    /* §4A: ensure non-blocking so cyclic TcpIp_MainFunction recv*() never hangs
     * (defensive — recvfrom/recv now also use MSG_DONTWAIT, but belt+suspenders). */
    (void)TcpIp_SetNonBlocking(TcpIp_SocketTable[SocketId].platformSocket);

    return E_OK;
}

Std_ReturnType TcpIp_TcpConnect(
    TcpIp_SocketIdType SocketId,
    const TcpIp_SockAddrType* RemoteAddrPtr
)
{
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    struct sockaddr_in remoteAddr;
#endif

#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_CONNECT, TCPIP_E_NOTINIT);
        return E_NOT_OK;
    }
    if (SocketId >= TCPIP_MAX_SOCKETS)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_CONNECT, TCPIP_E_INV_SOCKETID);
        return E_NOT_OK;
    }
    if (TcpIp_SocketTable[SocketId].state == TCPIP_SOCKET_STATE_UNUSED)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_CONNECT, TCPIP_E_INV_SOCKETID);
        return E_NOT_OK;
    }
    if (RemoteAddrPtr == NULL)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_CONNECT, TCPIP_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (TcpIp_SocketTable[SocketId].protocol != TCPIP_IPPROTO_TCP)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_CONNECT, TCPIP_E_INV_ARG);
        return E_NOT_OK;
    }
#endif

#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    TcpIp_SockAddrToSockAddrIn(RemoteAddrPtr, &remoteAddr);
    {
        int fd = (int)TcpIp_SocketTable[SocketId].platformSocket;
        /* cppcheck-suppress misra-c2012-17.3 */
        int rc = connect(fd, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));
        if (rc == TCPIP_PLATFORM_SOCKET_ERROR)
        {
#ifndef WINDOWS
            /* §4A made all sockets non-blocking at GetSocketId time, so connect()
             * for a reachable peer returns -1/EINPROGRESS — that is the *expected*
             * outcome of a non-blocking TCP connect, not a failure. Wait briefly
             * (≈ 800 ms — Pi-to-Pi wlan0 RTT was measured at ~135 ms p50 / ~250 ms
             * p99 under light load, so 800 ms covers a 3-way handshake even on a
             * congested link) for the handshake to complete, then read SO_ERROR
             * to confirm success. Hard errors (ECONNREFUSED, EHOSTUNREACH, …)
             * propagate immediately without entering the wait branch. */
            if (errno == EINPROGRESS)
            {
                fd_set wfds;
                struct timeval tv;
                int sockErr = 0;
                socklen_t errLen = (socklen_t)sizeof(sockErr);
                int sel;
                FD_ZERO(&wfds);
                FD_SET(fd, &wfds);
                tv.tv_sec  = 0;
                tv.tv_usec = 800000; /* 800 ms */
                /* cppcheck-suppress misra-c2012-17.3 */
                sel = select(fd + 1, NULL, &wfds, NULL, &tv);
                if (sel <= 0)
                {
                    return E_NOT_OK; /* timeout or select() error */
                }
                /* cppcheck-suppress misra-c2012-17.3 */
                if ((getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockErr, &errLen) < 0)
                    || (sockErr != 0))
                {
                    return E_NOT_OK; /* connect refused / unreachable */
                }
            }
            else
#endif
            {
                return E_NOT_OK;
            }
        }
    }
#endif

    TcpIp_SocketTable[SocketId].remoteAddr = *RemoteAddrPtr;
    TcpIp_SocketTable[SocketId].state      = TCPIP_SOCKET_STATE_CONNECTED;
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    TcpIp_SetTcpTimers(TcpIp_SocketTable[SocketId].platformSocket);
#endif

    return E_OK;
}

Std_ReturnType TcpIp_TcpListen(TcpIp_SocketIdType SocketId, uint16 MaxChannels)
{
#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_LISTEN, TCPIP_E_NOTINIT);
        return E_NOT_OK;
    }
    if (SocketId >= TCPIP_MAX_SOCKETS)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_LISTEN, TCPIP_E_INV_SOCKETID);
        return E_NOT_OK;
    }
    if (TcpIp_SocketTable[SocketId].state == TCPIP_SOCKET_STATE_UNUSED)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_LISTEN, TCPIP_E_INV_SOCKETID);
        return E_NOT_OK;
    }
    if (TcpIp_SocketTable[SocketId].protocol != TCPIP_IPPROTO_TCP)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_LISTEN, TCPIP_E_INV_ARG);
        return E_NOT_OK;
    }
#endif

#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    /* cppcheck-suppress misra-c2012-17.3 */
    if (listen(TcpIp_SocketTable[SocketId].platformSocket, (int)MaxChannels) == TCPIP_PLATFORM_SOCKET_ERROR)
    {
        return E_NOT_OK;
    }

    /* Set non-blocking so MainFunction can poll */
    (void)TcpIp_SetNonBlocking(TcpIp_SocketTable[SocketId].platformSocket);
#else
    (void)MaxChannels;
#endif

    TcpIp_SocketTable[SocketId].state = TCPIP_SOCKET_STATE_LISTENING;

    return E_OK;
}

static boolean TcpIp_IsTcpSocketInUse(TcpIp_SocketIdType SocketId)
{
    return ((TcpIp_ModuleState == TCPIP_STATE_ONLINE) && (SocketId < TCPIP_MAX_SOCKETS) &&
            (TcpIp_SocketTable[SocketId].state != TCPIP_SOCKET_STATE_UNUSED) &&
            (TcpIp_SocketTable[SocketId].protocol == TCPIP_IPPROTO_TCP)) ? TRUE : FALSE;
}

Std_ReturnType TcpIp_ChangeParameter(
    TcpIp_SocketIdType SocketId,
    TcpIp_ParamIdType ParameterId,
    const uint8* ParameterValue
)
{
    if ((TcpIp_IsTcpSocketInUse(SocketId) == FALSE) || (ParameterValue == NULL) ||
        (ParameterId != TCPIP_PARAMID_TCP_NAGLE) || (*ParameterValue > 0x01U))
    {
        return E_NOT_OK;
    }

#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    {
        /* Nagle's algorithm off is the socket option TCP_NODELAY on, and the reverse */
        const int noDelay = (*ParameterValue == 0x00U) ? 1 : 0;

        if (setsockopt(TcpIp_SocketTable[SocketId].platformSocket, IPPROTO_TCP, TCP_NODELAY,
                       (const char*)&noDelay, sizeof(noDelay)) != 0)
        {
            return E_NOT_OK;
        }
    }
    return E_OK;
#else
    return E_NOT_OK;    /* the EthIf back end has no such option */
#endif
}

Std_ReturnType TcpIp_GetTcpNoDelay(TcpIp_SocketIdType SocketId, uint8* NoDelayPtr)
{
    if ((TcpIp_IsTcpSocketInUse(SocketId) == FALSE) || (NoDelayPtr == NULL))
    {
        return E_NOT_OK;
    }

#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    {
        int noDelay = 0;
#ifdef WINDOWS
        int optLen = (int)sizeof(noDelay);
#else
        socklen_t optLen = (socklen_t)sizeof(noDelay);
#endif

        if (getsockopt(TcpIp_SocketTable[SocketId].platformSocket, IPPROTO_TCP, TCP_NODELAY,
                       (char*)&noDelay, &optLen) != 0)
        {
            return E_NOT_OK;
        }
        *NoDelayPtr = (noDelay != 0) ? 1U : 0U;
    }
    return E_OK;
#else
    return E_NOT_OK;
#endif
}

Std_ReturnType TcpIp_UdpTransmit(
    TcpIp_SocketIdType SocketId,
    const uint8* DataPtr,
    const TcpIp_SockAddrType* RemoteAddrPtr,
    uint16 TotalLength
)
{
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    struct sockaddr_in destAddr;
    int sendResult;
#endif
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_ETHIF)
    Eth_BufIdxType BufIdx;
    uint8* BufPtr;
    uint16 RequestedLength;
    Eth_FrameType FrameType;
#endif

#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_UDP_TRANSMIT, TCPIP_E_NOTINIT);
        return E_NOT_OK;
    }
    if (SocketId >= TCPIP_MAX_SOCKETS)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_UDP_TRANSMIT, TCPIP_E_INV_SOCKETID);
        return E_NOT_OK;
    }
    if (TcpIp_SocketTable[SocketId].state == TCPIP_SOCKET_STATE_UNUSED)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_UDP_TRANSMIT, TCPIP_E_INV_SOCKETID);
        return E_NOT_OK;
    }
    if (DataPtr == NULL)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_UDP_TRANSMIT, TCPIP_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (RemoteAddrPtr == NULL)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_UDP_TRANSMIT, TCPIP_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (TcpIp_SocketTable[SocketId].protocol != TCPIP_IPPROTO_UDP)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_UDP_TRANSMIT, TCPIP_E_INV_ARG);
        return E_NOT_OK;
    }
#endif

    TcpIp_SocketTable[SocketId].remoteAddr = *RemoteAddrPtr;
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_ETHIF)
    RequestedLength = TotalLength;
    FrameType = (Eth_FrameType)(TCPIP_ETHIF_FRAME_TYPE_BASE + (Eth_FrameType)SocketId);
    if (EthIf_ProvideTxBuffer(TCPIP_ETHIF_CTRL_IDX,
                              FrameType,
                              0U,
                              &BufIdx,
                              &BufPtr,
                              &RequestedLength) != BUFREQ_OK)
    {
        return E_NOT_OK;
    }
    if ((BufPtr == NULL) || (RequestedLength < TotalLength))
    {
        return E_NOT_OK;
    }
    (void)memcpy(BufPtr, DataPtr, TotalLength);
    if (EthIf_Transmit(TCPIP_ETHIF_CTRL_IDX, BufIdx, FrameType, FALSE, TotalLength, NULL) != E_OK)
    {
        return E_NOT_OK;
    }
#else
    TcpIp_SockAddrToSockAddrIn(RemoteAddrPtr, &destAddr);
    sendResult = sendto(
        TcpIp_SocketTable[SocketId].platformSocket,
        (const char*)DataPtr,
        (int)TotalLength,
        0,
        (struct sockaddr*)&destAddr,
        sizeof(destAddr)
    );

    if (sendResult == TCPIP_PLATFORM_SOCKET_ERROR)
    {
        return E_NOT_OK;
    }
#endif

    return E_OK;
}

Std_ReturnType TcpIp_TcpTransmit(
    TcpIp_SocketIdType SocketId,
    const uint8* DataPtr,
    uint32 AvailableLength,
    boolean ForceRetrieve
)
{
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_SOCKETS)
    int sendResult;
#endif
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_ETHIF)
    Eth_BufIdxType BufIdx;
    uint8* BufPtr;
    uint16 RequestedLength;
    Eth_FrameType FrameType;
#endif

    /* ETHDRV_SEND probe (TCP/IP send path — repurposed since legacy EthDrv_Send
     * is not used by SoAd's TCP backend). Captures kernel send() syscall
     * latency once peer Rx is up and connect() succeeds. */
    PERF_PROBE_BEGIN(tcp_tx);

    (void)ForceRetrieve;

#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_TRANSMIT, TCPIP_E_NOTINIT);
        return E_NOT_OK;
    }
    if (SocketId >= TCPIP_MAX_SOCKETS)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_TRANSMIT, TCPIP_E_INV_SOCKETID);
        return E_NOT_OK;
    }
    if (TcpIp_SocketTable[SocketId].state == TCPIP_SOCKET_STATE_UNUSED)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_TRANSMIT, TCPIP_E_INV_SOCKETID);
        return E_NOT_OK;
    }
    if (DataPtr == NULL)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_TRANSMIT, TCPIP_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (TcpIp_SocketTable[SocketId].protocol != TCPIP_IPPROTO_TCP)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_TRANSMIT, TCPIP_E_INV_ARG);
        return E_NOT_OK;
    }
    if (TcpIp_SocketTable[SocketId].state != TCPIP_SOCKET_STATE_CONNECTED)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_TCP_TRANSMIT, TCPIP_E_INV_ARG);
        return E_NOT_OK;
    }
#endif

#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_ETHIF)
    if (AvailableLength > 0xFFFFUL)
    {
        return E_NOT_OK;
    }
    RequestedLength = (uint16)AvailableLength;
    FrameType = (Eth_FrameType)(TCPIP_ETHIF_FRAME_TYPE_BASE + (Eth_FrameType)SocketId);
    if (EthIf_ProvideTxBuffer(TCPIP_ETHIF_CTRL_IDX,
                              FrameType,
                              0U,
                              &BufIdx,
                              &BufPtr,
                              &RequestedLength) != BUFREQ_OK)
    {
        return E_NOT_OK;
    }
    if ((BufPtr == NULL) || (RequestedLength < (uint16)AvailableLength))
    {
        return E_NOT_OK;
    }
    (void)memcpy(BufPtr, DataPtr, (uint16)AvailableLength);
    if (EthIf_Transmit(TCPIP_ETHIF_CTRL_IDX,
                       BufIdx,
                       FrameType,
                       FALSE,
                       (uint16)AvailableLength,
                       NULL) != E_OK)
    {
        return E_NOT_OK;
    }
#else
    {
        uint32 totalSent = 0U;
        const uint8* p   = DataPtr;
#if defined(MSG_NOSIGNAL)
        const int sendFlags = MSG_NOSIGNAL;
#else
        const int sendFlags = 0;
#endif
        (void)sendResult;
        while (totalSent < AvailableLength)
        {
            int n = send(
                TcpIp_SocketTable[SocketId].platformSocket,
                (const char*)(p + totalSent),
                (int)(AvailableLength - totalSent),
                sendFlags
            );
            if (n > 0)
            {
                totalSent += (uint32)n;
                continue;
            }
            if (n == 0)
            {
                continue;
            }
#ifdef WINDOWS
            return E_NOT_OK;
#else
            if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))
            {
                continue;
            }
            return E_NOT_OK;
#endif
        }
    }
#endif

    PERF_PROBE_END(tcp_tx, (uint16_t)SocketId, SECOC_PERF_STAGE_ETHDRV_SEND);
    return E_OK;
}

void TcpIp_RxIndication(
    TcpIp_SocketIdType SocketId,
    const TcpIp_SockAddrType* RemoteAddrPtr,
    const uint8* BufPtr,
    uint16 Length
)
{
#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_RX_INDICATION, TCPIP_E_NOTINIT);
        return;
    }
    if (SocketId >= TCPIP_MAX_SOCKETS)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_RX_INDICATION, TCPIP_E_INV_SOCKETID);
        return;
    }
    if ((RemoteAddrPtr == NULL) || (BufPtr == NULL))
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_RX_INDICATION, TCPIP_E_PARAM_POINTER);
        return;
    }
#endif

    SoAd_RxIndication(SocketId, RemoteAddrPtr, BufPtr, Length);
}

void TcpIp_MainFunction(void)
{
#if (TCPIP_PAYLOAD_BACKEND == TCPIP_PAYLOAD_BACKEND_ETHIF)
#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        return;
    }
#endif

    EthIf_MainFunctionRx();
    EthIf_MainFunctionTx();
    return;
#else
    uint16 idx;
    int recvLen;

#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        return;
    }
#endif

    for (idx = 0U; idx < TCPIP_MAX_SOCKETS; idx++)
    {
        if (TcpIp_SocketTable[idx].state == TCPIP_SOCKET_STATE_UNUSED)
        {
            continue;
        }

        /* Handle listening TCP sockets - accept new connections */
        if (TcpIp_SocketTable[idx].state == TCPIP_SOCKET_STATE_LISTENING)
        {
            struct sockaddr_in clientAddr;
#ifdef WINDOWS
            int addrLen = (int)sizeof(clientAddr);
#else
            socklen_t addrLen = sizeof(clientAddr);
#endif
            PlatformSocketType clientSock;
            uint16 freeSlot;

            clientSock = accept(
                TcpIp_SocketTable[idx].platformSocket,
                (struct sockaddr*)&clientAddr, &addrLen
            );

            if (clientSock != TCPIP_PLATFORM_INVALID_SOCKET)
            {
                /* Find a free slot for the accepted connection */
                for (freeSlot = 0U; freeSlot < TCPIP_MAX_SOCKETS; freeSlot++)
                {
                    if (TcpIp_SocketTable[freeSlot].state == TCPIP_SOCKET_STATE_UNUSED)
                    {
                        break;
                    }
                }

                if (freeSlot < TCPIP_MAX_SOCKETS)
                {
                    TcpIp_SocketTable[freeSlot].platformSocket = clientSock;
                    TcpIp_SocketTable[freeSlot].state          = TCPIP_SOCKET_STATE_CONNECTED;
                    TcpIp_SocketTable[freeSlot].domain         = TcpIp_SocketTable[idx].domain;
                    TcpIp_SocketTable[freeSlot].protocol       = TCPIP_IPPROTO_TCP;
                    TcpIp_SocketTable[freeSlot].localAddrId    = TcpIp_SocketTable[idx].localAddrId;
                    TcpIp_SocketTable[freeSlot].localPort      = TcpIp_SocketTable[idx].localPort;
                    TcpIp_SockAddrInToSockAddr(&clientAddr, &TcpIp_SocketTable[freeSlot].remoteAddr);

                    /* Set accepted socket non-blocking for polling */
                    (void)TcpIp_SetNonBlocking(clientSock);
                    TcpIp_SetTcpTimers(clientSock);

                    /* [SWS_SoAd_00099] the upper layer assigns the connection or refuses it */
                    if (SoAd_TcpAccepted((TcpIp_SocketIdType)idx, (TcpIp_SocketIdType)freeSlot,
                                         &TcpIp_SocketTable[freeSlot].remoteAddr) != E_OK)
                    {
                        TcpIp_ClosePlatformSocket(clientSock);
                        TcpIp_SocketTable[freeSlot].platformSocket = TCPIP_PLATFORM_INVALID_SOCKET;
                        TcpIp_SocketTable[freeSlot].state          = TCPIP_SOCKET_STATE_UNUSED;
                    }
                }
                else
                {
                    /* No free slot, reject connection */
                    TcpIp_ClosePlatformSocket(clientSock);
                }
            }
        }

        /* Poll connected TCP sockets and bound UDP sockets for incoming data */
        if ((TcpIp_SocketTable[idx].state == TCPIP_SOCKET_STATE_CONNECTED) ||
            ((TcpIp_SocketTable[idx].state == TCPIP_SOCKET_STATE_BOUND) &&
             (TcpIp_SocketTable[idx].protocol == TCPIP_IPPROTO_UDP)))
        {
            if (TcpIp_SocketTable[idx].protocol == TCPIP_IPPROTO_UDP)
            {
                struct sockaddr_in srcAddr;
#ifdef WINDOWS
                int addrLen = (int)sizeof(srcAddr);
#else
                socklen_t addrLen = sizeof(srcAddr);
#endif
                recvLen = recvfrom(
                    TcpIp_SocketTable[idx].platformSocket,
                    (char*)TcpIp_RxBuffer,
                    (int)TCPIP_RX_BUFFER_SIZE,
                    MSG_DONTWAIT,
                    (struct sockaddr*)&srcAddr,
                    &addrLen
                );

                if (recvLen > 0)
                {
                    TcpIp_SockAddrType remoteSockAddr;
                    TcpIp_SockAddrInToSockAddr(&srcAddr, &remoteSockAddr);
                    TcpIp_RxIndication((TcpIp_SocketIdType)idx, &remoteSockAddr, TcpIp_RxBuffer, (uint16)recvLen);
                }
            }
            else
            {
                recvLen = recv(
                    TcpIp_SocketTable[idx].platformSocket,
                    (char*)TcpIp_RxBuffer,
                    (int)TCPIP_RX_BUFFER_SIZE,
                    MSG_DONTWAIT
                );

                if (recvLen > 0)
                {
                    TcpIp_RxIndication(
                        (TcpIp_SocketIdType)idx,
                        &TcpIp_SocketTable[idx].remoteAddr,
                        TcpIp_RxBuffer,
                        (uint16)recvLen
                    );
                }
                else if ((recvLen == 0)
#ifndef WINDOWS
                         || ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINTR))
#endif
                        )
                {
                    /* Closed by the peer (0), or lost (reset, keep-alive or send timeout): the socket
                     * is released and the upper layer is told, so that it ends what was in progress
                     * on the connection and can accept or open a new one [SWS_SoAd_00646]. */
                    TcpIp_ClosePlatformSocket(TcpIp_SocketTable[idx].platformSocket);
                    TcpIp_SocketTable[idx].platformSocket = TCPIP_PLATFORM_INVALID_SOCKET;
                    TcpIp_SocketTable[idx].state          = TCPIP_SOCKET_STATE_UNUSED;
                    SoAd_TcpIpEvent((TcpIp_SocketIdType)idx, (recvLen == 0) ? TCPIP_TCP_CLOSED : TCPIP_TCP_RESET);
                }
                else
                {
                    /* nothing to read */
                }
            }
        }
    }
#endif
}

void TcpIp_GetVersionInfo(Std_VersionInfoType* VersionInfoPtr)
{
#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (VersionInfoPtr == NULL)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_GET_VERSION_INFO, TCPIP_E_PARAM_POINTER);
        return;
    }
#endif

    VersionInfoPtr->vendorID         = TCPIP_VENDOR_ID;
    VersionInfoPtr->moduleID         = TCPIP_MODULE_ID;
    VersionInfoPtr->sw_major_version = TCPIP_SW_MAJOR_VERSION;
    VersionInfoPtr->sw_minor_version = TCPIP_SW_MINOR_VERSION;
    VersionInfoPtr->sw_patch_version = TCPIP_SW_PATCH_VERSION;
}

Std_ReturnType TcpIp_RequestIpAddrAssignment(
    TcpIp_LocalAddrIdType LocalAddrId,
    TcpIp_IpAddrAssignmentType Type,
    const TcpIp_SockAddrType* LocalIpAddrPtr
)
{
#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_REQUEST_IP_ADDR, TCPIP_E_NOTINIT);
        return E_NOT_OK;
    }
    if (LocalAddrId >= TCPIP_MAX_LOCAL_ADDR)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_REQUEST_IP_ADDR, TCPIP_E_INV_ARG);
        return E_NOT_OK;
    }
#endif

    TcpIp_LocalAddrTable[LocalAddrId].assignmentType = Type;

    if ((Type == TCPIP_IPADDR_ASSIGNMENT_STATIC) && (LocalIpAddrPtr != NULL))
    {
        TcpIp_LocalAddrTable[LocalAddrId].ipAddr = *LocalIpAddrPtr;
    }

    TcpIp_LocalAddrTable[LocalAddrId].assigned = TRUE;
    EthSM_TcpIpModeIndication(0U, TCPIP_STATE_ONLINE);

    return E_OK;
}

Std_ReturnType TcpIp_GetIpAddr(
    TcpIp_LocalAddrIdType LocalAddrId,
    TcpIp_SockAddrType* IpAddrPtr,
    uint8* NetmaskPtr,
    TcpIp_SockAddrType* DefaultRouterPtr
)
{
#if (TCPIP_DEV_ERROR_DETECT == STD_ON)
    if (TcpIp_ModuleState != TCPIP_STATE_ONLINE)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_GET_IP_ADDR, TCPIP_E_NOTINIT);
        return E_NOT_OK;
    }
    if (LocalAddrId >= TCPIP_MAX_LOCAL_ADDR)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_GET_IP_ADDR, TCPIP_E_INV_ARG);
        return E_NOT_OK;
    }
    if (IpAddrPtr == NULL)
    {
        (void)Det_ReportError(TCPIP_MODULE_ID, 0U, TCPIP_SID_GET_IP_ADDR, TCPIP_E_PARAM_POINTER);
        return E_NOT_OK;
    }
#endif

    if (TcpIp_LocalAddrTable[LocalAddrId].assigned == FALSE)
    {
        return E_NOT_OK;
    }

    *IpAddrPtr = TcpIp_LocalAddrTable[LocalAddrId].ipAddr;

    if (NetmaskPtr != NULL)
    {
        *NetmaskPtr = TcpIp_LocalAddrTable[LocalAddrId].netmask;
    }

    if (DefaultRouterPtr != NULL)
    {
        *DefaultRouterPtr = TcpIp_LocalAddrTable[LocalAddrId].defaultRouter;
    }

    return E_OK;
}
