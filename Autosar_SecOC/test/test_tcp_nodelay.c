/********************************************************************************************************/
/*  File:   test/test_tcp_nodelay.c                                                                       */
/*  Brief:  SoAd's end of a real TCP connection over 127.0.0.1: the socket option TCP_NODELAY, read back  */
/*          from the connected socket, follows SoAdSocketTcpNoDelay of the socket connection              */
/*          ([SWS_SoAd_00689] item 3, [ECUC_SoAd_00023]).                                                 */
/*                                                                                                        */
/*          TcpIp and SoAd are the production sources on real sockets. One process holds only SoAd's end  */
/*          of a connection; the other end is a plain socket of this test. So the role of the build       */
/*          decides which path runs: a receiver-role build has SoAd listen and accept (the accepted       */
/*          socket is checked), any other build has SoAd connect (the connecting socket is checked). Both */
/*          ends of one connection are in the two logs of a loopback or two-node run of the gateways.     */
/*                                                                                                        */
/*          TcpIp_ChangeParameter is wrapped at link time; the real function runs behind the wrapper,     */
/*          which records what SoAd asked for. A read-back of 0 alone would show nothing (it is also the  */
/*          kernel's default), so the FALSE case also checks that SoAd asked for the value 0x01, and the  */
/*          case with the parameter absent that SoAd asked for nothing.                                   */
/*                                                                                                        */
/*  Exit code 0 and "PASS" on the last line when every check holds.                                       */
/********************************************************************************************************/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "Std_Types.h"
#include "SecOC_Cfg.h"
#include "SoAd.h"
#include "SoAd/SoAd_PduIds.h"
#include "TcpIp.h"

/* ports the gateway does not use (its own is SECOC_CFG_PORT, 50002, and the relay's 50003) */
#define TEST_PORT_NODELAY      ((uint16)50131U)
#define TEST_PORT_NAGLE        ((uint16)50132U)
#define TEST_PORT_ABSENT       ((uint16)50133U)

static uint32 Failed = 0U;
#define CHECK(cond, ...) do { if (!(cond)) { Failed++; (void)printf("  FAIL: "); (void)printf(__VA_ARGS__); (void)printf("\n"); } } while (0)

/* what SoAd asks TcpIp for */
Std_ReturnType __real_TcpIp_ChangeParameter(TcpIp_SocketIdType SocketId, TcpIp_ParamIdType ParameterId, const uint8* ParameterValue);
Std_ReturnType __wrap_TcpIp_ChangeParameter(TcpIp_SocketIdType SocketId, TcpIp_ParamIdType ParameterId, const uint8* ParameterValue);

static uint32 ParamCalls = 0U;
static TcpIp_SocketIdType LastSocket = TCPIP_SOCKET_ID_INVALID;
static TcpIp_ParamIdType LastId = 0U;
static uint8 LastValue = 0xFFU;

Std_ReturnType __wrap_TcpIp_ChangeParameter(TcpIp_SocketIdType SocketId, TcpIp_ParamIdType ParameterId, const uint8* ParameterValue)
{
    ParamCalls++;
    LastSocket = SocketId;
    LastId = ParameterId;
    LastValue = (ParameterValue != NULL) ? *ParameterValue : 0xFFU;
    return __real_TcpIp_ChangeParameter(SocketId, ParameterId, ParameterValue);
}

static void Test_LoopbackAddr(struct sockaddr_in* Addr, uint16 Port)
{
    (void)memset(Addr, 0, sizeof(*Addr));
    Addr->sin_family = AF_INET;
    Addr->sin_port = htons(Port);
    Addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

/* One connection of a socket connection configured with SoAdSocketTcpNoDelay = NoDelay */
static void Test_Connection(SoAd_TcpNoDelayType NoDelay, uint16 Port)
{
    const uint32 wantCalls = (NoDelay == SOAD_TCP_NODELAY_ABSENT) ? 0U : 1U;
    const uint8 wantValue = (NoDelay == SOAD_TCP_NODELAY_TRUE) ? 0x00U : 0x01U;
    const uint8 wantReadBack = (NoDelay == SOAD_TCP_NODELAY_TRUE) ? 1U : 0U;
    static const SoAd_PduRouteConfigType route[1] =
    {
        { (PduIdType)SECOC_PDUID_SIG(0U), SOAD_PDU_ROUTE_TP, (SoAd_RoutingGroupIdType)0U, SOAD_HEADERID_SIG(0U),
          0U, SOAD_UPPER_LAYER_PDUR, 0U, 0U, FALSE }
    };
    static SoAd_SoConConfigType soCon;      /* SoAd keeps the pointer */
    SoAd_ConfigType config;
    struct sockaddr_in addr;
    const uint8 nagleOn = 0x01U;
    const uint8 nagleOff = 0x00U;
    const uint8 wrongValue = 0x02U;
    uint32 connections = 0U;
    uint8 readBack = 0xFFU;
    int peerFd = -1;
#if (SECOC_ROLE_RECEIVER == TRUE)
    uint32 i;
#else
    int one = 1;
#endif

    (void)memset(&soCon, 0, sizeof(soCon));
    soCon.SoAdTxPduId = (PduIdType)SECOC_PDUID_SIG(0U);
    soCon.SoAdProtocol = TCPIP_IPPROTO_TCP;
    soCon.SoAdLocalAddrId = 0U;
    soCon.SoAdRemoteAddr.domain = TCPIP_AF_INET;
    soCon.SoAdRemoteAddr.addr[0] = 127U;
    soCon.SoAdRemoteAddr.addr[3] = 1U;
    soCon.SoAdRemoteAddr.port = Port;
    soCon.SoAdInitialMode = SOAD_SOCON_ONLINE;
    soCon.SoAdSocketTcpNoDelay = NoDelay;
#if (SECOC_ROLE_RECEIVER == TRUE)
    soCon.SoAdLocalPort = Port;             /* SoAd listens here */
#endif

    (void)memset(&config, 0, sizeof(config));
    config.SoAdPduRouteConfigPtr = route;
    config.SoAdPduRouteConfigCount = 1U;
    config.SoAdSoConConfigPtr = &soCon;
    config.SoAdSoConConfigCount = 1U;

    ParamCalls = 0U;
    LastSocket = TCPIP_SOCKET_ID_INVALID;
    TcpIp_Init(NULL);
    Test_LoopbackAddr(&addr, Port);

#if (SECOC_ROLE_RECEIVER == TRUE)
    /* SoAd listens; the peer is a plain socket; TcpIp accepts in its main function and asks SoAd */
    SoAd_Init(&config);
    CHECK(ParamCalls == 0U, "%u parameter request(s) for the listening socket, expected none", (unsigned)ParamCalls);
    peerFd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK((peerFd >= 0) && (connect(peerFd, (struct sockaddr*)&addr, sizeof(addr)) == 0),
          "the peer could not connect to SoAd's listening port %u", (unsigned)Port);
    for (i = 0U; (i < 500U) && (SoAd_GetSoConTcpInfo(0U, &connections, &readBack) != E_OK); i++)
    {
        TcpIp_MainFunction();
        (void)usleep(1000U);
    }
#else
    /* the peer listens (the kernel completes the connection without an accept); SoAd connects in SoAd_Init */
    peerFd = socket(AF_INET, SOCK_STREAM, 0);
    (void)setsockopt(peerFd, SOL_SOCKET, SO_REUSEADDR, &one, (socklen_t)sizeof(one));
    CHECK((peerFd >= 0) && (bind(peerFd, (struct sockaddr*)&addr, sizeof(addr)) == 0) && (listen(peerFd, 1) == 0),
          "the peer could not listen on port %u", (unsigned)Port);
    SoAd_Init(&config);
#endif

    CHECK(SoAd_GetSoConTcpInfo(0U, &connections, &readBack) == E_OK, "SoAd has no TCP connection");
    CHECK(connections == 1U, "%u connection(s) counted, expected 1", (unsigned)connections);
    CHECK(readBack == wantReadBack, "TCP_NODELAY read back from SoAd's socket is %u, expected %u",
          (unsigned)readBack, (unsigned)wantReadBack);
    CHECK(ParamCalls == wantCalls, "SoAd made %u parameter request(s), expected %u", (unsigned)ParamCalls, (unsigned)wantCalls);
    if (wantCalls == 1U)
    {
        CHECK((LastId == TCPIP_PARAMID_TCP_NAGLE) && (LastValue == wantValue),
              "SoAd asked for (id 0x%02X, value 0x%02X), expected (TCPIP_PARAMID_TCP_NAGLE, 0x%02X)",
              (unsigned)LastId, (unsigned)LastValue, (unsigned)wantValue);
    }

    /* the service on that socket: either value is read back; what it does not implement is refused */
    if (LastSocket != TCPIP_SOCKET_ID_INVALID)
    {
        const TcpIp_SocketIdType sock = LastSocket;

        CHECK((TcpIp_ChangeParameter(sock, TCPIP_PARAMID_TCP_NAGLE, &nagleOn) == E_OK) &&
              (TcpIp_GetTcpNoDelay(sock, &readBack) == E_OK) && (readBack == 0U), "Nagle on is not read back as TCP_NODELAY 0");
        CHECK((TcpIp_ChangeParameter(sock, TCPIP_PARAMID_TCP_NAGLE, &nagleOff) == E_OK) &&
              (TcpIp_GetTcpNoDelay(sock, &readBack) == E_OK) && (readBack == 1U), "Nagle off is not read back as TCP_NODELAY 1");
        CHECK(TcpIp_ChangeParameter(sock, (TcpIp_ParamIdType)0x7FU, &nagleOff) == E_NOT_OK, "a parameter that is not implemented was accepted");
        CHECK(TcpIp_ChangeParameter(sock, TCPIP_PARAMID_TCP_NAGLE, &wrongValue) == E_NOT_OK, "the value 0x02 was accepted");
        CHECK(TcpIp_ChangeParameter(sock, TCPIP_PARAMID_TCP_NAGLE, NULL) == E_NOT_OK, "a null value pointer was accepted");
        CHECK(TcpIp_ChangeParameter((TcpIp_SocketIdType)0xFFF0U, TCPIP_PARAMID_TCP_NAGLE, &nagleOff) == E_NOT_OK,
              "a socket id outside the table was accepted");
        CHECK(TcpIp_GetTcpNoDelay((TcpIp_SocketIdType)0xFFF0U, &readBack) == E_NOT_OK, "a read-back of a socket outside the table was answered");
    }

    if (peerFd >= 0)
    {
        (void)close(peerFd);
    }
    TcpIp_Shutdown();                       /* closes SoAd's sockets; the next case starts from an empty table */
}

int main(void)
{
    (void)setvbuf(stdout, NULL, _IOLBF, 0);

#if (SECOC_ROLE_RECEIVER == TRUE)
    (void)printf("N1 receiver role: SoAd accepts; SoAdSocketTcpNoDelay TRUE, the accepted socket reads back TCP_NODELAY 1\n");
#else
    (void)printf("N1 connecting role: SoAd connects; SoAdSocketTcpNoDelay TRUE, the connecting socket reads back TCP_NODELAY 1\n");
#endif
    Test_Connection(SOAD_TCP_NODELAY_TRUE, TEST_PORT_NODELAY);

    (void)printf("N2 SoAdSocketTcpNoDelay FALSE: SoAd asks for Nagle on (0x01) and the socket reads back TCP_NODELAY 0\n");
    Test_Connection(SOAD_TCP_NODELAY_FALSE, TEST_PORT_NAGLE);

    (void)printf("N3 SoAdSocketTcpNoDelay absent: SoAd asks for nothing and the socket has the default of the stack (0)\n");
    Test_Connection(SOAD_TCP_NODELAY_ABSENT, TEST_PORT_ABSENT);

    (void)printf("%s: %u failed check(s)\n", (Failed == 0U) ? "PASS" : "FAIL", (unsigned)Failed);
    return (Failed == 0U) ? 0 : 1;
}
