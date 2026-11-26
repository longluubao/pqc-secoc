#ifndef INCLUDE_PQCHS_H_
#define INCLUDE_PQCHS_H_

/********************************************************************************************************/
/*  PqcHs: authenticated key establishment PQC-SecOC-HS-v1 between two pinned ML-DSA-65 identities.       */
/*                                                                                                        */
/*  Project-specific component (CDD) on the SoAd generic upper-layer TP interface (SoAd SWS 5.2); in a    */
/*  production stack this function belongs to a KeyM key handler. SIGMA-style sign-and-MAC on an         */
/*  ephemeral ML-KEM-768 key: three messages and an acknowledgement, A = initiator, B = responder.        */
/*                                                                                                        */
/*      M1 A->B  ver || ID_A || ek                         1217 bytes                                     */
/*      M2 B->A  ver || ID_B || ct || sig_B || mac_B       4462 bytes                                     */
/*      M3 A->B  ver || sig_A || mac_A                     3342 bytes                                     */
/*      M4 B->A  ver || mac_ack                              33 bytes                                     */
/*                                                                                                        */
/*  All cryptography goes through the Csm (signature jobs, custom service, MAC jobs, key elements); the   */
/*  transcript hashes (SHA-384 over public data) are computed here.                                       */
/********************************************************************************************************/

#include "Std_Types.h"
#include "Com/ComStack_Types.h"
#include "SoAd/SoAd.h"
#include "PqcHs/PqcHs_Cfg.h"

#define PQCHS_VERSION               ((uint8)0x01U)
#define PQCHS_LABEL                 "PQC-SecOC-HS-v1"
#define PQCHS_LABEL_BYTES           (15U)

#define PQCHS_ID_BYTES              (32U)
#define PQCHS_MAC_BYTES             (32U)
#define PQCHS_HASH_BYTES            (48U)
#define PQCHS_KEY_BYTES             (32U)
#define PQCHS_EK_BYTES              (1184U)
#define PQCHS_CT_BYTES              (1088U)
#define PQCHS_SIG_BYTES             (3309U)
#define PQCHS_SID_BYTES             (4U)

#define PQCHS_M1_BYTES              (1U + PQCHS_ID_BYTES + PQCHS_EK_BYTES)                                      /* 1217 */
#define PQCHS_M2_BYTES              (1U + PQCHS_ID_BYTES + PQCHS_CT_BYTES + PQCHS_SIG_BYTES + PQCHS_MAC_BYTES)  /* 4462 */
#define PQCHS_M3_BYTES              (1U + PQCHS_SIG_BYTES + PQCHS_MAC_BYTES)                                    /* 3342 */
#define PQCHS_M4_BYTES              (1U + PQCHS_MAC_BYTES)                                                      /*   33 */

/* the 8-byte SoAd PDU header of each message is counted in the byte totals of an attempt */
#define PQCHS_PDU_HEADER_BYTES      (8U)

typedef enum
{
    PQCHS_ROLE_INITIATOR = 0U,      /* A: sends M1 and M3 */
    PQCHS_ROLE_RESPONDER = 1U       /* B: sends M2 and M4 */
} PqcHs_RoleType;

/* Outcome of an attempt, or the reason a message was discarded (the result labels of handshake.csv, in
 * this order). STATE: the message matched no handshake state, or a local step failed (transmission,
 * a crypto service). */
typedef enum
{
    PQCHS_RESULT_OK = 0U,
    PQCHS_RESULT_BAD_VER,
    PQCHS_RESULT_BAD_LEN,
    PQCHS_RESULT_UNKNOWN_ID,
    PQCHS_RESULT_SIG_FAIL,
    PQCHS_RESULT_MAC_FAIL,
    PQCHS_RESULT_TIMEOUT,
    PQCHS_RESULT_STATE
} PqcHs_ResultType;

typedef struct
{
    uint64 KeygenNs;
    uint64 EncapsNs;
    uint64 DecapsNs;
    uint64 SignNs;
    uint64 VerifyNs;
    uint64 KdfNs;
    uint64 HashNs;              /* all transcript hashes */
    uint64 MacNs;               /* key-confirmation MAC generation and verification */
} PqcHs_StageTimesType;

/* One row of handshake.csv: an attempt that ended, or a message that was discarded without ending one
 * (then the times and bytes are those of that message). Times on CLOCK_MONOTONIC.
 * TotalNs, initiator: start of the ML-KEM key generation to keys installed (M3 handed to SoAd; M4 is
 * not included), or to the abort. Responder: M1 completely received to keys installed, or to the abort.
 * A discarded message: completely received to the decision. */
typedef struct
{
    uint32 Seq;                 /* row index of this peer's instance, from 0 */
    PqcHs_RoleType Role;
    PqcHs_ResultType Result;
    uint64 TotalNs;
    uint32 BytesTx;
    uint32 BytesRx;
    PqcHs_StageTimesType Times;
} PqcHs_AttemptInfoType;

/* One instance per pinned peer. */
typedef struct
{
    PqcHs_RoleType PqcHsRole;
    uint8 PqcHsPeer;                    /* Csm peer index: pinned public key, session key object */
    SoAd_SoConIdType PqcHsSoConId;
    PduIdType PqcHsTxPduId[2];          /* initiator: M1, M3; responder: M2, M4 */
    PduIdType PqcHsRxPduId[2];          /* initiator: M2, M4; responder: M1, M3 */
    uint32 PqcHsTxAuthKeyId;            /* K_auth of the PDUs this node sends (initiator: i2r) */
    uint32 PqcHsRxAuthKeyId;            /* K_auth of the PDUs this node receives (initiator: r2i) */
    uint32 PqcHsConfirmKeyId;           /* confirmation-key slot, referenced by no SecOC job */
    uint32 PqcHsConfirmGenerateJobId;
    uint32 PqcHsConfirmVerifyJobId;
    const uint16* PqcHsFreshnessIds;    /* session-bound freshness values, reset at installation */
    uint8 PqcHsNumFreshnessIds;
} PqcHs_InstanceConfigType;

typedef struct
{
    uint32 PqcHsTPendMs;
    uint32 PqcHsTMinMs;
    uint32 PqcHsTAMs;
    uint32 PqcHsTFlushMs;
} PqcHs_TimersType;

typedef struct
{
    const PqcHs_InstanceConfigType* PqcHsInstances;
    uint8 PqcHsNumInstances;
    PqcHs_TimersType PqcHsTimers;
} PqcHs_ConfigType;

extern const PqcHs_ConfigType PqcHs_Config;

/* ConfigPtr NULL: PqcHs_Config. E_NOT_OK: invalid configuration (timer relation, too many instances). */
Std_ReturnType PqcHs_Init(const PqcHs_ConfigType* ConfigPtr);
/* Once per BSW cycle, after SecOC_MainFunctionRx and before SecOC_MainFunctionTx. Handshake messages
 * are processed, keys installed and timers evaluated here, never inside a SoAd call. */
void PqcHs_MainFunction(void);

/* "Initiate handshake now" (initiator only). The handshake starts in the next main function. */
Std_ReturnType PqcHs_Initiate(uint8 Peer);
/* Set only at key installation. While it is FALSE no Secured I-PDU of this peer is accepted or released. */
boolean PqcHs_IsEstablished(uint8 Peer);
/* Oracle of the tests: first bytes of the session transcript hash and number of key installations */
Std_ReturnType PqcHs_GetSession(uint8 Peer, uint8* SidPtr, uint32* InstallCountPtr);
/* Oldest unread row of this peer; E_NOT_OK when there is none. No output, no file I/O in the component. */
Std_ReturnType PqcHs_ReadAttempt(uint8 Peer, PqcHs_AttemptInfoType* AttemptPtr);

/* SoAd generic upper layer, TP API [SWS_SoAd_00138], [SWS_SoAd_00139], [SWS_SoAd_00180],
 * [SWS_SoAd_00137], [SWS_SoAd_00181], [SWS_SoAd_00514] */
BufReq_ReturnType PqcHs_SoAdTpStartOfReception(PduIdType id, const PduInfoType* info, PduLengthType TpSduLength,
                                               PduLengthType* bufferSizePtr);
BufReq_ReturnType PqcHs_SoAdTpCopyRxData(PduIdType id, const PduInfoType* info, PduLengthType* bufferSizePtr);
void PqcHs_SoAdTpRxIndication(PduIdType id, Std_ReturnType result);
BufReq_ReturnType PqcHs_SoAdTpCopyTxData(PduIdType id, const PduInfoType* info, const RetryInfoType* retry,
                                         PduLengthType* availableDataPtr);
void PqcHs_SoAdTpTxConfirmation(PduIdType id, Std_ReturnType result);
void PqcHs_SoConModeChg(SoAd_SoConIdType SoConId, SoAd_SoConModeType Mode);

#endif
