#ifndef INCLUDE_PQCHS_CFG_H_
#define INCLUDE_PQCHS_CFG_H_

/********************************************************************************************************/
/*  Configuration of the handshake component PqcHs (PQC-SecOC-HS-v1).                                     */
/*  Identifiers that other modules allocate are taken from their headers: the handshake PDU ids and the  */
/*  session-bound freshness values from the identifier table of the Ethernet PDUs (SoAd_PduIds.h, through */
/*  SoAd.h); the MAC keys and jobs of the peer from the Csm (Csm.h).                                      */
/********************************************************************************************************/

#include "Std_Types.h"
#include "SecOC/SecOC_Cfg.h"
#include "Csm/Csm.h"
#include "SoAd/SoAd.h"

/* Timers in milliseconds. T_A > max(T_pend, T_min); T_pend above the worst-case honest M1 -> M3 time;
 * T_flush < T_pend. */
#ifndef PQCHS_T_PEND_MS
#define PQCHS_T_PEND_MS                 (2000U)     /* responder: a pending handshake is wiped after this */
#endif
#ifndef SOAD_PQC_HS_MIN_INTERVAL_MS
#define SOAD_PQC_HS_MIN_INTERVAL_MS     (1000U)     /* T_min: responder drops an M1 earlier than this after the last accepted one */
#endif
#ifndef PQCHS_T_A_MS
#define PQCHS_T_A_MS                    (3000U)     /* initiator: no valid M2 after M1, or no valid M4 after M3, within this */
#endif
/* Initiator: longest wait, from the acceptance of M2, for SecOC to hand down what it had already
 * authenticated. Below T_pend: later than that the responder has dropped the handshake anyway. */
#ifndef PQCHS_T_FLUSH_MS
#define PQCHS_T_FLUSH_MS                (1000U)
#endif

/* Role of this node: the transmitting gateway is the initiator (A), the receiving gateway the responder (B) */
#if (SECOC_ROLE_SENDER == TRUE)
#define PQCHS_CFG_ROLE                  PQCHS_ROLE_INITIATOR
#else
#define PQCHS_CFG_ROLE                  PQCHS_ROLE_RESPONDER
#endif

/* SoAd: the socket connection of the handshake PDUs SOAD_PDUID_HS_M1 .. M4 */
#ifndef PQCHS_CFG_SOCON_ID
#define PQCHS_CFG_SOCON_ID              (0U)
#endif

/* Freshness values that are bound to the session and restart at key installation: the transmit
 * counters of the session-bound streams on the initiator, their receive counters on the responder */
#if (SECOC_ROLE_SENDER == TRUE)
#define PQCHS_CFG_SESSION_FRESHNESS_IDS     SECOC_SESSION_TX_FRESHNESS_IDS
#define PQCHS_CFG_NUM_SESSION_FRESHNESS_IDS SECOC_SESSION_TX_FRESHNESS_COUNT
#else
#define PQCHS_CFG_SESSION_FRESHNESS_IDS     SECOC_SESSION_RX_FRESHNESS_IDS
#define PQCHS_CFG_NUM_SESSION_FRESHNESS_IDS SECOC_SESSION_RX_FRESHNESS_COUNT
#endif

#endif
