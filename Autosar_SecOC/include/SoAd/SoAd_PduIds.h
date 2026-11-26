/********************************************************************************************************/
/*  File:   include/SoAd/SoAd_PduIds.h                                                                    */
/*  Brief:  The one table of identifiers for the PDUs that travel over the Ethernet socket connection:    */
/*          SecOC PDU IDs, SoAd PDU IDs, PDU header IDs on the wire, lengths, routing groups, freshness   */
/*          value IDs. Plain constants (usable in #if and in initialisers); cast at the place of use.     */
/*          Every module that needs one of these numbers takes it from here by name.                      */
/********************************************************************************************************/

#ifndef SOAD_PDUIDS_H
#define SOAD_PDUIDS_H

/* ---- SecOC PDU IDs ------------------------------------------------------------------------------- */
/* Rows of SecOC_TxPduProcessing / SecOC_RxPduProcessing; the same number is the lower-layer PDU ID
 * and the SoAd PDU ID of that PDU. The rows are dense: 0 .. SECOC_NUM_OF_*_PDU_PROCESSING - 1.
 *   0..5    as found (CAN IF / CAN TP / collection; 2 is the first Ethernet signature PDU)
 *   6..12   Ethernet signature streams 1..7
 *   13..20  Ethernet MAC streams 0..7
 *   21, 22  authentic and cryptographic PDU of secured PDU collection 5 (lower-layer IDs only, no rows) */
#define SECOC_PDUID_SIG_COUNT               (8U)
#define SECOC_PDUID_SIG(i)                  (((i) == 0U) ? 2U : (5U + (i)))
#define SECOC_PDUID_MAC_COUNT               (8U)
#define SECOC_PDUID_MAC(i)                  (13U + (i))
#define SECOC_PDUID_COLLECTION_AUTH         (21U)
#define SECOC_PDUID_COLLECTION_CRYPTO       (22U)

/* ---- SoAd PDU IDs that are not SecOC PDUs --------------------------------------------------------- */
/* Handshake messages M1..M4, dispatched to the handshake upper layer, not to PduR. */
#define SOAD_PDUID_HS_M1                    (23U)
#define SOAD_PDUID_HS_M2                    (24U)
#define SOAD_PDUID_HS_M3                    (25U)
#define SOAD_PDUID_HS_M4                    (26U)
#define SOAD_NUM_PDU_IDS                    (27U)

/* ---- PDU header IDs on the wire [SWS_SoAd_00198] --------------------------------------------------- */
#define SOAD_HEADERID_SIG(i)                (0x10U + (i))
#define SOAD_HEADERID_MAC(i)                (0x20U + (i))
#define SOAD_HEADERID_HS_M1                 (0x30U)
#define SOAD_HEADERID_HS_M2                 (0x31U)
#define SOAD_HEADERID_HS_M3                 (0x32U)
#define SOAD_HEADERID_HS_M4                 (0x33U)

/* ---- lengths ------------------------------------------------------------------------------------- */
/* Handshake messages have one fixed length each; any other length is discarded by SoAd. */
#define SOAD_HS_M1_LENGTH                   (1217U)
#define SOAD_HS_M2_LENGTH                   (4462U)
#define SOAD_HS_M3_LENGTH                   (3342U)
#define SOAD_HS_M4_LENGTH                   (33U)

/* ---- SoAd routing groups ------------------------------------------------------------------------- */
#define SOAD_ROUTING_GROUP_NORMAL           (0U)    /* secured PDUs; under BswM */
#define SOAD_ROUTING_GROUP_DIAGNOSTIC       (1U)    /* under BswM */
#define SOAD_ROUTING_GROUP_HS               (2U)    /* handshake; enabled at init, never disabled */

/* ---- freshness value IDs ------------------------------------------------------------------------- */
/* Rows 0..5 as found; every later row has its Tx and Rx counter in ranges of their own (both sides
 * of one PDU live in one counter table when transmitter and receiver run in one process). */
#define SECOC_FRESHNESS_ID_TX(pdu)          (((pdu) <= 5U) ? (10U + (pdu)) : (30U + (pdu)))
#define SECOC_FRESHNESS_ID_RX(pdu)          (((pdu) <= 5U) ? (20U + (pdu)) : (60U + (pdu)))

/* Counters that restart with a session: the signature streams, then the MAC streams. */
#define SECOC_SESSION_TX_FRESHNESS_COUNT    (16U)
#define SECOC_SESSION_RX_FRESHNESS_COUNT    (16U)
#define SECOC_SESSION_TX_FRESHNESS_IDS      12U, 36U, 37U, 38U, 39U, 40U, 41U, 42U,  43U, 44U, 45U, 46U, 47U, 48U, 49U, 50U
#define SECOC_SESSION_RX_FRESHNESS_IDS      22U, 66U, 67U, 68U, 69U, 70U, 71U, 72U,  73U, 74U, 75U, 76U, 77U, 78U, 79U, 80U

#endif /* SOAD_PDUIDS_H */
