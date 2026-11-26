/******************************************************************************
 * File Name   : SecOC_Lcfg                                                   *
 * Description : Header file of SecOC configuration                           *
 * Created on  : November 9, 2022                                             *
 ******************************************************************************/

/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/

#include "SecOC_Cfg.h"
#include "SecOC_Lcfg.h"
#include "Csm.h"
#include "PQC.h"

/* SWS SecOC 7.1.4 (2): a signature is not truncated, SecOCAuthInfoTruncLength is its complete length.
 * It applies to every PDU that references a signature job, the CAN PDUs included. */
#define SECOC_MLDSA_AUTH_INFO_LENGTH_BITS       ((uint16)(PQC_MLDSA_SIGNATURE_BYTES * 8U))
/* MAC variant: the leftmost 128 bits of HMAC-SHA-256 [SWS_SecOC_00036] */
#define SECOC_MAC_AUTH_INFO_LENGTH_BITS         ((uint16)128U)

/********************************************************************************************************/
/**********************************************Buffers***************************************************/
/********************************************************************************************************/

/* [SWS_SecOC_00057] The SecOC module shall provide sufficient buffers to store the Authentic I-PDU and the outgoing Secured I-PDU */ 
/* [SWS_SecOC_00146] The SecOC module shall provide separate buffers for the Authentic I-PDU and the Secured I-PDU. */
/* [SWS_SecOC_00058] */
/* direct */
uint8_t AuthPdu0BufferTx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t SecPdu0BufferTx[SECOC_SECPDU_MAX_LENGTH];

uint8_t AuthPdu0BufferRx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t SecPdu0BufferRx[SECOC_SECPDU_MAX_LENGTH];

/* for Tp */
uint8_t AuthPdu1BufferTx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t SecPdu1BufferTx[SECOC_SECPDU_MAX_LENGTH];

uint8_t AuthPdu1BufferRx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t SecPdu1BufferRx[SECOC_SECPDU_MAX_LENGTH];

/* for SOAD "Ethernet APIs" */
uint8_t AuthPdu2BufferTx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t SecPdu2BufferTx[SECOC_SECPDU_MAX_LENGTH];

uint8_t AuthPdu2BufferRx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t SecPdu2BufferRx[SECOC_SECPDU_MAX_LENGTH];



/* direct without Trunc-FV and header*/
uint8_t AuthPdu3BufferTx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t SecPdu3BufferTx[SECOC_SECPDU_MAX_LENGTH];

uint8_t AuthPdu3BufferRx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t SecPdu3BufferRx[SECOC_SECPDU_MAX_LENGTH];

/* Tp without header*/
uint8_t AuthPdu4BufferTx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t SecPdu4BufferTx[SECOC_SECPDU_MAX_LENGTH];

uint8_t AuthPdu4BufferRx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t SecPdu4BufferRx[SECOC_SECPDU_MAX_LENGTH];


/* for RxSecuredPduCollection */
uint8_t AuthPdu5BufferRx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t SecPdu5BufferRx[SECOC_SECPDU_MAX_LENGTH];
uint8_t AuthPduCollection5BufferRx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t CryptoPduCollection5BufferRx[SECOC_SECPDU_MAX_LENGTH];

/* for TxSecuredPduCollection */
uint8_t AuthPdu5BufferTx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t SecPdu5BufferTx[SECOC_SECPDU_MAX_LENGTH];
uint8_t AuthPduCollection5BufferTx[SECOC_AUTHPDU_MAX_LENGTH];
uint8_t CryptoPduCollection5BufferTx[SECOC_SECPDU_MAX_LENGTH];


/* Ethernet signature streams 1..7 (SecOC PDU 6..12, SoAd_PduIds.h): the configuration of PDU 2 with
 * other identifiers and buffers. One macro per configuration table; a MAC stream can use the same
 * shape with its own job references and authenticator length. */
#define SECOC_SIG_STREAM_BUFFERS(n) \
    uint8_t AuthPdu##n##BufferTx[SECOC_AUTHPDU_MAX_LENGTH]; uint8_t SecPdu##n##BufferTx[SECOC_SECPDU_MAX_LENGTH]; \
    uint8_t AuthPdu##n##BufferRx[SECOC_AUTHPDU_MAX_LENGTH]; uint8_t SecPdu##n##BufferRx[SECOC_SECPDU_MAX_LENGTH];
SECOC_SIG_STREAM_BUFFERS(6)
SECOC_SIG_STREAM_BUFFERS(7)
SECOC_SIG_STREAM_BUFFERS(8)
SECOC_SIG_STREAM_BUFFERS(9)
SECOC_SIG_STREAM_BUFFERS(10)
SECOC_SIG_STREAM_BUFFERS(11)
SECOC_SIG_STREAM_BUFFERS(12)
/* MAC stream 0 (SecOC PDU 13 = SECOC_PDUID_MAC(0), SoAd_PduIds.h): the same shape, with the MAC jobs
 * and a 128-bit authenticator. The literal 13 is needed for the buffer names. */
SECOC_SIG_STREAM_BUFFERS(13)
_Static_assert(SECOC_PDUID_MAC(0U) == 13U, "the MAC stream rows below are written for SecOC PDU 13");

#define SECOC_SIG_RX_AUTHENTIC_LAYER(n) \
    { .SecOCPduType = SECOC_IFPDU, .SecOCRxAuthenticLayerPduId = ((uint16)(10U + (n))), \
      .SecOCRxAuthenticLayerPduRef = { .SduDataPtr = AuthPdu##n##BufferRx, .MetaDataPtr = NULL, .SduLength = ((PduLengthType) 3) } }
#define SECOC_SIG_RX_SECURED_PDU(n) \
    { .SecOCAuthPduHeaderLength = ((uint8) 1), .SecOCRxSecuredLayerPduId = ((uint16)(10U + (n))), \
      .SecOCSecuredRxPduVerification = ((boolean) TRUE), \
      .SecOCRxSecuredLayerPduRef = { .SduDataPtr = SecPdu##n##BufferRx, .MetaDataPtr = NULL, .SduLength = ((PduLengthType) 0) } }
#define SECOC_SIG_RX_SECURED_LAYER(n) \
    { .SecOCRxSecuredPdu = &SecOC_RxSecuredPdu[n], .SecOCRxSecuredPduCollection = NULL }
#define SECOC_SIG_TX_AUTHENTIC_LAYER(n) \
    { .SecOCPduType = SECOC_TPPDU, .SecOCTxAuthenticLayerPduId = ((uint16)(n)), \
      .SecOCTxAuthenticLayerPduRef = { .SduDataPtr = AuthPdu##n##BufferTx, .MetaDataPtr = NULL, .SduLength = ((PduLengthType) 0) } }
#define SECOC_SIG_TX_SECURED_PDU(n) \
    { .SecOCAuthPduHeaderLength = ((uint8) 1), .SecOCTxSecuredLayerPduId = ((uint16)(n)), \
      .SecOCTxSecuredLayerPduRef = { .SduDataPtr = SecPdu##n##BufferTx, .MetaDataPtr = NULL, .SduLength = ((PduLengthType) 0) } }
#define SECOC_SIG_TX_SECURED_LAYER(n) \
    { .SecOCTxSecuredPdu = &SecOC_TxSecuredPdu[n], .SecOCTxSecuredPduCollection = NULL }
/* authRef: the Csm job the PDU references (it decides MAC or signature), authBits: SecOCAuthInfoTruncLength */
#define SECOC_ETH_TX_PROCESSING(n, authRef, authBits) \
    { .SecOCAuthenticationBuildAttempts = ((uint16) 2), \
      .SecOCAuthInfoTruncLength = (authBits), \
      .SecOCDataId = ((uint16)(n)), \
      .SecOCFreshnessValueId = ((uint16)SECOC_FRESHNESS_ID_TX(n)), \
      .SecOCFreshnessValueLength = ((uint8) 32), \
      .SecOCFreshnessValueTruncLength = ((uint8) 32), \
      .SecOCProvideTxTruncatedFreshnessValue = ((boolean) TRUE), \
      .SecOCReAuthenticateAfterTriggerTransmit = ((boolean) FALSE), \
      .SecOCTxPduUnusedAreasDefault = ((uint8) 0), \
      .SecOCUseTxConfirmation = ((boolean) FALSE), \
      .SecOCTxAuthServiceConfigRef = (authRef), \
      .SecOCTxAuthenticPduLayer = &SecOC_TxAuthenticPduLayer[n], \
      .SecOCTxSecuredPduLayer = &SecOC_TxSecuredPduLayer[n] }
#define SECOC_SIG_TX_PROCESSING(n)  SECOC_ETH_TX_PROCESSING(n, &SecOC_TxAuthServiceConfigRef, SECOC_MLDSA_AUTH_INFO_LENGTH_BITS)
#define SECOC_MAC_TX_PROCESSING(n)  SECOC_ETH_TX_PROCESSING(n, &SecOC_TxAuthServiceConfigRefMac, SECOC_MAC_AUTH_INFO_LENGTH_BITS)
#define SECOC_ETH_RX_PROCESSING(n, authRef, authBits) \
    { .SecOCAuthDataFreshnessLen = ((uint16) 0), \
      .SecOCAuthDataFreshnessStartPosition = ((uint16) 0), \
      .SecOCAuthenticationBuildAttempts = ((uint16) 2), \
      .SecOCAuthenticationVerifyAttempts = ((uint16) 0), /* [ECUC_SecOC_00080] 0: one verification attempt */ \
      .SecOCAuthInfoTruncLength = (authBits), \
      .SecOCClientServerVerificationStatusPropagationMode = ((SecOC_StatusPropagationMode_Type) SECOC_BOTH), \
      .SecOCDataId = ((uint16)(n)), \
      .SecOCFreshnessValueId = ((uint16)SECOC_FRESHNESS_ID_RX(n)), \
      .SecOCFreshnessValueLength = ((uint8) 32), \
      .SecOCFreshnessValueTruncLength = ((uint8) 32), \
      .SecOCReceptionOverflowStrategy = ((SecOC_ReceptionOverflowStrategy_Type) SECOC_REPLACE), \
      .SecOCReceptionQueueSize = ((uint16) 10), \
      .SecOCUseAuthDataFreshness = ((boolean) FALSE), \
      .SecOCVerificationStatusPropagationMode = ((SecOC_StatusPropagationMode_Type) SECOC_BOTH), \
      .SecOCRxAuthServiceConfigRef = (authRef), \
      .SecOCRxPduMainFunctionRef = &SecOCMainFunctionRx, \
      .SecOCRxSecuredPduLayer = &SecOC_RxSecuredPduLayer[n], \
      .SecOCRxAuthenticPduLayer = &SecOC_RxAuthenticPduLayer[n] }
#define SECOC_SIG_RX_PROCESSING(n)  SECOC_ETH_RX_PROCESSING(n, &SecOC_RxAuthServiceConfigRefPeer0, SECOC_MLDSA_AUTH_INFO_LENGTH_BITS)
#define SECOC_MAC_RX_PROCESSING(n)  SECOC_ETH_RX_PROCESSING(n, &SecOC_RxAuthServiceConfigRefMac, SECOC_MAC_AUTH_INFO_LENGTH_BITS)
/* rows 6..12 of one table */
#define SECOC_SIG_STREAM_ROWS(ROW) \
    [6] = ROW(6), [7] = ROW(7), [8] = ROW(8), [9] = ROW(9), [10] = ROW(10), [11] = ROW(11), [12] = ROW(12)

SecOC_PduCollection PdusCollections[] =
{
    {SECOC_SECURED_PDU_CANIF,0,0,0,0},        // ID 0: CAN Interface
    {SECOC_SECURED_PDU_CANTP,0,0,0,0},        // ID 1: CAN Transport Protocol
    {SECOC_SECURED_PDU_SOADTP,0,0,0,0},       // ID 2: SoAd TP (Ethernet gateway path)
    {SECOC_SECURED_PDU_CANIF,0,0,0,0},        // ID 3: CAN Interface
    {SECOC_SECURED_PDU_CANTP,0,0,0,0},        // ID 4: CAN Transport Protocol
    {SECOC_SECURED_PDU_CANIF,0,0,0,0},        // ID 5: CAN Interface
    /* IDs 6..20: Ethernet signature streams 1..7 and MAC streams 0..7 (SoAd_PduIds.h), all SoAd TP */
    [6]  = {SECOC_SECURED_PDU_SOADTP,0,0,0,0}, [7]  = {SECOC_SECURED_PDU_SOADTP,0,0,0,0},
    [8]  = {SECOC_SECURED_PDU_SOADTP,0,0,0,0}, [9]  = {SECOC_SECURED_PDU_SOADTP,0,0,0,0},
    [10] = {SECOC_SECURED_PDU_SOADTP,0,0,0,0}, [11] = {SECOC_SECURED_PDU_SOADTP,0,0,0,0},
    [12] = {SECOC_SECURED_PDU_SOADTP,0,0,0,0}, [13] = {SECOC_SECURED_PDU_SOADTP,0,0,0,0},
    [14] = {SECOC_SECURED_PDU_SOADTP,0,0,0,0}, [15] = {SECOC_SECURED_PDU_SOADTP,0,0,0,0},
    [16] = {SECOC_SECURED_PDU_SOADTP,0,0,0,0}, [17] = {SECOC_SECURED_PDU_SOADTP,0,0,0,0},
    [18] = {SECOC_SECURED_PDU_SOADTP,0,0,0,0}, [19] = {SECOC_SECURED_PDU_SOADTP,0,0,0,0},
    [20] = {SECOC_SECURED_PDU_SOADTP,0,0,0,0},
    [SECOC_PDUID_COLLECTION_AUTH] = {
        .Type =         SECOC_AUTH_COLLECTON_PDU,
        .CollectionId =     5,
        .AuthId =           SECOC_PDUID_COLLECTION_AUTH,
        .CryptoId=          SECOC_PDUID_COLLECTION_CRYPTO,
        .status=            0x02
    },
    [SECOC_PDUID_COLLECTION_CRYPTO] = {
        .Type =         SECOC_CRYPTO_COLLECTON_PDU,
        .CollectionId =     5,
        .AuthId =           SECOC_PDUID_COLLECTION_AUTH,
        .CryptoId=          SECOC_PDUID_COLLECTION_CRYPTO,
        .status=            0x02
    }
};


/*
* Start Of General
*/

// cppcheck-suppress misra-c2012-8.4
SecOC_MainFunctionTxType SecOC_MainFunctionTxConf = 
{
    SECOC_MAIN_FUNCTION_PERIOD_TX,
    /* cppcheck-suppress misra-c2012-11.5 */
    SECOC_MAIN_FUNCTION_TX_PARTITION_REF, /* NOT SURE ABOUT THAT TYPE */

};


// cppcheck-suppress misra-c2012-8.4
SecOC_MainFunctionRxType SecOCMainFunctionRx = 
{
    SECOC_MAIN_FUNCTION_PERIOD_RX,
    /* cppcheck-suppress misra-c2012-11.5 */
    SECOC_MAIN_FUNCTION_RX_PARTITION_REF, /* NOT SURE ABOUT THAT TYPE */

};



// cppcheck-suppress misra-c2012-8.4
/* cppcheck-suppress misra-c2012-9.3 */
SecOC_GeneralType SecOC_General =
{
    SECOC_DEFAULT_AUTHENTICATION_INFORMATION_PATTERN_VALUE,
    SECOC_DEV_ERROR_DETECT,
    SECOC_ENABLE_FORCED_PASS_OVERRIDE,
    SECOC_ENABLE_SECURITY_EVENT_REPORTING,
    SECOC_IGNORE_VERIFICATION_RESULT,
    {SECOC_MAX_ALIGN_SCALAR_TYPE},
    SECOC_OVERRIDE_STATUS_WITH_DATA_ID,
    SECOC_PROPAGATE_ONLY_FINAL_VERIFICATION_STATUS,
    SECOC_QUERY_FRESHNESS_VALUE,
    /* SECOC_VERIFICATION_STATUS_CALLOUT,*/
    SECOC_VERSION_INFO_API,
    /*SECOC_SECURITY_EVENT_REFS,*/ /* can't have the container of it */

};



SecOC_RxCryptographicPduType SecOC_RxCryptographicPdu[] =
{
    {
        SECOC_RX_CRYPTOGRAPHIC_PDUID,
        {
            .SduDataPtr =               CryptoPduCollection5BufferRx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        },
    }
};

SecOC_RxAuthenticPduType SecOC_RxAuthenticPdu[] =
{
    {
        SECOC_CRYPTO_AUTHPDU_HEADERLENGTH,
        SECOC_CRYPTO_RXAUTHENTIC_PDUID,
        {
            .SduDataPtr =               AuthPduCollection5BufferRx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        },
    }
};



SecOC_UseMessageLinkType SecOC_UseMessageLink[]=
{
    {
        SECOC_MESSAGE_LINKLEN,
        SECOC_MESSAGE_LINKPOS,
    }
};

SecOC_RxSecuredPduCollectionType SecOC_RxSecuredPduCollection[] =
{
    {
        SECOC_SECURED_RX_PDU_VERIFICATION,
        &SecOC_RxAuthenticPdu[0],
        &SecOC_RxCryptographicPdu[0],
        &SecOC_UseMessageLink[0]
    },
};

SecOC_RxAuthenticPduLayerType SecOC_RxAuthenticPduLayer[] = 
{
    { /* direct */
        SECOC_RX_PDUTYPE,
        SECOC_RXAUTHENTICLAYER_PDUID,
        {AuthPdu0BufferRx, NULL, 3},
    },
    { /* for Tp */
        .SecOCPduType =                 SECOC_TPPDU,
        .SecOCRxAuthenticLayerPduId =   ((uint16)11),
        .SecOCRxAuthenticLayerPduRef = 
        {
            .SduDataPtr =               AuthPdu1BufferRx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 16)
        }
    },
    { /* for SOAD "Ethernet APIs" */
        .SecOCPduType =                 SECOC_IFPDU,
        .SecOCRxAuthenticLayerPduId =   ((uint16)12),
        .SecOCRxAuthenticLayerPduRef = 
        {
            .SduDataPtr =               AuthPdu2BufferRx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 3)
        }
    },    
    { /* direct without Trunc-FV and header*/
        .SecOCPduType =                 SECOC_IFPDU,
        .SecOCRxAuthenticLayerPduId =   ((uint16)13),
        .SecOCRxAuthenticLayerPduRef = 
        {
            .SduDataPtr =               AuthPdu3BufferRx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 4)
        }
    },
    { /* Tp without header*/
        .SecOCPduType =                 SECOC_TPPDU,
        .SecOCRxAuthenticLayerPduId =   ((uint16)13),
        .SecOCRxAuthenticLayerPduRef = 
        {
            .SduDataPtr =               AuthPdu4BufferRx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 19)
        }        
    },
    { /* for RxSecuredPduCollection */
        .SecOCPduType =                 SECOC_IFPDU,
        .SecOCRxAuthenticLayerPduId =   ((uint16)12),
        .SecOCRxAuthenticLayerPduRef = 
        {
            .SduDataPtr =               AuthPdu5BufferRx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 20)
        }
    },
    /* Ethernet signature streams 1..7 */
    SECOC_SIG_STREAM_ROWS(SECOC_SIG_RX_AUTHENTIC_LAYER),
    [13] = SECOC_SIG_RX_AUTHENTIC_LAYER(13)
};

SecOC_RxSecuredPduType SecOC_RxSecuredPdu[] = 
{
    { /* direct */
        SECOC_AUTHPDU_HEADERLENGTH,
        SECOC_RX_SECUREDLAYER_PDUID,
        SECOC_SECURED_RX_PDUVERIFICATION,
        {SecPdu0BufferRx, NULL, 0},
    },
    { /* for Tp */
        .SecOCAuthPduHeaderLength =         ((uint8) 1),
        .SecOCRxSecuredLayerPduId =         ((uint16) 11),
        .SecOCSecuredRxPduVerification =    ((boolean) TRUE),
        .SecOCRxSecuredLayerPduRef = 
        {
            .SduDataPtr =                   SecPdu1BufferRx,
            .MetaDataPtr =                  NULL,
            .SduLength =                    ((PduLengthType) 0)
        }
    },
    { /* for SOAD "Ethernet APIs" */
        .SecOCAuthPduHeaderLength =         ((uint8) 1),
        .SecOCRxSecuredLayerPduId =         ((uint16) 12),
        .SecOCSecuredRxPduVerification =    ((boolean) TRUE),
        .SecOCRxSecuredLayerPduRef = 
        {
            .SduDataPtr =                   SecPdu2BufferRx,
            .MetaDataPtr =                  NULL,
            .SduLength =                    ((PduLengthType) 0)
        }
    },
    { /* direct without Trunc-FV and header*/
        .SecOCAuthPduHeaderLength =         ((uint8) 0),
        .SecOCRxSecuredLayerPduId =         ((uint16) 13),
        .SecOCSecuredRxPduVerification =    ((boolean) TRUE),
        .SecOCRxSecuredLayerPduRef = 
        {
            .SduDataPtr =                   SecPdu3BufferRx,
            .MetaDataPtr =                  NULL,
            .SduLength =                    ((PduLengthType) 0)
        }
    },
    { /* Tp without header*/
        .SecOCAuthPduHeaderLength =         ((uint8) 0),
        .SecOCRxSecuredLayerPduId =         ((uint16) 14),
        .SecOCSecuredRxPduVerification =    ((boolean) TRUE),
        .SecOCRxSecuredLayerPduRef = 
        {
            .SduDataPtr =                   SecPdu4BufferRx,
            .MetaDataPtr =                  NULL,
            .SduLength =                    ((PduLengthType) 0)
        }
    },
    { /* for RxSecuredPduCollection */
        .SecOCAuthPduHeaderLength =         ((uint8) 1),
        .SecOCRxSecuredLayerPduId =         ((uint16) 15),
        .SecOCSecuredRxPduVerification =    ((boolean) TRUE),
        .SecOCRxSecuredLayerPduRef = 
        {
            .SduDataPtr =                   SecPdu5BufferRx,
            .MetaDataPtr =                  NULL,
            .SduLength =                    ((PduLengthType) 0)
        }
    },
    /* Ethernet signature streams 1..7 */
    SECOC_SIG_STREAM_ROWS(SECOC_SIG_RX_SECURED_PDU),
    [13] = SECOC_SIG_RX_SECURED_PDU(13)
};

SecOC_RxSecuredPduLayerType SecOC_RxSecuredPduLayer[] =
{
    { /* direct */
        &SecOC_RxSecuredPdu[0],
        NULL  
    },
    { /* for Tp */
        .SecOCRxSecuredPdu =            &SecOC_RxSecuredPdu[1],
        .SecOCRxSecuredPduCollection =  NULL
    },
    { /* for SOAD "Ethernet APIs" */
        .SecOCRxSecuredPdu =            &SecOC_RxSecuredPdu[2],
        .SecOCRxSecuredPduCollection =  NULL
    },
    { /* direct without Trunc-FV and header*/
        .SecOCRxSecuredPdu =            &SecOC_RxSecuredPdu[3],
        .SecOCRxSecuredPduCollection =  NULL
    },
    { /* Tp without header*/
        .SecOCRxSecuredPdu =            &SecOC_RxSecuredPdu[4],
        .SecOCRxSecuredPduCollection =  NULL
    },
    { /* for RxSecuredPduCollection" */
        .SecOCRxSecuredPdu =            &SecOC_RxSecuredPdu[5],
        .SecOCRxSecuredPduCollection =  &SecOC_RxSecuredPduCollection[0]
    },
    /* Ethernet signature streams 1..7 */
    SECOC_SIG_STREAM_ROWS(SECOC_SIG_RX_SECURED_LAYER),
    [13] = SECOC_SIG_RX_SECURED_LAYER(13)
};



// cppcheck-suppress misra-c2012-8.4
// cppcheck-suppress misra-c2012-5.8
Csm_JobType CsmJob =
{
    CSM_JOBID,
    CRYPTO_SIGNATUREGENERATE
};

// cppcheck-suppress misra-c2012-8.4
SecOC_TxAuthServiceConfigRefType SecOC_TxAuthServiceConfigRef =
{
    &CsmJob
};



/* Reception of the CAN PDUs (rows 0, 1, 3, 4, 5, not part of the evaluated Ethernet set-up):
 * verification of what this node signed itself, with the listed loopback job. CSM_JOBID is a sign
 * job and verifies nothing. */
static Csm_JobType CsmJobVerifyLocal =
{
    CSM_JOBID_VERIFY_LOOPBACK,
    CRYPTO_SIGNATUREVERIFY
};

// cppcheck-suppress misra-c2012-8.4
SecOC_RxAuthServiceConfigRefType SecOC_RxAuthServiceConfigRef = 
{
    &CsmJobVerifyLocal
};

/* Verification of PDUs from the peer gateway uses the peer's ML-DSA public key (SWS SecOC 7.1.4 (1));
 * the loopback job above selects the local key pair. */
// cppcheck-suppress misra-c2012-8.4
Csm_JobType CsmJobVerifyPeer0 =
{
    CSM_JOBID_VERIFY_PEER_BASE,
    CRYPTO_SIGNATUREVERIFY
};

// cppcheck-suppress misra-c2012-8.4
SecOC_RxAuthServiceConfigRefType SecOC_RxAuthServiceConfigRefPeer0 =
{
    &CsmJobVerifyPeer0
};

/* MAC variant: HMAC-SHA-256 under the key for the PDUs this node sends (generate) and under the key
 * for the PDUs it receives (verify); the two directions never share a key. */
static Csm_JobType CsmJobMacGenerate =
{
    CSM_JOBID_MAC_GENERATE,
    CRYPTO_MACGENERATE
};

static SecOC_TxAuthServiceConfigRefType SecOC_TxAuthServiceConfigRefMac =
{
    &CsmJobMacGenerate
};

static Csm_JobType CsmJobMacVerify =
{
    CSM_JOBID_MAC_VERIFY,
    CRYPTO_MACVERIFY
};

static SecOC_RxAuthServiceConfigRefType SecOC_RxAuthServiceConfigRefMac =
{
    &CsmJobMacVerify
};

// cppcheck-suppress misra-c2012-8.4
SecOC_SameBufferPduCollectionType SecOC_SameBufferPduRef=
{
    SECOC_BUFFERLENGTH
};








SecOC_TxAuthenticPduLayerType SecOC_TxAuthenticPduLayer[]=
{
    { /* direct */  
        SECOC_TX_PDUTYPE,
        SECOC_TX_AUTHENTIC_LAYER_PDUID,
        {AuthPdu0BufferTx, NULL, 0},
    },
    { /* for Tp */
        .SecOCPduType =                 SECOC_TPPDU,
        .SecOCTxAuthenticLayerPduId =   ((uint16) 1),
        .SecOCTxAuthenticLayerPduRef = 
        {
            .SduDataPtr =               AuthPdu1BufferTx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        }
    },
    { /* for SOAD "Ethernet APIs" */
        .SecOCPduType =                 SECOC_TPPDU,
        .SecOCTxAuthenticLayerPduId =   ((uint16) 2),
        .SecOCTxAuthenticLayerPduRef = 
        {
            .SduDataPtr =               AuthPdu2BufferTx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        }
    },
    { /* direct without Trunc-FV and header*/
        .SecOCPduType =                 SECOC_IFPDU,
        .SecOCTxAuthenticLayerPduId =   ((uint16) 3),
        .SecOCTxAuthenticLayerPduRef = 
        {
            .SduDataPtr =               AuthPdu3BufferTx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        }
    },
    { /* Tp without header*/
        .SecOCPduType =                 SECOC_TPPDU,
        .SecOCTxAuthenticLayerPduId =   ((uint16) 4),
        .SecOCTxAuthenticLayerPduRef = 
        {
            .SduDataPtr =               AuthPdu4BufferTx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        }
    },
    { /* for TxSecuredPduCollection */
        .SecOCPduType =                 SECOC_IFPDU,
        .SecOCTxAuthenticLayerPduId =   ((uint16) 5),
        .SecOCTxAuthenticLayerPduRef = 
        {
            .SduDataPtr =               AuthPdu5BufferTx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        }
    },
    /* Ethernet signature streams 1..7 */
    SECOC_SIG_STREAM_ROWS(SECOC_SIG_TX_AUTHENTIC_LAYER),
    [13] = SECOC_SIG_TX_AUTHENTIC_LAYER(13)
};

SecOC_TxSecuredPduType SecOC_TxSecuredPdu[]=
{
    { /* direct */
        SECOC_AUTH_PDUHEADER_LENGTH,
        SECOC_TX_SECURED_LAYER_PDUID,
        {SecPdu0BufferTx, NULL, 0},
    },
    { /* for Tp */
        .SecOCAuthPduHeaderLength =     ((uint8) 1),
        .SecOCTxSecuredLayerPduId =     ((uint16) 1),
        .SecOCTxSecuredLayerPduRef = 
        {
            .SduDataPtr =               SecPdu1BufferTx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        }
    },
    { /* for SOAD "Ethernet APIs" */
        .SecOCAuthPduHeaderLength =     ((uint8) 1),
        .SecOCTxSecuredLayerPduId =     ((uint16) 2),
        .SecOCTxSecuredLayerPduRef = 
        {
            .SduDataPtr =               SecPdu2BufferTx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        }
    },
    { /* direct without Trunc-FV and header*/
        .SecOCAuthPduHeaderLength =     ((uint8) 0),
        .SecOCTxSecuredLayerPduId =     ((uint16) 3),
        .SecOCTxSecuredLayerPduRef = 
        {
            .SduDataPtr =               SecPdu3BufferTx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        }
    },
    { /* Tp without header*/
        .SecOCAuthPduHeaderLength =     ((uint8) 0),
        .SecOCTxSecuredLayerPduId =     ((uint16) 4),
        .SecOCTxSecuredLayerPduRef = 
        {
            .SduDataPtr =               SecPdu4BufferTx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        }
    },
    { /* TxSecuredPduCollection */
        .SecOCAuthPduHeaderLength =     ((uint8) 1),
        .SecOCTxSecuredLayerPduId =     ((uint16) 5),
        .SecOCTxSecuredLayerPduRef = 
        {
            .SduDataPtr =               SecPdu5BufferTx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        }
    },
    /* Ethernet signature streams 1..7 */
    SECOC_SIG_STREAM_ROWS(SECOC_SIG_TX_SECURED_PDU),
    [13] = SECOC_SIG_TX_SECURED_PDU(13)
};



/* Crypto not available now*/

SecOC_TxCryptographicPduType SecOC_TxCryptographicPdu[]=
{
    {
        SECOC_PDUID_COLLECTION_CRYPTO,
        {
            .SduDataPtr =               CryptoPduCollection5BufferTx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 0)
        },
    }
};


/* This is related to crypto(the authentic part)*/

SecOC_TxAuthenticPduType SecOC_TxAuthenticPdu[]=
{
    {
        SECOC_AUTH_PDUHEADER_LENGTH,
        SECOC_PDUID_COLLECTION_AUTH,
        {
            .SduDataPtr =               AuthPduCollection5BufferTx,
            .MetaDataPtr =              NULL,
            .SduLength =                ((PduLengthType) 20)
        },
    }
};



SecOC_TxSecuredPduCollectionType SecOC_TxSecuredPduCollection[]=
{
    {
        &SecOC_TxAuthenticPdu[0],
        &SecOC_TxCryptographicPdu[0],
        &SecOC_UseMessageLink[0],
    }
};


/* This block is commented as the whole authentic I-Pdu is included in authenticating algorithm*/
/*
SecOC_TxPduSecuredAreaType SecOC_TxPduSecuredArea=
{
    SECOC_SECURED_TX_PDULENGTH,
    SECOC_SECURED_TX_PDUOFFSET,
};


SecOC_RxPduSecuredAreaType SecOC_RxPduSecuredArea=
{
    SECOC_SECURED_RX_PDULENGTH,
    SECOC_SECURED_RX_PDUOFFSET,
};
*/

SecOC_TxSecuredPduLayerType SecOC_TxSecuredPduLayer[]=
{
    { /* direct */
        &SecOC_TxSecuredPdu[0],
        NULL,
    },
    { /* for Tp */
        .SecOCTxSecuredPdu =            &SecOC_TxSecuredPdu[1],
        .SecOCTxSecuredPduCollection =  NULL
    },
    { /* for SOAD "Ethernet APIs" */
        .SecOCTxSecuredPdu =            &SecOC_TxSecuredPdu[2],
        .SecOCTxSecuredPduCollection =  NULL
    },
    { /* direct without Trunc-FV and header*/
        .SecOCTxSecuredPdu =            &SecOC_TxSecuredPdu[3],
        .SecOCTxSecuredPduCollection =  NULL
    },
    { /* Tp without header*/
        .SecOCTxSecuredPdu =            &SecOC_TxSecuredPdu[4],
        .SecOCTxSecuredPduCollection =  NULL
    },
    { /* for TxSecuredPduCollection */
        .SecOCTxSecuredPdu =            &SecOC_TxSecuredPdu[5],
        .SecOCTxSecuredPduCollection =  &SecOC_TxSecuredPduCollection[0]
    },
    /* Ethernet signature streams 1..7 */
    SECOC_SIG_STREAM_ROWS(SECOC_SIG_TX_SECURED_LAYER),
    [13] = SECOC_SIG_TX_SECURED_LAYER(13)
};

SecOC_TxPduProcessingType SecOC_TxPduProcessing[] = {
    { /* direct */
        SECOC_AUTHENTICATION_BUILD_ATTEMPTS,
        SECOC_MLDSA_AUTH_INFO_LENGTH_BITS,
        SECOC_TX_DATA_ID,
        SECOC_TX_FRESHNESS_VALUE_ID,
        SECOC_TX_FRESHNESS_VALUE_LENGTH,
        SECOC_TX_FRESHNESS_VALUE_TRUNC_LENGTH,
        SECOC_PROVIDE_TX_TRUNCATED_FRESHNESS_VALUE,
        SECOC_RE_AUTHENTICATE_AFTER_TRIGGER_TRANSMIT,
        SECOC_TX_PDU_UNUSED_AREAS_DEFAULT,
        SECOC_USE_TX_CONFIRMATION,
        /*                                                  SecOCSameBufferPduRef;*/
        &SecOC_TxAuthServiceConfigRef,
        /*                                                  SecOCTxPduMainFunctionRef;*/
        &SecOC_TxAuthenticPduLayer[0],
        &SecOC_TxSecuredPduLayer[0],
        /*&SecOC_TxPduSecuredArea,*/
        /* &EcuC_Pdu,*/
    },
    { /* for Tp */
        .SecOCAuthenticationBuildAttempts =             ((uint16) 3),
        .SecOCAuthInfoTruncLength =                     SECOC_MLDSA_AUTH_INFO_LENGTH_BITS,
        .SecOCDataId =                                  ((uint16) 1),
        .SecOCFreshnessValueId =                        ((uint16) 11),
        .SecOCFreshnessValueLength =                    ((uint8) 24),
        .SecOCFreshnessValueTruncLength =               ((uint8) 18),
        .SecOCProvideTxTruncatedFreshnessValue =        ((boolean) TRUE),
        .SecOCReAuthenticateAfterTriggerTransmit =      ((boolean) FALSE),
        .SecOCTxPduUnusedAreasDefault =                 ((uint8) 0),
        .SecOCUseTxConfirmation =                       ((boolean) FALSE),
        /*                                              SecOCSameBufferPduRef;*/
        .SecOCTxAuthServiceConfigRef =                  &SecOC_TxAuthServiceConfigRef,
        /*                                              SecOCTxPduMainFunctionRef;*/
        .SecOCTxAuthenticPduLayer =                     &SecOC_TxAuthenticPduLayer[1],
        .SecOCTxSecuredPduLayer =                       &SecOC_TxSecuredPduLayer[1],
        /*&SecOC_TxPduSecuredArea,*/
        /* &EcuC_Pdu,*/
    },
    { /* for SOAD "Ethernet APIs" */
        .SecOCAuthenticationBuildAttempts =             ((uint16) 2),
        .SecOCAuthInfoTruncLength =                     SECOC_MLDSA_AUTH_INFO_LENGTH_BITS,
        .SecOCDataId =                                  ((uint16) 2),
        .SecOCFreshnessValueId =                        ((uint16) 12),
        .SecOCFreshnessValueLength =                    ((uint8) 32),
        /* complete value on the wire: with 8 of 32 bits one rejected PDU at a wrap of the low byte
         * left the receiver unable to reconstruct the counter */
        .SecOCFreshnessValueTruncLength =               ((uint8) 32),
        .SecOCProvideTxTruncatedFreshnessValue =        ((boolean) TRUE),
        .SecOCReAuthenticateAfterTriggerTransmit =      ((boolean) FALSE),
        .SecOCTxPduUnusedAreasDefault =                 ((uint8) 0),
        .SecOCUseTxConfirmation =                       ((boolean) FALSE),
        /*                                              SecOCSameBufferPduRef;*/
        .SecOCTxAuthServiceConfigRef =                  &SecOC_TxAuthServiceConfigRef,
        /*                                              SecOCTxPduMainFunctionRef;*/
        .SecOCTxAuthenticPduLayer =                     &SecOC_TxAuthenticPduLayer[2],
        .SecOCTxSecuredPduLayer =                       &SecOC_TxSecuredPduLayer[2],
        /*&SecOC_TxPduSecuredArea,*/
        /* &EcuC_Pdu,*/
    },
    { /* direct without Trunc-FV and header*/
        .SecOCAuthenticationBuildAttempts =             ((uint16) 2),
        .SecOCAuthInfoTruncLength =                     SECOC_MLDSA_AUTH_INFO_LENGTH_BITS,
        .SecOCDataId =                                  ((uint16) 3),
        .SecOCFreshnessValueId =                        ((uint16) 13),
        .SecOCFreshnessValueLength =                    ((uint8) 16),
        .SecOCFreshnessValueTruncLength =               ((uint8) 0),
        .SecOCProvideTxTruncatedFreshnessValue =        ((boolean) FALSE),
        .SecOCReAuthenticateAfterTriggerTransmit =      ((boolean) FALSE),
        .SecOCTxPduUnusedAreasDefault =                 ((uint8) 0),
        .SecOCUseTxConfirmation =                       ((boolean) FALSE),
        /*                                              SecOCSameBufferPduRef;*/
        .SecOCTxAuthServiceConfigRef =                  &SecOC_TxAuthServiceConfigRef,
        /*                                              SecOCTxPduMainFunctionRef;*/
        .SecOCTxAuthenticPduLayer =                     &SecOC_TxAuthenticPduLayer[3],
        .SecOCTxSecuredPduLayer =                       &SecOC_TxSecuredPduLayer[3],
        /*&SecOC_TxPduSecuredArea,*/
        /* &EcuC_Pdu,*/
    },
    { /* Tp without header*/
        .SecOCAuthenticationBuildAttempts =             ((uint16) 2),
        .SecOCAuthInfoTruncLength =                     SECOC_MLDSA_AUTH_INFO_LENGTH_BITS,
        .SecOCDataId =                                  ((uint16) 4),
        .SecOCFreshnessValueId =                        ((uint16) 14),
        .SecOCFreshnessValueLength =                    ((uint8) 32),
        .SecOCFreshnessValueTruncLength =               ((uint8) 30),
        .SecOCProvideTxTruncatedFreshnessValue =        ((boolean) TRUE),
        .SecOCReAuthenticateAfterTriggerTransmit =      ((boolean) FALSE),
        .SecOCTxPduUnusedAreasDefault =                 ((uint8) 0),
        .SecOCUseTxConfirmation =                       ((boolean) FALSE),
        /*                                              SecOCSameBufferPduRef;*/
        .SecOCTxAuthServiceConfigRef =                  &SecOC_TxAuthServiceConfigRef,
        /*                                              SecOCTxPduMainFunctionRef;*/
        .SecOCTxAuthenticPduLayer =                     &SecOC_TxAuthenticPduLayer[4],
        .SecOCTxSecuredPduLayer =                       &SecOC_TxSecuredPduLayer[4],
        /*&SecOC_TxPduSecuredArea,*/
        /* &EcuC_Pdu,*/
    },
    { /* for TxSecuredPduCollection */
        .SecOCAuthenticationBuildAttempts =             ((uint16) 2),
        .SecOCAuthInfoTruncLength =                     SECOC_MLDSA_AUTH_INFO_LENGTH_BITS,
        .SecOCDataId =                                  ((uint16) 5),
        .SecOCFreshnessValueId =                        ((uint16) 15),
        .SecOCFreshnessValueLength =                    ((uint8) 24),
        .SecOCFreshnessValueTruncLength =               ((uint8) 8),
        .SecOCProvideTxTruncatedFreshnessValue =        ((boolean) TRUE),
        .SecOCReAuthenticateAfterTriggerTransmit =      ((boolean) FALSE),
        .SecOCTxPduUnusedAreasDefault =                 ((uint8) 0),
        .SecOCUseTxConfirmation =                       ((boolean) FALSE),
        /*                                              SecOCSameBufferPduRef;*/
        .SecOCTxAuthServiceConfigRef =                  &SecOC_TxAuthServiceConfigRef,
        /*                                              SecOCTxPduMainFunctionRef;*/
        .SecOCTxAuthenticPduLayer =                     &SecOC_TxAuthenticPduLayer[5],
        .SecOCTxSecuredPduLayer =                       &SecOC_TxSecuredPduLayer[5],
        /*&SecOC_TxPduSecuredArea,*/
        /* &EcuC_Pdu,*/
    },
    /* Ethernet signature streams 1..7 */
    SECOC_SIG_STREAM_ROWS(SECOC_SIG_TX_PROCESSING),
    [13] = SECOC_MAC_TX_PROCESSING(13)
};



SecOC_RxPduProcessingType SecOC_RxPduProcessing[] = 
{
    
    { /* direct */     
        SECOC_AUTHDATA_FRESHNESSLEN,
        SECOC_AUTHDATA_FRESHNESS_STARTPOSITION,
        SECOC_AUTHENTICATION_BUILDATTEMPTS,
        SECOC_AUTHENTICATION_VERIFYATTEMPTS,
        SECOC_MLDSA_AUTH_INFO_LENGTH_BITS,
        SECOC_CLIENTSERVER_VERIFICATIONSTATUS_PROPAGATIONMODE,
        SECOC_RX_DATA_ID,
        SECOC_FRESHNESSVALUE_ID,
        SECOC_RX_FRESHNESS_VALUE_LENGTH,
        SECOC_RX_FRESHNESS_VALUE_TRUNCLENGTH,
        SECOC_RECEPTION_OVERFLOW_STRATEGY,
        SECOC_RECEPTION_QUEUESIZE,
        SECOC_USE_AUTHDATA_FRESHNESS,
        SECOC_VERIFICATIONSTATUS_PROPAGATIONMODE,
        &SecOC_RxAuthServiceConfigRef,
        &SecOCMainFunctionRx,
        &SecOC_SameBufferPduRef,
        &SecOC_RxSecuredPduLayer[0],
        &SecOC_RxAuthenticPduLayer[0],
        /*&SecOC_RxPduSecuredArea*/
    },
    { /* for Tp */
        .SecOCAuthDataFreshnessLen =                            ((uint16) 0),
        .SecOCAuthDataFreshnessStartPosition =                  ((uint16) 0),
        .SecOCAuthenticationBuildAttempts =                     ((uint16) 3),
        .SecOCAuthenticationVerifyAttempts =                    ((uint16) 3),
        .SecOCAuthInfoTruncLength =                             SECOC_MLDSA_AUTH_INFO_LENGTH_BITS,
        .SecOCClientServerVerificationStatusPropagationMode =   ((SecOC_StatusPropagationMode_Type) SECOC_BOTH),
        .SecOCDataId =                                          ((uint16) 1),
        .SecOCFreshnessValueId =                                ((uint16) 21),
        .SecOCFreshnessValueLength =                            ((uint8) 24),
        .SecOCFreshnessValueTruncLength =                       ((uint8) 18),
        .SecOCReceptionOverflowStrategy =                       ((SecOC_ReceptionOverflowStrategy_Type) SECOC_REPLACE),
        .SecOCReceptionQueueSize =                              ((uint16) 10),
        .SecOCUseAuthDataFreshness =                            ((boolean) FALSE),
        .SecOCVerificationStatusPropagationMode =               ((SecOC_StatusPropagationMode_Type) SECOC_BOTH),
        .SecOCRxAuthServiceConfigRef =                          &SecOC_RxAuthServiceConfigRef,
        .SecOCRxPduMainFunctionRef =                            &SecOCMainFunctionRx,
        .SecOCRxSecuredPduLayer =                               &SecOC_RxSecuredPduLayer[1],
        .SecOCRxAuthenticPduLayer =                             &SecOC_RxAuthenticPduLayer[1],
        /*&SecOC_RxPduSecuredArea*/
    },
    { /* for SOAD "Ethernet APIs" */
        .SecOCAuthDataFreshnessLen =                            ((uint16) 0),
        .SecOCAuthDataFreshnessStartPosition =                  ((uint16) 0),
        .SecOCAuthenticationBuildAttempts =                     ((uint16) 2),
        .SecOCAuthenticationVerifyAttempts =                    ((uint16) 0), /* [ECUC_SecOC_00080] 0: one verification attempt */
        .SecOCAuthInfoTruncLength =                             SECOC_MLDSA_AUTH_INFO_LENGTH_BITS,
        .SecOCClientServerVerificationStatusPropagationMode =   ((SecOC_StatusPropagationMode_Type) SECOC_BOTH),
        .SecOCDataId =                                          ((uint16) 2),
        .SecOCFreshnessValueId =                                ((uint16) 22),
        .SecOCFreshnessValueLength =                            ((uint8) 32),
        .SecOCFreshnessValueTruncLength =                       ((uint8) 32),
        .SecOCReceptionOverflowStrategy =                       ((SecOC_ReceptionOverflowStrategy_Type) SECOC_REPLACE),
        .SecOCReceptionQueueSize =                              ((uint16) 10),
        .SecOCUseAuthDataFreshness =                            ((boolean) FALSE),
        .SecOCVerificationStatusPropagationMode =               ((SecOC_StatusPropagationMode_Type) SECOC_BOTH),
        .SecOCRxAuthServiceConfigRef =                          &SecOC_RxAuthServiceConfigRefPeer0,
        .SecOCRxPduMainFunctionRef =                            &SecOCMainFunctionRx,
        .SecOCRxSecuredPduLayer =                               &SecOC_RxSecuredPduLayer[2],
        .SecOCRxAuthenticPduLayer =                             &SecOC_RxAuthenticPduLayer[2],
        /*&SecOC_RxPduSecuredArea*/
    },
    { /* direct without Trunc-FV and header*/
        .SecOCAuthDataFreshnessLen =                            ((uint16) 0),
        .SecOCAuthDataFreshnessStartPosition =                  ((uint16) 0),
        .SecOCAuthenticationBuildAttempts =                     ((uint16) 2),
        .SecOCAuthenticationVerifyAttempts =                    ((uint16) 2),
        .SecOCAuthInfoTruncLength =                             SECOC_MLDSA_AUTH_INFO_LENGTH_BITS,
        .SecOCClientServerVerificationStatusPropagationMode =   ((SecOC_StatusPropagationMode_Type) SECOC_BOTH),
        .SecOCDataId =                                          ((uint16) 3),
        .SecOCFreshnessValueId =                                ((uint16) 23),
        .SecOCFreshnessValueLength =                            ((uint8) 16),
        .SecOCFreshnessValueTruncLength =                       ((uint8) 0),
        .SecOCReceptionOverflowStrategy =                       ((SecOC_ReceptionOverflowStrategy_Type) SECOC_REPLACE),
        .SecOCReceptionQueueSize =                              ((uint16) 10),
        .SecOCUseAuthDataFreshness =                            ((boolean) FALSE),
        .SecOCVerificationStatusPropagationMode =               ((SecOC_StatusPropagationMode_Type) SECOC_BOTH),
        .SecOCRxAuthServiceConfigRef =                          &SecOC_RxAuthServiceConfigRef,
        .SecOCRxPduMainFunctionRef =                            &SecOCMainFunctionRx,
        .SecOCRxSecuredPduLayer =                               &SecOC_RxSecuredPduLayer[3],
        .SecOCRxAuthenticPduLayer =                             &SecOC_RxAuthenticPduLayer[3],
        /*&SecOC_RxPduSecuredArea*/
    },
    { /* Tp without header*/
        .SecOCAuthDataFreshnessLen =                            ((uint16) 0),
        .SecOCAuthDataFreshnessStartPosition =                  ((uint16) 0),
        .SecOCAuthenticationBuildAttempts =                     ((uint16) 2),
        .SecOCAuthenticationVerifyAttempts =                    ((uint16) 2),
        .SecOCAuthInfoTruncLength =                             SECOC_MLDSA_AUTH_INFO_LENGTH_BITS,
        .SecOCClientServerVerificationStatusPropagationMode =   ((SecOC_StatusPropagationMode_Type) SECOC_BOTH),
        .SecOCDataId =                                          ((uint16) 4),
        .SecOCFreshnessValueId =                                ((uint16) 24),
        .SecOCFreshnessValueLength =                            ((uint8) 32),
        .SecOCFreshnessValueTruncLength =                       ((uint8) 30),
        .SecOCReceptionOverflowStrategy =                       ((SecOC_ReceptionOverflowStrategy_Type) SECOC_REPLACE),
        .SecOCReceptionQueueSize =                              ((uint16) 10),
        .SecOCUseAuthDataFreshness =                            ((boolean) FALSE),
        .SecOCVerificationStatusPropagationMode =               ((SecOC_StatusPropagationMode_Type) SECOC_BOTH),
        .SecOCRxAuthServiceConfigRef =                          &SecOC_RxAuthServiceConfigRef,
        .SecOCRxPduMainFunctionRef =                            &SecOCMainFunctionRx,
        .SecOCRxSecuredPduLayer =                               &SecOC_RxSecuredPduLayer[4],
        .SecOCRxAuthenticPduLayer =                             &SecOC_RxAuthenticPduLayer[4],
        /*&SecOC_RxPduSecuredArea*/
    },
    { /* for RxSecuredPduCollection" */
        .SecOCAuthDataFreshnessLen =                            ((uint16) 0),
        .SecOCAuthDataFreshnessStartPosition =                  ((uint16) 0),
        .SecOCAuthenticationBuildAttempts =                     ((uint16) 2),
        .SecOCAuthenticationVerifyAttempts =                    ((uint16) 2),
        .SecOCAuthInfoTruncLength =                             SECOC_MLDSA_AUTH_INFO_LENGTH_BITS,
        .SecOCClientServerVerificationStatusPropagationMode =   ((SecOC_StatusPropagationMode_Type) SECOC_BOTH),
        .SecOCDataId =                                          ((uint16) 5),
        .SecOCFreshnessValueId =                                ((uint16) 25),
        .SecOCFreshnessValueLength =                            ((uint8) 24),
        .SecOCFreshnessValueTruncLength =                       ((uint8) 8),
        .SecOCReceptionOverflowStrategy =                       ((SecOC_ReceptionOverflowStrategy_Type) SECOC_REPLACE),
        .SecOCReceptionQueueSize =                              ((uint16) 10),
        .SecOCUseAuthDataFreshness =                            ((boolean) FALSE),
        .SecOCVerificationStatusPropagationMode =               ((SecOC_StatusPropagationMode_Type) SECOC_BOTH),
        .SecOCRxAuthServiceConfigRef =                          &SecOC_RxAuthServiceConfigRef,
        .SecOCRxPduMainFunctionRef =                            &SecOCMainFunctionRx,
        .SecOCRxSecuredPduLayer =                               &SecOC_RxSecuredPduLayer[5],
        .SecOCRxAuthenticPduLayer =                             &SecOC_RxAuthenticPduLayer[5],
        /*&SecOC_RxPduSecuredArea*/
    },
    /* Ethernet signature streams 1..7 */
    SECOC_SIG_STREAM_ROWS(SECOC_SIG_RX_PROCESSING),
    [13] = SECOC_MAC_RX_PROCESSING(13)
};


// cppcheck-suppress misra-c2012-8.4
SecOC_ConfigType SecOC_Config=
{
    &SecOC_General,
    SecOC_TxPduProcessing,
    SecOC_RxPduProcessing,
};

SecOC_TxCountersType SecOC_TxCounters[SECOC_NUM_OF_TX_PDU_PROCESSING] = 
{
    { /* direct */
        /* [SWS_SecOC_00226] */
        .AuthenticationCounter = ((uint16) 0)
    },
    { /* for Tp */
        /* [SWS_SecOC_00226] */
        .AuthenticationCounter = ((uint16) 0)
    },
    { /* for SOAD "Ethernet APIs" */
        /* [SWS_SecOC_00226] */
        .AuthenticationCounter = ((uint16) 0)
    },
    { /* direct without Trunc-FV and header*/
        /* [SWS_SecOC_00226] */
        .AuthenticationCounter = ((uint16) 0)
    },
    { /* Tp without header*/
        /* [SWS_SecOC_00226] */
        .AuthenticationCounter = ((uint16) 0)
    },
    { /* for TxSecuredPduCollection */
        /* [SWS_SecOC_00226] */
        .AuthenticationCounter = ((uint16) 0)
    }
};

SecOC_RxCountersType SecOC_RxCounters[SECOC_NUM_OF_RX_PDU_PROCESSING] =
{
    { /* direct */
        /* [SWS_SecOC_00235] */
        .AuthenticationCounter = ((uint16) 0),
        .VerificationCounter =   ((uint16) 0)
    },
    { /* for Tp */
        /* [SWS_SecOC_00235] */
        .AuthenticationCounter = ((uint16) 0),
        .VerificationCounter =   ((uint16) 0)
    },
    { /* for SOAD "Ethernet APIs" */
        /* [SWS_SecOC_00235] */
        .AuthenticationCounter = ((uint16) 0),
        .VerificationCounter =   ((uint16) 0)
    },
    { /* direct without Trunc-FV and header*/
        /* [SWS_SecOC_00235] */
        .AuthenticationCounter = ((uint16) 0),
        .VerificationCounter =   ((uint16) 0)
    },
    { /* Tp without header*/
        /* [SWS_SecOC_00235] */
        .AuthenticationCounter = ((uint16) 0),
        .VerificationCounter =   ((uint16) 0)
    },
    { /* for RxSecuredPduCollection */
        /* [SWS_SecOC_00235] */
        .AuthenticationCounter = ((uint16) 0),
        .VerificationCounter =   ((uint16) 0)
    }
};