/********************************************************************************************************/
/*  PqcHs configuration of the evaluated set-up: one peer (Csm peer 0) on one socket connection; the      */
/*  transmitting gateway is the initiator, the receiving gateway the responder.                           */
/********************************************************************************************************/

#include "PqcHs/PqcHs.h"

_Static_assert((PQCHS_T_A_MS > PQCHS_T_PEND_MS) && (PQCHS_T_A_MS > SOAD_PQC_HS_MIN_INTERVAL_MS),
               "T_A must exceed T_pend and T_min");
_Static_assert(PQCHS_T_FLUSH_MS < PQCHS_T_PEND_MS, "T_flush must stay below T_pend");

static const uint16 PqcHs_FreshnessIds[PQCHS_CFG_NUM_SESSION_FRESHNESS_IDS] = { PQCHS_CFG_SESSION_FRESHNESS_IDS };

static const PqcHs_InstanceConfigType PqcHs_InstanceConfig[1] =
{
    {
        PQCHS_CFG_ROLE,
        0U,
        PQCHS_CFG_SOCON_ID,
#if (SECOC_ROLE_SENDER == TRUE)
        { SOAD_PDUID_HS_M1, SOAD_PDUID_HS_M3 },
        { SOAD_PDUID_HS_M2, SOAD_PDUID_HS_M4 },
#else
        { SOAD_PDUID_HS_M2, SOAD_PDUID_HS_M4 },
        { SOAD_PDUID_HS_M1, SOAD_PDUID_HS_M3 },
#endif
        /* the two K_auth keys of peer 0, and its confirmation-key slot with the two full-tag jobs */
        CSM_KEYID_MAC_TX_PEER(0U),
        CSM_KEYID_MAC_RX_PEER(0U),
        CSM_KEYID_HS_KC_PEER(0U),
        CSM_JOBID_HS_KC_GENERATE_PEER(0U),
        CSM_JOBID_HS_KC_VERIFY_PEER(0U),
        PqcHs_FreshnessIds,
        PQCHS_CFG_NUM_SESSION_FRESHNESS_IDS
    }
};

const PqcHs_ConfigType PqcHs_Config =
{
    PqcHs_InstanceConfig,
    1U,
    { PQCHS_T_PEND_MS, SOAD_PQC_HS_MIN_INTERVAL_MS, PQCHS_T_A_MS, PQCHS_T_FLUSH_MS }
};
