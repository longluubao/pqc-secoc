/********************************************************************************************************/
/*********************************************SecOC_PQC_Cfg.h*********************************************/
/********************************************************************************************************/
/**
 * @file SecOC_PQC_Cfg.h
 * @brief Post-Quantum Cryptography Configuration for SecOC
 */

#ifndef SECOC_PQC_CFG_H
#define SECOC_PQC_CFG_H

/********************************************************************************************************/
/***********************************************DEFINES***************************************************/
/********************************************************************************************************/

/**
 * @brief Legacy switch, read only by the as-found unit tests (expectations for signature PDUs).
 * The BSW no longer uses it: MAC or signature is chosen per PDU by the Csm job the PDU
 * references (SecOC_Lcfg.c).
 */
#define SECOC_USE_PQC_MODE              TRUE

/**
 * @brief Enable ML-KEM key exchange
 * Requires SECOC_USE_PQC_MODE = TRUE
 */
#define SECOC_USE_MLKEM_KEY_EXCHANGE    TRUE

/**
 * @brief Ethernet Gateway mode (removes CAN/FlexRay dependencies)
 */
#define SECOC_ETHERNET_GATEWAY_MODE     TRUE

/**
 * @brief Maximum PDU size for PQC signatures
 * ML-DSA-65 signature is 3309 bytes, so total PDU can be large
 */
#define SECOC_PQC_MAX_PDU_SIZE          8192U

/**
 * @brief ML-DSA key storage directory
 * Override via CMake: -DPQC_MLDSA_KEY_DIR="/custom/path/"
 * Default: /etc/secoc/keys/ on Pi 4, CWD on simulation/Windows
 * MUST end with a trailing slash.
 */
#ifndef PQC_MLDSA_KEY_DIRECTORY
    #if defined(LINUX)
        #define PQC_MLDSA_KEY_DIRECTORY     "/etc/secoc/keys/"
    #else
        #define PQC_MLDSA_KEY_DIRECTORY     "./"
    #endif
#endif

#endif /* SECOC_PQC_CFG_H */
