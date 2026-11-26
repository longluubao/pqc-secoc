/* 
 * This is a compliant Freshness Value Manager (FVM) implementation 
 * based on AUTOSAR R19-11 [UC_SecOC_00200]
 */

#include "FVM.h"
#include "SoAd_PduIds.h"
#include "PqcHs/PqcHs.h"
#include <string.h>
#include "SecOC_Debug.h"

/********************************************************************************************************/
/******************************************Global Variables**********************************************/
/********************************************************************************************************/

/* Freshness Counter - Stored in Big Endian (Index 0 is MSB) */
static SecOC_FreshnessArrayType Freshness_Counter[SecOC_FreshnessValue_ID_MAX];
static uint32 Freshness_Counter_length_bits[SecOC_FreshnessValue_ID_MAX];
static boolean Freshness_Counter_Initialized[SecOC_FreshnessValue_ID_MAX];

static sint8 FVM_CompareBigEndian(const uint8* LeftPtr, const uint8* RightPtr, uint32 LengthBytes)
{
    uint32 idx;

    for (idx = 0U; idx < LengthBytes; idx++)
    {
        if (LeftPtr[idx] < RightPtr[idx])
        {
            return (sint8)-1;
        }
        if (LeftPtr[idx] > RightPtr[idx])
        {
            return (sint8)1;
        }
    }

    return (sint8)0;
}

static boolean FVM_AreAllBytesValue(const uint8* DataPtr, uint32 LengthBytes, uint8 Value)
{
    uint32 idx;

    for (idx = 0U; idx < LengthBytes; idx++)
    {
        if (DataPtr[idx] != Value)
        {
            return FALSE;
        }
    }

    return TRUE;
}

/* Session-bound freshness IDs (SoAd_PduIds.h): a 32-bit counter, sent in full, that restarts with
 * every session (FVM_SessionInstall). For these IDs, and only for these:
 *   - a transmit counter holds the next value to send, 1 at the start of a session. The value
 *     after 2^32 - 1 is 0 and is never sent: no freshness value is given out until the next session;
 *   - a receive counter holds the last value accepted, 0 before the first PDU. There is no state in
 *     which any value is accepted. */
static const uint16 FVM_SessionTxIds[SECOC_SESSION_TX_FRESHNESS_COUNT] = { SECOC_SESSION_TX_FRESHNESS_IDS };
static const uint16 FVM_SessionRxIds[SECOC_SESSION_RX_FRESHNESS_COUNT] = { SECOC_SESSION_RX_FRESHNESS_IDS };

static boolean FVM_IsIn(const uint16* IdsPtr, uint32 Count, uint16 Id)
{
    uint32 idx;

    for (idx = 0U; idx < Count; idx++)
    {
        if (IdsPtr[idx] == Id)
        {
            return TRUE;
        }
    }

    return FALSE;
}

/********************************************************************************************************/
/********************************************Functions***************************************************/
/********************************************************************************************************/

/* [SWS_SecOC_91005] Equivalent utility to increment counter */
Std_ReturnType FVM_IncreaseCounter(uint16 SecOCFreshnessValueID) {
    if (SecOCFreshnessValueID >= SecOC_FreshnessValue_ID_MAX) {
        return E_NOT_OK;
    }

    uint32 maxBytes = BIT_TO_BYTES(SECOC_MAX_FRESHNESS_SIZE);
    /* Big Endian Increment: Start from the last byte (LSB) */
    for (int i = (int)maxBytes - 1; i >= 0; i--) {
        Freshness_Counter[SecOCFreshnessValueID][i]++;
        if (Freshness_Counter[SecOCFreshnessValueID][i] != 0U) {
            break; 
        }
    }
    Freshness_Counter_Initialized[SecOCFreshnessValueID] = TRUE;
    return E_OK;
}

/* [SWS_SecOC_91006] Get Freshness for Transmission */
Std_ReturnType FVM_GetTxFreshness(uint16 SecOCFreshnessValueID, uint8* SecOCFreshnessValue, uint32* SecOCFreshnessValueLength) {
    if (SecOCFreshnessValueID >= SecOC_FreshnessValue_ID_MAX) {
        return E_NOT_OK;
    }

    uint32 currentLen = Freshness_Counter_length_bits[SecOCFreshnessValueID];
    /* If length is not initialized, default to maximum allowed size */
    if (currentLen == 0U) {
        currentLen = SECOC_MAX_FRESHNESS_SIZE;
    }

    /* a session counter that has gone through 2^32 - 1: nothing more is authenticated on this
     * session (SecOC drops the Authentic I-PDU, [SWS_SecOC_00229]) */
    if ((FVM_IsIn(FVM_SessionTxIds, SECOC_SESSION_TX_FRESHNESS_COUNT, SecOCFreshnessValueID) == TRUE) &&
        (FVM_AreAllBytesValue(Freshness_Counter[SecOCFreshnessValueID], BIT_TO_BYTES(SECOC_MAX_FRESHNESS_SIZE), 0x00U) == TRUE))
    {
        return E_NOT_OK;
    }

    (void)memcpy(SecOCFreshnessValue, Freshness_Counter[SecOCFreshnessValueID], BIT_TO_BYTES(currentLen));
    *SecOCFreshnessValueLength = currentLen;

    return E_OK;
}

/* shortcut: one peer (0), which is the evaluated set-up; with more peers the freshness ID has to say
 * which peer it belongs to */
boolean FVM_NoSession(void)
{
    uint8 sid[PQCHS_SID_BYTES];
    uint32 installs = 0U;

    /* PqcHs_GetSession fails when the component has no instance for the peer, i.e. is not in use */
    return ((PqcHs_GetSession(0U, sid, &installs) == E_OK) && (PqcHs_IsEstablished(0U) == FALSE)) ? TRUE : FALSE;
}

/* [SWS_SecOC_91007] Get Freshness for Reception (Reconstruction Logic) */
Std_ReturnType FVM_GetRxFreshness(
    uint16 SecOCFreshnessValueID, 
    const uint8* SecOCTruncatedFreshnessValue, 
    uint32 SecOCTruncatedFreshnessValueLength, 
    uint16 SecOCAuthVerifyAttempts, 
    uint8* SecOCFreshnessValue, 
    uint32* SecOCFreshnessValueLength
) {
    if (SecOCFreshnessValueID >= SecOC_FreshnessValue_ID_MAX) {
        return E_NOT_OK;
    }

    uint32 configFullLength = Freshness_Counter_length_bits[SecOCFreshnessValueID];
    if (configFullLength == 0U) {
        configFullLength = SECOC_MAX_FRESHNESS_SIZE;
    }
    
    uint32 truncLen = SecOCTruncatedFreshnessValueLength;
    uint8* lastStored = Freshness_Counter[SecOCFreshnessValueID];
    uint32 fullBytes = BIT_TO_BYTES(configFullLength);
    uint32 truncBytes = BIT_TO_BYTES(truncLen);

    (void)SecOCAuthVerifyAttempts;

    if ((truncLen == 0U) || (truncLen > configFullLength))
    {
        return E_NOT_OK;
    }

    /* no session with the peer: the PDU is dropped [SWS_SecOC_00256], whatever it carries */
    if ((FVM_IsIn(FVM_SessionRxIds, SECOC_SESSION_RX_FRESHNESS_COUNT, SecOCFreshnessValueID) == TRUE) &&
        (FVM_NoSession() == TRUE))
    {
        return E_NOT_OK;
    }

    if ((SecOCTruncatedFreshnessValue == NULL) || (SecOCFreshnessValue == NULL) || (SecOCFreshnessValueLength == NULL))
    {
        return E_NOT_OK;
    }

    /* Case 1: Full Freshness is transmitted [SWS_SecOC_00094] */
    if (truncLen == configFullLength) {
        if (((Freshness_Counter_Initialized[SecOCFreshnessValueID] == TRUE) ||
             (FVM_IsIn(FVM_SessionRxIds, SECOC_SESSION_RX_FRESHNESS_COUNT, SecOCFreshnessValueID) == TRUE)) &&
            (FVM_CompareBigEndian(SecOCTruncatedFreshnessValue, lastStored, fullBytes) <= 0))
        {
            return E_NOT_OK;
        }
        (void)memcpy(SecOCFreshnessValue, SecOCTruncatedFreshnessValue, fullBytes);
    } 
    /* Case 2: Truncated Freshness (Standard Reconstruction) [SWS_SecOC_91007] */
    else {
        uint32 msbLen = configFullLength - truncLen;
        uint32 msbBytes = BIT_TO_BYTES(msbLen);
        uint8 candidateCurrent[BIT_TO_BYTES(SECOC_MAX_FRESHNESS_SIZE)] = {0};
        uint8 candidateRolled[BIT_TO_BYTES(SECOC_MAX_FRESHNESS_SIZE)] = {0};

        /* 1. Copy MSB from the last successfully received/stored counter */
        (void)memcpy(candidateCurrent, lastStored, msbBytes);
        (void)memcpy(&candidateCurrent[fullBytes - truncBytes], SecOCTruncatedFreshnessValue, truncBytes);

        if (Freshness_Counter_Initialized[SecOCFreshnessValueID] == FALSE)
        {
            (void)memcpy(SecOCFreshnessValue, candidateCurrent, fullBytes);
            *SecOCFreshnessValueLength = configFullLength;
            return E_OK;
        }

        if (FVM_CompareBigEndian(candidateCurrent, lastStored, fullBytes) > 0)
        {
            (void)memcpy(SecOCFreshnessValue, candidateCurrent, fullBytes);
            *SecOCFreshnessValueLength = configFullLength;
            return E_OK;
        }

        /*
         * Strict rollover acceptance:
         * only permit rollover when stored LSB is saturated and received LSB restarted to 0.
         * This avoids accepting stale truncated freshness values as "new".
         */
        if ((msbBytes == 0U) ||
            (FVM_AreAllBytesValue(&lastStored[fullBytes - truncBytes], truncBytes, 0xFFU) == FALSE) ||
            (FVM_AreAllBytesValue(SecOCTruncatedFreshnessValue, truncBytes, 0x00U) == FALSE))
        {
            return E_NOT_OK;
        }

        (void)memcpy(candidateRolled, candidateCurrent, fullBytes);
        for (int i = (int)msbBytes - 1; i >= 0; i--)
        {
            candidateRolled[i]++;
            if (candidateRolled[i] != 0U)
            {
                break;
            }
        }

        if (FVM_CompareBigEndian(candidateRolled, lastStored, fullBytes) <= 0)
        {
            return E_NOT_OK;
        }

        (void)memcpy(SecOCFreshnessValue, candidateRolled, fullBytes);
        *SecOCFreshnessValueLength = configFullLength;
        return E_OK;
    }

    *SecOCFreshnessValueLength = configFullLength;
    return E_OK;
}

/* [SWS_SecOC_91003] Get Tx Freshness and Truncated Data */
Std_ReturnType FVM_GetTxFreshnessTruncData(
    uint16 SecOCFreshnessValueID, 
    uint8* SecOCFreshnessValue, 
    uint32* SecOCFreshnessValueLength, 
    uint8* SecOCTruncatedFreshnessValue, 
    uint32* SecOCTruncatedFreshnessValueLength
) {
    Std_ReturnType ret = FVM_GetTxFreshness(SecOCFreshnessValueID, SecOCFreshnessValue, SecOCFreshnessValueLength);
    
    if ((ret == E_OK) && (SecOCTruncatedFreshnessValue != (void*)0)) {
        uint32 truncBits = *SecOCTruncatedFreshnessValueLength;
        uint32 fullBytes = BIT_TO_BYTES(*SecOCFreshnessValueLength);
        uint32 truncBytes = BIT_TO_BYTES(truncBits);
        
        /* Extract the Least Significant Bits (LSB) for truncation as per [SWS_SecOC_00095] */
        (void)memcpy(SecOCTruncatedFreshnessValue, &SecOCFreshnessValue[fullBytes - truncBytes], truncBytes);
    }
    return ret;
}

/* Internal utility to update the local counter notion */
Std_ReturnType FVM_UpdateCounter(uint16 SecOCFreshnessValueID, uint8* SecOCFreshnessValue, uint32 SecOCFreshnessValueLength) {
    if (SecOCFreshnessValueID >= SecOC_FreshnessValue_ID_MAX) {
        return E_NOT_OK;
    }
    uint32 lengthBytes = BIT_TO_BYTES(SecOCFreshnessValueLength);
    (void)memcpy(Freshness_Counter[SecOCFreshnessValueID], SecOCFreshnessValue, lengthBytes);
    Freshness_Counter_length_bits[SecOCFreshnessValueID] = SecOCFreshnessValueLength;
    Freshness_Counter_Initialized[SecOCFreshnessValueID] = TRUE;
    return E_OK;
}

void FVM_SessionInstall(uint16 SecOCFreshnessValueID)
{
    uint32 lengthBytes = BIT_TO_BYTES(SECOC_MAX_FRESHNESS_SIZE);

    if (SecOCFreshnessValueID >= SecOC_FreshnessValue_ID_MAX)
    {
        return;
    }

    (void)memset(Freshness_Counter[SecOCFreshnessValueID], 0, sizeof(Freshness_Counter[SecOCFreshnessValueID]));
    if (FVM_IsIn(FVM_SessionTxIds, SECOC_SESSION_TX_FRESHNESS_COUNT, SecOCFreshnessValueID) == TRUE)
    {
        /* a transmit counter holds the next value to send */
        Freshness_Counter[SecOCFreshnessValueID][lengthBytes - 1U] = 1U;
    }
    Freshness_Counter_length_bits[SecOCFreshnessValueID] = SECOC_MAX_FRESHNESS_SIZE;
    Freshness_Counter_Initialized[SecOCFreshnessValueID] = TRUE;
}
