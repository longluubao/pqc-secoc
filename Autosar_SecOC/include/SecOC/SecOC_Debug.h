#ifndef SECOC_DEBUG_H
#define SECOC_DEBUG_H

/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/

#include <stdio.h>        /*in order to use printf statements for debugging*/

/********************************************************************************************************/
/************************************************Defines*************************************************/
/********************************************************************************************************/

#define RELEASE                    

#define DEBUG_ALL                   /*Required: makes STATIC macro empty so externs in SecOC.h match SecOC.c. SecOC_test() in main.c was replaced with role-aware logging.*/

#ifdef DEBUG_ALL
/* cppcheck-suppress misra-c2012-20.5 */
#undef RELEASE
#endif

/* CMake -DSECOC_QUIET=ON: same build without the per-cycle debug prints */
#if defined(DEBUG_ALL) && !defined(SECOC_QUIET)
#define SECOC_DEBUG                 /* Debug for SecOC */
#define FV_DEBUG                    /* Debug for FreshnessValueManger */
#define CANIF_DEBUG                 /* Debug for CanIF */
#define CANTP_DEBUG                 /* Debug for CanTP */
#define COM_DEBUG                   /* Debug for COM */
#define DCM_DEBUG                   /* Debug for DCM */ 
#define SOAD_DEBUG                  /* Debug for SoAd */ 
#define ETHERNET_DEBUG              /* Debug for Ethernet */ 
#define PDUR_DEBUG                  /* Debug for PduR */ 
#define COUNTERS_DEBUG              /* Debug for Auth && verify Counters */  
#define MAC_DEBUG                   /* Debug for MAC gerenration */  
#define PDU_COLLECTION_DEBUG        /* Debug for PDU Collection */  
#define SCHEDULER_DEBUG             /* Debug for Schedular */  
#endif

/*#define SCHEDULER_ON*/

#endif