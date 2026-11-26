/********************************************************************************************************/
/*  File:   include/App/App_Hs.h                                                                          */
/*  Brief:  The gateway's record of the handshake: one row of handshake.csv (DATA_SCHEMA.md) per attempt  */
/*          the handshake component reports, and a line on the console for every key installation        */
/*          (session identifier and installation counter, the oracle of the on-wire tests).              */
/*  SECOC_APP_HS_CSV   path of handshake.csv (not set: console only)                                      */
/********************************************************************************************************/
#ifndef INCLUDE_APP_APP_HS_H_
#define INCLUDE_APP_APP_HS_H_

void App_Hs_Init(void);
void App_Hs_MainFunction(void);

#endif /* INCLUDE_APP_APP_HS_H_ */
