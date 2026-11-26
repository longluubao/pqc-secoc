/**
 * @file Wdg_Pi4.c
 * @brief Watchdog Driver Implementation for Raspberry Pi 4
 * @details Uses the Linux watchdog API (/dev/watchdog) backed by the
 *          BCM2835 hardware watchdog on the Pi 4.
 *          Requires: kernel CONFIG_WATCHDOG=y, CONFIG_BCM2835_WDT=y.
 *
 *          If /dev/watchdog is not available (e.g. in development),
 *          the driver operates in software-only fallback mode.
 */

/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/

#include "Mcal/Wdg.h"
#include "Det/Det.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/watchdog.h>

/********************************************************************************************************/
/******************************************GlobalVaribles************************************************/
/********************************************************************************************************/

static boolean Wdg_Initialized = FALSE;
static Wdg_ModeType Wdg_CurrentMode = WDG_MODE_OFF;
static int Wdg_Fd = -1;
static uint8 Wdg_SlowTimeout = 15U;
static uint8 Wdg_FastTimeout = 5U;

/********************************************************************************************************/
/***************************************ForwardDeclarations**********************************************/
/********************************************************************************************************/

void Wdg_Init(const Wdg_ConfigType* ConfigPtr);
void Wdg_DeInit(void);
Std_ReturnType Wdg_SetMode(Wdg_ModeType Mode);
void Wdg_Trigger(void);

/********************************************************************************************************/
/********************************************Functions***************************************************/
/********************************************************************************************************/

void Wdg_Init(const Wdg_ConfigType* ConfigPtr)
{
    if (Wdg_Initialized != FALSE)
    {
        (void)Det_ReportError(WDG_MODULE_ID, MCAL_INSTANCE_ID, WDG_SID_INIT, WDG_E_DRIVER_STATE);
        return;
    }

    if (ConfigPtr != NULL)
    {
        Wdg_SlowTimeout = ConfigPtr->SlowTimeoutSec;
        Wdg_FastTimeout = ConfigPtr->FastTimeoutSec;
    }
    else
    {
        Wdg_SlowTimeout = MCAL_WDG_TIMEOUT_SEC;
        Wdg_FastTimeout = 5U;
    }

    /* DEPLOYMENT-CRITICAL: do NOT open /dev/watchdog by default.
     * On Pi 4 the BCM2835 watchdog driver AUTO-ARMS the hardware watchdog
     * the moment the device is opened (default timeout ~15s). If the SecOC
     * process is killed by SIGKILL (e.g. by `timeout` or kernel OOM), the
     * atexit() / signal handlers in main.c CANNOT run, the magic 'V' close
     * character is never written, and the kernel HARD-RESETS the Pi.
     *
     * For the Pi-to-Pi thesis Eth-only runs we use software-only mode:
     * no /dev/watchdog open, no kernel arming, no risk of reset.
     *
     * To opt back into the real hardware watchdog (production deployment),
     * compile with -DMCAL_WDG_HARDWARE. */
#ifdef MCAL_WDG_HARDWARE
    Wdg_Fd = open(MCAL_WDG_DEVICE, O_RDWR);
    if (Wdg_Fd < 0)
    {
        (void)printf("[Wdg] /dev/watchdog not available, running in software-only mode\n");
    }
#else
    Wdg_Fd = -1;
    (void)printf("[Wdg] software-only mode (hardware watchdog disabled at compile time; "
                 "rebuild with -DMCAL_WDG_HARDWARE for production)\n");
#endif

    Wdg_CurrentMode = WDG_MODE_OFF;
    Wdg_Initialized = TRUE;

    /* Apply initial mode if specified */
    if ((ConfigPtr != NULL) && (ConfigPtr->InitialMode != WDG_MODE_OFF))
    {
        (void)Wdg_SetMode(ConfigPtr->InitialMode);
    }
}

void Wdg_DeInit(void)
{
    if (Wdg_Initialized == FALSE)
    {
        (void)Det_ReportError(WDG_MODULE_ID, MCAL_INSTANCE_ID, WDG_SID_DEINIT, WDG_E_UNINIT);
        return;
    }

    if (Wdg_Fd >= 0)
    {
        /* Write magic close character 'V' to disable watchdog on close */
        (void)write(Wdg_Fd, "V", 1);
        (void)close(Wdg_Fd);
        Wdg_Fd = -1;
    }

    Wdg_CurrentMode = WDG_MODE_OFF;
    Wdg_Initialized = FALSE;
}

Std_ReturnType Wdg_SetMode(Wdg_ModeType Mode)
{
    int timeout;

    if (Wdg_Initialized == FALSE)
    {
        (void)Det_ReportError(WDG_MODULE_ID, MCAL_INSTANCE_ID, WDG_SID_SET_MODE, WDG_E_UNINIT);
        return E_NOT_OK;
    }

    if (Mode > WDG_MODE_FAST)
    {
        (void)Det_ReportError(WDG_MODULE_ID, MCAL_INSTANCE_ID, WDG_SID_SET_MODE, WDG_E_PARAM_MODE);
        return E_NOT_OK;
    }

    if (Mode == WDG_MODE_OFF)
    {
        /* Disable the watchdog by writing the magic close character */
        if (Wdg_Fd >= 0)
        {
            (void)write(Wdg_Fd, "V", 1);
            (void)close(Wdg_Fd);
            Wdg_Fd = -1;
        }
        Wdg_CurrentMode = WDG_MODE_OFF;
        return E_OK;
    }

    /* Re-open if needed (only when hardware watchdog is opt-in via compile flag).
     * In software-only mode (default for Pi-to-Pi thesis runs), we just track
     * the mode in RAM and return E_OK so EcuM startup does not fail. */
#ifdef MCAL_WDG_HARDWARE
    if (Wdg_Fd < 0)
    {
        Wdg_Fd = open(MCAL_WDG_DEVICE, O_RDWR);
        if (Wdg_Fd < 0)
        {
            return E_NOT_OK;
        }
    }
#else
    if (Wdg_Fd < 0)
    {
        Wdg_CurrentMode = Mode;
        return E_OK;  /* software-only mode: track state, no kernel call */
    }
#endif

    /* Set the timeout based on mode */
    if (Mode == WDG_MODE_SLOW)
    {
        timeout = (int)Wdg_SlowTimeout;
    }
    else
    {
        timeout = (int)Wdg_FastTimeout;
    }

    if (ioctl(Wdg_Fd, WDIOC_SETTIMEOUT, &timeout) != 0)
    {
        return E_NOT_OK;
    }

    Wdg_CurrentMode = Mode;
    return E_OK;
}

void Wdg_Trigger(void)
{
    if (Wdg_Initialized == FALSE)
    {
        return;
    }

    if ((Wdg_CurrentMode != WDG_MODE_OFF) && (Wdg_Fd >= 0))
    {
        /* Kick the watchdog by writing any data */
        (void)write(Wdg_Fd, "\0", 1);
    }
}
