/********************************************************************************************************/
/******************************************ethernet_test_shim.c*******************************************/
/********************************************************************************************************/
/**
 * @file   ethernet_test_shim.c
 * @brief  Failure-injection shim wrapping ethernet_send for tests.
 *
 * When SECOC_ENABLE_TEST_SHIM is defined at compile time AND the
 * environment variable SECOC_TEST_INJECT is set at run time, this shim
 * intercepts ethernet_send() and synthesises faults that are otherwise
 * hard to reproduce in CI:
 *
 *   - SECOC_TEST_INJECT=PEER_UNREACHABLE : returns -1, errno=EHOSTUNREACH
 *   - SECOC_TEST_INJECT=PARTIAL_WRITE    : forwards only the first len/2
 *                                          bytes to the real transmit
 *   - <anything else>                    : passthrough to the real impl
 *
 * The shim assumes the real implementation has been renamed to
 * ethernet_send_real() at link time (see test/CMakeLists.txt
 * objcopy/--wrap or per-target rename).
 *
 * If SECOC_ENABLE_TEST_SHIM is not defined the file compiles to nothing,
 * so it is safe to add it unconditionally to the build sources.
 *
 * Owner: TL-QA / Failure-injection
 */

#if defined(SECOC_ENABLE_TEST_SHIM)

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* The real, unwrapped ethernet_send. The build system arranges for the
 * production ethernet_send to be visible under this name (e.g. by
 * --wrap=ethernet_send, by objcopy --redefine-sym, or by renaming the
 * symbol in source/Ethernet/ethernet.c when SECOC_ENABLE_TEST_SHIM is
 * defined). */
extern int ethernet_send_real(const unsigned char* data, unsigned int len);

/**
 * @brief Wrapper around ethernet_send for fault injection.
 *
 * @param[in] data Pointer to bytes to transmit.
 * @param[in] len  Number of bytes.
 * @return Number of bytes accepted, or -1 on simulated failure.
 */
int ethernet_send(const unsigned char* data, unsigned int len)
{
    const char* mode = getenv("SECOC_TEST_INJECT");

    /* No injection requested -> straight passthrough. */
    if (mode == NULL) {
        return ethernet_send_real(data, len);
    }

    /* Simulated network black-hole. */
    if (strcmp(mode, "PEER_UNREACHABLE") == 0) {
        errno = EHOSTUNREACH;
        return -1;
    }

    /* Simulated short write — only the first half makes it out. */
    if (strcmp(mode, "PARTIAL_WRITE") == 0) {
        return ethernet_send_real(data, len / 2U);
    }

    /* Unknown injection token -> behave as passthrough rather than
       silently masking real send failures. */
    return ethernet_send_real(data, len);
}

#endif  /* SECOC_ENABLE_TEST_SHIM */
