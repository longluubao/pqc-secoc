/********************************************************************************************************/
/***********************************************PQC.c*****************************************************/
/********************************************************************************************************/
/**
 * @file PQC.c
 * @brief Post-Quantum Cryptography wrapper implementation
 * @details Wraps liboqs ML-KEM and ML-DSA for AUTOSAR SecOC
 */

/********************************************************************************************************/
/************************************************INCLUDES************************************************/
/********************************************************************************************************/
#include "PQC/PQC.h"
#include "SecOC/SecOC_PQC_Cfg.h"
#include "Perf/SecOC_Perf.h"
#include <string.h>
#include <stdio.h>

/* liboqs includes */
#include <oqs/oqs.h>

#if defined(LINUX)
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

/* External API declarations (MISRA 8.4 visibility). */
Std_ReturnType PQC_Init(void);
Std_ReturnType PQC_MLKEM_KeyGen(uint8* PublicKey, uint8* SecretKey);
Std_ReturnType PQC_MLKEM_Encapsulate(const uint8* PublicKey, uint8* Ciphertext,
                                     uint8* SharedSecret);
Std_ReturnType PQC_MLKEM_Decapsulate(const uint8* Ciphertext,
                                     const uint8* SecretKey,
                                     uint8* SharedSecret);
Std_ReturnType PQC_MLDSA_KeyGen(PQC_MLDSA_KeyPairType* KeyPair);
Std_ReturnType PQC_MLDSA_SaveKeys(const PQC_MLDSA_KeyPairType* KeyPair,
                                  const char* filePrefix);
Std_ReturnType PQC_MLDSA_LoadKeys(PQC_MLDSA_KeyPairType* KeyPair,
                                  const char* filePrefix);
Std_ReturnType PQC_MLDSA_Sign(const uint8* Message, uint32 MessageLength,
                              const uint8* Context, uint32 ContextLength,
                              const uint8* SecretKey, uint8* Signature,
                              uint32* SignatureLength);
Std_ReturnType PQC_MLDSA_Verify(const uint8* Message, uint32 MessageLength,
                                const uint8* Context, uint32 ContextLength,
                                const uint8* Signature, uint32 SignatureLength,
                                const uint8* PublicKey);
Std_ReturnType PQC_MLDSA_LoadPeerPublicKey(uint8 peerId, uint8* publicKeyOut,
                                            uint32 publicKeyOutLength);

/********************************************************************************************************/
/******************************************GLOBAL VARIABLES**********************************************/
/********************************************************************************************************/
static boolean PQC_Initialized = FALSE;
/* Created once in PQC_Init and kept: no allocation in the sign, verify or KEM calls. */
static OQS_SIG* PQC_SigCtx = NULL;
static OQS_KEM* PQC_KemCtx = NULL;

/********************************************************************************************************/
/**********************************************FUNCTIONS**************************************************/
/********************************************************************************************************/

/**
 * @brief Initialize the PQC module
 */
Std_ReturnType PQC_Init(void)
{
    if (PQC_Initialized == TRUE)
    {
        return PQC_E_OK;
    }

#if defined(LINUX)
    /* Tighten file-creation umask so that any subsequent open(O_CREAT)
     * defaults to owner-only; this is a defense-in-depth backstop in
     * addition to the explicit fchmod() in PQC_MLDSA_SaveKeys(). */
    (void)umask(0077);
#endif

    if (PQC_KemCtx == NULL)
    {
        PQC_KemCtx = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    }
    if ((PQC_KemCtx == NULL) ||
        (PQC_KemCtx->length_public_key != PQC_MLKEM_PUBLIC_KEY_BYTES) ||
        (PQC_KemCtx->length_secret_key != PQC_MLKEM_SECRET_KEY_BYTES) ||
        (PQC_KemCtx->length_ciphertext != PQC_MLKEM_CIPHERTEXT_BYTES) ||
        (PQC_KemCtx->length_shared_secret != PQC_MLKEM_SHARED_SECRET_BYTES))
    {
        (void)printf("ERROR: ML-KEM-768 is not available in liboqs with the expected sizes\n");
        return PQC_E_NOT_OK;
    }

    if (PQC_SigCtx == NULL)
    {
        PQC_SigCtx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    }
    /* sig_with_ctx_support: the per-PDU and the handshake signatures are separated by the context */
    if ((PQC_SigCtx == NULL) ||
        (PQC_SigCtx->sig_with_ctx_support == false) ||
        (PQC_SigCtx->length_public_key != PQC_MLDSA_PUBLIC_KEY_BYTES) ||
        (PQC_SigCtx->length_secret_key != PQC_MLDSA_SECRET_KEY_BYTES) ||
        (PQC_SigCtx->length_signature != PQC_MLDSA_SIGNATURE_BYTES))
    {
        (void)printf("ERROR: ML-DSA-65 with context strings is not available in liboqs with the expected sizes\n");
        return PQC_E_NOT_OK;
    }

    PQC_Initialized = TRUE;
    (void)printf("PQC Module initialized successfully\n");
    (void)printf("  ML-KEM-768: Public Key=%u bytes, Ciphertext=%u bytes\n",
                 PQC_MLKEM_PUBLIC_KEY_BYTES, PQC_MLKEM_CIPHERTEXT_BYTES);
    (void)printf("  ML-DSA-65: Public Key=%u bytes, Signature=%u bytes\n",
                 PQC_MLDSA_PUBLIC_KEY_BYTES, PQC_MLDSA_SIGNATURE_BYTES);

    return PQC_E_OK;
}

/**
 * @brief Generate ML-KEM-768 key pair
 */
Std_ReturnType PQC_MLKEM_KeyGen(uint8* PublicKey, uint8* SecretKey)
{
    if (PQC_Initialized == FALSE)
    {
        return PQC_E_NOT_OK;
    }

    if ((PublicKey == NULL) || (SecretKey == NULL))
    {
        return PQC_E_INVALID_PARAM;
    }

    if (OQS_KEM_keypair(PQC_KemCtx, PublicKey, SecretKey) != OQS_SUCCESS)
    {
        return PQC_E_NOT_OK;
    }

    return PQC_E_OK;
}

/**
 * @brief ML-KEM-768 encapsulation
 */
Std_ReturnType PQC_MLKEM_Encapsulate(
    const uint8* PublicKey,
    uint8* Ciphertext,
    uint8* SharedSecret)
{
    if (PQC_Initialized == FALSE)
    {
        return PQC_E_NOT_OK;
    }

    if ((PublicKey == NULL) || (Ciphertext == NULL) || (SharedSecret == NULL))
    {
        return PQC_E_INVALID_PARAM;
    }

    if (OQS_KEM_encaps(PQC_KemCtx, Ciphertext, SharedSecret, PublicKey) != OQS_SUCCESS)
    {
        return PQC_E_NOT_OK;
    }

    return PQC_E_OK;
}

/**
 * @brief ML-KEM-768 decapsulation
 */
Std_ReturnType PQC_MLKEM_Decapsulate(
    const uint8* Ciphertext,
    const uint8* SecretKey,
    uint8* SharedSecret)
{
    if (PQC_Initialized == FALSE)
    {
        return PQC_E_NOT_OK;
    }

    if ((Ciphertext == NULL) || (SecretKey == NULL) || (SharedSecret == NULL))
    {
        return PQC_E_INVALID_PARAM;
    }

    if (OQS_KEM_decaps(PQC_KemCtx, SharedSecret, Ciphertext, SecretKey) != OQS_SUCCESS)
    {
        return PQC_E_NOT_OK;
    }

    return PQC_E_OK;
}

/**
 * @brief Generate ML-DSA-65 key pair
 */
Std_ReturnType PQC_MLDSA_KeyGen(PQC_MLDSA_KeyPairType* KeyPair)
{
    if (PQC_Initialized == FALSE)
    {
        (void)printf("ERROR: PQC not initialized\n");
        return PQC_E_NOT_OK;
    }

    if (KeyPair == NULL)
    {
        return PQC_E_INVALID_PARAM;
    }

    if (OQS_SIG_keypair(PQC_SigCtx, KeyPair->PublicKey, KeyPair->SecretKey) != OQS_SUCCESS)
    {
        (void)printf("ERROR: ML-DSA keypair generation failed\n");
        return PQC_E_NOT_OK;
    }

    return PQC_E_OK;
}

/**
 * @brief Ensure the key storage directory exists (Linux only)
 */
static Std_ReturnType PQC_EnsureKeyDirectory(void)
{
#if defined(LINUX)
    struct stat st;
    if (stat(PQC_MLDSA_KEY_DIRECTORY, &st) != 0)
    {
        /* Attempt to create directory with owner-only permissions */
        if (mkdir(PQC_MLDSA_KEY_DIRECTORY, 0700) != 0)
        {
            int saved_errno = errno;
            if (saved_errno == EACCES)
            {
                (void)printf("ERROR: Cannot create key directory %s (EACCES).\n",
                             PQC_MLDSA_KEY_DIRECTORY);
                (void)printf("       Run as integrator: sudo install -d -m 0750 -o root -g secoc %s\n",
                             PQC_MLDSA_KEY_DIRECTORY);
                (void)printf("       and add the SecOC runtime user to the 'secoc' group.\n");
            }
            else
            {
                (void)printf("ERROR: Cannot create key directory %s (errno=%d)\n",
                             PQC_MLDSA_KEY_DIRECTORY, saved_errno);
            }
            return PQC_E_NOT_OK;
        }
        (void)printf("Created key directory: %s\n", PQC_MLDSA_KEY_DIRECTORY);
    }
#endif
    return PQC_E_OK;
}

/**
 * @brief Save ML-DSA-65 key pair to files
 * @details Keys are stored in PQC_MLDSA_KEY_DIRECTORY (configurable).
 *          On Linux, uses open()+fchmod()+write()+close() with explicit
 *          0644 (public) / 0600 (secret) modes, and verifies the secret
 *          file ends up at 0600 via stat(); a wrong mode triggers unlink+fail.
 */
Std_ReturnType PQC_MLDSA_SaveKeys(const PQC_MLDSA_KeyPairType* KeyPair, const char* filePrefix)
{
    char filename[512];

    if ((KeyPair == NULL) || (filePrefix == NULL))
    {
        return PQC_E_INVALID_PARAM;
    }

    /* Ensure key directory exists */
    (void)PQC_EnsureKeyDirectory();

#if defined(LINUX)
    {
        int fd;
        ssize_t writeRc;
        struct stat sb;

        /* Save public key (0644) */
        (void)snprintf(filename, sizeof(filename), "%s%s.pub",
                       PQC_MLDSA_KEY_DIRECTORY, filePrefix);
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0)
        {
            (void)printf("ERROR: Failed to create public key file: %s (errno=%d)\n", filename, errno);
            return PQC_E_NOT_OK;
        }
        if (fchmod(fd, 0644) != 0)
        {
            (void)printf("ERROR: fchmod 0644 on %s failed (errno=%d)\n", filename, errno);
            (void)close(fd);
            (void)unlink(filename);
            return PQC_E_NOT_OK;
        }
        writeRc = write(fd, KeyPair->PublicKey, PQC_MLDSA_PUBLIC_KEY_BYTES);
        (void)close(fd);
        if (writeRc != (ssize_t)PQC_MLDSA_PUBLIC_KEY_BYTES)
        {
            (void)printf("ERROR: Failed to write complete public key\n");
            (void)unlink(filename);
            return PQC_E_NOT_OK;
        }

        /* Save secret key (0600) */
        (void)snprintf(filename, sizeof(filename), "%s%s.key",
                       PQC_MLDSA_KEY_DIRECTORY, filePrefix);
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
        {
            (void)printf("ERROR: Failed to create secret key file: %s (errno=%d)\n", filename, errno);
            return PQC_E_NOT_OK;
        }
        if (fchmod(fd, 0600) != 0)
        {
            (void)printf("ERROR: fchmod 0600 on %s failed (errno=%d)\n", filename, errno);
            (void)close(fd);
            (void)unlink(filename);
            return PQC_E_NOT_OK;
        }
        writeRc = write(fd, KeyPair->SecretKey, PQC_MLDSA_SECRET_KEY_BYTES);
        (void)close(fd);
        if (writeRc != (ssize_t)PQC_MLDSA_SECRET_KEY_BYTES)
        {
            (void)printf("ERROR: Failed to write complete secret key\n");
            (void)unlink(filename);
            return PQC_E_NOT_OK;
        }

        /* Verify resulting mode is exactly 0600 — otherwise treat as security
         * regression (e.g. SUID/world-readable inherited from a broken umask)
         * and refuse to leave the key on disk. */
        if (stat(filename, &sb) != 0)
        {
            (void)printf("ERROR: stat() on secret key %s failed (errno=%d)\n", filename, errno);
            (void)unlink(filename);
            return PQC_E_NOT_OK;
        }
        if ((sb.st_mode & 07777) != 0600)
        {
            (void)printf("ERROR: Secret key %s has unexpected mode 0%o (want 0600). Removing.\n",
                         filename, (unsigned)(sb.st_mode & 07777));
            (void)unlink(filename);
            return PQC_E_NOT_OK;
        }
    }
#else
    {
        FILE* fp;
        size_t written;

        /* Save public key */
        (void)snprintf(filename, sizeof(filename), "%s%s.pub",
                       PQC_MLDSA_KEY_DIRECTORY, filePrefix);
        fp = fopen(filename, "wb");
        if (fp == NULL)
        {
            (void)printf("ERROR: Failed to create public key file: %s\n", filename);
            return PQC_E_NOT_OK;
        }
        written = fwrite(KeyPair->PublicKey, 1, PQC_MLDSA_PUBLIC_KEY_BYTES, fp);
        (void)fclose(fp);
        if (written != PQC_MLDSA_PUBLIC_KEY_BYTES)
        {
            (void)printf("ERROR: Failed to write complete public key\n");
            return PQC_E_NOT_OK;
        }

        /* Save secret key */
        (void)snprintf(filename, sizeof(filename), "%s%s.key",
                       PQC_MLDSA_KEY_DIRECTORY, filePrefix);
        fp = fopen(filename, "wb");
        if (fp == NULL)
        {
            (void)printf("ERROR: Failed to create secret key file: %s\n", filename);
            return PQC_E_NOT_OK;
        }
        written = fwrite(KeyPair->SecretKey, 1, PQC_MLDSA_SECRET_KEY_BYTES, fp);
        (void)fclose(fp);
        if (written != PQC_MLDSA_SECRET_KEY_BYTES)
        {
            (void)printf("ERROR: Failed to write complete secret key\n");
            return PQC_E_NOT_OK;
        }
    }
#endif

    (void)printf("ML-DSA keys saved to %s%s.pub and %s%s.key\n",
                 PQC_MLDSA_KEY_DIRECTORY, filePrefix,
                 PQC_MLDSA_KEY_DIRECTORY, filePrefix);
    return PQC_E_OK;
}

/**
 * @brief Load ML-DSA-65 key pair from files
 * @details Keys are loaded from PQC_MLDSA_KEY_DIRECTORY (configurable).
 */
Std_ReturnType PQC_MLDSA_LoadKeys(PQC_MLDSA_KeyPairType* KeyPair, const char* filePrefix)
{
    FILE* fp;
    char filename[512];
    size_t read_bytes;

    if ((KeyPair == NULL) || (filePrefix == NULL))
    {
        return PQC_E_INVALID_PARAM;
    }

    /* Load public key from configured directory */
    (void)snprintf(filename, sizeof(filename), "%s%s.pub",
                   PQC_MLDSA_KEY_DIRECTORY, filePrefix);
    fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        /* File doesn't exist - not an error, caller will generate new keys */
        return PQC_E_NOT_OK;
    }
    read_bytes = fread(KeyPair->PublicKey, 1, PQC_MLDSA_PUBLIC_KEY_BYTES, fp);
    (void)fclose(fp);
    if (read_bytes != PQC_MLDSA_PUBLIC_KEY_BYTES)
    {
        (void)printf("ERROR: Failed to read complete public key from %s\n", filename);
        return PQC_E_NOT_OK;
    }

    /* Load secret key from configured directory */
    (void)snprintf(filename, sizeof(filename), "%s%s.key",
                   PQC_MLDSA_KEY_DIRECTORY, filePrefix);
    fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        (void)printf("ERROR: Secret key file not found: %s\n", filename);
        return PQC_E_NOT_OK;
    }
    read_bytes = fread(KeyPair->SecretKey, 1, PQC_MLDSA_SECRET_KEY_BYTES, fp);
    (void)fclose(fp);
    if (read_bytes != PQC_MLDSA_SECRET_KEY_BYTES)
    {
        (void)printf("ERROR: Failed to read complete secret key from %s\n", filename);
        return PQC_E_NOT_OK;
    }

    (void)printf("ML-DSA keys loaded from %s%s.pub and %s%s.key\n",
                 PQC_MLDSA_KEY_DIRECTORY, filePrefix,
                 PQC_MLDSA_KEY_DIRECTORY, filePrefix);
    return PQC_E_OK;
}

/**
 * @brief Generate ML-DSA-65 digital signature
 */
Std_ReturnType PQC_MLDSA_Sign(
    const uint8* Message,
    uint32 MessageLength,
    const uint8* Context,
    uint32 ContextLength,
    const uint8* SecretKey,
    uint8* Signature,
    uint32* SignatureLength)
{
    OQS_STATUS status;
    size_t sig_len = 0;

    if (PQC_Initialized == FALSE)
    {
        return PQC_E_NOT_OK;
    }

    if ((Message == NULL) || (SecretKey == NULL) || (Signature == NULL) || (SignatureLength == NULL) ||
        (ContextLength > PQC_MLDSA_CONTEXT_MAX_BYTES) || ((Context == NULL) && (ContextLength > 0U)))
    {
        return PQC_E_INVALID_PARAM;
    }

    /* Sign the message */
    PERF_PROBE_BEGIN(mldsa_sign);
    status = OQS_SIG_sign_with_ctx_str(PQC_SigCtx,
                                       Signature,
                                       &sig_len,
                                       Message,
                                       (size_t)MessageLength,
                                       Context,
                                       (size_t)ContextLength,
                                       SecretKey);
    PERF_PROBE_END(mldsa_sign, 0xFFFFu, SECOC_PERF_STAGE_PQC_MLDSA_SIGN);

    if (status != OQS_SUCCESS)
    {
        (void)printf("ERROR: ML-DSA signature generation failed\n");
        return PQC_E_NOT_OK;
    }

    *SignatureLength = (uint32)sig_len;

    return PQC_E_OK;
}

/**
 * @brief Verify ML-DSA-65 digital signature
 */
Std_ReturnType PQC_MLDSA_Verify(
    const uint8* Message,
    uint32 MessageLength,
    const uint8* Context,
    uint32 ContextLength,
    const uint8* Signature,
    uint32 SignatureLength,
    const uint8* PublicKey)
{
    if (PQC_Initialized == FALSE)
    {
        return PQC_E_NOT_OK;
    }

    if ((Message == NULL) || (Signature == NULL) || (PublicKey == NULL) ||
        (ContextLength > PQC_MLDSA_CONTEXT_MAX_BYTES) || ((Context == NULL) && (ContextLength > 0U)))
    {
        return PQC_E_INVALID_PARAM;
    }

    if (OQS_SIG_verify_with_ctx_str(PQC_SigCtx,
                                    Message,
                                    (size_t)MessageLength,
                                    Signature,
                                    (size_t)SignatureLength,
                                    Context,
                                    (size_t)ContextLength,
                                    PublicKey) != OQS_SUCCESS)
    {
        return PQC_E_VERIFY_FAILED;
    }

    return PQC_E_OK;
}

/**
 * @brief Load an ML-DSA peer public key file from PQC_MLDSA_KEY_DIRECTORY.
 * @details Filename pattern: <dir>/mldsa_peer<peerId>.pub. The file MUST
 *          contain exactly PQC_MLDSA_PUBLIC_KEY_BYTES bytes — any extra
 *          trailing data is treated as a corrupt key and rejected.
 *
 * @param[in]  peerId               Numeric peer identifier (0..N-1).
 * @param[out] publicKeyOut         Buffer to receive the public key.
 * @param[in]  publicKeyOutLength   Buffer length; must equal PQC_MLDSA_PUBLIC_KEY_BYTES.
 * @return PQC_E_OK on success, PQC_E_INVALID_PARAM for bad inputs,
 *         PQC_E_NOT_OK if the file is missing or malformed.
 */
Std_ReturnType PQC_MLDSA_LoadPeerPublicKey(uint8 peerId, uint8* publicKeyOut, uint32 publicKeyOutLength)
{
    char filename[512];
    FILE* fp;
    size_t firstRead;
    uint8 trailingProbe;
    size_t trailingRead;

    if ((publicKeyOut == NULL) || (publicKeyOutLength != PQC_MLDSA_PUBLIC_KEY_BYTES))
    {
        return PQC_E_INVALID_PARAM;
    }

    (void)snprintf(filename, sizeof(filename), "%smldsa_peer%u.pub",
                   PQC_MLDSA_KEY_DIRECTORY, (unsigned)peerId);

    fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        return PQC_E_NOT_OK;
    }

    firstRead = fread(publicKeyOut, 1, PQC_MLDSA_PUBLIC_KEY_BYTES, fp);
    if (firstRead != PQC_MLDSA_PUBLIC_KEY_BYTES)
    {
        (void)fclose(fp);
        (void)memset(publicKeyOut, 0, PQC_MLDSA_PUBLIC_KEY_BYTES);
        return PQC_E_NOT_OK;
    }
    trailingRead = fread(&trailingProbe, 1, 1, fp);
    (void)fclose(fp);
    if (trailingRead != 0)
    {
        (void)memset(publicKeyOut, 0, PQC_MLDSA_PUBLIC_KEY_BYTES);
        return PQC_E_NOT_OK;
    }
    (void)printf("ML-DSA peer %u pubkey loaded: %s\n", (unsigned)peerId, filename);
    return PQC_E_OK;
}
