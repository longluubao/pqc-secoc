/* bench_hs_forge: what an attacker who holds no key of either gateway can make, for the on-wire
 * handshake tests (attack_proxy.py --hs ... replace / resign):
 *
 *   bench_hs_forge ek FILE     a valid ML-KEM-768 encapsulation key (1184 bytes) of a key pair made here
 *   bench_hs_forge ct FILE     a valid ML-KEM-768 ciphertext (1088 bytes) for such a key
 *   bench_hs_forge sign HEX    prints, as hex, an ML-DSA-65 signature over the given bytes under the
 *                              product's handshake context, with a key pair created for this call
 *
 * The secret halves are wiped and never written anywhere. */
#include <stdio.h>
#include <string.h>

#include <oqs/oqs.h>

#include "Csm/Csm_Pqc.h"    /* CSM_HS_SIG_CTX: the context string of the product's handshake signatures */

static int write_file(const char* path, const uint8_t* data, size_t len)
{
    FILE* f = fopen(path, "wb");
    size_t n;

    if (f == NULL) {
        perror(path);
        return -1;
    }
    n = fwrite(data, 1U, len, f);
    return ((fclose(f) == 0) && (n == len)) ? 0 : -1;
}

static int kem_part(const char* what, const char* path)
{
    static uint8_t ek[1184], dk[2400], ct[1088], ss[32];
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    int isEk = (strcmp(what, "ek") == 0) ? 1 : 0;
    int rc = 1;

    if ((kem != NULL) && (kem->length_public_key == sizeof(ek)) && (kem->length_secret_key == sizeof(dk)) &&
        (kem->length_ciphertext == sizeof(ct)) && (kem->length_shared_secret == sizeof(ss)) &&
        (OQS_KEM_keypair(kem, ek, dk) == OQS_SUCCESS) && (OQS_KEM_encaps(kem, ct, ss, ek) == OQS_SUCCESS) &&
        (write_file(path, (isEk != 0) ? ek : ct, (isEk != 0) ? sizeof(ek) : sizeof(ct)) == 0)) {
        rc = 0;
    }
    OQS_MEM_cleanse(dk, sizeof(dk));
    OQS_MEM_cleanse(ss, sizeof(ss));
    OQS_KEM_free(kem);
    return rc;
}

static int sign_hex(const char* hex)
{
    static uint8_t pk[OQS_SIG_ml_dsa_65_length_public_key];
    static uint8_t sk[OQS_SIG_ml_dsa_65_length_secret_key];
    static uint8_t signature[OQS_SIG_ml_dsa_65_length_signature];
    uint8_t msg[256];
    size_t hexLen = strlen(hex);
    size_t msgLen = hexLen / 2U;
    size_t sigLen = 0U;
    size_t i;
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    int rc = 1;

    if (((hexLen % 2U) != 0U) || (msgLen == 0U) || (msgLen > sizeof(msg))) {
        (void)fprintf(stderr, "sign: 1 to %zu bytes as hex\n", sizeof(msg));
        return 2;
    }
    for (i = 0U; i < msgLen; i++) {
        unsigned int byte;

        if (sscanf(&hex[2U * i], "%2x", &byte) != 1) {
            (void)fprintf(stderr, "sign: not hex\n");
            return 2;
        }
        msg[i] = (uint8_t)byte;
    }
    if ((sig != NULL) && (OQS_SIG_keypair(sig, pk, sk) == OQS_SUCCESS) &&
        (OQS_SIG_sign_with_ctx_str(sig, signature, &sigLen, msg, msgLen, (const uint8_t*)CSM_HS_SIG_CTX,
                                   (size_t)CSM_HS_SIG_CTX_BYTES, sk) == OQS_SUCCESS) &&
        (sigLen == sizeof(signature)) &&
        (OQS_SIG_verify_with_ctx_str(sig, msg, msgLen, signature, sigLen, (const uint8_t*)CSM_HS_SIG_CTX,
                                     (size_t)CSM_HS_SIG_CTX_BYTES, pk) == OQS_SUCCESS)) {
        for (i = 0U; i < sigLen; i++) {
            (void)printf("%02x", (unsigned int)signature[i]);
        }
        (void)printf("\n");
        rc = 0;
    }
    OQS_MEM_cleanse(sk, sizeof(sk));
    OQS_SIG_free(sig);
    return rc;
}

int main(int argc, char** argv)
{
    int rc = 2;

    if ((argc == 3) && ((strcmp(argv[1], "ek") == 0) || (strcmp(argv[1], "ct") == 0))) {
        rc = kem_part(argv[1], argv[2]);
    } else if ((argc == 3) && (strcmp(argv[1], "sign") == 0)) {
        rc = sign_hex(argv[2]);
    } else {
        (void)fprintf(stderr, "usage: bench_hs_forge ek FILE | ct FILE | sign HEX\n");
    }
    if (rc == 1) {
        (void)fprintf(stderr, "bench_hs_forge %s failed\n", argv[1]);
    }
    return rc;
}
