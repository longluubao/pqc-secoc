/* bench_keygen <dir>: create the ML-DSA-65 identity of one harness endpoint, mldsa_secoc.key
 * (0600) and mldsa_secoc.pub, in the same raw format the gateway uses. An existing key is kept:
 * the peer has its public half installed as mldsa_peer0.pub. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <oqs/oqs.h>

static int write_file(const char* dir, const char* name, const uint8_t* data, size_t len, mode_t mode)
{
    char path[512];
    int fd;
    ssize_t n;

    (void)snprintf(path, sizeof(path), "%s/%s", dir, name);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0) {
        perror(path);
        return -1;
    }
    n = write(fd, data, len);
    return ((close(fd) == 0) && (n == (ssize_t)len)) ? 0 : -1;
}

int main(int argc, char** argv)
{
    static uint8_t pk[OQS_SIG_ml_dsa_65_length_public_key];
    static uint8_t sk[OQS_SIG_ml_dsa_65_length_secret_key];
    char path[512];
    OQS_SIG* sig;

    if (argc != 2) {
        (void)fprintf(stderr, "usage: bench_keygen <dir>\n");
        return 2;
    }
    (void)snprintf(path, sizeof(path), "%s/mldsa_secoc.key", argv[1]);
    if (access(path, F_OK) == 0) {
        (void)printf("%s exists, kept\n", path);
        return 0;
    }
    (void)mkdir(argv[1], 0700);
    sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if ((sig == NULL) || (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) ||
        (write_file(argv[1], "mldsa_secoc.key", sk, sizeof(sk), 0600) != 0) ||
        (write_file(argv[1], "mldsa_secoc.pub", pk, sizeof(pk), 0644) != 0)) {
        (void)fprintf(stderr, "key generation failed\n");
        return 1;
    }
    OQS_MEM_cleanse(sk, sizeof(sk));
    (void)printf("created %s\n", path);
    return 0;
}
