/********************************************************************************************************/
/*  File:   test/test_pqc_crypto_layer.c                                                                  */
/*  Brief:  Crypto layer under the handshake PQC-SecOC-HS-v1, through the real Csm, CryIf and PQC code:   */
/*          K1 HKDF helper against the RFC 5869 test vectors (SHA-256 cases A.1 to A.3)                   */
/*          K2 ML-DSA-65 with FIPS 204 context strings: a signature verifies under its context only       */
/*          K3 Csm signature jobs: handshake and PDU signatures do not verify as each other; a PDU        */
/*             signature made under one session context fails under another; the no-session default       */
/*          K4 key identifiers (SHA-256 of the public key) follow the key state                           */
/*          K5 Csm_CustomService: ML-KEM round trip and key derivation; decapsulation key, shared secret  */
/*             and pseudorandom key are gone from static storage as soon as they have been used           */
/*          K6 no OQS context is created after initialisation                                             */
/*                                                                                                        */
/*  The test compiles Csm_Pqc.c itself with SECOC_TEST_ACCESS (storage accessor and secret tap, absent    */
/*  from gateway builds); OQS_SIG_new and OQS_KEM_new are counted at link time (-Wl,--wrap).              */
/********************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <oqs/oqs.h>

#include "Std_Types.h"
#include "SecOC_Cfg.h"
#include "Csm.h"
#include "CryIf.h"
#include "PQC.h"
#include "PQC_KeyDerivation.h"

static uint32 Failures = 0U;

#define CHECK(cond, ...) \
    do { if (!(cond)) { Failures++; (void)printf("  FAIL: " __VA_ARGS__); (void)printf("\n"); } } while (0)

#define SESSION_KEY(p)      (CSM_KEYID_SESSION_BASE + (uint32)(p))
#define VERIFIED(rc, ver)   (((rc) == E_OK) && ((ver) == CRYPTO_E_VER_OK))

/******************************************** link-time seams ********************************************/

static uint32 SigNewCalls = 0U;
static uint32 KemNewCalls = 0U;

OQS_SIG* __real_OQS_SIG_new(const char* method_name);
OQS_KEM* __real_OQS_KEM_new(const char* method_name);

OQS_SIG* __wrap_OQS_SIG_new(const char* method_name)
{
    SigNewCalls++;
    return __real_OQS_SIG_new(method_name);
}

OQS_KEM* __wrap_OQS_KEM_new(const char* method_name)
{
    KemNewCalls++;
    return __real_OQS_KEM_new(method_name);
}

/* secrets as they exist inside the custom service (kept outside the scanned storage) */
static uint8 Tap[4][CSM_MLKEM_SECRET_KEY_BYTES];
static uint32 TapLen[4];
static uint32 TapCount[4];

void Csm_Pqc_TestTap(uint8 kind, const uint8* dataPtr, uint32 length)
{
    if ((kind < 4U) && (length <= sizeof(Tap[0])))
    {
        (void)memcpy(Tap[kind], dataPtr, length);
        TapLen[kind] = length;
        TapCount[kind]++;
    }
}

/************************************************ helpers ************************************************/

static PQC_MLDSA_KeyPairType KeyK;      /* identity of this Csm */
static PQC_MLDSA_KeyPairType KeyO;      /* another ECU */
static const PQC_MLDSA_KeyPairType* ProvisionedKey = NULL;

static Std_ReturnType Test_LoadProvisionedKeys(uint8* publicKeyPtr, uint32 publicKeyLength,
                                               uint8* secretKeyPtr, uint32 secretKeyLength)
{
    if ((ProvisionedKey == NULL) || (publicKeyLength != sizeof(ProvisionedKey->PublicKey)) ||
        (secretKeyLength != sizeof(ProvisionedKey->SecretKey)))
    {
        return E_NOT_OK;
    }
    (void)memcpy(publicKeyPtr, ProvisionedKey->PublicKey, publicKeyLength);
    (void)memcpy(secretKeyPtr, ProvisionedKey->SecretKey, secretKeyLength);
    return E_OK;
}

static void Test_CsmIdentity(const PQC_MLDSA_KeyPairType* KeyPair)
{
    Csm_ConfigType cfg;
    cfg.CsmMldsaBootstrapMode = CSM_MLDSA_BOOTSTRAP_PROVISIONED;
    cfg.CsmLoadProvisionedMldsaKeysFct = Test_LoadProvisionedKeys;
    ProvisionedKey = KeyPair;
    Csm_Init(&cfg);
}

static void Test_PinPeer(uint8 Peer, const uint8* PublicKey)
{
    CHECK(Csm_KeyElementSet(CSM_KEYID_PEER_PUBKEY_BASE + (uint32)Peer, CSM_KEYELEMENT_MLDSA_PEER_PUBLIC,
                            PublicKey, CSM_MLDSA_PUBLIC_KEY_BYTES) == E_OK, "peer %u key element set", (unsigned)Peer);
    CHECK(Csm_KeySetValid(CSM_KEYID_PEER_PUBKEY_BASE + (uint32)Peer) == E_OK, "peer %u key set valid", (unsigned)Peer);
}

static uint32 Test_Hex(const char* Hex, uint8* Out)
{
    uint32 n = 0U;
    while ((Hex[0] != '\0') && (Hex[1] != '\0'))
    {
        unsigned int byte = 0U;
        (void)sscanf(Hex, "%2x", &byte);
        Out[n] = (uint8)byte;
        n++;
        Hex = &Hex[2];
    }
    return n;
}

/* TRUE when any 16-byte block of Secret (taken every 16 bytes) occurs in the storage */
static boolean Test_Residue(const uint8* Storage, uint32 StorageLength, const uint8* Secret, uint32 SecretLength)
{
    uint32 block;
    uint32 pos;

    for (block = 0U; (block + 16U) <= SecretLength; block += 16U)
    {
        for (pos = 0U; (pos + 16U) <= StorageLength; pos++)
        {
            if (memcmp(&Storage[pos], &Secret[block], 16U) == 0)
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static boolean Test_SessionStorageHolds(const uint8* Secret, uint32 SecretLength)
{
    const uint8* storage = NULL;
    uint32 length = 0U;

    Csm_Pqc_TestStorage(&storage, &length);
    return Test_Residue(storage, length, Secret, SecretLength);
}

/* FIPS 203: dk = dk_PKE (1152 bytes) || ek || H(ek) || z. Only dk_PKE and z are secret; ek is public
 * and stays in the transcript, so the erasure checks look for these two parts. */
#define DK_PKE_BYTES    (1152U)
#define DK_Z_OFFSET     (CSM_MLKEM_SECRET_KEY_BYTES - 32U)

static boolean Test_SessionStorageHoldsDk(const uint8* Dk)
{
    return ((Test_SessionStorageHolds(Dk, DK_PKE_BYTES) == TRUE) ||
            (Test_SessionStorageHolds(&Dk[DK_Z_OFFSET], 32U) == TRUE)) ? TRUE : FALSE;
}

static Std_ReturnType Test_Custom(uint32 JobId, uint32 Peer, const uint8* In, uint32 InLen, uint8* Out, uint32* OutLen)
{
    return Csm_CustomService(JobId, CRYPTO_OPERATIONMODE_SINGLECALL, SESSION_KEY(Peer), In, InLen,
                             NULL, 0U, NULL, 0U, Out, OutLen, NULL, NULL, NULL);
}

/************************************************* K1 ****************************************************/

static void Test_HkdfVector(const char* Name, const char* IkmHex, const char* SaltHex, const char* InfoHex,
                            const char* PrkHex, const char* OkmHex)
{
    uint8 ikm[80], salt[80], info[80], prkExp[32], okmExp[82], prk[32], okm[82];
    uint32 ikmLen = Test_Hex(IkmHex, ikm);
    uint32 saltLen = Test_Hex(SaltHex, salt);
    uint32 infoLen = Test_Hex(InfoHex, info);
    uint32 okmLen = Test_Hex(OkmHex, okmExp);

    (void)Test_Hex(PrkHex, prkExp);
    CHECK(PQC_Hkdf_Extract((saltLen > 0U) ? salt : NULL, saltLen, ikm, ikmLen, prk) == E_OK, "%s extract", Name);
    CHECK(memcmp(prk, prkExp, 32U) == 0, "%s PRK", Name);
    CHECK(PQC_Hkdf_Expand(prk, (infoLen > 0U) ? info : NULL, infoLen, okm, okmLen) == E_OK, "%s expand", Name);
    CHECK(memcmp(okm, okmExp, okmLen) == 0, "%s OKM", Name);
}

/* IKM, salt, info, PRK and OKM of RFC 5869, Appendix A, test cases 1 to 3 (SHA-256), compared byte for
 * byte with the text of the RFC (https://www.rfc-editor.org/rfc/rfc5869) on 2026-11-23 */
static void Test_K1_Hkdf(void)
{
    uint8 out[32];

    Test_HkdfVector("RFC 5869 A.1",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "000102030405060708090a0b0c",
        "f0f1f2f3f4f5f6f7f8f9",
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    Test_HkdfVector("RFC 5869 A.2",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
    Test_HkdfVector("RFC 5869 A.3",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "",
        "",
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");

    CHECK(PQC_Hkdf_Extract(NULL, 0U, NULL, 0U, out) != E_OK, "extract without keying material is refused");
    CHECK(PQC_Hkdf_Expand(NULL, NULL, 0U, out, 32U) != E_OK, "expand without a key is refused");
    (void)printf("K1 HKDF: RFC 5869 A.1, A.2, A.3\n");
}

/************************************************* K2 ****************************************************/

static void Test_K2_Context(void)
{
    static uint8 sig[PQC_MLDSA_SIGNATURE_BYTES];
    static uint8 sigPlain[PQC_MLDSA_SIGNATURE_BYTES];
    uint8 msg[14];
    uint8 ctx[PQC_PDU_SIG_CTX_BYTES];
    uint8 ctxOther[PQC_PDU_SIG_CTX_BYTES];
    uint8 longCtx[256];
    uint32 sigLen = 0U;
    uint32 sigPlainLen = 0U;
    uint32 i;

    for (i = 0U; i < sizeof(msg); i++) { msg[i] = (uint8)(i + 1U); }
    for (i = 0U; i < sizeof(ctx); i++) { ctx[i] = (uint8)(0xA0U + i); }
    (void)memcpy(ctxOther, ctx, sizeof(ctx));
    ctxOther[63] ^= 0x01U;
    (void)memset(longCtx, 0x55, sizeof(longCtx));

    CHECK(PQC_MLDSA_Sign(msg, sizeof(msg), ctx, sizeof(ctx), KeyK.SecretKey, sig, &sigLen) == PQC_E_OK, "sign with context");
    CHECK(sigLen == PQC_MLDSA_SIGNATURE_BYTES, "signature length %u", (unsigned)sigLen);
    CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), ctx, sizeof(ctx), sig, sigLen, KeyK.PublicKey) == PQC_E_OK, "same context verifies");
    CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), ctxOther, sizeof(ctxOther), sig, sigLen, KeyK.PublicKey) != PQC_E_OK, "context differing in one bit");
    CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), ctx, sizeof(ctx) - 1U, sig, sigLen, KeyK.PublicKey) != PQC_E_OK, "context one byte shorter");
    CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), NULL, 0U, sig, sigLen, KeyK.PublicKey) != PQC_E_OK, "empty context");
    CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), ctx, sizeof(ctx), sig, sigLen, KeyO.PublicKey) != PQC_E_OK, "other public key");

    CHECK(PQC_MLDSA_Sign(msg, sizeof(msg), NULL, 0U, KeyK.SecretKey, sigPlain, &sigPlainLen) == PQC_E_OK, "sign with empty context");
    CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), NULL, 0U, sigPlain, sigPlainLen, KeyK.PublicKey) == PQC_E_OK, "empty context verifies");
    CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), ctx, sizeof(ctx), sigPlain, sigPlainLen, KeyK.PublicKey) != PQC_E_OK, "empty-context signature under a context");

    CHECK(PQC_MLDSA_Sign(msg, sizeof(msg), longCtx, 256U, KeyK.SecretKey, sig, &sigLen) == PQC_E_INVALID_PARAM, "256-byte context refused");
    CHECK(PQC_MLDSA_Sign(msg, sizeof(msg), NULL, 4U, KeyK.SecretKey, sig, &sigLen) == PQC_E_INVALID_PARAM, "NULL context with a length refused");
    (void)printf("K2 ML-DSA-65 context strings\n");
}

/************************************************* K3 ****************************************************/

static Std_ReturnType Test_Sign(uint32 JobId, const uint8* Msg, uint32 MsgLen, uint8* Sig)
{
    uint32 sigLen = PQC_MLDSA_SIGNATURE_BYTES;
    Std_ReturnType rc = Csm_SignatureGenerate(JobId, CRYPTO_OPERATIONMODE_SINGLECALL, Msg, MsgLen, Sig, &sigLen);
    if ((rc == E_OK) && (sigLen != PQC_MLDSA_SIGNATURE_BYTES))
    {
        rc = E_NOT_OK;
    }
    return rc;
}

static boolean Test_Verifies(uint32 JobId, const uint8* Msg, uint32 MsgLen, const uint8* Sig)
{
    Crypto_VerifyResultType ver = CRYPTO_E_VER_NOT_OK;
    Std_ReturnType rc = Csm_SignatureVerify(JobId, CRYPTO_OPERATIONMODE_SINGLECALL, Msg, MsgLen, Sig,
                                            PQC_MLDSA_SIGNATURE_BYTES, &ver);
    return VERIFIED(rc, ver) ? TRUE : FALSE;
}

static void Test_K3_Jobs(void)
{
    static uint8 sigPdu[PQC_MLDSA_SIGNATURE_BYTES];
    static uint8 sigHs[PQC_MLDSA_SIGNATURE_BYTES];
    static uint8 sigS1[PQC_MLDSA_SIGNATURE_BYTES];
    static uint8 sigS2[PQC_MLDSA_SIGNATURE_BYTES];
    static uint8 sigO[PQC_MLDSA_SIGNATURE_BYTES];
    uint8 msg[49];
    uint8 ctxDefault[PQC_PDU_SIG_CTX_BYTES];
    uint8 ctxS1[PQC_PDU_SIG_CTX_BYTES];
    uint8 ctxS2[PQC_PDU_SIG_CTX_BYTES];
    uint8 buf[64];
    uint32 len = sizeof(buf);
    uint32 sigLen = 0U;
    uint32 i;
    Crypto_VerifyResultType ver = CRYPTO_E_VER_OK;
    const uint32 pduSign = (uint32)CSM_JOBID;
    const uint32 pduVerify0 = CSM_JOBID_VERIFY_PEER_BASE;
    const uint32 pduVerify1 = CSM_JOBID_VERIFY_PEER_BASE + 1U;
    const uint32 hsVerify0 = CSM_JOBID_HS_VERIFY_PEER_BASE;

    for (i = 0U; i < sizeof(msg); i++) { msg[i] = (uint8)(0x30U + i); }
    (void)memset(ctxDefault, 0, sizeof(ctxDefault));
    (void)memcpy(ctxDefault, PQC_PDU_SIG_CTX_LABEL, PQC_PDU_SIG_CTX_LABEL_BYTES);
    (void)memcpy(ctxS1, ctxDefault, sizeof(ctxS1));
    (void)memcpy(ctxS2, ctxDefault, sizeof(ctxS2));
    (void)memset(&ctxS1[PQC_PDU_SIG_CTX_LABEL_BYTES], 0x11, PQC_SESSION_HASH_BYTES);
    (void)memset(&ctxS2[PQC_PDU_SIG_CTX_LABEL_BYTES], 0x22, PQC_SESSION_HASH_BYTES);

    /* this Csm is K; peer 0 is pinned to K's own public key, peer 1 to the other ECU */
    Test_PinPeer(0U, KeyK.PublicKey);
    Test_PinPeer(1U, KeyO.PublicKey);

    /* the two contexts */
    CHECK(Test_Sign(pduSign, msg, sizeof(msg), sigPdu) == E_OK, "PDU sign job");
    CHECK(Test_Sign(CSM_JOBID_HS_SIGN, msg, sizeof(msg), sigHs) == E_OK, "handshake sign job");
    CHECK(Test_Verifies(pduVerify0, msg, sizeof(msg), sigPdu) == TRUE, "PDU signature, PDU verify job");
    CHECK(Test_Verifies(hsVerify0, msg, sizeof(msg), sigHs) == TRUE, "handshake signature, handshake verify job");
    CHECK(Test_Verifies(pduVerify0, msg, sizeof(msg), sigHs) == FALSE, "handshake signature presented to the PDU verify job");
    CHECK(Test_Verifies(hsVerify0, msg, sizeof(msg), sigPdu) == FALSE, "PDU signature presented to the handshake verify job");
    CHECK(Test_Verifies(pduVerify1, msg, sizeof(msg), sigPdu) == FALSE, "PDU signature under another peer's key");
    CHECK(Test_Verifies(CSM_JOBID_HS_VERIFY_PEER_BASE + 1U, msg, sizeof(msg), sigHs) == FALSE, "handshake signature under another peer's key");
    CHECK(Test_Verifies(CSM_JOBID_HS_VERIFY_PEER_BASE + 2U, msg, sizeof(msg), sigHs) == FALSE, "handshake verify job of a peer without a key");

    /* a job serves one service */
    CHECK(Csm_SignatureVerify(CSM_JOBID_HS_SIGN, CRYPTO_OPERATIONMODE_SINGLECALL, msg, sizeof(msg), sigHs,
                              PQC_MLDSA_SIGNATURE_BYTES, &ver) != E_OK, "sign job used for verification");
    CHECK(ver == CRYPTO_E_VER_NOT_OK, "refused verification reports not OK");
    sigLen = PQC_MLDSA_SIGNATURE_BYTES;
    CHECK(Csm_SignatureGenerate(hsVerify0, CRYPTO_OPERATIONMODE_SINGLECALL, msg, sizeof(msg), sigS1, &sigLen) != E_OK,
          "verify job used for signing");
    CHECK(Csm_CustomService(CSM_JOBID_HS_SIGN, CRYPTO_OPERATIONMODE_SINGLECALL, SESSION_KEY(0), NULL, 0U, NULL, 0U,
                            NULL, 0U, buf, &len, NULL, NULL, NULL) == E_NOT_OK, "signature job used as custom job");

    /* no session: label || 48 zero bytes */
    CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), ctxDefault, sizeof(ctxDefault), sigPdu, PQC_MLDSA_SIGNATURE_BYTES,
                           KeyK.PublicKey) == PQC_E_OK, "PDU signature carries the no-session context");
    CHECK(PQC_MLDSA_Verify(msg, sizeof(msg), NULL, 0U, sigPdu, PQC_MLDSA_SIGNATURE_BYTES,
                           KeyK.PublicKey) != PQC_E_OK, "PDU signature is not an empty-context signature");

    /* a job id that is in no row is refused for both services; the loopback verify job is the listed
     * way to verify, with this node's own public key, what it signed with the PDU sign job */
    sigLen = PQC_MLDSA_SIGNATURE_BYTES;
    CHECK(Csm_SignatureGenerate(0U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, sizeof(msg), sigS1, &sigLen) == E_NOT_OK, "unlisted job id signs nothing");
    ver = CRYPTO_E_VER_OK;
    CHECK((Csm_SignatureVerify(0U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, sizeof(msg), sigPdu, PQC_MLDSA_SIGNATURE_BYTES, &ver) == E_NOT_OK) &&
          (ver == CRYPTO_E_VER_NOT_OK), "unlisted job id verifies nothing");
    ver = CRYPTO_E_VER_OK;
    CHECK((Csm_SignatureVerify(pduSign, CRYPTO_OPERATIONMODE_SINGLECALL, msg, sizeof(msg), sigPdu, PQC_MLDSA_SIGNATURE_BYTES, &ver) == E_NOT_OK) &&
          (ver == CRYPTO_E_VER_NOT_OK), "the PDU sign job verifies nothing");
    CHECK(Test_Verifies(CSM_JOBID_VERIFY_LOOPBACK, msg, sizeof(msg), sigPdu) == TRUE, "loopback verify job: own signature, local public key");
    CHECK(Test_Verifies(CSM_JOBID_VERIFY_LOOPBACK, msg, sizeof(msg), sigHs) == FALSE, "loopback verify job: handshake signature refused");
    sigLen = PQC_MLDSA_SIGNATURE_BYTES;
    CHECK(Csm_SignatureGenerate(CSM_JOBID_VERIFY_LOOPBACK, CRYPTO_OPERATIONMODE_SINGLECALL, msg, sizeof(msg), sigS1, &sigLen) == E_NOT_OK,
          "loopback verify job signs nothing");

    /* The job table is asked before anything else, in every mode: START and UPDATE with an id that is
     * in no row, or with a job of the other service, are refused. They take no job context either:
     * twice as many unlisted ids as the Csm has contexts, then a listed job that has no context yet
     * is still served (a peer without a key: "key not valid", not "queue full"). */
    {
        uint32 refused = 0U;

        for (i = 0U; i < (2U * (uint32)CSM_MAX_JOB_CONTEXTS); i++)
        {
            const uint32 unlisted = 0x7000U + i;

            sigLen = PQC_MLDSA_SIGNATURE_BYTES;
            ver = CRYPTO_E_VER_OK;
            if ((Csm_SignatureGenerate(unlisted, CRYPTO_OPERATIONMODE_START, msg, sizeof(msg), sigS1, &sigLen) == E_NOT_OK) &&
                (Csm_SignatureGenerate(unlisted, CRYPTO_OPERATIONMODE_UPDATE, msg, sizeof(msg), sigS1, &sigLen) == E_NOT_OK) &&
                (Csm_SignatureVerify(unlisted, CRYPTO_OPERATIONMODE_START, msg, sizeof(msg), sigPdu, PQC_MLDSA_SIGNATURE_BYTES, &ver) == E_NOT_OK) &&
                (Csm_SignatureVerify(unlisted, CRYPTO_OPERATIONMODE_UPDATE, msg, sizeof(msg), sigPdu, PQC_MLDSA_SIGNATURE_BYTES, &ver) == E_NOT_OK) &&
                (ver == CRYPTO_E_VER_NOT_OK))
            {
                refused++;
            }
        }
        CHECK(refused == (2U * (uint32)CSM_MAX_JOB_CONTEXTS), "START and UPDATE with an unlisted job id are refused by both services");
    }
    sigLen = PQC_MLDSA_SIGNATURE_BYTES;
    CHECK((Csm_SignatureGenerate(CSM_JOBID_VERIFY_LOOPBACK, CRYPTO_OPERATIONMODE_START, msg, sizeof(msg), sigS1, &sigLen) == E_NOT_OK) &&
          (Csm_SignatureGenerate(hsVerify0, CRYPTO_OPERATIONMODE_UPDATE, msg, sizeof(msg), sigS1, &sigLen) == E_NOT_OK),
          "a verify job is refused by the sign service in START and UPDATE");
    ver = CRYPTO_E_VER_OK;
    CHECK((Csm_SignatureVerify(pduSign, CRYPTO_OPERATIONMODE_START, msg, sizeof(msg), sigPdu, PQC_MLDSA_SIGNATURE_BYTES, &ver) == E_NOT_OK) &&
          (Csm_SignatureVerify(CSM_JOBID_HS_SIGN, CRYPTO_OPERATIONMODE_UPDATE, msg, sizeof(msg), sigPdu, PQC_MLDSA_SIGNATURE_BYTES, &ver) == E_NOT_OK) &&
          (ver == CRYPTO_E_VER_NOT_OK), "a sign job is refused by the verify service in START and UPDATE");
    CHECK(Csm_SignatureVerify(CSM_JOBID_VERIFY_PEER_BASE + 3U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, sizeof(msg), sigPdu,
                              PQC_MLDSA_SIGNATURE_BYTES, &ver) == CRYPTO_E_KEY_NOT_VALID,
          "the refused requests took no job context: a job without one is still served");

    /* session context of peer 0 */
    CHECK(Csm_KeyElementSet(SESSION_KEY(0), CSM_KE_VENDOR_PDU_SIG_CTX, ctxS1, 63U) == CRYPTO_E_KEY_SIZE_MISMATCH, "63-byte context refused");
    CHECK(Test_Verifies(pduVerify0, msg, sizeof(msg), sigPdu) == TRUE, "refused write leaves the key valid");
    CHECK(Csm_KeyElementSet(SESSION_KEY(0), CSM_KE_VENDOR_PDU_SIG_CTX, ctxS1, sizeof(ctxS1)) == E_OK, "session 1 context written");
    CHECK(Test_Sign(pduSign, msg, sizeof(msg), sigS1) == CRYPTO_E_KEY_NOT_VALID, "sign before the session key is set valid");
    CHECK(Csm_SignatureVerify(pduVerify0, CRYPTO_OPERATIONMODE_SINGLECALL, msg, sizeof(msg), sigPdu,
                              PQC_MLDSA_SIGNATURE_BYTES, &ver) == CRYPTO_E_KEY_NOT_VALID, "verify before the session key is set valid");
    CHECK(Csm_KeySetValid(SESSION_KEY(0)) == E_OK, "session key set valid");
    CHECK(Test_Sign(pduSign, msg, sizeof(msg), sigS1) == E_OK, "sign in session 1");
    CHECK(Test_Verifies(pduVerify0, msg, sizeof(msg), sigS1) == TRUE, "session 1 signature in session 1");
    CHECK(Test_Verifies(pduVerify0, msg, sizeof(msg), sigPdu) == FALSE, "no-session signature in session 1");
    CHECK(Test_Verifies(hsVerify0, msg, sizeof(msg), sigHs) == TRUE, "handshake jobs do not depend on the session");

    CHECK(Csm_KeyElementSet(SESSION_KEY(0), CSM_KE_VENDOR_PDU_SIG_CTX, ctxS2, sizeof(ctxS2)) == E_OK, "session 2 context written");
    CHECK(Csm_KeySetValid(SESSION_KEY(0)) == E_OK, "session key set valid");
    CHECK(Test_Verifies(pduVerify0, msg, sizeof(msg), sigS1) == FALSE, "session 1 signature in session 2");
    CHECK(Test_Sign(pduSign, msg, sizeof(msg), sigS2) == E_OK, "sign in session 2");
    CHECK(Test_Verifies(pduVerify0, msg, sizeof(msg), sigS2) == TRUE, "session 2 signature in session 2");

    /* the session of peer 1 is untouched */
    CHECK(PQC_MLDSA_Sign(msg, sizeof(msg), ctxDefault, sizeof(ctxDefault), KeyO.SecretKey, sigO, &sigLen) == PQC_E_OK, "other ECU signs");
    CHECK(Test_Verifies(pduVerify1, msg, sizeof(msg), sigO) == TRUE, "peer 1 still verifies with the no-session context");

    /* the KEM elements cannot be written or read */
    CHECK(Csm_KeyElementSet(SESSION_KEY(0), CSM_KE_VENDOR_KEM_DK, ctxS1, sizeof(ctxS1)) == CRYPTO_E_KEY_WRITE_FAIL, "dk element is not writable");
    CHECK(Csm_KeyElementSet(SESSION_KEY(0), CSM_KE_VENDOR_KEM_SS, ctxS1, 32U) == CRYPTO_E_KEY_WRITE_FAIL, "ss element is not writable");
    len = sizeof(buf);
    CHECK(Csm_KeyElementGet(SESSION_KEY(0), CSM_KE_VENDOR_KEM_SS, buf, &len) == CRYPTO_E_KEY_READ_FAIL, "ss element is not readable");
    len = sizeof(buf);
    CHECK(Csm_KeyElementGet(SESSION_KEY(0), CSM_KE_VENDOR_KEM_DK, buf, &len) == CRYPTO_E_KEY_READ_FAIL, "dk element is not readable");
    (void)printf("K3 signature jobs and contexts\n");
}

/************************************************* K4 ****************************************************/

static void Test_K4_KeyIds(void)
{
    uint8 id[CSM_KEY_ID_BYTES];
    uint8 expected[SHA256_DIGEST_LENGTH];
    uint32 len;

    (void)SHA256(KeyK.PublicKey, sizeof(KeyK.PublicKey), expected);
    len = sizeof(id);
    CHECK(Csm_KeyElementGet(CSM_KEYID_MLDSA_LOCAL, CSM_KE_VENDOR_KEY_ID, id, &len) == E_OK, "own key id");
    CHECK((len == CSM_KEY_ID_BYTES) && (memcmp(id, expected, sizeof(id)) == 0), "own key id is SHA-256 of the public key");
    len = sizeof(id);
    CHECK(Csm_KeyElementGet(CSM_KEYID_PEER_PUBKEY_BASE, CSM_KE_VENDOR_KEY_ID, id, &len) == E_OK, "peer 0 key id");
    CHECK(memcmp(id, expected, sizeof(id)) == 0, "peer 0 key id");

    (void)SHA256(KeyO.PublicKey, sizeof(KeyO.PublicKey), expected);
    len = sizeof(id);
    CHECK(Csm_KeyElementGet(CSM_KEYID_PEER_PUBKEY_BASE + 1U, CSM_KE_VENDOR_KEY_ID, id, &len) == E_OK, "peer 1 key id");
    CHECK(memcmp(id, expected, sizeof(id)) == 0, "peer 1 key id");

    len = sizeof(id);
    CHECK(Csm_KeyElementGet(CSM_KEYID_PEER_PUBKEY_BASE + 2U, CSM_KE_VENDOR_KEY_ID, id, &len) == CRYPTO_E_KEY_EMPTY, "peer without a key has no id");
    len = 31U;
    CHECK(Csm_KeyElementGet(CSM_KEYID_MLDSA_LOCAL, CSM_KE_VENDOR_KEY_ID, id, &len) == CRYPTO_E_KEY_SIZE_MISMATCH, "short buffer");
    len = sizeof(id);
    CHECK(Csm_KeyElementGet(CSM_KEYID_MLDSA_LOCAL, CSM_KEYELEMENT_MLDSA_SECRET, id, &len) == CRYPTO_E_KEY_READ_FAIL, "secret key is not readable");

    /* a rewritten key has no id until it is valid again */
    CHECK(Csm_KeyElementSet(CSM_KEYID_PEER_PUBKEY_BASE + 1U, CSM_KEYELEMENT_MLDSA_PEER_PUBLIC,
                            KeyK.PublicKey, CSM_MLDSA_PUBLIC_KEY_BYTES) == E_OK, "peer 1 rewritten");
    len = sizeof(id);
    CHECK(Csm_KeyElementGet(CSM_KEYID_PEER_PUBKEY_BASE + 1U, CSM_KE_VENDOR_KEY_ID, id, &len) == CRYPTO_E_KEY_EMPTY, "no id while the key is invalid");
    CHECK(Csm_KeySetValid(CSM_KEYID_PEER_PUBKEY_BASE + 1U) == E_OK, "peer 1 valid");
    (void)SHA256(KeyK.PublicKey, sizeof(KeyK.PublicKey), expected);
    len = sizeof(id);
    CHECK(Csm_KeyElementGet(CSM_KEYID_PEER_PUBKEY_BASE + 1U, CSM_KE_VENDOR_KEY_ID, id, &len) == E_OK, "id of the new key");
    CHECK(memcmp(id, expected, sizeof(id)) == 0, "id follows the new key");
    (void)printf("K4 key identifiers\n");
}

/************************************************* K5 ****************************************************/

static void Test_K5_CustomService(void)
{
    static uint8 ek[CSM_MLKEM_PUBLIC_KEY_BYTES];
    static uint8 ek2[CSM_MLKEM_PUBLIC_KEY_BYTES];
    static uint8 ct[CSM_MLKEM_CIPHERTEXT_BYTES];
    static uint8 dk[CSM_MLKEM_SECRET_KEY_BYTES];
    static const char* const labels[4] = { "kc-r", "kc-i", "auth-i2r", "auth-r2i" };
    uint8 ss[CSM_MLKEM_SHARED_SECRET_BYTES];
    uint8 salt[48];
    uint8 head[15];
    uint8 tail[64];
    uint8 okmA[CSM_HS_KDF_OUTPUT_BYTES];
    uint8 okmB[CSM_HS_KDF_OUTPUT_BYTES];
    uint8 expected[CSM_HS_KDF_OUTPUT_BYTES];
    uint8 prk[PQC_HKDF_PRK_BYTES];
    uint8 info[96];
    uint32 len;
    uint32 i;
    Std_ReturnType rc;

    for (i = 0U; i < sizeof(salt); i++) { salt[i] = (uint8)(0x40U + i); }
    for (i = 0U; i < sizeof(tail); i++) { tail[i] = (uint8)(0x80U + i); }
    (void)memcpy(head, "PQC-SecOC-HS-v1", sizeof(head));

    /* ML-KEM round trip: key generation on session key 0, encapsulation on session key 1 */
    len = sizeof(ek);
    CHECK(Test_Custom(CSM_JOBID_KEM_KEYGEN, 0U, NULL, 0U, ek, &len) == E_OK, "key generation");
    CHECK(len == CSM_MLKEM_PUBLIC_KEY_BYTES, "encapsulation key length %u", (unsigned)len);
    CHECK(TapCount[CSM_PQC_TAP_DK] == 1U, "decapsulation key stored");
    (void)memcpy(dk, Tap[CSM_PQC_TAP_DK], sizeof(dk));
    CHECK(memcmp(&dk[DK_PKE_BYTES], ek, sizeof(ek)) == 0, "dk holds ek after dk_PKE (FIPS 203 layout assumed by the scans)");
    CHECK(Test_SessionStorageHoldsDk(dk) == TRUE, "scan finds the decapsulation key while it is stored");

    len = sizeof(ct);
    CHECK(Test_Custom(CSM_JOBID_KEM_ENCAPS, 1U, ek, sizeof(ek), ct, &len) == E_OK, "encapsulation");
    CHECK(len == CSM_MLKEM_CIPHERTEXT_BYTES, "ciphertext length %u", (unsigned)len);
    (void)memcpy(ss, Tap[CSM_PQC_TAP_SS], sizeof(ss));

    CHECK(Test_Custom(CSM_JOBID_KEM_DECAPS, 0U, ct, sizeof(ct), NULL, NULL) == E_OK, "decapsulation");
    CHECK(TapCount[CSM_PQC_TAP_SS] == 2U, "shared secret stored on both sides");
    CHECK(memcmp(ss, Tap[CSM_PQC_TAP_SS], sizeof(ss)) == 0, "both sides hold the same shared secret");
    CHECK(Test_SessionStorageHoldsDk(dk) == FALSE, "decapsulation key erased by the decapsulation");
    CHECK(Test_SessionStorageHolds(ss, sizeof(ss)) == TRUE, "scan finds the shared secret while it is stored");
    CHECK(Test_Custom(CSM_JOBID_KEM_DECAPS, 0U, ct, sizeof(ct), NULL, NULL) == CRYPTO_E_CUSTOM_ERROR, "second decapsulation has no key");
    CHECK(Test_SessionStorageHolds(ss, sizeof(ss)) == TRUE, "refused decapsulation leaves the shared secret");

    /* key derivation on both sides */
    len = sizeof(okmA);
    rc = Csm_CustomService(CSM_JOBID_HS_KDF, CRYPTO_OPERATIONMODE_SINGLECALL, SESSION_KEY(0), salt, sizeof(salt),
                           head, sizeof(head), tail, sizeof(tail), okmA, &len, NULL, NULL, NULL);
    CHECK((rc == E_OK) && (len == CSM_HS_KDF_OUTPUT_BYTES), "key derivation, initiator side");
    len = sizeof(okmB);
    rc = Csm_CustomService(CSM_JOBID_HS_KDF, CRYPTO_OPERATIONMODE_SINGLECALL, SESSION_KEY(1), salt, sizeof(salt),
                           head, sizeof(head), tail, sizeof(tail), okmB, &len, NULL, NULL, NULL);
    CHECK((rc == E_OK) && (len == CSM_HS_KDF_OUTPUT_BYTES), "key derivation, responder side");
    CHECK(memcmp(okmA, okmB, sizeof(okmA)) == 0, "both sides derive the same keys");

    /* the same keys from the two HKDF steps, with the info strings built here */
    CHECK(PQC_Hkdf_Extract(salt, sizeof(salt), ss, sizeof(ss), prk) == E_OK, "reference extract");
    CHECK(memcmp(prk, Tap[CSM_PQC_TAP_PRK], sizeof(prk)) == 0, "PRK = HKDF-Extract(salt, ss)");
    for (i = 0U; i < 4U; i++)
    {
        uint32 labelLen = (uint32)strlen(labels[i]);
        (void)memcpy(info, head, sizeof(head));
        (void)memcpy(&info[sizeof(head)], labels[i], labelLen);
        (void)memcpy(&info[sizeof(head) + labelLen], tail, sizeof(tail));
        CHECK(PQC_Hkdf_Expand(prk, info, (uint32)sizeof(head) + labelLen + (uint32)sizeof(tail),
                              &expected[i * 32U], 32U) == E_OK, "reference expand %u", (unsigned)i);
    }
    CHECK(memcmp(okmA, expected, sizeof(expected)) == 0, "keys = HKDF-Expand(PRK, head || label || tail, 32) in label order");
    CHECK(memcmp(&okmA[0], &okmA[32], 32U) != 0, "the keys differ from each other");

    /* nothing is left */
    CHECK(Test_SessionStorageHolds(ss, sizeof(ss)) == FALSE, "shared secret erased by the key derivation");
    CHECK(Test_SessionStorageHolds(prk, sizeof(prk)) == FALSE, "PRK not in static storage");
    CHECK(Test_SessionStorageHolds(okmA, sizeof(okmA)) == FALSE, "derived keys not in static storage");
    len = sizeof(okmA);
    rc = Csm_CustomService(CSM_JOBID_HS_KDF, CRYPTO_OPERATIONMODE_SINGLECALL, SESSION_KEY(0), salt, sizeof(salt),
                           head, sizeof(head), tail, sizeof(tail), okmA, &len, NULL, NULL, NULL);
    CHECK(rc == CRYPTO_E_CUSTOM_ERROR, "second key derivation has no shared secret");

    /* discard */
    len = sizeof(ek2);
    CHECK(Test_Custom(CSM_JOBID_KEM_KEYGEN, 0U, NULL, 0U, ek2, &len) == E_OK, "second key generation");
    CHECK(memcmp(ek, ek2, sizeof(ek)) != 0, "a fresh key pair every time");
    (void)memcpy(dk, Tap[CSM_PQC_TAP_DK], sizeof(dk));
    CHECK(Test_Custom(CSM_JOBID_KEM_DISCARD, 0U, NULL, 0U, NULL, NULL) == E_OK, "discard");
    CHECK(Test_SessionStorageHoldsDk(dk) == FALSE, "decapsulation key erased by the discard");
    CHECK(Test_Custom(CSM_JOBID_KEM_DECAPS, 0U, ct, sizeof(ct), NULL, NULL) == CRYPTO_E_CUSTOM_ERROR, "decapsulation after discard");

    /* refused requests */
    len = sizeof(ek2);
    CHECK(Csm_CustomService(CSM_JOBID_KEM_KEYGEN, CRYPTO_OPERATIONMODE_START, SESSION_KEY(0), NULL, 0U, NULL, 0U, NULL, 0U,
                            ek2, &len, NULL, NULL, NULL) == E_NOT_OK, "streaming mode refused");
    CHECK(Csm_CustomService(CSM_JOBID_KEM_KEYGEN, CRYPTO_OPERATIONMODE_SINGLECALL, CSM_KEYID_MLDSA_LOCAL, NULL, 0U, NULL, 0U,
                            NULL, 0U, ek2, &len, NULL, NULL, NULL) == E_NOT_OK, "target key that is not a session key");
    CHECK(Csm_CustomService(99U, CRYPTO_OPERATIONMODE_SINGLECALL, SESSION_KEY(0), NULL, 0U, NULL, 0U, NULL, 0U,
                            ek2, &len, NULL, NULL, NULL) == E_NOT_OK, "unknown job");
    len = CSM_MLKEM_PUBLIC_KEY_BYTES - 1U;
    CHECK(Test_Custom(CSM_JOBID_KEM_KEYGEN, 0U, NULL, 0U, ek2, &len) == E_NOT_OK, "short output buffer");
    len = sizeof(ct);
    CHECK(Test_Custom(CSM_JOBID_KEM_ENCAPS, 1U, ek, sizeof(ek) - 1U, ct, &len) == E_NOT_OK, "short encapsulation key");
    CHECK(Test_Custom(CSM_JOBID_KEM_DECAPS, 0U, ct, sizeof(ct) - 1U, NULL, NULL) == E_NOT_OK, "short ciphertext");

    /* the length guards of the key derivation (the two info parts go into a buffer on the stack, the
     * output is written at full length): refused, and the shared secret stays for the valid request */
    {
        uint8 longPart[CSM_HS_KDF_INFO_PART_MAX_BYTES + 1U] = { 0U };

        len = sizeof(ek2);
        CHECK(Test_Custom(CSM_JOBID_KEM_KEYGEN, 0U, NULL, 0U, ek2, &len) == E_OK, "key generation before the refused derivations");
        len = sizeof(ct);
        CHECK(Test_Custom(CSM_JOBID_KEM_ENCAPS, 1U, ek2, sizeof(ek2), ct, &len) == E_OK, "encapsulation before the refused derivations");
        len = sizeof(okmB);
        CHECK(Csm_CustomService(CSM_JOBID_HS_KDF, CRYPTO_OPERATIONMODE_SINGLECALL, SESSION_KEY(1), salt, sizeof(salt),
                                longPart, sizeof(longPart), tail, sizeof(tail), okmB, &len, NULL, NULL, NULL) == E_NOT_OK,
              "second input one byte too long");
        len = sizeof(okmB);
        CHECK(Csm_CustomService(CSM_JOBID_HS_KDF, CRYPTO_OPERATIONMODE_SINGLECALL, SESSION_KEY(1), salt, sizeof(salt),
                                head, sizeof(head), longPart, sizeof(longPart), okmB, &len, NULL, NULL, NULL) == E_NOT_OK,
              "third input one byte too long");
        len = CSM_HS_KDF_OUTPUT_BYTES - 1U;
        CHECK(Csm_CustomService(CSM_JOBID_HS_KDF, CRYPTO_OPERATIONMODE_SINGLECALL, SESSION_KEY(1), salt, sizeof(salt),
                                head, sizeof(head), tail, sizeof(tail), okmB, &len, NULL, NULL, NULL) == E_NOT_OK,
              "output buffer one byte short");
        len = sizeof(okmB);
        CHECK((Csm_CustomService(CSM_JOBID_HS_KDF, CRYPTO_OPERATIONMODE_SINGLECALL, SESSION_KEY(1), salt, sizeof(salt),
                                 head, sizeof(head), tail, sizeof(tail), okmB, &len, NULL, NULL, NULL) == E_OK) &&
              (len == CSM_HS_KDF_OUTPUT_BYTES), "the refused derivations left the shared secret in place");
        (void)Test_Custom(CSM_JOBID_KEM_DISCARD, 0U, NULL, 0U, NULL, NULL);
    }

    /* FIPS 203 Sec. 7.2 input check: an encapsulation key whose first coefficients are not reduced is
     * refused by the pinned liboqs build, and nothing is stored */
    (void)memcpy(ek2, ek, sizeof(ek2));
    (void)memset(ek2, 0xFF, 32U);
    TapCount[CSM_PQC_TAP_SS] = 0U;
    len = sizeof(ct);
    CHECK(Test_Custom(CSM_JOBID_KEM_ENCAPS, 1U, ek2, sizeof(ek2), ct, &len) == CRYPTO_E_CUSTOM_ERROR,
          "encapsulation key that fails the modulus check is refused");
    CHECK(TapCount[CSM_PQC_TAP_SS] == 0U, "refused encapsulation stores no shared secret");
    (void)Test_Custom(CSM_JOBID_KEM_DISCARD, 1U, NULL, 0U, NULL, NULL);
    (void)printf("K5 custom service: ML-KEM-768, key derivation, erasure\n");
}

/************************************************* main **************************************************/

int main(void)
{
    uint32 sigNewAfterInit;
    uint32 kemNewAfterInit;

    (void)setvbuf(stdout, NULL, _IOLBF, 0);

    CHECK(PQC_Init() == PQC_E_OK, "PQC_Init");
    CHECK(PQC_MLDSA_KeyGen(&KeyK) == PQC_E_OK, "identity K");
    CHECK(PQC_MLDSA_KeyGen(&KeyO) == PQC_E_OK, "identity O");
    Test_CsmIdentity(&KeyK);
    sigNewAfterInit = SigNewCalls;
    kemNewAfterInit = KemNewCalls;
    CHECK(sigNewAfterInit == 1U, "one ML-DSA context created at initialisation (%u)", (unsigned)sigNewAfterInit);
    CHECK(kemNewAfterInit == 1U, "one ML-KEM context created at initialisation (%u)", (unsigned)kemNewAfterInit);

    Test_K1_Hkdf();
    Test_K2_Context();
    Test_K3_Jobs();
    Test_K4_KeyIds();
    Test_K5_CustomService();

    CHECK(SigNewCalls == sigNewAfterInit, "no ML-DSA context created by a sign or verify call");
    CHECK(KemNewCalls == kemNewAfterInit, "no ML-KEM context created by a KEM call");
    (void)printf("K6 OQS contexts: %u signature, %u KEM, none after initialisation\n",
                 (unsigned)SigNewCalls, (unsigned)KemNewCalls);

    if (Failures == 0U)
    {
        (void)printf("PASS: 0 failed check(s)\n");
        return 0;
    }
    (void)printf("FAIL: %u failed check(s)\n", (unsigned)Failures);
    return 1;
}
