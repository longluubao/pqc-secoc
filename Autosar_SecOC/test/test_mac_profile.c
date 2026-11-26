/********************************************************************************************************/
/*  File:   test/test_mac_profile.c                                                                       */
/*  Brief:  HMAC-SHA-256 behind the Csm MAC interface, through the real Csm, CryIf and crypto driver.     */
/*                                                                                                        */
/*  Checks: K1 a MAC job fails with CRYPTO_E_KEY_NOT_VALID until Csm_KeyElementSet + Csm_KeySetValid      */
/*             ([SWS_Crypto_00039], SWS Crypto 7.2.4)                                                     */
/*          K2 RFC 4231 test cases 1 to 5 and RFC 4868 AUTH256-1 (a 32-byte key, the key length of the    */
/*             MAC variant) through Csm_MacGenerate, complete and truncated                               */
/*             ([SWS_Csm_00982], [SWS_Crypto_00065])                                                      */
/*          K3 Csm_MacVerify accepts the right tag and rejects a flipped bit, a short tag and a wrong     */
/*             key; the length is in bits ([SWS_Csm_01050])                                               */
/*          K4 after a key replacement the old key no longer verifies; the job fails in between; a        */
/*             shorter key leaves no byte of a longer one behind it in the driver's key table             */
/*          K5 a job only serves its own service ([SWS_Csm_01091]); key element checks                    */
/*          K6 START / UPDATE / FINISH gives the single-call result; repeated messages on one key         */
/*          K7 OpenSSL allocations per MAC call, measured with CRYPTO_set_mem_functions: none of this     */
/*             code's own, and not more than the library itself makes (2 before OpenSSL 3.5, then 0)      */
/*          K8 the keys and jobs of two peers are separate: a MAC made with one peer's send key verifies  */
/*             with the other peer's receive key when both hold the same bytes, and only then              */
/*          K9 the key-confirmation slot of the handshake: complete 32-byte tags, 256-bit compare length,  */
/*             no effect on the PDU keys; a slot overwritten with zeros and not set valid serves no job    */
/*          K10 erasure: after a key is replaced, overwritten or the driver is initialised again, its      */
/*             bytes are neither in the driver's static key table nor in a live or freed OpenSSL heap      */
/*             block (the test is built with SECOC_TEST_ACCESS and owns OpenSSL's allocator)               */
/********************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "Std_Types.h"
#include "Csm.h"
#include "Crypto_Mac.h"     /* Crypto_Mac_TestStorage (SECOC_TEST_ACCESS) */
#include "SecOC_Cfg.h"      /* CSM_JOBID, the signature job */

static uint32 Failures = 0U;

#define CHECK(cond, ...) \
    do { if (!(cond)) { Failures++; (void)printf("  FAIL: " __VA_ARGS__); (void)printf("\n"); } } while (0)

/* RFC 4231, HMAC-SHA-256. Cases 6 and 7 use 131-byte keys, more than the 32-byte MAC key element holds. */
typedef struct
{
    const char* Name;
    uint8       Key[32];
    uint32      KeyLength;
    uint8       Data[50];
    uint32      DataLength;
    uint8       Mac[32];
    uint32      MacLength;      /* 16: the RFC prints this case truncated to 128 bits */
} Test_VectorType;

static const Test_VectorType Test_Vectors[] =
{
    {
        "RFC 4231 case 1",
        { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b }, 20U,
        "Hi There", 8U,
        { 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
          0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7 }, 32U
    },
    {
        "RFC 4231 case 2",
        "Jefe", 4U,
        "what do ya want for nothing?", 28U,
        { 0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
          0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43 }, 32U
    },
    {
        "RFC 4231 case 3",
        { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa }, 20U,
        { 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
          0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
          0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd }, 50U,
        { 0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
          0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe }, 32U
    },
    {
        "RFC 4231 case 4",
        { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
          0x15, 0x16, 0x17, 0x18, 0x19 }, 25U,
        { 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
          0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
          0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd }, 50U,
        { 0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a,
          0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b }, 32U
    },
    {
        "RFC 4231 case 5 (128 bit)",
        { 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c }, 20U,
        "Test With Truncation", 20U,
        { 0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0, 0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55, 0x55, 0x2b }, 16U
    },
    {
        /* RFC 4868, 2.7.2.1, Test Case AUTH256-1: a 32-byte key; its HMAC-SHA-256-128 is the first half */
        "RFC 4868 AUTH256-1",
        { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
          0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b }, 32U,
        "Hi There", 8U,
        { 0x19, 0x8a, 0x60, 0x7e, 0xb4, 0x4b, 0xfb, 0xc6, 0x99, 0x03, 0xa0, 0xf1, 0xcf, 0x2b, 0xbd, 0xc5,
          0xba, 0x0a, 0xa3, 0xf3, 0xd9, 0xae, 0x3c, 0x1c, 0x7a, 0x3b, 0x16, 0x96, 0xa0, 0xb6, 0x8c, 0xf7 }, 32U
    }
};
#define TEST_NUM_VECTORS    (sizeof(Test_Vectors) / sizeof(Test_Vectors[0]))

static const uint8 Test_KeyA[32] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8 Test_KeyB[32] =
{
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef
};
static const uint8 Test_Message[14] = { 0x00, 0x06, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x00, 0x00, 0x01 };

/************************************************ helpers ************************************************/

static uint32 AllocCount = 0U;

/* OpenSSL's allocator, owned by the test: every block is on a list with its size in front, so that
 * live blocks can be searched for key bytes and a block is searched once more when it is freed. */
typedef struct Test_BlockTag
{
    struct Test_BlockTag* Prev;
    struct Test_BlockTag* Next;
    size_t Size;
    size_t Unused;              /* keeps the 16-byte alignment of malloc for the bytes behind */
} Test_BlockType;

static Test_BlockType Test_Blocks = { &Test_Blocks, &Test_Blocks, 0U, 0U };
static const uint8* WatchKey = NULL;        /* 32 bytes looked for in every block that is freed */
static uint32 WatchFreedHits = 0U;
static uint32 FailAllocs = 0U;              /* the next n allocations fail */

/* occurrences of the bytes From..31 of a 32-byte key */
static uint32 Test_FindFrom(const uint8* Data, size_t Length, const uint8* Key, size_t From)
{
    uint32 hits = 0U;
    size_t i;

    for (i = 0U; (i + (32U - From)) <= Length; i++)
    {
        if (memcmp(&Data[i], &Key[From], 32U - From) == 0)
        {
            hits++;
        }
    }
    return hits;
}

static uint32 Test_Find(const uint8* Data, size_t Length, const uint8* Key)
{
    return Test_FindFrom(Data, Length, Key, 0U);
}

static void Test_Link(Test_BlockType* Block, size_t Size)
{
    Block->Size = Size;
    Block->Unused = 0U;
    Block->Next = Test_Blocks.Next;
    Block->Prev = &Test_Blocks;
    Test_Blocks.Next->Prev = Block;
    Test_Blocks.Next = Block;
}

static void Test_Unlink(Test_BlockType* Block)
{
    Block->Prev->Next = Block->Next;
    Block->Next->Prev = Block->Prev;
}

static void* Test_Malloc(size_t Size, const char* File, int Line)
{
    Test_BlockType* block;

    (void)File; (void)Line;
    if (FailAllocs > 0U)
    {
        FailAllocs--;
        return NULL;
    }
    block = malloc(sizeof(*block) + Size);
    if (block == NULL)
    {
        return NULL;
    }
    AllocCount++;
    Test_Link(block, Size);
    return &block[1];
}

static void Test_Free(void* Ptr, const char* File, int Line)
{
    Test_BlockType* block;

    (void)File; (void)Line;
    if (Ptr == NULL)
    {
        return;
    }
    block = &((Test_BlockType*)Ptr)[-1];
    if (WatchKey != NULL)
    {
        WatchFreedHits += Test_Find((const uint8*)Ptr, block->Size, WatchKey);
    }
    Test_Unlink(block);
    free(block);
}

static void* Test_Realloc(void* Ptr, size_t Size, const char* File, int Line)
{
    Test_BlockType* block;

    if (Ptr == NULL)
    {
        return Test_Malloc(Size, File, Line);
    }
    if (Size == 0U)
    {
        Test_Free(Ptr, File, Line);
        return NULL;
    }
    block = &((Test_BlockType*)Ptr)[-1];
    Test_Unlink(block);
    block = realloc(block, sizeof(*block) + Size);
    if (block == NULL)
    {
        Test_Link(&((Test_BlockType*)Ptr)[-1], ((Test_BlockType*)Ptr)[-1].Size);
        return NULL;
    }
    AllocCount++;
    Test_Link(block, Size);
    return &block[1];
}

static uint32 Test_LiveHits(const uint8* Key)
{
    const Test_BlockType* block;
    uint32 hits = 0U;

    for (block = Test_Blocks.Next; block != &Test_Blocks; block = block->Next)
    {
        hits += Test_Find((const uint8*)&block[1], block->Size, Key);
    }
    return hits;
}

/* the Csm wants an ML-DSA identity at start-up; these tests do not sign */
static Std_ReturnType Test_LoadProvisionedKeys(uint8* publicKeyPtr, uint32 publicKeyLength,
                                               uint8* secretKeyPtr, uint32 secretKeyLength)
{
    (void)memset(publicKeyPtr, 0, publicKeyLength);
    (void)memset(secretKeyPtr, 0, secretKeyLength);
    return E_OK;
}

static void Test_CsmInit(void)
{
    Csm_ConfigType cfg;
    cfg.CsmMldsaBootstrapMode = CSM_MLDSA_BOOTSTRAP_PROVISIONED;
    cfg.CsmLoadProvisionedMldsaKeysFct = Test_LoadProvisionedKeys;
    Csm_Init(&cfg);
}

static Std_ReturnType Test_InstallKey(uint32 KeyId, const uint8* Key, uint32 Length)
{
    Std_ReturnType result = Csm_KeyElementSet(KeyId, CRYPTO_KE_MAC_KEY, Key, Length);
    if (result == E_OK)
    {
        result = Csm_KeySetValid(KeyId);
    }
    return result;
}

static Std_ReturnType Test_Generate(const uint8* Data, uint32 DataLength, uint8* Mac, uint32* MacLength)
{
    return Csm_MacGenerate(CSM_JOBID_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, Data, DataLength, Mac, MacLength);
}

static Std_ReturnType Test_Verify(const uint8* Data, uint32 DataLength, const uint8* Mac, uint32 MacLengthBits,
                                  Crypto_VerifyResultType* Verdict)
{
    *Verdict = CRYPTO_E_VER_OK;     /* the call has to write the verdict, also when it rejects the request */
    return Csm_MacVerify(CSM_JOBID_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, Data, DataLength, Mac, MacLengthBits, Verdict);
}

/* a generate job on a key that is not valid: the error, no tag, the length left alone */
static void Test_ExpectNoTag(const char* When)
{
    uint8 mac[32];
    uint32 macLength = sizeof(mac);
    uint32 i;
    uint32 written = 0U;
    Std_ReturnType result;

    (void)memset(mac, 0xA5, sizeof(mac));
    result = Test_Generate(Test_Message, sizeof(Test_Message), mac, &macLength);
    for (i = 0U; i < sizeof(mac); i++)
    {
        if (mac[i] != 0xA5U)
        {
            written++;
        }
    }
    CHECK((result == CRYPTO_E_KEY_NOT_VALID) && (macLength == sizeof(mac)) && (written == 0U),
          "generate %s: result %d, length %u, %u byte(s) of the buffer written; expected CRYPTO_E_KEY_NOT_VALID, 32, 0",
          When, (int)result, (unsigned)macLength, (unsigned)written);
}

/************************************************* checks ************************************************/

static void Test_KeyState(void)
{
    uint8 mac[32];
    uint32 macLength = sizeof(mac);
    Crypto_VerifyResultType verdict;
    Std_ReturnType result;

    (void)printf("K1 MAC jobs need a valid key\n");
    Test_CsmInit();

    Test_ExpectNoTag("without key");
    result = Test_Verify(Test_Message, sizeof(Test_Message), mac, 128U, &verdict);
    CHECK((result == CRYPTO_E_KEY_NOT_VALID) && (verdict == CRYPTO_E_VER_NOT_OK),
          "verify without key returned %d verdict %d", (int)result, (int)verdict);

    CHECK(Csm_KeyElementSet(CSM_KEYID_MAC_TX, CRYPTO_KE_MAC_KEY, Test_KeyA, 32U) == E_OK, "Csm_KeyElementSet failed");
    Test_ExpectNoTag("before Csm_KeySetValid");

    CHECK(Csm_KeySetValid(CSM_KEYID_MAC_TX) == E_OK, "Csm_KeySetValid failed");
    macLength = sizeof(mac);
    result = Test_Generate(Test_Message, sizeof(Test_Message), mac, &macLength);
    CHECK((result == E_OK) && (macLength == 32U), "generate after Csm_KeySetValid returned %d, length %u", (int)result, (unsigned)macLength);

    /* the receive key is a different key: still not valid */
    result = Test_Verify(Test_Message, sizeof(Test_Message), mac, 256U, &verdict);
    CHECK((result == CRYPTO_E_KEY_NOT_VALID) && (verdict == CRYPTO_E_VER_NOT_OK),
          "verify with only the transmit key installed returned %d verdict %d", (int)result, (int)verdict);

    CHECK(Csm_KeySetValid(CSM_KEYID_MAC_RX) != E_OK, "Csm_KeySetValid accepted a key without key material");

    /* a new Csm_Init drops the keys */
    Test_CsmInit();
    Test_ExpectNoTag("after re-initialisation");
    CHECK(Csm_KeySetValid(CSM_KEYID_MAC_TX) != E_OK, "after re-initialisation Csm_KeySetValid alone made the old key valid again");

    /* so does Csm_DeInit */
    Test_CsmInit();
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyA, 32U);
    Csm_DeInit();
    Test_CsmInit();
    Test_ExpectNoTag("after Csm_DeInit and a new Csm_Init");
    CHECK(Csm_KeySetValid(CSM_KEYID_MAC_TX) != E_OK, "after Csm_DeInit Csm_KeySetValid alone made the old key valid again");
}

static void Test_KnownAnswers(void)
{
    uint32 i;

    (void)printf("K2 RFC 4231 and RFC 4868 known answers through Csm_MacGenerate\n");
    Test_CsmInit();

    for (i = 0U; i < TEST_NUM_VECTORS; i++)
    {
        const Test_VectorType* v = &Test_Vectors[i];
        uint8 mac[64];
        uint32 macLength;
        Crypto_VerifyResultType verdict;
        Std_ReturnType result;

        CHECK(Test_InstallKey(CSM_KEYID_MAC_TX, v->Key, v->KeyLength) == E_OK, "%s: key not installed", v->Name);
        CHECK(Test_InstallKey(CSM_KEYID_MAC_RX, v->Key, v->KeyLength) == E_OK, "%s: key not installed", v->Name);

        /* buffer of the printed length: complete tag, or the most significant bytes for case 5 */
        (void)memset(mac, 0x5A, sizeof(mac));
        macLength = v->MacLength;
        result = Test_Generate(v->Data, v->DataLength, mac, &macLength);
        CHECK((result == E_OK) && (macLength == v->MacLength) && (memcmp(mac, v->Mac, v->MacLength) == 0),
              "%s: result %d length %u, tag differs", v->Name, (int)result, (unsigned)macLength);
        CHECK(mac[v->MacLength] == 0x5A, "%s: wrote past the buffer length", v->Name);

        /* larger buffer: the length comes back as 32 */
        macLength = sizeof(mac);
        result = Test_Generate(v->Data, v->DataLength, mac, &macLength);
        CHECK((result == E_OK) && (macLength == 32U) && (memcmp(mac, v->Mac, v->MacLength) == 0),
              "%s: 64-byte buffer gave result %d length %u", v->Name, (int)result, (unsigned)macLength);

        /* 4 bytes: truncated to the most significant 32 bits */
        (void)memset(mac, 0x5A, sizeof(mac));
        macLength = 4U;
        result = Test_Generate(v->Data, v->DataLength, mac, &macLength);
        CHECK((result == E_OK) && (macLength == 4U) && (memcmp(mac, v->Mac, 4U) == 0) && (mac[4] == 0x5A),
              "%s: truncation to 4 bytes gave result %d length %u", v->Name, (int)result, (unsigned)macLength);

        result = Test_Verify(v->Data, v->DataLength, v->Mac, v->MacLength * 8U, &verdict);
        CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_OK), "%s: Csm_MacVerify result %d verdict %d",
              v->Name, (int)result, (int)verdict);
    }
    (void)printf("   %u vectors\n", (unsigned)TEST_NUM_VECTORS);
}

static void Test_VerifyRejects(void)
{
    uint8 mac[32];
    uint8 bad[32];
    uint32 macLength = sizeof(mac);
    uint32 bit;
    uint32 rejected = 0U;
    Crypto_VerifyResultType verdict;
    Std_ReturnType result;

    (void)printf("K3 Csm_MacVerify: right tag, flipped bit, short tag, wrong key\n");
    Test_CsmInit();
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyA, 32U);
    (void)Test_InstallKey(CSM_KEYID_MAC_RX, Test_KeyA, 32U);
    result = Test_Generate(Test_Message, sizeof(Test_Message), mac, &macLength);
    CHECK((result == E_OK) && (macLength == 32U), "generate failed");

    result = Test_Verify(Test_Message, sizeof(Test_Message), mac, 256U, &verdict);
    CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_OK), "complete tag: result %d verdict %d", (int)result, (int)verdict);
    result = Test_Verify(Test_Message, sizeof(Test_Message), mac, 128U, &verdict);
    CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_OK), "128-bit tag: result %d verdict %d", (int)result, (int)verdict);

    /* every single bit of the 128-bit tag */
    for (bit = 0U; bit < 128U; bit++)
    {
        (void)memcpy(bad, mac, sizeof(bad));
        bad[bit / 8U] ^= (uint8)(0x80U >> (bit % 8U));
        result = Test_Verify(Test_Message, sizeof(Test_Message), bad, 128U, &verdict);
        if ((result == E_OK) && (verdict == CRYPTO_E_VER_NOT_OK))
        {
            rejected++;
        }
    }
    CHECK(rejected == 128U, "%u of 128 single-bit changes of the tag rejected", (unsigned)rejected);

    /* and of the complete 256-bit tag, compared over 256 bits (the handshake's confirmation MACs) */
    {
        uint8 full[32];
        uint8 changed[32];
        uint32 fullLength = sizeof(full);
        uint32 fullRejected = 0U;
        uint32 b;

        (void)Test_Generate(Test_Message, sizeof(Test_Message), full, &fullLength);
        for (b = 0U; b < 256U; b++)
        {
            (void)memcpy(changed, full, sizeof(changed));
            changed[b / 8U] ^= (uint8)(0x80U >> (b % 8U));
            result = Test_Verify(Test_Message, sizeof(Test_Message), changed, 256U, &verdict);
            if ((result == E_OK) && (verdict == CRYPTO_E_VER_NOT_OK))
            {
                fullRejected++;
            }
        }
        CHECK((fullLength == 32U) && (fullRejected == 256U), "%u of 256 single-bit changes of the complete tag rejected", (unsigned)fullRejected);
    }

    /* a changed message */
    (void)memcpy(bad, Test_Message, sizeof(Test_Message));
    bad[13] ^= 0x01U;
    result = Test_Verify(bad, sizeof(Test_Message), mac, 128U, &verdict);
    CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_NOT_OK), "changed message: result %d verdict %d", (int)result, (int)verdict);

    /* a correct prefix shorter than the job's compare length is not a tag */
    result = Test_Verify(Test_Message, sizeof(Test_Message), mac, 64U, &verdict);
    CHECK((result != E_OK) && (verdict == CRYPTO_E_VER_NOT_OK), "64-bit prefix: result %d verdict %d", (int)result, (int)verdict);
    result = Test_Verify(Test_Message, sizeof(Test_Message), mac, 0U, &verdict);
    CHECK((result != E_OK) && (verdict == CRYPTO_E_VER_NOT_OK), "0-bit tag: result %d verdict %d", (int)result, (int)verdict);
    result = Test_Verify(Test_Message, sizeof(Test_Message), mac, 129U, &verdict);
    CHECK((result != E_OK) && (verdict == CRYPTO_E_VER_NOT_OK), "129-bit tag: result %d verdict %d", (int)result, (int)verdict);
    result = Test_Verify(Test_Message, sizeof(Test_Message), mac, 264U, &verdict);
    CHECK((result != E_OK) && (verdict == CRYPTO_E_VER_NOT_OK), "264-bit tag: result %d verdict %d", (int)result, (int)verdict);

    /* wrong key on the verifying side */
    (void)Test_InstallKey(CSM_KEYID_MAC_RX, Test_KeyB, 32U);
    result = Test_Verify(Test_Message, sizeof(Test_Message), mac, 128U, &verdict);
    CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_NOT_OK), "wrong key: result %d verdict %d", (int)result, (int)verdict);
}

static void Test_KeyReplacement(void)
{
    uint8 macOld[32];
    uint8 macNew[32];
    uint32 macLength = sizeof(macOld);
    Crypto_VerifyResultType verdict;
    Std_ReturnType result;
    const uint8* storage = NULL;
    uint32 storageLength = 0U;
    uint32 tailBefore;
    uint32 tailAfter;

    (void)printf("K4 key replacement\n");
    Test_CsmInit();
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyA, 32U);
    (void)Test_InstallKey(CSM_KEYID_MAC_RX, Test_KeyA, 32U);
    (void)Test_Generate(Test_Message, sizeof(Test_Message), macOld, &macLength);
    result = Test_Verify(Test_Message, sizeof(Test_Message), macOld, 128U, &verdict);
    CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_OK), "old key does not verify its own tag");

    /* SWS Crypto 7.2.4: writing a key element makes the key invalid until it is set valid again */
    CHECK(Csm_KeyElementSet(CSM_KEYID_MAC_RX, CRYPTO_KE_MAC_KEY, Test_KeyB, 32U) == E_OK, "Csm_KeyElementSet failed");
    result = Test_Verify(Test_Message, sizeof(Test_Message), macOld, 128U, &verdict);
    CHECK((result == CRYPTO_E_KEY_NOT_VALID) && (verdict == CRYPTO_E_VER_NOT_OK),
          "verify between Csm_KeyElementSet and Csm_KeySetValid: result %d verdict %d", (int)result, (int)verdict);
    CHECK(Csm_KeySetValid(CSM_KEYID_MAC_RX) == E_OK, "Csm_KeySetValid failed");

    result = Test_Verify(Test_Message, sizeof(Test_Message), macOld, 128U, &verdict);
    CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_NOT_OK), "tag of the replaced key still verifies: result %d verdict %d",
          (int)result, (int)verdict);

    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyB, 32U);
    macLength = sizeof(macNew);
    (void)Test_Generate(Test_Message, sizeof(Test_Message), macNew, &macLength);
    CHECK(memcmp(macOld, macNew, sizeof(macNew)) != 0, "old and new key give the same tag");
    result = Test_Verify(Test_Message, sizeof(Test_Message), macNew, 128U, &verdict);
    CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_OK), "new key does not verify its own tag");

    /* a shorter key replaces a longer one completely (case 2 key is 4 bytes): the tag is the new key's,
     * and the bytes of the 32-byte key behind the new length are gone from the driver's key table.
     * The receive slot gets another key first, so that the send slot is the only place of Test_KeyB. */
    (void)Test_InstallKey(CSM_KEYID_MAC_RX, Test_KeyA, 32U);
    Crypto_Mac_TestStorage(&storage, &storageLength);
    tailBefore = Test_FindFrom(storage, storageLength, Test_KeyB, Test_Vectors[1].KeyLength);
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_Vectors[1].Key, Test_Vectors[1].KeyLength);
    macLength = sizeof(macNew);
    (void)Test_Generate(Test_Vectors[1].Data, Test_Vectors[1].DataLength, macNew, &macLength);
    CHECK(memcmp(macNew, Test_Vectors[1].Mac, 32U) == 0, "4-byte key after a 32-byte key gives a wrong tag");
    tailAfter = Test_FindFrom(storage, storageLength, Test_KeyB, Test_Vectors[1].KeyLength);
    CHECK((tailBefore == 1U) && (tailAfter == 0U),
          "bytes %u to 31 of the 32-byte key are %u time(s) in the key table before the %u-byte key is written and %u time(s) after, expected 1 and 0",
          (unsigned)Test_Vectors[1].KeyLength, (unsigned)tailBefore, (unsigned)Test_Vectors[1].KeyLength, (unsigned)tailAfter);
}

static void Test_ServiceAndKeyChecks(void)
{
    uint8 mac[32];
    uint8 macAgain[32];
    uint8 longKey[33];
    uint32 macLength = sizeof(mac);
    Crypto_VerifyResultType verdict = CRYPTO_E_VER_OK;
    Std_ReturnType result;

    (void)printf("K5 job service and key element checks\n");
    Test_CsmInit();
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyA, 32U);
    (void)Test_InstallKey(CSM_KEYID_MAC_RX, Test_KeyA, 32U);
    (void)Test_Generate(Test_Message, sizeof(Test_Message), mac, &macLength);

    /* the verify job does not generate, the generate job does not verify, a signature job does neither */
    macLength = sizeof(mac);
    result = Csm_MacGenerate(CSM_JOBID_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, Test_Message, sizeof(Test_Message), mac, &macLength);
    CHECK(result == E_NOT_OK, "Csm_MacGenerate on the verify job returned %d", (int)result);
    result = Csm_MacVerify(CSM_JOBID_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, Test_Message, sizeof(Test_Message), mac, 128U, &verdict);
    CHECK((result == E_NOT_OK) && (verdict == CRYPTO_E_VER_NOT_OK), "Csm_MacVerify on the generate job returned %d verdict %d",
          (int)result, (int)verdict);
    macLength = sizeof(mac);
    result = Csm_MacGenerate(CSM_JOBID, CRYPTO_OPERATIONMODE_SINGLECALL, Test_Message, sizeof(Test_Message), mac, &macLength);
    CHECK(result == E_NOT_OK, "Csm_MacGenerate on the signature job returned %d", (int)result);
    verdict = CRYPTO_E_VER_OK;
    result = Csm_MacVerify(CSM_JOBID_VERIFY_PEER_BASE, CRYPTO_OPERATIONMODE_SINGLECALL, Test_Message, sizeof(Test_Message), mac, 128U, &verdict);
    CHECK((result == E_NOT_OK) && (verdict == CRYPTO_E_VER_NOT_OK), "Csm_MacVerify on the signature job returned %d verdict %d",
          (int)result, (int)verdict);
    macLength = sizeof(mac);
    result = Csm_MacGenerate(0U, CRYPTO_OPERATIONMODE_SINGLECALL, Test_Message, sizeof(Test_Message), mac, &macLength);
    CHECK(result == E_NOT_OK, "Csm_MacGenerate on job 0 (not configured) returned %d", (int)result);

    /* null pointers */
    macLength = sizeof(mac);
    CHECK(Test_Generate(NULL, 8U, mac, &macLength) != E_OK, "generate accepted a null data pointer");
    CHECK(Test_Generate(Test_Message, sizeof(Test_Message), NULL, &macLength) != E_OK, "generate accepted a null MAC pointer");
    CHECK(Test_Generate(Test_Message, sizeof(Test_Message), mac, NULL) != E_OK, "generate accepted a null length pointer");

    /* the MAC key element holds up to 32 bytes; only key element 1 exists */
    (void)memset(longKey, 0xAA, sizeof(longKey));
    result = Csm_KeyElementSet(CSM_KEYID_MAC_TX, CRYPTO_KE_MAC_KEY, longKey, sizeof(longKey));
    CHECK(result == CRYPTO_E_KEY_SIZE_MISMATCH, "33-byte key returned %d, expected CRYPTO_E_KEY_SIZE_MISMATCH", (int)result);
    result = Csm_KeyElementSet(CSM_KEYID_MAC_TX, CRYPTO_KE_MAC_KEY, longKey, 0U);
    CHECK(result != E_OK, "0-byte key accepted");
    result = Csm_KeyElementSet(CSM_KEYID_MAC_TX, 2U, Test_KeyA, 32U);
    CHECK(result != E_OK, "key element 2 accepted");
    result = Csm_KeyElementSet(CSM_KEYID_HS_KC + 1U, CRYPTO_KE_MAC_KEY, Test_KeyA, 32U);
    CHECK(result != E_OK, "a fourth MAC key of one peer accepted");
    /* a rejected write leaves the installed key in place and valid */
    macLength = sizeof(macAgain);
    result = Test_Generate(Test_Message, sizeof(Test_Message), macAgain, &macLength);
    CHECK((result == E_OK) && (memcmp(macAgain, mac, 32U) == 0), "key changed by a rejected Csm_KeyElementSet");
}

static void Test_StreamingAndRepeats(void)
{
    const Test_VectorType* v = &Test_Vectors[1];
    uint8 mac[32];
    uint8 macTx[32];
    uint8 macRxKey[32];
    uint32 macLength;
    uint32 i;
    Crypto_VerifyResultType verdict;
    Std_ReturnType result;

    (void)printf("K6 START/UPDATE/FINISH and repeated messages\n");
    Test_CsmInit();
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, v->Key, v->KeyLength);
    (void)Test_InstallKey(CSM_KEYID_MAC_RX, v->Key, v->KeyLength);

    macLength = sizeof(mac);
    result = Csm_MacGenerate(CSM_JOBID_MAC_GENERATE, CRYPTO_OPERATIONMODE_START, v->Data, 5U, mac, &macLength);
    CHECK(result == E_OK, "START returned %d", (int)result);
    result = Csm_MacGenerate(CSM_JOBID_MAC_GENERATE, CRYPTO_OPERATIONMODE_UPDATE, &v->Data[5], 20U, mac, &macLength);
    CHECK(result == E_OK, "UPDATE returned %d", (int)result);
    result = Csm_MacGenerate(CSM_JOBID_MAC_GENERATE, CRYPTO_OPERATIONMODE_FINISH, &v->Data[25], 3U, mac, &macLength);
    CHECK((result == E_OK) && (macLength == 32U) && (memcmp(mac, v->Mac, 32U) == 0), "FINISH returned %d, tag differs from the single call", (int)result);

    result = Csm_MacVerify(CSM_JOBID_MAC_VERIFY, CRYPTO_OPERATIONMODE_START, v->Data, 10U, v->Mac, 256U, &verdict);
    CHECK(result == E_OK, "verify START returned %d", (int)result);
    verdict = CRYPTO_E_VER_NOT_OK;
    result = Csm_MacVerify(CSM_JOBID_MAC_VERIFY, CRYPTO_OPERATIONMODE_FINISH, &v->Data[10], 18U, v->Mac, 256U, &verdict);
    CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_OK), "verify FINISH returned %d verdict %d", (int)result, (int)verdict);

    /* the two keys do not disturb each other; each message starts from the key alone */
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyA, 32U);
    (void)Test_InstallKey(CSM_KEYID_MAC_RX, Test_KeyB, 32U);
    macLength = sizeof(macTx);
    (void)Test_Generate(Test_Message, sizeof(Test_Message), macTx, &macLength);
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyB, 32U);
    macLength = sizeof(macRxKey);
    (void)Test_Generate(Test_Message, sizeof(Test_Message), macRxKey, &macLength);
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyA, 32U);
    for (i = 0U; i < 1000U; i++)
    {
        macLength = sizeof(mac);
        result = Test_Generate(Test_Message, sizeof(Test_Message), mac, &macLength);
        if ((result != E_OK) || (memcmp(mac, macTx, 32U) != 0))
        {
            CHECK(FALSE, "generate %u of 1000 on one key differs", (unsigned)i);
            break;
        }
        result = Test_Verify(Test_Message, sizeof(Test_Message), macRxKey, 128U, &verdict);
        if ((result != E_OK) || (verdict != CRYPTO_E_VER_OK))
        {
            CHECK(FALSE, "verify %u of 1000 on the other key failed", (unsigned)i);
            break;
        }
        /* direction keys: a tag made with the transmit key does not verify with the receive key */
        result = Test_Verify(Test_Message, sizeof(Test_Message), mac, 128U, &verdict);
        if ((result != E_OK) || (verdict != CRYPTO_E_VER_NOT_OK))
        {
            CHECK(FALSE, "own tag %u of 1000 verified with the receive key", (unsigned)i);
            break;
        }
    }
}

static void Test_Allocations(boolean Counting)
{
    const uint32 allowed = (OpenSSL_version_num() >= 0x30500000UL) ? 0U : 2000U;
    uint8 mac[32];
    uint32 macLength;
    uint32 i;
    uint32 before;
    uint32 generateAllocs;
    uint32 verifyAllocs;
    Crypto_VerifyResultType verdict;

    Test_CsmInit();
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyA, 32U);
    (void)Test_InstallKey(CSM_KEYID_MAC_RX, Test_KeyA, 32U);
    macLength = sizeof(mac);
    (void)Test_Generate(Test_Message, sizeof(Test_Message), mac, &macLength);
    (void)Test_Verify(Test_Message, sizeof(Test_Message), mac, 128U, &verdict);

    before = AllocCount;
    for (i = 0U; i < 1000U; i++)
    {
        macLength = 16U;
        (void)Test_Generate(Test_Message, sizeof(Test_Message), mac, &macLength);
    }
    generateAllocs = AllocCount - before;
    (void)printf("K7 OpenSSL allocations in 1000 Csm_MacGenerate calls: %u", (unsigned)generateAllocs);
    before = AllocCount;
    for (i = 0U; i < 1000U; i++)
    {
        (void)Test_Verify(Test_Message, sizeof(Test_Message), mac, 128U, &verdict);
    }
    verifyAllocs = AllocCount - before;
    (void)printf(", in 1000 Csm_MacVerify calls: %u (%s, %s)\n", (unsigned)verifyAllocs,
                 (Counting == TRUE) ? "counted" : "NOT counted: CRYPTO_set_mem_functions refused",
                 OpenSSL_version(OPENSSL_VERSION));
    /* This code allocates nothing per call. OpenSSL's HMAC copies a digest context twice per MAC and
     * allocates for each copy up to 3.4 (measured: 2 per call on 3.0.18, none on 3.5.5), so that is
     * the limit there; a context created per call would be well above it. */
    CHECK(Counting == TRUE, "OpenSSL's allocator could not be replaced: the allocations were not counted");
    CHECK((generateAllocs <= allowed) && (verifyAllocs <= allowed),
          "%u and %u OpenSSL allocations in 1000 generate and 1000 verify calls, at most %u each allowed with this OpenSSL",
          (unsigned)generateAllocs, (unsigned)verifyAllocs, (unsigned)allowed);
}

static void Test_Peers(void)
{
    uint8 mac[16];
    uint32 macLength = sizeof(mac);
    Crypto_VerifyResultType verdict = CRYPTO_E_VER_OK;
    Std_ReturnType result;

    (void)printf("K8 two peers: separate keys and jobs\n");
    Test_CsmInit();

    /* node A sends to its peer 0 with K; node B, here peer slot 1 of the same Csm, receives with K */
    CHECK(Test_InstallKey(CSM_KEYID_MAC_TX_PEER(0U), Test_KeyA, 32U) == E_OK, "send key of peer 0 not installed");
    CHECK(Test_InstallKey(CSM_KEYID_MAC_RX_PEER(1U), Test_KeyA, 32U) == E_OK, "receive key of peer 1 not installed");
    result = Csm_MacGenerate(CSM_JOBID_MAC_GENERATE_PEER(0U), CRYPTO_OPERATIONMODE_SINGLECALL, Test_Message,
                             sizeof(Test_Message), mac, &macLength);
    CHECK((result == E_OK) && (macLength == 16U), "generate job of peer 0: result 0x%02X, %u bytes", (unsigned)result, (unsigned)macLength);
    result = Csm_MacVerify(CSM_JOBID_MAC_VERIFY_PEER(1U), CRYPTO_OPERATIONMODE_SINGLECALL, Test_Message,
                           sizeof(Test_Message), mac, 128U, &verdict);
    CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_OK), "verify job of peer 1 with the same key: result 0x%02X verdict %u",
          (unsigned)result, (unsigned)verdict);

    /* the other jobs of the two peers have no key: nothing was installed for them */
    verdict = CRYPTO_E_VER_OK;
    result = Csm_MacVerify(CSM_JOBID_MAC_VERIFY_PEER(0U), CRYPTO_OPERATIONMODE_SINGLECALL, Test_Message,
                           sizeof(Test_Message), mac, 128U, &verdict);
    CHECK((result == CRYPTO_E_KEY_NOT_VALID) && (verdict == CRYPTO_E_VER_NOT_OK),
          "verify job of peer 0 without a receive key: result 0x%02X verdict %u", (unsigned)result, (unsigned)verdict);
    macLength = sizeof(mac);
    result = Csm_MacGenerate(CSM_JOBID_MAC_GENERATE_PEER(1U), CRYPTO_OPERATIONMODE_SINGLECALL, Test_Message,
                             sizeof(Test_Message), mac, &macLength);
    CHECK(result == CRYPTO_E_KEY_NOT_VALID, "generate job of peer 1 without a send key: result 0x%02X", (unsigned)result);

    /* another receive key at peer 1: the MAC of peer 0's send key no longer verifies there */
    macLength = sizeof(mac);
    (void)Csm_MacGenerate(CSM_JOBID_MAC_GENERATE_PEER(0U), CRYPTO_OPERATIONMODE_SINGLECALL, Test_Message,
                          sizeof(Test_Message), mac, &macLength);
    CHECK(Test_InstallKey(CSM_KEYID_MAC_RX_PEER(1U), Test_KeyB, 32U) == E_OK, "receive key of peer 1 not replaced");
    verdict = CRYPTO_E_VER_OK;
    result = Csm_MacVerify(CSM_JOBID_MAC_VERIFY_PEER(1U), CRYPTO_OPERATIONMODE_SINGLECALL, Test_Message,
                           sizeof(Test_Message), mac, 128U, &verdict);
    CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_NOT_OK), "verify job of peer 1 with another key: result 0x%02X verdict %u",
          (unsigned)result, (unsigned)verdict);

    /* the last slot of the last peer exists (the crypto driver holds a key for every peer and slot) */
    CHECK(Test_InstallKey(CSM_KEYID_HS_KC_PEER(CSM_MAC_NUM_PEERS - 1U), Test_KeyB, 32U) == E_OK,
          "the confirmation slot of the last peer cannot be installed");

    /* only the configured peers and slots exist */
    CHECK(Csm_KeyElementSet(CSM_KEYID_MAC_TX_PEER(CSM_MAC_NUM_PEERS), CRYPTO_KE_MAC_KEY, Test_KeyA, 32U) != E_OK,
          "a MAC key of a peer beyond CSM_MAC_NUM_PEERS was accepted");
    CHECK(Csm_KeyElementSet(CSM_KEYID_HS_KC_PEER(0U) + 1U, CRYPTO_KE_MAC_KEY, Test_KeyA, 32U) != E_OK,
          "a key ID between the slots of two peers was accepted");
    macLength = sizeof(mac);
    CHECK(Csm_MacGenerate(CSM_JOBID_MAC_GENERATE_PEER(CSM_MAC_NUM_PEERS), CRYPTO_OPERATIONMODE_SINGLECALL, Test_Message,
                          sizeof(Test_Message), mac, &macLength) == E_NOT_OK,
          "a MAC job of a peer beyond CSM_MAC_NUM_PEERS was served");
}

static void Test_ConfirmationKey(void)
{
    static const uint8 zeros[32] = { 0U };
    const Test_VectorType* v = &Test_Vectors[0];
    uint8 mac[32];
    uint8 pduMac[16];
    uint8 pduMacAfter[16];
    uint32 macLength = sizeof(mac);
    Crypto_VerifyResultType verdict = CRYPTO_E_VER_NOT_OK;
    Std_ReturnType result;

    (void)printf("K9 key-confirmation slot\n");
    Test_CsmInit();
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyA, 32U);
    macLength = sizeof(pduMac);
    (void)Test_Generate(Test_Message, sizeof(Test_Message), pduMac, &macLength);

    /* RFC 4231 test case 1 through the slot: the complete tag */
    CHECK(Test_InstallKey(CSM_KEYID_HS_KC, v->Key, v->KeyLength) == E_OK, "confirmation key not installed");
    macLength = sizeof(mac);
    result = Csm_MacGenerate(CSM_JOBID_HS_KC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, v->Data, v->DataLength, mac, &macLength);
    CHECK((result == E_OK) && (macLength == 32U) && (memcmp(mac, v->Mac, 32U) == 0),
          "confirmation generate job: result 0x%02X, %u bytes, tag %s the RFC 4231 value", (unsigned)result,
          (unsigned)macLength, (memcmp(mac, v->Mac, 32U) == 0) ? "is" : "is not");
    result = Csm_MacVerify(CSM_JOBID_HS_KC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, v->Data, v->DataLength, mac, 256U, &verdict);
    CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_OK), "confirmation verify job, 256 bits: result 0x%02X verdict %u",
          (unsigned)result, (unsigned)verdict);
    verdict = CRYPTO_E_VER_OK;
    result = Csm_MacVerify(CSM_JOBID_HS_KC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, v->Data, v->DataLength, mac, 128U, &verdict);
    CHECK((result == E_NOT_OK) && (verdict == CRYPTO_E_VER_NOT_OK),
          "confirmation verify job with 128 of 256 bits: result 0x%02X verdict %u, expected a refusal", (unsigned)result, (unsigned)verdict);
    mac[31] ^= 0x01U;
    verdict = CRYPTO_E_VER_OK;
    result = Csm_MacVerify(CSM_JOBID_HS_KC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, v->Data, v->DataLength, mac, 256U, &verdict);
    CHECK((result == E_OK) && (verdict == CRYPTO_E_VER_NOT_OK), "confirmation verify job, last bit flipped: result 0x%02X verdict %u",
          (unsigned)result, (unsigned)verdict);

    /* the handshake's wipe: zeros written, not set valid */
    CHECK(Csm_KeyElementSet(CSM_KEYID_HS_KC, CRYPTO_KE_MAC_KEY, zeros, 32U) == E_OK, "zero key not written");
    (void)memset(mac, 0xA5, sizeof(mac));
    macLength = sizeof(mac);
    result = Csm_MacGenerate(CSM_JOBID_HS_KC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, v->Data, v->DataLength, mac, &macLength);
    CHECK((result == CRYPTO_E_KEY_NOT_VALID) && (macLength == sizeof(mac)) && (mac[0] == 0xA5U) && (mac[31] == 0xA5U),
          "generate on the wiped slot: result 0x%02X, length %u, buffer %s", (unsigned)result, (unsigned)macLength,
          ((mac[0] == 0xA5U) && (mac[31] == 0xA5U)) ? "untouched" : "written");
    verdict = CRYPTO_E_VER_OK;
    result = Csm_MacVerify(CSM_JOBID_HS_KC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, v->Data, v->DataLength, v->Mac, 256U, &verdict);
    CHECK((result == CRYPTO_E_KEY_NOT_VALID) && (verdict == CRYPTO_E_VER_NOT_OK), "verify on the wiped slot: result 0x%02X verdict %u",
          (unsigned)result, (unsigned)verdict);

    /* the PDU key of the same peer was not touched by any of this */
    macLength = sizeof(pduMacAfter);
    result = Test_Generate(Test_Message, sizeof(Test_Message), pduMacAfter, &macLength);
    CHECK((result == E_OK) && (memcmp(pduMac, pduMacAfter, sizeof(pduMac)) == 0),
          "the PDU send key gives another tag after the confirmation slot was used (result 0x%02X)", (unsigned)result);
}

static void Test_Erasure(boolean Counting)
{
    static const uint8 zeros[32] = { 0U };
    const uint8* storage = NULL;
    uint32 storageLength = 0U;
    uint8 mac[16];
    uint32 macLength = sizeof(mac);
    uint32 live;
    boolean failed = FALSE;

    (void)printf("K10 erasure of replaced keys\n");
    Test_CsmInit();
    Crypto_Mac_TestStorage(&storage, &storageLength);
    if ((storage == NULL) || (storageLength < 32U))
    {
        CHECK(FALSE, "no key storage to look at");
        return;
    }

    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyA, 32U);
    (void)Test_Generate(Test_Message, sizeof(Test_Message), mac, &macLength);
    live = Test_LiveHits(Test_KeyA);
    CHECK(Test_Find(storage, storageLength, Test_KeyA) == 1U, "the active key is %u times in the static key table, expected once",
          (unsigned)Test_Find(storage, storageLength, Test_KeyA));
    (void)printf("   copies of the active key in live OpenSSL heap blocks: %u (%s)\n", (unsigned)live,
                 (Counting == TRUE) ? OpenSSL_version(OPENSSL_VERSION) : "heap NOT observed: CRYPTO_set_mem_functions refused");

    /* replaced by another key */
    WatchKey = Test_KeyA;
    WatchFreedHits = 0U;
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyB, 32U);
    CHECK((Test_Find(storage, storageLength, Test_KeyA) == 0U) && (Test_Find(storage, storageLength, Test_KeyB) == 1U),
          "after the replacement the static key table holds the old key %u times and the new key %u times, expected 0 and 1",
          (unsigned)Test_Find(storage, storageLength, Test_KeyA), (unsigned)Test_Find(storage, storageLength, Test_KeyB));
    CHECK((Test_LiveHits(Test_KeyA) == 0U) && (WatchFreedHits == 0U),
          "after the replacement the old key is in %u live and %u freed OpenSSL heap block(s)",
          (unsigned)Test_LiveHits(Test_KeyA), (unsigned)WatchFreedHits);

    /* overwritten with zeros, the handshake's wipe */
    WatchKey = Test_KeyB;
    WatchFreedHits = 0U;
    (void)Csm_KeyElementSet(CSM_KEYID_MAC_TX, CRYPTO_KE_MAC_KEY, zeros, 32U);
    CHECK((Test_Find(storage, storageLength, Test_KeyB) == 0U) && (Test_LiveHits(Test_KeyB) == 0U) && (WatchFreedHits == 0U),
          "after the zero write the key is %u times in the static table, in %u live and %u freed heap block(s)",
          (unsigned)Test_Find(storage, storageLength, Test_KeyB), (unsigned)Test_LiveHits(Test_KeyB), (unsigned)WatchFreedHits);

    /* the driver initialised again */
    (void)Test_InstallKey(CSM_KEYID_MAC_RX, Test_KeyA, 32U);
    WatchKey = Test_KeyA;
    WatchFreedHits = 0U;
    Test_CsmInit();
    Crypto_Mac_TestStorage(&storage, &storageLength);
    CHECK((Test_Find(storage, storageLength, Test_KeyA) == 0U) && (Test_LiveHits(Test_KeyA) == 0U) && (WatchFreedHits == 0U),
          "after a new initialisation the key is %u times in the static table, in %u live and %u freed heap block(s)",
          (unsigned)Test_Find(storage, storageLength, Test_KeyA), (unsigned)Test_LiveHits(Test_KeyA), (unsigned)WatchFreedHits);

    /* Csm_DeInit */
    (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyB, 32U);
    WatchKey = Test_KeyB;
    WatchFreedHits = 0U;
    Csm_DeInit();
    Crypto_Mac_TestStorage(&storage, &storageLength);
    CHECK((Test_Find(storage, storageLength, Test_KeyB) == 0U) && (Test_LiveHits(Test_KeyB) == 0U) && (WatchFreedHits == 0U),
          "after Csm_DeInit the key is %u times in the static table, in %u live and %u freed heap block(s)",
          (unsigned)Test_Find(storage, storageLength, Test_KeyB), (unsigned)Test_LiveHits(Test_KeyB), (unsigned)WatchFreedHits);

    /* a re-key that fails inside OpenSSL (the allocations of the call are refused, one more each time,
     * until it fails): the old key goes all the same, the new one is not kept, and the slot works
     * again afterwards */
    Test_CsmInit();
    Crypto_Mac_TestStorage(&storage, &storageLength);
    for (live = 1U; live <= 16U; live++)
    {
        (void)Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyA, 32U);
        WatchKey = Test_KeyA;
        WatchFreedHits = 0U;
        FailAllocs = live;
        failed = (Csm_KeyElementSet(CSM_KEYID_MAC_TX, CRYPTO_KE_MAC_KEY, Test_KeyB, 32U) != E_OK) ? TRUE : FALSE;
        FailAllocs = 0U;
        if (failed == TRUE)
        {
            break;
        }
    }
    if (failed == FALSE)
    {
        (void)printf("   a failing re-key could not be provoked by refusing up to 16 allocations\n");
    }
    else
    {
        (void)printf("   re-key failed with allocation %u of the call refused\n", (unsigned)live);
        CHECK((Test_Find(storage, storageLength, Test_KeyA) == 0U) && (Test_Find(storage, storageLength, Test_KeyB) == 0U) &&
              (Test_LiveHits(Test_KeyA) == 0U) && (Test_LiveHits(Test_KeyB) == 0U) && (WatchFreedHits == 0U),
              "after a failed re-key: old key %u and new key %u times in the static table, old key in %u live and %u freed heap block(s), new key in %u live block(s)",
              (unsigned)Test_Find(storage, storageLength, Test_KeyA), (unsigned)Test_Find(storage, storageLength, Test_KeyB),
              (unsigned)Test_LiveHits(Test_KeyA), (unsigned)WatchFreedHits, (unsigned)Test_LiveHits(Test_KeyB));
        macLength = sizeof(mac);
        CHECK(Test_Generate(Test_Message, sizeof(Test_Message), mac, &macLength) == CRYPTO_E_KEY_NOT_VALID,
              "a MAC job was served after a failed re-key");
    }
    macLength = sizeof(mac);
    CHECK((Test_InstallKey(CSM_KEYID_MAC_TX, Test_KeyB, 32U) == E_OK) &&
          (Test_Generate(Test_Message, sizeof(Test_Message), mac, &macLength) == E_OK),
          "the key slot does not take a key after a failed re-key");
    WatchKey = NULL;
}

int main(void)
{
    /* has to come before the first OpenSSL allocation */
    boolean counting = (CRYPTO_set_mem_functions(Test_Malloc, Test_Realloc, Test_Free) == 1) ? TRUE : FALSE;

    (void)setvbuf(stdout, NULL, _IOLBF, 0);

    Test_KeyState();
    Test_KnownAnswers();
    Test_VerifyRejects();
    Test_KeyReplacement();
    Test_ServiceAndKeyChecks();
    Test_StreamingAndRepeats();
    Test_Allocations(counting);
    Test_Peers();
    Test_ConfirmationKey();
    Test_Erasure(counting);

    (void)printf("%s: %u failed check(s)\n", (Failures == 0U) ? "PASS" : "FAIL", (unsigned)Failures);
    return (Failures == 0U) ? 0 : 1;
}
