# In-process tests of the handshake PQC-SecOC-HS-v1 and of the crypto layer under it.
# Included by the top-level CMakeLists.txt (needs headerDirs, LIBOQS_* and the SecOCLib target).
#
# The sources listed in PQCHS_TEST_ACCESS_SOURCES are compiled into the test with SECOC_TEST_ACCESS:
# storage accessors (Csm session key objects, key table of the MAC driver) and the secret tap that the
# erasure and known-answer tests need. That macro is never defined for the gateway or the libraries.
if(UNIX)
    set(PQCHS_TEST_ACCESS_SOURCES ${CMAKE_SOURCE_DIR}/source/Csm/Csm_Pqc.c ${CMAKE_SOURCE_DIR}/source/Encrypt/Crypto_Mac.c)

    add_executable(pqc_crypto_layer_test test/test_pqc_crypto_layer.c ${PQCHS_TEST_ACCESS_SOURCES})
    target_include_directories(pqc_crypto_layer_test PRIVATE ${headerDirs} ${LIBOQS_INCLUDE_DIR})
    target_link_libraries(pqc_crypto_layer_test SecOCLib ${LIBOQS_LIBRARY} OpenSSL::Crypto rt)
    target_compile_definitions(pqc_crypto_layer_test PRIVATE LINUX SECOC_TEST_ACCESS)
    target_compile_options(pqc_crypto_layer_test PRIVATE -Wall -Wextra)
    foreach(_sym OQS_SIG_new OQS_KEM_new)
        target_link_options(pqc_crypto_layer_test PRIVATE "-Wl,--wrap=${_sym}")
    endforeach()
    add_test(NAME PQC_CryptoLayer COMMAND pqc_crypto_layer_test)
endif()

# Handshake: initiator and responder instance back to back in one process. Everything PqcHs uses from
# SoAd, SecOC and FVM, and the Csm calls it makes, are intercepted at link time (see test/test_pqchs.c).
# The second argument is the file the known-answer transcript is written to (checked by kat_pqchs.py).
# The transcript is a fixture: the check runs only behind a run of pqchs_test that passed.
if(UNIX)
    add_executable(pqchs_test test/test_pqchs.c ${PQCHS_TEST_ACCESS_SOURCES})
    target_include_directories(pqchs_test PRIVATE ${headerDirs} ${LIBOQS_INCLUDE_DIR})
    target_link_libraries(pqchs_test SecOCLib ${LIBOQS_LIBRARY} OpenSSL::Crypto rt)
    target_compile_definitions(pqchs_test PRIVATE LINUX SECOC_TEST_ACCESS)
    target_compile_options(pqchs_test PRIVATE -Wall -Wextra)
    foreach(_sym SoAd_TpTransmit SoAd_SetUpperLayer SoAd_RxGateRelease SecOC_RxSessionDrained SecOC_TxSessionHold SecOC_TxSessionFlushed
                 FVM_SessionInstall Csm_MacGenerate Csm_MacVerify Csm_KeyElementSet Csm_KeySetValid
                 Csm_SignatureGenerate Csm_SignatureVerify Csm_CustomService)
        target_link_options(pqchs_test PRIVATE "-Wl,--wrap=${_sym}")
    endforeach()
    add_test(NAME PqcHs_BackToBack COMMAND pqchs_test ${CMAKE_BINARY_DIR}/pqchs_kat.txt)
    add_test(NAME PqcHs_KnownAnswer COMMAND python3 ${CMAKE_SOURCE_DIR}/test/kat_pqchs.py ${CMAKE_BINARY_DIR}/pqchs_kat.txt)
    set_tests_properties(PqcHs_BackToBack PROPERTIES TIMEOUT 300 FIXTURES_SETUP pqchs_kat)
    set_tests_properties(PqcHs_KnownAnswer PROPERTIES FIXTURES_REQUIRED pqchs_kat)
    # the in-process programs have one label: "ctest -L INPROCESS" runs them in a build configured with tests
    set_tests_properties(PQC_CryptoLayer PqcHs_BackToBack PqcHs_KnownAnswer PROPERTIES LABELS "INPROCESS")
endif()
