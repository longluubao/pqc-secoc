cmake_minimum_required(VERSION 3.20)
# Build type: Release (-O2 here) unless another one is asked for with -DCMAKE_BUILD_TYPE. The tree
# was found with Debug forced on this line; nothing is unoptimised by default any more.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ---- Code Coverage Option ----
option(ENABLE_COVERAGE "Build with code coverage instrumentation (gcov)" OFF)
option(BUILD_TESTS "Build GoogleTest unit tests (pulls googletest via FetchContent)" ON)
option(SECOC_PERF "Build with SecOC Tx pipeline performance probes (CSV+shm live)" OFF)
option(SECOC_ENABLE_TEST_SHIM "Compile failure-injection ethernet shim (test only)" OFF)
if(SECOC_PERF)
    message(STATUS "SecOC perf probes: ENABLED -> SECOC_PERF_INSTRUMENT=1")
endif()

# ---- Role, addresses, keys, liboqs and commit stamp (one tree, two gateways) ----
# Usage: cmake -DSECOC_ROLE=TX -DSECOC_LOCAL_IP=10.10.10.1 -DSECOC_PEER_IP=10.10.10.2
#              -DPQC_MLDSA_KEY_DIR=/home/me/keys/ -DSECOC_GIT_COMMIT=<hash> ..
# Unset options keep the defaults in the headers (what scripts/configure_role.sh edits).
set(SECOC_ROLE "" CACHE STRING "Gateway role: TX (sender) or RX (receiver)")
set(SECOC_LOCAL_IP "" CACHE STRING "IPv4 address of this gateway on the experiment link")
set(SECOC_PEER_IP "" CACHE STRING "IPv4 address of the peer gateway on the experiment link")
set(PQC_MLDSA_KEY_DIR "" CACHE STRING "ML-DSA key directory, with trailing slash")
set(SECOC_PORT "" CACHE STRING "TCP port of the gateway PDUs (receiver listens, transmitter connects); default 50002")
set(SECOC_GIT_COMMIT "unknown" CACHE STRING "Commit hash printed at start-up (the Pis build from an rsync copy without .git)")
option(SECOC_QUIET "Build without the per-cycle debug prints of SecOC_Debug.h" OFF)
if(SECOC_QUIET)
    add_compile_definitions(SECOC_QUIET)
endif()
set(LIBOQS_ROOT "${CMAKE_SOURCE_DIR}/external/liboqs" CACHE PATH "liboqs source tree containing build/include and build/lib")
if(SECOC_ROLE STREQUAL "TX")
    add_compile_definitions(SECOC_ROLE_SENDER=TRUE SECOC_ROLE_RECEIVER=FALSE)
elseif(SECOC_ROLE STREQUAL "RX")
    add_compile_definitions(SECOC_ROLE_SENDER=FALSE SECOC_ROLE_RECEIVER=TRUE)
elseif(NOT SECOC_ROLE STREQUAL "")
    message(FATAL_ERROR "SECOC_ROLE must be TX or RX")
endif()
# A gateway built with a role but without addresses would bind every interface and connect to the
# address left in the sources (a Wi-Fi address), with nothing in any log to show it.
if(SECOC_ROLE AND (NOT SECOC_LOCAL_IP OR NOT SECOC_PEER_IP))
    message(FATAL_ERROR "SECOC_ROLE needs SECOC_LOCAL_IP and SECOC_PEER_IP")
endif()
if(SECOC_LOCAL_IP)
    string(REPLACE "." "," _secoc_local_ipv4 "${SECOC_LOCAL_IP}")
    add_compile_definitions(SECOC_CFG_LOCAL_IPV4=${_secoc_local_ipv4})
endif()
if(SECOC_PEER_IP)
    string(REPLACE "." "," _secoc_peer_ipv4 "${SECOC_PEER_IP}")
    add_compile_definitions(SECOC_CFG_PEER_IPV4=${_secoc_peer_ipv4})
endif()
if(PQC_MLDSA_KEY_DIR)
    add_compile_definitions(PQC_MLDSA_KEY_DIRECTORY="${PQC_MLDSA_KEY_DIR}")
endif()
if(SECOC_PORT)
    add_compile_definitions(SECOC_CFG_PORT=${SECOC_PORT}U)
endif()
message(STATUS "SecOC role='${SECOC_ROLE}' local='${SECOC_LOCAL_IP}' peer='${SECOC_PEER_IP}' keys='${PQC_MLDSA_KEY_DIR}' commit=${SECOC_GIT_COMMIT}")
if(ENABLE_COVERAGE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
    message(STATUS "Code coverage: ENABLED (gcov)")
endif()

# ---- MCAL Target Selection ----
# Usage: cmake -DMCAL_TARGET=PI4 ..   (or SIM for simulation)
# Default: PI4 on Linux, SIM on Windows
if(NOT DEFINED MCAL_TARGET)
    if(UNIX)
        set(MCAL_TARGET "PI4" CACHE STRING "MCAL target platform (PI4, SIM)")
    else()
        set(MCAL_TARGET "SIM" CACHE STRING "MCAL target platform (PI4, SIM)")
    endif()
endif()
message(STATUS "MCAL Target: ${MCAL_TARGET}")

if (WIN32)
    file(GLOB_RECURSE SCR_FILES CONFIGURE_DEPENDS "source/*.c")
    file(GLOB_RECURSE HDR_FILES CONFIGURE_DEPENDS "include/*.h")
    # Remove Linux-specific files
    list(REMOVE_ITEM SCR_FILES "${CMAKE_SOURCE_DIR}/source/Ethernet/ethernet.c")
    list(REMOVE_ITEM HDR_FILES "${CMAKE_SOURCE_DIR}/include/Ethernet/ethernet.h")
    list(REMOVE_ITEM SCR_FILES "${CMAKE_SOURCE_DIR}/source/Scheduler/scheduler.c")
    list(REMOVE_ITEM HDR_FILES "${CMAKE_SOURCE_DIR}/include/Scheduler/scheduler.h")
    # Remove Windows-specific files from the glob (they're not needed on Linux)
    list(REMOVE_ITEM SCR_FILES "${CMAKE_SOURCE_DIR}/source/Ethernet/ethernet_windows.c")
    list(REMOVE_ITEM HDR_FILES "${CMAKE_SOURCE_DIR}/include/Ethernet/ethernet_windows.h")
    # Add Windows-specific files back
    list(APPEND SCR_FILES "${CMAKE_SOURCE_DIR}/source/Ethernet/ethernet_windows.c")
    list(APPEND HDR_FILES "${CMAKE_SOURCE_DIR}/include/Ethernet/ethernet_windows.h")
    # Remove Pi4 MCAL files on Windows (use simulation CAN)
    file(GLOB_RECURSE MCAL_PI4_FILES "${CMAKE_SOURCE_DIR}/source/Mcal/Pi4/*.c")
    foreach(_f ${MCAL_PI4_FILES})
        list(REMOVE_ITEM SCR_FILES "${_f}")
    endforeach()
elseif(UNIX)
    file(GLOB_RECURSE SCR_FILES CONFIGURE_DEPENDS  "source/*.c")
    file(GLOB_RECURSE HDR_FILES CONFIGURE_DEPENDS  "include/*.h")
    # Remove Windows-specific files on Linux
    list(REMOVE_ITEM SCR_FILES "${CMAKE_SOURCE_DIR}/source/Ethernet/ethernet_windows.c")
    list(REMOVE_ITEM HDR_FILES "${CMAKE_SOURCE_DIR}/include/Ethernet/ethernet_windows.h")
    # Keep scheduler path disabled when OS task-based dispatch is active
    list(REMOVE_ITEM SCR_FILES "${CMAKE_SOURCE_DIR}/source/Scheduler/scheduler.c")
    list(REMOVE_ITEM HDR_FILES "${CMAKE_SOURCE_DIR}/include/Scheduler/scheduler.h")
    # Compiler + generator selection: respect the environment. Forcing
    # gcc/g++ and "Unix Makefiles" here breaks CI invocations that pass
    # -GNinja or CC=clang (the googletest FetchContent sub-build then
    # tries to feed a Makefile to Ninja).

    # ---- MCAL Target-specific source selection ----
    if(MCAL_TARGET STREQUAL "PI4")
        # Replace simulation CAN driver with SocketCAN Pi4 driver
        list(REMOVE_ITEM SCR_FILES "${CMAKE_SOURCE_DIR}/source/Can/Can.c")
        message(STATUS "MCAL: Using Pi4 SocketCAN driver (replacing simulation Can.c)")
    else()
        # SIM mode: remove Pi4-specific MCAL source files
        file(GLOB_RECURSE MCAL_PI4_FILES "${CMAKE_SOURCE_DIR}/source/Mcal/Pi4/*.c")
        foreach(_f ${MCAL_PI4_FILES})
            list(REMOVE_ITEM SCR_FILES "${_f}")
        endforeach()
        message(STATUS "MCAL: Using simulation mode (Can.c software queues)")
    endif()
endif()

project(SecOC)

set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")
string(TOUPPER "${CMAKE_BUILD_TYPE}" _secoc_build_type)
string(STRIP "${CMAKE_BUILD_TYPE}: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION} ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${_secoc_build_type}}" SECOC_BUILD_INFO)
message(STATUS "SecOC build: ${SECOC_BUILD_INFO}")

# gcc 14 promotes -Wimplicit-function-declaration and
# -Wincompatible-pointer-types from warning to hard error by default.
# A lot of AUTOSAR C relies on forward-declared extern functions and
# header pathing that built cleanly on gcc 13 but trips those checks
# on gcc 14+ (e.g. Raspberry Pi OS "Bookworm" and later).
# Downgrade to warnings so the Pi build keeps working while we clean
# up the underlying missing includes incrementally.
if(CMAKE_C_COMPILER_ID STREQUAL "GNU"
   AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL "14")
    add_compile_options(
        -Wno-error=implicit-function-declaration
        -Wno-error=incompatible-pointer-types
    )
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Add liboqs library path
set(LIBOQS_INCLUDE_DIR "${LIBOQS_ROOT}/build/include")
set(LIBOQS_LIB_DIR "${LIBOQS_ROOT}/build/lib")
set(LIBOQS_LIBRARY "${LIBOQS_LIB_DIR}/liboqs.a")

# Check if liboqs exists
if(NOT EXISTS ${LIBOQS_LIBRARY})
    message(FATAL_ERROR "liboqs not found! Please build liboqs first in external/liboqs/build")
endif()


add_executable(SecOC ${SCR_FILES})
# Only main.c and the applications use the stamps, so a new commit recompiles four files.
set_source_files_properties(source/main.c source/App/App_Tx.c source/App/App_Rx.c source/App/App_Hs.c
                            PROPERTIES COMPILE_DEFINITIONS "SECOC_GIT_COMMIT=\"${SECOC_GIT_COMMIT}\";SECOC_BUILD_INFO=\"${SECOC_BUILD_INFO}\";SECOC_ADDR_INFO=\"local ${SECOC_LOCAL_IP}, peer ${SECOC_PEER_IP}, port ${SECOC_PORT}\"")

# Add liboqs include directory
target_include_directories(SecOC PUBLIC ${LIBOQS_INCLUDE_DIR})

# Link liboqs library (requires OpenSSL)
target_link_libraries(SecOC ${LIBOQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL)

if(THREADS_HAVE_PTHREAD_ARG)
  target_compile_options(SecOC PUBLIC "-pthread")
endif()
if(CMAKE_THREAD_LIBS_INIT)
  target_link_libraries(SecOC "${CMAKE_THREAD_LIBS_INIT}")
endif()

foreach (_file ${HDR_FILES})
    cmake_path(REMOVE_FILENAME _file)

    target_include_directories(SecOC PUBLIC ${_file})
endforeach()


if(WIN32)
    target_compile_definitions(SecOC PUBLIC WINDOWS)
    target_compile_definitions(SecOC PUBLIC MCAL_TARGET=MCAL_TARGET_SIM)
    # Link Winsock2 library for Windows sockets
    target_link_libraries(SecOC ws2_32)
elseif(UNIX)
    target_compile_definitions(SecOC PUBLIC LINUX)
    if(MCAL_TARGET STREQUAL "PI4")
        target_compile_definitions(SecOC PUBLIC MCAL_TARGET=MCAL_TARGET_PI4)
    else()
        target_compile_definitions(SecOC PUBLIC MCAL_TARGET=MCAL_TARGET_SIM)
    endif()
endif()

# ---- Performance instrumentation (opt-in) ----
if(SECOC_PERF)
    target_compile_definitions(SecOC PUBLIC SECOC_PERF_INSTRUMENT=1)
    if(UNIX)
        target_link_libraries(SecOC rt)
    endif()
endif()
if(SECOC_ENABLE_TEST_SHIM)
    target_compile_definitions(SecOC PUBLIC SECOC_ENABLE_TEST_SHIM=1)
endif()


# Adding unit tests (skippable via -DBUILD_TESTS=OFF for static-analysis builds
# like CodeQL where FetchContent googletest's Makefile sub-build clashes with
# a Ninja parent build).
if(BUILD_TESTS)
    include(CTest)

    include(FetchContent)

    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.15.2
    )
    FetchContent_MakeAvailable(googletest)
endif()

# Extract include directories from main target SecOC
set(headerDirs "")
get_target_property(headerDirs SecOC INCLUDE_DIRECTORIES)

# Print include directories one per line for cppchecke extension 
string(REPLACE ";"  "\n" cppincludes "${headerDirs}")
file(WRITE "${CMAKE_SOURCE_DIR}/build/cppcheck_includes.txt" ${cppincludes})

# Create static library for linking with gtest
add_library(SecOCLib STATIC ${SCR_FILES} ${HDR_FILES})
target_include_directories(SecOCLib PUBLIC ${headerDirs} ${LIBOQS_INCLUDE_DIR})
target_link_libraries(SecOCLib ${LIBOQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL)

# Create shared library for linking with the GUI
add_library(SecOCLibShared SHARED ${SCR_FILES} ${HDR_FILES})
target_include_directories(SecOCLibShared PUBLIC ${headerDirs} ${LIBOQS_INCLUDE_DIR})
target_link_libraries(SecOCLibShared ${LIBOQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL)

# Platform-specific configurations for libraries
if(WIN32)
    target_compile_definitions(SecOCLib PUBLIC WINDOWS)
    target_compile_definitions(SecOCLibShared PUBLIC WINDOWS)
    target_compile_definitions(SecOCLib PUBLIC MCAL_TARGET=MCAL_TARGET_SIM)
    target_compile_definitions(SecOCLibShared PUBLIC MCAL_TARGET=MCAL_TARGET_SIM)
    target_link_libraries(SecOCLib ws2_32)
    target_link_libraries(SecOCLibShared ws2_32)
elseif(UNIX)
    target_compile_definitions(SecOCLib PUBLIC LINUX)
    target_compile_definitions(SecOCLibShared PUBLIC LINUX)
    if(MCAL_TARGET STREQUAL "PI4")
        target_compile_definitions(SecOCLib PUBLIC MCAL_TARGET=MCAL_TARGET_PI4)
        target_compile_definitions(SecOCLibShared PUBLIC MCAL_TARGET=MCAL_TARGET_PI4)
    else()
        target_compile_definitions(SecOCLib PUBLIC MCAL_TARGET=MCAL_TARGET_SIM)
        target_compile_definitions(SecOCLibShared PUBLIC MCAL_TARGET=MCAL_TARGET_SIM)
    endif()
endif()

if(SECOC_PERF)
    target_compile_definitions(SecOCLib PUBLIC SECOC_PERF_INSTRUMENT=1)
    target_compile_definitions(SecOCLibShared PUBLIC SECOC_PERF_INSTRUMENT=1)
    if(UNIX)
        target_link_libraries(SecOCLib rt)
        target_link_libraries(SecOCLibShared rt)
    endif()
endif()
if(SECOC_ENABLE_TEST_SHIM)
    target_compile_definitions(SecOCLib PUBLIC SECOC_ENABLE_TEST_SHIM=1)
    target_compile_definitions(SecOCLibShared PUBLIC SECOC_ENABLE_TEST_SHIM=1)
endif()

# ---- microbench (only when SECOC_PERF=ON) ----
if(SECOC_PERF)
    add_executable(microbench test/microbench.c)
    target_compile_definitions(microbench PUBLIC SECOC_PERF_INSTRUMENT=1)
    if(UNIX)
        target_compile_definitions(microbench PUBLIC LINUX)
    endif()
    target_include_directories(microbench PUBLIC ${headerDirs} ${LIBOQS_INCLUDE_DIR})
    target_link_libraries(microbench SecOCLib ${LIBOQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL)
    if(UNIX)
        target_link_libraries(microbench rt)
    endif()
endif()

# ---- attack_bench (Item #6 + #7 — standalone attack-detection harness) ----
# Drives ML-DSA sign/verify + in-test freshness counter against 4 attack
# vectors and a benign baseline. Always built on UNIX; CSV consumed by
# scripts/attack_rollup.py.
if(UNIX)
    add_executable(attack_bench test/attack_bench.c)
    target_include_directories(attack_bench PRIVATE ${headerDirs} ${LIBOQS_INCLUDE_DIR})
    target_link_libraries(attack_bench SecOCLib ${LIBOQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL rt)
    target_compile_definitions(attack_bench PRIVATE LINUX)
endif()

# ---- tx_perf_10k (Item #1 — N>=10,000 PQC sign+verify benchmark) ----
# Drives PQC_MLDSA_Sign / PQC_MLDSA_Verify directly with its own CLOCK_MONOTONIC
# probes (independent of SecOC_Perf ring). CSV consumed by
# scripts/perf_summary_extended.py.
if(UNIX)
    add_executable(tx_perf_10k test/tx_perf_10k.c)
    target_include_directories(tx_perf_10k PRIVATE ${headerDirs} ${LIBOQS_INCLUDE_DIR})
    target_link_libraries(tx_perf_10k SecOCLib ${LIBOQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL rt)
    target_compile_definitions(tx_perf_10k PRIVATE LINUX)
endif()

# ---- phase_compare (Item #4 — 4-phase comparison; Phase A/B only) ----
# Compares direct PQC sign/verify (standalone) against Csm_SignatureGenerate /
# Csm_SignatureVerify (integrated). Phase C/D need a SECOC_PERF_LOOPBACK_MODE
# guard in source/SecOC/SecOC.c that is outside its scope -- this driver
# stops at Phase A + Phase B and still resolves the standalone-vs-Csm anomaly.
if(UNIX)
    add_executable(phase_compare test/phase_compare.c)
    target_include_directories(phase_compare PRIVATE ${headerDirs} ${LIBOQS_INCLUDE_DIR})
    target_link_libraries(phase_compare SecOCLib ${LIBOQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL rt)
    target_compile_definitions(phase_compare PRIVATE LINUX)
endif()

# ---- txrx_e2e_test: Tx path -> in-memory wire -> Rx path in one process ----
# TcpIp, the Csm signature calls and Com_RxIndication are intercepted at link
# time (see test/test_txrx_e2e.c), so the BSW sources are the production ones.
if(UNIX)
    add_executable(txrx_e2e_test test/test_txrx_e2e.c)
    target_include_directories(txrx_e2e_test PRIVATE ${headerDirs} ${LIBOQS_INCLUDE_DIR})
    target_link_libraries(txrx_e2e_test SecOCLib ${LIBOQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL rt)
    target_compile_definitions(txrx_e2e_test PRIVATE LINUX)
    foreach(_sym TcpIp_GetSocketId TcpIp_Bind TcpIp_TcpConnect TcpIp_TcpListen TcpIp_Close TcpIp_ChangeParameter
                 TcpIp_TcpTransmit TcpIp_MainFunction Csm_SignatureGenerate Csm_SignatureVerify
                 Csm_MacGenerate Csm_MacVerify Com_RxIndication SecOC_VerificationStatusCallout
                 PQC_MLDSA_Sign PQC_MLDSA_Verify PqcHs_IsEstablished)
        target_link_options(txrx_e2e_test PRIVATE "-Wl,--wrap=${_sym}")
    endforeach()
    add_test(NAME TxRx_E2E COMMAND txrx_e2e_test)
    # The handshake is the only source of the MAC keys: no code of the gateway reads a key file, so
    # its binary does not contain the name of the variable the dry runs used for one.
    add_test(NAME Gateway_MacKeyFileCode_Absent
             COMMAND sh -c "test -f '$<TARGET_FILE:SecOC>' && ! grep -q SECOC_APP_MAC_KEY_FILE '$<TARGET_FILE:SecOC>'")
    set_tests_properties(TxRx_E2E Gateway_MacKeyFileCode_Absent PROPERTIES LABELS "INPROCESS")
    # test targets of the handshake component, when that component is in the tree
    include(${CMAKE_SOURCE_DIR}/test/pqchs_tests.cmake OPTIONAL)
endif()

# ---- mac_profile_test: HMAC-SHA-256 through Csm_MacGenerate / Csm_MacVerify (RFC 4231, key handling) ----
if(UNIX)
    # Crypto_Mac.c is compiled into the test once more, with the storage accessor (SECOC_TEST_ACCESS);
    # the linker then takes the driver from here and not from SecOCLib.
    add_executable(mac_profile_test test/test_mac_profile.c source/Encrypt/Crypto_Mac.c)
    target_include_directories(mac_profile_test PRIVATE ${headerDirs} ${LIBOQS_INCLUDE_DIR})
    target_link_libraries(mac_profile_test SecOCLib ${LIBOQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL rt)
    target_compile_definitions(mac_profile_test PRIVATE LINUX SECOC_TEST_ACCESS)
    add_test(NAME Mac_Profile COMMAND mac_profile_test)
    set_tests_properties(Mac_Profile PROPERTIES LABELS "INPROCESS")
endif()

# ---- tcp_nodelay_test: SoAd's end of a real TCP connection over 127.0.0.1 reads back TCP_NODELAY ----
# Production TcpIp and SoAd on real sockets (ports 50131, 50132); TcpIp_ChangeParameter is wrapped so that
# the test sees what SoAd asks for, and calls the real function behind the wrapper.
if(UNIX)
    add_executable(tcp_nodelay_test test/test_tcp_nodelay.c)
    target_include_directories(tcp_nodelay_test PRIVATE ${headerDirs} ${LIBOQS_INCLUDE_DIR})
    target_link_libraries(tcp_nodelay_test SecOCLib ${LIBOQS_LIBRARY} OpenSSL::Crypto OpenSSL::SSL rt)
    target_compile_definitions(tcp_nodelay_test PRIVATE LINUX)
    target_link_options(tcp_nodelay_test PRIVATE "-Wl,--wrap=TcpIp_ChangeParameter")
    add_test(NAME Tcp_NoDelay COMMAND tcp_nodelay_test)
    set_tests_properties(Tcp_NoDelay PROPERTIES LABELS "INPROCESS")
endif()

# Add our test folder cmakelists (requires googletest, gated by BUILD_TESTS)
if(BUILD_TESTS)
    add_subdirectory(test)
endif()







