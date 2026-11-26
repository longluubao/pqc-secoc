# Single-node measurement harnesses: crypto_ops.csv and overhead_paired.csv of DATA_SCHEMA.md.
#
# A project of its own on purpose: the tree's top-level CMakeLists.txt forces a Debug build, and
# a measurement binary must not link unoptimised BSW objects. The BSW files on the Csm signature
# path are compiled here, with the same optimisation as the harnesses.
#
#   bench/stamp_commit.sh        in the git checkout, before the tree is copied to a Pi
#   cmake -S Autosar_SecOC/bench -B build-bench -G Ninja -DCMAKE_BUILD_TYPE=Release \
#         -DLIBOQS_ROOT=$HOME/opt/liboqs-0.15.0
#   ninja -C build-bench && ctest --test-dir build-bench --output-on-failure
cmake_minimum_required(VERSION 3.20)
project(SecOCBench C)

if(NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    message(FATAL_ERROR "bench: configure with -DCMAKE_BUILD_TYPE=Release (got '${CMAKE_BUILD_TYPE}')")
endif()
# CMake's own Release default is -O3 -DNDEBUG; the campaign measures the stack at -O2.
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Same meaning as in the top-level build: the install is in ${LIBOQS_ROOT}/build (scripts/build_liboqs.sh).
set(LIBOQS_ROOT "$ENV{HOME}/opt/liboqs-0.15.0" CACHE PATH "liboqs root containing build/include and build/lib/liboqs.a")
set(LIBOQS_INCLUDE_DIR "${LIBOQS_ROOT}/build/include")
set(LIBOQS_LIBRARY "${LIBOQS_ROOT}/build/lib/liboqs.a")
if(NOT EXISTS "${LIBOQS_LIBRARY}")
    message(FATAL_ERROR "bench: ${LIBOQS_LIBRARY} not found; build it with scripts/build_liboqs.sh")
endif()

# Every CSV carries the commit of the code that produced it. The Pis build from a copy without
# .git, so the stamp travels as a file and a build without one is refused.
set(_stamp "${CMAKE_CURRENT_SOURCE_DIR}/COMMIT")
if(NOT EXISTS "${_stamp}")
    message(FATAL_ERROR "bench: ${_stamp} is missing; run bench/stamp_commit.sh in the git checkout")
endif()
file(STRINGS "${_stamp}" BENCH_GIT_COMMIT LIMIT_COUNT 1)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_stamp}")

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

get_filename_component(SECOC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(BENCH_DEFS LINUX MCAL_TARGET=MCAL_TARGET_PI4)   # what the top-level build defines on the Pi
add_compile_definitions(${BENCH_DEFS})
string(REPLACE ";" " -D" _defs "-D${BENCH_DEFS}")
string(REGEX REPLACE " +" " " BENCH_C_FLAGS
       "${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}: ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_RELEASE} ${_defs}")
message(STATUS "bench: commit=${BENCH_GIT_COMMIT} flags='${BENCH_C_FLAGS}' liboqs=${LIBOQS_ROOT}")

# Everything Csm_SignatureGenerate / Csm_SignatureVerify reach: Csm -> CryIf -> PQC (-> liboqs).
# The four module directories as they are in this tree (their file lists changed with the handshake).
file(GLOB _crypto_layer "${SECOC_DIR}/source/Csm/*.c" "${SECOC_DIR}/source/CryIf/*.c"
                        "${SECOC_DIR}/source/PQC/*.c" "${SECOC_DIR}/source/Encrypt/*.c")
add_library(bench_bsw STATIC ${_crypto_layer})
# The BSW sources include headers both as "Csm/Csm.h" and as "PQC.h": every header directory, as the top-level build does.
file(GLOB_RECURSE _headers "${SECOC_DIR}/include/*.h")
set(_include_dirs "${SECOC_DIR}/include")
foreach(_h ${_headers})
    cmake_path(GET _h PARENT_PATH _d)
    list(APPEND _include_dirs "${_d}")
endforeach()
list(REMOVE_DUPLICATES _include_dirs)
target_include_directories(bench_bsw PUBLIC ${_include_dirs} "${LIBOQS_INCLUDE_DIR}")
target_link_libraries(bench_bsw PUBLIC "${LIBOQS_LIBRARY}" OpenSSL::Crypto Threads::Threads)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL "14")
    # Same downgrade as the top-level build: gcc 14 turned these into errors and the BSW code trips them.
    target_compile_options(bench_bsw PRIVATE -Wno-error=implicit-function-declaration -Wno-error=incompatible-pointer-types)
endif()

add_executable(bench_crypto_ops bench_crypto_ops.c)
target_include_directories(bench_crypto_ops PRIVATE "${LIBOQS_INCLUDE_DIR}")
target_link_libraries(bench_crypto_ops PRIVATE "${LIBOQS_LIBRARY}" OpenSSL::Crypto Threads::Threads)

# attribution of the signing tail (wall time against thread CPU time): its own target, the same libraries
add_executable(bench_sign_attrib bench_sign_attrib.c)
target_include_directories(bench_sign_attrib PRIVATE "${LIBOQS_INCLUDE_DIR}")
target_link_libraries(bench_sign_attrib PRIVATE "${LIBOQS_LIBRARY}" OpenSSL::Crypto Threads::Threads)

add_executable(bench_overhead_paired bench_overhead_paired.c)
target_link_libraries(bench_overhead_paired PRIVATE bench_bsw)

# ---- networked harnesses: the whole BSW, once per gateway role, at the same -O2 ----
# The role is a compile-time switch of the BSW (SoAd listens or connects), so there is one BSW
# library per role; a target only builds the one it links. Sources as in the top-level build
# (Linux, Pi 4 MCAL) without main.c: the harness is the program.
file(GLOB_RECURSE _bsw_sources "${SECOC_DIR}/source/*.c")
list(REMOVE_ITEM _bsw_sources
    "${SECOC_DIR}/source/main.c"
    "${SECOC_DIR}/source/Ethernet/ethernet_windows.c"
    "${SECOC_DIR}/source/Scheduler/scheduler.c"
    "${SECOC_DIR}/source/Can/Can.c")
# Hooks: calls the BSW already makes, intercepted at link time; no BSW source is edited.
# bsw_stamps.c takes the five instants of the data path and can be linked into any binary that
# contains the BSW, with these six options (the gateway at integration); the rest is the harness's own.
# struct tcp_info of this board's kernel header: the time-out counter exists from Linux 6.7 (bench_tcpinfo.c)
include(CheckStructHasMember)
check_struct_has_member("struct tcp_info" tcpi_total_rto "linux/tcp.h" BENCH_HAVE_TCPI_TOTAL_RTO LANGUAGE C)
message(STATUS "bench: struct tcp_info has tcpi_total_rto: ${BENCH_HAVE_TCPI_TOTAL_RTO}")
set(_wraps_stamps PduR_SoAdTpRxIndication SecOC_VerificationStatusCallout Com_RxIndication
                  Csm_SignatureGenerate Csm_MacGenerate PduR_SoAdTpTxConfirmation)
set(_wraps_common connect accept recv Com_TxConfirmation Com_TpTxConfirmation ${_wraps_stamps})
set(_wraps_tx "")
set(_wraps_rx PduR_SoAdStartOfReception PduR_SoAdTpCopyRxData)
foreach(_role tx rx)
    add_library(bench_bsw_${_role} STATIC EXCLUDE_FROM_ALL ${_bsw_sources})
    if(_role STREQUAL "tx")
        target_compile_definitions(bench_bsw_${_role} PUBLIC SECOC_ROLE_SENDER=TRUE SECOC_ROLE_RECEIVER=FALSE)
    else()
        target_compile_definitions(bench_bsw_${_role} PUBLIC SECOC_ROLE_SENDER=FALSE SECOC_ROLE_RECEIVER=TRUE)
    endif()
    # SECOC_QUIET: the build option of the gateway that drops its per-cycle debug prints.
    target_compile_definitions(bench_bsw_${_role} PUBLIC SECOC_QUIET)
    target_include_directories(bench_bsw_${_role} PUBLIC ${_include_dirs} "${LIBOQS_INCLUDE_DIR}")
    target_link_libraries(bench_bsw_${_role} PUBLIC "${LIBOQS_LIBRARY}" OpenSSL::Crypto OpenSSL::SSL Threads::Threads)
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL "14")
        target_compile_options(bench_bsw_${_role} PRIVATE -Wno-error=implicit-function-declaration -Wno-error=incompatible-pointer-types)
    endif()

    add_executable(bench_net_${_role} EXCLUDE_FROM_ALL bench_net_${_role}.c bench_net.c bsw_stamps.c bench_tcpinfo.c)
    if(BENCH_HAVE_TCPI_TOTAL_RTO)
        target_compile_definitions(bench_net_${_role} PRIVATE BENCH_HAVE_TCPI_TOTAL_RTO)
    endif()
    target_link_libraries(bench_net_${_role} PRIVATE bench_bsw_${_role})
    foreach(_sym ${_wraps_common} ${_wraps_${_role}})
        target_link_options(bench_net_${_role} PRIVATE "-Wl,--wrap=${_sym}")
    endforeach()
endforeach()

# n handshakes as the initiator: the transmitter's BSW and wraps, no PDU stream
add_executable(bench_handshake EXCLUDE_FROM_ALL bench_handshake.c bench_net.c bsw_stamps.c bench_tcpinfo.c)
if(BENCH_HAVE_TCPI_TOTAL_RTO)
    target_compile_definitions(bench_handshake PRIVATE BENCH_HAVE_TCPI_TOTAL_RTO)
endif()
target_link_libraries(bench_handshake PRIVATE bench_bsw_tx)
foreach(_sym ${_wraps_common})
    target_link_options(bench_handshake PRIVATE "-Wl,--wrap=${_sym}")
endforeach()

add_executable(bench_keygen EXCLUDE_FROM_ALL bench_keygen.c)
target_include_directories(bench_keygen PRIVATE "${LIBOQS_INCLUDE_DIR}")
target_link_libraries(bench_keygen PRIVATE "${LIBOQS_LIBRARY}" OpenSSL::Crypto Threads::Threads)

# what the attack proxy needs for the on-wire handshake tests: a foreign ek or ct, a signature by a foreign key
add_executable(bench_hs_forge EXCLUDE_FROM_ALL bench_hs_forge.c)
target_include_directories(bench_hs_forge PRIVATE ${_include_dirs} "${LIBOQS_INCLUDE_DIR}")
target_link_libraries(bench_hs_forge PRIVATE "${LIBOQS_LIBRARY}" OpenSSL::Crypto Threads::Threads)

# E9: the clock probe between the two boards (no stack, no library), and one verification repeated
# for `perf stat` (the instructions of a verification by the difference of two run lengths)
add_executable(bench_clock_probe bench_clock_probe.c)
target_link_libraries(bench_clock_probe PRIVATE Threads::Threads)     # its second thread samples the board's two clocks
add_executable(bench_verify_only bench_verify_only.c)
target_include_directories(bench_verify_only PRIVATE "${LIBOQS_INCLUDE_DIR}")
target_link_libraries(bench_verify_only PRIVATE "${LIBOQS_LIBRARY}" OpenSSL::Crypto Threads::Threads)

foreach(_t bench_crypto_ops bench_sign_attrib bench_overhead_paired bench_net_tx bench_net_rx bench_handshake bench_keygen bench_hs_forge
           bench_clock_probe bench_verify_only)
    target_compile_options(${_t} PRIVATE -Wall -Wextra -Wconversion)
    target_compile_definitions(${_t} PRIVATE BENCH_GIT_COMMIT="${BENCH_GIT_COMMIT}" BENCH_C_FLAGS="${BENCH_C_FLAGS}")
endforeach()

# Each harness is run briefly and its CSV checked against DATA_SCHEMA.md.
enable_testing()
set(_check "python3 ${CMAKE_CURRENT_SOURCE_DIR}/check_csv.py")
add_test(NAME check_csv_selftest COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/check_csv.py --selftest)
add_test(NAME attack_proxy_selftest COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/attack_proxy.py --selftest)
add_test(NAME join_attack_selftest COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/join_attack.py --selftest)
add_test(NAME hs_side_probes_selftest COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/hs_side_probes.py --selftest)
add_test(NAME check_hsneg_selftest COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/check_hsneg.py --selftest)
# the forge helper: key and ciphertext sizes, and a signature of ML-DSA-65 length over 49 bytes
add_test(NAME hs_forge COMMAND sh -c
         "./bench_hs_forge ek forge_ek.bin && ./bench_hs_forge ct forge_ct.bin && [ $(wc -c < forge_ek.bin) = 1184 ] && [ $(wc -c < forge_ct.bin) = 1088 ] && [ $(./bench_hs_forge sign $(printf '52%096d' 0) | tr -d '\\n' | wc -c) = 6618 ]")
# the proxy's serving loop between two fake endpoints on 127.0.0.1: edits, injections, recording, old-session replay
add_test(NAME attack_proxy_sockets COMMAND sh -c
         "mkdir -p proxy_sockets && python3 ${CMAKE_CURRENT_SOURCE_DIR}/test_attack_proxy_local.py ${CMAKE_CURRENT_SOURCE_DIR}/attack_proxy.py proxy_sockets")
add_test(NAME net_loopback_schema COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test_net_loopback.sh
         ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
set_tests_properties(net_loopback_schema PROPERTIES SKIP_RETURN_CODE 77)
# E9: the checker's own cases. Then client and server of the probe on this one host (true offset zero) for 12 s,
# after which the client completes its window: three files of probe format 2 (footers that agree with the rows, both
# clock maps covering the exchanges, widths that are plausible), and every exchange must give |theta| <= delta/2.
# Then the same with memory for 200 map samples, one second's worth: the samples that found it full must be counted.
add_test(NAME check_clock_probe_selftest COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/check_clock_probe.py --selftest)
set(_probe_check "python3 ${CMAKE_CURRENT_SOURCE_DIR}/check_clock_probe.py")
add_test(NAME clock_probe_same_host COMMAND sh -c
    "rm -f clock_probe_test.csv clock_map_test_a.csv clock_map_test_b.csv; $<TARGET_FILE:bench_clock_probe> --server --bind 127.0.0.1 --port 50191 --map-out clock_map_test_b.csv > clock_probe_server.log 2>&1 & s=$!; sleep 0.5; timeout -s TERM 12 $<TARGET_FILE:bench_clock_probe> --client --peer 127.0.0.1 --port 50191 --interval-ms 101 --out clock_probe_test.csv --map-out clock_map_test_a.csv; kill $s; wait $s; ${_probe_check} --files clock_probe_test.csv clock_map_test_a.csv clock_map_test_b.csv && ${_probe_check} --zero clock_probe_test.csv && test ! -e clock_probe_test.csv.tmp && test ! -e clock_map_test_a.csv.tmp && test ! -e clock_map_test_b.csv.tmp")
add_test(NAME clock_probe_memory_full COMMAND sh -c
    "rm -f clock_full.csv clock_full_a.csv clock_full_b.csv; $<TARGET_FILE:bench_clock_probe> --server --bind 127.0.0.1 --port 50192 --map-out clock_full_b.csv --map-samples 200 > clock_full_server.log 2>&1 & s=$!; sleep 0.5; timeout -s TERM 3 $<TARGET_FILE:bench_clock_probe> --client --peer 127.0.0.1 --port 50192 --out clock_full.csv --map-out clock_full_a.csv --map-samples 200; kill $s; wait $s; grep -qx '# samples=200' clock_full_a.csv && grep -qx '# samples=200' clock_full_b.csv && grep -q '^# samples_dropped=[1-9]' clock_full_a.csv && grep -q '^# samples_dropped=[1-9]' clock_full_b.csv && ! ${_probe_check} --files clock_full.csv clock_full_a.csv clock_full_b.csv")
add_test(NAME verify_only COMMAND bench_verify_only --n 20 --msg-bytes 14 --ctx-bytes 64)
# the unrelated flow of cell i: source and sink on 127.0.0.1 for 2 s, then the report on their files
add_test(NAME bg_traffic_selftest COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/bg_traffic.py --selftest)
add_test(NAME crypto_ops_schema COMMAND sh -c
    "$<TARGET_FILE:bench_crypto_ops> --n 25 --msg-bytes 64 --allow-unlocked --out crypto_ops_test.csv && ${_check} crypto_ops_test.csv")
add_test(NAME sign_attrib_schema COMMAND sh -c
    "$<TARGET_FILE:bench_sign_attrib> --n 25 --msg-bytes 14 --allow-unlocked --out sign_attrib_test.csv && ${_check} sign_attrib_test.csv")
add_test(NAME sign_attrib_shake_schema COMMAND sh -c
    "$<TARGET_FILE:bench_sign_attrib> --n 25 --msg-bytes 14 --count-shake --allow-unlocked --out sign_attrib_shake_test.csv && ${_check} sign_attrib_shake_test.csv")
add_test(NAME overhead_paired_schema COMMAND sh -c
    "$<TARGET_FILE:bench_overhead_paired> --n 25 --seed 1 --msg-bytes 64 --allow-unlocked --out overhead_paired_test.csv && ${_check} overhead_paired_test.csv")
add_test(NAME overhead_paired_aa_schema COMMAND sh -c
    "$<TARGET_FILE:bench_overhead_paired> --n 25 --seed 1 --msg-bytes 64 --mode aa --allow-unlocked --out overhead_paired_aa_test.csv && ${_check} overhead_paired_aa_test.csv")
