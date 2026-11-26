#!/usr/bin/env bash
# scripts/build_liboqs.sh
#
# Build the one liboqs configuration this revision measures (ML-KEM-768 and
# ML-DSA-65 only, static, CPU-specific) and install it, or build the same
# configuration with liboqs's own tests and run its known-answer, ACVP-vector
# and Wycheproof tests for the two algorithms.
#
# Usage:
#   scripts/build_liboqs.sh <source_dir> <LIBOQS_ROOT>        build in <LIBOQS_ROOT>/_cmake, install into <LIBOQS_ROOT>/build
#   scripts/build_liboqs.sh <source_dir> <LIBOQS_ROOT> kat    test build in <source_dir>/build-kat, run the tests
# Environment (kat mode):
#   PYTEST   pytest command, default "python3 -m pytest" (liboqs's tests are pytest files)
#
# <LIBOQS_ROOT>/build/include and <LIBOQS_ROOT>/build/lib/liboqs.a are what the
# tree's CMake (-DLIBOQS_ROOT) and scripts/capture_env.sh read. The build record
# (BUILD_INFO.txt, CMakeCache.txt, configure log) is kept next to the install.
#
# The source tree is fetched beforehand, pinned to the release tag:
#   git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs <source_dir>
#
# An existing <LIBOQS_ROOT>/build/lib/liboqs.a is never overwritten: every run
# of the campaign must link the same build.

set -euo pipefail

if [[ $# -lt 2 ]]; then
    sed -n '2,23p' "${BASH_SOURCE[0]}" >&2
    exit 2
fi

SRC="$(cd "$1" && pwd)"
ROOT="$2"
PREFIX="${ROOT}/build"
MODE="${3:-install}"

# One flag list for both modes; only OQS_BUILD_ONLY_LIB differs.
FLAGS=(
    -DCMAKE_BUILD_TYPE=Release
    -DBUILD_SHARED_LIBS=OFF
    -DOQS_DIST_BUILD=OFF
    -DOQS_OPT_TARGET=auto
    -DOQS_USE_OPENSSL=ON
    "-DOQS_MINIMAL_BUILD=KEM_ml_kem_768;SIG_ml_dsa_65"
)

build_info() {
    echo "liboqs_source=${SRC}"
    echo "liboqs_git_describe=$(git -C "${SRC}" describe --tags --always 2>/dev/null || echo unknown)"
    echo "liboqs_git_commit=$(git -C "${SRC}" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "liboqs_cmake_flags=${FLAGS[*]} $1"
    echo "liboqs_build_host=$(hostname)"
    echo "liboqs_build_cc=$(cc --version | head -1)"
    echo "liboqs_build_cmake=$(cmake --version | head -1)"
    echo "liboqs_build_date=$(date -Is)"
}

if [[ "${MODE}" == "install" ]]; then
    if [[ -f "${PREFIX}/lib/liboqs.a" ]]; then
        echo "[liboqs] ${PREFIX}/lib/liboqs.a exists, not rebuilding" >&2
        exit 0
    fi
    BUILD="${ROOT}/_cmake"
    mkdir -p "${ROOT}"
    cmake -S "${SRC}" -B "${BUILD}" -G Ninja "${FLAGS[@]}" -DOQS_BUILD_ONLY_LIB=ON \
        -DCMAKE_INSTALL_PREFIX="${PREFIX}" 2>&1 | tee "${ROOT}/_cmake_configure.log"
    nice -n 10 ninja -C "${BUILD}"
    ninja -C "${BUILD}" install > /dev/null
    build_info "-DOQS_BUILD_ONLY_LIB=ON" > "${PREFIX}/BUILD_INFO.txt"
    echo "liboqs_a_sha256=$(sha256sum "${PREFIX}/lib/liboqs.a" | cut -d' ' -f1)" >> "${PREFIX}/BUILD_INFO.txt"
    mv "${ROOT}/_cmake_configure.log" "${PREFIX}/cmake_configure.log"
    cp "${BUILD}/CMakeCache.txt" "${PREFIX}/CMakeCache.txt"
    cat "${PREFIX}/BUILD_INFO.txt"
elif [[ "${MODE}" == "kat" ]]; then
    BUILD="${SRC}/build-kat"
    SELECT="ML-KEM-768 or ML-DSA-65"
    read -r -a PYTEST_CMD <<< "${PYTEST:-python3 -m pytest}"
    cmake -S "${SRC}" -B "${BUILD}" -G Ninja "${FLAGS[@]}" -DOQS_BUILD_ONLY_LIB=OFF 2>&1 | tee "${BUILD}.cmake.log"
    nice -n 10 ninja -C "${BUILD}"
    echo "===== build info ====="
    build_info "-DOQS_BUILD_ONLY_LIB=OFF"
    # The tested configuration is the installed one only if the generated configuration headers agree.
    echo "===== diff installed oqsconfig.h vs test build (expected: only OQS_BUILD_ONLY_LIB) ====="
    diff "${PREFIX}/include/oqs/oqsconfig.h" "${BUILD}/include/oqs/oqsconfig.h" && echo "identical"
    echo "===== liboqs.a: installed vs test build (same hash = the tested library is the measured one) ====="
    sha256sum "${PREFIX}/lib/liboqs.a" "${BUILD}/lib/liboqs.a"
    rc=0
    for t in test_kat.py test_acvp_vectors.py test_wycheproof_vectors.py; do
        if [[ ! -f "${SRC}/tests/${t}" ]]; then
            echo "===== tests/${t}: not shipped in this tree ====="
            continue
        fi
        echo "===== tests/${t} ====="
        echo "+ cd ${SRC} && OQS_BUILD_DIR=${BUILD} ${PYTEST_CMD[*]} -v -p no:cacheprovider tests/${t} -k \"${SELECT}\""
        (cd "${SRC}" && OQS_BUILD_DIR="${BUILD}" "${PYTEST_CMD[@]}" -v -p no:cacheprovider "tests/${t}" -k "${SELECT}") || rc=1
    done
    exit "${rc}"
else
    echo "unknown mode '${MODE}' (expected nothing or 'kat')" >&2
    exit 2
fi
