#!/usr/bin/env bash
# scripts/build_gateway.sh
#
# Configure and build one gateway binary (and optional extra targets) out of
# tree. The same sources build as transmitter or receiver; nothing is edited.
#
# Usage:
#   scripts/build_gateway.sh <tx|rx> <local_ip> <peer_ip> <key_dir> <build_dir> [ninja targets...]
# Environment:
#   LIBOQS_ROOT       prebuilt liboqs tree (with build/include and build/lib); required
#   SECOC_BUILD_TYPE  Release (default, -O2: everything that is measured) or Debug
#   SECOC_PORT        TCP port of the gateway PDUs (default 50002)
#   SECOC_GIT_COMMIT  commit stamp printed at start-up (the Pis have no .git); default "unknown"
#   SECOC_QUIET       ON (default) builds without the per-cycle debug prints
#
# Example (iris, transmitter over the direct Ethernet cable):
#   LIBOQS_ROOT=~/opt/liboqs-0.15.0 SECOC_GIT_COMMIT=abc123 \
#     scripts/build_gateway.sh tx 10.10.10.1 10.10.10.2 ~/pqc-secoc-rev1/keys ~/pqc-secoc-rev1/build-tx

set -euo pipefail

if [[ $# -lt 5 ]]; then
    sed -n '2,19p' "${BASH_SOURCE[0]}" >&2
    exit 2
fi

ROLE="$(echo "$1" | tr '[:lower:]' '[:upper:]')"
LOCAL_IP="$2"
PEER_IP="$3"
KEY_DIR="${4%/}/"
BUILD_DIR="$5"
shift 5

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${LIBOQS_ROOT:?set LIBOQS_ROOT to the prebuilt liboqs tree}"

mkdir -p "${KEY_DIR}"
chmod 700 "${KEY_DIR}"

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -G Ninja \
    -DCMAKE_BUILD_TYPE="${SECOC_BUILD_TYPE:-Release}" \
    -DSECOC_PORT="${SECOC_PORT:-50002}" \
    -DSECOC_ROLE="${ROLE}" \
    -DSECOC_LOCAL_IP="${LOCAL_IP}" \
    -DSECOC_PEER_IP="${PEER_IP}" \
    -DPQC_MLDSA_KEY_DIR="${KEY_DIR}" \
    -DLIBOQS_ROOT="${LIBOQS_ROOT}" \
    -DSECOC_GIT_COMMIT="${SECOC_GIT_COMMIT:-unknown}" \
    -DSECOC_QUIET="${SECOC_QUIET:-ON}" \
    -DBUILD_TESTS=OFF > "${BUILD_DIR}.cmake.log" 2>&1 || { tail -20 "${BUILD_DIR}.cmake.log" >&2; exit 1; }

# two jobs: the boards are shared and baolong overheats with more
ninja -j "${SECOC_BUILD_JOBS:-2}" -C "${BUILD_DIR}" SecOC "$@"
# what was really used: the liboqs archive on the link line and the compile command of main.c
echo "linked: $(ninja -C "${BUILD_DIR}" -t commands SecOC | tail -1 | grep -o '[^ ]*liboqs\.a' | sort -u | tr '\n' ' ')"
