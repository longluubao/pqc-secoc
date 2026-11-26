#!/usr/bin/env bash
# scripts/capture_env.sh — append the environment of this host to a file
# (env_<host>.txt of DATA_SCHEMA.md). Run once before and once after a run.
#
# Usage: scripts/capture_env.sh <before|after> <out_file> <liboqs_root> <commit> [peer_ip] [build_dir...]
#   peer_ip    "-" or empty when there is none
#   build_dir  gateway build directories used in the run: build type, compile command, binary hash
#
# Read-only. `sudo -n ethtool` is used for two read-only queries (--show-eee, -S); without sudo
# rights those fields read "unavailable".
# Fields a run is judged by (before against after): eth0_carrier_changes, eth0_addr,
# eth0_rbuf_ovflow_cnt, TcpRetransSegs, TcpExtTCPTimeouts, eth0_eee, throttled.

set -uo pipefail
LABEL="$1"; OUT="$2"; LIBOQS_ROOT="$3"; COMMIT="$4"; PEER_IP="${5:-}"
shift $(( $# < 5 ? $# : 5 ))
OQS_BUILD="${LIBOQS_ROOT}/build"
CFG="${OQS_BUILD}/include/oqs/oqsconfig.h"

if [[ ! -f "${OQS_BUILD}/lib/liboqs.a" || ! -f "${CFG}" ]]; then
    echo "capture_env.sh: no liboqs build at ${OQS_BUILD} (lib/liboqs.a, include/oqs/oqsconfig.h)" >&2
    exit 1
fi

cpus() { for f in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/"$1"; do printf '%s ' "$(cat "$f")"; done; }

{
    echo "===== ${LABEL} $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
    echo "hostname=$(hostname)"
    echo "board=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null)"
    echo "board_revision=$(awk '/^Revision/ {print $3}' /proc/cpuinfo)"
    echo "mem_total_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
    echo "kernel=$(uname -r)"
    echo "kernel_build=$(uname -v)"
    echo "kernel_preempt=$( (zcat /proc/config.gz 2>/dev/null || cat "/boot/config-$(uname -r)" 2>/dev/null) | grep -E '^CONFIG_PREEMPT(_NONE|_VOLUNTARY|_RT|_DYNAMIC)?=y' | tr '\n' ' ')"
    # what the thread CPU clock counts and how often the tick fires (bench_sign_attrib reads wall - cpu)
    echo "kernel_irq_time_accounting=$( (zcat /proc/config.gz 2>/dev/null || cat "/boot/config-$(uname -r)" 2>/dev/null) | grep -E '^(# )?CONFIG_IRQ_TIME_ACCOUNTING[= ]' | sed 's/^# //' | grep . || echo unknown)"
    echo "kernel_tick=$( (zcat /proc/config.gz 2>/dev/null || cat "/boot/config-$(uname -r)" 2>/dev/null) | grep -E '^CONFIG_(HZ|HZ_[0-9]+|NO_HZ[A-Z_]*|HZ_PERIODIC|TICK_CPU_ACCOUNTING|VIRT_CPU_ACCOUNTING[A-Z_]*)=' | tr '\n' ' ')"
    echo "kernel_cmdline=$(cat /proc/cmdline)"
    echo "os=$(. /etc/os-release && echo "${PRETTY_NAME}")"
    echo "glibc=$(getconf GNU_LIBC_VERSION)"
    echo "gcc=$(gcc -dumpfullversion)"
    echo "cmake=$(cmake --version | head -1)"
    echo "openssl=$(openssl version)"
    echo "git_commit=${COMMIT}"
    echo "git_dirty=$([[ "${COMMIT}" == *-dirty ]] && echo yes || echo no)"

    echo "liboqs_root=${LIBOQS_ROOT}"
    echo "liboqs_a_sha256=$(sha256sum "${OQS_BUILD}/lib/liboqs.a" | cut -d' ' -f1)"
    # how this liboqs was built: the builder's own record, then the cmake cache (algorithm switches
    # that are OFF are left out: this is a minimal build)
    sed 's/^/liboqs_build_info: /' "${OQS_BUILD}/BUILD_INFO.txt" 2>/dev/null || echo "liboqs_build_info: unavailable"
    grep -E '^(CMAKE_BUILD_TYPE|CMAKE_C_COMPILER|CMAKE_C_FLAGS[A-Z_]*|BUILD_SHARED_LIBS|OQS_[A-Za-z0-9_]+):' "${OQS_BUILD}/CMakeCache.txt" 2>/dev/null \
        | grep -v -e '-ADVANCED:' -e '^OQS_ENABLE_.*=OFF$' -e '-STRINGS:' | sed 's/^/liboqs_cmake_/; s/:[A-Z]*=/=/'
    grep -E '^#define (OQS_VERSION_TEXT|OQS_COMPILE_BUILD_TARGET|OQS_OPT_TARGET|OQS_DIST_BUILD|OQS_USE_[A-Z0-9_]*OPENSSL|OQS_USE_ARM_[A-Z0-9_]*|OQS_ENABLE_KEM_ml_kem_768[a-z0-9_]*|OQS_ENABLE_SIG_ml_dsa_65[a-z0-9_]*) ' "${CFG}" \
        | sed 's/^#define /liboqs_/; s/ /=/'
    # no ML-DSA-65 switch with an architecture suffix means the portable C implementation is compiled
    echo "liboqs_mldsa65_impl=$(grep -qE '^#define OQS_ENABLE_SIG_ml_dsa_65_(aarch64|neon)' "${CFG}" && echo aarch64 || echo 'portable C (pqcrystals ref)')"
    echo "liboqs_mlkem768_impl=$(grep -q '^#define OQS_ENABLE_KEM_ml_kem_768_aarch64' "${CFG}" && echo 'aarch64 NEON' || echo 'portable C')"

    for b in "$@"; do
        echo "gateway_build=${b}"
        echo "gateway_build_type=$(sed -n 's/^CMAKE_BUILD_TYPE:[A-Z]*=//p' "${b}/CMakeCache.txt" 2>/dev/null)"
        echo "gateway_sha256=$(sha256sum "${b}/SecOC" 2>/dev/null | cut -d' ' -f1)"
        echo "gateway_banner=$("${b}/SecOC" --version 2>/dev/null | grep -F '[main] PQC-SecOC')"
        echo "gateway_compile_main_c=$(ninja -C "${b}" -t commands SecOC 2>/dev/null | grep -m1 -E '/source/main\.c( |$)')"
        echo "gateway_link_liboqs=$(ninja -C "${b}" -t commands SecOC 2>/dev/null | tail -1 | grep -o '[^ ]*liboqs\.a' | sort -u | tr '\n' ' ')"
    done

    echo "governor=$(cpus scaling_governor)"
    echo "scaling_cur_freq=$(cpus scaling_cur_freq)"
    echo "scaling_min_freq=$(cpus scaling_min_freq)"
    echo "scaling_max_freq=$(cpus scaling_max_freq)"
    echo "dev_freq_cap=$(cat "$HOME/array_rev/DEV_FREQ_CAP" 2>/dev/null || echo none)"
    echo "cpuinfo_max_freq=$(cpus cpuinfo_max_freq)"
    echo "temp=$(vcgencmd measure_temp 2>/dev/null || cat /sys/class/thermal/thermal_zone0/temp)"
    echo "throttled=$(vcgencmd get_throttled 2>/dev/null || echo unavailable)"

    echo "eth0_speed_mbit=$(cat /sys/class/net/eth0/speed 2>/dev/null)"
    echo "eth0_duplex=$(cat /sys/class/net/eth0/duplex 2>/dev/null)"
    echo "eth0_autoneg=$(/usr/sbin/ethtool eth0 2>/dev/null | sed -n 's/^[[:space:]]*Auto-negotiation: //p')"
    echo "eth0_advertised=$(/usr/sbin/ethtool eth0 2>/dev/null | sed -n '/Advertised link modes/,/Advertised pause/p' | grep -oE '[0-9]+base[A-Za-z]+/(Half|Full)' | tr '\n' ' ')"
    echo "eth0_eee=$(sudo -n /usr/sbin/ethtool --show-eee eth0 2>/dev/null | sed -n 's/^[[:space:]]*EEE status: //p' | grep . || echo unavailable)"
    echo "eth0_offload=$(/usr/sbin/ethtool -k eth0 2>/dev/null | grep -E '^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|rx-checksumming|tx-checksumming):' | tr -s ' ' | tr '\n' ';')"
    echo "eth0_addr=$(ip -4 -br addr show dev eth0 | awk '{print $3}')"
    echo "eth0_nm_state=$(nmcli -t -f DEVICE,STATE device status 2>/dev/null | sed -n 's/^eth0://p')"
    echo "eth0_carrier_changes=$(cat /sys/class/net/eth0/carrier_changes)"
    echo "eth0_rbuf_ovflow_cnt=$(sudo -n /usr/sbin/ethtool -S eth0 2>/dev/null | awk '/rbuf_ovflow_cnt/ {print $2}' | grep . || echo unavailable)"
    for c in rx_bytes rx_packets tx_bytes tx_packets rx_errors tx_errors rx_dropped tx_dropped; do
        echo "eth0_${c}=$(cat /sys/class/net/eth0/statistics/${c})"
    done
    # host-wide TCP counters (all interfaces)
    nstat -asz TcpRetransSegs TcpExtTCPTimeouts 2>/dev/null | awk 'NR > 1 {print $1 "=" $2}'
    echo "wlan0_tx_bytes=$(cat /sys/class/net/wlan0/statistics/tx_bytes 2>/dev/null)"
    echo "wlan0_rx_bytes=$(cat /sys/class/net/wlan0/statistics/rx_bytes 2>/dev/null)"
    if [[ -n "${PEER_IP}" && "${PEER_IP}" != "-" ]]; then
        echo "route_to_peer=$(ip route get "${PEER_IP}" | head -1)"
    fi

    echo "clock: $(timedatectl show -p Timezone -p NTP -p NTPSynchronized -p TimeUSec 2>/dev/null | tr '\n' ' ')"
    echo "clock_services=$(for s in systemd-timesyncd chrony ntp ptp4l phc2sys; do printf '%s:%s ' "$s" "$(systemctl is-active "$s" 2>/dev/null)"; done)"
    echo "clock_note=the two hosts are not synchronised to each other; CSV times are per-host CLOCK_MONOTONIC"
    echo "loadavg=$(cat /proc/loadavg)"
    echo "busiest=$(ps -eo pcpu,comm --sort=-pcpu | sed -n '2,6p' | tr -s ' ' | tr '\n' ';')"
    echo "mem_available_kb=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)"
    echo "disk_home_avail_mb=$(df --output=avail -m "${HOME}" | tail -1 | tr -d ' ')"
} >> "${OUT}"
