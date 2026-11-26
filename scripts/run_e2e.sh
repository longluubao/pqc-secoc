#!/usr/bin/env bash
# scripts/run_e2e.sh — driver on the measuring workstation: sync this tree to the Raspberry Pis, build the gateway
# binaries, provision ML-DSA keys, run transmitter -> receiver, collect the logs and check them.
#
#   PI_SSH_CFG=<ssh config> scripts/run_e2e.sh buildall [run_id]
#       build the transmitter AND the receiver binary on both Pis from this commit; record the
#       start-up banner (commit hash, role) of all four binaries
#   PI_SSH_CFG=<ssh config> [LINK_SPEED=100] scripts/run_e2e.sh link [run_id]
#       eth0 of both Pis: EEE off, speed, 10.10.10.1 (iris) / 10.10.10.2 (baolong), NetworkManager
#       told to ignore eth0 (Autosar_SecOC/scripts/link_eth0.sh, non-persistent); ping; link speed
#   PI_SSH_CFG=<ssh config> scripts/run_e2e.sh linkdown [run_id]
#       undo the link step (EEE stays off; link_eth0.sh says how to switch it on again)
#   PI_SSH_CFG=<ssh config> scripts/run_e2e.sh loopback <iris|baolong> <count> <run_id>
#       transmitter and receiver processes on one host over 127.0.0.1
#   PI_SSH_CFG=<ssh config> scripts/run_e2e.sh twonode <count> <run_id>
#       transmitter on iris (10.10.10.1) -> receiver on baolong (10.10.10.2) over eth0
#
# PI_SSH_CFG is an ssh config file that defines the hosts pi-iris and pi-baolong with working,
# non-interactive authentication. No credentials are read or stored by this script.
# Optional environment:
#   PERIOD_CYCLES     BSW cycles of about 1 ms between PDUs of one stream (default 10)
#   STREAMS           streams the transmitter sends on, 1..8 (default 1; one with PROFILE=mac, two with
#                     PROFILE=both); <count> is per stream
#   PROFILE           variant of the run: mldsa65 (default, the signature streams), mac (HMAC-SHA-256
#                     PDU, SecOC PDU 13) or both (STREAMS=2: stream 0 the signature PDU, stream 1 the
#                     MAC PDU; no forged PDUs in this variant). The MAC keys are the ones the handshake
#                     installs; the gateway reads no key file.
#   MAC_KEY_FILE_PROBE  loopback, PROFILE=mac, 1: a file with a known key lies where the key file of
#                     the dry runs used to be and SECOC_APP_MAC_KEY_FILE points to it for both
#                     gateways; the FORGED PDUs carry right tags under that key. The run fails if a
#                     gateway opens the file (each binary runs 5 s under strace first) or accepts one
#                     of those PDUs.
#   CORE              CPU core the gateway processes are pinned to (default 3)
#   CLOCK_PROBE       1 (E9, cell g; two-node or loopback run without RESTART): the clock probe of the bench
#                     tree (bench_clock_probe; PROBE_BIN, default <PI_TREE>/build-bench/bench_clock_probe on
#                     the boards, where `scripts/run_bench_net.sh build` with PI_DIR='$HOME/<PI_TREE>' puts
#                     it) runs beside the gateways on core PROBE_CPU (default 1), UDP port 50105, from 12 s before the transmitter starts to 12 s after it
#                     has ended. clock_probe.csv and the two clock maps (clock_map_a.csv of the transmitter's
#                     board, clock_map_b.csv of the receiver's; probe format 2) lie beside app_tx.csv and
#                     app_rx.csv and check_clock_probe.py --run judges them into e9_check.txt (a FAIL, a
#                     missing file included: E9_INVALID and exit code 1). The directory gets a DRY_RUN marker unless DRY_RUN=0.
#   LINK_SPEED        1000 (default) or 100: eth0 speed set by the link step (autonegotiation stays on)
#   SECOC_BUILD_TYPE  Release (default, -O2) or Debug
#   PI_LIBOQS_ROOT    liboqs tree on the Pis (default $HOME/opt/liboqs-0.15.0)
#   PI_TREE           directory under $HOME on the Pis that this clone owns (default pqc-secoc-rev1).
#                     Its first sync records this clone's path in <PI_TREE>/.origin; a sync from any
#                     other clone into it is refused (rsync --delete would wipe the other's tree).
#   FORGED            number of forged PDUs sent to the receiver before the transmitter starts
#                     (default 0; Autosar_SecOC/scripts/inject_forged.py). No session exists yet, so
#                     the receiver must refuse every one of them (freshness_fail, the no-session
#                     gate) and deliver every genuine PDU after them.
#   FORGED_MIDRUN     number of forged PDUs sent on a second TCP connection 3 s after the
#                     transmitter started: the receiver must refuse that connection (one connection
#                     at a time), so no row is expected from it and every genuine PDU is delivered.
#   TAMPER_EVERY      an in-path relay (Autosar_SecOC/scripts/relay_tamper.py) puts a
#                     tampered copy in front of every n-th PDU; each must be rejected (auth_fail) and
#                     every genuine PDU still delivered.
#   RESTART           rx or tx: that gateway process ends after RESTART_AFTER (rx: outcomes, tx: PDUs
#                     per stream) and a new process takes its place 2 s later; the other gateway
#                     keeps running. Its files carry the suffix 2; the checker gets both parts.
#   REKEY_AT          the transmitter asks for a second handshake after this many PDUs of stream 0
#   DROP_HEADER       loopback only: the relay does not forward the DROP_NTH-th (default first) PDU with
#                     this PDU header ID, e.g. 0x32 (handshake message M3)
#   WRONG_PEER_KEY    loopback only, 1: the receiver gets a wrong peer public key; no session comes
#                     about (initiator: timeout, responder: unknown_id) and no PDU is released.
#
#   HOLDING_MEASURING 1: for the holder of the measuring marker (the campaign runs). The local
#                     marker MEASURING_<host> and ~/array_rev/MEASURING are no obstacle, no board lock is
#                     taken, the governor and the frequency cap are left as they are (the holder has set
#                     them), and while the transmitter runs there is one SSH session to its board that only
#                     waits, pinned to core 0, and none to the receiver's board.
#   BOARD_LOCK_OWNER  name under which the board locks are taken (default: this clone's directory
#                     name), BOARD_LOCK_WAIT seconds to wait (default 0)
#   BOARD_COOL_WAIT   seconds to wait for baolong to be below START_TEMP_MAX (default 78 C) before
#                     any lock is taken (default 300); checked again with the lock held (up to 120 s)
#                     and once more behind the builds, before the gateways start
#
# Boards are shared. Everything that uses core 3 or the eth0 link (link step, loopback, two-node run)
# holds ~/array_rev/boardlock.sh on the boards it uses (iris first, then baolong; released in reverse
# order, also on failure) for everything it does there: sync, build and run (one job at a time on
# a board, rule of 2026-11-23). Builds run on cores 0-2 at low priority with two jobs. No SSH session is opened to a Pi whose marker MEASURING_<host> exists in
# MARKER_DIR on this machine (default ~/Downloads/pqc-secoc-campaign): the board is under measurement.
# Nothing is built or run on a Pi that has a file ~/array_rev/MEASURING or less than
# 250 MB free, and nothing is run while somebody else's SecOC process is alive there.
# Results land in runs/<run_id>/ next to this script's parent: app_tx.csv, app_rx.csv (the gateway
# applications' own logs: closed-loop sender, functional evidence, not the periodic files of
# DATA_SCHEMA.md), rx_payload.csv, tx_<host>.log, rx_<host>.log, env_<host>.txt, cmd.txt, check.txt,
# MANIFEST.sha256.

set -euo pipefail

# macOS goes to sleep about a minute after the last activity and the SSH sessions die with it
if [[ "$(uname)" == Darwin && -z "${CAFFEINATED:-}" ]]; then
    export CAFFEINATED=1
    exec caffeinate -is "$0" "$@"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${PI_SSH_CFG:?set PI_SSH_CFG to an ssh config with hosts pi-iris and pi-baolong}"
PERIOD_CYCLES="${PERIOD_CYCLES:-10}"
STREAMS="${STREAMS:-1}"
PROFILE="${PROFILE:-mldsa65}"
CORE="${CORE:-3}"
LINK_SPEED="${LINK_SPEED:-1000}"
CLOCK_PROBE="${CLOCK_PROBE:-0}"
HOLDING_MEASURING="${HOLDING_MEASURING:-}"
PROBE_CPU="${PROBE_CPU:-1}"
PROBE_PORT=50105        # UDP
PROBE_INTERVAL_MS="${PROBE_INTERVAL_MS:-101}"   # the phase to the application's 10 ms moves through its ten values (to the 1 ms cycle it stays fixed)
FORGED="${FORGED:-0}"
TAMPER_EVERY="${TAMPER_EVERY:-0}"
DROP_HEADER="${DROP_HEADER:-0}"         # loopback only: the relay leaves out the DROP_NTH-th PDU with this header ID (0x32 = M3)
DROP_NTH="${DROP_NTH:-1}"
RELAY_ON=$(( TAMPER_EVERY > 0 || DROP_HEADER > 0 ))
RELAY_HOST=""; RELAY_LISTEN=""; RELAY_DST=""    # set by the loopback and two-node steps when the relay is used
FORGED_MIDRUN="${FORGED_MIDRUN:-0}"
WRONG_PEER_KEY="${WRONG_PEER_KEY:-0}"
RESTART="${RESTART:-}"                  # rx | tx: that gateway process is replaced during the run
RESTART_AFTER="${RESTART_AFTER:-0}"     # rx: outcomes of the first receiver; tx: PDUs per stream of the first transmitter
MAC_KEY_FILE_PROBE="${MAC_KEY_FILE_PROBE:-0}"
REKEY_AT="${REKEY_AT:-0}"               # the transmitter asks for a new handshake after this many PDUs of stream 0
RELAY_PORT=50003          # receiver port when the relay sits on RX_PORT
# The receiver ends by itself this long after its last outcome. It must outlast the steps between
# the forged PDUs and the transmitter's first PDU (three SSH commands: 15 s on a board busy with
# builds, where 10 s lost a run).
RX_IDLE_EXIT_MS=30000
RX_END_WAIT=$(( RX_IDLE_EXIT_MS / 1000 + 30 ))
BUILD_PORT=""             # SECOC_PORT of the next build (empty: default)
BUILD_TYPE="${SECOC_BUILD_TYPE:-Release}"
RX_PORT=50002
INJECT_PORT="${RX_PORT}"  # where forged PDUs go: the receiver itself
LOCK_OWNER="${BOARD_LOCK_OWNER:-$(basename "${ROOT}")}"
TX_HOST=iris;    TX_IP=10.10.10.1
RX_HOST=baolong; RX_IP=10.10.10.2
PI_TREE="${PI_TREE:-pqc-secoc-rev1}"
PI_DIR='$HOME/'"${PI_TREE}"
PROBE_BIN="${PROBE_BIN:-${PI_DIR}/build-bench/bench_clock_probe}"
PROBE_PAT="${PROBE_BIN#\$HOME/}"; PROBE_PAT="${PROBE_PAT%e}[e]"     # for pkill -f: this probe, never the shell that asks
PROBE_HOSTS=""          # boards on which a clock probe of this run is running
PROBE_WAIT="${PROBE_WAIT:-20}"  # s a probe process is waited for after its SIGTERM (a map of 1,000 s is about 10 MB to write)
if [[ "${CLOCK_PROBE}" == 1 && ( -n "${RESTART}" || "${PROBE_CPU}" == "${CORE}" ) ]]; then
    echo "CLOCK_PROBE=1 goes with a run without RESTART and needs a core of its own (PROBE_CPU=${PROBE_CPU}, gateways on ${CORE})" >&2
    exit 2
fi

COMMIT="$(git -C "${ROOT}" rev-parse --short=12 HEAD)"
if [[ -n "$(git -C "${ROOT}" status --porcelain -- Autosar_SecOC scripts)" ]]; then
    COMMIT="${COMMIT}-dirty"
fi

# the pinned liboqs 0.15.0 build, same path on both Pis (as found: 0.15.0-rc2 inside the old trees)
liboqs_root() {
    echo "${PI_LIBOQS_ROOT:-\$HOME/opt/liboqs-0.15.0}"
}

CMD_LOG=/dev/null
# run a command on a Pi and record it in cmd.txt
r() {
    local host="$1"; shift
    echo "[${host}] $*" >> "${CMD_LOG}"
    ssh -F "${PI_SSH_CFG}" "pi-${host}" "$*"
}

# Every run of this driver is a functional run (delivery and rejection counts; the logs are closed
# loop and carry no timing result), and says so with a file FUNCTIONAL in its directory. Such a run
# may start on baolong below 78 C (the campaign rule; a timing run needs 68 C and clean throttle
# flags, and is not made with this script). The start temperature is in env_<host>.txt.
START_TEMP_MAX="${START_TEMP_MAX:-78}"
# remote command: wait up to <seconds> for the board to be below the start temperature, fail otherwise
cool_check() {
    echo "for i in \$(seq 0 $1); do t=\$(vcgencmd measure_temp | tr -dc '0-9.'); test \"\${t%.*}\" -lt ${START_TEMP_MAX} && exit 0; sleep 1; done; echo \"this board is at \$t C: no run at ${START_TEMP_MAX} C or more\" >&2; exit 1"
}

# cool_gate <host>: with the lock held and the builds done, baolong must be below the start temperature
cool_gate() {
    [[ "$1" != baolong ]] || r "$1" "$(cool_check "${BOARD_COOL_WAIT:-300}")"
}

# board locks: lock_boards <purpose> <host>...; everything held is released at exit, last taken first
LOCKED=()
TMP=""
lock_boards() {
    local purpose="$1" h
    shift
    for h in "$@"; do
        local_marker_check "${h}"
    done
    # baolong throttles under the developers' builds: wait for it to be below the start temperature
    # before any lock is taken, so that iris is not held while baolong cools.
    for h in "$@"; do
        [[ "${h}" != baolong ]] || r "${h}" "$(cool_check "${BOARD_COOL_WAIT:-300}")"
    done
    for h in "$@"; do
        if [[ -z "${HOLDING_MEASURING}" ]]; then    # the holder of the measuring marker has the board without a lock
            r "${h}" "\$HOME/array_rev/boardlock.sh acquire '${LOCK_OWNER}' '${purpose}' ${BOARD_LOCK_WAIT:-0}"
            LOCKED=("${h}" ${LOCKED[@]+"${LOCKED[@]}"})
        fi
        # and once more with the lock held, in case somebody's run heated it in between
        [[ "${h}" != baolong ]] || r "${h}" "$(cool_check 120)"
        # with the lock held nobody else's gateway may be running here
        r "${h}" "for i in \$(seq 0 ${BOARD_LOCK_WAIT:-0}); do pgrep -x SecOC > /dev/null || exit 0; sleep 1; done; echo \"a SecOC process is running on this board although the lock was free: \$(pgrep -a -x SecOC | head -1)\" >&2; exit 1"
    done
}
# probe_end <pattern> <name>: the commands, for a board, that end the probe processes matching the pattern and wait
# for them (E9_SPEC.md, E12.4). A process still there PROBE_WAIT s after its SIGTERM is named in one line and killed, so
# that no probe is running when the board's run directory is removed or the locks are released; the file it did not
# write is then missing, which the check says. (The name carries no path: the pattern must not match the asking shell.)
probe_end() {
    echo "pkill -TERM -f '$1'; for i in \$(seq $(( PROBE_WAIT * 10 ))); do pgrep -f '$1' > /dev/null || break; sleep 0.1; done; if pgrep -f '$1' > /dev/null; then echo \"$2 on \$(hostname) has not ended within ${PROBE_WAIT} s of its SIGTERM: SIGKILL\"; pkill -KILL -f '$1'; for i in \$(seq 50); do pgrep -f '$1' > /dev/null || break; sleep 0.1; done; fi"
}
cleanup() {
    local h
    for h in ${PROBE_HOSTS}; do     # a clock probe must not stay behind a run that stopped half-way: ended and waited for before the locks go
        r "${h}" "$(probe_end "${PROBE_PAT}" 'a clock probe (bench_clock_probe)')" || true
    done
    for h in ${LOCKED[@]+"${LOCKED[@]}"}; do
        r "${h}" "\$HOME/array_rev/boardlock.sh release '${LOCK_OWNER}'" || true
    done
    LOCKED=()
    [[ -z "${TMP}" ]] || rm -rf "${TMP}"
    # the manifest of a checked run, written last: the lock releases above are still logged to cmd.txt
    # (written in finish(), as before, the manifest's line for cmd.txt never verified)
    if [[ -n "${OUT:-}" && -f "${OUT}/check.txt" ]]; then
        (cd "${OUT}" && shasum -a 256 $(ls | grep -v MANIFEST.sha256) > MANIFEST.sha256)
    fi
}
trap cleanup EXIT
# A signal ends the driver through its exit trap, and the cleanup is not cut short by a second one. Without these
# lines an exit trap set off by SIGTERM was ended in mid-course when the signal came twice (to the process group, and
# once more from caffeinate, under which the driver runs on the measuring workstation): probes left running, board locks left held.
trap 'trap "" INT TERM HUP; exit 130' INT
trap 'trap "" INT TERM HUP; exit 143' TERM
trap 'trap "" INT TERM HUP; exit 129' HUP

# the campaign measures on the same boards: its marker file means hands off; iris's disk is nearly full
# A board under measurement gets no SSH session at all, not even to look for its marker: a login
# shell is foreign activity next to a latency measurement. The campaign scripts keep a marker
# file per board on this machine; the marker on the board itself stays as the second check.
MARKER_DIR="${MARKER_DIR:-${HOME}/Downloads/pqc-secoc-campaign}"
local_marker_check() {
    [[ -z "${HOLDING_MEASURING}" ]] || return 0
    [[ ! -e "${MARKER_DIR}/MEASURING_$1" ]] || { echo "${MARKER_DIR}/MEASURING_$1 exists: $1 is under measurement, nothing is started" >&2; exit 1; }
}

guard() {
    local_marker_check "$1"
    r "$1" "${HOLDING_MEASURING:+true || }"'test ! -e $HOME/array_rev/MEASURING || { echo "~/array_rev/MEASURING exists: not touching this board" >&2; exit 1; }; avail=$(df --output=avail -m $HOME | tail -1); test "$avail" -ge 250 || { echo "only $avail MB free in $HOME" >&2; exit 1; }'
}

sync_tree() {
    guard "$1"
    # the board directory belongs to the clone that synced into it first
    r "$1" "mkdir -p ${PI_DIR} && if test -f ${PI_DIR}/.origin && ! grep -qxF '${ROOT}' ${PI_DIR}/.origin; then echo \"${PI_DIR} belongs to another clone: \$(cat ${PI_DIR}/.origin). Set PI_TREE to a directory of your own.\" >&2; exit 1; fi; echo '${ROOT}' > ${PI_DIR}/.origin"
    echo "[mac] rsync Autosar_SecOC -> pi-$1:${PI_TREE}/ (commit ${COMMIT})" >> "${CMD_LOG}"
    rsync -az --delete -e "ssh -F ${PI_SSH_CFG}" --exclude '.git' --exclude '/Autosar_SecOC/build/' \
        "${ROOT}/Autosar_SecOC" "pi-$1:${PI_TREE}/"
}

# build <host> <tx|rx> <local_ip> <peer_ip> <key_dir> <build_dir> [extra ninja targets]
build() {
    r "$1" "set -o pipefail; df -h \$HOME | tail -1; LIBOQS_ROOT=$(liboqs_root "$1") SECOC_GIT_COMMIT=${COMMIT} SECOC_BUILD_TYPE=${BUILD_TYPE} SECOC_PORT=${BUILD_PORT:-${RX_PORT}} taskset -c 0-2 nice -n 10 ${PI_DIR}/Autosar_SecOC/scripts/build_gateway.sh $2 $3 $4 $5 $6 ${7:-} | tail -2"
}

# the gateway does not create its identity at start-up: its ML-DSA key pair is made by `SecOC --keygen`
# (an existing pair is kept)
ensure_keypair() {
    r "$1" "cd $3 && ./SecOC --keygen | tail -1 && sha256sum $2/mldsa_secoc.pub"
}

cpu_setup() {
    [[ -z "${HOLDING_MEASURING}" ]] || return 0     # the holder of the measuring marker has set governor and cap
    r "$1" 'echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null; cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor'
    # baolong (board Rev 1.5) runs up to 1.8 GHz: capped to iris's 1.5 GHz for comparable hosts. A file
    # ~/array_rev/DEV_FREQ_CAP (kHz) on a board is the campaign's lower cap for the development phase and
    # wins; functional runs do not need 1.5 GHz. Not persistent; env_<host>.txt records what is in force.
    local default=""
    [[ "$1" != baolong ]] || default=1500000
    r "$1" "f=\$(cat \$HOME/array_rev/DEV_FREQ_CAP 2>/dev/null || echo ${default}); test -z \"\$f\" || echo \$f | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq > /dev/null; cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq"
}

# The link step itself is Autosar_SecOC/scripts/link_eth0.sh on each Pi (what it does and why is
# written there). The speed is what both ends advertise, so the transmitter side first only changes
# its advertisement and is brought up and checked after the receiver side has renegotiated.
link_up() {
    r "${TX_HOST}" "${PI_DIR}/Autosar_SecOC/scripts/link_eth0.sh speed ${LINK_SPEED}"
    r "${RX_HOST}" "${PI_DIR}/Autosar_SecOC/scripts/link_eth0.sh up ${RX_IP} ${LINK_SPEED}"
    r "${TX_HOST}" "${PI_DIR}/Autosar_SecOC/scripts/link_eth0.sh up ${TX_IP} ${LINK_SPEED}"
}

# start_rx <host> <build> <run_dir> <suffix> <outcomes, 0 = no limit> <time limit s>
# The receiver gateway, detached; its pid goes to rx<suffix>.pid. Returns when it is in RUN state.
start_rx() {
    local h="$1" b="$2" rd="$3" x="$4" n="$5" limit="$6"
    r "${h}" "cd ${rd} && (${APPENV} SECOC_APP_CSV=${rd}/app_rx${x}.csv SECOC_APP_HS_CSV=${rd}/handshake_rx${x}.csv SECOC_APP_PAYLOAD_CSV=${rd}/rx_payload${x}.csv SECOC_APP_COUNT=${n} SECOC_APP_IDLE_EXIT_MS=${RX_IDLE_EXIT_MS} nohup timeout ${limit} taskset -c ${CORE} ${b}/SecOC > rx${x}_${h}.log 2>&1 < /dev/null & echo \$! > rx${x}.pid); for i in \$(seq 50); do grep -q 'Program entered RUN state' rx${x}_${h}.log 2>/dev/null && break; sleep 0.2; done; grep -q 'Program entered RUN state' rx${x}_${h}.log && tail -2 rx${x}_${h}.log"
}

# wait_rx <host> <run_dir> <suffix> <seconds>: the receiver has exited by itself, or is stopped by its pid
wait_rx() {
    local h="$1" rd="$2" x="$3" limit="$4" waited=0
    echo "[${h}] (repeated, at most ${limit} s) p=\$(cat ${rd}/rx${x}.pid); for i in \$(seq 20); do kill -0 \$p 2>/dev/null || exit 0; sleep 1; done; exit 3" >> "${CMD_LOG}"
    until ssh -F "${PI_SSH_CFG}" "pi-${h}" "p=\$(cat ${rd}/rx${x}.pid); for i in \$(seq 20); do kill -0 \$p 2>/dev/null || exit 0; sleep 1; done; exit 3"; do
        waited=$(( waited + 20 ))
        (( waited < limit )) || break
    done
    r "${h}" "p=\$(cat ${rd}/rx${x}.pid); if kill -0 \$p 2>/dev/null; then echo 'receiver still running: stopped'; kill \$p; fi; grep -E 'App_Rx\\] (done|WARN)|App_Hs\\]' ${rd}/rx${x}_${h}.log | tail -6"
}

# start_tx <host> <build> <run_dir> <suffix> <PDUs per stream> <time limit s>
# The transmitter gateway, detached from the SSH session (a session that dies must not take the run
# with it); its exit code goes to tx<suffix>.rc.
start_tx() {
    local h="$1" b="$2" rd="$3" x="$4" n="$5" limit="$6" midrun="" rekey=""
    if (( FORGED_MIDRUN > 0 )) && [[ -z "${x}" ]]; then
        midrun="(sleep 3; python3 ${PI_DIR}/Autosar_SecOC/scripts/inject_forged.py ${TXPEER_OF_RUN} ${INJECT_PORT} ${FORGED_MIDRUN} 0.05 ${PROFILE} > ${rd}/inject_midrun.log 2>&1 &); "
    fi
    (( REKEY_AT == 0 )) || rekey="SECOC_APP_REKEY_AT=${REKEY_AT} "
    r "${h}" "${midrun}cd ${rd} && rm -f tx${x}.rc && (nohup setsid sh -c '${rekey}${APPENV} SECOC_APP_CSV=${rd}/app_tx${x}.csv SECOC_APP_HS_CSV=${rd}/handshake_tx${x}.csv SECOC_APP_COUNT=${n} SECOC_APP_STREAMS=${STREAMS} SECOC_APP_PERIOD_CYCLES=${PERIOD_CYCLES} timeout ${limit} taskset -c ${CORE} ${b}/SecOC > tx${x}_${h}.log 2>&1 < /dev/null; echo \$? > tx${x}.rc' > /dev/null 2>&1 < /dev/null &)"
}

# E9, cell g: the clock probe beside the gateways (Autosar_SecOC/bench/bench_clock_probe.c). Server on the
# receiver's board, client on the transmitter's. An anchor of the offset track is the best exchange of a window
# of 5 s, and the run needs two before its first PDU and two behind its last delivery (the first and the last
# anchor only delimit): the transmitter starts 12 s after the probe, and the probe goes on for 12 s after the
# transmitter has ended and then to the end of its window.
# Both ends are under `timeout`: a probe that the driver lost ends by itself.
# probe_start <tx_host> <rx_host> <run_dir> <address of the receiver> <time limit s>
probe_start() {
    PROBE_HOSTS="$1 $2"
    r "$2" "cd $3 && (nohup timeout -s TERM $5 ${PROBE_BIN} --server --bind $4 --port ${PROBE_PORT} --cpu ${PROBE_CPU} --map-out $3/clock_map_b.csv > probe_server.log 2>&1 < /dev/null &); sleep 0.5; grep -q 'clock probe server' probe_server.log"
    r "$1" "cd $3 && (nohup timeout -s TERM $5 ${PROBE_BIN} --client --peer $4 --port ${PROBE_PORT} --cpu ${PROBE_CPU} --interval-ms ${PROBE_INTERVAL_MS} --out $3/clock_probe.csv --map-out $3/clock_map_a.csv > probe_client.log 2>&1 < /dev/null &); for i in \$(seq 50); do grep -q 'first exchange completed' probe_client.log 2>/dev/null && break; sleep 0.1; done; grep -q 'first exchange completed' probe_client.log && sleep 12"
}

# probe_stop <tx_host> <rx_host> <run_dir>: the client first; told to end, it completes its window of 5 s
# (up to 5 s more) and writes clock_probe.csv and its map; each end is waited for up to PROBE_WAIT s (probe_end)
probe_stop() {
    r "$1" "sleep 12; $(probe_end "${PROBE_PAT} --client" 'the probe client (bench_clock_probe --client)'); tail -n 1 $3/probe_client.log"
    # the server writes its clock map when it is told to end: waited for, so that the copy finds the whole file
    r "$2" "$(probe_end "${PROBE_PAT} --server" 'the probe server (bench_clock_probe --server)'); tail -n 1 $3/probe_server.log"
    PROBE_HOSTS=""
}

# wait_tx <host> <run_dir> <suffix> <time limit s>: waited for in short sessions
wait_tx() {
    local h="$1" rd="$2" x="$3" limit="$4" waited=0 rc tries=0
    if [[ -n "${HOLDING_MEASURING}" ]]; then
        # under the measuring marker a login is foreign activity: one session that only waits, on core 0; the
        # transmitter runs under its own time limit, so the file comes. A lost session is made again and waits on.
        while :; do
            rc=0
            r "${h}" "taskset -cp 0 \$\$ > /dev/null; while [ ! -f ${rd}/tx${x}.rc ]; do sleep 2; done" || rc=$?
            [[ "${rc}" == 255 ]] && (( ++tries < 20 )) || break
            sleep 15
        done
    else
    echo "[${h}] (repeated until it succeeds, at most $(( limit + 60 )) s) for i in \$(seq 20); do test -f ${rd}/tx${x}.rc && exit 0; sleep 2; done; exit 3" >> "${CMD_LOG}"
    until ssh -F "${PI_SSH_CFG}" "pi-${h}" "for i in \$(seq 20); do test -f ${rd}/tx${x}.rc && exit 0; sleep 2; done; exit 3"; do
        waited=$(( waited + 40 ))
        (( waited < limit + 60 )) || { echo "the transmitter did not finish within $(( limit + 60 )) s" >&2; exit 1; }
    done
    fi
    r "${h}" "cd ${rd} && echo tx_exit=\$(cat tx${x}.rc); grep -E 'commit|App_Tx\\] (done|WARN|rekey)|App_Hs\\]' tx${x}_${h}.log | tail -8"
}

# run_pair <tx_host> <rx_host> <tx_build> <rx_build> <count> <pi_run_dir> <peer_ip_of_tx> <peer_ip_of_rx>
run_pair() {
    local txh="$1" rxh="$2" txb="$3" rxb="$4" count="$5" rd="$6" txpeer="$7" rxpeer="$8"
    TXPEER_OF_RUN="${txpeer}"
    local txlimit=$(( count * PERIOD_CYCLES / 500 + 180 ))
    # with a wrong peer key no session comes about and the transmitter never finishes: a few attempts are enough
    [[ "${WRONG_PEER_KEY}" != 1 ]] || txlimit=20
    local tampered=$(( TAMPER_EVERY > 0 ? count * STREAMS / TAMPER_EVERY : 0 ))
    local appenv="SECOC_APP_PROFILE=${PROFILE}"
    (( MAC_KEY_FILE_PROBE == 0 )) || appenv="${appenv} SECOC_APP_MAC_KEY_FILE=${rd}/mac_keys.bin"
    APPENV="${appenv}"      # for start_rx and start_tx
    local rxbuilds="${rxb}"
    [[ "${txh}" == "${rxh}" ]] && rxbuilds="${txb} ${rxb}"

    guard "${rxh}"
    [[ "${txh}" == "${rxh}" ]] || guard "${txh}"
    r "${rxh}" "${PI_DIR}/Autosar_SecOC/scripts/capture_env.sh before ${rd}/env_${rxh}.txt $(liboqs_root "${rxh}") ${COMMIT} ${rxpeer} ${rxbuilds}"
    [[ "${txh}" == "${rxh}" ]] || r "${txh}" "${PI_DIR}/Autosar_SecOC/scripts/capture_env.sh before ${rd}/env_${txh}.txt $(liboqs_root "${txh}") ${COMMIT} ${txpeer} ${txb}"

    # Receiver first. It exits after its number of outcomes or 10 s without traffic. With RESTART=rx
    # the first receiver process exits after RESTART_AFTER outcomes and a second one is started 2 s
    # later (files with the suffix 2); with RESTART=tx the transmitter is the one that is replaced.
    local rxcount=$(( count * STREAMS + FORGED + tampered ))
    [[ "${RESTART}" != rx ]] || rxcount="${RESTART_AFTER}"
    start_rx "${rxh}" "${rxb}" "${rd}" "" "${rxcount}" "$(( txlimit + 60 ))"
    # the UDP control channel of the old key exchange is gone: nothing may listen on its port
    r "${rxh}" "if ss -Hlun | grep -q ':60500 '; then echo 'a UDP listener on port 60500 (the retired control channel)' >&2; exit 1; fi; echo 'no UDP listener on port 60500'"

    if (( FORGED > 0 )); then
        # forged PDUs from the transmitter's host, on a TCP connection of their own that is closed
        # before the transmitter connects: the receiver has no session yet
        r "${txh}" "python3 ${PI_DIR}/Autosar_SecOC/scripts/inject_forged.py ${txpeer} ${INJECT_PORT} ${FORGED} 0.05 ${PROFILE}$( (( MAC_KEY_FILE_PROBE )) && echo " ${rd}/mac_keys.copy" ) && sleep 1"
    fi
    if (( RELAY_ON )); then
        # the transmitter connects to the relay, the relay to the receiver (loopback: the relay takes
        # the gateway port and the receiver listens one port further; two-node: the relay runs on the
        # transmitter's board, so that its connection reaches the receiver from the configured peer
        # address, and the transmitter is a build whose peer is the relay)
        r "${RELAY_HOST}" "cd ${rd} && (nohup python3 ${PI_DIR}/Autosar_SecOC/scripts/relay_tamper.py ${RELAY_LISTEN} ${RELAY_DST} ${TAMPER_EVERY} $( (( DROP_HEADER > 0 )) && echo "${DROP_HEADER} ${DROP_NTH}" ) > relay.log 2>&1 < /dev/null &); for i in \$(seq 25); do grep -q listening relay.log 2>/dev/null && break; sleep 0.2; done; cat relay.log"
    fi

    case "${RESTART}" in
    rx)
        start_tx "${txh}" "${txb}" "${rd}" "" "${count}" "${txlimit}"
        wait_rx "${rxh}" "${rd}" "" "${txlimit}"
        r "${rxh}" "sleep 2"
        start_rx "${rxh}" "${rxb}" "${rd}" 2 0 "$(( txlimit + 60 ))"
        wait_tx "${txh}" "${rd}" "" "${txlimit}"
        wait_rx "${rxh}" "${rd}" 2 "${RX_END_WAIT}"
        ;;
    tx)
        start_tx "${txh}" "${txb}" "${rd}" "" "${RESTART_AFTER}" "${txlimit}"
        wait_tx "${txh}" "${rd}" "" "${txlimit}"
        r "${txh}" "sleep 2"
        start_tx "${txh}" "${txb}" "${rd}" 2 "$(( count - RESTART_AFTER ))" "${txlimit}"
        wait_tx "${txh}" "${rd}" 2 "${txlimit}"
        wait_rx "${rxh}" "${rd}" "" "${RX_END_WAIT}"
        ;;
    *)
        [[ "${CLOCK_PROBE}" != 1 ]] || probe_start "${txh}" "${rxh}" "${rd}" "${txpeer}" "$(( txlimit + 120 ))"
        start_tx "${txh}" "${txb}" "${rd}" "" "${count}" "${txlimit}"
        wait_tx "${txh}" "${rd}" "" "${txlimit}"
        [[ "${CLOCK_PROBE}" != 1 ]] || probe_stop "${txh}" "${rxh}" "${rd}"
        wait_rx "${rxh}" "${rd}" "" "${RX_END_WAIT}"
        ;;
    esac

    r "${rxh}" "${PI_DIR}/Autosar_SecOC/scripts/capture_env.sh after ${rd}/env_${rxh}.txt $(liboqs_root "${rxh}") ${COMMIT} ${rxpeer} ${rxbuilds}"
    [[ "${txh}" == "${rxh}" ]] || r "${txh}" "${PI_DIR}/Autosar_SecOC/scripts/capture_env.sh after ${rd}/env_${txh}.txt $(liboqs_root "${txh}") ${COMMIT} ${txpeer} ${txb}"
}

collect() {
    local host="$1" rd="$2" out="$3"
    echo "[mac] rsync pi-${host}:${rd}/{*.csv,*.log,env_*.txt} -> ${out}/" >> "${CMD_LOG}"
    rsync -az -e "ssh -F ${PI_SSH_CFG}" --include '*.csv' --include '*.log' --include 'env_*.txt' --include 'ping_before.txt' --include 'key_file_probe.txt' --include 'strace_*.txt' --include 'inject_midrun.log' --exclude '*' \
        "pi-${host}:${rd#\$HOME/}/" "${out}/"
}

# merge_csv <out> <first> <second>: the rows of the second file behind the first file
merge_csv() {
    # the second part's rows, and its TCP_NODELAY read-back lines (one per connection of that process)
    { cat "$2"; awk '/^# tcp_nodelay=/ || !/^(#|stream,|seq,)/' "$3"; } > "$1"
}

# finish <out_dir> <count> [env files of a run over eth0: the link must not have changed under it]
finish() {
    local out="$1" count="$2"
    shift 2
    local rc=0
    # Expected rows, from the specification ("No session", "Reaction to a verification failure"):
    #  - forged PDUs sent before the transmitter connects meet a receiver without a session: dropped
    #    by the freshness function, freshness_fail (before the handshake existed: auth_fail);
    #  - a tampered copy inside the session fails verification: auth_fail; nothing is discarded by SoAd;
    #  - forged PDUs in the middle of a run come on a second connection, which is refused: no row;
    #  - wrong peer key on the receiver: it does not know the initiator (unknown_id), no session comes
    #    about, the transmitter gives up each attempt after T_A (timeout) and releases no PDU at all.
    local expect="freshness_fail=${FORGED},auth_fail=$(( TAMPER_EVERY > 0 ? count * STREAMS / TAMPER_EVERY : 0 ))"
    #  - a second handshake asked for by the transmitter (REKEY_AT): two installations on each side,
    #    every PDU delivered, no failure of any class;
    #  - a gateway process replaced during the run (RESTART): traffic resumes after exactly one more
    #    handshake. Receiver replaced: PDUs that were on their way while no receiver ran, or that
    #    the transmitter still sent under the old session, are lost (one run of sequence numbers per
    #    stream) and those that reach the new receiver before the new session are freshness_fail.
    #    Transmitter replaced: nothing is lost.
    local none="" hs="tx:ok=1 rx:ok=1"
    local tx="${out}/app_tx.csv" rx="${out}/app_rx.csv" pay="${out}/rx_payload.csv"
    local hstx="${out}/handshake_tx.csv" hsrx="${out}/handshake_rx.csv"
    if [[ "${WRONG_PEER_KEY}" == 1 ]]; then
        none="--no-pdu"; hs="tx:timeout=1+ rx:unknown_id=1+"; expect=""
    fi
    (( REKEY_AT == 0 )) || hs="tx:ok=2 rx:ok=2"
    #  - M3 left out by the relay (specification, on-wire test 11): the responder installs nothing and
    #    wipes its pending handshake after T_pend (timeout); the initiator has installed, gets no M4
    #    within T_A (timeout) and runs a new handshake (ok on both sides). The PDUs it sent in
    #    between meet a receiver without a session: freshness_fail, one run of them lost per stream.
    if (( DROP_HEADER == 0x32 )); then
        none="--lost-run"; hs="tx:timeout=1,ok=1 rx:timeout=1,ok=1"
    fi
    case "${RESTART}" in
    rx) # both receiver processes in one file each for the checker (the parts stay next to them)
        merge_csv "${out}/app_rx_all.csv" "${rx}" "${out}/app_rx2.csv"; rx="${out}/app_rx_all.csv"
        merge_csv "${out}/rx_payload_all.csv" "${pay}" "${out}/rx_payload2.csv"; pay="${out}/rx_payload_all.csv"
        merge_csv "${out}/handshake_rx_all.csv" "${hsrx}" "${out}/handshake_rx2.csv"; hsrx="${out}/handshake_rx_all.csv"
        none="--restart rx"; hs="tx:ok=2 rx:ok=2" ;;
    tx) merge_csv "${out}/app_tx_all.csv" "${tx}" "${out}/app_tx2.csv"; tx="${out}/app_tx_all.csv"
        merge_csv "${out}/handshake_tx_all.csv" "${hstx}" "${out}/handshake_tx2.csv"; hstx="${out}/handshake_tx_all.csv"
        none="--restart tx"; hs="tx:ok=2 rx:ok=2" ;;
    esac
    python3 "${ROOT}/scripts/check_run.py" "${tx}" "${rx}" "${count}" \
        --payload "${pay}" --expect "${EXPECT_FAIL:-${expect}}" --commit "${COMMIT}" ${none} \
        --handshake "${hstx}" "${hsrx}" --expect-hs "${EXPECT_HS:-${hs}}" ${1:+--env "$@"} > "${out}/check.txt" || rc=$?
    cat "${out}/check.txt"
    if [[ "${CLOCK_PROBE}" == 1 ]]; then      # E9, cell g: the latency rules of DATA_SCHEMA.md on the gateways' own files (no probe file: a FAIL)
        # the period of the gateway's own application, from its own files: cycles between two PDUs of a stream
        # (app_tx.csv) times the length of a BSW cycle (the handshake log), closed loop
        local pc mf
        pc="$(grep -m1 '^# period_cycles=' "${tx}" | cut -d= -f2 || true)"; mf="$(grep -m1 '^# mf_period_us=' "${hstx}" | cut -d= -f2 || true)"
        echo "gateway application: period_cycles=${pc:-missing} (app_tx.csv) x mf_period_us=${mf:-missing} (handshake_tx.csv)$([[ -z "${pc}" || -z "${mf}" ]] || echo " = $(( pc * mf )) us from one PDU of a stream to the next, closed loop")" > "${out}/e9_check.txt"
        python3 -I "${ROOT}/Autosar_SecOC/bench/check_clock_probe.py" --run "${out}/clock_probe.csv" "${tx}" "${rx}" >> "${out}/e9_check.txt" 2>&1 \
            || { rc=1; tail -1 "${out}/e9_check.txt" > "${out}/E9_INVALID"; }
        cat "${out}/e9_check.txt"
    fi
    echo "run directory: ${out}"
    return "${rc}"
}

new_run_dir() {
    OUT="${ROOT}/runs/$1"
    shift
    [[ ! -e "${OUT}" ]] || { echo "${OUT} exists; choose another run_id" >&2; exit 2; }
    mkdir -p "${OUT}"
    CMD_LOG="${OUT}/cmd.txt"
    echo "Functional run of the development phase: delivery and rejection counts only. Nothing in this directory is a timing result." > "${OUT}/FUNCTIONAL"
    [[ "${CLOCK_PROBE}" != 1 ]] || echo "With CLOCK_PROBE=1 (E9, cell g): clock_probe.csv beside the application logs relates the two boards' clocks; e9_check.txt judges the latency across the boards by the rules of DATA_SCHEMA.md (clock_probe.csv)." >> "${OUT}/FUNCTIONAL"
    [[ "${CLOCK_PROBE}" != 1 || "${DRY_RUN:-1}" == 0 ]] || echo "DRY RUN - harness check only; nothing in this directory may be quoted as a result." > "${OUT}/DRY_RUN"
    {
        echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ)  commit ${COMMIT}"
        echo "# PI_SSH_CFG=<ssh config> PERIOD_CYCLES=${PERIOD_CYCLES} STREAMS=${STREAMS} CORE=${CORE} LINK_SPEED=${LINK_SPEED} SECOC_BUILD_TYPE=${BUILD_TYPE} PROFILE=${PROFILE} FORGED=${FORGED} FORGED_MIDRUN=${FORGED_MIDRUN} TAMPER_EVERY=${TAMPER_EVERY} WRONG_PEER_KEY=${WRONG_PEER_KEY} RESTART=${RESTART} RESTART_AFTER=${RESTART_AFTER} REKEY_AT=${REKEY_AT} DROP_HEADER=${DROP_HEADER} DROP_NTH=${DROP_NTH} MAC_KEY_FILE_PROBE=${MAC_KEY_FILE_PROBE} PI_TREE=${PI_TREE} scripts/run_e2e.sh $*"
        echo "# commands executed on each host, in order:"
    } > "${CMD_LOG}"
}

case "${1:-}" in
buildall)
    new_run_dir "${2:-phase1_t1}" "$@"
    lock_boards "build of both gateway binaries" "${TX_HOST}" "${RX_HOST}"
    for H in "${TX_HOST}" "${RX_HOST}"; do
        if [[ "${H}" == "${TX_HOST}" ]]; then LOCAL="${TX_IP}"; PEER="${RX_IP}"; else LOCAL="${RX_IP}"; PEER="${TX_IP}"; fi
        sync_tree "${H}"
        {
            build "${H}" tx "${LOCAL}" "${PEER}" "${PI_DIR}/keys" "${PI_DIR}/build-tx"
            build "${H}" rx "${LOCAL}" "${PEER}" "${PI_DIR}/keys" "${PI_DIR}/build-rx"
            r "${H}" "cd ${PI_DIR}; for b in build-tx build-rx; do echo \"== \$(hostname) \$b\"; sha256sum \$b/SecOC; \$b/SecOC --version; ninja -C \$b -t commands SecOC | grep -m1 -E '/source/main\\.c( |\$)'; done; df -h \$HOME | tail -1"
        } 2>&1 | tee "${OUT}/build_${H}.txt"
    done
    ;;

link)
    new_run_dir "${2:-phase1_t2}" "$@"
    lock_boards "link step ${LINK_SPEED} Mbit/s and ping" "${TX_HOST}" "${RX_HOST}"
    sync_tree "${TX_HOST}"
    sync_tree "${RX_HOST}"
    link_up 2>&1 | tee "${OUT}/link_up.txt"
    r "${TX_HOST}" "cat /sys/class/net/eth0/speed /sys/class/net/eth0/duplex; ip route get ${RX_IP}; ping -c 20 -I eth0 ${RX_IP}" | tee "${OUT}/link_${TX_HOST}.txt"
    r "${RX_HOST}" "cat /sys/class/net/eth0/speed /sys/class/net/eth0/duplex; ip route get ${TX_IP}; ping -c 5 -I eth0 ${TX_IP}" | tee "${OUT}/link_${RX_HOST}.txt"
    grep -q ' 0% packet loss' "${OUT}/link_${TX_HOST}.txt" && grep -q ' 0% packet loss' "${OUT}/link_${RX_HOST}.txt"
    ;;

linkdown)
    new_run_dir "${2:-linkdown}" "$@"
    lock_boards "link down" "${TX_HOST}" "${RX_HOST}"
    r "${TX_HOST}" "${PI_DIR}/Autosar_SecOC/scripts/link_eth0.sh down ${TX_IP}" | tee "${OUT}/link_down_${TX_HOST}.txt"
    r "${RX_HOST}" "${PI_DIR}/Autosar_SecOC/scripts/link_eth0.sh down ${RX_IP}" | tee "${OUT}/link_down_${RX_HOST}.txt"
    ;;

loopback)
    HOST="${2:?host}"; COUNT="${3:?count}"; RUN_ID="${4:?run_id}"
    new_run_dir "${RUN_ID}" "$@"
    RD="${PI_DIR}/runs/${RUN_ID}"
    lock_boards "loopback ${COUNT} PDUs, run ${RUN_ID} (sync, build, run)" "${HOST}"
    sync_tree "${HOST}"
    build "${HOST}" tx 127.0.0.1 127.0.0.1 "${PI_DIR}/keys/lo-tx" "${PI_DIR}/build-lo-tx"
    RXB="${PI_DIR}/build-lo-rx"
    if (( RELAY_ON )); then
        # the relay takes the gateway port; this receiver listens one port further
        RXB="${PI_DIR}/build-lo-rx-relay"
        BUILD_PORT="${RELAY_PORT}"
        RELAY_HOST="${HOST}"; RELAY_LISTEN="${RX_PORT}"; RELAY_DST="127.0.0.1 ${RELAY_PORT}"; INJECT_PORT="${RELAY_PORT}"
    fi
    build "${HOST}" rx 127.0.0.1 127.0.0.1 "${PI_DIR}/keys/lo-rx" "${RXB}" "txrx_e2e_test mac_profile_test"
    BUILD_PORT=""
    ensure_keypair "${HOST}" "${PI_DIR}/keys/lo-tx" "${PI_DIR}/build-lo-tx"
    ensure_keypair "${HOST}" "${PI_DIR}/keys/lo-rx" "${RXB}"
    r "${HOST}" "cp ${PI_DIR}/keys/lo-tx/mldsa_secoc.pub ${PI_DIR}/keys/lo-rx/mldsa_peer0.pub; cp ${PI_DIR}/keys/lo-rx/mldsa_secoc.pub ${PI_DIR}/keys/lo-tx/mldsa_peer0.pub"
    if [[ "${WRONG_PEER_KEY}" == 1 ]]; then
        # the receiver's own public key in the place of the transmitter's (the next loopback run puts the right one back)
        r "${HOST}" "cp ${PI_DIR}/keys/lo-rx/mldsa_secoc.pub ${PI_DIR}/keys/lo-rx/mldsa_peer0.pub; sha256sum ${PI_DIR}/keys/lo-*/*.pub"
    fi
    cpu_setup "${HOST}"
    cool_gate "${HOST}"
    r "${HOST}" "test ! -e ${RD} && mkdir -p ${RD}"
    # in-process Tx -> wire -> Rx test (test/test_txrx_e2e.c) of the same build
    r "${HOST}" "cd ${RD} && (${RXB}/txrx_e2e_test 2>&1 | grep -E '^(Tx|Rx|[CVM][0-9]|PASS|FAIL|  FAIL|   )' > txrx_e2e_test.log; tail -1 txrx_e2e_test.log; tail -1 txrx_e2e_test.log | grep -q '^PASS')"
    # Csm MAC test (test/test_mac_profile.c) of the same build
    r "${HOST}" "cd ${RD} && (${RXB}/mac_profile_test 2>&1 | grep -E '^(K[0-9]|PASS|FAIL|  FAIL|   )' > mac_profile_test.log; tail -1 mac_profile_test.log; tail -1 mac_profile_test.log | grep -q '^PASS')"
    if (( MAC_KEY_FILE_PROBE )); then
        # A known key where the key file of the dry runs was (and a second file with the same bytes
        # for the injector). Each gateway binary is started for 5 s under strace with the variable
        # pointing at the file: it must open its ML-DSA key pair (the trace sees opens) and must not
        # open the key file. (The access time cannot show this: the file system is mounted noatime.)
        r "${HOST}" "cd ${RD} && (umask 077; for f in mac_keys.bin mac_keys.copy; do head -c 64 /dev/zero | tr '\\000' 'K' > \$f; done) && for b in ${PI_DIR}/build-lo-tx ${RXB}; do n=\$(basename \$b); SECOC_APP_PROFILE=mac SECOC_APP_MAC_KEY_FILE=${RD}/mac_keys.bin strace -f -e trace=open,openat -o strace_\$n.txt timeout 5 taskset -c ${CORE} \$b/SecOC > probe_\$n.log 2>&1; echo \"\$n: key pair opened \$(grep -c mldsa_secoc strace_\$n.txt) time(s), key file opened \$(grep -c mac_keys strace_\$n.txt) time(s)\"; done | tee key_file_probe.txt; ! grep -q 'key file opened [1-9]' key_file_probe.txt && ! grep -q 'key pair opened 0 ' key_file_probe.txt"
    fi
    run_pair "${HOST}" "${HOST}" "${PI_DIR}/build-lo-tx" "${RXB}" "${COUNT}" "${RD}" 127.0.0.1 127.0.0.1
    collect "${HOST}" "${RD}" "${OUT}"
    finish "${OUT}" "${COUNT}"
    ;;

twonode)
    COUNT="${2:?count}"; RUN_ID="${3:?run_id}"
    new_run_dir "${RUN_ID}" "$@"
    RD="${PI_DIR}/runs/${RUN_ID}"
    lock_boards "two-node ${COUNT} PDUs at ${LINK_SPEED} Mbit/s, run ${RUN_ID} (sync, build, run)" "${TX_HOST}" "${RX_HOST}"
    sync_tree "${TX_HOST}"
    sync_tree "${RX_HOST}"
    TXB="${PI_DIR}/build-tx"
    if (( RELAY_ON )); then
        TXB="${PI_DIR}/build-tx-relay"
        BUILD_PORT="${RELAY_PORT}"
        build "${TX_HOST}" tx "${TX_IP}" 127.0.0.1 "${PI_DIR}/keys" "${TXB}"
        BUILD_PORT=""
        RELAY_HOST="${TX_HOST}"; RELAY_LISTEN="${RELAY_PORT}"; RELAY_DST="${RX_IP} ${RX_PORT}"
    else
        build "${TX_HOST}" tx "${TX_IP}" "${RX_IP}" "${PI_DIR}/keys" "${TXB}"
    fi
    build "${RX_HOST}" rx "${RX_IP}" "${TX_IP}" "${PI_DIR}/keys" "${PI_DIR}/build-rx"
    # same liboqs options on both boards, or the run stops (the build-target string names the kernel and is left out)
    OQS_CFG="grep '^#define' $(liboqs_root x)/build/include/oqs/oqsconfig.h | grep -v OQS_COMPILE_BUILD_TARGET | sort | sha256sum | cut -d' ' -f1"
    OQS_TX="$(r "${TX_HOST}" "${OQS_CFG}")"; OQS_RX="$(r "${RX_HOST}" "${OQS_CFG}")"
    echo "liboqs option defines: ${TX_HOST} ${OQS_TX}, ${RX_HOST} ${OQS_RX}"
    [[ -n "${OQS_TX}" && "${OQS_TX}" == "${OQS_RX}" ]] || { echo "liboqs configurations differ between the boards" >&2; exit 1; }
    cool_gate "${RX_HOST}"
    link_up 2>&1 | tee "${OUT}/link_up.txt"
    ensure_keypair "${TX_HOST}" "${PI_DIR}/keys" "${TXB}"
    ensure_keypair "${RX_HOST}" "${PI_DIR}/keys" "${PI_DIR}/build-rx"
    # public keys cross over through the measuring workstation; secret keys never leave their Pi
    TMP="$(mktemp -d)"
    echo "[mac] copy ${TX_HOST}:keys/mldsa_secoc.pub -> ${RX_HOST}:keys/mldsa_peer0.pub and the reverse" >> "${CMD_LOG}"
    rsync -az -e "ssh -F ${PI_SSH_CFG}" "pi-${TX_HOST}:${PI_TREE}/keys/mldsa_secoc.pub" "${TMP}/${TX_HOST}.pub"
    rsync -az -e "ssh -F ${PI_SSH_CFG}" "pi-${RX_HOST}:${PI_TREE}/keys/mldsa_secoc.pub" "${TMP}/${RX_HOST}.pub"
    rsync -az -e "ssh -F ${PI_SSH_CFG}" "${TMP}/${TX_HOST}.pub" "pi-${RX_HOST}:${PI_TREE}/keys/mldsa_peer0.pub"
    rsync -az -e "ssh -F ${PI_SSH_CFG}" "${TMP}/${RX_HOST}.pub" "pi-${TX_HOST}:${PI_TREE}/keys/mldsa_peer0.pub"
    r "${TX_HOST}" "sha256sum ${PI_DIR}/keys/*.pub"
    r "${RX_HOST}" "sha256sum ${PI_DIR}/keys/*.pub"
    cpu_setup "${TX_HOST}"
    cpu_setup "${RX_HOST}"
    # 20 pings must all return (the link step has already refused to pass with EEE not disabled)
    r "${TX_HOST}" "test ! -e ${RD} && mkdir -p ${RD} && ping -c 20 -i 0.2 -I eth0 ${RX_IP} | tail -2 | tee ${RD}/ping_before.txt && grep -q ' 0% packet loss' ${RD}/ping_before.txt"
    r "${RX_HOST}" "test ! -e ${RD} && mkdir -p ${RD}"
    run_pair "${TX_HOST}" "${RX_HOST}" "${TXB}" "${PI_DIR}/build-rx" "${COUNT}" "${RD}" "${RX_IP}" "${TX_IP}"
    collect "${TX_HOST}" "${RD}" "${OUT}"
    collect "${RX_HOST}" "${RD}" "${OUT}"
    finish "${OUT}" "${COUNT}" "${OUT}/env_${TX_HOST}.txt" "${OUT}/env_${RX_HOST}.txt"
    ;;

*)
    awk 'NR > 1 { if (/^#/) print; else exit }' "${BASH_SOURCE[0]}" >&2   # the header comment, whatever its length
    exit 2
    ;;
esac
