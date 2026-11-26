#!/usr/bin/env bash
# scripts/run_bench_net.sh — driver on the measuring workstation for the networked harnesses (Autosar_SecOC/bench):
# transmitter on iris, receiver on baolong, over eth0.
#
#   PI_SSH_CFG=<cfg> scripts/run_bench_net.sh build
#       sync this tree to both Pis, build bench_net_tx / bench_net_rx / bench_keygen and, on the
#       receiver's board, the gateway binary (role RX, for the attack runs); create and exchange keys
#   PI_SSH_CFG=<cfg> scripts/run_bench_net.sh periodic <run_id> <period_us> <count> [other|fifo]
#       one periodic stream, open loop: periodic_tx.csv, periodic_rx.csv, rx_payload.csv
#       CLOCK_PROBE=1 (E9, latency across the two boards): bench_clock_probe runs beside it, server on the
#       receiver's board and client on the transmitter's, on core PROBE_CPU (default 1), UDP port PORT+3,
#       one exchange every PROBE_INTERVAL_MS (default 101: the phase to the 10 ms releases moves through its
#       ten values; the phase to the 1 ms cycle stays fixed), from 12 s before the transmitter starts to 12 s after it has ended (PROBE_LEAD_IN, PROBE_LEAD_OUT:
#       two anchors of the offset track on each side of the run): periodic/clock_probe.csv,
#       with the clock maps of the two boards (clock_map_a.csv from the transmitter's, clock_map_b.csv from the
#       receiver's: CLOCK_MONOTONIC against CLOCK_MONOTONIC_RAW every 5 ms, probe format 2), judged by
#       check_clock_probe.py --run into e9_check.txt (PASS / FAIL with the bounds; a FAIL, a probe or map
#       file that was not collected included, leaves E9_INVALID and exit code 1; the periodic files are
#       judged as without the probe).
#       PROFILE=both: one transmitter process with two streams, stream 0 the first signature stream and
#       stream 1 the MAC stream (STREAMS is then 2), the usual files with both streams in them.
#       BG_MBIT=<rate> (unrelated traffic on the link): bg_traffic.py sends one unprotected TCP flow at that
#       mean rate from the transmitter's board to the receiver's (port PORT+4, core BG_CPU, default 2) from
#       before the transmitter starts until after it has ended; background_traffic.txt says what was offered,
#       sent and received (a flow that did not cover the run or stayed below 95 %: BG_INVALID, exit code 1).
#   PI_SSH_CFG=<cfg> scripts/run_bench_net.sh probetest <run_id> [seconds]
#       the two tests of the clock probe, <seconds> each (default 60): client and server on ONE board (true
#       offset zero) for each board, then two probes at once over the link, one in each direction;
#       probetest/zero_<host>.csv, pair_ab.csv, pair_ba.csv, verdicts in probetest.txt.
#   PI_SSH_CFG=<cfg> scripts/run_bench_net.sh ladder <run_id> <duration_s> <ramp_s> <repetitions> <rate_pps>...
#       sustained load, one step per rate and repetition: throughput_{tx,rx}_<rate>pps_rep<k>.csv.
#       With PARTITIONS=N the load is N transmitter processes, each on its own core (CORES="0 1 2 3")
#       with its own TCP connection and receiver process, started and stopped together; <rate_pps> is
#       the total (divisible by N), each process offers rate/N, and the files end in _p<i> (header:
#       partition, partitions, rep). With several partitions each board's temperature is written once
#       per second (temp_<host>_<step>.csv) and at STOP_AT_C (default 78) the transmitters are told to
#       end the step: the files are complete for what was released, stopped_early=1, the run EXCLUDED.
#   PI_SSH_CFG=<cfg> scripts/run_bench_net.sh attack <run_id> <pdus> <every> <vector[,vector...]>
#       harness transmitter -> attack_proxy.py on the transmitter's board -> eth0 -> the GATEWAY receiver
#       binary (full BSW start-up including BswM, accepting its configured peer address only); its
#       application log is the oracle; attack.csv by join_attack.py (header oracle=gateway_app_log).
#       ORACLE=harness runs the same vectors against bench_net_rx instead: a separate run, labelled
#       oracle=harness_receiver, whose only purpose is detect_ns (the gateway's log has no reception time).
#       With <every> 0 and <vectors> none there is no proxy: the harness transmitter talks to the gateway
#       receiver directly; checked are the delivery count and that both name the same session.
#       Old-session replay (vector session_replay) takes two runs: one with <every> 0, a vector name and
#       RECORD_SESSION=/dev/shm/<file> (the proxy keeps every PDU of that session), then the attack run with
#       REPLAY_SESSION=/dev/shm/<file>; the recording must be longer than the attack run. session_replay.txt
#       in the attack run's directory names the session identifiers of the recording and of the injection.
#       RELAY_NETNS=1 (the attacker as a network node of its own, simulated on the transmitter's board): the
#       transmitter runs in a network namespace txns whose only interface is one end of a virtual Ethernet pair
#       (veth-tx, 10.99.0.1/30) and which has no route to the receiver; the other end (veth-atk, 10.99.0.2/30) is
#       in the root namespace, which owns eth0: there the proxy listens, pinned to core RELAY_CPU (default 2), and
#       connects on to the receiver from the board's own address. Namespace and pair exist for the run only and
#       are removed on every way out; eth0, wlan0 and the default route are not touched. netns_check.txt: the
#       route check from the namespace (it must fail), both ends of the pair, the addresses, and that both are
#       gone after the run. Vectors, files and the join are those of the attack mode without it.
# Every run starts with the handshake PQC-SecOC-HS-v1 between the two ends (NO_HANDSHAKE=1: session-less
# harnesses, development); handshake_tx.csv / handshake_rx.csv hold the attempt records (in a ladder or with
# partitions: one subdirectory handshake_<step>[_p<i>]/ per step and partition), and a run whose
# two ends name different sessions (header session_id; the gateway's "keys installed" line) is EXCLUDED.
#   PI_SSH_CFG=<cfg> scripts/run_bench_net.sh handshake <run_id> <n>
#       n handshakes one after the other (bench_handshake as initiator, bench_net_rx as responder), no PDU
#       stream, the tree's timers (about T_min + 50 ms per handshake): handshake_tx.csv and handshake_rx.csv
#       with one row per attempt on each side.
#   PI_SSH_CFG=<cfg> scripts/run_bench_net.sh hsneg <run_id> <test> <reps>
#       one on-wire handshake test of SPEC.md "Negative tests" (record, 1..10, 11drop, 11sig, 11mac, 11key,
#       12drop, 12flip): an hstest run with that test's proxy options (Autosar_SecOC/bench/README.md), judged by
#       check_hsneg.py into hsneg.txt (PASS / REJECT). 'record' first: it keeps M1..M4 of one run on the
#       transmitter's board for the replays of 5, 6, 7 and 10. The initiator is the GATEWAY transmitter
#       (build-gw-tx once, after build; INITIATOR=harness for development). Tests 11 and 12 are a batch of
#       <reps> short runs, one attacked handshake each, under one lock and one pair of gate snapshots:
#       hstest/r001.. , each judged on its own, one record line over the batch in hsneg.txt.
#   PI_SSH_CFG=<cfg> scripts/run_bench_net.sh hstest <run_id> <pdus> <rekey_after> <edit>...
#       the handshake under attack: harness transmitter -> proxy -> gateway receiver (ORACLE=harness: the
#       harness receiver). Session 1 is established, <rekey_after> PDUs are delivered, then the transmitter
#       asks for one more handshake and the proxy makes the edits on it (attack_proxy.py --hs, e.g.
#       0x32:drop@2 = the second M3 is dropped, 0x31:flip:1121:3309@2 = one bit of sig_B in the second M2);
#       <pdus> PDUs at 10 ms in total. hstest.txt: the result labels, session identifier and installation
#       counter of both sides before and after, and what the receiver did with the PDUs.
#   PI_SSH_CFG=<cfg> scripts/run_bench_net.sh calibrate <run_id> <rate_pps> <seconds>
#       one load step with tcpdump on the transmitter: bytes and TCP segments per PDU, offload state
#
# PI_SSH_CFG: ssh config with the hosts pi-iris and pi-baolong (no credentials are read here).
# Optional: CORE (pinned CPU, default 3; CORE_TX / CORE_RX for one end only), PORT (default 50102; the proxy listens on PORT+1 and the
#           gateway receiver of the attack runs is built for PORT+2, away from other gateways' 50002),
#           MAINFUNCTION=cyclic|event (default cyclic) and MF_PERIOD_US (default 1000) for both harnesses,
#           LOOPBACK=<iris|baolong> (both ends on one board over 127.0.0.1, CPUs 1 and 2: development only),
#           DRY_RUN=0 (default 1: the run directory gets a DRY_RUN marker),
#           LAYOUT="ID:HDR:PAYLOAD:FRESHNESS ..." (attack: field lengths per PDU header ID, default signature stream 0),
#           STREAMS=k (periodic: the first k signature streams on the one connection, default 1; attacks use one).
#           PROFILE=mac (the MAC stream, HMAC-SHA-256 under the session's key, instead of the signature streams).
#           PHASE=staggered (periodic: stream s of a transmitter's k streams is released s/k of a period after stream 0,
#           bench_net_tx --phase staggered, header phase=staggered; default sync, all at one instant, as without it).
#
# Every run holds the board lock (~/array_rev/boardlock.sh, owner BOARDLOCK_OWNER, default dev) of
# each board it uses, iris first and baolong second, for the run itself only, and releases it in the
# reverse order, also on failure; a run that does not get the lock within LOCK_WAIT seconds (default
# 300) is skipped with exit code 75. A build takes the locks too (one job at a time on a board) and stays
# on cores 0-2, two jobs, low priority.
# Second line of defence before every start: no ~/array_rev/MEASURING on either board (builds and
# copies included), no SecOC or harness process running, eth0 quiet, both boards below 68 C, or at
# 62 C or less before a step with several partitions, which heats a board by 15 C within minutes (waits
# COOL_WAIT seconds, default 120, then skips with exit code 75). More than two partitions are refused
# unless MAX_PARTITIONS says otherwise: three busy cores take these boards past 78 C in a minute. ALLOW_HOT_DRYRUN=1 lets a DRY_RUN
# (never a run with DRY_RUN=0) start on a hotter board, for "do the files exist and pass the checks";
# the start temperature goes into NOTE_hot_start, and the 78 C and throttling rules still exclude.
# HOLDING_MEASURING=1 is for the campaign scripts, which hold that marker: no lock is taken and the marker
# is not treated as an obstacle.
# A board under measurement gets no SSH session at all, not even to look: the measuring workstation's local
# marker files ${LOCAL_MARKERS:-~/Downloads/pqc-secoc-campaign}/MEASURING_<board> are checked on this
# workstation before anything is sent. Between the start and the end of a run one SSH session exists per
# board and it only blocks: on the transmitter's board it starts the transmitters detached (they
# survive a lost session and write tx.rc) and waits for that file, pinned to cpu 0; on the receiver's
# board there is none, or with several partitions the one that writes the temperature. Nothing is sent
# to a board while a run is going, except SIGTERM to the transmitters when the receiver's board reached
# STOP_AT_C. The driver keeps the measuring workstation awake (caffeinate) for as long as it runs.
# The eth0 link is put into (or confirmed in) the experiment state by Autosar_SecOC/scripts/link_eth0.sh
# on each board (EEE off, NetworkManager ignoring eth0, address) at the speed it already has unless
# LINK_SPEED=100|1000 is given, and must then return 20 of 20 pings.
# Results: runs/<run_id>/ with <experiment>/*.csv, cmd.txt, env_<host>.txt, gates_<host>.txt,
# check.txt, MANIFEST.sha256; a failed validity gate leaves a file EXCLUDED with the reason.

set -euo pipefail

# the measuring workstation goes to sleep about a minute after the last activity, which kills every SSH session
[[ -n "${CAFFEINATED:-}" ]] || ! command -v caffeinate > /dev/null || { export CAFFEINATED=1; exec caffeinate -is "$0" "$@"; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${PI_SSH_CFG:?set PI_SSH_CFG to an ssh config with hosts pi-iris and pi-baolong}"
CORE="${CORE:-3}"
PORT="${PORT:-50102}"
TX_HOST=iris;    TX_IP=10.10.10.1;  CORE_TX="${CORE_TX:-${CORE}}"
RX_HOST=baolong; RX_IP=10.10.10.2;  CORE_RX="${CORE_RX:-${CORE}}"
PROBE_CPU="${PROBE_CPU:-1}"     # the clock probe's core on both boards (E9): one the harnesses do not use
IFACE=eth0
if [[ -n "${LOOPBACK:-}" ]]; then
    TX_HOST="${LOOPBACK}"; RX_HOST="${LOOPBACK}"; TX_IP=127.0.0.1; RX_IP=127.0.0.1; IFACE=lo; CORE_TX=1; CORE_RX=2
    [[ "${PROBE_CPU}" != 1 ]] || PROBE_CPU=3
    BG_CPU="${BG_CPU:-0}"
fi
BG_CPU="${BG_CPU:-2}"           # the unrelated flow's core on both boards (BG_MBIT)
PI_DIR="${PI_DIR:-\$HOME/pqc-secoc-rev1-bench}"     # the tree on the boards; a second tree goes below it, e.g. PI_DIR='$HOME/pqc-secoc-rev1-bench/hs'
PI_REL="${PI_DIR#\$HOME/}"
BIN="${PI_DIR}/build-bench"
LIBOQS='$HOME/opt/liboqs-0.15.0'
LIMITS='sudo -n prlimit --pid $$ --memlock=unlimited:unlimited --rtprio=99:99'
MF="--mainfunction ${MAINFUNCTION:-cyclic} --mf-period-us ${MF_PERIOD_US:-1000}"
[[ -z "${NO_HANDSHAKE:-}" ]] || MF="${MF} --no-handshake"
[[ -z "${PROFILE:-}" ]] || MF="${MF} --profile ${PROFILE}"     # mac: the MAC stream instead of the signature streams
[[ "${PROFILE:-}" != mac || -n "${LAYOUT:-}" ]] || LAYOUT="32:1:8:4"     # the proxy's field lengths for header ID 0x20
[[ "${PROFILE:-}" != both ]] || STREAMS=2      # both variants in one process: the signature stream and the MAC stream
# PHASE: how one transmitter releases its streams. sync adds nothing to its command line (the tool's default).
PHASE="${PHASE:-sync}"; PHASE_OPT=""
[[ "${PHASE}" == sync || "${PHASE}" == staggered ]] || { echo "PHASE=${PHASE}: sync or staggered" >&2; exit 2; }
[[ "${PHASE}" == sync || "${1:-}" == periodic ]] || { echo "PHASE=${PHASE} goes with the periodic mode only (mode: ${1:-none})" >&2; exit 2; }
[[ "${PHASE}" == sync ]] || PHASE_OPT=" --phase ${PHASE}"
PARTITIONS="${PARTITIONS:-1}"
(( PARTITIONS <= ${MAX_PARTITIONS:-2} )) || { echo "PARTITIONS=${PARTITIONS}: more than ${MAX_PARTITIONS:-2} sender cores overheat these boards (MAX_PARTITIONS to override)" >&2; exit 2; }
read -r -a CORE_LIST <<< "${CORES:-}"
GW_PORT=$((PORT + 2))   # the attack runs' gateway receiver; the port is fixed when it is built
PROBE_PORT=$((PORT + 3))    # UDP: the clock probe (the probe test's second direction: one more)
PROBE_INTERVAL_MS="${PROBE_INTERVAL_MS:-101}"
PROBE='bench_clock_prob[e]'     # for pgrep/pkill -f: matches the probe of this tree, never the shell that asks
PROBE_WAIT="${PROBE_WAIT:-20}"  # s a probe process is waited for after its SIGTERM (a map of 1,000 s is about 10 MB to write)
BG_PORT=$((PORT + 4))       # TCP: the unrelated flow
BG='bg_traffi[c].py'
RELAY_CPU="${RELAY_CPU:-2}"     # RELAY_NETNS=1: the proxy's core, another one than the transmitter's
NS_TX=10.99.0.1; NS_ATK=10.99.0.2   # RELAY_NETNS=1: the two ends of the pair, a /30 of their own
RUN_LIMIT=1800              # s: a probe or an unrelated flow that its driver lost ends by itself (periodic: from the run's length)
COMMIT="$("${ROOT}/Autosar_SecOC/bench/stamp_commit.sh")"
CMD_LOG=/dev/null
FAILED=0    # set when a transmitter run exits non-zero; the files are still collected
OWNER="${BOARDLOCK_OWNER:-dev}"
LOCK_WAIT="${LOCK_WAIT:-300}"
LOCKED=""   # boards whose lock this driver holds, last taken first
HOT=""      # boards a dry run was allowed to start on at 68 C or more, for the run's notes
MARKER='test ! -e $HOME/array_rev/MEASURING'
[[ -z "${HOLDING_MEASURING:-}" ]] || MARKER=true

r() {   # run a command on a Pi and record it
    local host="$1"; shift
    echo "[${host}] $*" >> "${CMD_LOG}"
    ssh -F "${PI_SSH_CFG}" "pi-${host}" "$*"
}

hosts() { if [[ "${TX_HOST}" == "${RX_HOST}" ]]; then echo "${TX_HOST}"; else echo "${TX_HOST} ${RX_HOST}"; fi; }

# Is a board of this run under measurement? Then no SSH session may be opened to it, not even to look
# for the marker on the board: a login is foreign activity next to a latency measurement.
measured() {
    local h
    [[ -z "${HOLDING_MEASURING:-}" ]] || return 1
    for h in $(hosts); do
        [[ ! -e "${LOCAL_MARKERS:-${HOME}/Downloads/pqc-secoc-campaign}/MEASURING_${h}" ]] \
            || { echo "${h} is under measurement (local marker MEASURING_${h}): nothing is sent to it" >&2; return 0; }
    done
    return 1
}

# One lock per board for anything that uses core 3 or the eth0 link. Order of taking is fixed
# (iris, then baolong) so that two drivers can never wait for each other.
lock_boards() {
    local h waited step
    ! measured || exit 75
    [[ -z "${HOLDING_MEASURING:-}" ]] || return 0
    for h in iris baolong; do
        [[ " $(hosts) " == *" ${h} "* ]] || continue
        # Wait in attempts of at most 20 s and read the local markers between them: a session that sits
        # in the lock script on the board cannot see a marker made on the measuring workstation meanwhile.
        waited=0
        while :; do
            step=$(( LOCK_WAIT - waited < 20 ? LOCK_WAIT - waited : 20 ))
            ssh -F "${PI_SSH_CFG}" "pi-${h}" "\$HOME/array_rev/boardlock.sh acquire ${OWNER} '$1' ${step}" && break
            waited=$(( waited + (step > 0 ? step : 1) ))
            ! measured || exit 75
            (( waited < LOCK_WAIT )) || { echo "${h}: board lock not obtained within ${LOCK_WAIT} s: run SKIPPED" >&2; exit 75; }
        done
        LOCKED="${h} ${LOCKED}"
    done
}

unlock_boards() {
    local h
    for h in ${LOCKED}; do
        ssh -F "${PI_SSH_CFG}" "pi-${h}" "\$HOME/array_rev/boardlock.sh release ${OWNER}" || true
    done
    LOCKED=""
}
# on any way out: our own gateway receiver must not stay behind (a failed step after its start), then the locks
GW_STARTED=""
PROBE_STARTED=""
BG_STARTED=""
NETNS_UP=""
TX_WRAP=""; PROXY_WRAP=""       # set by the attack mode with RELAY_NETNS=1 only, never taken from the caller's environment
[[ "${RELAY_NETNS:-}" != 1 || "${1:-}" == attack ]] || { echo "RELAY_NETNS=1 goes with the attack mode only (mode: ${1:-none})" >&2; exit 2; }
# probe_end <pattern> <name>: the commands, for a board, that end the probe processes matching the pattern and wait
# for them (E9_SPEC.md, E12.4). A process still there PROBE_WAIT s after its SIGTERM is named in one line and killed, so
# that no probe is running when the board's run directory is removed or the locks are released; the file it did not
# write is then missing, which the check says. (The name carries no path: the pattern must not match the asking shell.)
probe_end() {
    echo "pkill -TERM -f '$1'; for i in \$(seq $(( PROBE_WAIT * 10 ))); do pgrep -f '$1' > /dev/null || break; sleep 0.1; done; if pgrep -f '$1' > /dev/null; then echo \"$2 on \$(hostname) has not ended within ${PROBE_WAIT} s of its SIGTERM: SIGKILL\"; pkill -KILL -f '$1'; for i in \$(seq 50); do pgrep -f '$1' > /dev/null || break; sleep 0.1; done; fi"
}
cleanup() {
    local h
    if [[ -n "${NETNS_UP}" ]]; then     # an abort in mid-run: the transmitter and the proxy first, or the proxy waits for ever on a pair that is gone
        ssh -F "${PI_SSH_CFG}" "pi-${TX_HOST}" "pkill -TERM -x bench_net_tx; pkill -TERM -f '${PI_REL}/Autosar_SecOC/bench/attack_prox[y].py'; sleep 1; pkill -KILL -x bench_net_tx; pkill -KILL -f '${PI_REL}/Autosar_SecOC/bench/attack_prox[y].py'; true" || true
        netns_down
    fi
    [[ -z "${GW_STARTED}" ]] || ssh -F "${PI_SSH_CFG}" "pi-${RX_HOST}" "pkill -f '${PI_DIR#\$HOME/}/build-gw-rx/SecO[C]'" || true
    GW_STARTED=""
    # an interrupted run: the probes are ended and waited for before the locks are released
    [[ -z "${PROBE_STARTED}" ]] || for h in $(hosts); do ssh -F "${PI_SSH_CFG}" "pi-${h}" "$(probe_end "${PI_REL}/build-bench/${PROBE}" 'a clock probe (bench_clock_probe)')" || true; done
    PROBE_STARTED=""
    [[ -z "${BG_STARTED}" ]] || for h in $(hosts); do ssh -F "${PI_SSH_CFG}" "pi-${h}" "pkill -TERM -f '${PI_REL}/Autosar_SecOC/bench/${BG}'" || true; done
    BG_STARTED=""
    unlock_boards
}
trap cleanup EXIT
# A signal ends the driver through its exit trap, and the cleanup is not cut short by a second one. Without these
# lines an exit trap set off by SIGTERM was ended in mid-course when the signal came twice (to the process group, and
# once more from caffeinate, under which the driver runs on the measuring workstation): probes left running, board locks left held.
trap 'trap "" INT TERM HUP; exit 130' INT
trap 'trap "" INT TERM HUP; exit 143' TERM
trap 'trap "" INT TERM HUP; exit 129' HUP

# limit_c <NAME> <host> <default>: the temperature limit of a board: ${NAME_<host>}, else ${NAME}, else the default
limit_c() {
    local byboard="$1_$2"
    if [[ -n "${!byboard:-}" ]]; then echo "${!byboard}"; elif [[ -n "${!1:-}" ]]; then echo "${!1}"; else echo "$3"; fi
}

free_or_die() {
    local h temp tries=$(( ${COOL_WAIT:-120} / 5 + 1 )) below
    [[ "${ALLOW_HOT_DRYRUN:-}" != 1 || "${DRY_RUN:-1}" == 0 ]] || tries=1
    ! measured || exit 75
    for h in $(hosts); do
        r "${h}" "${MARKER}"' && ! pgrep -x SecOC > /dev/null && ! pgrep -x bench_net_tx > /dev/null && ! pgrep -x bench_net_rx > /dev/null && ! pgrep -f "[a]ttack_proxy" > /dev/null && ! pgrep -f "[b]ench_clock_probe" > /dev/null && ! pgrep -f "[b]g_traffic.py" > /dev/null' \
            || { echo "${h}: MEASURING marker present, or a SecOC / harness / clock probe / background traffic process is running: not starting" >&2; exit 1; }
        # A namespace txns or a veth-atk that a killed driver left (RELAY_NETNS=1): removed when no process runs in the
        # namespace, otherwise the start is refused. Our own, while a run with the option is going, is not looked at.
        [[ -n "${NETNS_UP}" ]] || r "${h}" "if ip netns list | grep -qw txns; then [ -z \"\$(sudo -n ip netns pids txns)\" ] || exit 1; sudo -n ip netns del txns && echo 'removed the namespace txns that an earlier run left (no process in it)'; fi; if ip link show veth-atk > /dev/null 2>&1; then sudo -n ip link del veth-atk && echo 'removed the veth-atk that an earlier run left'; fi" \
            || { echo "${h}: a process runs in a network namespace txns that an earlier run left: not starting" >&2; exit 1; }
        # the link must be ours alone: any other stream would be in the interface counters, and we in its results
        [[ -n "${LOOPBACK:-}" ]] || r "${h}" 'a=$(cat /sys/class/net/eth0/statistics/tx_packets /sys/class/net/eth0/statistics/rx_packets | paste -sd+ | bc); sleep 1; b=$(cat /sys/class/net/eth0/statistics/tx_packets /sys/class/net/eth0/statistics/rx_packets | paste -sd+ | bc); echo "eth0 packets in 1 s: $((b - a))"; test $((b - a)) -le 20' \
            || { echo "${h}: eth0 is carrying other traffic: not starting" >&2; exit 1; }
        # DATA_SCHEMA.md: no run starts on a board at 68 C or more; CAMPAIGN.md: several partitions from 62 C or less
        # (START_BELOW_C and START_BELOW_PARTITIONS_C, each also per board as <NAME>_<host>)
        if [[ "${PARTITIONS}" == 1 ]]; then below="$(limit_c START_BELOW_C "${h}" 68)"; else below="$(limit_c START_BELOW_PARTITIONS_C "${h}" 62.1)"; fi
        if ! temp="$(r "${h}" "for i in \$(seq ${tries}); do t=\$(vcgencmd measure_temp | tr -dc 0-9.); awk -v t=\$t 'BEGIN {exit !(t < ${below})}' && break; [ \$i = ${tries} ] || sleep 5; done; echo \$t; awk -v t=\$t 'BEGIN {exit !(t < ${below})}'")"; then
            [[ "${ALLOW_HOT_DRYRUN:-}" == 1 && "${DRY_RUN:-1}" != 0 ]] || { echo "${h}: ${temp} C, not below ${below} C: run SKIPPED" >&2; exit 75; }
            HOT+="${h}: a step started at ${temp} C, not below ${below} C, under ALLOW_HOT_DRYRUN=1 (functional dry run only)"$'\n'
        fi
    done
}

# CAMPAIGN.md validity gates, read before and after a run
gate() {
    r "$1" "{ echo \"== $2 \$(date -Is)\"; echo throttled=\$(vcgencmd get_throttled); echo temp=\$(vcgencmd measure_temp); echo eee=\$(sudo -n /usr/sbin/ethtool --show-eee eth0 | grep 'EEE status' | tr -s ' '); echo eth0_addr=\$(ip -4 -br addr show dev eth0 | awk '{print \$3}'); echo carrier_changes=\$(cat /sys/class/net/eth0/carrier_changes); echo eth0_rx_errors=\$(cat /sys/class/net/eth0/statistics/rx_errors); echo rbuf_ovflow_cnt=\$(sudo -n /usr/sbin/ethtool -S eth0 | awk '/rbuf_ovflow_cnt/ {print \$2}'); echo tcp_retrans_segs=\$(awk '/^Tcp:/ && \$2 ~ /^[0-9]/ {print \$13}' /proc/net/snmp); echo tcp_timeouts=\$(awk '/^TcpExt:/ {if (!h) {for (i = 1; i <= NF; i++) if (\$i == \"TCPTimeouts\") c = i; h = 1} else print \$c}' /proc/net/netstat); echo tcp_loss_probes=\$(awk '/^TcpExt:/ {if (!h) {for (i = 1; i <= NF; i++) if (\$i == \"TCPLossProbes\") c = i; h = 1} else print \$c}' /proc/net/netstat); echo tcp_loss_probe_recovery=\$(awk '/^TcpExt:/ {if (!h) {for (i = 1; i <= NF; i++) if (\$i == \"TCPLossProbeRecovery\") c = i; h = 1} else print \$c}' /proc/net/netstat); echo tcp_fast_retrans=\$(awk '/^TcpExt:/ {if (!h) {for (i = 1; i <= NF; i++) if (\$i == \"TCPFastRetrans\") c = i; h = 1} else print \$c}' /proc/net/netstat); echo tcp_slow_start_retrans=\$(awk '/^TcpExt:/ {if (!h) {for (i = 1; i <= NF; i++) if (\$i == \"TCPSlowStartRetrans\") c = i; h = 1} else print \$c}' /proc/net/netstat); echo governor=\$(cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort -u | tr '\n' ' '); echo freq_khz=\$(cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq | tr '\n' ' '); echo loadavg=\$(cat /proc/loadavg); echo mem_available_kb=\$(awk '/MemAvailable/ {print \$2}' /proc/meminfo); echo cpu_busy_total_jiffies=\$(awk '/^cpu[0-9]/ {printf \"%s=%d/%d \", \$1, \$2 + \$3 + \$4 + \$7 + \$8 + \$9, \$2 + \$3 + \$4 + \$5 + \$6 + \$7 + \$8 + \$9}' /proc/stat); echo busiest=\$(ps -eo pcpu,psr,comm --sort=-pcpu | awk 'NR > 1 && \$3 != \"ps\" && ++n <= 5' | tr -s ' ' | tr '\n' ';'); echo others_busy=\$(ps -eo pcpu,comm,args --sort=-pcpu | awk 'NR > 1 && \$1 > 20 && \$2 != \"ps\" && \$0 !~ /pqc-secoc-rev1-bench[/]/ {printf \"%s:%s \", \$2, \$1}'); } >> $3/gates_$1.txt; ${PI_DIR}/Autosar_SecOC/scripts/capture_env.sh $2 $3/env_$1.txt ${LIBOQS} ${COMMIT} > /dev/null 2>&1 || true"
}

gates() { local h; for h in $(hosts); do gate "${h}" "$1" "$2"; done; }

# a run is excluded when a gate value that must not move has moved, or the board throttled
gate_verdict() {
    local out="$1" f k before after counts
    for f in $(find "${out}" -maxdepth 1 -name 'gates_*.txt'); do
        for k in throttled carrier_changes eth0_addr rbuf_ovflow_cnt eth0_rx_errors; do
            before="$(grep "^${k}=" "${f}" | head -1)"; after="$(grep "^${k}=" "${f}" | tail -1)"
            [[ "${before}" == "${after}" ]] || echo "$(basename "${f}"): ${before} -> ${after}" >> "${out}/EXCLUDED"
        done
        # The host-wide TCP counters also count wlan0 (the SSH sessions) and failed connection attempts:
        # recorded and printed, not judged (CAMPAIGN.md).
        for k in tcp_retrans_segs tcp_timeouts tcp_loss_probes tcp_loss_probe_recovery tcp_fast_retrans tcp_slow_start_retrans; do
            before="$(grep "^${k}=" "${f}" | head -1)"; after="$(grep "^${k}=" "${f}" | tail -1)"
            [[ "${before}" == "${after}" ]] || echo "$(basename "${f}"): ${before} -> ${after} (host-wide, first to last snapshot of the run)" >> "${out}/NOTE_tcp_host_wide"
        done
        # DATA_SCHEMA.md: a currently-active throttling bit (bits 0-3) excludes the run; a change is caught above.
        # Sticky bits alone (since boot) do not, but they are reported: CAMPAIGN.md wants 0x0 for campaign runs.
        for k in $(grep '^throttled=' "${f}" | sed 's/.*=//' | sort -u); do
            (( (k & 0xF) == 0 )) || echo "$(basename "${f}"): throttling active (get_throttled ${k})" >> "${out}/EXCLUDED"
            (( k == 0 )) || echo "$(basename "${f}"): get_throttled ${k} is not 0x0 (bits from earlier since boot)" >> "${out}/NOTE_throttled_since_boot"
        done
        # CAMPAIGN.md: a run during which the board reached 78 C is excluded (STOP_AT_C, also per board)
        k="$(grep '^temp=' "${f}" | tr -dc '0-9.\n' | sort -n | tail -1)"; before="$(basename "${f}" .txt)"
        awk -v t="${k}" -v lim="$(limit_c STOP_AT_C "${before#gates_}" 78)" 'BEGIN {exit !(t >= lim)}' && echo "$(basename "${f}"): the board reached ${k} C" >> "${out}/EXCLUDED"
        # CAMPAIGN.md: nothing else running. A process above 20 % CPU that is not from this tree is someone else's work.
        ! grep -q '^others_busy=.' "${f}" || echo "$(basename "${f}"): other busy processes: $(grep -h '^others_busy=.' "${f}" | sort -u | tr '\n' ' ')" >> "${out}/EXCLUDED"
    done
    cat "${out}"/*/temp_limit_*.txt >> "${out}/EXCLUDED" 2> /dev/null || true
    [[ -s "${out}/EXCLUDED" ]] || rm -f "${out}/EXCLUDED"
    # The transmitter's own connection (footer of periodic_tx*.csv; CAMPAIGN.md): retransmissions and time-outs
    # inside the measured window are reported, never a reason to exclude (that would select on the outcome).
    # What excludes a file is a connection made again inside the window.
    for f in "${out}"/*/periodic_tx*.csv; do
        [[ -e "${f}" ]] || continue
        counts="$(grep -h -E '^# tcp_(total_retrans|dsack_dups|total_rto)_in_window=' "${f}" | tr -d '# ' | xargs)"
        [[ -z "${counts}" || ! "${counts}" =~ =[1-9] ]] || echo "${f#"${out}"/}: ${counts}" >> "${out}/NOTE_tcp_retrans"
        # CAMPAIGN.md: the only loss of a valid file is jobs_dropped_at_release; a job given up without a
        # confirmation (after 2,000 ticks or four cycles) lets its SecOC row take the next PDU
        before="$(grep -h '^# jobs_started=' "${f}" | sed 's/.*=//')"; after="$(grep -h '^# jobs_confirmed=' "${f}" | sed 's/.*=//')"
        [[ "${before}" == "${after}" ]] || echo "${f#"${out}"/}: jobs_started=${before} differs from jobs_confirmed=${after}: a job was given up without a confirmation" >> "${out}/EXCLUDED"
        before="$(grep -h '^# tcp_connections_at_first_release=' "${f}" | sed 's/.*=//')"; after="$(grep -h '^# tcp_connections_at_end=' "${f}" | sed 's/.*=//')"
        [[ "${before}" == "${after}" ]] || echo "${f#"${out}"/}: the TCP connection was made again inside the measured window (connections ${before} -> ${after})" >> "${out}/EXCLUDED"
    done
    # CAMPAIGN.md: a harness file whose header does not say tcp_nodelay=1 (read back on its own connection) is invalid
    # (attack.csv: the join script's verdict over both ends, the gateway receiver's own read-back lines included)
    for f in "${out}"/*/periodic_tx*.csv "${out}"/*/periodic_rx*.csv "${out}"/handshake/handshake_tx.csv "${out}"/handshake/handshake_rx.csv "${out}"/attack/attack.csv; do
        [[ -e "${f}" ]] || continue
        k="$(grep -h -m1 '^# tcp_nodelay=' "${f}" | sed 's/.*=//')"
        [[ "${k}" == 1 ]] || echo "${f#"${out}"/}: tcp_nodelay=${k:-missing}, must be 1 (with Nagle's algorithm the kernel holds PDUs back)" >> "${out}/EXCLUDED"
    done
    if [[ -e "${out}/EXCLUDED" ]]; then echo "validity gates FAILED:"; cat "${out}/EXCLUDED"; else echo "validity gates passed"; fi
}

new_run() {
    OUT="${ROOT}/runs/$1"; RD="/dev/shm/bench/$1"
    [[ ! -e "${OUT}" ]] || { echo "${OUT} exists; choose another run_id" >&2; exit 2; }
    lock_boards "run_bench_net.sh $2 $1"
    free_or_die
    mkdir -p "${OUT}/$2"
    if [[ -z "${LOOPBACK:-}" ]]; then
        local speed="${LINK_SPEED:-$(ssh -F "${PI_SSH_CFG}" "pi-${TX_HOST}" cat /sys/class/net/eth0/speed)}"
        [[ "${speed}" == 100 || "${speed}" == 1000 ]] || speed=100     # no link yet (after a boot it reads -1): the campaign's speed
        {
            # the negotiated speed is the best mode both ends advertise: the first board only changes what it
            # advertises (it cannot reach 1000 while the other offers 100 only), the second is brought up, then the first
            ssh -F "${PI_SSH_CFG}" "pi-${TX_HOST}" "${PI_DIR}/Autosar_SecOC/scripts/link_eth0.sh speed ${speed}" &&
            ssh -F "${PI_SSH_CFG}" "pi-${RX_HOST}" "${PI_DIR}/Autosar_SecOC/scripts/link_eth0.sh up ${RX_IP} ${speed}" &&
            ssh -F "${PI_SSH_CFG}" "pi-${TX_HOST}" "${PI_DIR}/Autosar_SecOC/scripts/link_eth0.sh up ${TX_IP} ${speed}; cat /sys/class/net/eth0/speed /sys/class/net/eth0/duplex; ping -c 20 -i 0.2 -I eth0 ${RX_IP} | tail -2 | tee /dev/stderr | grep -q ' 0% packet loss'"
        } > "${OUT}/link.txt" 2>&1 || { echo "link step failed (${OUT}/link.txt): not starting" >&2; exit 1; }
    fi
    CMD_LOG="${OUT}/$2/cmd.txt"
    shift 2
    echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) commit ${COMMIT}: scripts/run_bench_net.sh $* (LOOPBACK=${LOOPBACK:-} CORE=${CORE} PORT=${PORT})" > "${CMD_LOG}"
    [[ "${DRY_RUN:-1}" == 0 ]] || echo "DRY RUN - harness check only; nothing in this directory may be quoted as a result." > "${OUT}/DRY_RUN"
    local h; for h in $(hosts); do r "${h}" "rm -rf ${RD}; mkdir -p ${RD}"; done
}

# Several partitions heat a board within minutes. While the harness processes of a step run, one line
# per second per board goes to temp_<host><tag>.csv and at STOP_AT_C the transmitters get SIGTERM and
# end the step cleanly (the receivers follow when the connections close). On the transmitter's board
# that loop is part of the detached launcher (transfer); this is the receiver's board in a two-node
# run: its one session during the step.
watch_temp_rx() {
    (
        rc=0
        ssh -F "${PI_SSH_CFG}" "pi-${RX_HOST}" "taskset -cp 0 \$\$ > /dev/null; echo t_unix_s,temp_mC > ${RD}/temp_${RX_HOST}$1.csv; while pgrep -x bench_net_rx > /dev/null; do t=\$(cat /sys/class/thermal/thermal_zone0/temp); echo \"\$(date +%s),\$t\" >> ${RD}/temp_${RX_HOST}$1.csv; [ \$t -lt $(( $(limit_c STOP_AT_C "${RX_HOST}" 78) * 1000 )) ] || exit 3; sleep 1; done" || rc=$?
        if [[ "${rc}" == 3 ]]; then
            echo "${RX_HOST}: reached $(limit_c STOP_AT_C "${RX_HOST}" 78) C during step '$1': the transmitters were told to end it" >> "${OUT}/EXCLUDED"
            ssh -F "${PI_SSH_CFG}" "pi-${TX_HOST}" "pkill -TERM -x bench_net_tx" || true
        fi
    ) &
}

# transfer <rx options> <tx options> [listen port of the receiver] [port the transmitter connects to] [address it connects to]
# Runs PARTITIONS transmitter/receiver pairs side by side (one is the normal case). In the option
# strings @P@ becomes the file suffix of the partition ("" for a single pair, _p<i> otherwise).
transfer() {
    local rxopts="$1" txopts="$2" listen="${3:-${PORT}}" connect="${4:-${PORT}}" caddr="${5:-${RX_IP}}" i sfx ctx crx hsdir rxcmd="" launch rc tries=0
    local tag="${STEP_TAG:-}" limit=$(( $(limit_c STOP_AT_C "${TX_HOST}" 78) * 1000 ))
    [[ -n "${NO_RX:-}${PROXY_UP:-}" ]] || free_or_die     # (our own gateway receiver or proxy is already running)
    [[ -z "${BG_ON:-}" ]] || bg_start                      # behind the check for a quiet link, and before the probe:
    [[ -z "${PROBE_ON:-}" ]] || probe_start                # both are traffic on it, and the probe's anchors are taken under the load
    # the launcher of the transmitters: started detached on their board, it writes tx.rc when all have ended
    launch="cd ${RD}"$'\n'"${LIMITS}"$'\n'"pids=\"\""$'\n'
    for i in $(seq 0 $((PARTITIONS - 1))); do
        sfx=""; ctx="${CORE_TX}"; crx="${CORE_RX}"
        if [[ "${PARTITIONS}" != 1 ]]; then sfx="_p${i}"; ctx="${CORE_LIST[$i]}"; crx="${CORE_LIST[$i]}"; fi
        # one handshake record per host and directory (the toolkit keys it by host): a ladder step or a
        # partition gets its own subdirectory handshake_<step>[_p<i>]/
        hsdir="${RD}"; [[ -z "${tag}${sfx}" ]] || hsdir="${RD}/handshake${tag}${sfx}"
        rxcmd+="mkdir -p ${hsdir}; (nohup ${BIN}/bench_net_rx --listen $((listen + i)) --peer ${TX_IP} --key-dir ${PI_DIR}/keys/rx --cpu ${crx} --partition ${i} --partitions ${PARTITIONS} ${MF} --handshake-out ${hsdir}/handshake_rx.csv ${rxopts//@P@/${sfx}} > rx${sfx}.log 2>&1 < /dev/null &); "
        if [[ -n "${TX_CMD:-}" ]]; then     # a transmitter that is not a harness (the gateway binary): its own command line
            launch+="${TX_CMD} > tx${sfx}.log 2>&1 < /dev/null & pids=\"\$pids \$!\""$'\n'
            continue
        fi
        launch+="mkdir -p ${hsdir}"$'\n'"${TX_WRAP:-}${BIN}/${TX_BIN:-bench_net_tx} --peer ${caddr}:$((connect + i)) --key-dir ${PI_DIR}/keys/tx --cpu ${ctx} --partition ${i} --partitions ${PARTITIONS} ${MF} --handshake-out ${hsdir}/handshake_tx.csv ${txopts//@P@/${sfx}} > tx${sfx}.log 2>&1 < /dev/null & pids=\"\$pids \$!\""$'\n'
    done
    if [[ "${PARTITIONS}" != 1 ]]; then
        launch+="(echo t_unix_s,temp_mC > temp_${TX_HOST}${tag}.csv; while pgrep -x bench_net_tx > /dev/null; do t=\$(cat /sys/class/thermal/thermal_zone0/temp); echo \"\$(date +%s),\$t\" >> temp_${TX_HOST}${tag}.csv; [ \$t -lt ${limit} ] || { echo \"${TX_HOST}: reached $(( limit / 1000 )) C during step '${tag}': the transmitters were told to end it\" > temp_limit_${TX_HOST}${tag}.txt; pkill -TERM -x bench_net_tx; break; }; sleep 1; done) &"$'\n'
    fi
    launch+="rc=0; for p in \$pids; do wait \$p || rc=1; done"$'\n'"echo \$rc > tx.rc"$'\n'
    printf '[%s] launch_tx.sh:\n%s' "${TX_HOST}" "${launch}" >> "${CMD_LOG}"
    ssh -F "${PI_SSH_CFG}" "pi-${TX_HOST}" "cat > ${RD}/launch_tx.sh; rm -f ${RD}/tx.rc ${RD}/tx.started" <<< "${launch}"
    [[ -z "${NO_RX:-}" ]] && r "${RX_HOST}" "cd ${RD} && ${LIMITS}; ${rxcmd} for i in \$(seq 100); do [ \$(grep -l 'listening on port' rx*.log 2>/dev/null | wc -l) -ge ${PARTITIONS} ] && break; sleep 0.1; done; [ \$(grep -l 'listening on port' rx*.log | wc -l) -ge ${PARTITIONS} ]"
    [[ "${PARTITIONS}" == 1 || "${TX_HOST}" == "${RX_HOST}" ]] || watch_temp_rx "${tag}"
    # The one session on the transmitter's board: start the launcher detached, then block on its result.
    # If the session is lost the run goes on; the session is made again and only waits.
    while :; do
        rc=0
        r "${TX_HOST}" "taskset -cp 0 \$\$ > /dev/null; cd ${RD} && { [ -e tx.started ] || { touch tx.started; (nohup setsid bash launch_tx.sh > launch_tx.log 2>&1 < /dev/null &); }; }; while [ ! -e tx.rc ]; do sleep ${WAIT_SLEEP:-2}; done; tail -qn 1 tx*.log; exit \$(cat tx.rc)" || rc=$?
        [[ "${rc}" == 255 ]] && (( ++tries < 20 )) || break
        echo "the waiting session to ${TX_HOST} was lost; the run goes on on the board, reconnecting in 15 s" >&2
        sleep 15
    done
    [[ "${rc}" == 0 ]] || FAILED=1
    [[ -z "${NO_RX:-}" ]] && r "${RX_HOST}" "for i in \$(seq 100); do pgrep -x bench_net_rx > /dev/null || break; sleep 0.1; done; if pgrep -x bench_net_rx > /dev/null; then echo 'receiver still running: SIGTERM'; pkill -TERM -x bench_net_rx; sleep 1; fi; tail -qn 1 ${RD}/rx*.log"
    wait    # the receiver board's temperature watcher ends with the receivers
    return 0
}

# The attack and handshake-test runs: the gateway receiver (full BSW start-up), and the proxy in front of it.
gateway_rx_start() {
    GW_STARTED=1
    # receiving side: the gateway binary itself; its application log (App_Rx) is the outcome record
    r "${RX_HOST}" "cd ${RD} && (SECOC_APP_CSV=${RD}/app_rx.csv SECOC_APP_PAYLOAD_CSV=${RD}/rx_payload.csv SECOC_APP_HS_CSV=${RD}/handshake_gw_rx.csv SECOC_APP_IDLE_EXIT_MS=5000 SECOC_APP_COUNT=${GW_RX_COUNT:-0} ${PROFILE:+SECOC_APP_PROFILE=${PROFILE}} nohup timeout 600 taskset -c ${CORE_RX} ${PI_DIR}/build-gw-rx/SecOC > gw_rx.stdout 2>&1 < /dev/null &); for i in \$(seq 100); do grep -q 'Program entered RUN state' gw_rx.stdout 2>/dev/null && break; sleep 0.2; done; grep -a -E 'PQC-SecOC commit|Role|RUN state' gw_rx.stdout | tee gw_rx_banner.txt | tail -3; grep -q 'RUN state' gw_rx_banner.txt"
    # another receiver holding the port would take the stream instead (seen once: a foreign SecOC, 0 rows in our log)
    r "${RX_HOST}" "pid=\$(ss -ltnpH 'sport = :${GW_PORT}' | sed -n 's/.*pid=\\([0-9]*\\).*/\\1/p' | head -1); [ \"\$(readlink /proc/\$pid/exe)\" = \"${PI_DIR}/build-gw-rx/SecOC\" ] || { echo 'port ${GW_PORT} is not held by the gateway receiver of this run'; pkill -f '${PI_DIR#\$HOME/}/build-gw-rx/SecO[C]'; exit 1; }"
}

gateway_rx_stop() {
    GW_STARTED=""
    # the gateway receiver leaves by itself 5 s after the last PDU; only our own process is ever signalled
    r "${RX_HOST}" "for i in \$(seq 100); do pgrep -f '${PI_DIR#\$HOME/}/build-gw-rx/SecO[C]' > /dev/null || break; sleep 0.2; done; pkill -f '${PI_DIR#\$HOME/}/build-gw-rx/SecO[C]' && echo 'gateway receiver had to be stopped'; grep -a -E 'App_Rx\\] (done|WARN)|App_Hs\\]' ${RD}/gw_rx.stdout | tee -a ${RD}/gw_rx_banner.txt | tail -40; rm -f ${RD}/gw_rx.stdout"
}

proxy_start() {     # <vector and handshake-edit options of attack_proxy.py>; PROXY_OPTS adds further ones
    # (--record FILE, --session-file FILE, --hs-inject ..., --hs-record PREFIX; paths are on the transmitter's board)
    # The proxy sits on the transmitter's board: transmitter -> proxy (127.0.0.1:PORT+1) -> link -> gateway
    # receiver (GW_PORT). What it sends arrives from the transmitter's address, the only one the receiver's
    # SoAd accepts (the gateway's, or the harness receiver's with ORACLE=harness).
    r "${TX_HOST}" "cd ${RD} && (nohup ${PROXY_WRAP:-}python3 ${PI_DIR}/Autosar_SecOC/bench/attack_proxy.py --listen $((PORT + 1)) --connect ${RX_IP}:${DOWN_PORT} --log ${RD}/proxy_log.csv $1 --forge ${BIN}/bench_hs_forge ${PROXY_OPTS:-} --seed 20261123 ${LAYOUT:+--layout ${LAYOUT}} > proxy.log 2>&1 < /dev/null &); for i in \$(seq 50); do grep -q 'proxy listening' proxy.log 2>/dev/null && break; sleep 0.1; done; grep -q 'proxy listening' proxy.log"
}

# RELAY_NETNS=1: the transmitter's own network stack. Namespace txns with veth-tx (NS_TX/30) and nothing else;
# veth-atk (NS_ATK/30) stays in the root namespace, where the proxy is. What a killed driver left of these names
# was dealt with before the start (free_or_die); the driver calls the namespace its own, and removes it on every
# way out, only after it has seen that none is there. The run does not start when the namespace can reach the
# receiver or the two ends of the pair cannot reach each other.
netns_up() {
    r "${TX_HOST}" "! ip netns list | grep -qw txns && ! ip link show veth-atk > /dev/null 2>&1" \
        || { echo "${TX_HOST}: a namespace txns or a veth-atk is there that this run did not make: not touching it" >&2; exit 1; }
    NETNS_UP=1
    r "${TX_HOST}" "set -e; cd ${RD}; sudo -n ip netns add txns; sudo -n ip link add veth-atk type veth peer name veth-tx netns txns; sudo -n ip addr add ${NS_ATK}/30 dev veth-atk; sudo -n ip link set veth-atk up; sudo -n ip netns exec txns ip addr add ${NS_TX}/30 dev veth-tx; sudo -n ip netns exec txns ip link set veth-tx up; sudo -n ip netns exec txns ip link set lo up; { echo \"== before the run \$(date -Is), transmitter's board \$(hostname)\"; if out=\$(sudo -n ip netns exec txns ip route get ${RX_IP} 2>&1); then echo \"route_check=REACHABLE: \$out\"; else echo \"route_check=fails (ip netns exec txns ip route get ${RX_IP}: \$out)\"; fi; echo \"namespace_routes=[\$(sudo -n ip netns exec txns ip route | tr '\\n' ';')]\"; echo \"namespace_addresses=[\$(sudo -n ip netns exec txns ip -br -4 addr | tr -s ' ' | tr '\\n' ';')]\"; echo '-- ip -d link show veth-tx (in the namespace txns)'; sudo -n ip netns exec txns ip -d link show veth-tx; echo '-- ip -d link show veth-atk (root namespace)'; ip -d link show veth-atk; echo \"root_address_of_pair=\$(ip -br -4 addr show dev veth-atk | tr -s ' ')\"; echo \"root_route_to_receiver=\$(ip route get ${RX_IP} | head -1)\"; echo \"default_route=\$(ip route show default | head -1)\"; echo \"ip_forward=\$(cat /proc/sys/net/ipv4/ip_forward)\"; echo \"networkmanager_state_of_veth-atk=\$(nmcli -t -f DEVICE,STATE device status 2> /dev/null | sed -n 's/^veth-atk://p')\"; echo \"pair_ping=\$(sudo -n ip netns exec txns ping -c 3 -i 0.2 -W 1 ${NS_ATK} | grep 'packets transmitted')\"; } > netns_check.txt 2>&1; cat netns_check.txt | grep -E '^(route_check|pair_ping)='; grep -q '^route_check=fails' netns_check.txt && grep -q ' 0% packet loss' netns_check.txt"
}

netns_down() {
    r "${TX_HOST}" "sudo -n ip netns del txns 2> /dev/null; sudo -n ip link del veth-atk 2> /dev/null; gone=yes; ip netns list | grep -qw txns && gone=no; ip link show veth-atk > /dev/null 2>&1 && gone=no; [ ! -d ${RD} ] || { echo \"== after the run \$(date -Is)\"; echo \"gone_after_run=\$gone (namespaces: [\$(ip netns list | tr '\\n' ' ')], veth devices: \$(ip -br link | grep -c veth))\"; echo \"default_route=\$(ip route show default | head -1)\"; echo \"eth0=\$(ip -br -4 addr show dev eth0 | tr -s ' ')\"; } >> ${RD}/netns_check.txt; [ \$gone = yes ]" \
        || echo "${TX_HOST}: the namespace txns or veth-atk could not be removed: sudo ip netns del txns; sudo ip link del veth-atk" >&2
    NETNS_UP=""
}

# The clock probe of E9 (bench_clock_probe.c): server on the receiver's board, client on the transmitter's,
# both on core PROBE_CPU. Each also samples its board's two clocks every 5 ms (probe format 2): the client writes
# clock_probe.csv and clock_map_a.csv, the server clock_map_b.csv; a reader carries the PDU stamps, which are
# CLOCK_MONOTONIC, onto the raw clocks with the two maps. An anchor of the offset track is the best exchange of a window of 5 s, and the run
# needs two before its first release and two behind its last delivery (the first and the last anchor only
# delimit): the transmitter starts when two windows are over, and the probe goes on for 12 s after the
# transmitter has ended and then to the end of its window. Both ends are under
# `timeout`: a probe that the driver lost (the measuring workstation asleep, the driver killed) ends by itself after RUN_LIMIT.
probe_start() {
    PROBE_STARTED=1
    r "${RX_HOST}" "cd ${RD} && (nohup timeout -s TERM ${RUN_LIMIT} ${BIN}/bench_clock_probe --server --bind ${RX_IP} --port ${PROBE_PORT} --cpu ${PROBE_CPU} --map-out ${RD}/clock_map_b.csv > probe_server.log 2>&1 < /dev/null &); for i in \$(seq 50); do grep -q 'clock probe server' probe_server.log 2>/dev/null && break; sleep 0.1; done; grep -q 'clock probe server' probe_server.log"
    r "${TX_HOST}" "cd ${RD} && (nohup timeout -s TERM ${RUN_LIMIT} ${BIN}/bench_clock_probe --client --peer ${RX_IP} --port ${PROBE_PORT} --cpu ${PROBE_CPU} --interval-ms ${PROBE_INTERVAL_MS} --out ${RD}/clock_probe.csv --map-out ${RD}/clock_map_a.csv > probe_client.log 2>&1 < /dev/null &); for i in \$(seq 50); do grep -q 'first exchange completed' probe_client.log 2>/dev/null && break; sleep 0.1; done; grep -q 'first exchange completed' probe_client.log && sleep ${PROBE_LEAD_IN:-12}"
}

probe_stop() {      # the client first: told to end, it completes its window of 5 s (up to 5 s more) and writes its two files;
                    # each end is waited for up to PROBE_WAIT s (the wait ends when the process has gone), see probe_end
    r "${TX_HOST}" "taskset -cp 0 \$\$ > /dev/null; sleep ${PROBE_LEAD_OUT:-12}; $(probe_end "${PI_REL}/build-bench/${PROBE} --client" 'the probe client (bench_clock_probe --client)'); tail -n 1 ${RD}/probe_client.log"
    # the server writes its clock map when it is told to end: waited for, so that the copy finds the whole file
    r "${RX_HOST}" "$(probe_end "${PI_REL}/build-bench/${PROBE} --server" 'the probe server (bench_clock_probe --server)'); tail -n 1 ${RD}/probe_server.log"
    PROBE_STARTED=""
}

# Unrelated traffic on the link (bg_traffic.py): sink on the receiver's board, source on the transmitter's, both
# on core BG_CPU; both end by themselves after RUN_LIMIT. The source is told to end, the sink ends with the connection.
bg_start() {
    local py="python3 ${PI_DIR}/Autosar_SecOC/bench/bg_traffic.py"
    BG_STARTED=1
    r "${RX_HOST}" "cd ${RD} && (nohup ${py} --sink --bind ${RX_IP} --port ${BG_PORT} --peer ${TX_IP} --cpu ${BG_CPU} --max-seconds ${RUN_LIMIT} --out ${RD}/bg_sink.txt > bg_sink.log 2>&1 < /dev/null &); for i in \$(seq 50); do grep -q listening bg_sink.log 2>/dev/null && break; sleep 0.1; done; grep -q listening bg_sink.log"
    r "${TX_HOST}" "cd ${RD} && (nohup ${py} --source --connect ${RX_IP}:${BG_PORT} --mbit ${BG_MBIT} --cpu ${BG_CPU} --max-seconds ${RUN_LIMIT} --out ${RD}/bg_source.txt > bg_source.log 2>&1 < /dev/null &); for i in \$(seq 50); do grep -q connected bg_source.log 2>/dev/null && break; sleep 0.1; done; grep -q connected bg_source.log && sleep 2"
}

bg_stop() {
    local mine="${PI_REL}/Autosar_SecOC/bench/${BG}"
    r "${TX_HOST}" "pkill -TERM -f '${mine} --source'; for i in \$(seq 50); do pgrep -f '${mine} --source' > /dev/null || break; sleep 0.1; done; tail -n 1 ${RD}/bg_source.log"
    r "${RX_HOST}" "for i in \$(seq 30); do pgrep -f '${mine} --sink' > /dev/null || break; sleep 0.1; done; pkill -TERM -f '${mine} --sink'; sleep 0.3; tail -n 1 ${RD}/bg_sink.log"
    BG_STARTED=""
}

collect() {
    local h
    for h in $(hosts); do
        rsync -az -e "ssh -F ${PI_SSH_CFG}" --include 'handshake_*/' --include 'r[0-9][0-9][0-9]/' --include '*.csv' --include '*.log' --include '*.txt' --exclude '*' "pi-${h}:${RD}/" "${OUT}/$1/"
        r "${h}" "rm -rf ${RD}"
    done
    mv "${OUT}/$1"/env_*.txt "${OUT}/$1"/gates_*.txt "${OUT}/" 2>/dev/null || true
}

finish() {
    local rc=0 commits
    [[ -z "${HOT}" ]] || printf '%s' "${HOT}" | sort -u > "${OUT}/NOTE_hot_start"
    # CAMPAIGN.md: one commit on both boards
    # (compared on the first 12 hex digits, clock_probe.csv carries that many, and on what follows the hash: "-dirty")
    commits="$({ grep -h '^# commit=' "${OUT}"/*/*.csv "${OUT}"/*/r[0-9][0-9][0-9]/*.csv 2> /dev/null || true; } | sed -E 's/^# commit=([0-9a-f]{12})[0-9a-f]*/\1/' | sort -u)"
    [[ "$(echo "${commits}" | wc -l)" -eq 1 ]] || echo "the CSV files carry different commits: $(echo ${commits})" >> "${OUT}/EXCLUDED"
    # the two ends of a run must name the same session: the harness receiver in its header, the gateway
    # receiver in its "keys installed" line
    local f rxf a b
    for f in "${OUT}"/*/periodic_tx*.csv; do
        [[ -e "${f}" ]] || continue
        a="$(grep -h '^# session_id=' "${f}" | cut -d= -f2)"
        rxf="${f/periodic_tx/periodic_rx}"; b=""
        if [[ -e "${rxf}" ]]; then b="$(grep -h '^# session_id=' "${rxf}" | cut -d= -f2)"
        elif [[ -e "$(dirname "${f}")/gw_rx_banner.txt" ]]; then b="$(grep -a -o 'sid [0-9a-f]*' "$(dirname "${f}")/gw_rx_banner.txt" | tail -1 | cut -d' ' -f2)"
        else continue; fi
        echo "$(basename "${f}"): session ${a:-none} at the transmitter, ${b:-none} at the receiver" >> "${OUT}/sessions.txt"
        # a pair of harness files must name one profile: the receiver's profile decides the stream index of a MAC PDU
        [[ ! -e "${rxf}" || "$(grep -h -m1 '^# profile=' "${f}")" == "$(grep -h -m1 '^# profile=' "${rxf}")" ]] \
            || echo "$(basename "${f}"): transmitter and receiver name different profiles ($(grep -h -m1 '^# profile=' "${f}") / $(grep -h -m1 '^# profile=' "${rxf}"))" >> "${OUT}/EXCLUDED"
        [[ "${a}" == "${b}" ]] || echo "$(basename "${f}"): transmitter and receiver name different sessions (${a:-none} / ${b:-none})" >> "${OUT}/EXCLUDED"
    done
    # a timing run has its handshake before the measured interval and none inside it
    if [[ ! -d "${OUT}/attack" && ! -d "${OUT}/hstest" && ! -d "${OUT}/handshake" ]]; then
        a="$(grep -l '^# hs_records_in_run=[1-9]' "${OUT}"/*/periodic_[tr]x*.csv 2> /dev/null | xargs -n 1 basename 2> /dev/null | xargs || true)"
        [[ -z "${a}" ]] || echo "a handshake attempt ended inside the measured interval: ${a}" >> "${OUT}/EXCLUDED"
    fi
    for f in "${OUT}"/*/handshake_tx*.csv "${OUT}"/*/handshake_*/handshake_tx.csv; do      # and the handshake records of both ends: as many ok attempts, the same last session
        rxf="${f/handshake_tx/handshake_rx}"
        [[ -e "${f}" && -e "${rxf}" ]] || continue
        a="$(grep -h '^# session_id=' "${f}" | cut -d= -f2) after $(grep -c ',ok,' "${f}") ok attempts"
        b="$(grep -h '^# session_id=' "${rxf}" | cut -d= -f2) after $(grep -c ',ok,' "${rxf}") ok attempts"
        echo "${f#"${OUT}"/}: initiator ${a}, responder ${b}" >> "${OUT}/sessions.txt"
        [[ "${a}" == "${b}" ]] || echo "${f#"${OUT}"/}: the handshake records of the two ends disagree (${a} / ${b})" >> "${OUT}/EXCLUDED"
    done
    gate_verdict "${OUT}"
    # E9: a run with the clock probe is judged for the latency across the boards by the rules of DATA_SCHEMA.md
    # (clock_probe.csv). A FAIL says the run is no E9 result; its periodic files stand as without the probe.
    if [[ -n "${PROBE_ON:-}" ]]; then      # (a probe file that was not collected fails here as an unusable one does)
        a="${OUT}/periodic"
        python3 -I "${ROOT}/Autosar_SecOC/bench/check_clock_probe.py" --run "${a}/clock_probe.csv" "${a}/periodic_tx.csv" "${a}/periodic_rx.csv" > "${OUT}/e9_check.txt" 2>&1 \
            || { rc=1; tail -1 "${OUT}/e9_check.txt" > "${OUT}/E9_INVALID"; }
        cat "${OUT}/e9_check.txt"
    fi
    if [[ -n "${BG_ON:-}" ]]; then      # the unrelated flow: what it carried, and whether it covered the run at its rate
        python3 -I "${ROOT}/Autosar_SecOC/bench/bg_traffic.py" --report "${OUT}/periodic/bg_source.txt" "${OUT}/periodic/bg_sink.txt" "${OUT}/periodic/periodic_tx.csv" > "${OUT}/background_traffic.txt" 2>&1 \
            || { rc=1; tail -1 "${OUT}/background_traffic.txt" > "${OUT}/BG_INVALID"; }
        grep -E '^(rate_|bytes_|verdict)' "${OUT}/background_traffic.txt" || true
    fi
    # (the probe's own files, clock_probe.csv, the two clock maps and those of the probe test, are judged by check_clock_probe.py)
    find "${OUT}" -name '*.csv' ! -name 'rx_payload*' ! -name 'proxy_log*' ! -name 'hs_edits*' ! -name 'app_rx*' ! -name 'app_tx*' ! -name 'temp_*' ! -name 'unused_*' \
        ! -name 'clock_probe*' ! -name 'clock_map_*' ! -name 'zero_*' ! -name 'pair_*' -print0 | sort -z \
        | xargs -0 python3 -I "${ROOT}/Autosar_SecOC/bench/check_csv.py" > "${OUT}/check.txt" 2>&1 || rc=1
    # ... and get their line in check.txt from it, in the same form (format, footers, counts), so that every csv has one
    find "${OUT}" \( -name 'clock_probe*.csv' -o -name 'clock_map_*.csv' -o -name 'zero_*.csv' -o -name 'pair_*.csv' \) -print0 | sort -z \
        | xargs -0 python3 -I "${ROOT}/Autosar_SecOC/bench/check_clock_probe.py" --form >> "${OUT}/check.txt" 2>&1 || rc=1
    tail -3 "${OUT}/check.txt"
    (cd "${OUT}" && find . -type f ! -name MANIFEST.sha256 | sort | xargs shasum -a 256 > MANIFEST.sha256)
    echo "run directory: ${OUT}"
    [[ "${FAILED}" == 0 ]] || echo "a transmitter run FAILED (see tx.log), the oracle of an hsneg test said REJECT (hsneg.txt), or a probe test said FAIL (probetest.txt)"
    return $(( rc | FAILED ))
}

case "${1:-}" in
build-gw-tx)
    # The gateway TRANSMITTER for the on-wire handshake tests, where the gateway binary is the initiator: a build
    # whose peer is the proxy on its own board (127.0.0.1, port PORT+1), with the identity of the harness
    # transmitter (keys/tx: the receiver gateway pins its public half). Not part of 'build' (which syncs the tree
    # and must have run): the transmitter's board has little disk, so the free space is looked at first.
    ! measured || exit 75
    lock_boards "run_bench_net.sh build-gw-tx (gateway transmitter for the handshake tests)"
    r "${TX_HOST}" "avail=\$(df --output=avail -m \$HOME | tail -1); echo \"free on ${TX_HOST}: \$avail MB\"; [ \$avail -ge ${GW_BUILD_MIN_FREE_MB:-200} ]" \
        || { echo "less than ${GW_BUILD_MIN_FREE_MB:-200} MB free on ${TX_HOST}: the gateway transmitter is not built" >&2; exit 1; }
    r "${TX_HOST}" "cd ${PI_DIR} && LIBOQS_ROOT=${LIBOQS} SECOC_GIT_COMMIT=${COMMIT} SECOC_PORT=$((PORT + 1)) taskset -c 0-2 nice -n 10 Autosar_SecOC/scripts/build_gateway.sh tx ${TX_IP} 127.0.0.1 ${PI_DIR}/keys/tx ${PI_DIR}/build-gw-tx | tail -1 && sha256sum build-gw-tx/SecOC && echo \"build-gw-tx: \$(du -sm build-gw-tx | cut -f1) MB\""
    unlock_boards
    ;;

build)
    # one job at a time on a board: the build takes the board locks too (cores 0-2, low priority), and it
    # never runs next to a campaign measurement
    ! measured || exit 75
    lock_boards "run_bench_net.sh build (sync, build, key exchange)"
    for H in $(hosts); do
        r "${H}" "${MARKER}" || { echo "${H}: MEASURING marker present: not building" >&2; exit 1; }
    done
    for H in $(hosts); do
        ssh -F "${PI_SSH_CFG}" "pi-${H}" "mkdir -p ${PI_DIR}"
        rsync -az --delete -e "ssh -F ${PI_SSH_CFG}" --exclude '.git' "${ROOT}/Autosar_SecOC" "pi-${H}:${PI_REL}/"
        TARGETS="bench_keygen bench_clock_probe bench_verify_only"
        [[ "${H}" != "${TX_HOST}" ]] || TARGETS="${TARGETS} bench_net_tx bench_handshake bench_hs_forge"
        [[ "${H}" != "${RX_HOST}" ]] || TARGETS="${TARGETS} bench_net_rx"
        r "${H}" "cd ${PI_DIR} && cmake -S Autosar_SecOC/bench -B build-bench -G Ninja -DCMAKE_BUILD_TYPE=Release -DLIBOQS_ROOT=${LIBOQS} | grep 'bench:' && { taskset -c 0-2 nice -n 10 ninja -j2 -C build-bench ${TARGETS} > build-bench.log 2>&1; rc=\$?; tail -1 build-bench.log; echo \"compiler warnings in build-bench.log: \$(grep -c 'warning:' build-bench.log), of which in bench/: \$(grep 'warning:' build-bench.log | grep -c '/bench/')\"; grep 'warning:' build-bench.log | grep '/bench/' | head -20; [ \$rc = 0 ]; } && sha256sum build-bench/bench_net_?x"
    done
    # the real gateway receiver (EcuM, Os, BswM, Com, SecOC, PduR, SoAd, TcpIp), from this same tree, with the
    # harness transmitter's public key as its peer key: the oracle of the attack runs
    r "${RX_HOST}" "cd ${PI_DIR} && mkdir -p keys/gw-rx && LIBOQS_ROOT=${LIBOQS} SECOC_GIT_COMMIT=${COMMIT} SECOC_PORT=${GW_PORT} taskset -c 0-2 nice -n 10 Autosar_SecOC/scripts/build_gateway.sh rx ${RX_IP} ${TX_IP} ${PI_DIR}/keys/gw-rx ${PI_DIR}/build-gw-rx | tail -1 && sha256sum build-gw-rx/SecOC"
    r "${TX_HOST}" "mkdir -p ${PI_DIR}/keys && ${BIN}/bench_keygen ${PI_DIR}/keys/tx"
    r "${RX_HOST}" "mkdir -p ${PI_DIR}/keys && ${BIN}/bench_keygen ${PI_DIR}/keys/rx"
    # the public key crosses over through the measuring workstation; secret keys never leave their board
    TMP="$(mktemp -d)"; trap 'rm -rf "${TMP}"; cleanup' EXIT
    rsync -az -e "ssh -F ${PI_SSH_CFG}" "pi-${TX_HOST}:${PI_REL}/keys/tx/mldsa_secoc.pub" "${TMP}/tx.pub"
    rsync -az -e "ssh -F ${PI_SSH_CFG}" "${TMP}/tx.pub" "pi-${RX_HOST}:${PI_REL}/keys/rx/mldsa_peer0.pub"
    rsync -az -e "ssh -F ${PI_SSH_CFG}" "${TMP}/tx.pub" "pi-${RX_HOST}:${PI_REL}/keys/gw-rx/mldsa_peer0.pub"
    # the handshake pins the peer's key on both ends; the gateway receiver gets the harness receiver's
    # identity (its strict bootstrap creates none), so the transmitter pins one key for both receivers
    rsync -az -e "ssh -F ${PI_SSH_CFG}" "pi-${RX_HOST}:${PI_REL}/keys/rx/mldsa_secoc.pub" "${TMP}/rx.pub"
    rsync -az -e "ssh -F ${PI_SSH_CFG}" "${TMP}/rx.pub" "pi-${TX_HOST}:${PI_REL}/keys/tx/mldsa_peer0.pub"
    r "${RX_HOST}" "cp -p ${PI_DIR}/keys/rx/mldsa_secoc.key ${PI_DIR}/keys/rx/mldsa_secoc.pub ${PI_DIR}/keys/gw-rx/ && sha256sum ${PI_DIR}/keys/rx/mldsa_peer0.pub ${PI_DIR}/keys/gw-rx/mldsa_peer0.pub ${PI_DIR}/keys/gw-rx/mldsa_secoc.pub"
    r "${TX_HOST}" "sha256sum ${PI_DIR}/keys/tx/mldsa_peer0.pub"
    unlock_boards
    ;;

periodic)
    RUN_ID="${2:?run_id}"; PERIOD_US="${3:?period_us}"; COUNT="${4:?count}"; SCHED="${5:-other}"
    if [[ "${CLOCK_PROBE:-}" == 1 ]]; then
        [[ "${PARTITIONS}" == 1 && "${PROBE_CPU}" != "${CORE_TX}" && "${PROBE_CPU}" != "${CORE_RX}" ]] \
            || { echo "CLOCK_PROBE=1 needs one partition and a core of its own (PROBE_CPU=${PROBE_CPU}, harnesses on ${CORE_TX} and ${CORE_RX})" >&2; exit 2; }
        PROBE_ON=1
    fi
    if [[ -n "${BG_MBIT:-}" ]]; then
        [[ "${PARTITIONS}" == 1 && "${BG_CPU}" != "${CORE_TX}" && "${BG_CPU}" != "${CORE_RX}" && ( -z "${PROBE_ON:-}" || "${BG_CPU}" != "${PROBE_CPU}" ) ]] \
            || { echo "BG_MBIT needs one partition and a core of its own (BG_CPU=${BG_CPU}; harnesses on ${CORE_TX} and ${CORE_RX}, probe on ${PROBE_CPU})" >&2; exit 2; }
        BG_ON=1
    fi
    RUN_LIMIT=$(( COUNT * PERIOD_US / 1000000 + 300 ))
    new_run "${RUN_ID}" periodic "$@"
    gates before "${RD}"
    transfer "--sched ${SCHED} --out ${RD}/periodic_rx@P@.csv --payload-out ${RD}/rx_payload@P@.csv --max-rows $((COUNT * ${STREAMS:-1} + 1000))" \
             "--sched ${SCHED} --streams ${STREAMS:-1} --period-us ${PERIOD_US} --count ${COUNT}${PHASE_OPT} --out ${RD}/periodic_tx@P@.csv"
    [[ -z "${PROBE_ON:-}" ]] || probe_stop
    [[ -z "${BG_ON:-}" ]] || bg_stop
    gates after "${RD}"
    unlock_boards
    collect periodic
    finish
    ;;

probetest)
    # The two tests of the clock probe (E9). (a) Client and server on ONE board, where the true offset is zero, for
    # each board: every exchange must give |theta| <= delta/2. (b) Two probes at the same time over the link, A to B
    # and B to A: at every anchor the two tracks must sum to zero within the sum of their bounds.
    RUN_ID="${2:?run_id}"; SECS="${3:-60}"
    P="timeout -s TERM $((SECS + 120)) ${BIN}/bench_clock_probe"; MINE="${PI_REL}/build-bench/${PROBE}"     # (a probe the driver lost ends by itself)
    new_run "${RUN_ID}" probetest "$@"
    gates before "${RD}"
    PROBE_STARTED=1
    for H in $(hosts); do   # (a): the client on the probe's core, the server on another one that is free
        # (the server is ended by its process ID: a pattern for pkill -f would match this command line, which starts it)
        r "${H}" "taskset -cp 0 \$\$ > /dev/null; cd ${RD} && { nohup ${P} --server --bind 127.0.0.1 --port ${PROBE_PORT} --cpu 2 > zero_server_${H}.log 2>&1 < /dev/null & s=\$!; sleep 0.5; timeout -s TERM ${SECS} ${BIN}/bench_clock_probe --client --peer 127.0.0.1 --port ${PROBE_PORT} --cpu ${PROBE_CPU} --interval-ms ${PROBE_INTERVAL_MS} --out zero_${H}.csv > zero_client_${H}.log 2>&1; kill -TERM \$s; wait \$s; tail -qn 1 zero_client_${H}.log; }"
    done
    # (b): on each board one server and one client, all four on the probe's core as in a run
    r "${RX_HOST}" "cd ${RD} && (nohup ${P} --server --bind ${RX_IP} --port ${PROBE_PORT} --cpu ${PROBE_CPU} > pair_server_ab.log 2>&1 < /dev/null &); sleep 0.5"
    r "${TX_HOST}" "cd ${RD} && (nohup ${P} --server --bind ${TX_IP} --port $((PROBE_PORT + 1)) --cpu ${PROBE_CPU} > pair_server_ba.log 2>&1 < /dev/null &); sleep 0.5; (nohup ${P} --client --peer ${RX_IP} --port ${PROBE_PORT} --cpu ${PROBE_CPU} --interval-ms ${PROBE_INTERVAL_MS} --out pair_ab.csv > pair_client_ab.log 2>&1 < /dev/null &)"
    r "${RX_HOST}" "taskset -cp 0 \$\$ > /dev/null; cd ${RD} && timeout -s TERM ${SECS} ${BIN}/bench_clock_probe --client --peer ${TX_IP} --port $((PROBE_PORT + 1)) --cpu ${PROBE_CPU} --interval-ms ${PROBE_INTERVAL_MS} --out pair_ba.csv > pair_client_ba.log 2>&1; tail -qn 1 pair_client_ba.log"
    # every probe is waited for before the files are copied and the board's run directory is removed
    r "${TX_HOST}" "$(probe_end "${MINE} --client" 'the probe client (bench_clock_probe --client)'); $(probe_end "${MINE} --server" 'the probe server (bench_clock_probe --server)'); tail -qn 1 ${RD}/pair_client_ab.log"
    r "${RX_HOST}" "$(probe_end "${MINE} --server" 'the probe server (bench_clock_probe --server)')"
    PROBE_STARTED=""
    gates after "${RD}"
    unlock_boards
    collect probetest
    {
        for H in $(hosts); do
            python3 -I "${ROOT}/Autosar_SecOC/bench/check_clock_probe.py" --zero "${OUT}/probetest/zero_${H}.csv" || FAILED=1
        done
        python3 -I "${ROOT}/Autosar_SecOC/bench/check_clock_probe.py" --pair "${OUT}/probetest/pair_ab.csv" "${OUT}/probetest/pair_ba.csv" || FAILED=1
    } > "${OUT}/probetest.txt" 2>&1
    cat "${OUT}/probetest.txt"
    finish
    ;;

ladder)
    RUN_ID="${2:?run_id}"; DURATION="${3:?duration_s}"; RAMP="${4:?ramp_s}"; REPS="${5:?repetitions}"; shift 5
    for RATE in "$@"; do    # the file name carries the total, every process offers total / PARTITIONS
        (( RATE % PARTITIONS == 0 )) || { echo "rate ${RATE} is not divisible by PARTITIONS=${PARTITIONS}" >&2; exit 2; }
    done
    new_run "${RUN_ID}" throughput ladder "${DURATION}" "${RAMP}" "${REPS}" "$@"
    RXNAME="$(r "${RX_HOST}" hostname)"; TXNAME="$(r "${TX_HOST}" hostname)"
    for REP in $(seq "${REPS}"); do
        for RATE in "$@"; do
            TAG="${RATE}pps_rep${REP}"; EACH=$((RATE / PARTITIONS)); STEP_TAG="_${TAG}"
            gates "before_${TAG}" "${RD}"
            transfer "--rep ${REP} --out ${RD}/periodic_rx_${TAG}@P@.csv --max-rows $(( (DURATION + RAMP) * EACH + 1000 )) --samples ${RD}/throughput_rx_${TAG}@P@.csv --tx-host ${TXNAME} --rate-pps ${EACH} --duration ${DURATION} --ramp ${RAMP} --iface ${IFACE}" \
                     "--rep ${REP} --rate-pps ${EACH} --duration ${DURATION} --ramp ${RAMP} --out ${RD}/periodic_tx_${TAG}@P@.csv --samples ${RD}/throughput_tx_${TAG}@P@.csv --rx-host ${RXNAME} --iface ${IFACE}"
            gates "after_${TAG}" "${RD}"
        done
    done
    unlock_boards
    collect throughput
    finish
    ;;

attack)
    RUN_ID="${2:?run_id}"; PDUS="${3:?pdus}"; EVERY="${4:?every}"; VECTORS="${5:?vectors}"; ORACLE="${ORACLE:-gateway}"
    [[ "${ORACLE}" == gateway || "${ORACLE}" == harness ]] || { echo "ORACLE must be gateway or harness" >&2; exit 2; }
    # old-session replay: RECORD_SESSION=<file on the transmitter's board> keeps every PDU of this run's session,
    # REPLAY_SESSION=<that file> sends them into a later run (vector session_replay)
    [[ -z "${RECORD_SESSION:-}" ]] || PROXY_OPTS="${PROXY_OPTS:-} --record ${RECORD_SESSION}"
    [[ -z "${REPLAY_SESSION:-}" ]] || PROXY_OPTS="${PROXY_OPTS:-} --session-file ${REPLAY_SESSION}"
    PROXY_ADDR=127.0.0.1    # where the transmitter finds the proxy: on its own board
    if [[ "${RELAY_NETNS:-}" == 1 ]]; then
        [[ -z "${LOOPBACK:-}" && "${VECTORS}" != none && "${RELAY_CPU}" != "${CORE_TX}" ]] \
            || { echo "RELAY_NETNS=1 needs two boards, a proxy (vectors) and a core for it that is not the transmitter's (RELAY_CPU=${RELAY_CPU})" >&2; exit 2; }
        PROXY_ADDR="${NS_ATK}"
        PROXY_WRAP="taskset -c ${RELAY_CPU} "; PROXY_OPTS="--bind ${NS_ATK} ${PROXY_OPTS:-}"
        # into the namespace as root (ip netns exec needs it), then back to the user who runs everything else
        TX_WRAP="sudo -n ip netns exec txns setpriv --reuid=\$(id -u) --regid=\$(id -g) --init-groups "
    fi
    new_run "${RUN_ID}" attack "$@"
    gates before "${RD}"
    [[ "${RELAY_NETNS:-}" != 1 ]] || netns_up
    DOWN_PORT="${PORT}"     # ORACLE=harness: bench_net_rx listens on PORT
    if [[ "${ORACLE}" == gateway ]]; then
        DOWN_PORT="${GW_PORT}"
        gateway_rx_start
    fi
    if [[ "${VECTORS}" == none ]]; then
        # no proxy: the harness transmitter and the gateway receiver directly, over the link
        [[ "${ORACLE}" == gateway ]] || { echo "vectors none needs the gateway receiver" >&2; exit 2; }
        NO_RX=1 transfer "" "--allow-unlocked --period-us 10000 --count ${PDUS} --out ${RD}/periodic_tx.csv" "${PORT}" "${GW_PORT}"
    else
        proxy_start "--vector ${VECTORS} --every ${EVERY}"
        if [[ "${ORACLE}" == gateway ]]; then
            NO_RX=1 transfer "" "--allow-unlocked --period-us 10000 --count ${PDUS} --out ${RD}/periodic_tx.csv" "${PORT}" "$((PORT + 1))" "${PROXY_ADDR}"
        else
            PROXY_UP=1 transfer "--out ${RD}/periodic_rx.csv --payload-out ${RD}/rx_payload.csv --max-rows $((PDUS * 2 + 1000))" \
                                "--period-us 10000 --count ${PDUS} --out ${RD}/periodic_tx.csv" "${PORT}" "$((PORT + 1))" "${PROXY_ADDR}"
        fi
    fi
    [[ "${VECTORS}" == none ]] || r "${TX_HOST}" "for i in \$(seq 50); do pgrep -f '[a]ttack_proxy' > /dev/null || break; sleep 0.1; done; tail -1 ${RD}/proxy.log"
    [[ "${ORACLE}" != gateway ]] || gateway_rx_stop
    [[ -z "${NETNS_UP}" ]] || netns_down
    gates after "${RD}"
    unlock_boards
    collect attack
    if [[ "${RELAY_NETNS:-}" == 1 ]]; then      # the three things that make the proxy a node of its own in this run
        mv "${OUT}/attack/netns_check.txt" "${OUT}/netns_check.txt" 2> /dev/null || true
        grep -q '^route_check=fails' "${OUT}/netns_check.txt" 2> /dev/null || echo "netns_check.txt: the namespace of the transmitter was not shown to have no route to the receiver" >> "${OUT}/EXCLUDED"
        grep -q "^transmitter connected from ${NS_TX}:" "${OUT}/attack/proxy.log" 2> /dev/null || echo "proxy.log: the transmitter's connection did not come from ${NS_TX}" >> "${OUT}/EXCLUDED"
        grep -q '^gone_after_run=yes' "${OUT}/netns_check.txt" 2> /dev/null || echo "netns_check.txt: namespace and pair were not shown to be gone after the run" >> "${OUT}/EXCLUDED"
        grep -E '^(route_check|gone_after_run)=' "${OUT}/netns_check.txt" || true; grep '^transmitter connected' "${OUT}/attack/proxy.log" || true
    fi
    # the run directory names the session of the recording and the session the PDUs were sent into (DATA_SCHEMA.md)
    SID="$(grep -h -m1 '^# session_id=' "${OUT}/attack/periodic_tx.csv" | sed 's/.*=//')"
    [[ -z "${RECORD_SESSION:-}" ]] || r "${TX_HOST}" "echo 'recorded_run=${RUN_ID} recorded_session_id=${SID} recorded_pdus=${PDUS}' > ${RECORD_SESSION}.txt"
    if [[ -n "${REPLAY_SESSION:-}" ]]; then
        { r "${TX_HOST}" "cat ${REPLAY_SESSION}.txt"; echo "injection_run=${RUN_ID} injection_session_id=${SID}"; } > "${OUT}/attack/session_replay.txt"
        cat "${OUT}/attack/session_replay.txt"
        grep -q 'recorded_session_id=[0-9a-f]' "${OUT}/attack/session_replay.txt" && ! grep -q "recorded_session_id=${SID} " "${OUT}/attack/session_replay.txt" \
            || echo "session_replay: the recording has no session identifier or is of this run's own session" >> "${OUT}/EXCLUDED"
    fi
    if [[ "${VECTORS}" == none ]]; then
        DELIVERED="$(grep -c ',ok$' "${OUT}/attack/app_rx.csv" || true)"
        echo "gateway receiver: ${DELIVERED} of ${PDUS} PDUs delivered"
        [[ "${DELIVERED}" == "${PDUS}" ]] || echo "the gateway receiver delivered ${DELIVERED} of ${PDUS} PDUs" >> "${OUT}/EXCLUDED"
        finish && [[ ! -e "${OUT}/EXCLUDED" ]]
        exit $?
    fi
    JOIN=0
    RXLOG=app_rx.csv; NAME=gateway_app_log
    [[ "${ORACLE}" == gateway ]] || { RXLOG=periodic_rx.csv; NAME=harness_receiver; }
    python3 -I "${ROOT}/Autosar_SecOC/bench/join_attack.py" "${OUT}/attack/proxy_log.csv" "${OUT}/attack/${RXLOG}" \
        --out "${OUT}/attack/attack.csv" --commit "${COMMIT}" --oracle "${NAME}" --tx-file "${OUT}/attack/periodic_tx.csv" > "${OUT}/attack/join.txt" 2>&1 || JOIN=$?
    cat "${OUT}/attack/join.txt"; echo "join_attack exit code ${JOIN} (0: every attacked PDU rejected, every benign PDU delivered)"
    finish && [[ "${JOIN}" == 0 ]]
    ;;

handshake)
    RUN_ID="${2:?run_id}"; N="${3:?handshakes}"
    new_run "${RUN_ID}" handshake "$@"
    gates before "${RD}"
    TX_BIN=bench_handshake transfer "--out ${RD}/unused_rx.csv" "--n ${N}"
    gates after "${RD}"
    unlock_boards
    collect handshake
    finish
    ;;

hsneg)
    # hsneg <run_id> <test> <reps>: one on-wire handshake test of SPEC.md "Negative tests" as an hstest run
    # with the proxy options of Autosar_SecOC/bench/README.md, judged by check_hsneg.py. PDUs at 10 ms.
    RUN_ID="${2:?run_id}"; TEST="${3:?test: record 1..10 11drop 11sig 11mac 11key 12drop 12flip}"; REPS="${4:?repetitions}"
    FORGED=/dev/shm/bench_forge_; HSREC="${HSREC:-/dev/shm/bench_hsrec_}"; EDITS=""; INJECT=""; REKEY=300
    case "${TEST}" in
        record) PROXY_OPTS="${PROXY_OPTS:-} --hs-record ${HSREC}"; REKEY=0 ;;    # M1..M4 of this run, for 5, 6, 7 and 10
        1) EDITS="0x30:replace:33:${FORGED}ek.bin@2+" ;;
        2) EDITS="0x31:replace:33:${FORGED}ct.bin@2+" ;;
        3) EDITS="0x31:resign@2+" ;;
        4) EDITS="0x31:flip:4430:32@2+" ;;
        5) INJECT="0x30:${HSREC}30.bin:to_receiver" ;;
        6) EDITS="0x31:replace:0:${HSREC}31.bin@2+" ;;
        7) INJECT="0x32:${HSREC}32.bin:to_receiver" ;;
        8) EDITS="0x30:flip:1:32@2+" ;;
        9|10) export SIDE_PROBES=4; REKEY=0 ;;
        11drop) EDITS="0x32:drop@2/2" ;;
        11sig) EDITS="0x32:flip:1:3309@2/2" ;;
        11mac) EDITS="0x32:flip:3310:32@2/2" ;;
        11key) EDITS="0x32:resign@2/2" ;;
        12drop) EDITS="0x33:drop@2/2" ;;
        12flip) EDITS="0x33:flip:1:32@2/2" ;;
        *) echo "unknown test ${TEST}" >&2; exit 2 ;;
    esac
    # Run length in seconds. After a failed attempt the initiator starts the next handshake by itself T_A (3 s)
    # after its M1, so a test of the first group repeats every 3 s; an injection every 3 s (above T_pend).
    case "${TEST}" in
        record) SECONDS_RUN=3 ;;
        9|10) SECONDS_RUN=$(( 10 + REPS / 8 )) ;;       # the probes are repeated REPS times inside the session
        5|7) PROXY_OPTS="${PROXY_OPTS:-} --hs-inject ${INJECT}:2:3:${REPS}"; REKEY=0; SECONDS_RUN=$(( 2 + 3 * REPS + 2 )) ;;
        11*|12*)
            # "every second handshake attacked" = one attacked handshake per run (one rekey request after 100 PDUs,
            # the retry T_A later is genuine, then about 200 PDUs more): REPS short runs r001.. in one batch, under
            # one lock and one pair of gate snapshots, each judged on its own
            export HSNEG_BATCH="${REPS}"; REPS=1; REKEY=100; SECONDS_RUN=6 ;;
        *) SECONDS_RUN=$(( 3 + 3 * REPS + 2 )) ;;
    esac
    # the gateway receiver leaves when it has logged an outcome for every PDU sent (not 5 s later)
    export HSNEG_TEST="${TEST}" HSNEG_REPS="${REPS}" HSREC PROXY_OPTS INITIATOR="${INITIATOR:-gateway}" GW_RX_COUNT="$(( SECONDS_RUN * 100 ))"
    # shellcheck disable=SC2086
    exec "$0" hstest "${RUN_ID}" "$(( SECONDS_RUN * 100 ))" "${REKEY}" ${EDITS}
    ;;

hstest)
    RUN_ID="${2:?run_id}"; PDUS="${3:?pdus}"; REKEY="${4:?rekey_after}"; shift 4; ORACLE="${ORACLE:-gateway}"
    INITIATOR="${INITIATOR:-harness}"   # gateway: the gateway transmitter of build-gw-tx (SPEC: the real binary on both ends)
    new_run "${RUN_ID}" hstest "${PDUS}" "${REKEY}" "$@"
    if [[ "${INITIATOR}" == gateway ]]; then
        r "${TX_HOST}" "test -x ${PI_DIR}/build-gw-tx/SecOC" || { echo "no gateway transmitter on ${TX_HOST}: run 'build-gw-tx' first" >&2; exit 2; }
    fi
    case "${HSNEG_TEST:-}" in       # what the proxy's edits of this test need on the transmitter's board
        1|2) r "${TX_HOST}" "taskset -c 0-2 ${BIN}/bench_hs_forge ek /dev/shm/bench_forge_ek.bin && taskset -c 0-2 ${BIN}/bench_hs_forge ct /dev/shm/bench_forge_ct.bin" ;;
        5|6|7|10) r "${TX_HOST}" "test -s ${HSREC}30.bin -a -s ${HSREC}31.bin -a -s ${HSREC}32.bin" \
                      || { echo "no recorded handshake on ${TX_HOST} (${HSREC}3x.bin): run 'hsneg <run_id> record 1' first" >&2; exit 2; } ;;
    esac
    gates before "${RD}"
    DOWN_PORT="${PORT}"; [[ "${ORACLE}" != gateway ]] || DOWN_PORT="${GW_PORT}"
    # HSNEG_BATCH=N: N runs one after the other under this one lock and this one pair of gate snapshots, each in
    # its own directory r001.. on the boards (tests 11 and 12: one attacked handshake per run)
    BATCH="${HSNEG_BATCH:-1}"; RD_BASE="${RD}"
    if (( BATCH > 1 )); then
        for h in $(hosts); do r "${h}" "mkdir -p $(seq -f "${RD_BASE}/r%03g" 1 "${BATCH}" | xargs)"; done
    fi
    for k in $(seq 1 "${BATCH}"); do
        (( BATCH == 1 )) || RD="${RD_BASE}/r$(printf '%03d' "${k}")"
        if [[ "${INITIATOR}" == gateway ]]; then
            # closed loop, one PDU about every 10 BSW cycles; SECOC_APP_REKEY_AT asks for the second handshake
            export TX_CMD="env SECOC_APP_COUNT=${PDUS} SECOC_APP_STREAMS=1 SECOC_APP_PERIOD_CYCLES=10 SECOC_APP_REKEY_AT=${REKEY} SECOC_APP_CSV=${RD}/app_tx.csv SECOC_APP_HS_CSV=${RD}/handshake_gw_tx.csv timeout $(( PDUS / 50 + 60 )) taskset -c ${CORE_TX} ${PI_DIR}/build-gw-tx/SecOC"
        fi
        [[ "${ORACLE}" != gateway ]] || gateway_rx_start
        if [[ -n "${SIDE_PROBES:-}" ]]; then
            # Tests 9 and 10 of SPEC.md "Negative tests", SIDE_PROBES = seconds from here to the probes inside the
            # session: a datagram of the retired UDP channel to the receiver before any session and again inside it;
            # a second TCP connection to the receiver from an address that is not its peer (its own eth0 address)
            # with the M1 of an earlier run (HSREC, written by --hs-record); no UDP listener on either board.
            PROBE="python3 ${PI_DIR}/Autosar_SecOC/bench/hs_side_probes.py"; M1_FILE="${HSREC:-/dev/shm/bench_hsrec_}30.bin"
            if [[ "${TX_HOST}" != "${RX_HOST}" ]]; then
                rsync -az -e "ssh -F ${PI_SSH_CFG}" "pi-${TX_HOST}:${M1_FILE}" "${OUT}/old_m1.bin"
                rsync -az -e "ssh -F ${PI_SSH_CFG}" "${OUT}/old_m1.bin" "pi-${RX_HOST}:${M1_FILE}"
            fi
            r "${TX_HOST}" "cd ${RD} && { echo before_session; ${PROBE} udp ${RX_IP}; ${PROBE} listeners; } > side_probes_tx.txt 2>&1; (nohup sh -c 'sleep ${SIDE_PROBES}; echo in_session; ${PROBE} udp ${RX_IP} --count ${HSNEG_REPS:-1} --wait 0.05' >> side_probes_tx.txt 2>&1 < /dev/null &)"
            # the address the second connection comes from and goes to: the receiver's own eth0 address; in loopback
            # the peer is 127.0.0.1, so the connection comes from 127.0.0.2 (all of 127/8 is local) to 127.0.0.1
            OWN="\$(ip -4 -br addr show dev eth0 | awk '{print \$3}' | cut -d/ -f1)"; DST='$own'
            if [[ -n "${LOOPBACK:-}" ]]; then OWN=127.0.0.2; DST=127.0.0.1; fi
            r "${RX_HOST}" "cd ${RD} && own=${OWN}; { echo before_session; ${PROBE} listeners; } > side_probes_rx.txt 2>&1; (nohup sh -c \"sleep ${SIDE_PROBES}; echo in_session; if [ -n '\$own' ]; then ${PROBE} tcp ${DST} ${DOWN_PORT} --bind \$own --send ${M1_FILE} --count ${HSNEG_REPS:-1}; else echo 'probe=tcp skipped: eth0 has no address'; fi\" >> side_probes_rx.txt 2>&1 < /dev/null &)"
        fi
        proxy_start "--vector replay --every 0 ${*:+--hs $*} --hs-log ${RD}/hs_edits.csv"
        if [[ "${ORACLE}" == gateway ]]; then
            NO_RX=1 transfer "" "--allow-unlocked --period-us 10000 --count ${PDUS} --rekey-after ${REKEY} --out ${RD}/periodic_tx.csv" "${PORT}" "$((PORT + 1))" 127.0.0.1
        else
            PROXY_UP=1 transfer "--out ${RD}/periodic_rx.csv --max-rows $((PDUS * 2 + 1000))" \
                                "--period-us 10000 --count ${PDUS} --rekey-after ${REKEY} --out ${RD}/periodic_tx.csv" "${PORT}" "$((PORT + 1))" 127.0.0.1
        fi
        r "${TX_HOST}" "for i in \$(seq 50); do pgrep -f '[a]ttack_proxy' > /dev/null || break; sleep 0.1; done; tail -1 ${RD}/proxy.log"
        [[ "${ORACLE}" != gateway ]] || gateway_rx_stop
    done
    RD="${RD_BASE}"
    gates after "${RD}"
    unlock_boards
    collect hstest
    (( BATCH > 1 )) || {   # what the specification's oracle reads: result labels, session and installation counter on each side, deliveries
        echo "edits made by the proxy:"; grep -v '^#' "${OUT}/hstest/hs_edits.csv"
        if [[ -n "${SIDE_PROBES:-}" ]]; then echo "side probes:"; sed 's/^/tx host: /' "${OUT}/hstest/side_probes_tx.txt"; sed 's/^/rx host: /' "${OUT}/hstest/side_probes_rx.txt"; fi
        if [[ "${INITIATOR}" == gateway ]]; then
            echo "transmitter (gateway, initiator):"; grep -a 'App_Hs\] keys installed' "${OUT}/hstest/tx.log"
            grep -v '^#' "${OUT}/hstest/handshake_gw_tx.csv" | cut -d, -f1-6
            echo "transmitter's PDU log: $(grep -v '^#' "${OUT}/hstest/app_tx.csv" | awk -F, 'NR > 1 && $NF != 0 {n++} END {print n + 0}') PDUs confirmed"
        else
            echo "transmitter (initiator): $(grep -h -E '^# (session_id_first|hs_installs_first|session_id|hs_installs|hs_established)=' "${OUT}/hstest/periodic_tx.csv" | tr -d '#' | xargs)"
            grep -v '^#' "${OUT}/hstest/handshake_tx.csv" | cut -d, -f1-6
        fi
        if [[ "${ORACLE}" == gateway ]]; then
            echo "receiver (gateway, responder):"; grep -a 'App_Hs' "${OUT}/hstest/gw_rx_banner.txt"
            grep -v '^#' "${OUT}/hstest/handshake_gw_rx.csv" | cut -d, -f1-6
            echo "receiver's PDU log: $(grep -v '^#' "${OUT}/hstest/app_rx.csv" | awk -F, 'NR > 1 {n[$NF]++} END {for (k in n) printf "%s=%d ", k, n[k]}')"
        else
            echo "receiver (harness, responder): $(grep -h -E '^# (session_id_first|hs_installs_first|session_id|hs_installs|hs_established)=' "${OUT}/hstest/periodic_rx.csv" | tr -d '#' | xargs)"
            grep -v '^#' "${OUT}/hstest/handshake_rx.csv" | cut -d, -f1-6
            echo "receiver's PDU log: $(grep -v '^#' "${OUT}/hstest/periodic_rx.csv" | awk -F, 'NR > 1 {n[$NF]++} END {for (k in n) printf "%s=%d ", k, n[k]}')"
        fi
    } > "${OUT}/hstest.txt" 2>&1
    (( BATCH > 1 )) || cat "${OUT}/hstest.txt"
    if (( BATCH > 1 )); then    # each run of the batch is judged on its own; hsneg.txt: one line per run, the record line, the verdict
        python3 -I "${ROOT}/Autosar_SecOC/bench/check_hsneg.py" --batch "${OUT}/hstest" "${HSNEG_TEST}" "${HSNEG_REPS}" > "${OUT}/hsneg.txt" 2>&1 || FAILED=1
        grep -v ': PASS$' "${OUT}/hsneg.txt" || true
    elif [[ -n "${HSNEG_TEST:-}" && "${HSNEG_TEST}" != record ]]; then
        python3 -I "${ROOT}/Autosar_SecOC/bench/check_hsneg.py" "${OUT}/hstest" "${HSNEG_TEST}" "${HSNEG_REPS}" > "${OUT}/hsneg.txt" 2>&1 || FAILED=1
        cat "${OUT}/hsneg.txt"
    fi
    finish
    ;;

calibrate)
    RUN_ID="${2:?run_id}"; RATE="${3:?rate_pps}"; SECONDS_RUN="${4:?seconds}"
    new_run "${RUN_ID}" calibration "$@"
    RXNAME="$(r "${RX_HOST}" hostname)"; TXNAME="$(r "${TX_HOST}" hostname)"
    gates before "${RD}"
    r "${TX_HOST}" "/usr/sbin/ethtool -k ${IFACE} | grep -E '^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|tx-checksumming):' > ${RD}/offload_${TXNAME}.txt; (sudo -n nohup tcpdump -i ${IFACE} -s 96 -w ${RD}/tx.pcap tcp port ${PORT} > /dev/null 2>&1 < /dev/null &); sleep 1"
    transfer "--allow-unlocked --out ${RD}/periodic_rx.csv --samples ${RD}/throughput_rx.csv --tx-host ${TXNAME} --rate-pps ${RATE} --duration ${SECONDS_RUN} --iface ${IFACE}" \
             "--allow-unlocked --rate-pps ${RATE} --duration ${SECONDS_RUN} --out ${RD}/periodic_tx.csv --samples ${RD}/throughput_tx.csv --rx-host ${RXNAME} --iface ${IFACE}"
    # frames that carry TCP payload from the transmitter: count, payload bytes, frame bytes as captured (before any GSO split)
    r "${TX_HOST}" "sudo -n pkill -INT tcpdump; sleep 1; sudo -n tcpdump -e -nn -r ${RD}/tx.pcap 'src host ${TX_IP} and tcp[tcpflags] & tcp-syn == 0' 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if (\$i == \"length\") { if (!f) { frame = \$(i + 1) + 0; f = 1 } else pay = \$(i + 1) + 0 } f = 0; if (pay > 0) { n++; fb += frame; pb += pay } pay = 0 } END { printf \"captured_frames_with_payload=%d\\ntcp_payload_bytes=%d\\nframe_bytes_as_captured=%d\\n\", n, pb, fb }' > ${RD}/capture_${TXNAME}.txt; sudo -n rm -f ${RD}/tx.pcap; grep -h jobs_confirmed ${RD}/periodic_tx.csv >> ${RD}/capture_${TXNAME}.txt; cat ${RD}/capture_${TXNAME}.txt ${RD}/offload_${TXNAME}.txt"
    gates after "${RD}"
    unlock_boards
    collect calibration
    finish
    ;;

*)
    sed -n '2,40p' "${BASH_SOURCE[0]}" >&2
    exit 2
    ;;
esac
