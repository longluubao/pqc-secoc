#!/usr/bin/env bash
# scripts/run_single_node.sh
#
# The single-node experiments of the campaign (CAMPAIGN.md E1, E1a, E0 and E2), on this board, each
# into one run directory. Runs ON the Pi.
#
#   scripts/run_single_node.sh e1 <build_dir> <run_dir> [cpu]
#       primitive timing with bench_crypto_ops pinned to <cpu> (default 3), one process per step,
#       64-byte PDU signature context:
#         crypto_ops/crypto_ops_sign_p8.csv    mldsa_sign, N_SIGN iterations, 14-byte signed input
#                                              (Data ID 2 + payload 8 + freshness 4)
#         crypto_ops/crypto_ops_other_p8.csv   the eight other operations, N_OTHER each, same input
#         crypto_ops/crypto_ops_p<P>.csv       mldsa_sign and mldsa_verify, N_SWEEP each, for
#                                              payloads P = 64, 256, 1024 (signed input P + 6)
#       E1_OPS=receiver leaves out what the receiving board never does: mldsa_verify, mlkem_encaps
#       and hmac_verify only, and the payload sweep with mldsa_verify only.
#   scripts/run_single_node.sh e1a <build_dir> <run_dir> [cpu]
#       attribution of the signing tail: bench_sign_attrib pinned to <cpu>, N_SIGN signing calls
#       with the 14-byte input and the 64-byte context of e1, wall time and thread CPU time per call:
#         crypto_attrib/sign_attrib_p8.csv     seq,wall_ns,cpu_ns
#       COUNT_SHAKE=1 adds the column shake_calls (bench_sign_attrib --count-shake: a proxy for
#       the rounds of the rejection loop, at the price of one indirect call per SHAKE-256 start).
#   scripts/run_single_node.sh e0 <build_dir> <run_dir> [cpu]
#       scheduling-latency baseline with run_cyclictest.sh on <cpu>, CELL_SECONDS per cell:
#       SCHED_OTHER and SCHED_FIFO 80, each idle and with bench_crypto_ops signing on the cores
#       of LOAD_CPUS (default "2": one core; three signing cores take a board without a fan past
#       its limit within minutes). The load is started for a loaded cell and stopped after it.
#   scripts/run_single_node.sh e2 <build_dir> <run_dir> [cpu]
#       abstraction overhead, paired: bench_overhead_paired through run_overhead_launches.sh, LAUNCHES
#       (30) process launches of PAIRS (3000) pairs each, sign and verify, 14-byte signed input:
#         overhead/overhead_paired_L<nn>.csv      mode ab, liboqs called directly against the Csm path
#         overhead/overhead_paired_aa_L<nn>.csv   mode aa, the noise floor of the method
#       CTX_BYTES is the FIPS 204 context of the direct call (default 64: what the Csm path of this
#       tree signs with; the harness refuses to start when the two do not match). SEED_AB (1000) and
#       SEED_AA (2000): launch n runs with seed base + n.
#       E2_BLOCK chooses the block, because the margin is fixed between the two (CAMPAIGN.md):
#         aa    the noise floor alone, into its own run directory: run this first
#         ab    the A/B block alone, into its own run directory; needs MARGIN_FILE=<file on this
#               board>, the pre-registered margin written after the aa block: it is copied in as
#               equivalence_margin.txt before the first launch (hash and time in harness_<host>.txt)
#         both  (default) aa, then ab, in one directory: for dry runs, refused with MARKER=none
#
# Environment: N_SIGN (1000000), N_OTHER (100000), N_SWEEP (20000), CELL_SECONDS (600): the campaign
#              sizes, smaller for a dry run. SEED: shuffle the order of the steps reproducibly
#              (order.txt has the order that ran); without it the order is the one listed above.
#              MARKER: DRY_RUN (default), PILOT or none: the marker file that says nothing here may
#              be quoted. COOL_WAIT (900): seconds to wait for the board to cool before a step;
#              ALLOW_HOT_DRYRUN=1 lets a run with the DRY_RUN marker (no other) start a step on a
#              board at 68 C or more and notes the temperature in NOTE_hot_start.
#              STOP_AT_C (78): a loaded e0 cell is stopped when the board reaches this temperature.
#              LIBOQS_ROOT (~/opt/liboqs-0.15.0).
#
# The caller holds the board (the campaign scripts' ~/array_rev/MEASURING, or a developer's board
# lock) and has let it idle; this script takes no lock. It does not start while the pinned core is
# in use or the board is at 68 C or more, and it writes EXCLUDED when a step breaks a validity rule
# of DATA_SCHEMA.md that can be read off the board: throttling flags, end temperature, other busy
# cores, the pinned core's share, memory locking.
# Exit: 0 clean, 1 a step failed or is excluded, 2 usage, 75 not started (busy core or too hot).

set -euo pipefail
[[ $# -ge 3 && ( "$1" == e1 || "$1" == e1a || "$1" == e0 || "$1" == e2 ) ]] || { sed -n '2,/^$/p' "${BASH_SOURCE[0]}" >&2; exit 2; }
WHAT="$1"; BUILD="$(cd "$2" && pwd)"; RUN="$3"; CPU="${4:-3}"
TREE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBOQS_ROOT="${LIBOQS_ROOT:-${HOME}/opt/liboqs-0.15.0}"
COMMIT="$(cat "${TREE}/bench/COMMIT")"
HOST="$(hostname)"
GATES="${RUN}/gates_${HOST}.txt"
RC=0
[[ ! -e "${RUN}" ]] || { echo "${RUN} exists; choose another run directory" >&2; exit 2; }
case "${MARKER:-DRY_RUN}" in DRY_RUN|PILOT|none) ;; *) echo "MARKER must be DRY_RUN, PILOT or none" >&2; exit 2 ;; esac
case "${E1_OPS:-all}" in all|receiver) ;; *) echo "E1_OPS must be all or receiver" >&2; exit 2 ;; esac
if [[ "${WHAT}" == e2 ]]; then
    case "${E2_BLOCK:-both}" in
        aa)   ;;
        ab)   [[ -f "${MARGIN_FILE:-}" ]] || { echo "E2_BLOCK=ab needs MARGIN_FILE=<the margin file written after the aa block, on this board>" >&2; exit 2; } ;;
        both) [[ "${MARKER:-DRY_RUN}" != none ]] || { echo "E2_BLOCK=both is for dry runs: a session runs E2_BLOCK=aa, then E2_BLOCK=ab with MARGIN_FILE" >&2; exit 2; } ;;
        *)    echo "E2_BLOCK must be aa, ab or both" >&2; exit 2 ;;
    esac
fi

temp_c() { vcgencmd measure_temp | tr -dc '0-9.'; }
core_ticks() { awk -v c="cpu${CPU}" '$1 == c {print $2 + $3 + $4 + $7 + $8 + $9, $5 + $6}' /proc/stat; }

# a step is not started at 68 C or more: wait for the board, at most COOL_WAIT seconds
cool() {
    local waited=0
    while awk -v t="$(temp_c)" 'BEGIN {exit !(t >= 68)}'; do
        if [[ "${ALLOW_HOT_DRYRUN:-}" == 1 && "${MARKER:-DRY_RUN}" == DRY_RUN ]]; then
            [[ ! -d "${RUN}" ]] || echo "$1 started at $(temp_c) C under ALLOW_HOT_DRYRUN=1 (functional dry run only)" >> "${RUN}/NOTE_hot_start"
            return 0
        fi
        if (( waited >= ${COOL_WAIT:-900} )); then
            echo "$1 not started: $(temp_c) C after waiting ${waited} s" >&2
            [[ ! -d "${RUN}" ]] || echo "$1 not started: $(temp_c) C after waiting ${waited} s" >> "${RUN}/SKIPPED"
            exit 75
        fi
        sleep 15; waited=$((waited + 15))
    done
}

# one line per step boundary: what the validity rules compare before and after
snapshot() {   # <step> <start|end> <load on the other cores: none, idle or its label>
    echo "step=$1 phase=$2 load=$3 time=$(date -Is) temp_c=$(temp_c) throttled=$(vcgencmd get_throttled | cut -d= -f2)" \
         "$(awk '/^cpu[0-9]/ {printf "%s=%d/%d ", $1, $2 + $3 + $4 + $7 + $8 + $9, $2 + $3 + $4 + $5 + $6 + $7 + $8 + $9}' /proc/stat)" \
         "loadavg=$(cut -d' ' -f1-3 /proc/loadavg | tr ' ' ',')" \
         "busiest=$(ps -eo pcpu,psr,comm --sort=-pcpu | awk 'NR > 1 && $3 != "ps" && ++n <= 5' | tr -s ' ' | tr '\n' ';')" >> "${GATES}"
}

# run <experiment dir> <command...>: record the exact command line, then execute it
run() {
    local dir="$1"
    shift
    echo "$*" >> "${dir}/cmd.txt"
    "$@"
}

order() { if [[ -n "${SEED:-}" ]]; then shuf --random-source=<(yes "${SEED}"); else cat; fi; }

read -r busy0 idle0 < <(core_ticks); sleep 5; read -r busy1 idle1 < <(core_ticks)
if (( 100 * (busy1 - busy0) / (busy1 - busy0 + idle1 - idle0) > 5 )); then
    echo "cpu${CPU} is in use: not started" >&2
    exit 75
fi
cool "${WHAT}"

mkdir -p "${RUN}"
[[ "${MARKER:-DRY_RUN}" == none ]] || echo "${MARKER:-DRY_RUN}: nothing in this directory may be quoted as a result." > "${RUN}/${MARKER:-DRY_RUN}"
# what an early session is compared with when the campaign commit is fixed (CAMPAIGN.md)
{
    echo "commit=${COMMIT}"
    echo "order_seed=${SEED:-none: fixed order}"
    echo "compile_cmd=$(ninja -C "${BUILD}" -t commands bench_crypto_ops 2> /dev/null | grep -m 1 -F bench_crypto_ops.c || echo unavailable)"
    sha256sum "${TREE}/bench/bench_crypto_ops.c" "${TREE}/bench/bench_common.h" "${BUILD}/bench_crypto_ops" "${LIBOQS_ROOT}/build/lib/liboqs.a"
    [[ "${WHAT}" != e2 ]] || sha256sum "${TREE}/bench/bench_overhead_paired.c" "${BUILD}/bench_overhead_paired"
    [[ "${WHAT}" != e1a ]] || sha256sum "${TREE}/bench/bench_sign_attrib.c" "${BUILD}/bench_sign_attrib"
} > "${RUN}/harness_${HOST}.txt"
if [[ "${WHAT}" == e2 && "${E2_BLOCK:-both}" == ab ]]; then
    # the margin exists before the first A/B launch: that is what makes it pre-registered
    cp "${MARGIN_FILE}" "${RUN}/equivalence_margin.txt"
    echo "margin_file=${MARGIN_FILE} sha256=$(sha256sum "${RUN}/equivalence_margin.txt" | cut -d' ' -f1) copied=$(date -Is)" >> "${RUN}/harness_${HOST}.txt"
fi

# mlockall() needs more than the 8 MB an unprivileged shell gets on these boards
sudo -n prlimit --pid $$ --memlock=unlimited:unlimited
"${TREE}/scripts/capture_env.sh" before "${RUN}/env_${HOST}.txt" "${LIBOQS_ROOT}" "${COMMIT}"

if [[ "${WHAT}" == e1 ]]; then
    D="${RUN}/crypto_ops"; mkdir -p "${D}"
    if [[ "${E1_OPS:-all}" == all ]]; then
        SWEEP=mldsa_sign,mldsa_verify
        STEPS="sign_p8 ${N_SIGN:-1000000} 14 mldsa_sign"$'\n'"other_p8 ${N_OTHER:-100000} 14 mldsa_verify,mldsa_keygen,mlkem_keygen,mlkem_encaps,mlkem_decaps,hkdf,hmac_gen,hmac_verify"
    else
        SWEEP=mldsa_verify
        STEPS="other_p8 ${N_OTHER:-100000} 14 mldsa_verify,mlkem_encaps,hmac_verify"
    fi
    for P in 64 256 1024; do STEPS+=$'\n'"p${P} ${N_SWEEP:-20000} $((P + 6)) ${SWEEP}"; done
    echo "${STEPS}" | order > "${RUN}/order.txt"
    while read -r name n msg ops <&3; do
        cool "${name}"
        snapshot "${name}" start none
        run "${D}" taskset -c "${CPU}" "${BUILD}/bench_crypto_ops" --ctx-bytes 64 --n "${n}" --msg-bytes "${msg}" --ops "${ops}" \
            --out "${D}/crypto_ops_${name}.csv" > "${D}/stdout_${name}.txt" || { echo "${name}: bench_crypto_ops failed" >> "${RUN}/EXCLUDED"; }
        snapshot "${name}" end none
    done 3< "${RUN}/order.txt"
elif [[ "${WHAT}" == e1a ]]; then
    D="${RUN}/crypto_attrib"; mkdir -p "${D}"
    echo "sign_attrib_p8 ${N_SIGN:-1000000} 14 mldsa_sign" > "${RUN}/order.txt"
    cool sign_attrib_p8
    snapshot sign_attrib_p8 start none
    run "${D}" taskset -c "${CPU}" "${BUILD}/bench_sign_attrib" --ctx-bytes 64 --n "${N_SIGN:-1000000}" --msg-bytes 14 ${COUNT_SHAKE:+--count-shake} \
        --out "${D}/sign_attrib_p8.csv" > "${D}/stdout_sign_attrib_p8.txt" || { echo "sign_attrib_p8: bench_sign_attrib failed" >> "${RUN}/EXCLUDED"; }
    snapshot sign_attrib_p8 end none
elif [[ "${WHAT}" == e2 ]]; then
    D="${RUN}/overhead"; mkdir -p "${D}"
    case "${E2_BLOCK:-both}" in
        aa)   echo "aa ${SEED_AA:-2000}" ;;
        ab)   echo "ab ${SEED_AB:-1000}" ;;
        both) printf '%s\n' "aa ${SEED_AA:-2000}" "ab ${SEED_AB:-1000}" | order ;;
    esac > "${RUN}/order.txt"
    while read -r mode base <&3; do
        cool "${mode}"
        snapshot "${mode}" start none
        "${TREE}/scripts/run_overhead_launches.sh" "${BUILD}" "${D}" "${CPU}" "${mode}" "${LAUNCHES:-30}" "${PAIRS:-3000}" 14 "${base}" "${CTX_BYTES:-64}" \
            > "${D}/stdout_${mode}.txt" 2>&1 || { echo "${mode}: a launch of bench_overhead_paired failed (overhead/stdout_${mode}.txt)" >> "${RUN}/EXCLUDED"; }
        snapshot "${mode}" end none
    done 3< "${RUN}/order.txt"
else
    D="${RUN}/cyclictest"; mkdir -p "${D}"
    SECS="${CELL_SECONDS:-600}"
    OTHERS="$(echo ${LOAD_CPUS:-2})"
    [[ " ${OTHERS} " != *" ${CPU} "* ]] || { echo "LOAD_CPUS must not contain the measured cpu ${CPU}" >&2; exit 2; }
    LOAD="sign-cpu${OTHERS// /-}"
    printf '%s\n' "other idle" "fifo idle" "other ${LOAD}" "fifo ${LOAD}" | order > "${RUN}/order.txt"
    PIDS=""; WATCH=""
    trap 'kill ${PIDS} ${WATCH} 2> /dev/null || true' EXIT
    while read -r policy load <&3; do
        cool "${policy}_${load}"
        snapshot "${policy}_${load}" start "${load}"
        if [[ "${load}" != idle ]]; then
            # one signing process per load core, sized to outlast the cell
            for c in ${OTHERS}; do
                echo "taskset -c ${c} ${BUILD}/bench_crypto_ops --n $((SECS * 2000)) --msg-bytes 14 --ctx-bytes 64 --ops mldsa_sign --out /dev/null &" >> "${D}/cmd.txt"
                taskset -c "${c}" "${BUILD}/bench_crypto_ops" --n $((SECS * 2000)) --msg-bytes 14 --ctx-bytes 64 --ops mldsa_sign --out /dev/null > /dev/null &
                PIDS="${PIDS} $!"
            done
            # Three busy cores heat the board by several degrees in seconds. Stop the cell before
            # the firmware throttles: the flag that leaves stays set until a reboot.
            (
                taskset -cp "${OTHERS// /,}" "${BASHPID}" > /dev/null
                while sleep 2; do
                    if awk -v t="$(temp_c)" -v max="${STOP_AT_C:-78}" 'BEGIN {exit !(t >= max)}'; then
                        echo "${policy}_${load}: load and cyclictest stopped at $(temp_c) C" >> "${RUN}/EXCLUDED"
                        kill ${PIDS} 2> /dev/null || true
                        sudo -n pkill -INT -x cyclictest || true
                        break
                    fi
                done
            ) &
            WATCH=$!
            sleep 2
        fi
        run "${D}" "${TREE}/scripts/run_cyclictest.sh" "${D}" "${CPU}" "${SECS}" "${policy}" "${load}" \
            || { echo "${policy}_${load}: run_cyclictest.sh failed" >> "${RUN}/EXCLUDED"; }
        snapshot "${policy}_${load}" end "${load}"
        for p in ${PIDS}; do
            kill -0 "${p}" 2> /dev/null || { echo "${policy}_${load}: a load process ended before the cell did" >> "${RUN}/EXCLUDED"; break; }
        done
        if [[ -n "${PIDS}" ]]; then kill ${PIDS} ${WATCH} 2> /dev/null || true; wait ${PIDS} ${WATCH} 2> /dev/null || true; PIDS=""; WATCH=""; fi
    done 3< "${RUN}/order.txt"
    trap - EXIT
fi

"${TREE}/scripts/capture_env.sh" after "${RUN}/env_${HOST}.txt" "${LIBOQS_ROOT}" "${COMMIT}" || echo "capture_env.sh after: failed" >> "${RUN}/EXCLUDED"

# Validity, step by step, from the snapshots (a run is kept on file but excluded, with the reason).
# shortcut: other cores are judged by their average over a step, so a short burst inside a long
# step goes unseen; compare the process lists in the snapshots when in doubt.
awk -v pinned="cpu${CPU}" -v what="${WHAT}" -v loadcpus=" $(for c in ${LOAD_CPUS:-2}; do printf 'cpu%s ' "${c}"; done)" '
    {
        delete kv
        for (i = 1; i <= NF && $i !~ /^busiest=/; i++) { eq = index($i, "="); kv[substr($i, 1, eq - 1)] = substr($i, eq + 1) }
        s = kv["step"]
        if (substr(kv["throttled"], length(kv["throttled"])) != "0") print s ": get_throttled shows an active bit at " kv["phase"] " (" kv["throttled"] ")"
        if (kv["phase"] == "start") { for (k in kv) start[s, k] = kv[k]; next }
        if (kv["throttled"] != start[s, "throttled"]) print s ": get_throttled changed, " start[s, "throttled"] " -> " kv["throttled"]
        if (kv["temp_c"] + 0 >= 78) print s ": ended at " kv["temp_c"] " C"
        for (k in kv) if (k ~ /^cpu[0-9]+$/) {
            split(kv[k], e, "/"); split(start[s, k], b, "/")
            share = (e[1] - b[1]) / (e[2] - b[2] + 1)
            if (kv["load"] != "none" && kv["load"] != "idle" && index(loadcpus, " " k " ")) continue
            if (k != pinned && share > 0.20) printf "%s: %s was %.0f %% busy, nothing should run there\n", s, k, 100 * share
            if (k == pinned && what == "e0" && share > 0.10) printf "%s: %s was %.0f %% busy under cyclictest alone\n", s, k, 100 * share
        }
    }' "${GATES}" >> "${RUN}/EXCLUDED"
# With a flag already set since boot, a second event of the same kind during the run cannot be seen.
grep -o 'throttled=0x[0-9a-fA-F]*' "${GATES}" | sort -u | grep -v -x 'throttled=0x0' > "${RUN}/NOTE_throttled_since_boot" \
    || rm -f "${RUN}/NOTE_throttled_since_boot"

# Did each timing process have the core to itself, with its memory locked? (footer of the harness)
for f in "${RUN}"/crypto_ops/*.csv "${RUN}"/crypto_attrib/*.csv "${RUN}"/overhead/*.csv; do
    [[ -e "${f}" ]] || continue
    # paired files: both calls must have produced the same signature bytes, every time
    [[ "${f}" != */overhead/* ]] || { grep -qx '# signature_mismatches=0' "${f}" && grep -qx '# failed_calls=0' "${f}"; } \
        || echo "${f##*/}: signature mismatches or failed calls" >> "${RUN}/EXCLUDED"
    python3 "${TREE}/bench/check_csv.py" "${f}" >> "${RUN}/check.txt" 2>&1 || RC=1
    grep -qx "# commit=${COMMIT}" "${f}" || echo "${f##*/}: the binary was not built at ${COMMIT}" >> "${RUN}/EXCLUDED"
    awk -F= -v f="${f##*/}" '/^# wall_s=/ {w = $2} /^# cpu_s=/ {c = $2} /^# ctx_switches_involuntary=/ {i = $2} /^# mlockall=/ {m = $2}
        END {printf "%s: cpu_s/wall_s = %.4f, involuntary context switches = %d, mlockall = %s\n", f, c / w, i, m; exit (c / w < 0.97 || m != "ok")}' \
        "${f}" >> "${RUN}/core_share.txt" || echo "${f##*/}: cpu_s/wall_s below 0.97 or memory not locked (core_share.txt)" >> "${RUN}/EXCLUDED"
done
if [[ -s "${RUN}/EXCLUDED" ]]; then RC=1; cat "${RUN}/EXCLUDED" >&2; else rm -f "${RUN}/EXCLUDED"; fi
(cd "${RUN}" && find . -type f ! -name MANIFEST.sha256 | sort | xargs sha256sum > MANIFEST.sha256)
cat "${RUN}/core_share.txt" 2> /dev/null || true
echo "run directory: ${RUN} (exit ${RC})"
exit "${RC}"
