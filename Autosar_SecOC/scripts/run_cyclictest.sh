#!/usr/bin/env bash
# scripts/run_cyclictest.sh
#
# Scheduling-latency baseline of one CPU: a 1 ms periodic wake-up measured by cyclictest, so the
# platform's own latency can be set next to the signing tail measured on the same core.
#
# Usage: scripts/run_cyclictest.sh <outdir> <cpu> <seconds> <fifo|other> [load_label]
#   fifo   SCHED_FIFO priority 80        other   SCHED_OTHER (default scheduler)
#   load_label says what else runs meanwhile, e.g. idle (default) or sign-cpu0-2; it is only recorded.
# Output: <outdir>/cyclictest_<policy>_cpu<cpu>_<load_label>.txt (run conditions as "# key=value", then the
#         latency histogram in 1 us buckets up to 5 ms and cyclictest's min/avg/max lines);
#         the command is appended to <outdir>/cmd.txt.
#
# Needs passwordless sudo and at least 2 seconds. cyclictest keeps /dev/cpu_dma_latency at 0 while
# it runs (its default).

set -euo pipefail

usage() {
    sed -n '2,14p' "${BASH_SOURCE[0]}" >&2
    exit 2
}
[[ $# -eq 4 || $# -eq 5 ]] || usage
OUTDIR="$1"
CPU="$2"
SECONDS_TO_RUN="$3"
POLICY="$4"
LOAD="${5:-idle}"
# cyclictest switches to SCHED_FIFO as soon as it sees a priority option, so "other" must not pass one.
case "${POLICY}" in
    fifo) PRIORITY=80; SCHED=(--policy=fifo --priority=80); EXPECT="^FF 80 ${CPU}\$" ;;
    other) PRIORITY=0; SCHED=(--policy=other); EXPECT="^TS - ${CPU}\$" ;;
    *) usage ;;
esac

FREQ="/sys/devices/system/cpu/cpu${CPU}/cpufreq"
[[ -r "${FREQ}/scaling_governor" ]] || { echo "no such cpu: ${CPU}" >&2; exit 2; }
OUT="${OUTDIR}/cyclictest_${POLICY}_cpu${CPU}_${LOAD}.txt"
CMD=(cyclictest --quiet --mlockall --affinity="${CPU}" --threads=1 --interval=1000
     --duration="${SECONDS_TO_RUN}" --histogram=5000 "${SCHED[@]}")

conditions() {
    echo "# freq_khz_$1=$(cat "${FREQ}/scaling_cur_freq")"
    echo "# temp_$1=$(vcgencmd measure_temp 2> /dev/null || cat /sys/class/thermal/thermal_zone0/temp)"
    echo "# throttled_$1=$(vcgencmd get_throttled 2> /dev/null || echo unavailable)"
}

mkdir -p "${OUTDIR}"
{
    echo "# tool=$(cyclictest --help 2>&1 | head -1)"
    echo "# host=$(hostname)"
    echo "# kernel=$(uname -srv)"
    echo "# date=$(date -Is)"
    echo "# cpu=${CPU}"
    echo "# policy=${POLICY}"
    echo "# load=${LOAD}"
    echo "# priority=${PRIORITY}"
    echo "# interval_us=1000"
    echo "# duration_s=${SECONDS_TO_RUN}"
    echo "# governor=$(cat "${FREQ}/scaling_governor")"
    conditions start
    echo "# cmd=sudo ${CMD[*]}"
} > "${OUT}"
sudo -n "${CMD[@]}" >> "${OUT}" &
sleep 1
# The policy asked for is not trusted: the scheduling class of the running threads is read back.
THREADS="$(ps -L -o cls=,rtprio=,psr= -C cyclictest | awk '{print $1, $2, $3}')"
wait $!
{
    echo "# threads_observed_class_rtprio_cpu=$(echo "${THREADS}" | paste -sd ';')"
    conditions end
} >> "${OUT}"
echo "sudo ${CMD[*]} >> ${OUT}" >> "${OUTDIR}/cmd.txt"

# A run cut short leaves a file without the summary; that must not pass for a measurement.
for want in '^[0-9]{6} [0-9]{6}' '^# Min Latencies:' '^# Avg Latencies:' '^# Max Latencies:'; do
    grep -Eq "${want}" "${OUT}" || { echo "${OUT}: cyclictest output is incomplete (no line matching ${want})" >&2; exit 1; }
done
echo "${THREADS}" | grep -Eq "${EXPECT}" || { echo "${OUT}: no cyclictest thread ran as ${POLICY} on cpu ${CPU}: ${THREADS}" >&2; exit 1; }
if [[ "${POLICY}" == "other" ]] && echo "${THREADS}" | grep -Eq '^(FF|RR) '; then
    echo "${OUT}: a cyclictest thread ran with a real-time policy: ${THREADS}" >&2
    exit 1
fi
grep -E '^# (Min|Avg|Max) Latencies|^# Histogram Overflows' "${OUT}"
