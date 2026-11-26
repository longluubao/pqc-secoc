#!/usr/bin/env bash
# scripts/run_overhead_launches.sh
#
# The paired standalone-versus-Csm experiment as separate process launches, back to back: the
# estimate moves from launch to launch (memory layout), so the launch is the unit of replication.
# Runs ON the Pi. One file per launch, overhead_paired_L<nn>.csv (mode ab) or
# overhead_paired_aa_L<nn>.csv (mode aa, the noise floor), each with "# launch=<n>" and its seed.
#
# Usage: scripts/run_overhead_launches.sh <build_dir> <outdir> <cpu> <ab|aa> <launches> <pairs> <msg_bytes> <base_seed> [ctx_bytes]
#   seed of launch n = base_seed + n; ctx_bytes defaults to 64 (see bench_overhead_paired --ctx-bytes)
# The memlock limit of the calling shell must already be raised (sudo prlimit --pid $$ --memlock=unlimited:unlimited).

set -euo pipefail
[[ $# -eq 8 || $# -eq 9 ]] || { sed -n '2,12p' "${BASH_SOURCE[0]}" >&2; exit 2; }
BUILD="$1"; OUTDIR="$2"; CPU="$3"; MODE="$4"; LAUNCHES="$5"; PAIRS="$6"; MSG="$7"; BASE="$8"; CTX="${9:-64}"
[[ "${MODE}" == ab || "${MODE}" == aa ]] || { echo "mode must be ab or aa" >&2; exit 2; }
PREFIX="overhead_paired"; [[ "${MODE}" == ab ]] || PREFIX="overhead_paired_aa"
mkdir -p "${OUTDIR}"
for n in $(seq "${LAUNCHES}"); do
    out="${OUTDIR}/${PREFIX}_L$(printf '%02d' "${n}").csv"
    cmd=(taskset -c "${CPU}" "${BUILD}/bench_overhead_paired" --n "${PAIRS}" --seed "$((BASE + n))" --msg-bytes "${MSG}"
         --ctx-bytes "${CTX}" --op both --mode "${MODE}" --launch "${n}" --out "${out}")
    echo "${cmd[*]}" >> "${OUTDIR}/cmd.txt"
    "${cmd[@]}" | tail -n 1
done
