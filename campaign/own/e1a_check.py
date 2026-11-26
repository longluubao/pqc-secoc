"""Independent second reading of an E1a run directory (sign_attrib: wall and thread CPU time per signing call).

usage: python3 e1a_check.py <run_dir>          (needs numpy: run WITHOUT -I)
Per file crypto_attrib/sign_attrib_*.csv (warm-up: seq < 1000 dropped):
  - consistency: sum of cpu_ns over ALL rows against the process's CPU time in the footer; rows with wall < cpu - 2 us
  - wall and cpu: median, mean, p99, p99.9, max (type 7)
  - off = wall - cpu (time the pinned thread did not run): median, p99.9, max, counts above 0.1, 1, 5 ms, total
  - the tail: for thresholds 5, 10, 15, 20 ms of WALL time: calls above; of these, calls whose cpu time is also
    above the threshold (the call computed that long); the largest off among them
  - with a fourth column shake_calls (run with --count-shake): rounds = (shake_calls - min) / step + 1 from the header;
    mean rounds, share of one-round calls, least-squares line cpu = a + b * rounds, the residuals, mean cpu time for
    1 to 8 rounds, and for each wall-time threshold the smallest number of rounds among the calls above it
Exit 0 if the consistency checks hold (cpu sum within 1 % of the footer; no row with wall < cpu - 2 us), else 1.
"""
import glob
import math
import os
import sys

import numpy as np


def t7(a, p):
    h = (len(a) - 1) * p
    lo = math.floor(h); hi = min(lo + 1, len(a) - 1)
    return a[lo] + (h - lo) * (a[hi] - a[lo])


def main():
    run = sys.argv[1]
    files = sorted(glob.glob(os.path.join(run, "crypto_attrib", "sign_attrib_*.csv")))
    if not files:
        print("no sign_attrib files"); return 2
    ok = True
    for f in files:
        meta, seq, wall, cpu, shake = {}, [], [], [], []
        for line in open(f):
            if line.startswith("#"):
                if "=" in line:
                    k, v = line[1:].strip().split("=", 1); meta[k] = v
                continue
            if line.startswith("seq,"):
                continue
            parts = line.rstrip("\n").split(",")
            seq.append(int(parts[0])); wall.append(int(parts[1])); cpu.append(int(parts[2]))
            if len(parts) > 3:
                shake.append(int(parts[3]))
        seq = np.array(seq); wall = np.array(wall, dtype=np.int64); cpu = np.array(cpu, dtype=np.int64)
        if not (seq == np.arange(len(seq))).all():
            print(f"{os.path.basename(f)}: seq is not contiguous from 0"); ok = False
        cpu_sum = cpu.sum() / 1e9
        foot = float(meta.get("cpu_s", "nan"))
        ratio = cpu_sum / foot if foot else float("nan")
        bad_rows = int((wall < cpu - 2000).sum())
        print(f"== {os.path.basename(f)} commit={meta.get('commit', '')[:12]} n={len(seq)} msg_bytes={meta.get('msg_bytes')} ctx_bytes={meta.get('ctx_bytes')} "
              f"mlockall={meta.get('mlockall')} freq {meta.get('freq_khz_start')}->{meta.get('freq_khz_end')} clock_order={meta.get('clock_order')}")
        print(f"   consistency: sum of cpu_ns {cpu_sum:.3f} s, footer cpu_s {foot:.3f} s, ratio {ratio:.4f}; footer wall_s {meta.get('wall_s')}; "
              f"rows with wall < cpu - 2 us: {bad_rows}; timer overhead mono {meta.get('timer_overhead_ns')} ns, cpu clock {meta.get('cpu_timer_overhead_ns')} ns; "
              f"involuntary switches {meta.get('ctx_switches_involuntary')}")
        if not (0.99 <= ratio <= 1.01) or bad_rows:
            ok = False
        keep = seq >= 1000
        w = np.sort(wall[keep]) / 1000.0; c = np.sort(cpu[keep]) / 1000.0
        off = (wall[keep] - cpu[keep]) / 1000.0
        o = np.sort(off)
        n = len(w)
        for name, a in (("wall", w), ("cpu ", c)):
            print(f"   {name}: n={n} median={t7(a, .5):9.1f} mean={a.mean():9.1f} p99={t7(a, .99):9.1f} p99.9={t7(a, .999):9.1f} max={a[-1]:9.1f} us")
        # off has a floor: the two reads of the thread CPU clock lie inside the wall interval, so every call shows a
        # few microseconds of "off" that were spent on the processor. Time really off the processor = off above the
        # floor (the median), summed over the calls that are more than 100 us above it; compare with the footer.
        floor = t7(o, .5)
        above = off[off - floor > 100] - floor
        foot_off = float(meta.get("wall_s", "nan")) - float(meta.get("cpu_s", "nan"))
        print(f"   off = wall - cpu: min={o[0]:.2f} median (floor)={floor:.2f} p99.9={t7(o, .999):.1f} max={o[-1]:.1f} us; above 0.1 ms: {int((off > 100).sum())}, "
              f"above 1 ms: {int((off > 1000).sum())}, above 5 ms: {int((off > 5000).sum())}")
        print(f"   off above the floor, calls more than 100 us above it: {len(above)} calls, {above.sum() / 1e6:.4f} s; footer wall_s - cpu_s (whole file): {foot_off:.3f} s; "
              f"raw sum of off (floor included, not a time off the processor): {off.sum() / 1e6:.3f} s")
        wk, ck = wall[keep] / 1e6, cpu[keep] / 1e6
        for thr in (5, 10, 15, 20):
            sel = wk > thr
            k = int(sel.sum())
            both = int((ck[sel] > thr).sum()) if k else 0
            worst = float(off[sel].max()) if k else 0.0
            print(f"   wall > {thr:2d} ms: {k:6d} calls; of these with cpu time also > {thr} ms: {both:6d}; largest off among them: {worst:.1f} us")
        if shake:
            if len(shake) != len(seq):
                print("   shake_calls column incomplete"); ok = False; continue
            smin, step = int(meta.get("shake_calls_min", 0)), int(meta.get("shake_calls_step", 0))
            sh = np.array(shake, dtype=np.int64)[keep]
            if step < 2 or ((sh - smin) % step).any() or (sh < smin).any():
                print(f"   shake_calls are not on the progression {smin} + k * {step}"); ok = False; continue
            r = (sh - smin) // step + 1
            cu = cpu[keep] / 1000.0
            b, a = np.polyfit(r, cu, 1)
            res = cu - (a + b * r)
            print(f"   rounds: counted {meta.get('shake_counted', '')[:40]}; min {smin}, step {step}; mean {r.mean():.3f}, one round: {100 * (r == 1).mean():.2f} %, "
                  f"largest {int(r.max())}")
            print(f"   cpu = {a:.1f} + {b:.2f} * rounds us (least squares, n={len(r)}); residual: sd {res.std():.1f}, p0.1 {t7(np.sort(res), .001):.1f}, "
                  f"p99.9 {t7(np.sort(res), .999):.1f}, min {res.min():.1f}, max {res.max():.1f} us; R^2 {1 - res.var() / cu.var():.6f}")
            print("   mean cpu by rounds: " + ", ".join(f"{k}: {cu[r == k].mean():.1f}" for k in range(1, 9) if (r == k).any()) + " us")
            for thr in (5, 10, 15, 20):
                sel = wk > thr
                if sel.any():
                    print(f"   wall > {thr:2d} ms: {int(sel.sum())} calls, rounds among them: min {int(r[sel].min())}, median {int(np.median(r[sel]))}, max {int(r[sel].max())}; "
                          f"calls with at least {int(r[sel].min())} rounds in the file: {int((r >= r[sel].min()).sum())}")
            # processor-time version (one descheduled call cannot move it) and a two-by-two against the fitted line:
            # rstar = smallest whole number of rounds for which the line a + b * rounds is above the threshold
            for thr in (5, 10, 15, 20):
                selc = ck > thr
                rstar = int(np.floor((thr * 1000.0 - a) / b)) + 1
                both = int((selc & (r >= rstar)).sum()); cpu_only = int((selc & (r < rstar)).sum())
                rounds_only = int((~selc & (r >= rstar)).sum()); neither = int((~selc & (r < rstar)).sum())
                extra = f", fewest rounds among cpu > {thr} ms: {int(r[selc].min())} (calls with at least that many: {int((r >= r[selc].min()).sum())})" if selc.any() else ""
                print(f"   cpu > {thr:2d} ms against rounds >= {rstar}: both {both}, cpu only {cpu_only}, rounds only {rounds_only}, neither {neither}{extra}")
                p1 = float((r == 1).mean())
                below = int((selc & (r < rstar - 1)).sum()); above_x = int((~selc & (r > rstar)).sum())
                print(f"      beyond the crossing round: cpu above with fewer than {rstar - 1} rounds: {below}; cpu not above with more than {rstar} rounds: {above_x}; "
                      f"share cpu > {thr} ms: {100 * selc.mean():.4f} %, share rounds >= {rstar}: {100 * (r >= rstar).mean():.4f} %, "
                      f"geometric with the measured one-round share: {100 * (1 - p1) ** (rstar - 1):.4f} %")
    print("E1A-CHECK PASS" if ok else "E1A-CHECK FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
