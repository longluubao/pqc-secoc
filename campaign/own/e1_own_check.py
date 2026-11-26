"""Independent second reading of an E1 run directory (independent of the analysis toolkit).
usage: python3 e1_own_check.py <run_dir>   prints per op: n, median, mean, p99, p99.9, p99.99, max (us) and exceedance counts
with exact Clopper-Pearson 95 % intervals for mldsa_sign. Warm-up: seq < 1000 dropped per op and file."""
import sys, glob, os
import numpy as np
from scipy.stats import beta

def cp(k, n, a=0.05):
    lo = 0.0 if k == 0 else beta.ppf(a / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(1 - a / 2, k + 1, n - k)
    return lo, hi

run = sys.argv[1]
for f in sorted(glob.glob(os.path.join(run, "crypto_ops", "crypto_ops_*.csv"))):
    meta, ops = {}, {}
    with open(f) as fh:
        for line in fh:
            if line.startswith("#"):
                if "=" in line:
                    k, v = line[1:].strip().split("=", 1); meta[k] = v
                continue
            if line.startswith("op,"):
                continue
            op, seq, ns = line.rstrip("\n").split(",")
            if int(seq) >= 1000:
                ops.setdefault(op, []).append(int(ns))
    print(f"== {os.path.basename(f)}  msg_bytes={meta.get('msg_bytes')} ctx_bytes={meta.get('ctx_bytes')} commit={meta.get('commit','')[:12]} mlockall={meta.get('mlockall')} "
          f"freq {meta.get('freq_khz_start')}->{meta.get('freq_khz_end')} cpu_s/wall_s={float(meta.get('cpu_s','nan'))/float(meta.get('wall_s','nan')):.4f}")
    for op, v in ops.items():
        a = np.sort(np.array(v, dtype=np.int64)) / 1000.0
        n = len(a)
        q = lambda p: a[min(n - 1, int(np.ceil(p * n)) - 1)]   # nearest-rank percentile
        print(f"  {op:13s} n={n:7d} median={np.median(a):9.1f} mean={a.mean():9.1f} p99={q(0.99):9.1f} p99.9={q(0.999):9.1f} p99.99={q(0.9999):9.1f} max={a[-1]:9.1f} us")
        if op == "mldsa_sign" and n >= 100000:
            for thr in (5, 10, 15, 20):
                k = int((a > thr * 1000).sum()); lo, hi = cp(k, n)
                print(f"      P(t > {thr:2d} ms) = {k}/{n} = {100*k/n:.4f} %  CP95 [{100*lo:.4f} %, {100*hi:.4f} %]")
