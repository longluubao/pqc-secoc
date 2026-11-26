"""Independent second reading of an E1a run directory, compared key by key with the toolkit's numbers.csv.

usage: python3 -I e1a_compare.py <run_dir> <analysis_dir> <key_prefix>      (python3 -I e1a_compare.py --self-test)
Recomputes from crypto_attrib/sign_attrib_*.csv (warm-up seq < 1000 dropped) the quantities the manuscript will quote
and compares each with <prefix>.crypto_attrib.<file stem>.<key> where the toolkit has that key. The formulas are
written out here independently of the toolkit (see e1a_check.py for the printed report of the same quantities).
Exit 0 only if at least 20 keys per file were compared and none disagrees (relative 1e-6).
Added 2026-11-25 for a file with the shake_calls column, each of them compared as a count exactly or to nine
significant digits (no absolute allowance): header.shake_calls_min and header.shake_calls_step (the two '# key='
lines), resid_sd_us (root of the sum of the squared residuals of the least-squares line over n - 2),
rounds_at_least_threshold_<t>ms.share_cp95_lo/_hi (exact two-sided 95 % interval of k calls out of n, each bound
found from the binomial tail) and rounds_at_least_threshold_<t>ms.share_geometric_extrapolation, which is the
geometric share under the name it has when no call of the file reaches the threshold round: the reader makes the
key only then, and a toolkit key of that name at a threshold the file does reach is a disagreement.
line_and_law.<q>_cpu_rel_diff (q = p50, p99, p99_9) = line_and_law.<q>_cpu_us / cpu_<q>_us - 1; of these three, a key
that the toolkit lacks is a disagreement when the measured cpu_<q>_us is in numbers.csv and not held back (not listed
in suppressed_keys.txt of the analysis directory). Any other quantity the toolkit lacks is listed, as before.
"""
import csv
import glob
import math
import os
import re
import site
import sys
from pathlib import Path

if sys.flags.no_user_site:      # python3 -I hides the user site-packages, where numpy is installed on the measuring workstation
    site.addsitedir(site.getusersitepackages())
import numpy as np  # noqa: E402
from scipy import optimize, stats as sps  # noqa: E402


def t7(a, p):
    h = (len(a) - 1) * p
    lo = math.floor(h); hi = min(lo + 1, len(a) - 1)
    return float(a[lo] + (h - lo) * (a[hi] - a[lo]))


def cp95(k, n):
    """Exact two-sided 95 % interval of k out of n, by its definition: each bound is the share at which the binomial
    tail on the far side of k holds 2.5 %."""
    lo = 0.0 if k == 0 else optimize.brentq(lambda p: sps.binom.sf(k - 1, n, p) - 0.025, 0, 1, xtol=1e-15, rtol=1e-14)
    hi = 1.0 if k == n else optimize.brentq(lambda p: sps.binom.cdf(k, n, p) - 0.025, 0, 1, xtol=1e-15, rtol=1e-14)
    return lo, hi


def resid_sd(res):
    """sd of the residuals of a fitted line: two parameters were fitted, so the divisor is n - 2."""
    return math.sqrt(float(np.square(res).sum()) / (len(res) - 2))


def geometric_tail(p1, rounds):
    """Share of the calls with at least `rounds` rounds under a geometric law whose one-round share is p1."""
    return (1 - p1) ** (rounds - 1)


def law_rounds(p1, q):
    """The q-quantile of the number of rounds under a geometric law whose share of one-round calls is p1: the smallest r
    with 1 - (1 - p1)^r at or above q. None when p1 is not a share above 0."""
    if not 0 < p1 <= 1:
        return None
    r = 1
    while 1 - (1 - p1) ** r < q:
        r += 1
    return r


def over(model, measured):
    """model / measured - 1: by how much the figure of line and law lies above (+) or below (-) the measured percentile."""
    return model / measured - 1


def same(mine, theirs):
    """A count exactly, any other value to nine significant digits."""
    return float(theirs) == mine if isinstance(mine, int) else math.isclose(mine, float(theirs), rel_tol=1e-9, abs_tol=0.0)


def self_test():
    lo, hi = cp95(3, 10)                                                              # table value of 3 out of 10
    assert abs(lo - 0.06674) < 5e-6 and abs(hi - 0.65245) < 5e-6
    lo, hi = cp95(0, 500)
    assert lo == 0 and math.isclose(hi, 1 - 0.025 ** (1 / 500), rel_tol=1e-12)        # closed form without a hit
    lo, hi = cp95(500, 500)
    assert hi == 1 and math.isclose(lo, 0.025 ** (1 / 500), rel_tol=1e-12)
    x, y = np.array([1, 2, 3, 4]), np.array([1.0, 3.0, 2.0, 4.0])                     # line 0.5 + 0.8 x, residuals -.3 .9 -.9 .3
    b, a = np.polyfit(x, y, 1)
    assert math.isclose(resid_sd(y - (a + b * x)), math.sqrt(0.9), rel_tol=1e-12)     # 1.8 / (4 - 2)
    assert geometric_tail(0.5, 3) == 0.25 and geometric_tail(0.2, 1) == 1             # two failed rounds of one half each; every call has one round
    assert same(7, "7") and not same(7, "7.0000000001") and same(1.5, "1.5000000001") and not same(1.5, "1.50000001")
    assert not same(1.1e-7, "1.2e-7") and same(0.0, "0.0")                            # no absolute allowance for a small share
    # one-round share 1/2: half the calls have 1 round; 0.5^7 = 0.0078 is the first power at or below 0.01, 0.5^10 the first at or below 0.001
    assert [law_rounds(0.5, q) for q in (0.5, 0.99, 0.999)] == [1, 7, 10] and law_rounds(0.2, 0.5) == 4      # 0.8^3 = 0.512, 0.8^4 = 0.4096
    assert law_rounds(0.75, 0.9375) == 2 and law_rounds(1.0, 0.999) == 1 and law_rounds(0.0, 0.5) is None      # exactly at the share counts
    assert math.isclose(over(110.0, 100.0), 0.1, rel_tol=1e-12) and math.isclose(over(90.0, 100.0), -0.1, rel_tol=1e-12) and over(5.0, 5.0) == 0
    print("self-test ok")


def record_compared(analysis_dir, keys):
    """Addendum F4: <analysis_dir>/own_compared_keys.txt, the keys that this call compared with a toolkit value and found
    equal, one per line, sorted. Under e9_compare.py (OWN_COMPARED_KEYS=add) the readers of one call add to one file;
    a direct call writes its own set. A call that does not end in agreement leaves no key of its own."""
    path = Path(analysis_dir) / "own_compared_keys.txt"
    if path.parent.is_dir():
        old = path.read_text().split() if os.environ.get("OWN_COMPARED_KEYS") == "add" and path.exists() else []
        path.write_text("".join(k + "\n" for k in sorted({*old, *keys})))


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    self_test()
    run, ana, prefix = sys.argv[1:4]
    record_compared(ana, [])    # a direct call starts the file
    agreed, tk = [], {}
    with open(os.path.join(ana, "numbers.csv"), newline="") as fh:
        for r in csv.DictReader(fh):
            tk[r["key"]] = r["value"]
    held = Path(ana) / "suppressed_keys.txt"      # the keys the toolkit holds back from numbers.tex: key <tab> reason
    held = {l.split("\t")[0] for l in held.read_text().splitlines() if l[:1] != "#"} if held.exists() else set()
    files = sorted(glob.glob(os.path.join(run, "crypto_attrib", "sign_attrib_*.csv")))
    if not files:
        print("no sign_attrib files"); return 2
    ok = True
    for f in files:
        stem = os.path.basename(f)[:-4]
        meta, wall, cpu, shake = {}, [], [], []
        for line in open(f):
            if line.startswith("#"):
                if "=" in line:
                    k, v = line[1:].strip().split("=", 1); meta[k] = v
                continue
            if line.startswith("seq,"):
                continue
            p = line.rstrip("\n").split(",")
            if int(p[0]) >= 1000:
                wall.append(int(p[1])); cpu.append(int(p[2]))
                if len(p) > 3:
                    shake.append(int(p[3]))
        w = np.array(wall, dtype=np.int64) / 1000.0; c = np.array(cpu, dtype=np.int64) / 1000.0   # us
        off = w - c; n = len(w)
        own = {"wall_p50_us": t7(np.sort(w), .5), "wall_mean_us": float(w.mean()), "cpu_p50_us": t7(np.sort(c), .5), "cpu_mean_us": float(c.mean()),
               "n": n, "off_min_us": float(off.min()), "off_median_us": t7(np.sort(off), .5), "off_max_us": float(off.max()),
               "off_over_100us.k": int((off > 100).sum()), "off_over_1ms.k": int((off > 1000).sum()), "off_over_5ms.k": int((off > 5000).sum())}
        floor = own["off_median_us"]; sel = off - floor > 100
        own["off_above_floor.k"] = int(sel.sum()); own["off_above_floor_s"] = float((off[sel] - floor).sum() / 1e6)
        for t in (5, 10, 15, 20):
            ws, cs = w > t * 1000, c > t * 1000
            own[f"wall_over_{t}ms.k"] = int(ws.sum()); own[f"cpu_over_{t}ms.k"] = int(cs.sum())
            own[f"wall_over_{t}ms.cpu_also_over"] = int((ws & cs).sum())
            own[f"cpu_over_{t}ms.share"] = float(cs.mean())
            if ws.any():
                own[f"wall_over_{t}ms.max_off_us"] = float(off[ws].max())
        new, absent = {}, []      # the keys of 2026-11-25 (compared strictly), and the names the toolkit must not have
        new["cpu_p99_us"], new["cpu_p99_9_us"] = t7(np.sort(c), .99), t7(np.sort(c), .999)
        if shake:
            smin, step = int(meta["shake_calls_min"]), int(meta["shake_calls_step"])
            r = (np.array(shake, dtype=np.int64) - smin) // step + 1
            b, a = np.polyfit(r, c, 1)
            res = np.sort(c - (a + b * r))
            p1 = float((r == 1).mean())
            # line and law: the quantile of the rounds under the geometric law, and the fitted line of processor time at that many rounds
            for name, q in (("p50", 0.5), ("p99", 0.99), ("p99_9", 0.999)):
                rq = law_rounds(p1, q)
                if rq is not None:
                    new[f"line_and_law.{name}_rounds"], new[f"line_and_law.{name}_cpu_us"] = rq, float(a + b * rq)
                    new[f"line_and_law.{name}_cpu_rel_diff"] = over(float(a + b * rq), t7(np.sort(c), q))      # model over measured, minus 1
            new.update({"header.shake_calls_min": smin, "header.shake_calls_step": step, "resid_sd_us": resid_sd(res)})
            own.update({"rounds_mean": float(r.mean()), "rounds_one_share": p1, "rounds_max": int(r.max()), "rounds_mean_geometric": 1 / p1,
                        "cpu_per_round_us": float(b), "cpu_intercept_us": float(a), "r2": float(1 - res.var() / c.var()),
                        "resid_p0_1_us": t7(res, .001), "resid_p99_9_us": t7(res, .999), "resid_min_us": float(res[0]), "resid_max_us": float(res[-1])})
            for t in (5, 10, 15, 20):
                cs = c > t * 1000
                rstar = max(1, int(math.floor((t * 1000.0 - a) / b)) + 1)
                own[f"rounds_threshold_{t}ms"] = rstar
                own[f"cpu_vs_rounds_{t}ms.both"] = int((cs & (r >= rstar)).sum()); own[f"cpu_vs_rounds_{t}ms.cpu_only"] = int((cs & (r < rstar)).sum())
                own[f"cpu_vs_rounds_{t}ms.rounds_only"] = int((~cs & (r >= rstar)).sum()); own[f"cpu_vs_rounds_{t}ms.neither"] = int((~cs & (r < rstar)).sum())
                own[f"cpu_vs_rounds_{t}ms.cpu_only_below_crossing"] = int((cs & (r < rstar - 1)).sum())
                own[f"cpu_vs_rounds_{t}ms.rounds_only_above_crossing"] = int((~cs & (r > rstar)).sum())
                own[f"rounds_at_least_threshold_{t}ms.k"] = int((r >= rstar).sum()); own[f"rounds_at_least_threshold_{t}ms.share"] = float((r >= rstar).mean())
                own[f"rounds_at_least_threshold_{t}ms.share_geometric"] = (1 - p1) ** (rstar - 1)
                if cs.any():
                    own[f"cpu_over_{t}ms.rounds_min"] = int(r[cs].min())
                    own[f"cpu_over_{t}ms.calls_with_rounds_min_or_more"] = int((r >= r[cs].min()).sum())
                head = f"rounds_at_least_threshold_{t}ms."
                new[head + "share_cp95_lo"], new[head + "share_cp95_hi"] = cp95(int((r >= rstar).sum()), n)
                if int(r.max()) < rstar:      # no call of the file has that many rounds: the geometric share is an extrapolation
                    new[head + "share_geometric_extrapolation"] = geometric_tail(p1, rstar)
                else:
                    absent.append(head + "share_geometric_extrapolation")
        compared, bad, missing = 0, [], []
        for k, v in {**own, **new}.items():
            key = f"{prefix}.crypto_attrib.{stem}.{k}"
            if key not in tk:
                measured = re.sub(r"line_and_law\.(\w+)_cpu_rel_diff$", r"cpu_\1_us", key)
                if measured != key and measured in tk and measured not in held:
                    bad.append(f"{key}: own {v!r}, the toolkit lacks it although {measured} is not held back")
                else:
                    missing.append(k)
                continue
            compared += 1
            if not (same(v, tk[key]) if k in new else math.isclose(float(v), float(tk[key]), rel_tol=1e-6, abs_tol=1e-9)):
                bad.append(f"{key}: own {v!r} toolkit {tk[key]!r}")
            else:
                agreed.append(key)
        for k in absent:
            if f"{prefix}.crypto_attrib.{stem}.{k}" in tk:
                bad.append(f"{prefix}.crypto_attrib.{stem}.{k}: toolkit {tk[f'{prefix}.crypto_attrib.{stem}.{k}']!r}, but the file has calls with that many rounds: no extrapolation")
        for x in bad:
            print("DISAGREE:", x)
        print(f"{stem}: n={n}, own quantities {len(own) + len(new)}, compared {compared}, disagreements {len(bad)}, not in the toolkit: {missing if missing else 'none'}")
        if bad or compared < 20:
            ok = False
    record_compared(ana, agreed if ok else [])
    print("OWN-CHECK AGREES" if ok else "OWN-CHECK FAILS")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
