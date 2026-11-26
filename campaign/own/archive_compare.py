"""Independent second reading of the archived phase-comparison file of the submitted version (standalone against
Csm-integrated, two phases one after the other), compared key by key with the toolkit.

usage: python3 -I -B archive_compare.py <run_dir> <analysis_dir> <key_prefix>      (python3 -I -B archive_compare.py --self-test)
Reads <run_dir>/perf/phase_compare.csv itself: header phase,seq,ns_delta, one row per call with its time in ns, lines
that start with '#' are not data. Phases <letter>_Standalone_<Op> and <letter>_CsmIntegrated_<Op>; rows with seq < 1000
are the warm-up and are dropped; the rest of a phase is taken in the order of seq. Per operation, x = standalone and
y = Csm-integrated (two independent samples of m and n calls). Own rules, written from the definitions of the keys:
  counts, medians  n of each phase; median = mean of the two middle values of an even count; median y / median x - 1
  Hodges-Lehmann   the median of the m*n differences y_j - x_i (whole ns). 95 % interval: with the differences in
                   ascending order D(1) .. D(mn), from D(C) to D(mn + 1 - C), C = mn/2 - z(0.975) * sqrt(mn(m + n + 1)/12)
                   rounded DOWN (normal approximation of the Mann-Whitney count, no correction for ties)
  Mann-Whitney     U = pairs with y_j > x_i plus half of the pairs with y_j = x_i; two-sided p from the normal
                   approximation, variance corrected for ties, continuity correction 0.5. Cliff's delta = 2U/(mn) - 1
  TOST             on natural logarithms: d = mean log y - mean log x, Welch standard error, Welch-Satterthwaite degrees
                   of freedom; p = the larger of the two one-sided p against -log(1 + margin) and +log(1 + margin) (the
                   rule of e2_own.py), margins 1 % and 2 %; ratio of geometric means - 1 = exp(d) - 1 with the 90 %
                   interval exp(d -/+ t(0.95, df) * se) - 1
  block bootstrap  90 % interval (percentile method) of median y* / median x* - 1 over 2000 resamples: a resample of a
                   phase is ceil(n/100) blocks of 100 consecutive samples, each start drawn evenly from 0 .. n - 100 with
                   replacement, cut to n; the two phases are resampled independently; the ends are the 5th and 95th
                   percentile of type 7. The toolkit's random stream is NOT reproduced: 20 own bootstraps from an own
                   stream (numpy default_rng(SEED)); own value = their mean; standard error = their standard deviation
                   (n - 1), which is the sampling error of ONE bootstrap such as the toolkit's. Criterion, fixed before
                   the first run: |toolkit - own| <= 3 standard errors. These keys are written to own_checked_keys.txt
                   (key, toolkit value, own value, standard error, deviation in standard errors; tab-separated) and
                   never to own_compared_keys.txt.
Comparison: counts exactly, other values to nine significant digits (rel. 1e-9 and NO absolute allowance: the 1e-12 of
the other readers would accept any value for a p of 1e-32). A key computed here that the toolkit lacks is a difference.
  lag 1            lag-1 autocorrelation of each phase in the order of seq after the warm-up, the sample autocorrelation
                   function at lag 1 (the form of e1_compare.py): sum (x_i - m)(x_i+1 - m) / sum (x_i - m)^2. A phase
                   whose seq has a gap or a duplicate has none: then the toolkit's key is a difference
  run parameters   <prefix>.run.warmup, .block_len and .n_boot against the values this reader uses (1000, 100, 2000)
A value this reader cannot compute where the toolkit has the key is a difference, not a stop.
NOT compared, printed by name: the other run parameters (<prefix>.run.seed, .sim_draws, .sim_jobs, .trim): settings of
the toolkit that this reader does not use (its own random stream is another one by design).
Exit 0 only if every key computed here agrees and every bootstrap end meets the criterion.

A directory with perf/tx_perf_10k.csv instead (the archived signing series; README.txt of that directory): header
seq,phase,ns_delta,wallclock_ns, one row per call. The signing phase is the rows with phase = sign; its rows with
seq < 1000 are the warm-up. Keys <prefix>.crypto_ops.perf.sign.: n (calls after the warm-up), n_total, n_dropped,
exceed_10ms.k (calls with ns_delta above 10,000,000, strictly), exceed_10ms.p = k / n, exceed_10ms.cp95_lo and _hi
(exact two-sided Clopper-Pearson 95 % interval, by its definition), p50_us and p50_ms (type-7 median). Compared by
the same rule; the toolkit's other keys of the directory (other statistics, the other phases) are counted, not compared.
"""
import contextlib
import csv
import io
import math
import os
import site
import sys
from pathlib import Path

if sys.flags.no_user_site:      # python3 -I hides the user site-packages, where numpy is installed on the measuring workstation
    site.addsitedir(site.getusersitepackages())
import numpy as np  # noqa: E402
from scipy import optimize, stats as sps  # noqa: E402

WARMUP, BLOCK, N_BOOT, REPLICATES, SEED = 1000, 100, 2000, 20, 31415926
MARGINS = (0.01, 0.02)
KINDS = {"Standalone": "standalone", "CsmIntegrated": "csm"}
AGREED = []      # the full names of the keys that were compared with a toolkit value and are equal (Addendum F4)


def record_compared(analysis_dir, keys):
    """Addendum F4: <analysis_dir>/own_compared_keys.txt, the keys that this call compared with a toolkit value and found
    equal, one per line, sorted. Under e9_compare.py (OWN_COMPARED_KEYS=add) the readers of one call add to one file;
    a direct call writes its own set. A call that does not end in agreement leaves no key of its own."""
    path = Path(analysis_dir) / "own_compared_keys.txt"
    if path.parent.is_dir():
        old = path.read_text().split() if os.environ.get("OWN_COMPARED_KEYS") == "add" and path.exists() else []
        path.write_text("".join(k + "\n" for k in sorted({*old, *keys})))


def record_checked(analysis_dir, rows):
    """<analysis_dir>/own_checked_keys.txt: the bootstrap keys that agree within the sampling error, one per line, sorted:
    key, toolkit value, own value, standard error, deviation in standard errors (tab-separated). Same rules as
    record_compared."""
    path = Path(analysis_dir) / "own_checked_keys.txt"
    if path.parent.is_dir():
        old = path.read_text().splitlines() if os.environ.get("OWN_COMPARED_KEYS") == "add" and path.exists() else []
        lines = {**{line.split("\t")[0]: line for line in old}, **{r[0]: "\t".join(map(str, r)) for r in rows}}
        path.write_text("".join(lines[k] + "\n" for k in sorted(lines)))


def lag1(x):
    """Lag-1 autocorrelation of a series in its order: sum (x_i - m)(x_i+1 - m) / sum (x_i - m)^2, m the mean of all."""
    d = np.asarray(x, dtype=float)
    d = d - d.mean()
    return float(np.dot(d[:-1], d[1:]) / np.dot(d, d))


def read(path):
    """({operation: {"standalone" | "csm": times in ns after the warm-up, in the order of seq}}, the (operation, phase)
    whose seq has a gap or a duplicate)"""
    rows = {}
    with open(path, newline="") as f:
        for r in csv.DictReader(line for line in f if not line.startswith("#")):
            if int(r["seq"]) >= WARMUP:
                _, kind, op = r["phase"].split("_")
                rows.setdefault(op.lower(), {}).setdefault(KINDS[kind], []).append((int(r["seq"]), int(r["ns_delta"])))
    broken = {(op, k) for op, kinds in rows.items() for k, v in kinds.items() if any(b[0] - a[0] != 1 for a, b in zip(sorted(v), sorted(v)[1:]))}
    return {op: {k: np.array([ns for _, ns in sorted(v)], dtype=np.int64) for k, v in kinds.items()} for op, kinds in rows.items()}, broken


def median(a):
    s = np.sort(a)
    return (float(s[(len(s) - 1) // 2]) + float(s[len(s) // 2])) / 2


def pct7(a, p):
    """Percentile of type 7 (linear interpolation between order statistics), p as a fraction."""
    s, h = np.sort(a), (len(a) - 1) * p
    lo = math.floor(h)
    return float(s[lo] + (h - lo) * (s[min(lo + 1, len(s) - 1)] - s[lo]))


def hl_rank(m, n):
    """C of the 95 % interval D(C) .. D(mn + 1 - C) of the shift."""
    return math.floor(m * n / 2 - sps.norm.ppf(0.975) * math.sqrt(m * n * (m + n + 1) / 12))


def kth_difference(xs, y, k):
    """The k-th smallest (k from 1) of the differences y_j - x_i of whole numbers, xs in ascending order, without forming
    them: the smallest v such that at least k differences are <= v, by bisection on v. A difference is <= v exactly when
    x_i >= y_j - v, and their number comes from the position of y_j - v in xs."""
    lo, hi = int(y.min()) - int(xs[-1]), int(y.max()) - int(xs[0])      # the smallest and the largest difference
    while lo < hi:
        v = (lo + hi) // 2
        if int((len(xs) - np.searchsorted(xs, y - v, "left")).sum()) >= k:
            hi = v
        else:
            lo = v + 1
    return lo


def hodges_lehmann(x, y, in_memory=200_000_000):
    """(median of the differences y_j - x_i, D(C), D(mn + 1 - C)); the two bounds are None when C < 1. More than
    `in_memory` differences are not formed: the same order statistics are counted (kth_difference)."""
    if len(x) * len(y) > in_memory:
        xs, c, mn = np.sort(x), hl_rank(len(x), len(y)), len(x) * len(y)
        ranks = ((mn + 1) // 2, mn // 2 + 1, *((c, mn + 1 - c) if c >= 1 else ()))
        d = {k: float(kth_difference(xs, y, k)) for k in set(ranks)}
        return ((d[ranks[0]] + d[ranks[1]]) / 2, *([d[k] for k in ranks[2:]] or [None, None]))
    d = np.subtract.outer(y, x).ravel()
    c, mid = hl_rank(len(x), len(y)), ((d.size - 1) // 2, d.size // 2)
    ends = (c - 1, d.size - c) if c >= 1 else ()
    d.partition(sorted({*mid, *ends}))
    return ((float(d[mid[0]]) + float(d[mid[1]])) / 2, *([float(d[i]) for i in ends] or [None, None]))


def mann_whitney(x, y):
    """(U of y, two-sided p, Cliff's delta)."""
    m, n, xs = len(x), len(y), np.sort(x)
    u = (int(np.searchsorted(xs, y, "left").sum()) + int(np.searchsorted(xs, y, "right").sum())) / 2
    ties = np.unique(np.concatenate([x, y]), return_counts=True)[1].astype(float)
    var = m * n / 12 * (m + n + 1 - float((ties ** 3 - ties).sum()) / ((m + n) * (m + n - 1)))
    return u, min(1.0, 2 * float(sps.norm.sf((abs(u - m * n / 2) - 0.5) / math.sqrt(var)))), 2 * u / (m * n) - 1


def welch_log(x, y):
    """(d = mean log y - mean log x, its Welch standard error, Welch-Satterthwaite degrees of freedom)."""
    lx, ly = np.log(x), np.log(y)
    vx, vy = float(lx.var(ddof=1)) / len(x), float(ly.var(ddof=1)) / len(y)
    return float(ly.mean() - lx.mean()), math.sqrt(vx + vy), (vx + vy) ** 2 / (vx ** 2 / (len(x) - 1) + vy ** 2 / (len(y) - 1))


def tost_p(d, se, df, margin):
    delta = math.log1p(margin)
    return float(max(sps.t.sf((d + delta) / se, df), sps.t.cdf((d - delta) / se, df)))


def gm_ratio(d, se, df):
    """(ratio of geometric means - 1, lower end, upper end of its 90 % interval)."""
    h = float(sps.t.ppf(0.95, df)) * se
    return math.expm1(d), math.expm1(d - h), math.expm1(d + h)


def block_index(n, rng):
    """N_BOOT rows of n positions: blocks of BLOCK consecutive positions, each start drawn evenly from 0 .. n - BLOCK."""
    starts = rng.integers(0, n - BLOCK + 1, size=(N_BOOT, -(-n // BLOCK)))
    return (starts[:, :, None] + np.arange(BLOCK)).reshape(N_BOOT, -1)[:, :n]


def bootstrap_ends(x, y, rng):
    """(5th, 95th percentile) of median y* / median x* - 1 over N_BOOT resamples, the phases resampled independently."""
    mx = np.median(x[block_index(len(x), rng)], axis=1)
    my = np.median(y[block_index(len(y), rng)], axis=1)
    return pct7(my / mx - 1, 0.05), pct7(my / mx - 1, 0.95)


def sampling_check(theirs, replicates):
    """(own value = mean of the replicates, standard error = their standard deviation, (theirs - own) / standard error)."""
    own, se = float(np.mean(replicates)), float(np.std(replicates, ddof=1))
    return own, se, (theirs - own) / se if se else (0.0 if theirs == own else math.inf)


def own_numbers(x, y, rng):
    """({name: value} compared to nine digits, {name: the replicates of a bootstrap end}, Welch df) of one operation. A
    value that cannot be computed (an interval bound when C < 1) is None."""
    mx, my, hl, (_, p, delta), (d, se, df) = median(x), median(y), hodges_lehmann(x, y), mann_whitney(x, y), welch_log(x, y)
    own = {"median_standalone_us": mx / 1e3, "median_csm_us": my / 1e3, "hl_us": hl[0] / 1e3,
           "hl_ci95_lo_us": None if hl[1] is None else hl[1] / 1e3, "hl_ci95_hi_us": None if hl[2] is None else hl[2] / 1e3}
    own.update({k[:-2] + "ms": None if v is None else v / 1e3 for k, v in own.items()})
    own.update({"n_standalone": len(x), "n_csm": len(y), "median_rel_diff": my / mx - 1, "mann_whitney_p": p, "cliffs_delta": delta})
    for margin in MARGINS:
        t = f"tost_m{round(margin * 100)}pct_"
        own.update(zip((t + "gm_ratio_diff", t + "gm_ratio_diff_ci90_lo", t + "gm_ratio_diff_ci90_hi"), gm_ratio(d, se, df)))
        own[t + "p"] = tost_p(d, se, df, margin)
    ends = np.array([bootstrap_ends(x, y, rng) for _ in range(REPLICATES)])
    return own, {"median_rel_diff_bb90_lo": ends[:, 0], "median_rel_diff_bb90_hi": ends[:, 1]}, df


def cp95(k, n):
    """Exact two-sided 95 % interval of k out of n, by its definition: each bound is the share at which the binomial
    tail on the far side of k holds 2.5 %."""
    lo = 0.0 if k == 0 else optimize.brentq(lambda p: sps.binom.sf(k - 1, n, p) - 0.025, 0, 1, xtol=1e-15, rtol=1e-14)
    hi = 1.0 if k == n else optimize.brentq(lambda p: sps.binom.cdf(k, n, p) - 0.025, 0, 1, xtol=1e-15, rtol=1e-14)
    return lo, hi


def signing_series(rows):
    """{name: value} of the signing phase of a tx_perf file; rows: (seq, ns_delta) of the rows with phase = sign."""
    kept = np.array([ns for seq, ns in sorted(rows) if seq >= WARMUP], dtype=np.int64)
    k = int((kept > 10_000_000).sum())
    lo, hi = cp95(k, len(kept))
    return {"n": len(kept), "n_total": len(rows), "n_dropped": len(rows) - len(kept), "exceed_10ms.k": k, "exceed_10ms.p": k / len(kept),
            "exceed_10ms.cp95_lo": lo, "exceed_10ms.cp95_hi": hi, "p50_us": pct7(kept, 0.5) / 1e3, "p50_ms": pct7(kept, 0.5) / 1e6}


def tx_perf(path, analysis_dir, prefix, theirs):
    """The archived signing series: prints the comparison, returns True when every key computed here agrees."""
    with open(path, newline="") as f:
        rows = [(int(r["seq"]), int(r["ns_delta"])) for r in csv.DictReader(line for line in f if not line.startswith("#")) if r["phase"] == "sign"]
    own, head = signing_series(rows), f"{prefix}.crypto_ops.perf.sign."
    diffs = compare(head, own, theirs)
    print(f"sign: {own['n']} calls after the warm-up of {WARMUP} ({own['n_total']} rows); above 10 ms: {own['exceed_10ms.k']} = "
          f"{own['exceed_10ms.p'] * 100:.4f} % [{own['exceed_10ms.cp95_lo'] * 100:.4f}, {own['exceed_10ms.cp95_hi'] * 100:.4f}] (exact 95 %); median "
          f"{own['p50_us']} us; keys compared {len(own)}, differences {diffs}")
    print(f"toolkit keys of the directory not recomputed here: {len(set(theirs) - {head + k for k in own})} (other statistics of the signing phase, the other phases, run parameters)")
    return bool(rows) and not diffs


def compare(head, own, theirs):
    """Prints each difference; returns their number. A key the toolkit lacks is a difference, and so is a toolkit key
    whose value this reader could not compute (own None); None on both sides is no key. Counts are compared exactly,
    other values to nine digits."""
    bad = 0
    for key, a in own.items():
        b = theirs.get(head + key)
        if a is None and b is None:
            continue
        if a is None or b is None or not (float(b) == a if isinstance(a, int) else math.isclose(a, float(b), rel_tol=1e-9, abs_tol=0.0)):
            bad += 1
            print(f"DIFF {head}{key}: own {a!r}, toolkit {b}")
        else:
            AGREED.append(head + key)
    return bad


def self_test():
    arr = np.array
    assert median(arr([4, 1, 3, 2])) == 2.5 and median(arr([3, 1, 2])) == 2.0
    assert math.isclose(pct7(arr([5, 1, 4, 2, 3]), 0.05), 1.2) and pct7(arr([1, 2, 3, 4]), 0.5) == 2.5
    # tables of the Mann-Whitney count, two-sided 5 %: critical value 23 for 10 and 10, 2 for 5 and 5, so C = 24 and 3
    assert hl_rank(10, 10) == 24 and hl_rank(5, 5) == 3
    assert hodges_lehmann(arr([1, 2, 3]), arr([4, 5, 7])) == (3.0, None, None)      # differences 1 2 2 3 3 4 4 5 6
    assert hodges_lehmann(np.arange(50), np.arange(50) + 7)[0] == 7.0               # a pure shift is found
    assert [kth_difference(arr([1, 2, 3]), arr([4, 5, 7]), k) for k in range(1, 10)] == [1, 2, 2, 3, 3, 4, 4, 5, 6]     # the nine differences above
    assert lag1([1, 2, 3, 4]) == 0.25 and math.isclose(lag1([3, 1, 4, 1, 5, 9, 2, 6]), -593 / 3384, rel_tol=1e-12)      # by hand, as in e1_compare.py
    rng = np.random.default_rng(1)
    x, y = rng.integers(0, 1000, 20), rng.integers(0, 1000, 20)
    d, c = sorted(int(b) - int(a) for a in x for b in y), hl_rank(20, 20)
    assert c == 127 and hodges_lehmann(x, y) == ((d[199] + d[200]) / 2, d[c - 1], d[400 - c])
    assert hodges_lehmann(x, y, in_memory=0) == hodges_lehmann(x, y)                # counted without forming the differences: the same
    assert hodges_lehmann(x[:7], y[:9], in_memory=0) == hodges_lehmann(x[:7], y[:9])               # an odd number of differences
    with contextlib.redirect_stdout(io.StringIO()) as said:      # a value that cannot be computed: no key on both sides, else a difference
        counts = [compare("h.", {"a": None}, {}), compare("h.", {"a": None}, {"h.a": "1"}), compare("h.", {"a": 2}, {"h.a": "2.0"}), compare("h.", {"a": 2}, {})]
    assert counts == [0, 1, 0, 1] and AGREED[-1] == "h.a" and "own None" in said.getvalue()
    # by hand: y = 2 has one x below and two ties (2), the other three y lie above all four x: U = 14; one tie group of
    # three in eight values: variance 16/12 * (9 - 24/56) = 80/7; z = (14 - 8 - 0.5) / sqrt(80/7)
    u, p, delta = mann_whitney(arr([1, 2, 2, 3]), arr([2, 4, 5, 6]))
    assert u == 14 and math.isclose(p, 2 * sps.norm.sf(5.5 / math.sqrt(80 / 7))) and abs(p - 0.10376) < 5e-5
    assert delta == 0.75                                                            # 13 pairs above, 1 below, of 16
    assert mann_whitney(arr([1, 2, 3]), arr([1, 2, 3])) == (4.5, 1.0, 0.0)
    logs = np.exp(arr([0.0, 1.0, 2.0]))
    d, se, df = welch_log(logs, logs)
    assert d == 0 and math.isclose(se, math.sqrt(2 / 3)) and math.isclose(df, 4)    # equal n and variances: df = 2n - 2
    assert abs(tost_p(0, se, 4, math.expm1(2.132 * se)) - 0.05) < 1e-4              # t table: 2.132 at 95 %, 4 df
    gm = gm_ratio(0, se, 4)                                                         # the same table value in the interval
    assert gm[0] == 0 and abs(math.log1p(gm[2]) - 2.132 * se) < 1e-3 and math.isclose(math.log1p(gm[1]), -math.log1p(gm[2]))
    d, se, df = welch_log(logs, 1.5 * logs)                                         # every time 1.5 times longer: ratio - 1 = 0.5
    assert math.isclose(gm_ratio(d, se, df)[0], 0.5) and gm_ratio(d, se, df)[1] < 0.5 < gm_ratio(d, se, df)[2]
    d, se, df = welch_log(logs, np.exp(arr([1.0, 3.0, 5.0])))
    assert math.isclose(d, 2) and math.isclose(se, math.sqrt(5 / 3)) and math.isclose(df, 50 / 17)   # variances 1 and 4
    assert math.isclose(tost_p(0.004, 0.003, 50, 0.01), tost_p(-0.004, 0.003, 50, 0.01))       # symmetric margins on the log scale
    assert tost_p(math.log(1.03), 0.001, 100, 0.02) > 0.99 and tost_p(0, 0.001, 100, 0.02) < 1e-20
    assert math.isclose(tost_p(math.log1p(0.01), 0.003, 50, 0.01), 0.5)             # on the margin itself: p = 0.5
    idx = block_index(250, rng)
    inside = [j for j in range(1, 250) if j % BLOCK]
    assert idx.shape == (N_BOOT, 250) and idx.min() >= 0 and idx.max() <= 249
    assert (idx[:, inside] - idx[:, [j - 1 for j in inside]] == 1).all()            # runs of consecutive positions
    assert len(set(idx[:, 0].tolist())) > 100                                       # and the starts vary
    assert bootstrap_ends(np.full(300, 2.0), np.full(300, 3.0), rng) == (0.5, 0.5)
    lo, hi = bootstrap_ends(np.arange(1000.0, 2000.0), np.arange(1000.0, 2000.0), rng)
    assert lo < 0 < hi                                                              # equal phases: 0 lies inside
    assert sampling_check(4.0, [1.0, 2.0, 3.0]) == (2.0, 1.0, 2.0) and sampling_check(5.0, [2.0, 2.0])[2] == math.inf
    # the signing series, by hand: 1000 warm-up rows, then six calls of 5 ms and one each of 10 ms, 10 ms + 1 ns, 11 ms, 12 ms:
    # three above 10 ms (exactly 10 ms is not), share 0.3, table interval of 3 out of 10; median = mean of the 5th and 6th = 5 ms
    s = signing_series([(i, 99_000_000) for i in range(1000)] + list(enumerate([5_000_000] * 6 + [10_000_000, 10_000_001, 11_000_000, 12_000_000], 1000)))
    assert (s["n"], s["n_total"], s["n_dropped"], s["exceed_10ms.k"], s["exceed_10ms.p"], s["p50_us"], s["p50_ms"]) == (10, 1010, 1000, 3, 0.3, 5000.0, 5.0)
    assert abs(s["exceed_10ms.cp95_lo"] - 0.06674) < 5e-6 and abs(s["exceed_10ms.cp95_hi"] - 0.65245) < 5e-6
    lo, hi = cp95(0, 2000)
    assert lo == 0 and math.isclose(hi, 1 - 0.025 ** (1 / 2000), rel_tol=1e-12)     # closed form without a hit
    print("self-test ok")


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    self_test()
    AGREED.clear()
    run_dir, analysis_dir, prefix = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    record_compared(analysis_dir, [])    # a direct call starts the two files
    record_checked(analysis_dir, [])
    with open(Path(analysis_dir) / "numbers.csv", newline="") as f:
        theirs = {r["key"]: r["value"] for r in csv.DictReader(f) if r["key"].startswith(prefix + ".") and r["unit"] != "text"}
    if (run_dir / "perf" / "tx_perf_10k.csv").exists():      # the archived signing series
        ok = tx_perf(run_dir / "perf" / "tx_perf_10k.csv", analysis_dir, prefix, theirs)
        record_compared(analysis_dir, AGREED if ok else [])
        print("OWN-CHECK AGREES" if ok else "OWN-CHECK DISAGREES")
        sys.exit(0 if ok else 1)
    rng, compared, bad, outside, checked, mine = np.random.default_rng(SEED), 0, 0, 0, [], set()
    phases, broken = read(run_dir / "perf" / "phase_compare.csv")
    params = {"warmup": WARMUP, "block_len": BLOCK, "n_boot": N_BOOT}      # the settings of the definitions, as this reader uses them
    mine |= {f"{prefix}.run.{k}" for k in params}
    diffs = compare(f"{prefix}.run.", params, theirs)
    compared, bad = compared + len(params), bad + diffs
    print(f"run parameters: warm-up {WARMUP} rows, blocks of {BLOCK}, {N_BOOT} resamples; keys compared {len(params)}, differences {diffs}")
    for op, kinds in sorted(phases.items()):
        head = f"{prefix}.overhead_unpaired.perf.{op}."
        own, boot, df = own_numbers(kinds["standalone"], kinds["csm"], rng)
        own.update({f"lag1_{k}": None if (op, k) in broken else lag1(kinds[k]) for k in ("standalone", "csm")})
        mine |= {head + k for k in (*own, *boot)}
        diffs = compare(head, own, theirs)
        compared, bad = compared + len(own), bad + diffs
        print(f"{op}: n {own['n_standalone']} standalone, {own['n_csm']} Csm; medians {own['median_standalone_us']} and {own['median_csm_us']} us, "
              f"relative difference {own['median_rel_diff'] * 100:+.4f} %; Hodges-Lehmann shift {own['hl_us']} us "
              f"[{own['hl_ci95_lo_us']}, {own['hl_ci95_hi_us']}]; Mann-Whitney p {own['mann_whitney_p']:.6g}; geometric means "
              f"{own['tost_m1pct_gm_ratio_diff'] * 100:+.4f} % [{own['tost_m1pct_gm_ratio_diff_ci90_lo'] * 100:+.4f}, "
              f"{own['tost_m1pct_gm_ratio_diff_ci90_hi'] * 100:+.4f}] (90 %), Welch df {df:.3f}, TOST p {own['tost_m1pct_p']:.6g} at 1 %, "
              f"{own['tost_m2pct_p']:.6g} at 2 %; lag 1 " + ", ".join(f"{k} " + ("not computed (seq has a gap or a duplicate)" if own[f"lag1_{k}"] is None
                                                                                else f"{own[f'lag1_{k}']:.6g}") for k in ("standalone", "csm"))
              + f"; keys compared {len(own)}, differences {diffs}")
        for name, reps in boot.items():
            if head + name not in theirs:
                outside += 1
                print(f"DIFF {head}{name}: the toolkit has no such key")
                continue
            row = (head + name, theirs[head + name], *sampling_check(float(theirs[head + name]), reps))
            ok = abs(row[4]) <= 3
            outside += not ok
            checked.append(row)
            print(f"{head}{name}: toolkit {row[1]}, own {row[2]:.9g} (mean of {REPLICATES} own bootstraps, they run from {reps.min():.6g} "
                  f"to {reps.max():.6g}), standard error {row[3]:.3g}, deviation {row[4]:+.2f} standard errors: "
                  + ("agrees within the sampling error" if ok else "DIFF, outside 3 standard errors"))
    for key in sorted(set(theirs) - mine):
        print(f"NOT COMPARED {key}" + (" (a setting of the toolkit that this reader does not use)" if key.startswith(prefix + ".run.") else ""))
    print(f"keys compared {compared}, differences {bad}; bootstrap ends checked against the sampling error {len(checked)}, outside it {outside}")
    ok = bool(phases) and not bad and not outside
    record_compared(analysis_dir, AGREED if ok else [])
    record_checked(analysis_dir, checked if ok else [])
    print("OWN-CHECK AGREES" if ok else "OWN-CHECK DISAGREES")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
