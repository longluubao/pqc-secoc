"""Independent second reading of an E1 run directory, compared key by key with the toolkit's numbers.csv.

usage: python3 -I -B e1_compare.py <run_dir> <analysis_dir> <key_prefix>      (python3 -I -B e1_compare.py --self-test)
(needs numpy and scipy; under -I the user site-packages are added, as in periodic_compare.py; without -I it runs too)
Reads crypto_ops/crypto_ops_<step>.csv itself (warm-up: seq < 1000 dropped per operation), computes n, min, mean, max,
the type-7 percentiles (written out by hand here, not numpy's percentile) and, for ML-DSA signing, the exceedance
counts with exact Clopper-Pearson 95 % intervals, and compares each with <prefix>.crypto_ops.<step>.<op>.<stat>.
Prints one line per operation and every disagreement; exit 0 only if every compared key agrees (rel. 1e-9).
The nearest-rank percentile is printed next to type 7 so the size of the definition effect is on file.

Also recomputed, from the definitions of number_keys.md alone (own code, nothing of the toolkit); these keys are
compared to a relative 1e-9 with no absolute floor, which is exact for a count:
  <op>.sd_us, <op>.cv   standard deviation of the post-warm-up times and sd / mean. The definition says "sd" without its
                     divisor: n - 1, as the docstring of the toolkit's describe() states it (settled there)
  header.off_cpu_s   wall_s - cpu_s of the '# key=value' footer of the file
  <op>.lag1          lag-1 autocorrelation of the post-warm-up series in the order of seq, the sample autocorrelation
                     function at lag 1: sum (x_i - m)(x_i+1 - m) / sum (x_i - m)^2, m the mean of all n values
  mldsa_sign, per threshold T of 5, 10, 15, 20 ms, k the calls above T (strictly):
    exceed_<T>ms.adjacent_pairs.k                 pairs of calls consecutive in seq that are both above T
    exceed_<T>ms.adjacent_pairs_if_independent    (n - 1) (k / n)^2
    exceed_<T>ms.p_squared_estimate               (k / n)^2
  mldsa_sign.excess_over_10ms_s, _calls           sum of (t - 10 ms) over the calls above 10 ms, and their number
  mldsa_sign.tail_* (only where the toolkit has tail_ratio_per_ms): see tail_fit(). tail_ratio_per_ms, tail_ratio_lo,
    tail_ratio_hi and tail_dispersion come from an ITERATIVE fit (Poisson regression by Newton's method) and are
    compared to a relative 1e-6; the range and the counts of the fit (tail_fit_from_ms, tail_fit_to_ms, tail_fit_bins,
    tail_above_fit_end) are compared exactly.
Each operation's rows are put in the order of seq first. Where a key cannot be computed (the pairs and lag 1 when seq
has a gap or a duplicate; the tail fit with fewer than 3 bins or without convergence) and the toolkit has the key, it is
recorded as a disagreement: the other keys are still compared and the run ends with its count line and OWN-CHECK FAILS.
"""
import csv
import glob
import math
import os
import site
import sys
from pathlib import Path

if sys.flags.no_user_site:      # python3 -I hides the user site-packages, where numpy is installed on the measuring workstation
    site.addsitedir(site.getusersitepackages())
import numpy as np  # noqa: E402
from scipy.stats import beta, t as student_t  # noqa: E402


def cp(k, n, a=0.05):
    lo = 0.0 if k == 0 else beta.ppf(a / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(1 - a / 2, k + 1, n - k)
    return lo, hi


def type7(a, p):          # a sorted; linear interpolation between order statistics (Hyndman-Fan type 7)
    h = (len(a) - 1) * p
    lo = math.floor(h)
    hi = min(lo + 1, len(a) - 1)
    return a[lo] + (h - lo) * (a[hi] - a[lo])


def nearest(a, p):
    return a[min(len(a) - 1, math.ceil(p * len(a)) - 1)]


def lag1(x):
    """Lag-1 autocorrelation of a series in its order: sum (x_i - m)(x_i+1 - m) / sum (x_i - m)^2, m the mean of all."""
    d = np.asarray(x, dtype=float)
    d = d - d.mean()
    return float(np.dot(d[:-1], d[1:]) / np.dot(d, d))


def above(ns, thr_ns):
    """(calls above the threshold, pairs of consecutive calls that are both above it, time beyond it in those calls
    in ns) of an integer series in the order of seq; exactly the threshold is not above it."""
    over = ns > thr_ns
    return int(over.sum()), int((over[:-1] & over[1:]).sum()), int((ns[over] - thr_ns).sum())


def if_independent(k, n):
    """((k / n)^2, (n - 1) (k / n)^2): the square of the share above a threshold, and the number of pairs of consecutive
    calls both above it that n independent calls with that share would give."""
    return (k / n) ** 2, (n - 1) * (k / n) ** 2


def by_seq(rows):
    """(the times of the (seq, ns) rows in the order of seq, whether seq runs on without a gap or a duplicate). The
    adjacent pairs and lag 1 are defined in the order of seq and need every call to have its neighbour."""
    rows = sorted(rows)
    return [ns for _, ns in rows], all(b[0] - a[0] == 1 for a, b in zip(rows, rows[1:]))


def off_cpu(meta):
    """wall_s - cpu_s of the '# key=value' footer: the seconds of the file in which the process was not on a processor."""
    return float(meta["wall_s"]) - float(meta["cpu_s"])


def poisson_line(x, y):
    """Maximum-likelihood line of a Poisson regression with log link, y_j ~ Poisson(exp(a + b x_j)): Newton's method on
    the log-likelihood from the least-squares line of log(y + 1/2), until the step is below 1e-12.
    Returns b, its standard error from the Fisher information X'WX with W = diag(mu), and Pearson's chi-square
    sum (y - mu)^2 / mu divided by len(y) - 2."""
    x, y = np.asarray(x, dtype=float), np.asarray(y, dtype=float)
    X = np.column_stack([np.ones(len(x)), x - x.mean()])      # centred: b and its error are the same, the system is better conditioned
    coef = np.linalg.lstsq(X, np.log(y + 0.5), rcond=None)[0]
    for _ in range(100):
        mu = np.exp(X @ coef)
        step = np.linalg.solve(X.T @ (mu[:, None] * X), X.T @ (y - mu))
        coef = coef + step
        if np.abs(step).max() < 1e-12:
            break
    else:
        raise ValueError("Poisson regression: Newton's method did not converge")
    mu = np.exp(X @ coef)
    var_b = np.linalg.inv(X.T @ (mu[:, None] * X))[1, 1]
    return float(coef[1]), math.sqrt(var_b), float(((y - mu) ** 2 / mu).sum() / (len(y) - 2))


def tail_fit(ns, median_ms, least=100):
    """The tail fit as number_keys.md words it. Thresholds are whole milliseconds and 'above' is strict, as in exceed_*:
    from = the first whole millisecond above the median, to = the last one with at least `least` samples above it,
    bin j (from <= j < to) = the samples above j ms that are not above j + 1 ms. Poisson regression of the bin counts
    on j; ratio = exp(-slope), the factor by which the count falls per millisecond; 95 % interval
    exp(-slope -/+ t se), se the standard error of the slope scaled by sqrt(max(1, dispersion)), dispersion = Pearson
    chi-square / (bins - 2), t the 97.5 % point of Student's t with bins - 2 degrees of freedom (the residual ones;
    the toolkit's summary.json states them in the fit's 'method' field: 'Student-t (bins - 2 degrees of freedom)').
    ValueError when the fit cannot be made: fewer than 3 bins, or no convergence."""
    def n_above(ms):
        return int((ns > ms * 1_000_000).sum())
    first = math.floor(median_ms) + 1
    last = first
    while n_above(last + 1) >= least:
        last += 1
    if last - first < 3:
        raise ValueError(f"{last - first} bins from {first} ms to {last} ms, at least 3 are needed")
    counts = [n_above(j) - n_above(j + 1) for j in range(first, last)]
    b, se, dispersion = poisson_line(range(first, last), counts)
    half = float(student_t.ppf(0.975, len(counts) - 2)) * se * math.sqrt(max(1.0, dispersion))
    return {"tail_fit_from_ms": first, "tail_fit_to_ms": last, "tail_fit_bins": len(counts), "tail_above_fit_end": n_above(last),
            "tail_ratio_per_ms": math.exp(-b), "tail_ratio_lo": math.exp(-b - half), "tail_ratio_hi": math.exp(-b + half),
            "tail_dispersion": dispersion}


def record_compared(analysis_dir, keys):
    """Addendum F4: <analysis_dir>/own_compared_keys.txt, the keys that this call compared with a toolkit value and found
    equal, one per line, sorted. Under e9_compare.py (OWN_COMPARED_KEYS=add) the readers of one call add to one file;
    a direct call writes its own set. A call that does not end in agreement leaves no key of its own."""
    path = Path(analysis_dir) / "own_compared_keys.txt"
    if path.parent.is_dir():
        old = path.read_text().split() if os.environ.get("OWN_COMPARED_KEYS") == "add" and path.exists() else []
        path.write_text("".join(k + "\n" for k in sorted({*old, *keys})))


def self_test():
    """Every statistic added to the reader, on data whose answer is known by hand."""
    assert lag1([1, 2, 3, 4]) == 0.25                 # (-1.5 x -0.5 + -0.5 x 0.5 + 0.5 x 1.5) / 5; Pearson of the shifted series would give 1
    assert math.isclose(lag1([1, -1] * 50), -0.99, rel_tol=1e-12) and math.isclose(lag1([3, 1, 4, 1, 5, 9, 2, 6]), -593 / 3384, rel_tol=1e-12)
    ms = np.array([11, 12, 3, 11, 11, 11, 10, 2], dtype=np.int64) * 1_000_000        # exactly 10 ms is not above 10 ms
    assert above(ms, 10_000_000) == (5, 3, 6_000_000) and above(ms, 20_000_000) == (0, 0, 0) and above(ms[:1], 10_000_000) == (1, 0, 1_000_000)
    assert by_seq([(1001, 5), (1000, 3), (1002, 4)]) == ([3, 5, 4], True)             # rows out of order in the file: put in the order of seq
    assert by_seq([(1000, 1), (1002, 2)])[1] is False and by_seq([(1000, 1), (1000, 2), (1001, 3)])[1] is False and by_seq([(1000, 7)]) == ([7], True)
    assert math.isclose(float(np.array([1.0, 2, 3, 4]).std(ddof=1)), math.sqrt(5 / 3), rel_tol=1e-15)      # the sd with the divisor n - 1
    assert if_independent(2, 4) == (0.25, 0.75) and if_independent(0, 9) == (0, 0) and off_cpu({"wall_s": "3.5", "cpu_s": "3.25"}) == 0.25
    # counts 4, 2, 1 at x = 0, 1, 2 lie on a line exactly: slope -ln 2, variance of the slope S0 / (S0 S2 - S1^2) = 7 / 26, chi-square 0
    b, se, dispersion = poisson_line([0, 1, 2], [4, 2, 1])
    assert math.isclose(b, -math.log(2), rel_tol=1e-12) and math.isclose(se, math.sqrt(7 / 26), rel_tol=1e-12) and abs(dispersion) < 1e-18
    assert math.isclose(poisson_line([5, 6, 7], [4, 2, 1])[1], se, rel_tol=1e-12)     # a shift of x changes neither
    # counts off the line: the fit is the point where both score equations hold, sum (y - mu) = 0 and sum x (y - mu) = 0
    x, y = np.array([2.0, 3, 4, 5]), np.array([900.0, 380, 260, 90])
    b, se, dispersion = poisson_line(x, y)
    a = math.log(y.sum() / np.exp(b * x).sum())
    mu = np.exp(a + b * x)
    assert abs((x * (y - mu)).sum()) < 1e-7 and math.isclose(dispersion, ((y - mu) ** 2 / mu).sum() / 2, rel_tol=1e-9) and dispersion > 1
    # the same counts as the bins of a series (median 1.5 ms, 100 samples above 6 ms): the dispersion is above 1 and
    # widens the interval by its square root; Student's t with 2 degrees of freedom has the quantile (2p - 1) / sqrt(2p(1 - p))
    t2 = 0.95 / math.sqrt(2 * 0.975 * 0.025)
    fit = tail_fit(np.array([1_500_000] * 5000 + [2_500_000] * 900 + [3_500_000] * 380 + [4_500_000] * 260 + [5_500_000] * 90
                            + [6_500_000] * 100, dtype=np.int64), 1.5)
    half = t2 * se * math.sqrt(dispersion)
    assert (fit["tail_fit_from_ms"], fit["tail_fit_to_ms"], fit["tail_fit_bins"]) == (2, 6, 4) and fit["tail_dispersion"] == dispersion
    assert math.isclose(fit["tail_ratio_lo"], math.exp(-b - half), rel_tol=1e-9) and math.isclose(fit["tail_ratio_hi"], math.exp(-b + half), rel_tol=1e-9)
    # a series with the median at 1.5 ms and 1600, 800, 400, 200, 100, 0 samples above 2, 3, 4, 5, 6, 7 ms; one sample of
    # exactly 3 ms, which is not above 3 ms: fit from 2 to 6 ms (the last threshold with 100 above it), bins 800, 400,
    # 200, 100, ratio 2, variance of the slope S0 / (S0 S2 - S1^2) = 1500 / (1500 x 2100 - 1100^2) = 3 / 3880
    series = np.array([1_500_000] * 2000 + [2_500_000] * 799 + [3_000_000] + [3_500_000] * 400 + [4_500_000] * 200
                      + [5_500_000] * 100 + [6_500_000] * 100, dtype=np.int64)
    fit = tail_fit(series, 1.5)
    assert [fit[k] for k in ("tail_fit_from_ms", "tail_fit_to_ms", "tail_fit_bins", "tail_above_fit_end")] == [2, 6, 4, 100]
    half = t2 * math.sqrt(3 / 3880)    # 4 bins: 2 degrees of freedom; no dispersion, so no widening
    assert math.isclose(fit["tail_ratio_per_ms"], 2, rel_tol=1e-12) and abs(fit["tail_dispersion"]) < 1e-18
    assert math.isclose(fit["tail_ratio_lo"], 2 * math.exp(-half), rel_tol=1e-9) and math.isclose(fit["tail_ratio_hi"], 2 * math.exp(half), rel_tol=1e-9)
    fit = tail_fit(series, 2.0)        # a median of exactly 2 ms: the first whole millisecond ABOVE it is 3
    assert (fit["tail_fit_from_ms"], fit["tail_fit_bins"]) == (3, 3) and math.isclose(fit["tail_ratio_per_ms"], 2, rel_tol=1e-12)
    for median in (3.0, 5.5):          # from 4 ms two bins are left, from 6 ms none: no fit, said as a ValueError and not as a stop
        try:
            tail_fit(series, median)
            raise AssertionError("a fit with fewer than 3 bins")
        except ValueError as e:
            assert "at least 3 are needed" in str(e)
    print("self-test ok")
    return 0


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
    compared, bad = 0, []

    def check(key, mine, rel=1e-9, floor=1e-12):
        nonlocal compared
        if key not in tk:
            return
        compared += 1
        theirs = float(tk[key])
        if not math.isclose(mine, theirs, rel_tol=rel, abs_tol=floor):
            bad.append(f"{key}: own {mine!r} toolkit {theirs!r}")
        else:
            agreed.append(key)

    def cannot(key, why):
        """A key that the toolkit has and that this reader cannot compute from the file: a disagreement, not a stop."""
        nonlocal compared
        if key in tk:
            compared += 1
            bad.append(f"{key}: own not computed ({why}) toolkit {float(tk[key])!r}")

    files = sorted(glob.glob(os.path.join(run, "crypto_ops", "crypto_ops_*.csv")))
    if not files:
        print("no crypto_ops files"); return 2
    for f in files:
        step = os.path.basename(f)[len("crypto_ops_"):-len(".csv")]
        ops, meta = {}, {}
        with open(f) as fh:
            for line in fh:
                if line.startswith("#"):
                    name, _, value = line[1:].strip().partition("=")
                    meta[name] = value
                    continue
                if line.startswith("op,"):
                    continue
                op, seq, ns = line.rstrip("\n").split(",")
                if int(seq) >= 1000:
                    ops.setdefault(op, []).append((int(seq), int(ns)))
        if "wall_s" in meta and "cpu_s" in meta:
            check(f"{prefix}.crypto_ops.{step}.header.off_cpu_s", off_cpu(meta), floor=0.0)
        for op, rows in ops.items():
            v, in_order = by_seq(rows)
            gap = "seq has a gap or a duplicate"
            series = np.array(v, dtype=np.int64)                   # nanoseconds, in the order of seq
            a = np.sort(series) / 1000.0      # microseconds
            n = len(a)
            base = f"{prefix}.crypto_ops.{step}.{op}"
            check(f"{base}.n", n)
            check(f"{base}.min_us", float(a[0]))
            check(f"{base}.max_us", float(a[-1]))
            check(f"{base}.mean_us", float(a.mean()))
            if n > 1:
                check(f"{base}.sd_us", float(a.std(ddof=1)), floor=0.0)
                check(f"{base}.cv", float(a.std(ddof=1)) / float(a.mean()), floor=0.0)
            worst = 0.0
            for name, p in (("p50", .5), ("p90", .9), ("p95", .95), ("p99", .99), ("p99_9", .999), ("p99_99", .9999)):
                t7 = type7(a, p)
                check(f"{base}.{name}_us", float(t7))
                worst = max(worst, abs(nearest(a, p) - t7))
            line = (f"{step:9s} {op:13s} n={n:7d} p50={type7(a, .5):9.1f} mean={a.mean():9.1f} p99={type7(a, .99):9.1f} "
                    f"p99.9={type7(a, .999):9.1f} p99.99={type7(a, .9999):9.1f} max={a[-1]:9.1f} us | nearest-rank differs by at most {worst:.1f} us")
            print(line)
            if in_order:
                r1 = lag1(series)
                check(f"{base}.lag1", r1, floor=0.0)
                print(f"            lag-1 autocorrelation {r1:.6g}")
            else:
                cannot(f"{base}.lag1", gap)
                print(f"            lag-1 autocorrelation: not computed, {gap}")
            if op == "mldsa_sign":
                for thr in (5, 10, 15, 20):
                    k = int((a > thr * 1000).sum())
                    lo, hi = cp(k, n)
                    check(f"{base}.exceed_{thr}ms.k", k)
                    check(f"{base}.exceed_{thr}ms.p", k / n)
                    check(f"{base}.exceed_{thr}ms.cp95_lo", lo)
                    check(f"{base}.exceed_{thr}ms.cp95_hi", hi)
                    print(f"            P(t > {thr:2d} ms) = {k}/{n} = {100 * k / n:.4f} %  CP95 [{100 * lo:.4f} %, {100 * hi:.4f} %]")
                    calls, pairs, beyond_ns = above(series, thr * 1_000_000)
                    squared, expected = if_independent(calls, n)
                    if in_order:
                        check(f"{base}.exceed_{thr}ms.adjacent_pairs.k", pairs, floor=0.0)
                    else:
                        pairs = f"not computed ({gap})"
                        cannot(f"{base}.exceed_{thr}ms.adjacent_pairs.k", gap)
                    check(f"{base}.exceed_{thr}ms.adjacent_pairs_if_independent", expected, floor=0.0)
                    check(f"{base}.exceed_{thr}ms.p_squared_estimate", squared, floor=0.0)
                    print(f"              adjacent pairs above {thr} ms: {pairs}, {expected:.6g} expected if independent; (k/n)^2 = {squared:.6g}")
                    if thr == 10:
                        check(f"{base}.excess_over_10ms_calls", calls, floor=0.0)
                        check(f"{base}.excess_over_10ms_s", beyond_ns / 1e9, floor=0.0)
                        print(f"              time beyond 10 ms in those {calls} calls: {beyond_ns / 1e9:.9f} s")
                fit = None
                if f"{base}.tail_ratio_per_ms" in tk:
                    try:
                        fit = tail_fit(series, type7(a, .5) / 1000.0)
                    except ValueError as e:      # also numpy's LinAlgError of a singular system
                        for name in ("tail_fit_from_ms", "tail_fit_to_ms", "tail_fit_bins", "tail_above_fit_end", "tail_ratio_per_ms", "tail_ratio_lo",
                                     "tail_ratio_hi", "tail_dispersion"):
                            cannot(f"{base}.{name}", f"tail fit: {e}")
                        print(f"            tail fit: not computed, {e}")
                if fit:
                    for name, mine in fit.items():      # the floats are results of the iterative fit: relative 1e-6
                        check(f"{base}.{name}", mine, rel=1e-6 if isinstance(mine, float) else 1e-9, floor=0.0)
                    print(f"            tail fit, {fit['tail_fit_bins']} bins of 1 ms from {fit['tail_fit_from_ms']} to {fit['tail_fit_to_ms']} ms "
                          f"({fit['tail_above_fit_end']} above): count falls by {fit['tail_ratio_per_ms']:.9g} per ms "
                          f"[{fit['tail_ratio_lo']:.9g}, {fit['tail_ratio_hi']:.9g}], dispersion {fit['tail_dispersion']:.9g} "
                          f"(iterative fit: these four compared to a relative 1e-6)")
    for b in bad:
        print("DISAGREE:", b)
    print(f"compared {compared} keys with the toolkit, {len(bad)} disagreements")
    record_compared(ana, agreed if compared and not bad else [])
    print("OWN-CHECK AGREES" if compared and not bad else "OWN-CHECK FAILS")
    return 0 if compared and not bad else 1


if __name__ == "__main__":
    sys.exit(main())
