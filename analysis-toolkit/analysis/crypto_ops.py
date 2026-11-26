"""crypto_ops.csv (op, seq, ns): single-node primitive timing."""
import math

import numpy as np
from scipy import stats as sps

from analysis import stats

EXCESS_MS = 10  # signing: the time beyond this many milliseconds, summed over the calls above it
TAIL_THRESHOLDS_MS = tuple(range(1, 26))  # whole milliseconds at which the samples above are counted
TAIL_MIN_N = 100_000        # a signing series needs this many values for the tail-shape output
# The fit range, fixed on 2026-11-23 on the E1 run that is now pilot B, before any E1 session of the campaign was measured:
TAIL_START_QUANTILE = 0.5   # from the first whole millisecond above this quantile of the sample (the median) ...
TAIL_MIN_COUNT = 100        # ... to the last whole millisecond with at least this many samples above it
TAIL_METHOD = ("Poisson regression (log link, maximum likelihood) of the counts in the 1-ms bins between the thresholds "
               "on the bin index; ratio per ms = exp(-slope); 95% interval: Wald on the log ratio with Student-t "
               "(bins - 2 degrees of freedom) and the standard error multiplied by sqrt(max(1, dispersion)), dispersion "
               "= Pearson chi-square / (bins - 2)")


def samples(cols, op, warmup):
    """Times (ns) of one op in seq order with seq < warmup dropped. A duplicate seq is an error."""
    sel = cols["op"] == op
    seq, ns = cols["seq"][sel], cols["ns"][sel]
    order = np.argsort(seq, kind="stable")
    seq, ns = seq[order], ns[order]
    dup = np.flatnonzero(seq[1:] == seq[:-1])
    if dup.size:
        raise ValueError(f"op {op}: seq {int(seq[dup[0]])} appears more than once")
    return ns[seq >= warmup]


def _tail_fit(above, start_ms):
    """The geometric fit of tail() from the threshold start_ms on, or None with fewer than 3 bins."""
    k = np.array(TAIL_THRESHOLDS_MS)
    use = np.flatnonzero((k >= start_ms) & (above >= TAIL_MIN_COUNT))  # counts above never rise: a contiguous range
    if use.size < 4 or k[use[0]] != start_ms:
        return None
    lo, hi = int(use[0]), int(use[-1])
    bins = (above[lo:hi] - above[lo + 1:hi + 1]).astype(float)  # values in (k, k + 1] ms for k = from_ms .. to_ms - 1
    intercept, slope, se, mu = stats.poisson_loglinear(np.arange(bins.size), bins)
    dispersion = float(((bins - mu) ** 2 / mu).sum() / (bins.size - 2))
    half = float(sps.t.ppf(0.975, bins.size - 2)) * se * math.sqrt(max(1.0, dispersion))
    ratio = math.exp(-slope)
    return {"from_ms": int(k[lo]), "to_ms": int(k[hi]), "bins": int(bins.size), "ratio_per_ms": ratio,
            "ratio_ci95": [math.exp(-slope - half), math.exp(-slope + half)], "dispersion": dispersion,
            "above_fit_end": int(above[hi]),
            # the fitted bin counts continued for ever hold exp(intercept) / (1 - 1 / ratio) values above from_ms
            "fitted_above_from": math.exp(intercept) / (1 - 1 / ratio) if ratio > 1 else None, "method": TAIL_METHOD}


def tail(x_us, start_ms=None):
    """Tail shape of a series of times (us): the number of values above each whole millisecond of
    TAIL_THRESHOLDS_MS, the largest value, and a fit of a geometric decay to the counts.

    Fit range, computed for the sample: from the first whole millisecond above its median
    (TAIL_START_QUANTILE; `start_ms` overrides it) to the last whole millisecond with at least
    TAIL_MIN_COUNT values above it ('from_ms', 'to_ms'). What is fitted are the counts in the 1-ms
    bins between consecutive thresholds of that range, not the counts above: those are nested in
    one another, so an interval from them would be too narrow, while the bin counts are separate
    samples. For a geometric tail both fall by the same factor per millisecond, 'ratio_per_ms'
    (TAIL_METHOD says how it and its interval are computed). 'dispersion' near 1 means the bin
    counts scatter around the fitted line as Poisson counts would; a large value means the decay is
    not geometric over the range, and the interval is widened by its square root. No fit with fewer
    than 3 bins ('fit_note' says so). 'above_fit_end' is the count above to_ms; 'share_above_from'
    the share of the sample that the fitted decay puts above from_ms (see tail_expected()).

    'from_1ms' is a sensitivity figure: ratio and dispersion of the same fit started at 1 ms
    whatever the median is.
    """
    x_us = np.asarray(x_us, dtype=float)
    above = np.array([int(np.count_nonzero(x_us > 1000.0 * t)) for t in TAIL_THRESHOLDS_MS])
    if start_ms is None:
        start_ms = math.floor(float(np.quantile(x_us, TAIL_START_QUANTILE)) / 1000.0) + 1
    out = {"thresholds_ms": list(TAIL_THRESHOLDS_MS), "counts_above": above.tolist(), "max_ms": float(x_us.max()) / 1000.0,
           "fit": _tail_fit(above, start_ms), "fit_note": None, "from_1ms": None}
    if out["fit"] is None:
        out["fit_note"] = (f"no fit: fewer than 3 one-millisecond bins between thresholds with at least {TAIL_MIN_COUNT} "
                           "samples above them")
    else:
        fitted = out["fit"].pop("fitted_above_from")
        out["fit"]["share_above_from"] = None if fitted is None else fitted / x_us.size
    if first := _tail_fit(above, 1):
        out["from_1ms"] = {k: first[k] for k in ("to_ms", "bins", "ratio_per_ms", "dispersion")}
    return out


def tail_expected(fit, x_ms, n):
    """Expected count above x_ms under the fitted decay, for n calls: n times the share that the fit
    puts above its from_ms, divided by ratio_per_ms for every millisecond from there to x_ms. Beyond
    to_ms this continues the fitted decay past the range it was fitted on. It is a statement about
    the fitted curve, not about why a value occurred. None below from_ms, where the fit says nothing."""
    if x_ms < fit["from_ms"] or fit["share_above_from"] is None:
        return None
    return n * fit["share_above_from"] * fit["ratio_per_ms"] ** -(x_ms - fit["from_ms"])


def _neighbours(above):
    """Of a series of calls in seq order, `above` a threshold or not: adjacent_pairs, the pairs of consecutive calls
    that are both above it; adjacent_pairs_if_independent = (n - 1) p^2, their expected number if the calls were
    independent with the measured share p = k / n; p_squared = p^2, which is also the share of signatures above the
    threshold if two independent attempts ran side by side and the first to finish were taken (an estimate from an
    assumption, not a measurement)."""
    p = float(np.count_nonzero(above)) / above.size
    return {"adjacent_pairs": int(np.count_nonzero(above[1:] & above[:-1])),
            "adjacent_pairs_if_independent": (above.size - 1) * p * p, "p_squared": p * p}


def analyse(cols, *, warmup, block_len, n_boot, thresholds_ms, rng):
    """Per op, in microseconds: describe() of the post-warm-up times; moving-block bootstrap 95% CIs
    for the median and p99 (only when at least two blocks fit); and, for signing ops (name contains
    'sign'), the exceedance probability P(t > d) with Wilson interval for each threshold d (ms),
    'excess_over_10ms' (the number of calls above EXCESS_MS and the sum of t - EXCESS_MS over them,
    in seconds: the time those calls spent beyond 10 ms each) and, when the series has at least
    TAIL_MIN_N values, its tail shape (tail())."""
    out = []
    for op in dict.fromkeys(cols["op"].tolist()):
        x = samples(cols, op, warmup) / 1e3
        n_total = int(np.count_nonzero(cols["op"] == op))
        r = {"op": op, "n_total": n_total, "n_warmup_dropped": n_total - x.size, "time_us": stats.describe(x)}
        if x.size >= 2 * block_len:
            ci = stats.block_bootstrap_quantile_ci(x, [0.5, 0.99], block_len, n_boot, 0.95, rng)
            r["bootstrap"] = {"method": "moving-block bootstrap, percentile interval", "block_len": block_len,
                              "n_boot": n_boot, "p50_ci95_us": ci[0].tolist(), "p99_ci95_us": ci[1].tolist()}
        if "sign" in op and x.size:
            r["exceedance"] = [{"threshold_ms": d, **stats.exceedance(x, 1e3 * d), **_neighbours(x > 1e3 * d)} for d in thresholds_ms]
            over = x[x > 1e3 * EXCESS_MS]
            r["excess_over_10ms"] = {"calls": int(over.size), "seconds": float((over - 1e3 * EXCESS_MS).sum() / 1e6)}
            if x.size >= TAIL_MIN_N:
                r["tail"] = tail(x)
        out.append(r)
    return out
