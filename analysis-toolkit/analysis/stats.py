"""Shared statistics.

Every function states which quantity it estimates; none silently substitutes another estimator.
Inputs may be in any unit, except the exact Hodges-Lehmann routines, which need integers (ns).
"""
import math

import numpy as np
from scipy import stats as sps

PCTS = (50, 90, 95, 99, 99.9, 99.99)


def lag1_autocorr(x):
    """Lag-1 sample autocorrelation r1 = sum((x_t - m)(x_{t+1} - m)) / sum((x_t - m)^2), x in the given
    order. None for an empty or constant series."""
    x = np.asarray(x, dtype=float)
    if x.size == 0:
        return None
    d = x - x.mean()
    ss = float(d @ d)
    return float(d[:-1] @ d[1:]) / ss if ss > 0 else None


def describe(x):
    """Sample summary: n, mean, sd (ddof=1), min, max, percentiles PCTS, cv = sd/mean, lag1.

    Percentiles are numpy's default estimator (Hyndman-Fan type 7: linear interpolation between order
    statistics), so with 10,000 points p99.99 is an interpolation between the two largest values.
    """
    x = np.asarray(x, dtype=float)
    if x.size == 0:
        return {"n": 0}
    mean = float(x.mean())
    sd = float(x.std(ddof=1)) if x.size > 1 else None
    out = {"n": int(x.size), "mean": mean, "sd": sd, "min": float(x.min()), "max": float(x.max())}
    out.update({f"p{p:g}": float(v) for p, v in zip(PCTS, np.quantile(x, np.array(PCTS) / 100))})
    out["cv"] = sd / mean if sd is not None and mean else None
    out["lag1"] = lag1_autocorr(x)
    return out


def mean_ci(x, level=0.95):
    """Mean of x with the Student-t confidence interval mean +/- t * sd / sqrt(n). Assumes independent
    samples; positively autocorrelated samples make it too narrow. Returns (mean, lo, hi)."""
    x = np.asarray(x, dtype=float)
    m = float(x.mean())
    if x.size < 2:
        return m, None, None
    h = float(sps.t.ppf((1 + level) / 2, x.size - 1) * x.std(ddof=1) / math.sqrt(x.size))
    return m, m - h, m + h


def moving_block_indices(n, block_len, n_rep, rng):
    """(n_rep, n) index matrix of moving-block resamples: each row concatenates ceil(n / block_len)
    blocks of block_len consecutive indices, block starts uniform on [0, n - block_len], cut to n."""
    if not 1 <= block_len <= n:
        raise ValueError(f"block_len must be in [1, n={n}], got {block_len}")
    n_blocks = -(-n // block_len)
    starts = rng.integers(0, n - block_len + 1, size=(n_rep, n_blocks))
    return (starts[:, :, None] + np.arange(block_len)).reshape(n_rep, n_blocks * block_len)[:, :n]


def block_bootstrap_quantile_ci(x, probs, block_len, n_boot, level, rng):
    """Percentile-method confidence intervals for the quantiles `probs` (type 7) of a serially
    dependent series x in acquisition order, by the moving-block bootstrap (Kuensch 1989).

    Covers the population quantile of a stationary series. Too narrow if block_len is shorter than
    the dependence range, and blind beyond the sample maximum, so intervals for extreme quantiles
    are optimistic. Returns an array of shape (len(probs), 2).
    """
    x = np.asarray(x, dtype=float)
    reps = np.empty((n_boot, len(probs)))
    step = max(1, 4_000_000 // x.size)  # keeps each index matrix near 32 MB
    for i in range(0, n_boot, step):
        idx = moving_block_indices(x.size, block_len, min(step, n_boot - i), rng)
        reps[i:i + len(idx)] = np.quantile(x[idx], probs, axis=1).T
    return np.quantile(reps, [(1 - level) / 2, (1 + level) / 2], axis=0).T


def block_bootstrap_ratio_of_medians_ci(a, b, block_len, n_boot, level, rng):
    """Percentile-method interval of median(b) / median(a) for two serially dependent series, each in acquisition
    order: every replicate resamples each series on its own in moving blocks (moving_block_indices), independently
    of the other. It sees dependence inside a series only: when the two series were measured one after the other, a
    change of the system between them is part of the ratio and no resampling can show it."""
    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    reps = np.empty(n_boot)
    step = max(1, 4_000_000 // max(a.size, b.size))  # keeps each index matrix near 32 MB
    for i in range(0, n_boot, step):
        k = min(step, n_boot - i)
        reps[i:i + k] = (np.median(b[moving_block_indices(b.size, block_len, k, rng)], axis=1)
                         / np.median(a[moving_block_indices(a.size, block_len, k, rng)], axis=1))
    return np.quantile(reps, [(1 - level) / 2, (1 + level) / 2])


def wilson_interval(k, n, level=0.95):
    """Wilson score interval (no continuity correction) for a binomial proportion with k successes
    in n independent trials. Clustered events (e.g. bursts of deadline misses) make it too narrow."""
    if n <= 0 or not 0 <= k <= n:
        raise ValueError(f"need 0 <= k <= n and n > 0, got k={k}, n={n}")
    z = sps.norm.ppf((1 + level) / 2)
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (0.0 if k == 0 else c - h), (1.0 if k == n else c + h)  # the exact end points, free of rounding


def clopper_pearson_upper(k, n, level=0.95):
    """One-sided exact (Clopper-Pearson) upper confidence bound for a binomial proportion: the p at
    which P(X <= k | n, p) = 1 - level. For k = 0 this is 1 - (1 - level)^(1/n) ("rule of three")."""
    if n <= 0 or not 0 <= k <= n:
        raise ValueError(f"need 0 <= k <= n and n > 0, got k={k}, n={n}")
    return 1.0 if k == n else float(sps.beta.ppf(level, k + 1, n - k))


def clopper_pearson_interval(k, n, level=0.95):
    """Two-sided exact (Clopper-Pearson) confidence interval for a binomial proportion: each tail
    holds (1 - level) / 2. Conservative: coverage is at least `level` for independent trials.
    Its upper end is larger than clopper_pearson_upper() at the same level, which is one-sided."""
    if n <= 0 or not 0 <= k <= n:
        raise ValueError(f"need 0 <= k <= n and n > 0, got k={k}, n={n}")
    tail = (1 - level) / 2
    return (0.0 if k == 0 else float(sps.beta.ppf(tail, k, n - k + 1)),
            1.0 if k == n else float(sps.beta.ppf(1 - tail, k + 1, n - k)))


def exceedance(x, threshold):
    """Empirical exceedance probability P(x > threshold) (strict) with its exact Clopper-Pearson and
    its Wilson 95% interval. Both assume independent samples."""
    k, n = int(np.count_nonzero(np.asarray(x) > threshold)), len(x)
    return {"k": k, "n": n, "p": k / n, "cp95": list(clopper_pearson_interval(k, n)),
            "wilson95": list(wilson_interval(k, n))}


def _ints(x, name):
    x = np.asarray(x)
    if x.dtype.kind not in "iu":
        raise TypeError(f"{name} must be an integer array (e.g. nanoseconds), got dtype {x.dtype}")
    return x.astype(np.int64)


def _kth_smallest(count_le, lo, hi, k):
    """k-th smallest (1-based) member of an integer multiset inside [lo, hi], given only
    count_le(v) = number of members <= v. Exact: bisection on integers."""
    while lo < hi:
        mid = (lo + hi) // 2
        if count_le(mid) >= k:
            hi = mid
        else:
            lo = mid + 1
    return lo


def _median_and_ci(count_le, lo, hi, total, null_sd, level):
    """Median of the multiset and the rank interval [X_(K), X_(total+1-K)] with
    K = floor(total/2 - z * null_sd); flooring K makes the interval conservative."""
    def kth(k):
        return _kth_smallest(count_le, lo, hi, k)
    est = kth((total + 1) // 2) if total % 2 else (kth(total // 2) + kth(total // 2 + 1)) / 2
    k = math.floor(total / 2 - sps.norm.ppf((1 + level) / 2) * null_sd)
    return (est, kth(k), kth(total + 1 - k)) if k >= 1 else (est, None, None)


def hodges_lehmann_two_sample(a, b, level=0.95):
    """Hodges-Lehmann estimate of the shift of b relative to a for independent samples: the median of
    all len(a)*len(b) differences b_j - a_i, with the distribution-free confidence interval from
    inverting the Mann-Whitney test, [D_(K), D_(nm+1-K)], K = floor(nm/2 - z*sqrt(nm(n+m+1)/12))
    (large-sample normal approximation, no tie correction; Hollander & Wolfe).

    This is the median of the difference between one b and one a. It equals the difference of the
    medians only under a pure location shift. Inputs must be integers; the order statistics are
    found exactly without forming the nm differences. Returns (estimate, lo, hi); lo and hi are
    None when the samples are too small for the level.
    """
    a, b = np.sort(_ints(a, "a")), _ints(b, "b")
    n, m = a.size, b.size

    def count_le(v):  # pairs with b_j - a_i <= v, i.e. a_i >= b_j - v
        return n * m - int(np.searchsorted(a, b - v, side="left").sum())

    return _median_and_ci(count_le, int(b.min() - a.max()), int(b.max() - a.min()), n * m,
                          math.sqrt(n * m * (n + m + 1) / 12), level)


def hodges_lehmann_paired(d, level=0.95):
    """Hodges-Lehmann estimate for paired differences d: the median of the n(n+1)/2 Walsh averages
    (d_i + d_j)/2, i <= j, with the confidence interval from inverting the Wilcoxon signed-rank
    test, [W_(K), W_(N+1-K)], N = n(n+1)/2, K = floor(N/2 - z*sqrt(n(n+1)(2n+1)/24)) (large-sample
    normal approximation, no tie correction).

    This is the pseudo-median of the differences. It equals their median only if the distribution of
    the differences is symmetric. d must be integers. Returns (estimate, lo, hi); lo and hi are
    None when n is too small for the level.
    """
    d = np.sort(_ints(d, "d"))
    n, rank = d.size, np.arange(d.size)

    def count_le(v):  # pairs i <= j with d_i + d_j <= v
        return int(np.maximum(np.searchsorted(d, v - d, side="right") - rank, 0).sum())

    res = _median_and_ci(count_le, int(2 * d[0]), int(2 * d[-1]), n * (n + 1) // 2,
                         math.sqrt(n * (n + 1) * (2 * n + 1) / 24), level)
    return tuple(None if v is None else v / 2 for v in res)


def mann_whitney(a, b):
    """Two-sided Mann-Whitney U test of b against a, and Cliff's delta.

    The test's null hypothesis is stochastic equality, P(b > a) = P(b < a), not equality of medians
    (scipy: exact for small tie-free samples, otherwise normal approximation with tie and
    continuity correction). Cliff's delta = P(b > a) - P(b < a) over all cross pairs = 2U/(nm) - 1.
    Returns (p, delta); p is None when every value is tied, where the test is undefined.
    """
    r = sps.mannwhitneyu(b, a, alternative="two-sided")
    p = float(r.pvalue)
    return (None if math.isnan(p) else p), float(2 * r.statistic / (len(a) * len(b)) - 1)


def wilcoxon_p(a, b):
    """Two-sided Wilcoxon signed-rank p-value for the paired differences b - a (zero differences
    dropped; scipy chooses exact or normal approximation). Null: the differences are symmetric
    about zero. None when every difference is zero."""
    d = np.asarray(b) - np.asarray(a)
    return float(sps.wilcoxon(d).pvalue) if np.any(d) else None


def _log(x):
    x = np.asarray(x, dtype=float)
    if x.size == 0 or x.min() <= 0:
        raise ValueError("log-time TOST needs a non-empty sample of strictly positive times")
    return np.log(x)


def _tost(d, se, df, margin, alpha):
    m = math.log1p(margin)
    if se > 0:
        p = float(max(sps.t.sf((d + m) / se, df), sps.t.cdf((d - m) / se, df)))
    else:
        p = 0.0 if abs(d) < m else 1.0
    h = float(sps.t.ppf(1 - alpha, df)) * se
    return {"margin": margin, "p": p, "equivalent": p < alpha, "alpha": alpha, "gm_ratio": math.exp(d),
            "gm_ratio_ci": [math.exp(d - h), math.exp(d + h)], "ci_level": 1 - 2 * alpha, "df": float(df)}


def tost_log_two_sample(a, b, margin, alpha=0.05):
    """Equivalence of two independent samples by two one-sided Welch t-tests on log-times.

    Tests the ratio of GEOMETRIC means GM(b)/GM(a) (means of log-times), not medians and not
    arithmetic means. H0: ratio <= 1/(1+margin) or ratio >= 1+margin; H1: ratio strictly inside.
    Returns the larger one-sided p, the ratio and its (1 - 2*alpha) confidence interval;
    p < alpha is the same statement as that interval lying inside the margin.
    """
    la, lb = _log(a), _log(b)
    va, vb = la.var(ddof=1) / la.size, lb.var(ddof=1) / lb.size
    df = (va + vb) ** 2 / (va ** 2 / (la.size - 1) + vb ** 2 / (lb.size - 1)) if va + vb > 0 else la.size + lb.size - 2
    return _tost(float(lb.mean() - la.mean()), math.sqrt(va + vb), df, margin, alpha)


def tost_log_values(d, margin, alpha=0.05):
    """Equivalence from a sample of log-ratios d (one per pair, or one per launch) by two one-sided
    one-sample t-tests: tests exp(mean(d)), the GEOMETRIC mean of the ratios, against the region
    (1/(1+margin), 1+margin), treating the d as independent draws. Same return value as
    tost_log_two_sample; df = len(d) - 1."""
    d = np.asarray(d, dtype=float)
    if d.size < 2:
        raise ValueError("a TOST on log-ratios needs at least two values")
    return _tost(float(d.mean()), float(d.std(ddof=1)) / math.sqrt(d.size), d.size - 1, margin, alpha)


def tost_log_paired(a, b, margin, alpha=0.05):
    """Equivalence of paired samples: tost_log_values() on the log-ratios log(b_i / a_i). Tests the
    GEOMETRIC mean of the paired ratios b_i/a_i; the pairs are treated as independent, which holds
    within one process launch but ignores launch-to-launch variation."""
    return tost_log_values(_log(b) - _log(a), margin, alpha)


def longest_run(mask):
    """Length of the longest run of consecutive True values."""
    m = np.concatenate(([0], np.asarray(mask, dtype=np.int8), [0]))
    edges = np.flatnonzero(np.diff(m))
    return int((edges[1::2] - edges[::2]).max(initial=0))


def max_in_window(mask, k):
    """Largest number of True values in any window of k consecutive entries (the m of a weakly-hard
    (m, k) bound actually observed). None if there are fewer than k entries."""
    c = np.concatenate(([0], np.cumsum(np.asarray(mask, dtype=np.int64))))
    return int((c[k:] - c[:-k]).max()) if len(c) > k else None


def poisson_loglinear(x, y, tol=1e-12, max_iter=200):
    """Maximum-likelihood fit of independent Poisson counts y with log E[y] = a + b x (Poisson
    regression with a log link, by Newton's method). Returns (a, b, se_b, mu): the standard error of
    b from the Fisher information, 1 / sqrt(sum mu (x - xbar)^2) with xbar the mu-weighted mean of x,
    and the fitted means mu. The standard error is right only if the counts are independent and the
    log-linear model holds; callers that doubt the model scale it by a dispersion estimate."""
    x, y = np.asarray(x, dtype=float), np.asarray(y, dtype=float)
    if x.size != y.size or x.size < 2 or np.unique(x).size < 2 or np.any(y < 0) or y.sum() == 0:
        raise ValueError("poisson_loglinear needs at least two distinct x and non-negative counts that are not all 0")
    design = np.column_stack([np.ones_like(x), x])
    beta = np.linalg.lstsq(design, np.log(np.maximum(y, 0.5)), rcond=None)[0]  # start: least squares on the logs
    for _ in range(max_iter):
        mu = np.exp(design @ beta)
        step = np.linalg.solve(design.T @ (design * mu[:, None]), design.T @ (y - mu))
        beta = beta + step
        if np.abs(step).max() < tol:
            break
    else:
        raise ValueError("poisson_loglinear did not converge")
    mu = np.exp(design @ beta)
    cov = np.linalg.inv(design.T @ (design * mu[:, None]))
    return float(beta[0]), float(beta[1]), float(math.sqrt(cov[1, 1])), mu
