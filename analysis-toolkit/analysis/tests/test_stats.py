"""Every statistic against a hand-computed value, a brute-force computation, or an independent scipy route."""
import bisect
import math

import numpy as np
import pytest
from scipy import optimize
from scipy import stats as sps

from analysis import stats


def rng():
    return np.random.default_rng(12345)


# ---- descriptive ---------------------------------------------------------------------------------

def test_describe_hand_values():
    d = stats.describe([1, 2, 3, 4])
    assert (d["n"], d["mean"], d["min"], d["max"], d["p50"]) == (4, 2.5, 1.0, 4.0, 2.5)
    assert d["sd"] == pytest.approx(math.sqrt(5 / 3))
    assert d["p90"] == pytest.approx(3.7)  # type 7: 1 + 0.9 * (4 - 1)
    assert d["cv"] == pytest.approx(math.sqrt(5 / 3) / 2.5)
    d = stats.describe(np.arange(1, 12))  # 1..11: position p * 10 in the sorted sample
    assert [d[k] for k in ("p50", "p90", "p95", "p99")] == pytest.approx([6, 10, 10.5, 10.9])
    assert d["p99.9"] == pytest.approx(10.99) and d["p99.99"] == pytest.approx(10.999)


def test_describe_degenerate():
    assert stats.describe([]) == {"n": 0}
    d = stats.describe([5])
    assert d["n"] == 1 and d["sd"] is None and d["cv"] is None and d["lag1"] is None and d["p99"] == 5


def test_lag1_autocorr_hand_values():
    assert stats.lag1_autocorr(np.arange(5)) == pytest.approx(0.4)  # 4 / 10
    assert stats.lag1_autocorr([1, -1] * 5) == pytest.approx(-0.9)  # -(n - 1) / n
    assert stats.lag1_autocorr([3, 3, 3]) is None and stats.lag1_autocorr([]) is None


def test_mean_ci_hand_value():
    m, lo, hi = stats.mean_ci([1, 2, 3, 4, 5])  # t(0.975, 4) = 2.776445, se = 1.581139 / sqrt(5)
    assert (m, lo, hi) == pytest.approx((3, 3 - 1.963243, 3 + 1.963243), abs=1e-5)
    assert stats.mean_ci([7]) == (7.0, None, None)


def test_longest_run():
    assert stats.longest_run([]) == 0 and stats.longest_run([False]) == 0 and stats.longest_run([True]) == 1
    assert stats.longest_run([1, 1, 0, 1, 1, 1, 0]) == 3
    assert stats.longest_run([True] * 5) == 5


def test_max_in_window():
    mask = [1, 0, 1, 1, 0, 0, 1, 1, 1, 0]
    assert stats.max_in_window(mask, 1) == 1
    assert stats.max_in_window(mask, 3) == 3
    assert stats.max_in_window(mask, 10) == 6
    assert stats.max_in_window(mask, 11) is None
    for k in range(1, 11):  # brute force
        assert stats.max_in_window(mask, k) == max(sum(mask[i:i + k]) for i in range(len(mask) - k + 1))


# ---- binomial intervals --------------------------------------------------------------------------

def test_wilson_known_values():
    assert stats.wilson_interval(5, 10) == pytest.approx((0.236593, 0.763407), abs=1e-6)
    assert stats.wilson_interval(0, 10) == pytest.approx((0.0, 0.277533), abs=1e-6)  # z^2 / (n + z^2)
    assert stats.wilson_interval(0, 12)[0] == 0.0 and stats.wilson_interval(12, 12)[1] == 1.0  # exactly
    assert stats.wilson_interval(10, 10) == pytest.approx((1 - 0.277533, 1.0), abs=1e-6)
    lo, hi = stats.wilson_interval(17, 10_000)
    assert (round(100 * lo, 2), round(100 * hi, 2)) == (0.11, 0.27)


@pytest.mark.parametrize("k,n", [(0, 7), (1, 10), (17, 10_000), (999, 1000), (1000, 1000), (3, 24)])
def test_wilson_matches_scipy(k, n):
    ref = sps.binomtest(k, n).proportion_ci(0.95, method="wilson")
    assert stats.wilson_interval(k, n) == pytest.approx((ref.low, ref.high), abs=1e-12)


def test_wilson_rejects_bad_input():
    with pytest.raises(ValueError):
        stats.wilson_interval(1, 0)
    with pytest.raises(ValueError):
        stats.wilson_interval(5, 4)


def test_clopper_pearson_known_values():
    assert stats.clopper_pearson_upper(0, 10_000) == pytest.approx(1 - 0.05 ** 1e-4)  # 2.995e-4, "rule of three"
    assert stats.clopper_pearson_upper(0, 10_000) == pytest.approx(2.9953e-4, rel=1e-4)
    assert stats.clopper_pearson_upper(1, 10) == pytest.approx(0.394163, abs=1e-6)
    assert stats.clopper_pearson_upper(10, 10) == 1.0
    up = stats.clopper_pearson_upper(3, 50)  # defining property: P(X <= k | p_upper) = 0.05
    assert sps.binom.cdf(3, 50, up) == pytest.approx(0.05)


@pytest.mark.parametrize("k,n", [(0, 50), (1, 10), (3, 50), (10, 1000)])
def test_clopper_pearson_matches_scipy(k, n):
    ref = sps.binomtest(k, n, alternative="less").proportion_ci(0.95, method="exact").high
    assert stats.clopper_pearson_upper(k, n) == pytest.approx(ref, abs=1e-12)


def test_clopper_pearson_interval_known_values():
    assert stats.clopper_pearson_interval(5, 10) == pytest.approx((0.187086, 0.812914), abs=1e-6)  # textbook value
    lo, hi = stats.clopper_pearson_interval(1000, 1000)
    assert hi == 1.0 and lo == pytest.approx(0.025 ** (1 / 1000))  # 99.63%
    lo, hi = stats.clopper_pearson_interval(0, 1000)
    assert lo == 0.0 and hi == pytest.approx(1 - 0.025 ** (1 / 1000))
    lo, hi = stats.clopper_pearson_interval(3, 50)  # defining property: each tail holds 2.5%
    assert sps.binom.sf(2, 50, lo) == pytest.approx(0.025) and sps.binom.cdf(3, 50, hi) == pytest.approx(0.025)
    with pytest.raises(ValueError):
        stats.clopper_pearson_interval(3, 2)


@pytest.mark.parametrize("k,n", [(0, 7), (1, 10), (9, 10), (17, 10_000), (1000, 1000)])
def test_clopper_pearson_interval_matches_scipy(k, n):
    ref = sps.binomtest(k, n).proportion_ci(0.95, method="exact")
    assert stats.clopper_pearson_interval(k, n) == pytest.approx((ref.low, ref.high), abs=1e-12)


def test_tiny_p_values_are_not_lost_to_cancellation():
    """1 - cdf cannot go below about 1e-16. These test statistics sit 25 to 30 standard errors out,
    where the p-value is about 1e-140 to 1e-200: tiny, but far from underflow, so it must be nonzero."""
    r = rng()
    a = np.exp(r.normal(7.3, 0.0165, 4000))
    assert 0 < stats.tost_log_paired(a, a * np.exp(r.normal(0.0, 0.023, 4000)), 0.01)["p"] < 1e-100
    assert 0 < stats.tost_log_two_sample(a, np.exp(r.normal(7.3, 0.0165, 4000)), 0.01)["p"] < 1e-100
    assert 0 < stats.mann_whitney(a[:400], 2 * a[:400])[0] < 1e-100  # complete separation, n = m = 400: z = 24.5
    assert 0 < stats.wilcoxon_p(a[:1000], 2 * a[:1000]) < 1e-100  # all 1000 differences positive: z = 27.4


def test_exceedance_is_strict():
    e = stats.exceedance(np.array([1, 2, 3, 4, 5]), 3)
    assert (e["k"], e["n"], e["p"]) == (2, 5, 0.4)
    assert e["wilson95"] == list(stats.wilson_interval(2, 5))


# ---- Hodges-Lehmann ------------------------------------------------------------------------------

def test_kth_smallest_on_a_multiset():
    members = sorted([-7, -7, 0, 3, 3, 3, 10, 42])
    for k, want in enumerate(members, 1):
        assert stats._kth_smallest(lambda v: bisect.bisect_right(members, v), -7, 42, k) == want


def test_hl_two_sample_hand_values():
    assert stats.hodges_lehmann_two_sample([1, 2, 3], [4, 5, 7])[0] == 3  # diffs 1 2 2 3 3 4 4 5 6
    assert stats.hodges_lehmann_two_sample([0, 10], [1, 2])[0] == -3.5  # diffs -9 -8 1 2
    assert stats.hodges_lehmann_two_sample([5], [9]) == (4, None, None)


@pytest.mark.parametrize("n,m,span", [(2, 3, 5), (7, 5, 4), (30, 30, 6), (31, 28, 10**9), (60, 45, 50)])
def test_hl_two_sample_matches_brute_force(n, m, span):
    r = rng()
    a, b = r.integers(0, span, n), r.integers(0, span, m) + span // 3
    diffs = np.sort(np.subtract.outer(b, a).ravel())
    est, lo, hi = stats.hodges_lehmann_two_sample(a, b)
    assert est == np.median(diffs)
    k = math.floor(n * m / 2 - 1.959964 * math.sqrt(n * m * (n + m + 1) / 12))
    if k < 1:
        assert lo is None and hi is None
    else:
        assert (lo, hi) == (diffs[k - 1], diffs[n * m - k])


def test_hl_two_sample_ci_inverts_the_mann_whitney_test():
    """Just outside the interval the test rejects at 5%; one order statistic inside it does not."""
    r = rng()
    a, b = r.integers(0, 10**9, 30), r.integers(0, 10**9, 30) + 10**8
    diffs = np.sort(np.subtract.outer(b, a).ravel())
    _, lo, hi = stats.hodges_lehmann_two_sample(a, b)
    i_lo, i_hi = np.searchsorted(diffs, lo), np.searchsorted(diffs, hi)

    def p(theta):
        return sps.mannwhitneyu(b - theta, a, method="asymptotic", use_continuity=False).pvalue

    assert p(lo - 0.5) < 0.05 and p(hi + 0.5) < 0.05
    assert p(diffs[i_lo + 1] + 0.5) >= 0.05 and p(diffs[i_hi - 1] - 0.5) >= 0.05


def test_hl_two_sample_ci_coverage():
    r, hits, trials = rng(), 0, 300
    for _ in range(trials):
        a = np.rint(r.normal(0, 100, 25)).astype(np.int64)
        b = np.rint(r.normal(50, 100, 25)).astype(np.int64)
        _, lo, hi = stats.hodges_lehmann_two_sample(a, b)
        hits += lo <= 50 <= hi
    assert 0.91 <= hits / trials <= 0.99  # nominal 95%, slightly conservative by construction


def test_hl_requires_integers():
    with pytest.raises(TypeError):
        stats.hodges_lehmann_two_sample([1.5, 2.5], [1, 2])
    with pytest.raises(TypeError):
        stats.hodges_lehmann_paired(np.array([0.1, 0.2]))


def walsh(d):
    return np.sort([(d[i] + d[j]) / 2 for i in range(len(d)) for j in range(i, len(d))])


def test_hl_paired_hand_values():
    assert stats.hodges_lehmann_paired([1, 2, 6])[0] == 2.75  # Walsh averages 1 1.5 2 3.5 4 6
    assert stats.hodges_lehmann_paired([7]) == (7, None, None)
    assert stats.hodges_lehmann_paired([-4, -4, -4, -4])[0] == -4


@pytest.mark.parametrize("n,span", [(2, 5), (5, 3), (12, 4), (40, 7), (41, 10**9), (75, 30)])
def test_hl_paired_matches_brute_force(n, span):
    d = rng().integers(-span, span, n)
    w = walsh(d)
    est, lo, hi = stats.hodges_lehmann_paired(d)
    assert est == np.median(w)
    k = math.floor(w.size / 2 - 1.959964 * math.sqrt(n * (n + 1) * (2 * n + 1) / 24))
    if k < 1:
        assert lo is None and hi is None
    else:
        assert (lo, hi) == (w[k - 1], w[w.size - k])


def test_hl_paired_ci_inverts_the_wilcoxon_test():
    d = rng().integers(-10**9, 10**9, 40) + 10**8
    w = walsh(d)
    _, lo, hi = stats.hodges_lehmann_paired(d)
    i_lo, i_hi = np.searchsorted(w, lo), np.searchsorted(w, hi)

    def p(theta):
        return sps.wilcoxon(d - theta, correction=False, method="asymptotic").pvalue

    assert p(lo - 0.25) < 0.05 and p(hi + 0.25) < 0.05
    assert p(w[i_lo + 1] + 0.25) >= 0.05 and p(w[i_hi - 1] - 0.25) >= 0.05


# ---- rank tests and effect size ------------------------------------------------------------------

def test_mann_whitney_and_cliffs_delta_known_values():
    p, delta = stats.mann_whitney([1, 2, 3], [4, 5, 6])
    assert p == pytest.approx(0.1) and delta == 1.0  # exact two-sided p = 2 / C(6, 3)
    assert stats.mann_whitney([4, 5, 6], [1, 2, 3])[1] == -1.0
    assert stats.mann_whitney([1, 2, 3, 4], [1, 2, 3, 4])[1] == 0.0
    assert stats.mann_whitney([5, 5, 5], [5, 5]) == (None, 0.0)  # all tied: test undefined, no dominance


def test_cliffs_delta_matches_brute_force_with_ties():
    r = rng()
    a, b = r.integers(0, 8, 40), r.integers(1, 9, 55)
    brute = np.sign(np.subtract.outer(b, a)).mean()  # P(b > a) - P(b < a)
    assert stats.mann_whitney(a, b)[1] == pytest.approx(brute)


def test_wilcoxon_known_values():
    assert stats.wilcoxon_p(np.zeros(6), np.arange(1, 7)) == pytest.approx(2 / 64)  # all six ranks positive
    assert stats.wilcoxon_p([3, 3], [3, 3]) is None


# ---- TOST ----------------------------------------------------------------------------------------

def lognormal_pair(n=60):
    r = rng()
    return np.exp(r.normal(7.3, 0.4, n)), np.exp(r.normal(7.31, 0.5, n + 7))


@pytest.mark.parametrize("margin", [0.01, 0.05, 0.3])
def test_tost_two_sample_matches_shifted_welch_tests(margin):
    a, b = lognormal_pair()
    la, lb, m = np.log(a), np.log(b), math.log(1 + margin)
    p_lower = sps.ttest_ind(lb + m, la, equal_var=False, alternative="greater").pvalue
    p_upper = sps.ttest_ind(lb - m, la, equal_var=False, alternative="less").pvalue
    t = stats.tost_log_two_sample(a, b, margin)
    assert t["p"] == pytest.approx(max(p_lower, p_upper))
    assert t["gm_ratio"] == pytest.approx(sps.gmean(b) / sps.gmean(a))
    inside = 1 / (1 + margin) < t["gm_ratio_ci"][0] and t["gm_ratio_ci"][1] < 1 + margin
    assert t["equivalent"] == (t["p"] < 0.05) == inside  # TOST at alpha <=> (1 - 2 alpha) CI inside the margin
    assert t["ci_level"] == pytest.approx(0.90)


def test_tost_two_sample_decides_both_ways():
    a, b = lognormal_pair(400)
    assert not stats.tost_log_two_sample(a, b, 0.01)["equivalent"]
    assert stats.tost_log_two_sample(a, b, 0.30)["equivalent"]
    assert not stats.tost_log_two_sample(a, 1.5 * a, 0.30)["equivalent"]  # a real 50% difference


@pytest.mark.parametrize("margin", [0.01, 0.05])
def test_tost_paired_matches_shifted_one_sample_tests(margin):
    r = rng()
    a = np.exp(r.normal(7.3, 0.4, 80))
    b = a * np.exp(r.normal(0.004, 0.03, 80))
    d, m = np.log(b / a), math.log(1 + margin)
    p_lower = sps.ttest_1samp(d, -m, alternative="greater").pvalue
    p_upper = sps.ttest_1samp(d, m, alternative="less").pvalue
    t = stats.tost_log_paired(a, b, margin)
    assert t["p"] == pytest.approx(max(p_lower, p_upper))
    assert t["gm_ratio"] == pytest.approx(sps.gmean(b / a))
    assert t["df"] == 79


def test_tost_paired_exact_scaling():
    a = np.array([100.0, 250.0, 900.0, 4000.0])
    t = stats.tost_log_paired(a, 1.05 * a, 0.10)  # every ratio is 1.05: variance is rounding noise only
    assert t["gm_ratio"] == pytest.approx(1.05) and t["p"] < 1e-12 and t["equivalent"]
    t = stats.tost_log_paired(a, 1.05 * a, 0.01)
    assert t["p"] > 1 - 1e-12 and not t["equivalent"]
    t = stats.tost_log_paired(a, a, 0.01)  # exactly zero variance and zero difference
    assert t["gm_ratio"] == 1.0 and t["p"] == 0.0 and t["gm_ratio_ci"] == [1.0, 1.0]


def test_tost_rejects_non_positive_times():
    with pytest.raises(ValueError):
        stats.tost_log_two_sample([1, 2, 0], [1, 2, 3], 0.01)
    with pytest.raises(ValueError):
        stats.tost_log_paired([1, 2, 3], [1, -2, 3], 0.01)


# ---- moving-block bootstrap ----------------------------------------------------------------------

def test_moving_block_indices_are_contiguous_blocks():
    idx = stats.moving_block_indices(23, 5, 50, rng())
    assert idx.shape == (50, 23) and idx.min() >= 0 and idx.max() <= 22
    inside_block = np.arange(1, 23) % 5 != 0
    assert np.all(np.diff(idx, axis=1)[:, inside_block] == 1)
    assert np.all(idx[:, ::5] <= 23 - 5)  # block starts
    assert len({tuple(row) for row in idx}) > 1
    assert np.array_equal(stats.moving_block_indices(9, 9, 3, rng()), np.tile(np.arange(9), (3, 1)))
    for bad in (0, 24):
        with pytest.raises(ValueError):
            stats.moving_block_indices(23, bad, 1, rng())


def test_block_bootstrap_degenerate_cases_are_exact():
    x = rng().normal(size=200)
    ci = stats.block_bootstrap_quantile_ci(x, [0.5, 0.99], 200, 50, 0.95, rng())  # one possible block: no spread
    assert ci == pytest.approx(np.repeat(np.quantile(x, [0.5, 0.99]), 2).reshape(2, 2))
    ci = stats.block_bootstrap_quantile_ci(np.full(300, 4.2), [0.5, 0.99], 10, 50, 0.95, rng())
    assert np.all(ci == 4.2)


def test_block_bootstrap_is_deterministic_given_the_seed():
    x = rng().normal(size=1000)
    a = stats.block_bootstrap_quantile_ci(x, [0.5, 0.99], 20, 200, 0.95, np.random.default_rng(1))
    b = stats.block_bootstrap_quantile_ci(x, [0.5, 0.99], 20, 200, 0.95, np.random.default_rng(1))
    c = stats.block_bootstrap_quantile_ci(x, [0.5, 0.99], 20, 200, 0.95, np.random.default_rng(2))
    assert np.array_equal(a, b) and not np.array_equal(a, c)


def test_block_bootstrap_of_a_ratio_of_medians():
    """Two series, each resampled on its own in moving blocks: the interval of median(b) / median(a)."""
    a, b = rng().normal(100, 5, size=400), rng().normal(110, 5, size=300)
    ratio = np.median(b) / np.median(a)
    # one possible block per series (block length = its length is not possible for both: the shorter one bounds it)
    assert np.all(stats.block_bootstrap_ratio_of_medians_ci(a[:300], b, 300, 40, 0.90, rng()) == np.median(b) / np.median(a[:300]))
    assert np.all(stats.block_bootstrap_ratio_of_medians_ci(np.full(50, 2.0), np.full(70, 3.0), 10, 40, 0.90, rng()) == 1.5)
    lo, hi = stats.block_bootstrap_ratio_of_medians_ci(a, b, 20, 400, 0.90, np.random.default_rng(1))
    # for independent normal values the median has the standard error 1.2533 sd / sqrt(n): 0.31% and 0.33% here, so
    # the ratio 0.45%, and a 90% interval is 2 * 1.645 of that wide
    width = 2 * 1.645 * ratio * math.hypot(1.2533 * 5 / 100 / math.sqrt(400), 1.2533 * 5 / 110 / math.sqrt(300))
    assert lo < ratio < hi and hi - lo == pytest.approx(width, rel=0.3)
    again = stats.block_bootstrap_ratio_of_medians_ci(a, b, 20, 400, 0.90, np.random.default_rng(1))
    other = stats.block_bootstrap_ratio_of_medians_ci(a, b, 20, 400, 0.90, np.random.default_rng(2))
    assert np.array_equal([lo, hi], again) and not np.array_equal([lo, hi], other)
    # two AR(1) series with phi = 0.9 around 100 (as in the test below): blocks of 100 show the dependence, single
    # values cannot
    r = rng()
    e, x = r.normal(size=(2, 5000)), np.zeros((2, 5000))
    for t in range(1, 5000):
        x[:, t] = 0.9 * x[:, t - 1] + e[:, t]
    w = [float(np.diff(stats.block_bootstrap_ratio_of_medians_ci(100 + x[0], 100 + x[1], L, 1000, 0.90, rng()))[0]) for L in (1, 100)]
    assert w[1] > 2.5 * w[0] > 0


def test_block_bootstrap_iid_median_matches_theory():
    """Block length 1 is the ordinary bootstrap; for i.i.d. N(0, 1) the 95% interval of the median
    has half-width 1.96 * sqrt(pi / 2) / sqrt(n)."""
    x = rng().normal(size=2000)
    lo, hi = stats.block_bootstrap_quantile_ci(x, [0.5], 1, 2000, 0.95, rng())[0]
    assert lo < np.median(x) < hi
    assert hi - lo == pytest.approx(2 * 1.96 * math.sqrt(math.pi / 2) / math.sqrt(2000), rel=0.25)


def test_block_bootstrap_widens_for_dependent_data():
    """AR(1) with phi = 0.9: the variance of a location estimate is inflated about (1 + phi)/(1 - phi) =
    19 times, which blocks of 100 must show and blocks of 1 (i.i.d. resampling) cannot."""
    r = rng()
    e, x = r.normal(size=5000), np.zeros(5000)
    for t in range(1, 5000):
        x[t] = 0.9 * x[t - 1] + e[t]
    w = [float(np.diff(stats.block_bootstrap_quantile_ci(x, [0.5], L, 1000, 0.95, rng())[0])[0]) for L in (1, 100)]
    assert w[1] > 2.5 * w[0]


def test_toolkit_identity_is_a_commit_or_a_source_hash():
    import re

    import analysis
    assert re.fullmatch(r"[0-9a-f]{12}(-dirty)?|nogit-[0-9a-f]{12}", analysis.toolkit_commit())


# ---- Poisson log-linear fit ------------------------------------------------------------------------

def test_poisson_loglinear_through_two_counts_is_exact():
    """Two counts determine the line: slope log(y1 / y0), and its standard error is sqrt(1/y0 + 1/y1)."""
    a, b, se, mu = stats.poisson_loglinear([0, 1], [400, 100])
    assert (a, b, se) == pytest.approx((math.log(400), math.log(0.25), math.sqrt(1 / 400 + 1 / 100)))
    assert mu == pytest.approx([400, 100])


def test_poisson_loglinear_is_the_maximum_likelihood_fit():
    x, y = np.array([2.0, 3, 4, 5, 6]), np.array([812.0, 395, 207, 96, 55])
    a, b, se, mu = stats.poisson_loglinear(x, y)
    # the score equations of log E[y] = a + b x
    assert (y - mu).sum() == pytest.approx(0, abs=1e-6) and (x * (y - mu)).sum() == pytest.approx(0, abs=1e-6)
    # the same optimum by a general-purpose minimiser of the negative log-likelihood
    best = optimize.minimize(lambda p: (np.exp(p[0] + p[1] * x) - y * (p[0] + p[1] * x)).sum(), [8.0, -0.7], method="Nelder-Mead",
                             options={"xatol": 1e-10, "fatol": 1e-10, "maxiter": 5000})
    assert (a, b) == pytest.approx(tuple(best.x), rel=1e-5)
    # standard error from the Fisher information: 1 / sum mu (x - weighted mean of x)^2
    centre = (mu @ x) / mu.sum()
    assert se == pytest.approx(1 / math.sqrt((mu * (x - centre) ** 2).sum()))
    # counts that are exactly geometric are reproduced
    a, b, se, mu = stats.poisson_loglinear([0, 1, 2, 3], [800, 400, 200, 100])
    assert math.exp(b) == pytest.approx(0.5) and mu == pytest.approx([800, 400, 200, 100])
    for bad_x, bad_y in (([1], [5]), ([1, 1], [5, 6]), ([0, 1], [5, -1]), ([0, 1], [0, 0])):
        with pytest.raises(ValueError):
            stats.poisson_loglinear(bad_x, bad_y)
