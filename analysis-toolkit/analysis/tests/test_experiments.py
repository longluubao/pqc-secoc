"""Each experiment module on synthetic CSVs whose answers are worked out by hand in synth.py and here."""
import math
import re
import statistics

import numpy as np
import pytest
from scipy import stats as sps

from analysis import (attack, crypto_ops, csvio, cyclictest, handshake, overhead, periodic, sign_attrib, simulate, stats,
                      throughput)
from analysis.tests import synth

MS = synth.MS


def exact(k, n):
    """Clopper-Pearson interval by scipy's own route, independent of analysis.stats."""
    ci = sps.binomtest(k, n).proportion_ci(0.95, method="exact")
    return [ci.low, ci.high]


def load(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return csvio.load(p)[1:]  # (meta, cols)


# ---- crypto_ops ----------------------------------------------------------------------------------

def run_crypto(tmp_path, block_len=5, content=None):
    _, cols = load(tmp_path, "crypto_ops.csv", content or synth.crypto_ops())
    res = crypto_ops.analyse(cols, warmup=10, block_len=block_len, n_boot=50, thresholds_ms=(5, 10),
                             rng=np.random.default_rng(0))
    return {r["op"]: r for r in res}


def test_crypto_ops_known_values(tmp_path):
    r = run_crypto(tmp_path)
    s = r["mldsa_sign"]  # post-warm-up: 1, 2, ..., 10 ms in seq order
    assert (s["n_total"], s["n_warmup_dropped"]) == (20, 10)
    t = s["time_us"]
    assert (t["n"], t["mean"], t["min"], t["max"], t["p50"]) == (10, 5500, 1000, 10000, 5500)
    assert t["sd"] == pytest.approx(1000 * np.std(np.arange(1, 11), ddof=1))
    assert t["p90"] == pytest.approx(9100) and t["p99"] == pytest.approx(9910)
    assert t["lag1"] == pytest.approx(0.7)  # 57.75 / 82.5; 0.264 if the rows were left in file order
    assert [(e["threshold_ms"], e["k"], e["n"]) for e in s["exceedance"]] == [(5, 5, 10), (10, 0, 10)]
    assert s["exceedance"][0]["wilson95"] == pytest.approx(stats.wilson_interval(5, 10))
    assert s["exceedance"][0]["cp95"] == pytest.approx(exact(5, 10))  # [18.7%, 81.3%], the textbook value
    assert s["exceedance"][0]["cp95"] == pytest.approx([0.187086, 0.812914], abs=1e-6)
    assert s["exceedance"][1]["cp95"] == pytest.approx(exact(0, 10))
    # in seq order the calls above 5 ms are the last five (6 .. 10 ms): four adjacent pairs with both calls above it,
    # against (n - 1) p^2 = 9 x 0.25 expected if the calls were independent; p^2 is also the share of signatures above
    # the threshold if two independent attempts ran and the first to finish were taken
    assert [(e["adjacent_pairs"], e["adjacent_pairs_if_independent"], e["p_squared"]) for e in s["exceedance"]] == [(4, 2.25, 0.25), (0, 0, 0)]
    for key in ("p50_ci95_us", "p99_ci95_us"):
        lo, hi = s["bootstrap"][key]
        assert 1000 <= lo <= hi <= 10000
    v = r["mldsa_verify"]  # 410..419 us after warm-up
    assert (v["time_us"]["n"], v["time_us"]["mean"], v["time_us"]["min"], v["time_us"]["max"]) == (10, 414.5, 410, 419)
    assert "exceedance" not in v


def test_crypto_ops_time_above_ten_milliseconds(tmp_path):
    """Signing times 1 .. 10 ms: none is above 10 ms. With 12, 13 and 25 ms added: 2 + 3 + 15 ms beyond 10 ms each."""
    r = run_crypto(tmp_path)
    assert r["mldsa_sign"]["excess_over_10ms"] == {"calls": 0, "seconds": 0} and "excess_over_10ms" not in r["mldsa_verify"]
    extra = "".join(f"mldsa_sign,{20 + i},{ms * synth.MS}\n" for i, ms in enumerate((12, 13, 25)))
    r = run_crypto(tmp_path, content=synth.crypto_ops(tail=()) + extra)
    assert r["mldsa_sign"]["excess_over_10ms"] == {"calls": 3, "seconds": pytest.approx(0.020)}


def test_crypto_ops_skips_bootstrap_when_fewer_than_two_blocks(tmp_path):
    assert "bootstrap" not in run_crypto(tmp_path, block_len=100)["mldsa_sign"]


def test_crypto_ops_rejects_duplicate_seq(tmp_path):
    with pytest.raises(ValueError, match="more than once"):
        run_crypto(tmp_path, content="op,seq,ns\nmldsa_sign,11,5\nmldsa_sign,11,6\n")


def test_crypto_ops_op_with_only_warmup_rows_is_reported_empty(tmp_path):
    r = run_crypto(tmp_path, content="op,seq,ns\nmldsa_keygen,0,5\n")["mldsa_keygen"]
    assert (r["n_total"], r["n_warmup_dropped"], r["time_us"]) == (1, 1, {"n": 0})


# ---- overhead ------------------------------------------------------------------------------------

def test_overhead_paired_known_values(tmp_path):
    _, cols = load(tmp_path, "overhead_paired.csv", synth.overhead_paired())
    r = {o["op"]: o for o in overhead.analyse_paired(cols, 0.01, warmup=10)}
    s = r["sign"]  # after warm-up: five AB pairs with +100 ns, five BA pairs with +300 ns, standalone 1 ms
    assert (s["n_pairs"], s["n_warmup_dropped"]) == (10, 10)
    assert s["median_standalone_us"] == 1000 and s["median_csm_us"] == pytest.approx(1000.2)
    assert s["median_diff_us"] == pytest.approx(0.2) and s["median_ratio"] == pytest.approx(1.0002)
    # 55 Walsh averages: 15 x 100, 25 x 200, 15 x 300 ns; K = floor(27.5 - 1.96 * 9.811) = 8
    assert s["hl_paired"] == {"estimate_us": 0.2, "ci95_us": [0.1, 0.3]}
    assert s["wilcoxon_p"] < 0.01
    t = s["tost_paired_log"]
    assert t["margin"] == 0.01 and t["equivalent"] and t["gm_ratio"] == pytest.approx((1.0001 * 1.0003) ** 0.5)
    assert s["cliffs_delta"] == 1.0
    e = s["order_effect"]
    assert (e["n_AB"], e["n_BA"]) == (5, 5)
    assert e["median_diff_AB_us"] == pytest.approx(0.1) and e["median_diff_BA_us"] == pytest.approx(0.3)
    assert e["hl_shift_BA_minus_AB"] == {"estimate_us": 0.2, "ci95_us": [0.2, 0.2]}
    assert e["mann_whitney_p"] < 0.05
    v = r["verify"]  # identical columns
    assert v["median_diff_us"] == 0 and v["median_ratio"] == 1 and v["hl_paired"] == {"estimate_us": 0, "ci95_us": [0, 0]}
    assert v["wilcoxon_p"] is None and v["cliffs_delta"] == 0 and v["tost_paired_log"]["gm_ratio"] == 1
    assert v["order_effect"]["mann_whitney_p"] is None  # every difference is zero


def test_overhead_paired_nothing_left_after_warmup(tmp_path):
    _, cols = load(tmp_path, "overhead_paired.csv", synth.overhead_paired())
    with pytest.raises(ValueError, match="no pairs left"):
        overhead.analyse_paired(cols, 0.01, warmup=1000)


@pytest.mark.parametrize("content,want", [("0.01\n", 0.01), ("# pre-registered 2026-11-22\n\n0.02\n", 0.02)])
def test_read_margin(tmp_path, content, want):
    (tmp_path / overhead.MARGIN_FILE).write_text(content)
    assert overhead.read_margin(tmp_path) == want


@pytest.mark.parametrize("content", ["abc\n", "0.01\n0.02\n", "", "5\n", "0\n", "-0.01\n", "1%\n"])
def test_read_margin_rejects_malformed(tmp_path, content):
    (tmp_path / overhead.MARGIN_FILE).write_text(content)
    with pytest.raises(ValueError):
        overhead.read_margin(tmp_path)


def test_read_margin_missing_file_fails_loudly(tmp_path):
    with pytest.raises(FileNotFoundError, match="equivalence_margin.txt"):
        overhead.read_margin(tmp_path)


def test_placeholder_margin_is_refused_outside_a_marked_directory(tmp_path):
    (tmp_path / overhead.MARGIN_FILE).write_text("# DRY RUN placeholder, NOT the pre-registered margin (candidate value).\n0.01\n")
    with pytest.raises(ValueError, match="calls itself a placeholder.*no DRY_RUN or PILOT marker"):
        overhead.read_margin(tmp_path)
    assert overhead.read_margin(tmp_path, "DRY_RUN") == 0.01 and overhead.read_margin(tmp_path, "PILOT") == 0.01


def test_noise_floor_file_is_not_judged_against_the_margin(tmp_path):
    _, cols = load(tmp_path, "overhead_paired.csv", synth.overhead_paired(mode="aa"))
    judged = {o["op"]: o for o in overhead.analyse_paired(cols, 0.01, warmup=10)}["sign"]
    floor = {o["op"]: o for o in overhead.analyse_paired(cols, 0.01, warmup=10, noise_floor=True)}["sign"]
    assert judged["tost_paired_log"]["equivalent"] is True and judged["tost_paired_log"]["margin"] == 0.01
    t = floor["tost_paired_log"]
    assert (t["margin"], t["p"], t["equivalent"]) == (None, None, None)
    assert t["gm_ratio"] == judged["tost_paired_log"]["gm_ratio"] and t["gm_ratio_ci"] == judged["tost_paired_log"]["gm_ratio_ci"]
    assert floor["hl_paired"] == judged["hl_paired"]  # the estimates themselves are the same


def launch(hl_us, ratio, op="sign", pairs=2000):
    """What across_launches() reads from one launch's analyse_paired() result."""
    return [{"op": op, "n_pairs": pairs, "hl_paired": {"estimate_us": hl_us}, "tost_paired_log": {"gm_ratio": ratio}}]


LAUNCH_HL = [0.64, 0.54, 0.06, 0.85, 0.57, -0.13]  # us: the six launches of the probe run
LAUNCH_RATIO = [1.00062, 1.00045, 1.00023, 1.00062, 1.00045, 0.99990]


def test_across_launches_known_values():
    per_launch = [(i + 1, launch(h, r)) for i, (h, r) in enumerate(zip(LAUNCH_HL, LAUNCH_RATIO))]
    (a,) = overhead.across_launches(per_launch, 0.01)
    assert (a["op"], a["n_launches"], a["launches"], a["pairs_per_launch"]) == ("sign", 6, [1, 2, 3, 4, 5, 6], [2000] * 6)
    x = np.array(LAUNCH_HL)
    h = a["hl_us"]
    assert (h["mean"], h["min"], h["max"]) == (pytest.approx(2.53 / 6), -0.13, 0.85)
    assert h["sd"] == pytest.approx(0.37478, abs=1e-5)  # by hand: sqrt(0.702283 / 5)
    for level, key in ((0.95, "t95"), (0.90, "t90")):  # scipy's own t interval of a mean
        ref = sps.t.interval(level, 5, loc=x.mean(), scale=sps.sem(x))
        assert h[key] == pytest.approx(list(ref))
    assert h["t95"] == pytest.approx([0.0284, 0.8150], abs=1e-4)  # 0.42167 +/- 2.5706 * 0.37478 / sqrt(6)
    logs = np.log(LAUNCH_RATIO)
    g = a["gm_ratio"]
    assert g["mean"] == pytest.approx(sps.gmean(LAUNCH_RATIO)) and (g["min"], g["max"]) == pytest.approx((0.99990, 1.00062))
    assert g["log_sd"] == pytest.approx(logs.std(ddof=1))
    assert g["t90"] == pytest.approx(list(np.exp(sps.t.interval(0.90, 5, loc=logs.mean(), scale=sps.sem(logs)))))
    m = np.log(1.01)  # TOST on six launch-level log-ratios, by two shifted one-sample t-tests
    want = max(sps.ttest_1samp(logs, -m, alternative="greater").pvalue, sps.ttest_1samp(logs, m, alternative="less").pvalue)
    assert a["tost"]["p"] == pytest.approx(want) and a["tost"]["df"] == 5 and a["tost"]["margin"] == 0.01
    assert a["tost"]["equivalent"] and a["verdict"] == "equivalent within the margin"
    # a margin the launch-to-launch spread cannot meet: +/-0.03% against a spread of about 0.03%
    (tight,) = overhead.across_launches(per_launch, 0.0003)
    assert not tight["tost"]["equivalent"] and tight["verdict"] == "equivalence not shown"


def test_across_launches_gives_no_verdict_without_enough_launches_or_for_a_noise_floor():
    per_launch = [(i + 1, launch(h, r)) for i, (h, r) in enumerate(zip(LAUNCH_HL, LAUNCH_RATIO))]
    (few,) = overhead.across_launches(per_launch[:4], 0.01)
    assert few["tost"] is None and few["verdict"] == "no verdict: 4 launch(es), fewer than 5" and few["hl_us"]["t95"][0] is not None
    (five,) = overhead.across_launches(per_launch[:5], 0.01)
    assert five["tost"] is not None
    (floor,) = overhead.across_launches(per_launch, 0.01, noise_floor=True)
    assert floor["tost"] is None and floor["verdict"] == "noise floor: not judged against the margin"
    assert floor["hl_us"]["mean"] == pytest.approx(2.53 / 6)
    (one,) = overhead.across_launches(per_launch[:1], 0.01)
    assert (one["hl_us"]["mean"], one["hl_us"]["sd"], one["hl_us"]["t95"]) == (0.64, None, [None, None])
    both = overhead.across_launches([(1, launch(0.5, 1.0005) + launch(0.1, 1.0001, "verify"))] * 2, 0.01)
    assert [b["op"] for b in both] == ["sign", "verify"]


def test_overhead_unpaired_known_values(tmp_path):
    rows = [("A_Standalone_Sign", 0, 9_000 * MS)] + [("A_Standalone_Sign", i, 10_000 * i) for i in range(1, 6)]
    rows += [("B_CsmIntegrated_Sign", 0, 9_000 * MS)] + [("B_CsmIntegrated_Sign", i, 10_000 * i + 3_000) for i in range(1, 6)]
    _, cols = load(tmp_path, "phase_compare.csv", synth.text("phase,seq,ns_delta", rows))
    (r,) = overhead.analyse_unpaired(cols, warmup=1, margins=(0.01, 0.02))
    assert (r["op"], r["n_standalone"], r["n_csm"]) == ("sign", 5, 5)
    assert (r["median_standalone_us"], r["median_csm_us"]) == (30, 33) and r["median_rel_diff"] == pytest.approx(0.1)
    # differences are 3 + 10 (j - i) us; K = floor(12.5 - 1.96 * 4.787) = 3 -> [D_(3), D_(23)] = [-27, 33] us
    assert r["hl_shift"] == {"estimate_us": 3, "ci95_us": [-27, 33]}
    assert r["cliffs_delta"] == pytest.approx(0.2)  # (15 - 10) / 25
    a, b = np.arange(1, 6) * 10_000, np.arange(1, 6) * 10_000 + 3_000
    assert r["mann_whitney_p"] == pytest.approx(sps.mannwhitneyu(b, a).pvalue)
    assert [t["margin"] for t in r["tost_log_post_hoc"]] == [0.01, 0.02]
    assert r["tost_log_post_hoc"][0]["gm_ratio"] == pytest.approx(sps.gmean(b) / sps.gmean(a))
    assert "lag1_standalone" not in r and "bootstrap" not in r  # only with the bootstrap parameters
    # with them: the lag-1 autocorrelation of each phase in seq order (10, 20, .., 50 us: deviations -2 .. 2, products
    # 2 + 0 + 0 + 2 over 10) and the moving-block interval of the relative median difference; a block as long as the
    # series leaves one possible resample, the series itself. The rows may come in any order: seq orders them
    shuffled = {k: v[::-1] for k, v in cols.items()}
    for given in (cols, shuffled):
        (r,) = overhead.analyse_unpaired(given, 1, (0.01, 0.02), block_len=5, n_boot=30, rng=np.random.default_rng(0))
        assert (r["lag1_standalone"], r["lag1_csm"]) == (pytest.approx(0.4), pytest.approx(0.4))
        assert r["bootstrap"] == {"median_rel_diff_ci90": pytest.approx([0.1, 0.1]), "block_len": 5, "n_boot": 30}


def geometric_sample(**kw):
    """synth.geometric_times_us in shuffled order: counts above 1..8 ms are 12700, 6300, 3100, 1500, 700, 300, 100, 0."""
    return np.random.default_rng(5).permutation(np.array(synth.geometric_times_us(**kw)))


def test_sign_tail_counts_and_geometric_fit():
    t = crypto_ops.tail(geometric_sample())
    assert t["thresholds_ms"] == list(range(1, 26))
    assert t["counts_above"] == [12700, 6300, 3100, 1500, 700, 300, 100] + [0] * 18
    # the rule: from the first whole millisecond above the median (1.5 ms: 2 ms) to the last one with at least 100
    # samples above it (7 ms); the five 1-ms bins between those thresholds are fitted
    fit = t["fit"]
    assert (t["max_ms"], fit["from_ms"], fit["to_ms"], fit["bins"], fit["above_fit_end"]) == (7.5, 2, 7, 5, 100)
    assert fit["ratio_per_ms"] == pytest.approx(2) and fit["dispersion"] == pytest.approx(0, abs=1e-12)
    # interval: Wald on the log ratio, Student-t with bins - 2 degrees of freedom; standard error from the Fisher
    # information of the five bin counts 3200 ... 200
    mu, x = 3200 / 2.0 ** np.arange(5), np.arange(5)
    se = 1 / math.sqrt((mu * (x - (mu @ x) / mu.sum()) ** 2).sum())
    half = sps.t.ppf(0.975, 3) * se
    assert fit["ratio_ci95"] == pytest.approx([2 * math.exp(-half), 2 * math.exp(half)])
    assert "Poisson regression" in fit["method"] and "dispersion" in fit["method"]
    # sensitivity: the same fit started at 1 ms (six bins, 6400 ... 200)
    assert t["from_1ms"] == {"to_ms": 7, "bins": 6, "ratio_per_ms": pytest.approx(2), "dispersion": pytest.approx(0, abs=1e-12)}
    later = crypto_ops.tail(geometric_sample(), start_ms=3)["fit"]
    assert (later["from_ms"], later["to_ms"], later["bins"], later["ratio_per_ms"]) == (3, 7, 4, pytest.approx(2))
    assert crypto_ops.TAIL_START_QUANTILE == 0.5 and crypto_ops.TAIL_MIN_COUNT == 100  # the two parameters of the rule


def test_sign_tail_starts_strictly_above_the_median():
    tail_part = [1000.0 * k + 500 for k in range(3, 10) for _ in range(6400 >> (k - 3))]  # 12700 values in (3, 4] .. (9, 10] ms
    for body_us, start in ((1999.0, 2), (2000.0, 3), (2400.0, 3)):  # more than half of the sample sits at body_us
        values = np.array([body_us] * 12701 + tail_part)
        assert np.median(values) == body_us and crypto_ops.tail(values)["fit"]["from_ms"] == start


def test_expected_count_above_a_value_under_the_fitted_decay():
    """The fitted bins are 3200, 1600, ... from 2 ms: continued for ever they hold 6400 values above 2 ms, and the
    count halves with every further millisecond."""
    fit = crypto_ops.tail(geometric_sample())["fit"]
    assert fit["share_above_from"] == pytest.approx(6400 / 13700)
    assert crypto_ops.tail_expected(fit, 8.5, 13700) == pytest.approx(6400 * 2 ** -6.5)  # 70.7 of this series' 13700 calls
    assert crypto_ops.tail_expected(fit, 21.1, 19000) == pytest.approx(19000 * 6400 / 13700 * 2 ** -19.1)  # another series
    assert crypto_ops.tail_expected(fit, 2, 13700) == pytest.approx(6400)
    assert crypto_ops.tail_expected(fit, 1.9, 13700) is None  # below the start of the fit the decay says nothing


def test_sign_tail_dispersion_widens_the_interval_when_the_decay_is_not_geometric():
    """Bin counts 6400, 1600, 1600, 400, 400, 100 (two steps of 4, not six of 2) fit a line badly."""
    parts = [np.full(c, 1000.0 * (i + 1) + 500) for i, c in enumerate((6400, 1600, 1600, 400, 400, 100, 100))]
    fit = crypto_ops.tail(np.concatenate(parts), start_ms=1)["fit"]
    y = np.array([6400.0, 1600, 1600, 400, 400, 100])
    mu = y.sum() * fit["ratio_per_ms"] ** -np.arange(6) / (fit["ratio_per_ms"] ** -np.arange(6.0)).sum()  # the fitted means
    assert fit["dispersion"] == pytest.approx(((y - mu) ** 2 / mu).sum() / 4) and fit["dispersion"] > 50
    lo, hi = fit["ratio_ci95"]
    se = 1 / math.sqrt((mu * (np.arange(6) - (mu @ np.arange(6)) / mu.sum()) ** 2).sum())
    assert math.log(hi / lo) / 2 == pytest.approx(sps.t.ppf(0.975, 4) * se * math.sqrt(fit["dispersion"]))


def test_sign_tail_needs_three_bins_and_a_large_sample(tmp_path, monkeypatch):
    short = crypto_ops.tail(geometric_sample(first=400, bins=3))  # counts above 1, 2, 3 ms: 700, 300, 100: two bins
    assert short["counts_above"][:4] == [700, 300, 100, 0] and short["fit"] is None
    assert short["fit_note"] == "no fit: fewer than 3 one-millisecond bins between thresholds with at least 100 samples above them"
    assert crypto_ops.tail(np.full(50, 2500.0))["fit"] is None
    # in the analysis: signing ops only, and only a series of at least TAIL_MIN_N values
    assert crypto_ops.TAIL_MIN_N == 100_000 and all("tail" not in r for r in run_crypto(tmp_path).values())
    monkeypatch.setattr(crypto_ops, "TAIL_MIN_N", 10)
    res = run_crypto(tmp_path)
    assert res["mldsa_sign"]["tail"]["counts_above"][:10] == [9, 8, 7, 6, 5, 4, 3, 2, 1, 0] and "tail" not in res["mldsa_verify"]


# ---- sign_attrib: wall time and processor time of every signing call ------------------------------

CELLS = ("threshold_ms", "k", "rounds_min", "rounds_min_or_more", "rounds_threshold", "both", "cpu_only", "rounds_only", "neither")


def cells(row):
    return {name: row[name] for name in CELLS}


def exact95(k, n):  # the Clopper-Pearson interval by another scipy route
    return pytest.approx(tuple(sps.binomtest(k, n).proportion_ci(0.95, method="exact")))


def attrib(tmp_path, **kw):
    meta, cols = load(tmp_path, "sign_attrib_p8.csv", synth.sign_attrib(**kw))
    assert sign_attrib.consistency(meta, cols) == []
    return sign_attrib.analyse(meta, cols, warmup=10)


def test_sign_attrib_time_off_the_processor(tmp_path):
    r = attrib(tmp_path)
    assert (r["n_total"], r["n_warmup_dropped"], r["n"]) == (30, 10, 20)
    assert (r["off_total_s"], r["off_max_us"]) == (pytest.approx(0.013184), 7000)  # 17 x 2 + 150 + 7000 + 6000 us
    # every call carries a floor (the clock reads inside the wall interval): its size is the smallest and the median off
    assert (r["off_min_us"], r["off_median_us"]) == (2, 2)
    # median and mean of the two times. Processor time, 100 + 250 us per round: 8 x 350, 5 x 600, 3 x 850, 2 x 1100,
    # 1600, 5100: the 10th and 11th of the 20 are 600; the sum is 20 x 100 + 61 x 250 = 17250. Wall time is 2 us more,
    # except 7350 (1 round), 1250 (4 rounds) and 11100 (20 rounds): the 10th and 11th are 602; the sum is 17250 + 13184
    assert r["cpu_us"] == {"p50": 600, "mean": 862.5} and r["wall_us"] == {"p50": 602, "mean": pytest.approx(1521.7)}
    # the measured upper percentiles of the processor time (type 7): the two largest of the 20 are 1600 and 5100 us, and
    # the positions 18.81 and 18.981 lie between them
    assert r["cpu_tail_us"] == {"p99": pytest.approx(1600 + 0.81 * 3500), "p99.9": pytest.approx(1600 + 0.981 * 3500)}
    # above the floor: the calls more than 100 us above the median (150, 7000 and 6000 us), and their off minus the median
    assert r["off_above_floor"] == {"k": 3, "seconds": pytest.approx(0.013144)}  # 148 + 6998 + 5998 us
    assert r["off_over"] == [{"threshold_us": 100, "k": 3}, {"threshold_us": 1000, "k": 2}, {"threshold_us": 5000, "k": 2}]
    # wall time above t: how many calls, how many of them with processor time above t as well, the largest off among
    # them, and the fewest rounds among them
    assert r["wall_over"] == [
        # 7.35 ms (1 round) and 11.1 ms: every one of the 20 calls has at least 1 round
        {"threshold_ms": 5, "k": 2, "cpu_also_over": 1, "max_off_us": 7000, "rounds_min": 1, "rounds_min_or_more": 20},
        # 11.1 ms (20 rounds, cpu 5.1 ms): one call has at least 20 rounds, so "above 10 ms" and "20 rounds or more" coincide
        {"threshold_ms": 10, "k": 1, "cpu_also_over": 0, "max_off_us": 6000, "rounds_min": 20, "rounds_min_or_more": 1},
        {"threshold_ms": 15, "k": 0, "cpu_also_over": 0, "max_off_us": None, "rounds_min": None, "rounds_min_or_more": None},
        {"threshold_ms": 20, "k": 0, "cpu_also_over": 0, "max_off_us": None, "rounds_min": None, "rounds_min_or_more": None}]
    # processor time above t (cpu = 100 + 250 us per round, exactly: only the 20-round call, 5.1 ms, is above 5 ms), the
    # fewest rounds among those calls, and the two-by-two against the line: 100 + 250 r > 5000 from r = 20 (19.6), > 10000
    # from r = 40 (39.6), then 60 and 80
    none = {"rounds_min": None, "rounds_min_or_more": None}
    assert [cells(c) for c in r["cpu_over"]] == [
        {"threshold_ms": 5, "k": 1, "rounds_min": 20, "rounds_min_or_more": 1,
         "rounds_threshold": 20, "both": 1, "cpu_only": 0, "rounds_only": 0, "neither": 19},
        {"threshold_ms": 10, "k": 0, **none, "rounds_threshold": 40, "both": 0, "cpu_only": 0, "rounds_only": 0, "neither": 20},
        {"threshold_ms": 15, "k": 0, **none, "rounds_threshold": 60, "both": 0, "cpu_only": 0, "rounds_only": 0, "neither": 20},
        {"threshold_ms": 20, "k": 0, **none, "rounds_threshold": 80, "both": 0, "cpu_only": 0, "rounds_only": 0, "neither": 20}]
    # the share of the calls with processor time above t, and the calls with at least rounds_threshold rounds: measured,
    # and under a geometric law with the measured one-round share 0.4: 0.6^(threshold - 1)
    c5, c10 = r["cpu_over"][:2]
    assert (c5["share"], c5["share_cp95"]) == (0.05, exact95(1, 20))
    assert c5["share_cp95"] == pytest.approx((1 - 0.975 ** (1 / 20), 0.2487), abs=5e-5)  # by hand for 1 of 20
    # bounds of the share under the geometric law: the formula at the exact 95% bounds of the one-round share (8 of 20
    # calls: 0.191 to 0.639 by the tables), the larger one-round share giving the smaller share
    lo, hi = sps.binomtest(8, 20).proportion_ci(0.95, method="exact")
    assert (lo, hi) == pytest.approx((0.1912, 0.6395), abs=5e-4)
    assert r["rounds"]["one_share_cp95"] == pytest.approx((lo, hi))
    assert c5["rounds_at_least"] == {"k": 1, "share": 0.05, "share_cp95": exact95(1, 20), "share_geometric": pytest.approx(0.6 ** 19),
                                     "share_geometric_ci95": pytest.approx(((1 - hi) ** 19, (1 - lo) ** 19))}
    assert c5["rounds_at_least"]["share_geometric_ci95"] == pytest.approx((0.3605 ** 19, 0.8088 ** 19), rel=0.02)  # by hand
    assert c5["rounds_at_least"]["share_geometric_ci95"][0] < 0.6 ** 19 < c5["rounds_at_least"]["share_geometric_ci95"][1]
    assert (c10["share"], c10["share_cp95"]) == (0, pytest.approx((0, 1 - 0.025 ** (1 / 20))))  # none of 20
    assert c10["rounds_at_least"] == {"k": 0, "share": 0, "share_cp95": pytest.approx((0, 1 - 0.025 ** (1 / 20))),
                                      "share_geometric": pytest.approx(0.6 ** 39),
                                      "share_geometric_ci95": pytest.approx(((1 - hi) ** 39, (1 - lo) ** 39))}
    # no call off the diagonal, so none beyond the round where the line crosses t either
    assert [(c["cpu_only_below_crossing"], c["rounds_only_above_crossing"]) for c in r["cpu_over"]] == [(0, 0)] * 4


def test_sign_attrib_rounds_and_processor_time_per_round(tmp_path):
    rounds = attrib(tmp_path)["rounds"]  # 8 calls of 1 round, 5 of 2, 3 of 3, 2 of 4, one of 6, one of 20: 61 rounds
    assert (rounds["mean"], rounds["one_share"], rounds["max"], rounds["geometric_mean"]) == (3.05, 0.4, 20, 2.5)
    fit = rounds["fit"]  # cpu = 100 us + 250 us per round, exactly
    assert (fit["cpu_per_round_us"], fit["cpu_intercept_us"], fit["r2"]) == pytest.approx((250, 100, 1))
    assert fit["resid_us"] == {"n": 20, "sd": pytest.approx(0, abs=1e-6), "p0.1": pytest.approx(0, abs=1e-6),
                               "p99.9": pytest.approx(0, abs=1e-6), "min": pytest.approx(0, abs=1e-6),
                               "max": pytest.approx(0, abs=1e-6)}
    assert [(p["rounds"], p["n"], p["share"], p["mean_cpu_us"]) for p in rounds["per_round"]] == \
        [(1, 8, 0.4, 350), (2, 5, 0.25, 600), (3, 3, 0.15, 850), (4, 2, 0.1, 1100), (6, 1, 0.05, 1600), (20, 1, 0.05, 5100)]
    # next to each measured share: the share a geometric law with the measured one-round share gives, 0.4 x 0.6^(k-1)
    assert [p["geometric_share"] for p in rounds["per_round"]] == pytest.approx([0.4 * 0.6 ** (k - 1) for k in (1, 2, 3, 4, 6, 20)])
    # what the line and the law imply together: under the geometric law with one-round share 0.4 the share of calls with
    # at most r rounds is 1 - 0.6^r, which first reaches 0.5 at r = 2 (0.64), 0.99 at r = 10 (0.6^10 = 0.0060) and 0.999
    # at r = 14 (0.6^14 = 0.00078); the line gives 100 + 250 r us for that many rounds
    assert rounds["law"] == {"p50": {"rounds": 2, "cpu_us": pytest.approx(600)}, "p99": {"rounds": 10, "cpu_us": pytest.approx(2600)},
                             "p99.9": {"rounds": 14, "cpu_us": pytest.approx(3600)}}
    # the 10 ms threshold needs 40 rounds and no call has more than 20: its geometric share lies beyond the data (the
    # key says so), that of 5 ms, 20 rounds, does not
    over = {c["threshold_ms"]: c["rounds_threshold"] for c in attrib(tmp_path)["cpu_over"]}
    assert (over[5], over[10], rounds["max"]) == (20, 40, 20)
    plain = attrib(tmp_path, counted=False)  # three columns: no rounds, everything else the same
    assert plain["rounds"] is None and [(w["rounds_min"], w["rounds_min_or_more"]) for w in plain["wall_over"]] == [(None, None)] * 4
    assert (plain["off_total_s"], plain["wall_over"][0]["k"]) == (pytest.approx(0.013184), 2)
    p5 = plain["cpu_over"][0]
    assert cells(p5) == {"threshold_ms": 5, "k": 1, "rounds_min": None, "rounds_min_or_more": None,
                         "rounds_threshold": None, "both": None, "cpu_only": None, "rounds_only": None, "neither": None}
    # the share by processor time needs no rounds; everything about rounds is absent
    assert (p5["share"], p5["share_cp95"]) == (0.05, exact95(1, 20))
    assert (p5["rounds_at_least"], p5["cpu_only_below_crossing"], p5["rounds_only_above_crossing"]) == (None, None, None)


def test_sign_attrib_line_by_an_independent_route_and_no_line_without_spread(tmp_path):
    rng = np.random.default_rng(11)
    r = rng.geometric(0.2, 400)
    cpu = 1000 * (120 + 260 * r) + rng.integers(-20_000, 20_000, 400)
    rows = [(i, int(c) + 3000, int(c), 5 + 3 * (int(k) - 1)) for i, (k, c) in enumerate(zip(r, cpu))]
    tail = ("freq_khz_end=1500000", f"wall_s={cpu.sum() / 1e9 + 0.001:.6f}", f"cpu_s={cpu.sum() / 1e9:.6f}")
    meta, cols = load(tmp_path, "sign_attrib.csv", synth.sign_attrib(rows=rows, tail=tail))
    assert sign_attrib.consistency(meta, cols) == []
    fit = sign_attrib.analyse(meta, cols, warmup=0)["rounds"]["fit"]
    slope, intercept = np.polyfit(r, cpu / 1e3, 1)
    resid = cpu / 1e3 - (intercept + slope * r)
    assert (fit["cpu_per_round_us"], fit["cpu_intercept_us"]) == pytest.approx((slope, intercept))
    assert fit["r2"] == pytest.approx(np.corrcoef(r, cpu)[0, 1] ** 2)
    assert fit["resid_us"]["sd"] == pytest.approx(math.sqrt((resid ** 2).sum() / 398))  # divisor n - 2
    assert (fit["resid_us"]["p0.1"], fit["resid_us"]["p99.9"]) == pytest.approx(tuple(np.quantile(resid, [0.001, 0.999])))  # type 7
    assert (fit["resid_us"]["min"], fit["resid_us"]["max"]) == pytest.approx((resid.min(), resid.max()))
    # 400 calls: the median is the mean of the 200th and 201st value (type 7), by another route
    times = sign_attrib.analyse(meta, cols, warmup=0)
    assert times["cpu_us"] == {"p50": pytest.approx(statistics.median((cpu / 1e3).tolist())), "mean": pytest.approx(cpu.mean() / 1e3)}
    assert times["wall_us"] == {"p50": pytest.approx(statistics.median((cpu / 1e3).tolist()) + 3), "mean": pytest.approx(cpu.mean() / 1e3 + 3)}
    assert "bootstrap" not in times  # no interval unless the bootstrap parameters are given
    # the interval of the two medians is the one the E1 median has: the moving-block bootstrap of crypto_ops, over the
    # calls in acquisition order, wall time first and processor time second from the same generator
    boot = sign_attrib.analyse(meta, cols, warmup=0, block_len=10, n_boot=200, rng=np.random.default_rng(3))
    same = np.random.default_rng(3)
    wall_ci = stats.block_bootstrap_quantile_ci(cpu / 1e3 + 3, [0.5], 10, 200, 0.95, same)[0]
    cpu_ci = stats.block_bootstrap_quantile_ci(cpu / 1e3, [0.5], 10, 200, 0.95, same)[0]
    assert boot["bootstrap"] == {"method": "moving-block bootstrap, percentile interval", "block_len": 10, "n_boot": 200}
    assert boot["wall_us"]["p50_ci95"] == pytest.approx(wall_ci) and boot["cpu_us"]["p50_ci95"] == pytest.approx(cpu_ci)
    assert boot["cpu_us"]["p50_ci95"][0] <= boot["cpu_us"]["p50"] <= boot["cpu_us"]["p50_ci95"][1]
    assert {k: v for k, v in boot["cpu_us"].items() if k != "p50_ci95"} == times["cpu_us"] and boot["rounds"] == times["rounds"]
    # fewer than two blocks: no interval, as for the E1 series
    short = sign_attrib.analyse(meta, cols, warmup=0, block_len=201, n_boot=200, rng=np.random.default_rng(3))
    assert "bootstrap" not in short and "p50_ci95" not in short["wall_us"]
    same = [(i, 353_000, 350_000, 5) for i in range(30)]  # every call has one round: no line through one abscissa
    meta, cols = load(tmp_path, "sign_attrib.csv", synth.sign_attrib(rows=same, tail=("freq_khz_end=1500000", "wall_s=0.0106", "cpu_s=0.0105")))
    flat_all = sign_attrib.analyse(meta, cols, warmup=10)
    flat = flat_all["rounds"]
    assert flat["fit"] is None and (flat["mean"], flat["one_share"], flat["geometric_mean"]) == (1, 1, 1)
    # without a line there is no rounds threshold and no two-by-two; the count of calls stays
    assert cells(flat_all["cpu_over"][0]) == {"threshold_ms": 5, "k": 0, "rounds_min": None, "rounds_min_or_more": None,
                                              "rounds_threshold": None, "both": None, "cpu_only": None, "rounds_only": None, "neither": None}
    assert (flat_all["cpu_over"][0]["share"], flat_all["cpu_over"][0]["rounds_at_least"]) == (0, None)
    # a line that does not rise (processor time falls with the rounds) gives none either; the fewest rounds are still counted
    falling = [(i, 1000 * (9000 - 1000 * k) + 3000, 1000 * (9000 - 1000 * k), 5 + 3 * (k - 1)) for i, k in enumerate([1, 1, 2, 3, 3, 5])]
    meta, cols = load(tmp_path, "sign_attrib.csv", synth.sign_attrib(rows=falling, tail=("freq_khz_end=1500000", "wall_s=0.040", "cpu_s=0.039")))
    assert sign_attrib.consistency(meta, cols) == []
    down = sign_attrib.analyse(meta, cols, warmup=0)
    assert down["rounds"]["fit"]["cpu_per_round_us"] == pytest.approx(-1000)
    assert cells(down["cpu_over"][0]) == {"threshold_ms": 5, "k": 5, "rounds_min": 1, "rounds_min_or_more": 6,  # 8, 8, 7, 6, 6 ms; 4 ms
                                          "rounds_threshold": None, "both": None, "cpu_only": None, "rounds_only": None, "neither": None}
    assert (down["cpu_over"][0]["share"], down["cpu_over"][0]["rounds_at_least"]) == (pytest.approx(5 / 6), None)
    # no call with one round: a geometric law with a one-round share of zero is none, so no share under it
    # (2 ms per round: the line is above 5 ms from 3 rounds; the calls with 3 and 5 rounds have at least that many)
    rising = [(i, 2_000_000 * k + 3000, 2_000_000 * k, 5 + 3 * (k - 1)) for i, k in enumerate([2, 2, 3, 5])]
    meta, cols = load(tmp_path, "sign_attrib.csv", synth.sign_attrib(rows=rising, tail=("freq_khz_end=1500000", "wall_s=0.0241", "cpu_s=0.024")))
    assert sign_attrib.consistency(meta, cols) == []
    up = sign_attrib.analyse(meta, cols, warmup=0)["cpu_over"][0]
    assert (up["rounds_threshold"], up["k"], up["share"]) == (3, 2, 0.5)
    assert up["rounds_at_least"] == {"k": 2, "share": 0.5, "share_cp95": exact95(2, 4), "share_geometric": None,
                                     "share_geometric_ci95": None}


def test_sign_attrib_rounds_threshold_is_the_smallest_whole_number_of_rounds_with_the_line_above_t():
    f = sign_attrib.rounds_threshold
    assert f(100, 250, 5000) == 20          # 100 + 250 x 19.6 = 5000
    assert f(0, 250, 5000) == 21            # the line equals t at 20 rounds: 'above' is strict
    assert f(1000, 500, 5000) == 9          # equal at 8
    assert f(4750, 250, 5000) == 2          # equal at 1
    assert f(4900, 250, 5000) == 1
    assert f(6000, 250, 5000) == 1          # above t already at one round: a call has at least one round
    assert f(100, 0, 5000) is None and f(100, -250, 5000) is None and f(9000, -250, 5000) is None  # a line that does not rise
    rng = np.random.default_rng(5)
    for a, b, t in zip(rng.uniform(-500, 6000, 300), rng.uniform(0.5, 900, 300), rng.choice([5000.0, 10000.0, 20000.0], 300)):
        brute = next(k for k in range(1, 50_000) if a + b * k > t)  # the definition, tried round by round
        assert f(a, b, t) == brute


def test_sign_attrib_two_by_two_counts_the_calls_the_rounds_do_not_explain(tmp_path):
    """400 calls on a line (120 + 260 us per round, +-20 us) plus eight placed calls. The line is above 5 ms from 19
    rounds (120 + 260 x 18 = 4800, x 19 = 5060). 'cpu_only' (processor time above 5 ms, fewer than 19 rounds): two calls
    with 10 rounds and 6 ms, one with 10 rounds whose processor time is just above 5 ms while its wall time is just
    below (inside the 2 us the row rule allows), one with 17 and one with 18 rounds at 5.5 ms. 'rounds_only' (not above
    5 ms, at least 19 rounds): 4.9 ms with 19 and with 20 rounds, 4 ms with 25 rounds. Beyond the round where the line
    crosses: fewer than 18 rounds (the three with 10 and the one with 17), more than 19 rounds (20 and 25)."""
    rng = np.random.default_rng(11)
    r = np.r_[rng.geometric(0.2, 400), 10, 10, 10, 25, 18, 19, 17, 20]
    cpu = np.r_[1000 * (120 + 260 * r[:400]) + rng.integers(-20_000, 20_000, 400), 6_000_000, 6_000_000, 5_000_500, 4_000_000,
                5_500_000, 4_900_000, 5_500_000, 4_900_000]
    wall = cpu + 3000
    wall[402] = 4_999_500
    rows = [(i, int(w), int(c), 5 + 3 * (int(k) - 1)) for i, (w, c, k) in enumerate(zip(wall, cpu, r))]
    tail = ("freq_khz_end=1500000", f"wall_s={wall.sum() / 1e9:.6f}", f"cpu_s={cpu.sum() / 1e9:.6f}")
    meta, cols = load(tmp_path, "sign_attrib.csv", synth.sign_attrib(rows=rows, tail=tail))
    assert sign_attrib.consistency(meta, cols) == []
    out = sign_attrib.analyse(meta, cols, warmup=0)
    c5, w5 = out["cpu_over"][0], out["wall_over"][0]
    # an independent route: the line by polyfit, the threshold round by round, the cells one call at a time
    slope, intercept = np.polyfit(r, cpu / 1e3, 1)
    threshold = next(k for k in range(1, 1000) if intercept + slope * k > 5000)
    cells = {"both": 0, "cpu_only": 0, "rounds_only": 0, "neither": 0}
    for k, c in zip(r, cpu):
        cells[("both" if k >= threshold else "cpu_only") if c > 5_000_000 else ("rounds_only" if k >= threshold else "neither")] += 1
    assert threshold == 19 and c5["rounds_threshold"] == 19
    assert {name: c5[name] for name in cells} == cells
    assert (c5["cpu_only"], c5["rounds_only"]) == (5, 3) and c5["both"] == int(np.count_nonzero(r >= 19)) - 3 > 0
    assert c5["both"] + c5["cpu_only"] + c5["rounds_only"] + c5["neither"] == 408
    # beyond the one-round ambiguity at the crossing: 17 rounds counts (fewer than 18), 18 does not; 20 counts, 19 does not
    below = sum(1 for k, c in zip(r, cpu) if c > 5_000_000 and k < threshold - 1)
    above = sum(1 for k, c in zip(r, cpu) if not c > 5_000_000 and k > threshold)
    assert (c5["cpu_only_below_crossing"], c5["rounds_only_above_crossing"]) == (below, above) == (4, 2)
    # the calls with at least 19 rounds: measured share with its exact interval, and the share a geometric law with the
    # measured one-round share gives, P(X >= 19) = geom.sf(18)
    many = int(np.count_nonzero(r >= 19))
    lo, hi = sps.binomtest(int(np.count_nonzero(r == 1)), 408).proportion_ci(0.95, method="exact")
    assert c5["rounds_at_least"] == {"k": many, "share": many / 408, "share_cp95": exact95(many, 408),
                                     "share_geometric": pytest.approx(sps.geom.sf(18, np.mean(r == 1))),
                                     "share_geometric_ci95": pytest.approx((sps.geom.sf(18, hi), sps.geom.sf(18, lo)))}
    assert many == c5["both"] + c5["rounds_only"]
    assert (c5["share"], c5["share_cp95"]) == (c5["k"] / 408, exact95(c5["k"], 408))
    assert c5["k"] == c5["both"] + c5["cpu_only"] == int(np.count_nonzero(cpu > 5_000_000))
    # the fewest rounds among the calls with processor time above 5 ms are the 10 of the placed calls
    assert (c5["rounds_min"], c5["rounds_min_or_more"]) == (10, int(np.count_nonzero(r >= 10)))
    # the call with processor time above 5 ms and wall time below it is in cpu_over, not among the calls above 5 ms in wall time
    assert w5["k"] == w5["cpu_also_over"] == c5["k"] - 1


def test_sign_attrib_rows_that_contradict_the_file_make_it_invalid(tmp_path):
    def reasons(**kw):
        meta, cols = load(tmp_path, "sign_attrib_p8.csv", synth.sign_attrib(**kw))
        return sign_attrib.consistency(meta, cols)

    good = [list(map(int, ln.split(","))) for ln in synth.sign_attrib().splitlines() if ln[:1].isdigit()]
    # 1. the processor times of all rows, warm-up included, must add up to the footer's cpu_s within 1%
    assert reasons(tail=("freq_khz_end=1500000", "wall_s=0.0212", "cpu_s=0.02095")) == []  # 20750 us against 20950: 0.95%
    assert reasons(tail=("freq_khz_end=1500000", "wall_s=0.0215", "cpu_s=0.02100")) == [
        "sum of cpu_ns over all rows is 0.020750 s, the footer's cpu_s is 0.021000 s: more than 1% apart"]
    # 2. wall time may be shorter than processor time by the resolution of the two clocks only
    rows = [r[:] for r in good]
    rows[12][1] = rows[12][2] - 2000  # exactly 2000 ns less: allowed
    assert reasons(rows=rows) == []
    rows[12][1] -= 1
    rows[25][1] = rows[25][2] - 5000
    assert reasons(rows=rows) == ["2 row(s) with wall_ns < cpu_ns - 2000 (first: seq 12)"]
    # 3. a count that is not shake_calls_min plus a multiple of shake_calls_step
    rows = [r[:] for r in good]
    rows[7][3] = 6
    assert reasons(rows=rows) == ["1 row(s) with shake_calls off the progression 5 + k x 3 (first: seq 7)"]
    rows[7][3] = 2  # below the minimum
    assert reasons(rows=rows) == ["1 row(s) with shake_calls off the progression 5 + k x 3 (first: seq 7)"]


def test_sign_attrib_malformed_files_are_errors(tmp_path):
    good = synth.sign_attrib()
    for bad, message in (
            (good.replace("# shake_calls_step=3\n", ""), "four columns need the header lines shake_calls_min and shake_calls_step"),
            (good.replace("# shake_calls_step=3", "# shake_calls_step=0"), "shake_calls_step='0' is not a positive integer"),
            (synth.sign_attrib(counted=False).replace("# shake_counted=off", "# shake_counted=OQS_SHA3"),
             "three columns, but the header says shake_counted=OQS_SHA3"),
            (good.replace("\n11,", "\n12,", 1), "seq is not contiguous from 0")):
        meta, cols = load(tmp_path, "sign_attrib_p8.csv", bad)
        with pytest.raises(ValueError, match=message):
            sign_attrib.consistency(meta, cols)
    with pytest.raises(csvio.CsvError, match="header"):  # a fourth column of another name
        load(tmp_path, "sign_attrib_p8.csv", good.replace("shake_calls\n", "rounds\n"))
    old = synth.sign_attrib(counted=False).replace("# shake_counted=off\n", "")  # written before --count-shake existed
    meta, cols = load(tmp_path, "sign_attrib_p8.csv", old)
    assert sign_attrib.consistency(meta, cols) == []


# ---- periodic ------------------------------------------------------------------------------------

def periodic_tx(tmp_path, rows=None, **override):
    meta, cols = load(tmp_path, "periodic_tx.csv", synth.periodic_tx_two_streams(rows, **override))
    return periodic.analyse_tx(meta, cols)


def test_periodic_tx_known_values(tmp_path):
    r = periodic_tx(tmp_path)
    assert (r["period_us"], r["deadline_us"], r["streams"], r["cores"], r["profile"], r["scheduler"]) == \
        (10_000, 10_000, 2, 1, "mldsa65", "fifo")
    assert (r["payload_bytes"], r["commit"], r["host"]) == (64, "abc1234", "iris")
    assert (r["jobs"], r["unfinished"], r["not_started"], r["misses"], r["miss_ratio"]) == (24, 0, 0, 3, 0.125)
    assert r["miss_wilson95"] == pytest.approx(stats.wilson_interval(3, 24))
    assert r["miss_cp95"] == pytest.approx(exact(3, 24))  # [2.66%, 32.4%]
    assert r["longest_miss_run"] == 2  # seq 1 and 2 of stream 0; 1 if rows were left in file order
    assert r["max_misses_in_window"] == {"10": 3, "100": None, "1000": None}
    s0, s1 = r["per_stream"]
    assert (s0["stream"], s0["jobs"], s0["misses"], s0["longest_miss_run"], s0["max_misses_in_window"]["10"]) == ("0", 12, 3, 2, 3)
    assert (s1["stream"], s1["jobs"], s1["misses"], s1["longest_miss_run"]) == ("1", 12, 0, 0)
    resp = r["response_us"]  # ms: eight 2s, twelve 3s, 10, 11, 12, 13
    assert (resp["n"], resp["min"], resp["p50"], resp["max"]) == (24, 2000, 3000, 13000)
    assert resp["mean"] == pytest.approx(98_000 / 24)
    assert (r["queueing_us"]["mean"], r["queueing_us"]["sd"]) == (1000, 0)
    assert r["auth_us"]["mean"] == pytest.approx(98_000 / 24 - 1500)
    assert r["service_us"]["mean"] == pytest.approx(98_000 / 24 - 1000)


def test_footer_job_counts_must_be_those_of_the_rows():
    """The harness writes the job counts of a sender's footer and the rows from the same jobs: released = rows,
    started = rows with a start_ns, confirmed = rows with a send_done_ns, dropped at release = rows without a start_ns
    (they agree in all 104 real files of 2026-11-23). Hand-made rows: one release dropped, one job started and not
    confirmed, three complete."""
    cols = {"release_ns": np.array([10, 20, 30, 40, 50]), "start_ns": np.array([11, 0, 31, 41, 51]),
            "auth_done_ns": np.array([12, 0, 32, 42, 0]), "send_done_ns": np.array([13, 0, 33, 43, 0])}
    footer = {"jobs_released": "5", "jobs_dropped_at_release": "1", "jobs_started": "4", "jobs_confirmed": "3"}
    assert periodic.consistency(footer, cols) == []
    assert periodic.consistency({}, cols) == [] == periodic.consistency({"jobs_started": "4"}, cols)  # only what the footer has
    assert periodic.consistency({**footer, "jobs_released": "6"}, cols) == ["jobs_released=6 in the footer, but the file has 5 rows"]
    assert periodic.consistency({**footer, "jobs_started": "5", "jobs_confirmed": "5"}, cols) == [
        "jobs_started=5 in the footer, but the file has 4 rows with a start_ns",
        "jobs_confirmed=5 in the footer, but the file has 3 rows with a send_done_ns"]
    assert periodic.consistency({**footer, "jobs_dropped_at_release": "0"}, cols) == [
        "jobs_dropped_at_release=0 in the footer, but the file has 1 rows without a start_ns"]
    assert periodic.consistency({**footer, "jobs_released": "many"}, cols) == ["jobs_released=many in the footer is not a count"]
    # a line that is no count among the two the jobs rule judges is reported there, once
    assert periodic.consistency({**footer, "jobs_started": "-1"}, cols) == []


def test_periodic_deadline_comes_from_deadline_ns_and_is_strict(tmp_path):
    """Stream 0 has responses of 10, 11, 12 and 13 ms; the period stays 10 ms throughout."""
    for deadline_ms, misses in ((10, 3), (11, 2), (9.5, 4), (20, 0)):
        r = periodic_tx(tmp_path, deadline_ns=round(deadline_ms * MS))
        assert (r["period_us"], r["deadline_us"], r["misses"]) == (10_000, deadline_ms * 1000, misses)


@pytest.mark.parametrize("key", periodic.HEADER)
def test_periodic_header_key_is_mandatory(tmp_path, key):
    with pytest.raises(ValueError, match=f"missing header key.*{key}"):
        periodic_tx(tmp_path, **{key: None})


@pytest.mark.parametrize("override", [{"profile": "mldsa"}, {"scheduler": "rr"}, {"period_ns": "10ms"},
                                      {"deadline_ns": 0}, {"cores": "one"}, {"streams": 3}])
def test_periodic_header_values_are_validated(tmp_path, override):
    with pytest.raises(ValueError, match=next(iter(override))):
        periodic_tx(tmp_path, **override)


def test_periodic_file_with_a_signature_stream_and_a_mac_stream(tmp_path):
    """DATA_SCHEMA.md, 'Profile both in the periodic files (E9, cell h)': profile=both with one profile per stream
    index in stream_profiles; that line belongs to this profile and to no other."""
    r = periodic_tx(tmp_path, profile="both", stream_profiles="mldsa65,mac")
    assert (r["profile"], r["stream_profiles"], r["streams"]) == ("both", ["mldsa65", "mac"], 2)
    assert "stream_profiles" not in periodic_tx(tmp_path)
    # in a file of one variant the line is not needed; one that repeats the file's profile is taken, one that contradicts it is not
    assert "stream_profiles" not in periodic_tx(tmp_path, stream_profiles="mldsa65,mldsa65")
    for override, message in (({"profile": "both"}, "profile=both needs the line stream_profiles"),
                              ({"profile": "both", "stream_profiles": "mldsa65"}, "stream_profiles='mldsa65' does not name one profile"),
                              ({"profile": "both", "stream_profiles": "mldsa65,both"}, "stream_profiles='mldsa65,both' does not name one profile"),
                              ({"stream_profiles": "mldsa65,mac"}, "stream_profiles='mldsa65,mac' contradicts profile=mldsa65")):
        with pytest.raises(ValueError, match=message):
            periodic_tx(tmp_path, **override)


def test_periodic_optional_header_keys_are_validated_and_reported(tmp_path):
    r = periodic_tx(tmp_path, mainfunction="cyclic", mf_period_us=1000, phase="sync", partition=0)
    assert (r["mainfunction"], r["mf_period_us"], r["phase"], r["partition"]) == ("cyclic", 1000, "sync", 0)
    assert not {"mainfunction", "mf_period_us", "phase", "partition"} & set(periodic_tx(tmp_path))  # absent keys are not invented
    for override, message in (({"mainfunction": "polled"}, "mainfunction='polled' is not one of"),
                              ({"phase": "random"}, "phase='random' is not one of"),
                              ({"partition": "-1"}, "partition='-1' is not a non-negative integer"),
                              ({"mf_period_us": "1ms"}, "mf_period_us='1ms' is not a non-negative integer")):
        with pytest.raises(ValueError, match=message):
            periodic_tx(tmp_path, **override)


def test_periodic_tx_stage_declared_not_recorded_is_not_a_missed_stage(tmp_path):
    """The gateway application has no timestamp for the authenticator: auth_done_ns is 0 in every row."""
    rows = [(*r[:4], 0, r[5]) for r in synth.periodic_tx_rows()]
    full, r = periodic_tx(tmp_path), periodic_tx(tmp_path, rows, not_recorded="auth_done_ns")
    assert r["not_recorded"] == ["auth_done_ns"] and r["auth_us"] is None and full["not_recorded"] == []
    for k in ("jobs", "unfinished", "misses", "miss_ratio", "longest_miss_run", "response_us", "queueing_us", "service_us"):
        assert r[k] == full[k]
    with pytest.raises(ValueError, match="timestamps must satisfy.*must say '# not_recorded=auth_done_ns'"):
        periodic_tx(tmp_path, rows)  # without the key a 0 is a stage the job did not reach
    with pytest.raises(ValueError, match=r"not_recorded names auth_done_ns, but 24 row\(s\) carry a value"):
        periodic_tx(tmp_path, not_recorded="auth_done_ns")
    with pytest.raises(ValueError, match="not_recorded=send_done_ns: only auth_done_ns can be analysed as not recorded"):
        periodic_tx(tmp_path, not_recorded="send_done_ns")
    rows[3] = (*rows[3][:3], 0, 0, rows[3][5])  # sent without having started: impossible with or without the key
    with pytest.raises(ValueError, match="timestamps must satisfy"):
        periodic_tx(tmp_path, rows, not_recorded="auth_done_ns")


def test_periodic_partitions_are_combined_as_independent_processes(tmp_path):
    """Two gateway processes: one with two streams (24 jobs, 3 misses), one with a single stream (12 jobs, none)."""
    a = periodic_tx(tmp_path, partition=0)
    meta, cols = load(tmp_path, "periodic_tx_p1.csv", synth.text(synth.TX_HEADER, [synth._job(0, s, 0, 3) for s in range(12)],
                                                                 synth.tx_meta(1, partition=1)))
    b = periodic.analyse_tx(meta, cols)
    assert periodic.combine([a, b]) == {"partitions": 2, "streams": 3, "cores": 2, "jobs": 36, "misses": 3,
                                        "miss_ratio": 3 / 36, "miss_cp95": pytest.approx(exact(3, 36))}
    assert periodic_tx(tmp_path, partitions=4, partition=3)["partitions"] == 4  # the '# partitions=' line is kept
    # the sensitivity figure of a cell: the same combination over the partitions whose transmitter reports no
    # retransmitted segment in the window. A count above 0, or one that was not given, leaves the partition out.
    def with_counts(*counts):
        return [{**p, "transport": {"tcp_total_retrans_in_window": c}} for p, c in zip((a, b), counts)]

    second = periodic.combine(with_counts(0, 2))["no_retrans"]  # only the first process (24 jobs, 3 misses) is left
    assert second == {"partitions": 1, "left_out_retransmitted": 1, "left_out_unknown": 0, "streams": 2, "jobs": 24, "misses": 3,
                      "miss_ratio": 0.125, "miss_cp95": pytest.approx(exact(3, 24))}
    both = periodic.combine(with_counts(0, 0))
    assert {k: both["no_retrans"][k] for k in ("partitions", "jobs", "misses", "miss_ratio")} == {k: both[k] for k in ("partitions", "jobs", "misses", "miss_ratio")}
    unknown = periodic.combine(with_counts(None, 0))["no_retrans"]  # not given is not zero
    assert (unknown["partitions"], unknown["left_out_unknown"], unknown["jobs"], unknown["misses"]) == (1, 1, 12, 0)
    none_left = periodic.combine(with_counts(1, 3))["no_retrans"]
    assert none_left == {"partitions": 0, "left_out_retransmitted": 2, "left_out_unknown": 0, "streams": None, "jobs": None,
                         "misses": None, "miss_ratio": None, "miss_cp95": None}
    assert "no_retrans" not in periodic.combine(with_counts(None, None))  # no file gives the count: no second figure


def test_periodic_unfinished_jobs_are_deadline_misses(tmp_path):
    rows = synth.periodic_tx_rows()
    st, seq, rel, start, auth, _ = rows[22]  # stream 1 seq 10: authenticated but never sent
    rows[22] = (st, seq, rel, start, auth, 0)
    st, seq, rel, *_ = rows[23]  # stream 1 seq 11: dropped before it started
    rows[23] = (st, seq, rel, 0, 0, 0)
    r = periodic_tx(tmp_path, rows)
    assert (r["jobs"], r["unfinished"], r["not_started"], r["misses"], r["miss_ratio"]) == (24, 2, 1, 5, 5 / 24)
    assert (r["per_stream"][1]["misses"], r["per_stream"][1]["longest_miss_run"]) == (2, 2)
    # time statistics cover only the jobs that reached the stage
    assert (r["response_us"]["n"], r["service_us"]["n"], r["auth_us"]["n"], r["queueing_us"]["n"]) == (22, 22, 23, 23)
    assert r["response_us"]["max"] == 13000 and r["queueing_us"]["mean"] == 1000
    assert periodic.service_ns(load(tmp_path, "periodic_tx.csv", synth.periodic_tx_two_streams(rows))[1]).size == 22


@pytest.mark.parametrize("row", [
    lambda rel: (rel, 0, rel + 5, rel + 9),        # authenticated without having started
    lambda rel: (rel, rel + 1, 0, rel + 9),        # sent without having been authenticated
    lambda rel: (rel, 0, 0, rel + 9),
    lambda rel: (rel, rel + 5, rel + 3, rel + 9),  # auth_done before start
    lambda rel: (rel, rel + 5, rel + 7, rel + 6),  # send_done before auth_done
    lambda rel: (rel, rel - 1, rel + 5, rel + 9),  # start before release
    lambda rel: (0, 0, 0, 0),                      # release 0 would make "0 = not reached" ambiguous
])
def test_periodic_rejects_impossible_timestamps(tmp_path, row):
    rows = synth.periodic_tx_rows()
    st, seq, rel, *_ = rows[23]
    rows[23] = (st, seq, *row(rel))
    with pytest.raises(ValueError, match="stream 1, seq 11"):
        periodic_tx(tmp_path, rows)


def test_periodic_seq_must_be_contiguous_from_zero(tmp_path):
    rows = synth.periodic_tx_rows()
    with pytest.raises(ValueError, match="stream 0: seq is not contiguous from 0 .expected 3, found 4"):
        periodic_tx(tmp_path, rows[:3] + rows[4:])  # stream 0 never logged seq 3
    with pytest.raises(ValueError, match="stream 1: seq is not contiguous from 0 .expected 5, found 4"):
        periodic_tx(tmp_path, rows + [synth._job(1, 4, 5, 3)])  # stream 1 seq 4 twice
    with pytest.raises(ValueError, match="stream 0: seq is not contiguous from 0 .expected 0, found 1"):
        periodic_tx(tmp_path, rows[1:])  # stream 0 starts at seq 1


def test_periodic_release_offsets(tmp_path):
    _, cols = load(tmp_path, "periodic_tx.csv", synth.periodic_tx_two_streams())
    assert periodic.release_offsets_ns(cols, 10 * MS).tolist() == [0, 5 * MS]  # streams "0" and "1"


def rx_case(tmp_path, clock=None, offset=synth.RX_AHEAD, rx_meta=None):
    """Stream 0: seq 0..4, stream 1: seq 0..2 (responses 2 ms). Rx rows are scrambled in the file;
    arrival order is rx_done_ns. Verification takes 400, 410, ... us in the order listed.
    With `rx_meta` (comment lines of the Rx file) rx_done_ns is written as 0 in every row."""
    tx_rows = [synth._job(0, s, 0, 2) for s in range(5)] + [synth._job(1, s, 5, 2) for s in range(3)]
    job = {(r[0], r[1]): r for r in tx_rows}

    def rejected(row, decision_us):  # a rejected PDU has its reject decision in verify_done_ns and is never delivered
        return (*row[:3], row[2] + 1000 * decision_us, 0, row[5])

    rx_rows = [
        synth.rx_row(job[0, 1], latency_us=30_000, verify_us=400, offset=offset),   # overtaken by seq 2: out of order
        synth.rx_row(job[0, 0], latency_us=300, verify_us=410, offset=offset),
        synth.rx_row(job[0, 2], latency_us=400, verify_us=420, offset=offset),
        synth.rx_row(job[0, 2], latency_us=15_000, verify_us=430, offset=offset),   # duplicate, arrives later
        rejected(synth.rx_row(job[0, 4], result="auth_fail", offset=offset), 425),  # seq 3 never arrives: lost
        synth.rx_row(job[1, 0], latency_us=500, verify_us=440, offset=offset),
        rejected(synth.rx_row(job[1, 1], result="freshness_fail", offset=offset), 15),
        synth.rx_row(job[1, 2], latency_us=600, verify_us=450, offset=offset),
        synth.rx_row((1, 7, 0, 0, 0, job[1, 2][5] + 10 * MS), verify_us=460, offset=offset),  # never logged by the sender
        (-1, -1, job[1, 2][5] + offset + 20 * MS, 0, 0, "framing_fail"),  # no PDU was recovered: stream = seq = -1
    ]
    _, tx = load(tmp_path, "periodic_tx.csv", synth.text(synth.TX_HEADER, tx_rows))
    if rx_meta is not None:
        rx_rows = [(*r[:2], 0, *r[3:]) for r in rx_rows]
    meta, rx = load(tmp_path, "periodic_rx.csv", synth.text(synth.RX_HEADER, rx_rows, rx_meta or ()))
    if clock is not None:
        clock = load(tmp_path, "clock_offset.csv", clock)[1]
    return periodic.analyse_rx(tx, rx, clock, meta)


def test_periodic_rx_known_values(tmp_path):
    r = rx_case(tmp_path)
    assert {k: r[k] for k in ("tx_jobs", "rx_rows", "delivered", "delivery_ratio", "lost", "duplicates",
                              "out_of_order", "rx_not_in_tx")} == \
        {"tx_jobs": 8, "rx_rows": 10, "delivered": 5, "delivery_ratio": 0.625, "lost": 1, "duplicates": 1,
         "out_of_order": 1, "rx_not_in_tx": 1}  # the framing_fail row is counted below and matched to nothing
    assert r["by_result"] == {"ok": 7, "freshness_fail": 1, "auth_fail": 1, "framing_fail": 1}
    # reject-decision time per failure class: verify_done - rx_done
    assert {k: (d["n"], d.get("mean")) for k, d in r["reject_us"].items()} == {"freshness_fail": (1, 15), "auth_fail": (1, 425)}
    # verification and delivery time over the seven ok rows: 400..460 us, delivery 20 us later
    v, d = r["verify_us"], r["deliver_us"]
    assert (v["n"], v["mean"], v["min"], v["p50"], v["max"]) == (7, 430, 400, 430, 460)
    assert (d["n"], d["mean"], d["max"]) == (7, 450, 480)
    assert r["per_stream"] == [
        {"stream": "0", "tx_jobs": 5, "delivered": 3, "lost": 1, "by_result": {"ok": 4, "freshness_fail": 0, "auth_fail": 1}},
        {"stream": "1", "tx_jobs": 3, "delivered": 2, "lost": 0, "by_result": {"ok": 3, "freshness_fail": 1, "auth_fail": 0}}]
    assert [ps["stream"] for ps in r["per_stream"]] == ["0", "1"]  # the -1 of the framing_fail row is not a stream
    assert r["latency"] is None and r["latency_note"] == "not reported (no clock relation)"


def test_periodic_rx_without_reception_timestamps(tmp_path):
    """rx_done_ns declared not recorded (gateway application): the counts stand, arrival order is the
    order of the accept/reject decisions, and no time that starts at reception is reported."""
    full = rx_case(tmp_path)
    r = rx_case(tmp_path, clock=synth.clock_offset(), rx_meta=("not_recorded=rx_done_ns",))
    for k in ("tx_jobs", "rx_rows", "delivered", "delivery_ratio", "lost", "duplicates", "out_of_order", "rx_not_in_tx",
              "by_result", "per_stream"):
        assert r[k] == full[k]
    assert (r["not_recorded"], full["not_recorded"]) == (["rx_done_ns"], [])
    assert r["verify_us"] is None and r["deliver_us"] is None and r["reject_us"] == {}
    assert r["latency"] is None and r["latency_note"] == "not reported (rx_done_ns not recorded)"
    with pytest.raises(ValueError, match="every row needs 0 < rx_done_ns.*must say '# not_recorded=rx_done_ns'"):
        rx_case(tmp_path, rx_meta=())  # zeros without the declaration
    _, tx = load(tmp_path, "periodic_tx.csv", synth.periodic_tx_two_streams())
    meta, rx = load(tmp_path, "periodic_rx.csv", synth.text(synth.RX_HEADER, [synth.rx_row(r) for r in synth.periodic_tx_rows()],
                                                           ("not_recorded=rx_done_ns",)))
    with pytest.raises(ValueError, match=r"not_recorded names rx_done_ns, but 24 row\(s\) carry a value"):
        periodic.analyse_rx(tx, rx, None, meta)
    with pytest.raises(ValueError, match="not_recorded=deliver_ns: only rx_done_ns can be analysed as not recorded"):
        rx_case(tmp_path, rx_meta=("not_recorded=deliver_ns",))


def test_periodic_rx_ok_row_needs_ordered_timestamps(tmp_path):
    tx_rows = [synth._job(0, 0, 0, 2)]
    _, tx = load(tmp_path, "periodic_tx.csv", synth.text(synth.TX_HEADER, tx_rows))
    good = synth.rx_row(tx_rows[0])
    for bad in ((*good[:3], good[2] - 1, good[4], "ok"), (*good[:4], good[3] - 1, "ok"), (*good[:2], 0, 5, 9, "ok")):
        _, rx = load(tmp_path, "periodic_rx.csv", synth.text(synth.RX_HEADER, [bad]))
        with pytest.raises(ValueError, match="stream 0, seq 0.*rx_done_ns <= verify_done_ns <= deliver_ns"):
            periodic.analyse_rx(tx, rx)


@pytest.mark.parametrize("row,what", [
    ((0, 0, 500, 900, 950, "auth_fail"), "deliver_ns = 0"),        # a rejected PDU was delivered
    ((0, 0, 500, 0, 0, "auth_fail"), "rx_done_ns <= verify_done_ns"),  # no reject decision recorded
    ((0, 0, 500, 400, 0, "freshness_fail"), "rx_done_ns <= verify_done_ns"),
    ((-1, -1, 500, 900, 0, "framing_fail"), "framing_fail: verify_done_ns = deliver_ns = 0"),
    ((-1, -1, 0, 0, 0, "framing_fail"), "0 < rx_done_ns"),
    # by the schema a framing_fail row carries stream = seq = -1, and no other row does
    ((0, 0, 500, 0, 0, "framing_fail"), "only a framing_fail row does"),
    ((-1, 4, 500, 0, 0, "framing_fail"), "only a framing_fail row does"),
    ((0, -1, 500, 900, 950, "ok"), "only a framing_fail row does"),
    ((-1, 0, 500, 900, 0, "auth_fail"), "only a framing_fail row does"),
    ((0, -2, 500, 900, 950, "ok"), "only a framing_fail row does"),
])
def test_periodic_rx_stage_rules_per_result(tmp_path, row, what):
    _, tx = load(tmp_path, "periodic_tx.csv", synth.text(synth.TX_HEADER, [synth._job(0, 0, 0, 2)]))
    _, rx = load(tmp_path, "periodic_rx.csv", synth.text(synth.RX_HEADER, [row]))
    with pytest.raises(ValueError, match=f"stream {row[0]}, seq {row[1]}, result {row[5]}.*{re.escape(what)}"):
        periodic.analyse_rx(tx, rx)


def test_clock_relation_interpolates_between_probes(tmp_path):
    clock = load(tmp_path, "clock_offset.csv", synth.text(synth.CLOCK_HEADER, [(1000, 100, 9, "ping"), (0, 0, 9, "ping")]))[1]
    # offset 0 at t=0 and 100 at t=1000: 50 at t=500; outside the probes the nearest one is used
    assert periodic.rx_on_tx_clock(np.array([500, 2000, 0]), clock).tolist() == [450, 1900, 0]


def test_periodic_latency_known_values(tmp_path):
    lat = rx_case(tmp_path, synth.clock_offset())["latency"]
    # first ok arrival of each delivered job: 300 us (0/0), 30 ms (0/1), 400 us (0/2), 500 us (1/0), 600 us (1/2)
    one = lat["one_way_us"]
    assert (one["n"], one["min"], one["p50"], one["max"]) == (5, 300, 500, 30_000)
    assert one["mean"] == pytest.approx((300 + 30_000 + 400 + 500 + 600) / 5)
    # end to end = response 2 ms + one-way latency + delivery; delivery is verify + 20 us = 430, 420, 440, 460, 470
    e2e = lat["end_to_end_us"]
    assert (e2e["n"], e2e["min"], e2e["max"]) == (5, 2000 + 300 + 430, 2000 + 30_000 + 420)
    assert (lat["clock_samples"], lat["clock_rtt_max_us"], lat["outside_clock_span"]) == (2, 250, 0)
    assert "Rx clock - Tx clock" in lat["convention"]


def test_periodic_latency_counts_arrivals_outside_the_probed_span(tmp_path):
    late_probe_missing = synth.text(synth.CLOCK_HEADER, [(7_900 * MS, synth.RX_AHEAD, 200_000, "ping"),
                                                         (8_003 * MS, synth.RX_AHEAD, 200_000, "ping")])
    lat = rx_case(tmp_path, late_probe_missing)["latency"]
    assert lat["outside_clock_span"] == 4 and lat["one_way_us"]["min"] == 300  # only 0/0 arrived before 8.003 s


@pytest.mark.parametrize("true_offset", [500 * MS, -500 * MS])
def test_periodic_latency_rejects_the_wrong_offset_sign(tmp_path, true_offset):
    """The right sign passes whichever clock is ahead; the wrong sign is caught in both directions."""
    assert rx_case(tmp_path, synth.clock_offset(true_offset), true_offset)["latency"]["one_way_us"]["min"] == 300
    wrong = "before it was sent" if true_offset > 0 else "implausible"
    with pytest.raises(ValueError, match=wrong):
        rx_case(tmp_path, synth.clock_offset(true_offset), -true_offset)


def test_periodic_latency_needs_a_positive_round_trip_time(tmp_path):
    with pytest.raises(ValueError, match="rtt_ns"):
        rx_case(tmp_path, synth.text(synth.CLOCK_HEADER, [(7_900 * MS, synth.RX_AHEAD, 0, "ping")]))


# ---- throughput ----------------------------------------------------------------------------------

LADDER = [("iris", 100), ("iris", 200), ("baolong", 100), ("baolong", 200)]


def ladder(files, trim=5):
    """throughput.analyse on the synthetic files, whose samples outside 5..14 are garbage that must be trimmed."""
    return throughput.analyse(files, trim)


def tput_files(tmp_path, specs=LADDER, comments=synth.TPUT_META):
    """One file per (host, rate), as (name, config, cols): what make_tables hands to throughput.analyse."""
    files = []
    for host, rate in specs:
        name = f"throughput_{host}_{rate}.csv"
        meta, cols = load(tmp_path, name, synth.throughput(host, rate, comments))
        files.append((name, throughput.config(meta), cols))
    return files


def test_throughput_known_values(tmp_path):
    res = ladder(tput_files(tmp_path))
    rows = {(r["host"], r["offered_pps"]): r for r in res["rows"]}
    assert len(rows) == 4
    a = rows["iris", 100]
    assert (a["file"], a["role"], a["intervals"], a["window_s"]) == ("throughput_iris_100.csv", "tx", 9, 9)
    assert a["pps_mean"] == 100 and a["pps_ci95"] == [100, 100]
    assert a["cpu_util"] == 0.25 and a["wire_mbit_s"] == pytest.approx(2.72) and a["wire_bytes_per_pdu"] == 3400
    assert (a["sendq_mean_bytes"], a["sendq_max_bytes"], a["sendq_growing"]) == (7000, 8000, False)
    assert a["sendq_slope_bytes_per_s"] == pytest.approx(-5000 / 82.5)
    assert a["sendq_growth_bytes"] == pytest.approx(9 * -5000 / 82.5)  # the fitted slope over the 9 s of the window
    assert (a["drops"], a["drop_ratio"]) == (0, 0)
    b = rows["iris", 200]
    assert b["pps_mean"] == 150 and b["cpu_util"] == 0.99 and b["wire_mbit_s"] == pytest.approx(4.08)
    assert (b["sendq_mean_bytes"], b["sendq_max_bytes"], b["sendq_growing"]) == (95_000, 140_000, True)
    assert b["sendq_slope_bytes_per_s"] == pytest.approx(10_000) and b["sendq_growth_bytes"] == pytest.approx(90_000)
    # ... and per step over the repetitions (one here)
    assert res["saturation"]["steps"][1]["across"]["sendq_growth_bytes"]["max"] == pytest.approx(90_000)
    assert (b["drops"], b["drop_ratio"]) == (450, 0.25)  # 450 / (1350 + 450), the generator's own drops
    c = rows["baolong", 100]
    assert (c["role"], c["pps_mean"], c["cpu_util"], c["wire_bytes_per_pdu"], c["sendq_max_bytes"]) == ("rx", 100, 0.10, 3400, 0)
    assert c["wire_mbit_s"] == pytest.approx(2.72) and c["tx_mbit_s"] == pytest.approx(0.0528)
    sat = res["saturation"]
    assert (sat["saturation_pps"], sat["loss_max"], res["reps"]) == (100, 0.001, [None])
    s100, s200 = sat["steps"]
    assert (s100["delivered_pps"], s100["sendq_growing"], s100["sustained"]) == (100, False, True)  # baolong delivered
    assert (s200["delivered_pps"], s200["sendq_growing"], s200["sustained"]) == (150, True, False)
    # loss of a repetition, from the counters of both hosts over the same samples: the generator released
    # done + drops PDUs; lost = its drops + (sent - delivered)
    (r100,), (r200,) = s100["reps"], s200["reps"]
    assert (r100["rep"], r100["offered_pdus"], r100["lost_pdus"], r100["loss_ratio"], r100["sustained"]) == (None, 900, 0, 0, True)
    assert r100["loss_cp95"] == pytest.approx(exact(0, 900)) and r100["files"] == ["throughput_iris_100.csv", "throughput_baolong_100.csv"]
    assert (r200["offered_pdus"], r200["lost_pdus"], r200["loss_ratio"], r200["sustained"]) == (1800, 450, 0.25, False)
    assert r200["loss_cp95"] == pytest.approx(exact(450, 1800))
    # the transmitter's own part of that: the releases it dropped at a full queue, here all 450 of the 1800 offered
    assert (r100["dropped_pdus"], r200["dropped_pdus"]) == (0, 450)
    assert s200["across"]["tx_drop_ratio"] == {"n": 1, "mean": 0.25, "min": 0.25, "max": 0.25, "t95": [None, None]}
    assert s100["across"]["tx_drop_ratio"]["mean"] == 0
    assert (s100["n_reps"], s100["judged_reps"], s100["sustained_reps"], s200["sustained_reps"]) == (1, 1, 1, 0)


def reps_files(tmp_path, specs):
    """(host, rate, repetition, PDUs per steady second, samples) -> files as make_tables hands them over."""
    files = []
    for host, rate, rep, steady, *samples in specs:
        name = f"throughput_{host}_{rate}_rep{rep}.csv"
        meta, cols = load(tmp_path, name, synth.throughput(host, rate, synth.TPUT_META, steady, *samples))
        files.append((name, {**throughput.config(meta), "rep": rep}, cols))
    return files


def one_step(tmp_path, tx_steady, rx_steady, *rx_samples):
    res = ladder(reps_files(tmp_path, [("iris", 100, 1, tx_steady), ("baolong", 100, 1, rx_steady, *rx_samples)]))
    return res["saturation"]["steps"][0]["reps"][0]


def test_throughput_loss_threshold_is_compared_in_whole_pdus(tmp_path):
    """Nine steady seconds. The generator sends 1000 PDUs/s: 9000 offered, so 9 lost is exactly 0.001."""
    at = one_step(tmp_path, (1000,), (999,))
    assert (at["offered_pdus"], at["lost_pdus"], at["loss_ratio"], at["sustained"]) == (9000, 9, 0.001, True)
    over = one_step(tmp_path, (1000,), (999,) * 8 + (998,))
    assert (over["lost_pdus"], over["sustained"]) == (10, False) and over["loss_cp95"] == pytest.approx(exact(10, 9000))
    # a PDU that was in flight at the first sample is delivered inside the window: more delivered than sent is no loss
    ahead = one_step(tmp_path, None, (101,))
    assert (ahead["offered_pdus"], ahead["lost_pdus"], ahead["loss_ratio"], ahead["sustained"]) == (900, 0, 0, True)
    # the drops are counted on the transmitter, the loss ratio end to end: at 200 PDU/s the generator sends 1350 and
    # drops 450 of 1800; a receiver that delivers 1359 inside the window (9 PDUs sent before it) leaves 441 not
    # delivered. The 450 dropped releases are therefore not a part "of" the 441, and the two ratios are 25% and 24.5%
    res = ladder(reps_files(tmp_path, [("iris", 200, 1, None), ("baolong", 200, 1, (151,))]))
    (step,) = res["saturation"]["steps"]
    (both,) = step["reps"]
    assert (both["offered_pdus"], both["lost_pdus"], both["dropped_pdus"], both["loss_ratio"]) == (1800, 441, 450, 0.245)
    assert step["across"]["tx_drop_ratio"]["mean"] == 0.25 > step["across"]["loss_ratio"]["mean"]
    # the two hosts' samples are compared index by index: with different numbers of samples there is no loss figure
    ragged = one_step(tmp_path, None, None, 21)
    assert (ragged["offered_pdus"], ragged["lost_pdus"], ragged["loss_ratio"], ragged["loss_cp95"], ragged["sustained"]) == \
        (None, None, None, None, None)
    assert ragged["note"] == "not judged: the tx and rx files have different numbers of samples (20, 21)"


def test_throughput_repetition_is_the_unit_of_replication(tmp_path):
    """Three repetitions of one step. The receiver delivers 100, 99 and 98 PDUs/s: 0, 9 and 18 of 900 lost."""
    spec = [("iris", 100, k, None) for k in (1, 2, 3)] + [("baolong", 100, 1, None), ("baolong", 100, 2, (99,)), ("baolong", 100, 3, (98,))]
    res = ladder(reps_files(tmp_path, spec))
    assert res["reps"] == [1, 2, 3] and len(res["rows"]) == 6 and {r["rep"] for r in res["rows"]} == {1, 2, 3}
    (step,) = res["saturation"]["steps"]
    assert [(r["rep"], r["lost_pdus"], r["sustained"]) for r in step["reps"]] == [(1, 0, True), (2, 9, False), (3, 18, False)]
    assert (step["n_reps"], step["judged_reps"], step["sustained_reps"], step["sustained"]) == (3, 3, 1, False)
    assert res["saturation"]["saturation_pps"] is None
    a = step["across"]  # one value per repetition; the 1-second samples of different repetitions are never pooled
    lo, hi = sps.t.interval(0.95, 2, loc=99, scale=1 / 3 ** 0.5)  # 100, 99, 98: sd 1
    assert a["delivered_pps"] == {"n": 3, "mean": 99, "min": 98, "max": 100, "t95": pytest.approx([lo, hi])}
    assert step["delivered_pps"] == 99
    # secondary: the counts of the three repetitions pooled, 27 of 2700, with the exact interval of that proportion
    assert step["pooled_loss"] == {"reps": 3, "lost_pdus": 27, "offered_pdus": 2700, "loss_ratio": 0.01,
                                   "loss_cp95": pytest.approx(exact(27, 2700))}
    assert (a["loss_ratio"]["mean"], a["loss_ratio"]["min"], a["loss_ratio"]["max"]) == (pytest.approx(0.01), 0, 0.02)
    # none of these 27 PDUs was dropped at release: the generator sent all 900 each time, the receiver delivered fewer
    assert [r["dropped_pdus"] for r in step["reps"]] == [0, 0, 0]
    assert a["tx_drop_ratio"] == {"n": 3, "mean": 0, "min": 0, "max": 0, "t95": [0, 0]}
    # a loss ratio is a proportion: the Student-t interval, which reaches to -1.5% here, is clamped to [0, 1]
    assert (lo - 99) / 100 + 0.01 < 0 and a["loss_ratio"]["t95"] == [0, pytest.approx((hi - 99) / 100 + 0.01)]
    assert a["tx_cpu_util"] == {"n": 3, "mean": 0.25, "min": 0.25, "max": 0.25, "t95": [0.25, 0.25]}
    assert (a["rx_cpu_util"]["mean"], a["wire_mbit_s"]["mean"]) == (pytest.approx(0.10), pytest.approx(2.72))
    assert (a["sendq_mean_bytes"]["mean"], a["sendq_max_bytes"]["max"]) == (7000, 8000)
    assert a["sendq_slope_bytes_per_s"]["mean"] == pytest.approx(-5000 / 82.5)
    # every repetition must pass: three clean repetitions sustain the step
    clean = ladder(reps_files(tmp_path, [(h, 100, k, None) for h in ("iris", "baolong") for k in (1, 2, 3)]))
    (step,) = clean["saturation"]["steps"]
    assert (step["sustained"], step["sustained_reps"], clean["saturation"]["saturation_pps"]) == (True, 3, 100)
    assert step["across"]["delivered_pps"]["t95"] == [100, 100]
    # a repetition that cannot be judged leaves the step unjudged, unless another repetition already failed
    partial = ladder(reps_files(tmp_path, [(h, 100, k, None) for h in ("iris", "baolong") for k in (1, 2, 3)][:-1]))
    (step,) = partial["saturation"]["steps"]
    assert (step["n_reps"], step["judged_reps"], step["sustained_reps"], step["sustained"]) == (3, 2, 2, None)
    assert step["reps"][2]["note"] == "not judged: the rx file is missing, invalid or incomplete" and step["across"]["delivered_pps"]["n"] == 2
    assert partial["saturation"]["saturation_pps"] is None
    (step,) = ladder(reps_files(tmp_path, spec[:-1]))["saturation"]["steps"]
    assert (step["judged_reps"], step["sustained"]) == (2, False)
    # one repetition: its values, and no interval
    (step,) = ladder(reps_files(tmp_path, [("iris", 100, 4, None), ("baolong", 100, 4, None)]))["saturation"]["steps"]
    assert step["across"]["delivered_pps"] == {"n": 1, "mean": 100, "min": 100, "max": 100, "t95": [None, None]}


def test_throughput_cpu_counters_one_tick_is_rounding_two_are_a_contradiction(tmp_path):
    """total = busy + idle + iowait, each a whole number of ticks. The kernel's split between idle and iowait is
    provisional, so the two truncated parts of a growing sum can read one tick less than before (5.0 + 4.0 -> 9, later
    5.95 + 3.95 -> 8): busy may grow by one tick more than total. Such a step counts as fully busy and is counted.
    Two ticks, or a busy counter that goes backwards, is not rounding: the file is invalid."""
    def check(rows):
        _, cols = load(tmp_path, "throughput.csv", synth.text(synth.TPUT_HEADER, rows, synth.TPUT_META))
        return throughput.consistency(cols), throughput.one_tick_clamps(cols)

    good = [list(r) for r in synth.throughput_rows("iris", 100)]  # t_ns 5 s, 6 s, ...; busy is column 4, total column 5

    def changed(*edits):  # (first row, column, amount): the counter is shifted from that row on
        rows = [r[:] for r in good]
        for first, column, amount in edits:
            for r in rows[first:]:
                r[column] += amount
        return rows

    assert check(good) == ([], 0)
    assert check(changed((8, 4, 75))) == ([], 0)  # busy grows by exactly the total, 100: a full second on the processor
    # the rounding example: busy stands still (25 - 25) and total reads one tick less (100 - 101) at 13 s
    assert check(changed((8, 4, -25), (8, 5, -101))) == ([], 1)
    # ... and with busy growing: 101 against 100 at 15 s; both steps are counted
    rounding = changed((8, 4, -25), (8, 5, -101), (10, 4, 76))
    assert check(rounding) == ([], 2)
    two = "1 sample step(s) in which the busy jiffies grew by 2 or more ticks more than the total jiffies (first: t_ns 13000000000)"
    assert check(changed((8, 4, 77))) == ([two], 0)                 # 102 against 100
    # busy stands still and total goes back by two or more: named for what it is, with the number of ticks
    assert check(changed((8, 4, -25), (8, 5, -102))) == (
        ["1 sample step(s) in which idle plus iowait went backwards by 2 ticks (first: t_ns 13000000000)"], 0)
    assert check(changed((8, 4, -25), (8, 5, -102), (11, 4, -25), (11, 5, -105))) == (
        ["2 sample step(s) in which idle plus iowait went backwards by 2 to 5 ticks (first: t_ns 13000000000)"], 0)
    assert check(changed((8, 4, 77), (11, 4, -25), (11, 5, -105))) == (
        [two, "1 sample step(s) in which idle plus iowait went backwards by 5 ticks (first: t_ns 16000000000)"], 0)
    assert check(changed((8, 4, 200), (10, 4, 76))) == ([two], 1)   # 225 against 100, and one tick elsewhere
    assert check(changed((3, 4, -50))) == (["1 sample step(s) in which cpu_busy_jiffies went backwards (first: t_ns 8000000000)"], 0)
    # the utilisation of the nine steady seconds (225 of 900 jiffies) with the two rounding steps counted as fully
    # busy: busy 225 - 25 + 76 = 276; total 900 - 100 (0 of 0 at 13 s) + 1 (101 of 101 at 15 s) = 801
    files = []
    for name, rows in (("throughput_iris_100.csv", rounding), ("throughput_baolong_100.csv", synth.throughput_rows("baolong", 100))):
        meta, cols = load(tmp_path, name, synth.text(synth.TPUT_HEADER, rows, synth.TPUT_META))
        files.append((name, throughput.config(meta), cols))
    tx = next(r for r in ladder(files)["rows"] if r["role"] == "tx")
    assert (tx["cpu_util"], tx["cpu_one_tick_clamps"], tx["cpu_steps"]) == (pytest.approx(276 / 801), 2, 19)
    rx = next(r for r in ladder(files)["rows"] if r["role"] == "rx")
    assert (rx["cpu_util"], rx["cpu_one_tick_clamps"], rx["cpu_steps"]) == (pytest.approx(0.1), 0, 19)
    # a file with two ticks does not reach the analysis through make_tables; handed over directly it is refused
    meta, cols = load(tmp_path, "throughput_iris_100.csv", synth.text(synth.TPUT_HEADER, changed((8, 4, 77)), synth.TPUT_META))
    with pytest.raises(ValueError, match="throughput_iris_100.csv: the busy jiffies grew by 2 or more ticks more than the total"):
        ladder([("throughput_iris_100.csv", throughput.config(meta), cols), files[1]])


def test_throughput_sensitivity_over_the_repetitions_without_a_retransmission(tmp_path):
    """Retransmissions never drop a file. Every delivery figure is formed over all repetitions, and a second time
    over the repetitions whose transmitter files all report tcp_total_retrans_in_window = 0. Three repetitions at 100
    PDU/s: the second retransmitted one segment and delivered 99 PDU/s (9 of 900 lost), the others are clean."""
    retrans = "tcp_total_retrans_in_window"

    def files(counts, rx=(None, (99,), None), rate=100):  # counts: the transmitter's count per repetition
        out = reps_files(tmp_path, [("iris", rate, k, None) for k in (1, 2, 3)]
                         + [("baolong", rate, k, steady) for k, steady in zip((1, 2, 3), rx)])
        for (name, cfg, _), count in zip(out[:3], counts):
            cfg["transport"] = {retrans: count, "tcp_dsack_dups_in_window": 0, "tcp_total_rto_in_window": None}
        return out

    res = ladder(files((0, 1, 0)))["saturation"]
    (step,) = res["steps"]
    assert (step["n_reps"], step["sustained_reps"], step["sustained"], res["saturation_pps"]) == (3, 2, False, None)  # over all
    quiet = res["no_retrans"]
    (q,) = quiet["steps"]
    assert (quiet["reps_left_out"], quiet["files_with_retrans"], quiet["files_unknown"], quiet["files_known"]) == (1, 1, 0, 3)
    assert (q["offered_pps"], q["kept_reps"], q["left_out"]) == (100, [1, 3], {2: "retransmitted"})
    assert (q["n_reps"], q["sustained_reps"], q["sustained"], quiet["saturation_pps"]) == (2, 2, True, 100)
    assert q["across"]["delivered_pps"] == {"n": 2, "mean": 100, "min": 100, "max": 100, "t95": [100, 100]}
    assert (q["across"]["loss_ratio"]["max"], step["across"]["loss_ratio"]["max"]) == (0, 0.01)
    assert (q["pooled_loss"]["lost_pdus"], q["pooled_loss"]["offered_pdus"]) == (0, 1800)
    # nothing retransmitted: the second line repeats the first
    same = ladder(files((0, 0, 0)))["saturation"]
    assert same["no_retrans"]["steps"][0]["across"] == same["steps"][0]["across"]
    assert (same["no_retrans"]["reps_left_out"], same["no_retrans"]["steps"][0]["sustained"], same["steps"][0]["sustained"]) == (0, False, False)
    # a count that was not given is not zero: that repetition is left out as 'unknown'
    part = ladder(files((0, None, 0)))["saturation"]["no_retrans"]
    assert (part["steps"][0]["left_out"], part["files_unknown"], part["files_with_retrans"], part["saturation_pps"]) == ({2: "unknown"}, 1, 0, 100)
    # every repetition retransmitted: no repetition is left, the step is not judged and ends the sustained range
    none = ladder(files((2, 1, 5), rx=(None, None, None)))["saturation"]
    assert (none["saturation_pps"], none["no_retrans"]["saturation_pps"], none["no_retrans"]["range_ended_at"]) == (100, None, 100)
    assert (none["no_retrans"]["steps"][0]["n_reps"], none["no_retrans"]["steps"][0]["sustained"], none["no_retrans"]["steps"][0]["across"]["delivered_pps"]) == \
        (0, None, None)
    # a repetition whose transmitter file is missing or invalid cannot be judged in either line: it is not a file
    # 'without the count', and leaving it out would turn 'not judged' into 'sustained' for a reason that is no retransmission
    gap = files((0, 0, 0), rx=(None, None, None))
    gap = [f for f in gap if f[0] != "throughput_iris_100_rep2.csv"]
    gap = ladder(gap)["saturation"]
    assert (gap["steps"][0]["sustained"], gap["no_retrans"]["steps"][0]["sustained"]) == (None, None)
    assert (gap["no_retrans"]["steps"][0]["kept_reps"], gap["no_retrans"]["steps"][0]["left_out"]) == ([1, 2, 3], {})
    assert (gap["no_retrans"]["reps_left_out"], gap["no_retrans"]["files_unknown"], gap["no_retrans"]["files_known"]) == (0, 0, 2)
    # files that give no count at all (old files): nothing is known, and the output says so
    old = ladder(reps_files(tmp_path, [(h, 100, k, None) for h in ("iris", "baolong") for k in (1, 2, 3)]))["saturation"]["no_retrans"]
    assert (old["files_known"], old["files_unknown"], old["reps_left_out"], old["saturation_pps"]) == (0, 3, 3, None)


def test_throughput_processor_time_of_the_process(tmp_path):
    """The sampler's 13th column, proc_cpu_ns, is the cumulative processor time of the harness process. Over the steady
    window its growth divided by the growth of t_ns is the share of one core: 250 ms per second here for the sender,
    1.2 s per second for a receiver with several busy threads. A 12-column file has no such figure."""
    def files(specs):
        out = []
        for host, rate, proc_ns, rep in specs:
            name = f"throughput_{host}_{rate}_rep{rep}.csv"
            meta, cols = load(tmp_path, name, synth.throughput(host, rate, proc_ns=proc_ns))
            out.append((name, {**throughput.config(meta), "rep": rep}, cols))
        return out

    res = ladder(files([("iris", 100, 250_000_000, 1), ("baolong", 100, 1_200_000_000, 1)]))
    tx, rx = (next(r for r in res["rows"] if r["role"] == role) for role in ("tx", "rx"))
    assert (tx["proc_cpu_share"], rx["proc_cpu_share"]) == (pytest.approx(0.25), pytest.approx(1.2))  # nine steady seconds
    assert tx["cpu_util"] == 0.25  # the jiffies figure is untouched
    # old files, or one old file beside a new one: no figure for the 12-column file, and no failure
    mixed = ladder(files([("iris", 100, 250_000_000, 1), ("baolong", 100, None, 1)]))
    assert [r["proc_cpu_share"] for r in mixed["rows"] if r["role"] == "rx"] == [None]
    assert [r["proc_cpu_share"] for r in mixed["rows"] if r["role"] == "tx"] == [pytest.approx(0.25)]
    # across repetitions: mean, interval, minimum and maximum; not a proportion, so nothing is clamped (above 1 here)
    reps = ladder(files([("iris", 100, 250_000_000, 1), ("baolong", 100, 1_200_000_000, 1),
                         ("iris", 100, 350_000_000, 2), ("baolong", 100, 900_000_000, 2)]))
    across = reps["saturation"]["steps"][0]["across"]
    lo, hi = sps.t.interval(0.95, 1, loc=1.05, scale=np.std([1.2, 0.9], ddof=1) / 2 ** 0.5)
    assert across["rx_proc_cpu_share"] == {"n": 2, "mean": pytest.approx(1.05), "min": pytest.approx(0.9), "max": pytest.approx(1.2),
                                           "t95": pytest.approx([lo, hi])}
    assert hi > 1 and (across["tx_proc_cpu_share"]["mean"], across["tx_proc_cpu_share"]["n"]) == (pytest.approx(0.3), 2)
    # the counter is cumulative: a value that goes backwards stops the run
    name = "throughput_iris_100_rep3.csv"
    text = synth.throughput("iris", 100, proc_ns=250_000_000).splitlines()
    text[14] = text[14].rsplit(",", 1)[0] + ",5"
    meta, cols = load(tmp_path, name, "\n".join(text) + "\n")
    with pytest.raises(ValueError, match="cumulative counter proc_cpu_ns went backwards"):
        ladder([(name, {**throughput.config(meta), "rep": 3}, cols), *files([("baolong", 100, None, 3)])])


def test_interval_of_a_proportion_over_repetitions_stays_in_its_range():
    """The Student-t interval of a mean knows no range: for a proportion (loss ratio, CPU utilisation) its ends are
    clamped to [0, 1]; a rate keeps its interval, and an interval inside the range is untouched."""
    low, high = throughput._across([0.0, 0.0, 0.003], proportion=True), throughput._across([0.999, 1.0, 0.998], proportion=True)
    free = sps.t.interval(0.95, 2, loc=0.001, scale=np.std([0.0, 0.0, 0.003], ddof=1) / 3 ** 0.5)
    assert free[0] < 0 and low["t95"] == [0, pytest.approx(free[1])] and low["mean"] == pytest.approx(0.001)
    free = sps.t.interval(0.95, 2, loc=0.999, scale=0.001 / 3 ** 0.5)
    assert free[1] > 1 and high["t95"] == [pytest.approx(free[0]), 1]
    inside = sps.t.interval(0.95, 2, loc=0.25, scale=0.05 / 3 ** 0.5)
    assert throughput._across([0.2, 0.3, 0.25], proportion=True)["t95"] == pytest.approx(inside)
    assert throughput._across([0.0, 0.0, 0.003])["t95"][0] < 0  # not a proportion: as computed
    assert throughput._across([0.4], proportion=True)["t95"] == [None, None]


def test_saturation_point_needs_every_lower_step_sustained(tmp_path):
    """A step behaves like the synthetic 100 pps step (sustained) or the 200 pps step (queue grows, 25% lost)."""
    def steps(*spec, hosts=("iris", "baolong")):
        files = []
        for offered, like in spec:
            for host in hosts if like else hosts[:1]:  # like None: the receiver file is missing
                name = f"throughput_{host}_{offered}.csv"
                meta, cols = load(tmp_path, name, synth.throughput(host, like or 100, offered=offered))
                files.append((name, throughput.config(meta), cols))
        return ladder(files)["saturation"]

    up = steps((100, 100), (300, 100), (400, 200))
    assert (up["saturation_pps"], up["range_ended_at"], up["non_monotone"]) == (300, 400, [])
    assert [s["sustained"] for s in up["steps"]] == [True, True, False]
    # a higher step that passes does not count once a lower one has failed
    dip = steps((100, 100), (200, 200), (300, 100), (500, 100))
    assert (dip["saturation_pps"], dip["range_ended_at"], dip["non_monotone"]) == (100, 200, [300, 500])
    # a step that cannot be judged ends the sustained range as well
    gap = steps((100, 100), (250, None), (300, 100))
    assert [s["sustained"] for s in gap["steps"]] == [True, None, True]
    assert (gap["saturation_pps"], gap["range_ended_at"], gap["non_monotone"]) == (100, 250, [300])
    first = steps((200, 200), (300, 100))  # the lowest step already fails: no saturation point
    assert (first["saturation_pps"], first["range_ended_at"], first["non_monotone"]) == (None, 200, [300])
    clean = steps((100, 100), (300, 100))
    assert (clean["saturation_pps"], clean["range_ended_at"], clean["non_monotone"]) == (300, None, [])
    assert "every lower step" in clean["criterion"]


def test_throughput_uses_every_sample_unless_told_otherwise(tmp_path):
    """The harness leaves the ramp out of its samples, so the default drops nothing."""
    files = tput_files(tmp_path, LADDER[::2])  # 100 pps, both hosts; 20 samples, the outer ones are synthetic garbage
    res = throughput.analyse(files)
    assert res["trim"] == 0 and {r["intervals"] for r in res["rows"]} == {19}
    assert {r["intervals"] for r in throughput.analyse(files, 5)["rows"]} == {9}
    rep = res["saturation"]["steps"][0]["reps"][0]  # ten garbage intervals add 10 PDUs on each host
    assert (rep["offered_pdus"], rep["lost_pdus"]) == (910, 0)


def test_throughput_repetition_labels_must_be_complete_and_unique(tmp_path):
    files = reps_files(tmp_path, [("iris", 100, 1, None), ("baolong", 100, 1, None)])
    with pytest.raises(ValueError, match="some files of the ladder have a repetition number and some do not"):
        ladder(files + tput_files(tmp_path, LADDER[1:2]))
    with pytest.raises(ValueError, match=r"throughput_iris_100_rep1.csv and copy.csv are both the tx host at 100 pps \(repetition 1\); "
                                         "a repetition needs its own '# rep=' line or a file label rep<k>"):
        ladder(files + [("copy.csv", *files[0][1:])])
    good = dict(c.split("=") for c in synth.TPUT_META)
    assert throughput.config({**good, "rep": "3", "partitions": "4"}) == {**throughput.config(good), "rep": 3, "partitions": 4}
    with pytest.raises(ValueError, match="rep='two' is not a non-negative integer"):
        throughput.config({**good, "rep": "two"})


def test_throughput_partitions_line_names_the_number_of_partitions(tmp_path):
    """With '# partitions=N' a missing partition is seen even when it is missing on both hosts."""
    def parts(specs, n):
        files = []
        for host, part in specs:
            name = f"throughput_{host}_100_p{part}.csv"
            meta, cols = load(tmp_path, name, synth.throughput(host, 100, (*synth.TPUT_META, f"partition={part}", f"partitions={n}")))
            files.append((name, throughput.config(meta), cols))
        return files

    whole = ladder(parts([(h, i) for h in ("iris", "baolong") for i in (0, 1)], 2))
    assert (whole["partitions"], whole["cores"], whole["incomplete"], whole["saturation"]["saturation_pps"]) == (2, 2, [], 200)
    short = ladder(parts([("iris", 0), ("baolong", 0)], 2))  # partition 1 is missing on both hosts
    assert (short["partitions"], short["cores"], short["rows"]) == (2, 2, [])
    assert short["incomplete"] == [{"offered_pps": 200, "rep": None, "role": role, "partitions": [0], "expected": [0, 1]}
                                   for role in ("tx", "rx")]
    (step,) = short["saturation"]["steps"]
    assert (step["offered_pps"], step["sustained"], step["reps"][0]["note"]) == (200, None, "not judged: the tx and rx files are missing, invalid or incomplete")
    with pytest.raises(ValueError, match=r"partition 2 in a ladder of partitions=2"):
        ladder(parts([("iris", 2)], 2))


def tput_parts(tmp_path, specs):
    """(host, rate offered by that partition, partition, PDUs per steady second, samples) -> files as make_tables
    hands them to throughput.analyse."""
    files = []
    for host, rate, part, steady, *samples in specs:
        name = f"throughput_{host}_{rate}_p{part}.csv"
        meta, cols = load(tmp_path, name, synth.throughput(host, rate, (*synth.TPUT_META, f"partition={part}"), steady, *samples))
        files.append((name, throughput.config(meta), cols))
    return files


PARTS = [("iris", 100, 0, None), ("iris", 100, 1, (90, 110), 21), ("baolong", 100, 0, None), ("baolong", 100, 1, (90, 110))]


def test_throughput_partitions_of_a_rate_step_are_summed(tmp_path):
    """Two gateway processes that each offer 100 PDU/s make one 200 PDU/s step. Partition 1 does 90, 110, 90, ...
    PDUs per second, so the per-second sums over the 9 common intervals are 190, 210, ..., 190 (five and four)."""
    res = ladder(tput_parts(tmp_path, PARTS))
    assert (res["partitions"], res["cores"], res["incomplete"]) == (2, 2, [])
    sums = np.array([190, 210] * 4 + [190], dtype=float)
    lo, hi = sps.t.interval(0.95, 8, loc=sums.mean(), scale=sps.sem(sums))
    tx, rx = res["rows"]
    assert (tx["file"], tx["role"], tx["offered_pps"], tx["partitions"], tx["intervals"]) == \
        ("throughput_iris_100_p0.csv + throughput_iris_100_p1.csv", "tx", 200, 2, 9)  # the 10th interval of p1 has no partner
    assert tx["pps_mean"] == pytest.approx(1790 / 9) and tx["pps_ci95"] == pytest.approx([lo, hi])
    assert tx["cpu_util"] == pytest.approx(451 / 1900)  # busy / total jiffies over both windows: (225 + 226) / (900 + 1000)
    # the interface counters are the host's, not the process's: taken from one partition, never added
    assert tx["wire_mbit_s"] == pytest.approx(2.72) and tx["wire_bytes_per_pdu"] == pytest.approx(340_000 * 9 / 1790)
    # two connections: the mean depths add up (7000 + 78000 / 11 bytes), the maximum is the deepest single queue
    assert (tx["sendq_mean_bytes"], tx["sendq_max_bytes"], tx["sendq_growing"]) == (pytest.approx(7000 + 78_000 / 11), 8000, False)
    assert (tx["drops"], tx["drop_ratio"], tx["sendq_slope_lower95"]) == (0, 0, None)
    assert (rx["role"], rx["offered_pps"], rx["pps_mean"], rx["cpu_util"]) == ("rx", 200, pytest.approx(1790 / 9), 0.10)
    parts = {(p["host"], p["partition"]): p for p in res["parts"]}
    assert len(parts) == 4 and parts["iris", 1]["intervals"] == 10 and parts["baolong", 1]["pps_mean"] == pytest.approx(890 / 9)
    assert parts["iris", 0]["pps_mean"] == 100 and parts["iris", 0]["offered_pps"] == 100
    (step,) = res["saturation"]["steps"]
    # partition 1 of the sender has one sample more than its receiver: the pair cannot be compared, so no loss count
    assert (step["offered_pps"], step["delivered_pps"], step["sustained"]) == (200, pytest.approx(1790 / 9), None)
    assert step["reps"][0]["note"] == "not judged: the tx and rx files have different numbers of samples (21, 20)"
    even = ladder(tput_parts(tmp_path, [(h, 100, i, None) for h in ("iris", "baolong") for i in (0, 1, 2)]))
    assert (even["cores"], even["saturation"]["saturation_pps"], even["rows"][1]["pps_mean"]) == (3, 300, 300)
    rep = even["saturation"]["steps"][0]["reps"][0]  # the counts of the three partitions are added
    assert (rep["offered_pdus"], rep["lost_pdus"], rep["sustained"]) == (2700, 0, True)
    assert even["rows"][0]["sendq_slope_bytes_per_s"] == pytest.approx(3 * -5000 / 82.5)


def test_throughput_single_process_ladder_is_its_own_sum(tmp_path):
    """bench_net writes '# partition=0' also when there is one process: nothing changes."""
    plain = ladder(tput_files(tmp_path))
    one = ladder(tput_files(tmp_path, comments=(*synth.TPUT_META, "partition=0")))
    assert (plain["partitions"], plain["cores"], plain["parts"], one["parts"]) == (1, 1, [], [])
    for a, b in zip(plain["rows"], one["rows"]):
        np.testing.assert_equal({**a, "partition": 0}, b)  # NaN-tolerant: the slope bound of a constant queue is NaN
        assert a["partition"] is None
    assert plain["saturation"] == one["saturation"]


def test_throughput_partition_sets_must_be_complete_and_unambiguous(tmp_path):
    lone = ladder(tput_parts(tmp_path, PARTS[:3]))  # the receiver file of partition 1 is missing
    assert [r["role"] for r in lone["rows"]] == ["tx"] and len(lone["parts"]) == 3
    assert lone["incomplete"] == [{"offered_pps": 200, "rep": None, "role": "rx", "partitions": [0], "expected": [0, 1]}]
    (step,) = lone["saturation"]["steps"]
    assert (step["offered_pps"], step["delivered_pps"], step["sustained"]) == (200, None, None)
    assert lone["saturation"]["saturation_pps"] is None
    with pytest.raises(ValueError, match=r"throughput_iris_100_p0.csv and copy.csv are both the tx host at 100 pps \(partition 0\); "
                                         "a repetition needs its own '# rep=' line"):
        ladder(tput_parts(tmp_path, PARTS[:1]) + [("copy.csv", *tput_parts(tmp_path, PARTS[:1])[0][1:])])
    with pytest.raises(ValueError, match="some files of the ladder have a '# partition=' line and some do not"):
        ladder(tput_parts(tmp_path, PARTS[:1]) + tput_files(tmp_path, LADDER[2:3]))
    with pytest.raises(ValueError, match=r"partitions \[0, 2\] of the ladder are not 0\.\.1: the files of a partition are missing"):
        ladder(tput_parts(tmp_path, [("iris", 100, 0, None), ("iris", 100, 2, None)]))
    good = dict(c.split("=") for c in synth.TPUT_META)
    assert throughput.config({**good, "partition": "2", "mainfunction": "event", "mf_period_us": "1000"}) == \
        {**throughput.config(good), "partition": 2, "mainfunction": "event", "mf_period_us": 1000}
    with pytest.raises(ValueError, match="partition='p1' is not a non-negative integer"):
        throughput.config({**good, "partition": "p1"})


def test_throughput_step_without_both_hosts_is_not_judged(tmp_path):
    """A sender's own rate is not a delivered rate, and without the sender the queue cannot be checked."""
    tx_only = ladder(tput_files(tmp_path, LADDER[:2]))
    assert len(tx_only["rows"]) == 2 and tx_only["saturation"]["saturation_pps"] is None
    assert [(s["delivered_pps"], s["sendq_growing"], s["sustained"]) for s in tx_only["saturation"]["steps"]] == \
        [(None, False, None), (None, True, None)]
    assert tx_only["saturation"]["steps"][0]["reps"][0]["note"] == "not judged: the rx file is missing, invalid or incomplete"
    rx_only = ladder(tput_files(tmp_path, LADDER[2:]))["saturation"]
    assert rx_only["saturation_pps"] is None
    assert [(s["delivered_pps"], s["sendq_growing"], s["sustained"]) for s in rx_only["steps"]] == \
        [(100, None, None), (150, None, None)]
    partial = ladder(tput_files(tmp_path, LADDER[:3]))["saturation"]  # the rx file at 200 pps is missing
    assert partial["saturation_pps"] == 100 and [s["sustained"] for s in partial["steps"]] == [True, None]


def queue_step(tmp_path, sendq, pdu=37, pps=500):
    """One rate step, a tx / rx file pair per gateway process, one-second samples that are all in the window (trim 0).
    `sendq[k]`: the send queue of process k in each sample. Every process sends `pps` PDUs of `pdu` bytes per second, one
    PDU per packet under 66 bytes of headers; the interface counters are the host's, the same in every process's file."""
    files, wire = [], len(sendq) * pps * (pdu + 66)
    for part, depths in enumerate(sendq):
        for host in ("iris", "baolong"):
            out = wire if host == "iris" else 0
            rows = [(i * 10**9, host, pps, i * pps, i, 100 * i, i * out, i * len(sendq) * pps * bool(out), i * (wire - out),
                     i * len(sendq) * pps * (not out), depths[i] if out else 0, 0) for i in range(len(depths))]
            name = f"throughput_{host}_{pps}pps_p{part}.csv"
            meta, cols = load(tmp_path, name, synth.text(synth.TPUT_HEADER, rows, (*synth.TPUT_META, f"partition={part}")))
            files.append((name, throughput.config(meta), cols))
    return files


def tx_row(res):
    (row,) = [r for r in res["rows"] if r["role"] == "tx"]
    return row


def test_throughput_queue_grows_only_by_at_least_one_queued_pdu(tmp_path):
    """Ruling of 2026-11-23 (CAMPAIGN.md, '"Sustained" (E7), made robust'): the send queue of a repetition is growing only
    when the lower bound of its fitted slope, times the length of the window, is at least one PDU as it is queued."""
    # the dry run's case: an empty queue in 20 samples and one PDU of 37 bytes in the last. Least squares over
    # t = 0..20 s: Sxx = 770 and Sxy = 10 * 37, so the slope is 37/77 bytes/s; Syy = 37^2 * 20/21
    res = throughput.analyse(queue_step(tmp_path, [[0] * 20 + [37]]) + queue_step(tmp_path, [[0] * 21], pps=1000))
    tx = res["rows"][0]
    lower = 37 / 77 - sps.t.ppf(0.95, 19) * math.sqrt((37**2 * 20 / 21 - 370**2 / 770) / 19 / 770)
    assert (tx["role"], tx["offered_pps"], tx["window_s"]) == ("tx", 500, 20)
    assert tx["sendq_slope_bytes_per_s"] == pytest.approx(37 / 77) and tx["sendq_slope_lower95"] == pytest.approx(lower)
    assert 0 < lower < 0.001  # above zero: the rule before this one called the queue growing
    assert tx["queued_bytes_per_pdu"] == 37 and tx["sendq_growth_lower95_bytes"] == pytest.approx(20 * lower)
    assert tx["sendq_growing"] is False
    sat = res["saturation"]
    assert (sat["saturation_pps"], sat["non_monotone"], [s["sustained"] for s in sat["steps"]]) == (1000, [], [True, True])
    assert "at least one PDU as it is queued" in sat["criterion"] and "66 bytes" in sat["criterion"]  # which size is used
    # one queue, 360 bytes more in each second of a 9 s window (3,240 bytes; exactly linear, so the bound is the slope):
    # growing when a PDU is that size ('at least') or one byte smaller, not growing when it is one byte larger. Nothing is
    # lost: the queue alone decides whether the step is sustained
    for pdu, growing in ((3239, True), (3240, True), (3241, False)):
        res = throughput.analyse(queue_step(tmp_path, [[360 * i for i in range(10)]], pdu, 100))
        tx = tx_row(res)
        assert (tx["queued_bytes_per_pdu"], tx["sendq_growing"]) == (pdu, growing)
        assert tx["sendq_growth_lower95_bytes"] == pytest.approx(3240)
        assert res["saturation"]["steps"][0]["sustained"] is (not growing)
    # the receiver's file gives no size and no verdict
    rx = next(r for r in res["rows"] if r["role"] == "rx")
    assert (rx["queued_bytes_per_pdu"], rx["sendq_growing"]) == (None, None)


def test_throughput_each_connection_is_judged_against_the_size_of_the_step(tmp_path):
    """Two processes: the interface counters are the host's, so one PDU is the host's payload over the PDUs of both,
    3,235 bytes (one file alone would give twice that). The second connection's queue grows by 4,860 bytes, more than one
    PDU and less than two; the step's bound is the larger of its connections' bounds."""
    res = throughput.analyse(queue_step(tmp_path, [[0] * 10, [540 * i for i in range(10)]], 3235, 50))
    tx = tx_row(res)
    assert (tx["partitions"], tx["offered_pps"], tx["sendq_slope_lower95"]) == (2, 100, None)
    assert tx["queued_bytes_per_pdu"] == pytest.approx(3235) and tx["sendq_growth_lower95_bytes"] == pytest.approx(4860)
    assert tx["sendq_growing"] is True
    parts = [p for p in res["parts"] if p["role"] == "tx"]
    assert [(p["sendq_growing"], p["queued_bytes_per_pdu"]) for p in parts] == [(False, pytest.approx(3235)), (True, pytest.approx(3235))]
    assert [p["sendq_growth_lower95_bytes"] for p in parts] == [0, pytest.approx(4860)]
    assert res["saturation"]["steps"][0]["sustained"] is False


def test_throughput_queue_without_a_size_is_not_judged(tmp_path):
    """Interface counters that leave no payload after the headers (they count something else than this connection's
    frames) give no size: the queue is then not judged, never 'not growing', and neither is the repetition."""
    res = throughput.analyse(queue_step(tmp_path, [[0] * 10], 0, 100))
    tx, (rep,) = tx_row(res), res["saturation"]["steps"][0]["reps"]
    assert (tx["queued_bytes_per_pdu"], tx["sendq_growing"], tx["sendq_growth_lower95_bytes"]) == (None, None, 0)
    assert (rep["loss_ratio"], rep["sendq_growing"], rep["sustained"], rep["note"]) == (0, None, None, throughput.NO_SIZE)
    assert res["saturation"]["saturation_pps"] is None
    # a repetition that fails on the loss is not sustained whatever the queue is: 100 releases dropped beside 900 PDUs sent
    files = queue_step(tmp_path, [[0] * 10], 0, 100)
    files[0][2]["drops"][:] = [100 * (i > 0) for i in range(10)]
    (rep,) = throughput.analyse(files)["saturation"]["steps"][0]["reps"]
    assert (rep["dropped_pdus"], rep["sendq_growing"], rep["sustained"]) == (100, None, False)


def test_throughput_header_is_mandatory_and_validated():
    good = dict(c.split("=") for c in synth.TPUT_META)
    assert throughput.config(good) == {"tx_host": "iris", "rx_host": "baolong", "profile": "mldsa65", "cores": 1, "commit": "abc1234"}
    for key in throughput.HEADER:
        with pytest.raises(ValueError, match=f"missing header key.*{key}"):
            throughput.config({k: v for k, v in good.items() if k != key})
    with pytest.raises(ValueError, match="ambiguous"):
        throughput.config({**good, "rx_host": "iris"})
    with pytest.raises(ValueError, match="cores"):
        throughput.config({**good, "cores": "four"})


def test_throughput_role_comes_from_the_header_and_is_cross_checked(tmp_path):
    swapped = ("tx_host=baolong", "rx_host=iris", *synth.TPUT_META[2:])
    with pytest.raises(ValueError, match="makes 'iris' the rx host, but its interface sent 3060000 and received 59400"):
        ladder(tput_files(tmp_path, [("iris", 100)], swapped))
    with pytest.raises(ValueError, match="makes 'baolong' the tx host"):
        ladder(tput_files(tmp_path, [("baolong", 100)], swapped))
    strangers = ("tx_host=alpha", "rx_host=beta", *synth.TPUT_META[2:])
    with pytest.raises(ValueError, match="neither tx_host 'alpha' nor rx_host 'beta'"):
        ladder(tput_files(tmp_path, [("iris", 100)], strangers))


def test_throughput_rejects_bad_input(tmp_path):
    with pytest.raises(ValueError, match="need at least 21"):
        ladder(tput_files(tmp_path, LADDER[:1]), trim=9)
    cfg = throughput.config(dict(c.split("=") for c in synth.TPUT_META))

    def one(name, rows):
        return [(name, cfg, load(tmp_path, name, synth.text(synth.TPUT_HEADER, rows, synth.TPUT_META))[1])]

    with pytest.raises(ValueError, match="one host at one offered rate"):  # two rate steps in one file
        ladder(one("throughput_a.csv", synth.throughput_rows("iris", 100) + synth.throughput_rows("iris", 200)))
    with pytest.raises(ValueError, match="one host at one offered rate"):  # two hosts in one file
        ladder(one("throughput_b.csv", synth.throughput_rows("iris", 100) + synth.throughput_rows("baolong", 100)))
    rows = [list(r) for r in synth.throughput_rows("iris", 100)]
    rows[10][3] = 0  # pdus_done of a steady-state sample falls below the one before
    with pytest.raises(ValueError, match="throughput_c.csv: cumulative counter pdus_done went backwards"):
        ladder(one("throughput_c.csv", rows))
    twice = tput_files(tmp_path, LADDER[:1])
    with pytest.raises(ValueError, match="both the tx host at 100 pps; a repetition needs its own '# rep=' line or a file "
                                         "label rep<k>"):
        ladder(twice + [("copy.csv", *twice[0][1:])])


# ---- cyclictest ----------------------------------------------------------------------------------

def cyc(tmp_path, env=None, **kw):
    p = tmp_path / "cyclictest_x.txt"
    p.write_text(synth.cyclictest(**kw))
    return cyclictest.analyse(*cyclictest.read(p), env)


def test_cyclictest_known_values(tmp_path):
    r = cyc(tmp_path)  # buckets 3: 100, 4: 800, 5: 80, 6: 15, 10: 4, 40: 1
    assert (r["policy"], r["cpu"], r["priority"], r["load"], r["load_from_header"]) == ("fifo", 3, 80, "cpu3", False)
    assert (r["interval_us"], r["duration_s"], r["host"], r["histogram_us"]) == (1000, 1, "iris", 50)
    assert (r["samples"], r["overflows"], r["min_us"], r["avg_us"], r["max_us"]) == (1000, 0, 3, 4, 40)
    assert r["mean_us"] == pytest.approx(4.07)  # (300 + 3200 + 400 + 90 + 40 + 40) / 1000
    # cumulative counts 100, 900, 980, 995, 999, 1000: the 990th, 999th and 1000th sample
    assert (r["p99_us"], r["p99.9_us"], r["p99.99_us"]) == (6, 10, 40)
    assert r["validity"] == {"valid": True, "reasons": [], "warnings": [], "freq_khz_start": "1500000",
                             "freq_khz_end": "1500000", "throttled_start": "throttled=0x0",
                             "throttled_end": "throttled=0x0", "throttled": False}
    assert cyc(tmp_path, policy="other", load="signing")["load"] == "signing"


def test_cyclictest_late_wake_ups(tmp_path):
    """Wake-ups later than 100 us and than 1 ms: strictly above, overflows included."""
    assert cyc(tmp_path)["late_over"] == [{"threshold_us": 100, "k": 0}, {"threshold_us": 1000, "k": 0}]  # nothing above 40 us
    other = cyc(tmp_path, policy="other", counts={12: 900, 55: 90, 300: 10}, size=400)
    assert other["late_over"] == [{"threshold_us": 100, "k": 10}, {"threshold_us": 1000, "k": 0}]
    edge = cyc(tmp_path, counts={3: 90, 100: 4, 101: 3, 1000: 2, 1001: 1}, size=1200)  # exactly 100 us is not later than 100 us
    assert edge["late_over"] == [{"threshold_us": 100, "k": 6}, {"threshold_us": 1000, "k": 1}]
    # an overflow is at or above the histogram size: later than every threshold inside the histogram ...
    over = cyc(tmp_path, counts={3: 100, 150: 5}, size=200, overflows=2, max_line=450)
    assert over["late_over"] == [{"threshold_us": 100, "k": 7}, {"threshold_us": 1000, "k": None}]
    # ... but against a threshold beyond the histogram it cannot be placed: no count
    assert [late["k"] for late in cyc(tmp_path, overflows=2, max_line=73)["late_over"]] == [None, None]


def test_cyclictest_overflows_are_samples_outside_the_histogram(tmp_path):
    r = cyc(tmp_path, overflows=2, max_line=73)  # two wake-ups of 50 us or more are in no bucket
    assert (r["samples"], r["overflows"], r["max_us"], r["mean_us"]) == (1002, 2, 73, None)
    assert (r["p99_us"], r["p99.9_us"], r["p99.99_us"]) == (6, None, None)  # the 992nd of 1002; the 1001st and 1002nd overflowed


@pytest.mark.parametrize("kw,reason", [
    ({"complete": False}, "incomplete (Total, Min Latencies, Avg Latencies, Max Latencies, Histogram Overflows, "
                          "freq_khz_end, throttled_end missing): the run was cut short"),
    ({"end": ()}, "incomplete (freq_khz_end, throttled_end missing): the run was cut short"),
    ({"end": ("freq_khz_end=600000", "throttled_end=throttled=0x0")}, "CPU frequency changed during the run (1500000 -> 600000 kHz)"),
    ({"end": ("freq_khz_end=1500000", "throttled_end=throttled=0x4")}, "throttling active (file: get_throttled 0x0 -> 0x4)"),
    ({"end": ("freq_khz_end=1500000", "throttled_end=throttled=0x40000")}, "get_throttled changed during the run (file: 0x0 -> 0x40000)"),
    ({"observed": "TS - 3;TS - 3"}, "no thread ran as SCHED_FIFO priority 80 on cpu 3 (observed: TS - 3;TS - 3)"),
    ({"policy": "other", "observed": "TS - 3;FF 80 3"}, "threads did not all run as SCHED_OTHER on cpu 3 (observed: TS - 3;FF 80 3)"),
])
def test_cyclictest_invalid_runs(tmp_path, kw, reason):
    v = cyc(tmp_path, **kw)["validity"]
    assert v["valid"] is False and v["reasons"] == [reason]


def test_cyclictest_env_file_throttling_applies(tmp_path):
    env = {"host": "iris", "throttled": [("before", "throttled=0x0"), ("after", "throttled=0x2")]}
    assert cyc(tmp_path, env)["validity"]["reasons"] == ["throttling active (env file of iris: get_throttled 0x0 -> 0x2)"]
    env = {"host": "iris", "throttled": [("before", "throttled=0x50000"), ("after", "throttled=0x50000")]}
    v = cyc(tmp_path, env)["validity"]
    assert v["valid"] and v["throttled"] is True and len(v["warnings"]) == 1


def test_cyclictest_rejects_files_that_contradict_themselves(tmp_path):
    with pytest.raises(ValueError, match="min/max lines .3, 41. disagree with the histogram .3, 40."):
        cyc(tmp_path, max_line=41)
    with pytest.raises(ValueError, match="2 overflow.s. but Max Latencies is 40, inside the histogram of 50"):
        cyc(tmp_path, overflows=2)  # cyclictest's maximum includes the overflowed samples
    good = synth.cyclictest()
    for bad, message in ((good.replace("# Total: 000001000", "# Total: 000001001"), "sums to 1000 but '# Total:' says 1001"),
                         (good.replace("# policy=fifo\n", ""), "missing header key")):
        (tmp_path / "c.txt").write_text(bad)
        with pytest.raises(ValueError, match=message):
            cyclictest.analyse(*cyclictest.read(tmp_path / "c.txt"))
    for bad in (good.replace("000007 000000\n", ""), good.replace("000007 000000", "000007 000000 000000"),
                good.replace("000007 000000", "seven 0")):
        (tmp_path / "c.txt").write_text(bad)
        with pytest.raises(csvio.CsvError, match=r"c\.txt:\d+: expected the histogram row '000007 <count>'"):
            cyclictest.read(tmp_path / "c.txt")


# ---- attack --------------------------------------------------------------------------------------

def test_attack_known_values(tmp_path):
    _, cols = load(tmp_path, "attack.csv", synth.attack())
    r = {v["vector"]: v for v in attack.analyse(cols)}
    b = r["benign"]
    assert (b["n"], b["delivered"], b["rejected"], b["rejection_rate"], b["false_rejections"]) == (50, 50, 0, 0, 0)
    assert b["false_rejection_upper95"] == pytest.approx(1 - 0.05 ** (1 / 50))  # 5.8%, one-sided
    assert b["false_rejection_rate"] == 0 and b["false_rejection_cp95"] == pytest.approx(exact(0, 50))  # [0, 7.1%], two-sided
    assert b["by_stage"] == {"none": 50, "framing": 0, "freshness": 0, "auth": 0}
    assert b["detect_us"] == {"n": 0} and b["rejection_cp95"] == pytest.approx([0, 1 - 0.025 ** (1 / 50)])
    p = r["replay"]
    assert (p["n"], p["delivered"], p["rejected"], p["rejection_rate"]) == (20, 0, 20, 1)
    assert p["rejection_wilson95"] == pytest.approx(stats.wilson_interval(20, 20))
    assert p["by_stage"]["freshness"] == 20
    d = p["detect_us"]  # 1..20 us
    assert (d["n"], d["mean"], d["p50"], d["max"]) == (20, 10.5, 10.5, 20) and d["p95"] == pytest.approx(19.05)
    assert p["rejection_cp95"] == pytest.approx([0.025 ** (1 / 20), 1])  # exact two-sided: [83.2%, 100%]
    framing, freshness, auth = p["stages"]
    assert (freshness["stage"], freshness["count"], freshness["rate"]) == ("freshness", 20, 1)
    assert freshness["cp95"] == p["rejection_cp95"] and freshness["detect_us"]["p50"] == 10.5
    assert (auth["stage"], auth["count"], auth["rate"], auth["detect_us"]) == ("auth", 0, 0, {"n": 0})
    assert auth["cp95"] == pytest.approx([0, 1 - 0.025 ** (1 / 20)]) and framing["count"] == 0
    assert "false_rejection_upper95" not in p
    f = r["bitflip"]
    assert (f["n"], f["delivered"], f["rejected"], f["rejection_rate"]) == (10, 1, 9, 0.9)
    assert f["by_stage"] == {"none": 1, "framing": 0, "freshness": 0, "auth": 9} and f["detect_us"]["mean"] == 5
    assert f["stages"][2]["cp95"] == pytest.approx(stats.clopper_pearson_interval(9, 10)) and f["stages"][2]["rate"] == 0.9


def test_attack_session_replay_is_a_vector_of_its_own(tmp_path):
    """A PDU recorded in an earlier session and injected into a later one (schema of 2026-11-23): 30 injected, all
    rejected at the authenticator, 4 us to the decision."""
    rows = [("session_replay", i, 0, "auth", 4000) for i in range(30)] + [("benign", i, 1, "none", 0) for i in range(5)]
    _, cols = load(tmp_path, "attack.csv", synth.text("vector,iter,delivered,reject_stage,detect_ns", rows))
    replayed, benign = attack.analyse(cols)
    assert (replayed["vector"], replayed["n"], replayed["delivered"], replayed["rejected"], replayed["by_stage"]["auth"]) == \
        ("session_replay", 30, 0, 30, 30)
    assert replayed["detect_us"]["mean"] == 4 and benign["vector"] == "benign"
    with pytest.raises(csvio.CsvError, match="vector"):
        load(tmp_path, "attack.csv", synth.text("vector,iter,delivered,reject_stage,detect_ns", [("session_swap", 0, 0, "auth", 1)]))


def test_attack_detection_time_is_not_recorded_by_the_gateway_oracle(tmp_path):
    """With '# oracle=gateway_app_log' detect_ns is 0 by construction: the counts stand, the times are not measured."""
    _, cols = load(tmp_path, "attack.csv", synth.attack())
    timed, untimed = attack.analyse(cols), attack.analyse(cols, timed=False)
    for a, b in zip(timed, untimed):
        assert {k: v for k, v in a.items() if k not in ("detect_us", "stages")} == {k: v for k, v in b.items() if k not in ("detect_us", "stages")}
        assert b["detect_us"] is None and all(st["detect_us"] is None for st in b["stages"])
        assert [(st["stage"], st["count"], st["cp95"]) for st in a["stages"]] == [(st["stage"], st["count"], st["cp95"]) for st in b["stages"]]
    assert timed[1]["detect_us"]["mean"] == 10.5


def test_attack_benign_false_rejection_and_contradiction(tmp_path):
    rows = [("benign", i, 1, "none", 0) for i in range(49)] + [("benign", 49, 0, "freshness", 700)]
    _, cols = load(tmp_path, "attack.csv", synth.text("vector,iter,delivered,reject_stage,detect_ns", rows))
    (b,) = attack.analyse(cols)
    assert (b["false_rejections"], b["rejected"], b["false_rejection_rate"]) == (1, 1, 0.02)
    assert b["false_rejection_cp95"] == pytest.approx(exact(1, 50))
    assert b["false_rejection_upper95"] == pytest.approx(sps.beta.ppf(0.95, 2, 49))
    _, cols = load(tmp_path, "attack.csv", "vector,iter,delivered,reject_stage,detect_ns\nreplay,0,1,auth,5\n")
    with pytest.raises(ValueError, match="delivered=1"):
        attack.analyse(cols)


# ---- handshake -----------------------------------------------------------------------------------

def test_handshake_known_values(tmp_path):
    _, cols = load(tmp_path, "handshake.csv", synth.handshake())
    ini, rsp = handshake.analyse(cols)
    assert (ini["role"], ini["n"], ini["ok"], ini["failures"]) == ("initiator", 4, 3, {"timeout": 1})
    assert ini["results"] == {"ok": 3, "timeout": 1} and rsp["results"] == {"ok": 2}
    assert (ini["total_us"]["n"], ini["total_us"]["mean"], ini["total_us"]["p50"], ini["total_us"]["max"]) == (3, 2000, 2000, 3000)
    assert list(ini["phases_us"]) == ["keygen", "decaps", "sign", "verify", "kdf", "hash", "mac"]  # encaps unused by the initiator
    assert ini["phases_us"]["keygen"]["mean"] == 200 and ini["phases_us"]["kdf"]["max"] == 1
    assert (ini["phases_us"]["hash"]["mean"], ini["phases_us"]["mac"]["mean"]) == (15, 5)
    # compute = sum of the stage columns of each successful handshake: 571 us + keygen
    c = ini["compute_us"]
    assert (c["n"], c["min"], c["mean"], c["p50"], c["max"]) == (3, 671, 771, 771, 871)
    assert rsp["compute_us"]["mean"] == 576 and rsp["compute_us"]["n"] == 2
    assert "M4" in ini["total_means"] and "initiator's computation and two network legs" in rsp["total_means"]
    assert ini["bytes_tx"] == {"min": 3000, "median": 3000, "max": 3000} and ini["bytes_rx"]["median"] == 5000
    assert (rsp["role"], rsp["n"], rsp["ok"], rsp["failures"]) == ("responder", 2, 2, {})
    assert rsp["total_us"]["mean"] == 2000 and list(rsp["phases_us"]) == ["encaps", "sign", "verify", "kdf", "hash", "mac"]


def test_handshake_result_is_a_closed_list_and_the_old_columns_are_refused(tmp_path):
    with pytest.raises(csvio.CsvError, match="column result: 'gave_up' is not one of"):
        load(tmp_path, "handshake.csv", synth.handshake().replace("timeout", "gave_up"))
    for result in ("bad_ver", "bad_len", "unknown_id", "sig_fail", "mac_fail", "state"):
        _, cols = load(tmp_path, "handshake.csv", synth.handshake().replace("timeout", result))
        assert handshake.analyse(cols)[0]["failures"] == {result: 1}
    old = synth.handshake().replace(",hash_ns,mac_ns", "")  # the column list before 2026-11-23
    with pytest.raises(csvio.CsvError, match="handshake.csv"):
        load(tmp_path, "handshake.csv", old)


# ---- queue model ---------------------------------------------------------------------------------

def sim(service, streams, cores, jobs, offsets="synchronous"):
    offsets = np.zeros(streams) if isinstance(offsets, str) else offsets
    return simulate.miss_ratio(np.array([float(service)]), 10.0, streams, cores, jobs, np.random.default_rng(3), offsets)


def test_simulation_deterministic_cases():
    assert sim(4, streams=2, cores=1, jobs=100) == 0  # responses 4 and 8 <= 10
    # service 6, two synchronous streams, one core: finishes 6 12 18 24 30 36 42 48 against releases
    # 0 0 10 10 20 20 30 30 -> responses 6 12 8 14 10 16 12 18 -> 5 of 8 exceed 10 (10 itself does not)
    assert sim(6, streams=2, cores=1, jobs=8) == 5 / 8
    assert sim(6, streams=2, cores=2, jobs=8) == 0  # a second core removes all queueing
    assert sim(15, streams=1, cores=1, jobs=50) == 1  # overload: every response is 15 + 5k
    assert sim(10, streams=1, cores=1, jobs=50) == 0  # response == period is not a miss
    assert sim(9, streams=1, cores=1, jobs=50, offsets=None) == 0  # a single stream never queues
    # offsets 0 and 5, service 6: finishes 6 12 18 24 30 36 42 48 against releases 0 5 10 15 20 25 30 35
    # -> responses 6 7 8 9 10 11 12 13 -> 3 of 8
    assert sim(6, streams=2, cores=1, jobs=8, offsets=[0, 5]) == 3 / 8
    with pytest.raises(ValueError, match="one offset per stream"):
        sim(6, streams=2, cores=1, jobs=8, offsets=[0, 5, 7])
    # same synchronous case as above (responses 6 12 8 14 10 16 12 18) against a 13-unit deadline: 14, 16, 18
    assert simulate.miss_ratio(np.array([6.0]), 10.0, 2, 1, 8, np.random.default_rng(3), np.zeros(2), deadline=13.0) == 3 / 8


def test_simulation_random_offsets_between_best_and_worst_case():
    # service 6, two streams, one core: load 1.2, so the backlog grows and almost every job is late
    assert sim(6, streams=2, cores=1, jobs=4000, offsets=None) > 0.99
    # service 4: two jobs fit in a period whatever the offsets are
    assert sim(4, streams=2, cores=1, jobs=4000, offsets=None) == 0


def test_model_summary_is_deterministic():
    service = np.array([1.0, 2.0, 7.0])  # two streams, period 10: utilisation 2/3
    a = simulate.model(service, 10.0, 2, 1, rng=np.random.default_rng(7), draws=4, fixed_runs=2, jobs=2000)
    b = simulate.model(service, 10.0, 2, 1, rng=np.random.default_rng(7), draws=4, fixed_runs=2, jobs=2000)
    assert a == b and "measured_offsets" not in a
    c = simulate.model(service, 10.0, 2, 1, rng=np.random.default_rng(7), fixed_runs=2, jobs=2000, measured_offsets=[0, 5])
    assert c["measured_offsets"]["jobs_per_run"] == 2000
    # overload (service 6, two streams): the first 8 jobs give exactly 3/8 (hand-computed above), a longer run more
    d = simulate.model(np.array([6.0]), 10.0, 2, 1, rng=np.random.default_rng(7), draws=1, jobs=2000,
                       measured_offsets=[0, 5], measured_jobs=8)
    assert d["measured_offsets"] == {"runs": 3, "jobs_per_run": 8, "mean": 3 / 8}
    assert 0 < c["measured_offsets"]["mean"] < c["synchronous"]["mean"]  # 7 + 7 misses at once when released together; half a period apart it takes three 7s in a row
    assert a["utilisation"] == pytest.approx(2 / 3)
    r = a["random_offsets"]
    assert r["draws"] == 4 and 0 < r["min"] <= r["mean"] <= r["max"] < 1
    assert 0 < a["synchronous"]["mean"] < 1
