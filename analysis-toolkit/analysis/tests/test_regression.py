"""End-to-end regression on the published dataset run_FINAL_20260525_230303 (skipped if it is absent).

The reference numbers were produced by the two throwaway scripts this toolkit replaces; each is
compared in the precision it was reported in. Set PQC_LEGACY_RUN to point at another copy.
"""
import csv
import json
import os
from pathlib import Path

import pytest
from scipy import stats as sps

from analysis import make_tables

LEGACY = Path(os.environ.get("PQC_LEGACY_RUN", "run_FINAL_20260525_230303"))
pytestmark = pytest.mark.skipif(not (LEGACY / "perf" / "phase_compare.csv").is_file(), reason=f"{LEGACY} not available")


def listing():
    return sorted((str(p), p.stat().st_mtime_ns) for p in LEGACY.rglob("*"))


@pytest.fixture(scope="module")
def out(tmp_path_factory):
    out = tmp_path_factory.mktemp("legacy_out")
    before = listing()
    make_tables.run(LEGACY, out)
    assert listing() == before  # the audited bundle is read-only input: nothing created or modified in it
    return out


@pytest.fixture(scope="module")
def results(out):
    return json.loads((out / "summary.json").read_text())["results"]


def by_op(results, kind, source):
    (f,) = [f for f in results[kind] if f["source"] == source]
    return {o["op"]: o for o in f["ops"]}


def test_phase_compare_sign(results):
    s = by_op(results, "overhead_unpaired", "perf/phase_compare.csv")["sign"]
    assert (s["n_standalone"], s["n_csm"]) == (10_000, 10_000)
    assert (f"{s['median_standalone_us']:.2f}", f"{s['median_csm_us']:.2f}") == ("1522.05", "1524.68")
    assert f"{s['mann_whitney_p']:.3f}" == "0.636"
    assert f"{s['hl_shift']['estimate_us']:+.2f}" == "+3.13"
    assert [f"{v:+.2f}" for v in s["hl_shift"]["ci95_us"]] == ["-11.93", "+19.33"]
    assert f"{s['cliffs_delta']:+.4f}" == "+0.0039"
    tost = {t["margin"]: t["p"] for t in s["tost_log_post_hoc"]}
    assert (f"{tost[0.01]:.3g}", f"{tost[0.02]:.3g}") == ("0.191", "0.0183")


def test_phase_compare_verify(results):
    v = by_op(results, "overhead_unpaired", "perf/phase_compare.csv")["verify"]
    assert f"{v['hl_shift']['estimate_us']:+.2f}" == "+0.44"
    assert [f"{x:+.2f}" for x in v["hl_shift"]["ci95_us"]] == ["+0.30", "+0.57"]


def test_tx_perf_sign(results):
    s = by_op(results, "crypto_ops", "perf/tx_perf_10k.csv")["sign"]
    t = s["time_us"]
    assert (s["n_total"], s["n_warmup_dropped"], t["n"]) == (11_000, 1_000, 10_000)
    assert [f"{t[k]:.1f}" for k in ("mean", "p50", "p99", "max")] == ["1930.1", "1527.4", "6771.6", "17137.0"]
    assert f"{t['lag1']:.3f}" == "0.061"
    (e,) = [e for e in s["exceedance"] if e["threshold_ms"] == 10]
    assert (e["k"], e["n"]) == (17, 10_000)
    assert [f"{100 * v:.2f}%" for v in e["wilson95"]] == ["0.11%", "0.27%"]
    lo, hi = s["bootstrap"]["p50_ci95_us"]
    assert lo < t["p50"] < hi


def test_attack_raw(results):
    (f,) = results["attack"]
    assert f["source"] == "attack/attack_raw.csv" and f["legacy"]
    v = {x["vector"]: x for x in f["vectors"]}
    assert (v["benign"]["n"], v["benign"]["delivered"], v["benign"]["false_rejections"]) == (10_000, 10_000, 0)
    assert v["benign"]["false_rejection_upper95"] == pytest.approx(2.9953e-4, rel=1e-4)
    for name in ("replay", "bitflip", "auth_tamper", "freshness_rollback"):
        assert (v[name]["n"], v[name]["rejected"], v[name]["delivered"]) == (1_000, 1_000, 0)


def test_tiny_p_values_stay_nonzero(results):
    """The verify TOSTs are far in the tail; a 1 - cdf computation would return 0 or 1e-16 noise here."""
    v = by_op(results, "overhead_unpaired", "perf/phase_compare.csv")["verify"]
    p1, p2 = (t["p"] for t in v["tost_log_post_hoc"])
    assert 1e-33 < p1 < 1e-31 and 1e-151 < p2 < 1e-149
    assert 1e-7 < v["mann_whitney_p"] < 2e-7


def test_numbers_macros(out):
    """Golden strings: the manuscript prints exactly these for the published dataset."""
    with open(out / "numbers.csv", newline="") as f:
        n = {r["key"]: r["formatted"] for r in csv.DictReader(f)}
    plus, minus, sci = r"\ensuremath{+}", r"\ensuremath{-}", r"\ensuremath{%s\times10^{%d}}"
    sign = "crypto_ops.perf.sign."
    assert [n[sign + k] for k in ("n", "mean_us", "p50_us", "p50_ms", "p99_us", "max_us", "max_ms")] == \
        ["10{,}000", "1{,}930", "1{,}527", "1.53", "6{,}772", "17{,}137", "17.14"]
    assert (n[sign + "lag1"], n[sign + "cv"]) == ("0.0610", "0.699")
    # an estimate and its bounds share their decimals: 17 of 10,000 with its exact [0.099%, 0.272%] and Wilson
    # [0.106%, 0.272%] bounds needs three; 0 of 10,000 is [0, 0.0369%] exact (checked against scipy below), and an
    # exact zero prints 0% (the five zero strings below were changed by hand on 2026-11-23, while the dataset could
    # not be opened: they follow fmt_together and have not been run against it)
    assert [n[sign + "exceed_10ms." + k] for k in ("k", "p", "wilson95_lo", "wilson95_hi", "cp95_lo", "cp95_hi")] == \
        ["17", r"0.170\%", r"0.106\%", r"0.272\%", r"0.099\%", r"0.272\%"]
    assert [n[sign + "exceed_20ms." + k] for k in ("k", "p", "wilson95_lo", "wilson95_hi", "cp95_lo", "cp95_hi")] == \
        ["0", r"0\%", r"0\%", r"0.038\%", r"0\%", r"0.037\%"]
    assert [n["attack.benign." + k] for k in ("false_rejection_rate", "false_rejection_cp95_lo", "false_rejection_cp95_hi")] == \
        [r"0\%", r"0\%", r"0.037\%"]
    s, v = "overhead_unpaired.perf.sign.", "overhead_unpaired.perf.verify."
    assert [n[s + k] for k in ("hl_us", "hl_ci95_lo_us", "hl_ci95_hi_us")] == [plus + "3.1", minus + "11.9", plus + "19.3"]
    assert [n[v + k] for k in ("hl_us", "hl_ci95_lo_us", "hl_ci95_hi_us")] == [plus + "0.44", plus + "0.30", plus + "0.57"]
    assert [n[s + k] for k in ("mann_whitney_p", "tost_m1pct_p", "tost_m2pct_p", "cliffs_delta", "median_rel_diff")] == \
        ["0.64", "0.19", "0.018", plus + "0.00386", plus + r"0.17\%"]
    assert [n[v + k] for k in ("mann_whitney_p", "tost_m1pct_p", "tost_m2pct_p")] == [sci % ("1.4", -7), sci % ("3.4", -32), sci % ("1.1", -150)]
    assert (n[s + "median_standalone_us"], n[s + "median_csm_us"]) == ("1{,}522", "1{,}525")
    assert (n["attack.benign.n"], n["attack.benign.false_rejections"], n["attack.benign.false_rejection_cp95_onesided_hi"]) == \
        ("10{,}000", "0", r"0.030\%")
    assert [n["attack.replay." + k] for k in ("rejected", "rejection_rate", "rejection_cp95_lo", "rejection_cp95_hi", "rejection_wilson95_lo")] == \
        ["1{,}000", r"100\%", r"99.63\%", r"100\%", r"99.62\%"]  # 1000 of 1000: exactly one (changed by hand, not run)
    # nothing for what this dataset does not contain
    assert n["crypto_ops.perf.keygen.n"] == "0" and "crypto_ops.perf.keygen.p50_us" not in n  # one sample, dropped as warm-up
    assert not [k for k in n if k.startswith(("periodic.", "throughput.", "handshake.", "overhead_paired."))]


def test_exact_intervals_match_scipy(results):
    (e,) = [e for e in by_op(results, "crypto_ops", "perf/tx_perf_10k.csv")["sign"]["exceedance"] if e["threshold_ms"] == 10]
    ref = sps.binomtest(17, 10_000).proportion_ci(0.95, method="exact")
    assert e["cp95"] == pytest.approx([ref.low, ref.high]) and [f"{100 * v:.3f}" for v in e["cp95"]] == ["0.099", "0.272"]
    benign = [v for v in results["attack"][0]["vectors"] if v["vector"] == "benign"][0]
    ref = sps.binomtest(0, 10_000).proportion_ci(0.95, method="exact")
    assert benign["false_rejection_cp95"] == pytest.approx([ref.low, ref.high]) and f"{100 * ref.high:.4f}" == "0.0369"
