"""The entry point on a complete synthetic run directory."""
import csv
import hashlib
import inspect
import json
import math
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest
from scipy import stats as sps

from analysis import crypto_ops, csvio, make_tables, throughput
from analysis.tests import synth

PARAMS = dict(warmup=10, block_len=5, n_boot=50, sim_draws=3, sim_jobs=400, trim=5)  # trim: the synthetic ladder files
PLUS, MINUS = r"\ensuremath{+}", r"\ensuremath{-}"
TABLES = {"validity", "crypto_ops", "crypto_ops_ci", "exceedance", "sign_excess", "sign_attrib", "sign_attrib_tail", "sign_attrib_two_by_two", "sign_attrib_shares", "sign_attrib_rounds", "overhead_paired", "overhead_order", "periodic", "periodic_times",
          "periodic_rx", "periodic_rx_times", "periodic_rx_streams", "throughput", "throughput_reps", "throughput_steps",
          "throughput_saturation", "attack",
          "attack_stages", "handshake", "handshake_phases", "cyclictest"}


def strict_json(path):
    def no_constants(name):
        raise AssertionError(f"non-standard JSON constant {name}")
    return json.loads(Path(path).read_text(), parse_constant=no_constants)


@pytest.fixture(scope="module")
def done(tmp_path_factory):
    run_dir = synth.make_run(tmp_path_factory.mktemp("run"))
    out = tmp_path_factory.mktemp("out")
    make_tables.run(run_dir, out, **PARAMS)
    return run_dir, out, strict_json(out / "summary.json")


def test_writes_every_table_in_both_formats(done):
    _, out, summary = done
    assert set(summary["tables"]) == TABLES
    for name in TABLES:
        md = (out / "tables" / f"{name}.md").read_text().splitlines()
        tex = (out / "tables" / f"{name}.tex").read_text().splitlines()
        md_rows = [ln for ln in md if ln.startswith("|")][2:]
        body = [ln for ln in tex if not ln.startswith("%")]
        assert body[0].startswith(r"\begin{tabular}{l") and body[1] == r"\toprule" and body[3] == r"\midrule"
        assert body[-2:] == [r"\bottomrule", r"\end{tabular}"]
        tex_rows = body[4:-2]
        assert len(tex_rows) == len(md_rows) >= 1
        for ln in body[2:3] + tex_rows:  # booktabs rows: same column count, special characters escaped
            assert ln.endswith(r" \\") and ln.count(" & ") == md[-1].count(" | ")
            assert "_" not in ln.replace(r"\_", "") and "%" not in ln.replace(r"\%", "") and "µ" not in ln


def test_summary_records_seed_parameters_and_sources(done):
    run_dir, _, summary = done
    assert summary["seed"] == make_tables.SEED and summary["params"]["block_len"] == 5
    assert summary["run_dir"] == run_dir.name  # no absolute path: identical output on any machine
    sources = []
    for kind, blocks in summary["results"].items():
        for b in blocks:
            sources += b.get("files", [b]) + ([b["rx"]] if "rx" in b else [])
    assert sorted(s["source"] for s in sources) == [
        "attack/attack.csv", "crypto/crypto_ops.csv", "crypto_attrib/sign_attrib_p8.csv", "cyclictest/cyclictest_fifo_cpu3.txt",
        "cyclictest/cyclictest_other_cpu3.txt", "handshake/handshake.csv", "overhead/overhead_paired.csv",
        "periodic_1s/periodic_tx.csv", "periodic_2s/periodic_rx.csv", "periodic_2s/periodic_tx.csv",
        "throughput_1core/throughput_baolong_100.csv", "throughput_1core/throughput_baolong_200.csv",
        "throughput_1core/throughput_iris_100.csv", "throughput_1core/throughput_iris_200.csv"]
    for s in sources:
        assert s["sha256"] == hashlib.sha256((run_dir / s["source"]).read_bytes()).hexdigest()
    assert summary["skipped_csv"] == [
        {"path": "clock/clock_offset.csv", "reason": "clock_offset file not used: no analysed periodic_rx file in its directory",
         "header_matches_schema": "clock_offset"}]


def test_summary_numbers_match_the_hand_computed_ones(done):
    _, _, summary = done
    res = summary["results"]
    sign = res["crypto_ops"][0]["ops"][0]
    assert (sign["op"], sign["time_us"]["mean"], sign["time_us"]["lag1"]) == ("mldsa_sign", 5500, pytest.approx(0.7))
    paired = res["overhead_paired"][0]
    assert (paired["margin"], paired["margin_source"]) == (0.01, "equivalence_margin.txt")
    assert {o["op"]: o["hl_paired"]["estimate_us"] for o in paired["ops"]} == {"sign": 0.2, "verify": 0}
    one, two = res["periodic"]
    assert (one["source"], one["streams"], one["cores"], one["misses"]) == ("periodic_1s/periodic_tx.csv", 1, 1, 0)
    assert (two["misses"], two["miss_ratio"], two["longest_miss_run"]) == (3, 0.125, 2)
    rx = two["rx"]
    assert (rx["source"], rx["delivered"], rx["lost"]) == ("periodic_2s/periodic_rx.csv", 23, 1)
    assert (rx["verify_us"]["p50"], rx["deliver_us"]["p50"]) == (430, 450)
    lat = rx["latency"]  # every delivered PDU: 500 us on the wire, then 450 us to delivery
    assert (lat["clock_source"], lat["one_way_us"]["n"], lat["one_way_us"]["min"], lat["one_way_us"]["max"]) == \
        ("periodic_2s/clock_offset.csv", 23, 500, 500)
    assert lat["end_to_end_us"]["max"] == 13_000 + 500 + 450 and "latency" not in one
    # the model takes its service times (2 ms) from the single-stream run: two streams of 2 ms in 10 ms never miss
    m = two["model"]
    assert (m["service_source"], m["utilisation"]) == ("periodic_1s/periodic_tx.csv", pytest.approx(0.4))
    assert (m["random_offsets"]["max"], m["synchronous"]["mean"], m["random_offsets"]["draws"]) == (0, 0, 3)
    assert m["measured_offsets"] == {"runs": 3, "jobs_per_run": 24, "mean": 0}  # as many jobs as were measured
    (t,) = res["throughput"]
    assert (t["source"], t["profile"], t["cores"], t["tx_host"], t["rx_host"]) == ("throughput_1core", "mldsa65", 1, "iris", "baolong")
    assert t["saturation"]["saturation_pps"] == 100 and len(t["rows"]) == 4
    assert res["attack"][0]["vectors"][1]["rejected"] == 20 and res["handshake"][0]["roles"][0]["ok"] == 3


def test_same_seed_gives_identical_output_and_a_new_seed_changes_the_bootstrap(done, tmp_path):
    run_dir, out, _ = done
    make_tables.run(run_dir, tmp_path / "again", **PARAMS)
    assert (tmp_path / "again" / "summary.json").read_bytes() == (out / "summary.json").read_bytes()
    make_tables.run(run_dir, tmp_path / "other", seed=1, **PARAMS)
    a, b = (strict_json(d / "summary.json")["results"]["crypto_ops"][0]["ops"] for d in (out, tmp_path / "other"))
    assert [o["time_us"] for o in a] == [o["time_us"] for o in b]
    assert [o["bootstrap"] for o in a] != [o["bootstrap"] for o in b]


def test_figures_are_optional(done):
    _, out, summary = done
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        assert summary["figures"] == {"status": "skipped: matplotlib is not installed", "written": []}
    else:
        assert summary["figures"]["status"] == "ok"
        assert all((out / "figures" / name).stat().st_size > 0 for name in summary["figures"]["written"])
        assert len(summary["figures"]["written"]) == 6


def test_ecdf_thinning_keeps_the_whole_tail():
    import numpy as np
    from analysis import figures  # importable without matplotlib; only make_all needs it
    x, f = figures._ecdf(np.arange(100_000)[::-1])
    assert x.size < 3_100 and np.all(np.diff(x) > 0)
    assert np.array_equal(x[-1000:], np.arange(99_000, 100_000)) and f[-1] == 1.0  # top 1% untouched
    assert np.allclose(f, (x + 1) / 100_000)  # every kept point still sits on the full-sample ECDF
    x, f = figures._ecdf([3.0, 1.0, 2.0])
    assert x.tolist() == [1.0, 2.0, 3.0] and np.allclose(f, [1 / 3, 2 / 3, 1.0])


def test_sign_tail_counts_fit_keys_and_figure(tmp_path, monkeypatch):
    """A signing series with 12700, 6300, 3100, 1500, 700, 300, 100 values above 1 .. 7 ms: the count halves per ms."""
    monkeypatch.setattr(crypto_ops, "TAIL_MIN_N", 10_000)  # the real output needs 100,000 values
    run_dir = tmp_path / "run"
    (run_dir / "crypto").mkdir(parents=True)
    (run_dir / "crypto" / "crypto_ops.csv").write_text(synth.crypto_ops_geometric())
    (run_dir / "crypto_sweep").mkdir()  # a short signing series of the same run: 10 values, the largest 10 ms
    (run_dir / "crypto_sweep" / "crypto_ops.csv").write_text(synth.crypto_ops())
    (run_dir / "DRY_RUN").write_text("dry\n")
    out = tmp_path / "out"
    s = make_tables.run(run_dir, out, **PARAMS)
    fit = s["results"]["crypto_ops"][0]["ops"][0]["tail"]["fit"]  # from above the median (1.5 ms) to the last count >= 100
    assert (fit["from_ms"], fit["to_ms"], fit["bins"], fit["ratio_per_ms"]) == (2, 7, 5, pytest.approx(2))
    assert s["tables_csv"] == ["sign_tail_counts.csv"] and "sign_tail_fit" in s["tables"]
    lines = (out / "tables" / "sign_tail_counts.csv").read_text().splitlines()
    assert lines[:2] == ["# DRY RUN: not a result", "file,op,n,threshold_ms,count_above,in_fit"] and len(lines) == 2 + 25
    assert lines[2] == "crypto/crypto_ops.csv,mldsa_sign,13700,1,12700,0" and lines[3] == "crypto/crypto_ops.csv,mldsa_sign,13700,2,6300,1"
    assert lines[8] == "crypto/crypto_ops.csv,mldsa_sign,13700,7,100,1"
    assert lines[9] == "crypto/crypto_ops.csv,mldsa_sign,13700,8,0,0" and lines[-1].endswith(",25,0,0")
    row = next(ln for ln in (out / "tables" / "sign_tail_fit.md").read_text().splitlines() if ln.startswith("| crypto/"))
    assert row.startswith("| crypto/crypto_ops.csv | mldsa_sign | 13700 | 7.500 | 2 | 7 | 5 | 2.0000 | [1.9")
    # ... | dispersion | ratio and dispersion from 1 ms | samples above the fit end | fit used | expected count above the largest value
    assert row.endswith("| 0.00 | 2.0000 | 0.00 | 100 | own | 141.42 |")  # 6400 x 2^-5.5 above 7.5 ms among 13700 calls
    other = next(ln for ln in (out / "tables" / "sign_tail_fit.md").read_text().splitlines() if ln.startswith("| crypto_sweep/"))
    assert other == ("| crypto_sweep/crypto_ops.csv | mldsa_sign | 10 | 10.000 | – | – | – | – | – | – | – | – | – | "
                     "crypto/crypto_ops.csv | 0.018248 |")  # 10 calls x 6400 / 13700 x 2^-8 above 10 ms
    assert "expected count above x ms under the fitted decay, for n calls" in (out / "tables" / "sign_tail_fit.md").read_text()
    with open(out / "numbers.csv", newline="") as f:
        rows = {r["key"]: r["value"] for r in csv.DictReader(f)}
    base = "crypto_ops.mldsa_sign.tail_"
    assert float(rows[base + "ratio_per_ms"]) == pytest.approx(2) and float(rows[base + "ratio_lo"]) < 2 < float(rows[base + "ratio_hi"])
    assert (rows[base + "fit_from_ms"], rows[base + "fit_to_ms"], rows[base + "fit_bins"], rows[base + "above_fit_end"]) == \
        ("2", "7", "5", "100")
    assert float(rows[base + "dispersion"]) == pytest.approx(0, abs=1e-9)
    assert float(rows[base + "ratio_from1ms"]) == pytest.approx(2) and float(rows[base + "dispersion_from1ms"]) == pytest.approx(0, abs=1e-9)
    assert float(rows[base + "expected_above_max"]) == pytest.approx(6400 * 2 ** -5.5)
    assert float(rows["crypto_ops.sweep.mldsa_sign.tail_expected_above_max"]) == pytest.approx(10 * 6400 / 13700 * 2 ** -8)
    assert "crypto_ops.sweep.mldsa_sign.tail_ratio_per_ms" not in rows  # the short series has no fit of its own
    keys_md = (out / "number_keys.md").read_text()  # the list of keys names quantities and carries no measured value
    assert "tail_expected_above_max` | expected count above the largest value of this series under the fitted decay of " in keys_md
    assert "7.5" not in keys_md and "10.000" not in keys_md
    if s["figures"]["status"] != "skipped: matplotlib is not installed":
        assert s["figures"]["status"] == "ok" and "sign_tail_survival.pdf" in s["figures"]["written"]
        assert (out / "figures" / "sign_tail_survival.pdf").stat().st_size > 0
    # a series without a fit still gets its counts, and the fit table says why there is no ratio
    (run_dir / "crypto" / "crypto_ops.csv").write_text(synth.crypto_ops_geometric(below=9500, first=400, bins=3))  # 10,200 values
    s = make_tables.run(run_dir, out, **PARAMS)
    assert s["tables_csv"] == ["sign_tail_counts.csv"] and "| no fit: fewer than 3 one-millisecond bins" in (out / "tables" / "sign_tail_fit.md").read_text()
    assert base + "ratio_per_ms" not in (out / "numbers.csv").read_text()
    # a rerun in which no series is long enough leaves none of it behind
    monkeypatch.setattr(crypto_ops, "TAIL_MIN_N", 100_000)
    s = make_tables.run(run_dir, out, **PARAMS)
    assert s["tables_csv"] == [] and "sign_tail_fit" not in s["tables"]
    assert not (out / "tables" / "sign_tail_counts.csv").exists() and not (out / "tables" / "sign_tail_fit.md").exists()
    assert not (out / "figures" / "sign_tail_survival.pdf").exists()


def test_attack_file_of_the_gateway_oracle_gets_no_detection_times(tmp_path):
    run_dir = tmp_path / "run"
    (run_dir / "attack").mkdir(parents=True)
    (run_dir / "attack_h").mkdir()
    (run_dir / "attack" / "attack.csv").write_text("# tool=join_attack\n# oracle=gateway_app_log\n# tcp_nodelay=1\n" + synth.attack())
    (run_dir / "attack_h" / "attack.csv").write_text("# tool=join_attack\n# oracle=harness_receiver\n# tcp_nodelay=1\n" + synth.attack())
    for d in ("attack", "attack_h"):  # the generator's traffic log: its footer says that every started job was confirmed
        (run_dir / d / "periodic_tx.csv").write_text(harness_lines(synth.periodic_tx_one_stream()))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    gateway, harness = s["results"]["attack"]
    assert (gateway["oracle"], gateway["vectors"][1]["detect_us"], harness["oracle"]) == ("gateway_app_log", None, "harness_receiver")
    assert harness["vectors"][1]["detect_us"]["mean"] == 10.5 and gateway["vectors"][1]["rejected"] == 20
    numbers = (tmp_path / "out" / "numbers.csv").read_text()
    assert "attack.h.replay.detect_p50_us," in numbers and "attack.replay.detect_" not in numbers and "attack.replay.rejection_rate," in numbers
    md = (tmp_path / "out" / "tables" / "attack.md").read_text()
    row = next(ln for ln in md.splitlines() if ln.startswith("| attack/attack.csv | replay |"))
    assert "| not recorded | – | – |" in row and "oracle=gateway_app_log" in md


def test_sign_attrib_tables_figure_and_invalid_files(done, tmp_path):
    _, out, summary = done
    (f,) = summary["results"]["sign_attrib"]
    assert (f["source"], f["counted"], f["n"], f["validity"]["valid"]) == ("crypto_attrib/sign_attrib_p8.csv", True, 20, True)
    tables = out / "tables"
    row = next(ln for ln in (tables / "sign_attrib.md").read_text().splitlines() if ln.startswith("| crypto_attrib/"))
    assert row == ("| crypto_attrib/sign_attrib_p8.csv | 20 | 2.00 | 7000.00 | 3 | 0.013144 | 3 | 2 | 2 | 3.0500 | 2.5000 | 40% | 20 | "
                   "250.00 | 100.00 | 1.00000 | 0.00 |")  # median off, largest off, calls above the floor and their time
    tail = (tables / "sign_attrib_tail.md").read_text()
    assert "| crypto_attrib/sign_attrib_p8.csv | 5 | 2 | 1 | 7000.00 | 1 | 20 |" in tail
    assert "| crypto_attrib/sign_attrib_p8.csv | 10 | 1 | 0 | 6000.00 | 20 | 1 |" in tail  # the same set: 1 call, 1 call
    assert "| crypto_attrib/sign_attrib_p8.csv | 20 | 0 | 0 | – | – | – |" in tail
    # processor time above t: calls, fewest rounds among them, calls with at least that many; then the rounds threshold of
    # the line and the four cells (both, processor time only, rounds only, neither)
    two = (tables / "sign_attrib_two_by_two.md").read_text()
    assert "| crypto_attrib/sign_attrib_p8.csv | 5 | 1 | 20 | 1 | 20 | 1 | 0 | 0 | 19 | 0 | 0 |" in two  # last two: beyond the crossing round
    assert "| crypto_attrib/sign_attrib_p8.csv | 10 | 0 | – | – | 40 | 0 | 0 | 0 | 20 | 0 | 0 |" in two and "instrumented run" in two
    # shares: 1 of 20 calls above 5 ms in processor time (exact interval 0.127% to 24.9%, by hand in test_experiments), the
    # same call has at least 20 rounds, and a geometric law with the one-round share 0.4 gives 0.6^19 = 0.00609%
    shares = (tables / "sign_attrib_shares.md").read_text()
    assert ("| crypto_attrib/sign_attrib_p8.csv | 5 | 20 | 1 | 5% | [0.127%, 24.9%] | 20 | 1 | 5% | [0.127%, 24.9%] | 0.00609% |") in shares
    assert "| crypto_attrib/sign_attrib_p8.csv | 20 | 20 | 0 | 0% | [0%, 16.8%] | 80 | 0 | 0% | [0%, 16.8%] |" in shares
    assert "| 0.00609% | [" in shares and ", 1.77%] |" in shares  # its bounds: 0.8088^19 = 1.77% at the lower bound of the one-round share
    assert "independent calls" in shares and "instrumented run" in shares
    assert "fails the 1% rule by construction" in (tables / "validity.md").read_text()
    rounds = (tables / "sign_attrib_rounds.md").read_text()
    assert "| crypto_attrib/sign_attrib_p8.csv | 2 | 5 | 25% | 24% | 600.00 |" in rounds  # 0.4 x 0.6 under a geometric law
    assert "instrumented run" in rounds and "instrumented run" in (tables / "sign_attrib.md").read_text()
    if summary["figures"]["status"] == "ok":
        assert "sign_attrib_cpu_vs_rounds.pdf" in summary["figures"]["written"]
        # the paper form of the same figure: no file name in the legend, and a thin line at 10 ms
        assert "sign_attrib_cpu_vs_rounds_paper.pdf" in summary["figures"]["written"]
        if shutil.which("pdftotext"):
            def words(name):
                return subprocess.run(["pdftotext", str(out / "figures" / name), "-"], capture_output=True, text=True).stdout
            working, paper = words("sign_attrib_cpu_vs_rounds.pdf"), words("sign_attrib_cpu_vs_rounds_paper.pdf")
            assert "sign_attrib_p8.csv: mean, min to max" in working and "10 ms" not in working
            assert "mean, minimum to maximum" in paper and "sign_attrib_p8" not in paper and "10 ms" in paper
            assert "least squares: 100 + 250" in paper and "least squares: 100 + 250" in working  # the same line in both
    # a file whose rows contradict it is listed with every reason and takes no part in tables or numbers;
    # a three-column file next to it is analysed without the rounds
    run_dir = tmp_path / "run"
    (run_dir / "crypto_attrib").mkdir(parents=True)
    rows = [list(map(int, ln.split(","))) for ln in synth.sign_attrib().splitlines() if ln[:1].isdigit()]
    rows[12][1] = rows[12][2] - 5000
    rows[7][3] = 6
    (run_dir / "crypto_attrib" / "sign_attrib_p8.csv").write_text(
        synth.sign_attrib(rows=rows, tail=("freq_khz_end=1500000", "wall_s=0.0215", "cpu_s=0.02100")))
    (run_dir / "crypto_attrib" / "sign_attrib_p64.csv").write_text(synth.sign_attrib(counted=False))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    (bad,) = s["invalid_runs"]
    assert (bad["source"], bad["experiment"]) == ("crypto_attrib/sign_attrib_p8.csv", "sign_attrib")
    assert bad["reasons"] == ["sum of cpu_ns over all rows is 0.020750 s, the footer's cpu_s is 0.021000 s: more than 1% apart",
                              "1 row(s) with wall_ns < cpu_ns - 2000 (first: seq 12)",
                              "1 row(s) with shake_calls off the progression 5 + k x 3 (first: seq 7)"]
    (plain,) = s["results"]["sign_attrib"]
    assert (plain["source"], plain["counted"], plain["rounds"]) == ("crypto_attrib/sign_attrib_p64.csv", False, None)
    assert "sign_attrib_rounds" not in s["tables"] and "sign_attrib_cpu_vs_rounds.pdf" not in s["figures"]["written"]
    assert "sign_attrib_two_by_two" not in s["tables"]
    # the share by processor time needs no rounds: the table is written, with dashes in the columns about rounds
    assert "| crypto_attrib/sign_attrib_p64.csv | 5 | 20 | 1 | 5% | [0.127%, 24.9%] | – | – | – | – | – | – |" in \
        (tmp_path / "out" / "tables" / "sign_attrib_shares.md").read_text()
    numbers = (tmp_path / "out" / "numbers.csv").read_text()
    assert "crypto_attrib.sign_attrib_p64.cpu_over_5ms.k,1," in numbers and "crypto_attrib.sign_attrib_p64.wall_over_5ms.cpu_also_over,1," in numbers
    assert "rounds_threshold" not in numbers and "cpu_vs_rounds" not in numbers and "rounds_min" not in numbers
    assert "rounds_at_least_threshold" not in numbers and "crypto_attrib.sign_attrib_p64.cpu_over_5ms.share,0.05," in numbers
    assert "crypto_attrib.sign_attrib_p64.off_total_s," in numbers and "sign_attrib_p8" not in numbers and "rounds_mean" not in numbers
    # a plain run has the four time keys too, without the note of an instrumented run
    assert "crypto_attrib.sign_attrib_p64.wall_p50_us,602.0,602,us,20," in numbers and "median wall time of a signing call" in numbers
    assert "crypto_attrib.sign_attrib_p64.cpu_mean_us,862.5," in numbers and "instrumented run" not in numbers
    with pytest.raises(SystemExit) as e:
        make_tables.main([str(run_dir), "--out", str(tmp_path / "cli"), "--warmup", "10", "--no-figures"])
    assert e.value.code == make_tables.EXIT_INVALID


def test_missing_margin_fails_before_anything_is_written(tmp_path, capsys):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "equivalence_margin.txt").unlink()
    with pytest.raises(FileNotFoundError, match="equivalence_margin.txt"):
        make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert not (tmp_path / "out").exists()
    with pytest.raises(SystemExit) as e:
        make_tables.main([str(run_dir), "--out", str(tmp_path / "out")])
    assert "equivalence_margin.txt" in str(e.value.code) and not (tmp_path / "out").exists()


def test_valid_runs_carry_their_self_checks_and_header(done):
    _, out, summary = done
    assert summary["invalid_runs"] == []
    paired, crypto = summary["results"]["overhead_paired"][0], summary["results"]["crypto_ops"][0]
    assert (paired["mode"], paired["header"]["tool"], paired["header"]["commit"][:7]) == ("ab", "bench_overhead_paired", "eed269f")
    assert paired["validity"] == {"valid": True, "reasons": [], "warnings": [], "signature_mismatches": 0, "failed_calls": 0,
                                  "mlockall": "ok", "freq_khz_start": 1500000, "freq_khz_end": 1500000,
                                  "cpu_share": 18.612 / 18.608, "throttled_start": None, "throttled_end": None,
                                  "env_throttled": ["before: throttled=0x0", "after: throttled=0x0"], "throttled": False}
    assert crypto["validity"]["valid"] and crypto["validity"]["signature_mismatches"] is None  # crypto_ops has no counters
    assert summary["env"] == [{"file": "env_iris.txt", "host": "iris", "throttled": ["before: throttled=0x0", "after: throttled=0x0"]}]
    assert summary["not_a_result"] is None and summary["key_prefix"] == ""
    rows = [ln.split(" | ") for ln in (out / "tables" / "validity.md").read_text().splitlines() if ".csv |" in ln or ".txt |" in ln]
    assert [(r[1], r[2]) for r in rows] == [  # every timing file whose host has an env file, or that carries its own lines
        ("crypto_ops", "valid"), ("overhead_paired", "valid"), ("sign_attrib", "valid"), ("cyclictest", "valid"),
        ("cyclictest", "valid"), ("periodic_tx", "valid"), ("periodic_tx", "valid"), ("handshake", "valid")]
    assert (rows[1][5], rows[1][6], rows[1][9]) == ("ok", "1.0002", "no")  # mlockall, cpu_s/wall_s, throttled


@pytest.mark.parametrize("tail,reason", [
    (("signature_mismatches=3", "failed_calls=0", *synth.CRYPTO_TAIL), "signature_mismatches=3"),
    (("signature_mismatches=0", "failed_calls=2", *synth.CRYPTO_TAIL), "failed_calls=2"),
    ((), "trailer missing (freq_khz_end, wall_s, cpu_s, signature_mismatches, failed_calls): the run did not finish"),
    (("signature_mismatches=0", "failed_calls=0", "freq_khz_end=600000", "wall_s=18.6", "cpu_s=18.6"),
     "CPU frequency changed during the run (1500000 -> 600000 kHz)"),
    (("signature_mismatches=0", "failed_calls=0", "freq_khz_end=1500000", "wall_s=20.0", "cpu_s=15.0"),
     "cpu_s/wall_s = 0.750, below 0.97: the core was shared"),
])
def test_invalid_paired_run_is_reported_and_not_analysed(tmp_path, capsys, tail, reason):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "overhead" / "overhead_paired.csv").write_text(synth.overhead_paired(tail=tail))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    (bad,) = s["invalid_runs"]
    assert (bad["source"], bad["experiment"], bad["valid"], bad["reasons"]) == \
        ("overhead/overhead_paired.csv", "overhead_paired", False, [reason])
    assert bad["sha256"] and s["results"]["overhead_paired"] == []
    assert not {"overhead_paired", "overhead_order"} & set(s["tables"]) and "validity" in s["tables"]
    assert not (tmp_path / "out" / "tables" / "overhead_paired.md").exists()
    assert f"INVALID, not analysed: {reason}" in (tmp_path / "out" / "tables" / "validity.md").read_text()
    numbers = (tmp_path / "out" / "numbers.csv").read_text()
    # no key of the paired file (the text of run.warmup names the kind); the rest of the run is intact
    assert "\noverhead_paired" not in numbers and "crypto_ops.mldsa_sign.p50_us" in numbers
    with pytest.raises(SystemExit) as e:  # the command line reports it and exits with its own code after writing everything
        make_tables.main([str(run_dir), "--out", str(tmp_path / "cli"), "--warmup", "10", "--block-len", "5", "--n-boot", "20",
                          "--sim-draws", "0"])
    assert e.value.code == make_tables.EXIT_INVALID == 3 and (tmp_path / "cli" / "summary.json").is_file()
    assert f"INVALID, not analysed: overhead/overhead_paired.csv: {reason}" in capsys.readouterr().err


def test_unfinished_crypto_run_is_invalid_and_warnings_do_not_stop_analysis(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "crypto" / "crypto_ops.csv").write_text(synth.crypto_ops(tail=()))  # killed before the trailer was written
    (run_dir / "env_iris.txt").write_text(synth.env_file("0x50000", "0x50000"))  # throttled at some time before the run
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert [(f["source"], f["reasons"]) for f in s["invalid_runs"]] == \
        [("crypto/crypto_ops.csv", ["trailer missing (freq_khz_end, wall_s, cpu_s): the run did not finish"])]
    v = s["results"]["overhead_paired"][0]["validity"]
    assert v["valid"] and v["throttled"] is True and len(v["warnings"]) == 1 and "overhead_paired" in s["tables"]
    table = (tmp_path / "out" / "tables" / "validity.md").read_text()
    assert "throttling had occurred before the run (env file of iris: get_throttled 0x50000 -> 0x50000, sticky bits only)" in table
    assert "| yes |" in table


@pytest.mark.parametrize("before,after,reason", [
    ("0x0", "0x50005", "throttling active (env file of iris: get_throttled 0x0 -> 0x50005)"),
    ("0x0", "0x50000", "get_throttled changed during the run (env file of iris: 0x0 -> 0x50000)"),
])
def test_throttling_in_the_env_file_invalidates_every_timing_file_of_that_host(tmp_path, before, after, reason):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "env_iris.txt").write_text(synth.env_file(before, after))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert {f["source"]: f["reasons"] for f in s["invalid_runs"]} == {
        "crypto/crypto_ops.csv": [reason], "overhead/overhead_paired.csv": [reason], "crypto_attrib/sign_attrib_p8.csv": [reason],
        "cyclictest/cyclictest_fifo_cpu3.txt": [reason], "cyclictest/cyclictest_other_cpu3.txt": [reason],
        "periodic_1s/periodic_tx.csv": [reason], "periodic_2s/periodic_tx.csv": [reason], "handshake/handshake.csv": [reason],
        # the receiver's file of a pair goes with its sender's, in the same list
        "periodic_2s/periodic_rx.csv": [f"the sender's file of this pair, periodic_tx.csv, is invalid ({reason}): the pair is invalid as a pair"]}
    assert s["results"]["crypto_ops"] == s["results"]["overhead_paired"] == s["results"]["cyclictest"] == []
    assert s["results"]["periodic"] == s["results"]["handshake"] == []
    # files that name no host, and the attack oracle (not a timing run), stay
    assert "throughput" in s["tables"] and "attack" in s["tables"]
    assert "periodic_2s/periodic_rx.csv" not in [e["path"] for e in s["skipped_csv"]]
    # the readings of another host do not touch these files
    (run_dir / "env_iris.txt").write_text(synth.env_file())
    (run_dir / "env_baolong.txt").write_text(synth.env_file(before, after, host="baolong"))
    assert make_tables.run(run_dir, tmp_path / "out2", **PARAMS)["invalid_runs"] == []


NET_HEAD = ("tool=bench_net_tx", "freq_khz_start=1500000", "mlockall=ok")
NET_TAIL = ("freq_khz_end=1500000", "wall_s=20.213", "cpu_s=4.333")
# a sound connection, and no job given up; the last line stands for the receiving end where a fixture has a sender's file alone
TRANSPORT = ("tcp_nodelay=1", "tcp_connections_at_first_release=1", "tcp_connections_at_end=1", "jobs_started=2400", "jobs_confirmed=2400",
             "tcp_nodelay_rx=1")
NO_ATTACK_LOG = "no traffic log periodic_tx.csv beside the file: whether every started job was confirmed is not recorded"
GIVEN_UP = "jobs_started / jobs_confirmed missing: whether every started job was confirmed is not recorded"
NAGLE = "Nagle's algorithm was not switched off on this connection"
NO_NODELAY = "no tcp_nodelay line: whether Nagle's algorithm was off on this connection is not recorded"


def harness_lines(content, head=NET_HEAD, tail=NET_TAIL, transport=TRANSPORT):
    """A synthetic file with the comment lines a bench_net harness writes above and below it, the transport lines of
    its connection among them. In a sender's file the two jobs lines of TRANSPORT (2400, a stand-in) become the number
    of its rows, as a real footer agrees with its rows; any other pair of values is written as given."""
    rows = sum(1 for ln in content.splitlines() if ln and ln[0].isdigit()) if "release_ns" in content else None
    if rows is not None and all(c in transport for c in TRANSPORT[3:5]):
        transport = [f"{c.partition('=')[0]}={rows}" if c in TRANSPORT[3:5] else c for c in transport]
    return "".join(f"# {c}\n" for c in (*transport, *head)) + content + "".join(f"# {c}\n" for c in tail)


def test_networked_harness_files_need_no_delay_and_one_connection(tmp_path):
    """DATA_SCHEMA.md, 'Transport keys': tcp_nodelay must read 1 in every networked harness file, and a transmitter's
    connection must not have been established again. Each file is judged by its own lines."""
    run_dir = synth.make_run(tmp_path / "run")
    files = {"periodic_1s/periodic_tx.csv": (synth.periodic_tx_one_stream(), ("tcp_nodelay=0", *TRANSPORT[1:])),
             "periodic_2s/periodic_tx.csv": (synth.periodic_tx_two_streams(), TRANSPORT),
             "periodic_2s/periodic_rx.csv": (synth.periodic_rx_two_streams(), ()),  # an old receiver file: no line
             "handshake/handshake.csv": (synth.handshake(), ("tcp_nodelay=-1",))}
    for name, (content, transport) in files.items():
        (run_dir / name).write_text(harness_lines(content, transport=transport))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    unread = "not a read-back of 1, so whether Nagle's algorithm was off on this connection is not known"
    assert {f["source"]: f["reasons"] for f in s["invalid_runs"]} == {
        "periodic_1s/periodic_tx.csv": [f"tcp_nodelay=0: {NAGLE}"], "periodic_2s/periodic_rx.csv": [NO_NODELAY],
        # one connection has one configuration: the sound sender file is invalid with its receiver file, as a pair
        "periodic_2s/periodic_tx.csv": [f"the receiver's file of this pair, periodic_rx.csv, does not read tcp_nodelay=1 ({NO_NODELAY}): "
                                        "a pair is one connection and is invalid as a pair"],
        "handshake/handshake.csv": [f"tcp_nodelay=-1: {unread}"]}
    assert s["results"]["periodic"] == [] and s["results"]["handshake"] == []
    # a receiver file that is invalid for another reason leaves the sender standing, as before
    (run_dir / "periodic_2s" / "periodic_rx.csv").write_text(
        harness_lines(synth.periodic_rx_two_streams(), head=(*NET_HEAD[:2], "mlockall=failed (ENOMEM)")))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    (two,) = s["results"]["periodic"]
    assert two["source"] == "periodic_2s/periodic_tx.csv" and "rx" not in two
    (run_dir / "periodic_2s" / "periodic_rx.csv").write_text(harness_lines(synth.periodic_rx_two_streams()))
    # the connection was made again inside the window: 1 connection at the first release, 2 at the end
    (run_dir / "periodic_2s" / "periodic_tx.csv").write_text(harness_lines(
        synth.periodic_tx_two_streams(), transport=("tcp_nodelay=1", "tcp_connections_at_first_release=1", "tcp_connections_at_end=2",
                                                    *TRANSPORT[3:])))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert next(f["reasons"] for f in s["invalid_runs"] if f["source"] == "periodic_2s/periodic_tx.csv") == [
        "the TCP connection was established again inside the measured window (tcp_connections_at_first_release=1, "
        "tcp_connections_at_end=2)"]
    assert s["results"]["periodic"] == []
    # a job started and not confirmed (DATA_SCHEMA.md, 'Jobs given up'): the transmitter's file is invalid, its
    # receiver's file goes with it; a transmitter file without the two lines does not say and is invalid too
    unconfirmed = synth.periodic_tx_rows()
    unconfirmed[5] = (*unconfirmed[5][:5], 0)  # one job has a start and no send_done: the footer counts it as started only
    for lines, reason in (((*TRANSPORT[:3], "jobs_started=24", "jobs_confirmed=23"),
                           "1 job(s) started and not confirmed (jobs_started=24, jobs_confirmed=23)"), (TRANSPORT[:3], GIVEN_UP)):
        (run_dir / "periodic_2s" / "periodic_tx.csv").write_text(harness_lines(synth.periodic_tx_two_streams(unconfirmed), transport=lines))
        s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
        bad = {f["source"]: f["reasons"] for f in s["invalid_runs"]}
        # one rule, one list, both directions: the receiver's file is invalid with it, and the reason names the sender's
        assert bad["periodic_2s/periodic_tx.csv"] == [reason] and bad["periodic_2s/periodic_rx.csv"] == [
            f"the sender's file of this pair, periodic_tx.csv, is invalid ({reason}): the pair is invalid as a pair"]
        assert s["results"]["periodic"] == [] and "periodic_2s/periodic_rx.csv" not in [e["path"] for e in s["skipped_csv"]]
    # the footer's job counts are those of the rows (24 here): a footer that says otherwise contradicts its own file
    (run_dir / "periodic_2s" / "periodic_tx.csv").write_text(harness_lines(synth.periodic_tx_two_streams(), transport=(
        *TRANSPORT[:3], "jobs_released=25", "jobs_dropped_at_release=1", "jobs_started=24", "jobs_confirmed=24", TRANSPORT[5])))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert next(f["reasons"] for f in s["invalid_runs"] if f["source"] == "periodic_2s/periodic_tx.csv") == [
        "jobs_released=25 in the footer, but the file has 24 rows", "jobs_dropped_at_release=1 in the footer, but the file has 0 rows without a start_ns"]
    (run_dir / "periodic_2s" / "periodic_tx.csv").write_text(harness_lines(synth.periodic_tx_two_streams(), transport=(
        *TRANSPORT[:3], "jobs_released=24", "jobs_dropped_at_release=0", "jobs_started=24", "jobs_confirmed=24", TRANSPORT[5])))
    assert "periodic_2s/periodic_tx.csv" not in [f["source"] for f in make_tables.run(run_dir, tmp_path / "out", **PARAMS)["invalid_runs"]]
    # both ends fail on their own: each file is listed once, with its own reason and the other end's
    (run_dir / "periodic_2s" / "periodic_tx.csv").write_text(harness_lines(synth.periodic_tx_two_streams(), transport=("tcp_nodelay=0", *TRANSPORT[1:])))
    (run_dir / "periodic_2s" / "periodic_rx.csv").write_text(harness_lines(synth.periodic_rx_two_streams(), transport=("tcp_nodelay=0",)))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert {f["source"]: f["reasons"] for f in s["invalid_runs"] if f["source"].startswith("periodic_2s")} == {
        "periodic_2s/periodic_tx.csv": [f"tcp_nodelay=0: {NAGLE}", f"the receiver's file of this pair, periodic_rx.csv, does not read tcp_nodelay=1 "
                                        f"(tcp_nodelay=0: {NAGLE}): a pair is one connection and is invalid as a pair"],
        "periodic_2s/periodic_rx.csv": [f"tcp_nodelay=0: {NAGLE}", f"the sender's file of this pair, periodic_tx.csv, is invalid (tcp_nodelay=0: {NAGLE}): "
                                        "the pair is invalid as a pair"]}
    (run_dir / "periodic_2s" / "periodic_rx.csv").write_text(harness_lines(synth.periodic_rx_two_streams()))
    # a harness sender's file without a receiver's file beside it (the gateway binary as receiver; no campaign experiment
    # has that): the receiving end must have been read back in the sender's file, else nothing says how it was set
    alone = run_dir / "periodic_1s" / "periodic_tx.csv"
    for last, reason in ((("tcp_nodelay_rx=1",), None), ((), "no tcp_nodelay_rx line"), (("tcp_nodelay_rx=0",), "tcp_nodelay_rx=0"),
                         (("tcp_nodelay_rx=-1",), "tcp_nodelay_rx=-1")):
        alone.write_text(harness_lines(synth.periodic_tx_one_stream(), transport=(*TRANSPORT[:5], *last)))
        s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
        assert [f["reasons"] for f in s["invalid_runs"] if f["source"] == "periodic_1s/periodic_tx.csv"] == ([] if reason is None else [[
            f"no receiver's file periodic_rx.csv beside it and {reason}: the receiving end of the connection was not read back as 1"]])
    alone.write_text(synth.periodic_tx_one_stream())  # a hand-made file (no tool line) is not judged
    assert "periodic_1s/periodic_tx.csv" not in [f["source"] for f in make_tables.run(run_dir, tmp_path / "out", **PARAMS)["invalid_runs"]]
    alone.write_text(harness_lines(synth.periodic_tx_one_stream(), transport=("tcp_nodelay=0", *TRANSPORT[1:])))  # as it was above
    # retransmitted segments do not make a file invalid
    (run_dir / "periodic_2s" / "periodic_tx.csv").write_text(harness_lines(
        synth.periodic_tx_two_streams(), transport=(*TRANSPORT, "tcp_total_retrans_in_window=3", "tcp_total_rto_in_window=1")))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert [r["source"] for r in s["results"]["periodic"]] == ["periodic_2s/periodic_tx.csv"]
    # ... they are reported: 3 retransmitted segments and 1 time-out in the window; the file has no duplicate-SACK line
    (two,) = s["results"]["periodic"]
    assert two["transport"] == {"tcp_total_retrans_in_window": 3, "tcp_dsack_dups_in_window": None, "tcp_total_rto_in_window": 1}
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        rows = {r["key"]: r for r in csv.DictReader(f)}
    base = "periodic." + next(k for k in rows if k.endswith(".tcp_total_retrans_in_window")).split(".")[1]
    assert (rows[base + ".tcp_total_retrans_in_window"]["value"], rows[base + ".tcp_total_rto_in_window"]["value"]) == ("3", "1")
    assert base + ".tcp_dsack_dups_in_window" not in rows
    assert "retransmitted segments of the transmitter's connection in the measured window" in rows[base + ".tcp_total_retrans_in_window"]["how"]
    line = next(ln for ln in (tmp_path / "out" / "tables" / "periodic.md").read_text().splitlines() if ln.startswith("| periodic_2s/"))
    assert line.endswith("| 3 | – | 1 |")
    # -1: the kernel did not give the field. That is not a count of zero: a dash, and no key
    (run_dir / "periodic_2s" / "periodic_tx.csv").write_text(harness_lines(
        synth.periodic_tx_two_streams(), transport=(*TRANSPORT, "tcp_total_retrans_in_window=0", "tcp_dsack_dups_in_window=0",
                                                    "tcp_total_rto_in_window=-1")))
    make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    numbers = (tmp_path / "out" / "numbers.csv").read_text()
    assert base + ".tcp_total_retrans_in_window,0," in numbers and base + ".tcp_dsack_dups_in_window,0," in numbers
    assert "tcp_total_rto_in_window" not in numbers
    line = next(ln for ln in (tmp_path / "out" / "tables" / "periodic.md").read_text().splitlines() if ln.startswith("| periodic_2s/"))
    assert line.endswith("| 0 | 0 | – |")


def ladder_step(directory, tx_lines=(), rx_lines=(), log_tx=TRANSPORT, log_rx=TRANSPORT[:1], log_host=("iris", "baolong"), rep=1,
                proc_ns=None):
    """One ladder step as the harness lays it out: throughput_<role>_100pps_rep1.csv of each host and, beside them, the
    generator's traffic logs periodic_<role>_100pps_rep1.csv, whose header and footer carry the transport lines."""
    directory.mkdir(parents=True, exist_ok=True)
    for role, host, own, log, log_from in (("tx", "iris", tx_lines, log_tx, log_host[0]), ("rx", "baolong", rx_lines, log_rx, log_host[1])):
        (directory / f"throughput_{role}_100pps_rep1.csv").write_text(harness_lines(
            synth.throughput(host, 100, proc_ns=proc_ns), head=(*NET_HEAD, f"host={host}", "rep=1", "partition=0"), transport=own))
        if log is not None:
            content = synth.periodic_tx_one_stream() if role == "tx" else synth.periodic_rx_two_streams()
            content = "".join(ln for ln in content.splitlines(keepends=True) if not ln.startswith("# host="))  # the head names the host
            (directory / f"periodic_{role}_100pps_rep1.csv").write_text(harness_lines(
                content, head=(*NET_HEAD, f"host={log_from}", f"rep={rep}", "partition=0"), transport=log))


def test_ladder_files_take_their_transport_lines_from_the_traffic_log_beside_them(tmp_path):
    """The sampler files of a ladder step carry no transport lines of their own; the generator's traffic log of the same
    host, repetition and partition beside them does. Its header and footer are read (its rows never), and without a
    usable one the sampler file is invalid."""
    def run(name, **kw):
        ladder_step(tmp_path / name / "throughput", **kw)
        s = make_tables.run(tmp_path / name, tmp_path / (name + "_out"), **PARAMS)
        return s, {f["source"].rsplit("/", 1)[-1]: f["reasons"] for f in s["invalid_runs"]}

    s, bad = run("sound", log_tx=(*TRANSPORT, "tcp_total_retrans_in_window=2", "tcp_dsack_dups_in_window=1", "tcp_total_rto_in_window=-1"))
    assert bad == {} and len(s["results"]["throughput"]) == 1 and s["results"]["periodic"] == []
    # the window counts of the transmitter's connection come with them: keys of the tx row, none for the receiver
    numbers = (tmp_path / "sound_out" / "numbers.csv").read_text()
    assert ".rep1.tx.tcp_total_retrans_in_window,2," in numbers and ".rep1.tx.tcp_dsack_dups_in_window,1," in numbers
    assert "tcp_total_rto_in_window" not in numbers and ".rx.tcp_" not in numbers
    rows = [ln for ln in (tmp_path / "sound_out" / "tables" / "throughput.md").read_text().splitlines() if ln.startswith("| throughput |")]
    assert [ln.split(" | ")[6] for ln in rows] == ["rx", "tx"] and rows[0].endswith("| – | – | – |") and rows[1].endswith("| 2 | 1 | – |")
    assert [e["path"] for e in s["skipped_csv"]] == ["throughput/periodic_rx_100pps_rep1.csv", "throughput/periodic_tx_100pps_rep1.csv"]
    # Nagle on at the sender: its sampler file is invalid, and the reason names the file the line was read from
    _, bad = run("nagle", log_tx=("tcp_nodelay=0", *TRANSPORT[1:]))
    assert bad == {"throughput_tx_100pps_rep1.csv": [f"tcp_nodelay=0 (read from periodic_tx_100pps_rep1.csv): {NAGLE}"]}
    # the connection was made again: read from the log's footer
    _, bad = run("again", log_tx=("tcp_nodelay=1", "tcp_connections_at_first_release=1", "tcp_connections_at_end=3", *TRANSPORT[3:]))
    assert bad == {"throughput_tx_100pps_rep1.csv": [
        "the TCP connection was established again inside the measured window (tcp_connections_at_first_release=1, "
        "tcp_connections_at_end=3 (read from periodic_tx_100pps_rep1.csv))"]}
    # a traffic log is judged by its header and footer, never by its rows: its footer may count 7,500 jobs of a
    # ladder step while the synthetic log has 12 rows
    _, bad = run("rows_unread", log_tx=(*TRANSPORT[:3], "jobs_released=7500", "jobs_dropped_at_release=1", "jobs_started=7499", "jobs_confirmed=7499"))
    assert bad == {}
    # a started job was not confirmed: the two lines are in the footer of the traffic log, never in the sampler file
    _, bad = run("given_up", log_tx=(*TRANSPORT[:3], "jobs_started=2400", "jobs_confirmed=2399"))
    assert bad == {"throughput_tx_100pps_rep1.csv": [
        "1 job(s) started and not confirmed (jobs_started=2400, jobs_confirmed=2399 (read from periodic_tx_100pps_rep1.csv))"]}
    # the layout of the reworked harness: the sampler file carries its own tcp_ lines, the log the two jobs lines. A
    # reason about a line of the sampler file itself does not name the log
    _, bad = run("again_own", tx_lines=("tcp_nodelay=1", "tcp_connections_at_first_release=1", "tcp_connections_at_end=10"),
                 rx_lines=TRANSPORT[:1], log_tx=(*TRANSPORT[:3], "jobs_started=1200", "jobs_confirmed=1191", "tx_confirmations_failed=2"))
    assert bad == {"throughput_tx_100pps_rep1.csv": [
        "the TCP connection was established again inside the measured window (tcp_connections_at_first_release=1, "
        "tcp_connections_at_end=10)",
        "9 job(s) started and not confirmed (jobs_started=1200, jobs_confirmed=1191 (read from periodic_tx_100pps_rep1.csv)), "
        "of which 2 with a failed confirmation (tx_confirmations_failed) and 7 given up without one"]}
    # such a sampler file without its log: nothing says whether every started job was confirmed
    _, bad = run("jobs_unknown", tx_lines=TRANSPORT[:3], rx_lines=TRANSPORT[:1], log_tx=None, log_rx=None)
    assert bad == {"throughput_tx_100pps_rep1.csv": [GIVEN_UP + "; no traffic log periodic_tx_100pps_rep1.csv beside the file"]}
    # no traffic log beside the receiver's file: nothing says that Nagle was off
    _, bad = run("no_log", log_rx=None)
    assert bad == {"throughput_rx_100pps_rep1.csv": [NO_NODELAY + "; no traffic log periodic_rx_100pps_rep1.csv beside the file"]}
    # a log of another host or another repetition is not this file's connection
    _, bad = run("other_host", log_host=("baolong", "baolong"))
    assert bad == {"throughput_tx_100pps_rep1.csv": [
        NO_NODELAY + "; the traffic log periodic_tx_100pps_rep1.csv beside the file is not used: its host=baolong differs from iris",
        "tcp_connections_at_first_release / tcp_connections_at_end missing: whether the connection was established again "
        "inside the measured window is not recorded", GIVEN_UP]}
    _, bad = run("other_rep", rep=2)
    assert set(bad) == {"throughput_tx_100pps_rep1.csv", "throughput_rx_100pps_rep1.csv"} and \
        "its rep=2 differs from 1" in bad["throughput_rx_100pps_rep1.csv"][0]
    # the sampler file has the three validity lines, the window counts are in the traffic log only: they are still read
    s, bad = run("split", tx_lines=TRANSPORT, rx_lines=TRANSPORT[:1], log_tx=(*TRANSPORT, "tcp_total_retrans_in_window=4"))
    assert bad == {} and ".rep1.tx.tcp_total_retrans_in_window,4," in (tmp_path / "split_out" / "numbers.csv").read_text()
    # lines in the sampler file itself are used first, and the log is then not needed
    s, bad = run("own", tx_lines=TRANSPORT, rx_lines=TRANSPORT[:1], log_tx=None, log_rx=None, proc_ns=250_000_000)
    assert bad == {} and len(s["results"]["throughput"]) == 1
    # sampler files with the 13th column: the processor time of the process, 250 ms per second of the steady window
    with open(tmp_path / "own_out" / "numbers.csv", newline="") as f:
        rows = {r["key"].split(".", 2)[2]: r for r in csv.DictReader(f) if r["key"].startswith("throughput.")}
    assert (rows["r100.rep1.tx.proc_cpu_share"]["value"], rows["r100.rep1.tx.proc_cpu_share"]["formatted"]) == ("0.25", r"25\%")
    assert "not board utilisation" in rows["r100.rep1.rx.proc_cpu_share"]["how"]
    assert rows["r100.tx_proc_cpu_share_mean"]["value"] == "0.25" and "r100.tx_proc_cpu_share_t95_lo" not in rows  # one repetition
    tex = (tmp_path / "own_out" / "numbers.tex").read_text()
    assert "r100.rep1.tx.proc_cpu_share" in tex and "r100.rep1.tx.cpu_util" not in tex  # the process figure is a manuscript number
    table = [ln.split(" | ") for ln in (tmp_path / "own_out" / "tables" / "throughput.md").read_text().splitlines() if ln.startswith("| throughput |")]
    assert [ln[11] for ln in table] == ["25%", "25%"]


def test_an_attack_file_needs_no_delay_on_both_ends(tmp_path):
    """attack.csv is written by a join script, with either oracle. Its own tcp_nodelay line is used when it has one (1
    only when both ends read 1, -1 when an end has no read-back); otherwise the traffic logs of the two ends beside it
    must both say 1. A file without a tool line is hand-made and is not judged."""
    def run(name, lines=("tool=join_attack", "oracle=harness_receiver"), tx=TRANSPORT, rx=TRANSPORT[:1]):
        d = tmp_path / name / "attack"
        d.mkdir(parents=True)
        (d / "attack.csv").write_text("".join(f"# {c}\n" for c in lines) + synth.attack())
        for role, content, transport in (("tx", synth.periodic_tx_one_stream(), tx), ("rx", synth.periodic_rx_two_streams(), rx)):
            if transport is not None:
                (d / f"periodic_{role}.csv").write_text(harness_lines(content, transport=transport))
        s = make_tables.run(tmp_path / name, tmp_path / (name + "_out"), **PARAMS)
        return len(s["results"]["attack"]), [f["reasons"] for f in s["invalid_runs"]]

    assert run("sound") == (1, [])
    # the layout of the real runs: the join script wrote the line into attack.csv, the generator's log is beside it and
    # there is no receiver log (the gateway receives). The log's two jobs lines judge the attack file, fail closed
    own = ("tool=join_attack", "oracle=harness_receiver", "tcp_nodelay=1")
    assert run("own", lines=own, rx=None) == (1, [])
    assert run("own_unconfirmed", lines=own, tx=(*TRANSPORT[:3], "jobs_started=1300", "jobs_confirmed=1299"), rx=None) == (
        0, [["1 job(s) started and not confirmed (jobs_started=1300, jobs_confirmed=1299 (read from periodic_tx.csv))"]])
    assert run("own_silent", lines=own, tx=TRANSPORT[:3], rx=None) == (
        0, [["jobs_started / jobs_confirmed missing in periodic_tx.csv: whether every started job was confirmed is not recorded"]])
    assert run("own_no_log", lines=own, tx=None, rx=None) == (0, [[NO_ATTACK_LOG]])
    assert run("own_0", lines=("tool=join_attack", "oracle=harness_receiver", "tcp_nodelay=0")) == (0, [[f"tcp_nodelay=0: {NAGLE}"]])
    assert run("rx_0", rx=("tcp_nodelay=0",)) == (0, [[f"tcp_nodelay=0 (read from periodic_rx.csv): {NAGLE}"]])
    assert run("no_rx_line", rx=()) == (0, [[NO_NODELAY + "; the traffic log periodic_rx.csv beside the file has no tcp_nodelay line"]])
    assert run("no_logs", tx=None, rx=None) == (0, [[NO_NODELAY + "; no traffic log periodic_tx.csv beside the file", NO_ATTACK_LOG]])
    # the gateway's own log as oracle: judged by the same line; without it there is no receiver log to fall back on
    assert run("gateway_1", lines=("tool=join_attack", "oracle=gateway_app_log", "tcp_nodelay=1"), rx=None) == (1, [])
    assert run("gateway_unread", lines=("tool=join_attack", "oracle=gateway_app_log", "tcp_nodelay=-1"), rx=None) == (
        0, [["tcp_nodelay=-1: not a read-back of 1, so whether Nagle's algorithm was off on this connection is not known"]])
    assert run("gateway_old", lines=("tool=join_attack", "oracle=gateway_app_log"), rx=None) == (
        0, [[NO_NODELAY + "; no traffic log periodic_rx.csv beside the file"]])
    assert run("hand_made", lines=(), tx=None, rx=None) == (1, [])


def data_rows(content):
    return sum(1 for ln in content.splitlines() if ln and not ln.startswith("#")) - 1  # the column line is no row


LOST = "rows of the log were lost"
STOPPED = "the run was stopped before its end"


def test_a_footer_that_contradicts_its_file_makes_it_invalid(tmp_path):
    """CAMPAIGN.md, 'Invalid files' (ruling of 2026-11-23): a file whose footer count differs from its rows, with
    rows_lost other than 0 or with stopped_early=1 is invalid with that reason. A line a file does not have is not
    judged (every other test of this file writes none)."""
    rx, tx, hs = synth.periodic_rx_two_streams(), synth.periodic_tx_two_streams(), synth.handshake()
    n_rx, n_hs = data_rows(rx), data_rows(hs)

    def run(name, rx_tail=(), tx_tail=(), hs_tail=()):
        for path, content, tail in (("periodic_2s/periodic_tx.csv", tx, tx_tail), ("periodic_2s/periodic_rx.csv", rx, rx_tail),
                                    ("handshake/handshake.csv", hs, hs_tail)):
            (tmp_path / name / path).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / name / path).write_text(harness_lines(content, tail=(*NET_TAIL, *tail)))
        s = make_tables.run(tmp_path / name, tmp_path / (name + "_out"), **PARAMS)
        return ({f["source"]: f["reasons"] for f in s["invalid_runs"]}, ["rx" in r for r in s["results"]["periodic"]],
                len(s["results"]["handshake"]))

    sound = (f"rows={n_rx}", "rows_lost=0")
    assert run("sound", sound, ("stopped_early=0",), (f"rows={n_hs}", "rows_lost=0")) == ({}, [True], 1)
    # a receiver's footer that counts three rows more than the file holds (a file cut after its footer was written
    # cannot exist, so rows are missing). The receiver's file is out; the sender's side stands on its own
    assert run("cut", (f"rows={n_rx + 3}", "rows_lost=0")) == (
        {"periodic_2s/periodic_rx.csv": [f"rows={n_rx + 3}, but the file has {n_rx} rows"]}, [False], 1)
    assert run("lost", (f"rows={n_rx}", "rows_lost=2")) == ({"periodic_2s/periodic_rx.csv": [f"rows_lost=2: {LOST}"]}, [False], 1)
    # anything but 0 is a reason, also what is no count
    assert run("unknown", (f"rows={n_rx}", "rows_lost=unavailable"))[0] == {
        "periodic_2s/periodic_rx.csv": ["rows_lost=unavailable: not a count, so the file does not say 0"]}
    # a sender that was stopped early takes its receiver with it: the pair is invalid as a pair
    assert run("stopped", sound, ("stopped_early=1",)) == (
        {"periodic_2s/periodic_tx.csv": [f"stopped_early=1: {STOPPED}"],
         "periodic_2s/periodic_rx.csv": [f"the sender's file of this pair, periodic_tx.csv, is invalid (stopped_early=1: {STOPPED}): "
                                         "the pair is invalid as a pair"]}, [], 1)
    assert run("handshake", sound, hs_tail=(f"rows={n_hs - 1}", "rows_lost=4")) == (
        {"handshake/handshake.csv": [f"rows={n_hs - 1}, but the file has {n_hs} rows", f"rows_lost=4: {LOST}"]}, [True], 0)
    note = (tmp_path / "handshake_out" / "tables" / "validity.md").read_text()
    assert "rows_lost other than 0" in note and "stopped_early other than 0" in note and "contradicting_pdus other than 0" in note


def test_an_attack_file_is_judged_by_its_own_counts_and_by_the_footers_of_the_logs_it_was_joined_from(tmp_path):
    """attack.csv says how many PDUs it holds (pdus) and how many of them the join script found contradicting
    (contradicting_pdus): another number of rows, or a count other than 0, makes it invalid. The
    receiver's log beside it is one of the two files it is joined from, so one that lost rows or holds another number of
    rows than its footer says makes it invalid as well; so does a generator's log that was stopped early."""
    n, rx_log = data_rows(synth.attack()), synth.periodic_rx_two_streams()

    def run(name, lines=(), tx=TRANSPORT, rx=TRANSPORT[:1]):
        d = tmp_path / name / "attack"
        d.mkdir(parents=True)
        (d / "attack.csv").write_text("".join(f"# {c}\n" for c in ("tool=join_attack", "oracle=harness_receiver", "tcp_nodelay=1", *lines))
                                      + synth.attack())
        for role, content, transport in (("tx", synth.periodic_tx_one_stream(), tx), ("rx", rx_log, rx)):
            (d / f"periodic_{role}.csv").write_text(harness_lines(content, transport=transport))
        s = make_tables.run(tmp_path / name, tmp_path / (name + "_out"), **PARAMS)
        return len(s["results"]["attack"]), [f["reasons"] for f in s["invalid_runs"]]

    assert run("sound", (f"pdus={n}", "contradicting_pdus=0"), (*TRANSPORT, "stopped_early=0"),
               ("tcp_nodelay=1", f"rows={data_rows(rx_log)}", "rows_lost=0")) == (1, [])
    assert run("short", (f"pdus={n + 1}", "contradicting_pdus=0")) == (0, [[f"pdus={n + 1}, but the file has {n} rows"]])
    assert run("contradicting", (f"pdus={n}", "contradicting_pdus=2")) == (
        0, [["contradicting_pdus=2: the join script counted PDUs that contradict"]])
    assert run("stopped", tx=(*TRANSPORT, "stopped_early=1")) == (0, [[f"stopped_early=1 (read from periodic_tx.csv): {STOPPED}"]])
    assert run("lost", rx=("tcp_nodelay=1", "rows_lost=3")) == (0, [[f"rows_lost=3 (read from periodic_rx.csv): {LOST}"]])
    assert run("cut_log", rx=("tcp_nodelay=1", "rows=2000", "rows_lost=0")) == (
        0, [[f"rows=2000 in periodic_rx.csv, but that log has {data_rows(rx_log)} rows"]])


def test_a_ladder_step_that_was_stopped_early_is_invalid_and_rows_its_log_lost_do_not_touch_it(tmp_path):
    """A sampler file carries none of these lines: stopped_early is the line of the generator's traffic log beside it. A
    ladder reads the sampler's counters and never the rows of a log, so rows a log lost do not make the step invalid."""
    ladder_step(tmp_path / "lost" / "throughput", log_rx=("tcp_nodelay=1", "rows=999", "rows_lost=7"))
    assert make_tables.run(tmp_path / "lost", tmp_path / "lost_out", **PARAMS)["invalid_runs"] == []
    ladder_step(tmp_path / "stopped" / "throughput", log_tx=(*TRANSPORT, "stopped_early=1"))
    s = make_tables.run(tmp_path / "stopped", tmp_path / "stopped_out", **PARAMS)
    assert {f["source"]: f["reasons"] for f in s["invalid_runs"]} == {
        "throughput/throughput_tx_100pps_rep1.csv": [f"stopped_early=1 (read from periodic_tx_100pps_rep1.csv): {STOPPED}"]}
    (step,) = s["results"]["throughput"][0]["saturation"]["steps"]
    assert (step["sustained"], step["judged_reps"]) == (None, 0)


def test_networked_timing_files_are_checked_like_the_single_node_ones(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    for name, content in (("periodic_1s/periodic_tx.csv", synth.periodic_tx_one_stream()),
                          ("periodic_2s/periodic_rx.csv", synth.periodic_rx_two_streams()),
                          ("handshake/handshake.csv", synth.handshake())):
        (run_dir / name).write_text(harness_lines(content))
    for host in ("iris", "baolong"):
        (run_dir / "throughput_1core" / f"throughput_{host}_200.csv").write_text(harness_lines(synth.throughput(host, 200)))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert s["invalid_runs"] == []  # a gateway process is idle between PDUs: cpu_s / wall_s of 0.21 is not a fault here
    one, two = s["results"]["periodic"]
    assert one["validity"]["cpu_share"] == pytest.approx(4.333 / 20.213) and two["rx"]["validity"]["mlockall"] == "ok"
    rows = [ln.split(" | ") for ln in (tmp_path / "out" / "tables" / "validity.md").read_text().splitlines() if ".csv |" in ln]
    assert {(r[0].lstrip("| "), r[1], r[2]) for r in rows} >= {
        ("periodic_1s/periodic_tx.csv", "periodic_tx", "valid"), ("periodic_2s/periodic_rx.csv", "periodic_rx", "valid"),
        ("throughput_1core/throughput_iris_200.csv", "throughput", "valid"), ("handshake/handshake.csv", "handshake", "valid")}
    # one fault per experiment: each file is reported with its reason and takes no part in any table or number
    (run_dir / "periodic_1s" / "periodic_tx.csv").write_text(harness_lines(synth.periodic_tx_one_stream(), tail=()))
    (run_dir / "periodic_2s" / "periodic_rx.csv").write_text(
        harness_lines(synth.periodic_rx_two_streams(), head=(*NET_HEAD[:2], "mlockall=failed (ENOMEM)")))
    (run_dir / "throughput_1core" / "throughput_baolong_200.csv").write_text(
        harness_lines(synth.throughput("baolong", 200), tail=("freq_khz_end=600000", *NET_TAIL[1:])))
    (run_dir / "handshake" / "handshake.csv").write_text(harness_lines(synth.handshake(), head=(*NET_HEAD[:2], "mlockall=failed")))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert {(f["source"], f["experiment"]): f["reasons"] for f in s["invalid_runs"]} == {
        ("periodic_1s/periodic_tx.csv", "periodic_tx"): ["trailer missing (freq_khz_end, wall_s, cpu_s): the run did not finish"],
        ("periodic_2s/periodic_rx.csv", "periodic_rx"): ["mlockall=failed (ENOMEM)"],
        ("throughput_1core/throughput_baolong_200.csv", "throughput"): ["CPU frequency changed during the run (1500000 -> 600000 kHz)"],
        ("handshake/handshake.csv", "handshake"): ["mlockall=failed"]}
    (two,) = s["results"]["periodic"]  # the sender side of the second configuration stands; its receiver file is out
    assert two["source"] == "periodic_2s/periodic_tx.csv" and "rx" not in two and s["results"]["handshake"] == []
    steps = s["results"]["throughput"][0]["saturation"]["steps"]
    # 200 pps: the sender's queue grows, so the step is not sustained whatever the missing receiver file would say
    assert [(st["offered_pps"], st["sustained"], st["judged_reps"]) for st in steps] == [(100, True, 1), (200, None, 0)]
    numbers = (tmp_path / "out" / "numbers.csv").read_text()
    assert "handshake." not in numbers and ".rx_delivered," not in numbers and "r200.rx." not in numbers
    with pytest.raises(SystemExit) as e:  # the exit code of "a file was left unanalysed" covers the networked files too
        make_tables.main([str(run_dir), "--out", str(tmp_path / "out3"), "--warmup", "10", "--block-len", "5", "--n-boot", "50",
                          "--sim-draws", "3", "--sim-jobs", "400", "--no-figures"])
    assert e.value.code == make_tables.EXIT_INVALID


def test_every_marker_is_on_record_with_its_text(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    reason = "gates_iris.txt: the board reached 80.8 C\ngates_iris.txt: other busy processes: others_busy=SecOC:93.3\n"
    (run_dir / "EXCLUDED").write_text(reason)
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert s["not_a_result"] == "EXCLUDED" and s["markers"] == [{"name": "EXCLUDED", "path": "EXCLUDED", "text": reason.strip()}]
    head = "\n".join(ln for ln in (tmp_path / "out" / "numbers.tex").read_text().splitlines() if ln.startswith("%"))
    assert "% EXCLUDED directory: NOT A RESULT" in head and "% EXCLUDED: gates_iris.txt: the board reached 80.8 C" in head
    assert "% EXCLUDED: gates_iris.txt: other busy processes: others_busy=SecOC:93.3" in head
    keys = (tmp_path / "out" / "number_keys.md").read_text()
    assert "EXCLUDED directory: the keys below are real, the values of this run are not results" in keys
    (run_dir / "DRY_RUN").write_text("")  # a dry run that was also excluded: the tag is the dry run's, both are recorded
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert s["not_a_result"] == "DRY_RUN" and [(m["name"], m["text"]) for m in s["markers"]] == [("DRY_RUN", ""), ("EXCLUDED", reason.strip())]
    assert make_tables.run(synth.make_run(tmp_path / "plain"), tmp_path / "out2", **PARAMS)["markers"] == []


def test_run_without_an_env_file_reports_throttling_as_unknown(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "env_iris.txt").unlink()
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert s["env"] == [] and s["invalid_runs"] == []
    v = s["results"]["overhead_paired"][0]["validity"]
    assert v["valid"] and v["throttled"] is None and v["env_throttled"] is None
    rows = [ln.split(" | ") for ln in (tmp_path / "out" / "tables" / "validity.md").read_text().splitlines() if "overhead/" in ln]
    assert rows[0][9] == "unknown"


def test_rerun_into_the_same_directory_leaves_nothing_from_the_earlier_run(tmp_path):
    run_dir, out = synth.make_run(tmp_path / "run"), tmp_path / "out"
    first = make_tables.run(run_dir, out, **PARAMS)
    assert (out / "tables" / "overhead_paired.tex").is_file() and (out / "tables" / "handshake.md").is_file()
    (run_dir / "overhead" / "overhead_paired.csv").write_text(synth.overhead_paired(tail=("signature_mismatches=3", "failed_calls=0",
                                                                                         "freq_khz_end=1500000")))
    (run_dir / "handshake" / "handshake.csv").unlink()
    (run_dir / "crypto" / "crypto_ops.csv").unlink()
    second = make_tables.run(run_dir, out, **PARAMS)
    gone = set(first["tables"]) - set(second["tables"])
    assert gone == {"overhead_paired", "overhead_order", "handshake", "handshake_phases", "crypto_ops", "crypto_ops_ci", "exceedance",
                    "sign_excess"}
    left = {p.stem for p in (out / "tables").iterdir()}
    assert left == set(second["tables"])  # no table of the invalid or the removed files survives
    assert "overhead_paired" not in (out / "numbers.tex").read_text()
    if first["figures"]["status"] == "ok":
        assert "sign_tail_ecdf.pdf" in first["figures"]["written"] and "sign_tail_ecdf.pdf" not in second["figures"]["written"]
        assert {p.name for p in (out / "figures").iterdir()} == set(second["figures"]["written"])
        make_tables.run(run_dir, out, figures=False, **PARAMS)
        assert not list((out / "figures").iterdir())  # figures not drawn in this run are not left behind either


def test_run_killed_while_writing_is_invalid_not_a_crash(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    whole = synth.crypto_ops(tail=())
    (run_dir / "crypto" / "crypto_ops.csv").write_text(whole[:-4])  # the last row is cut inside its number, no trailer follows
    assert whole[:-4].endswith("mldsa_verify,19,419")
    (run_dir / "overhead" / "overhead_paired.csv").write_text(synth.overhead_paired(tail=())[:-9])  # ends "0,AB,sign,1000000,"
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    crypto, paired = s["invalid_runs"]
    assert crypto["reasons"] == ["trailer missing (freq_khz_end, wall_s, cpu_s): the run did not finish"]  # the cut row still parses
    assert paired["reasons"] == ["trailer missing (freq_khz_end, wall_s, cpu_s, signature_mismatches, failed_calls): the run did not "
                                 "finish",
                                 "unreadable row: overhead_paired.csv:59: column csm_ns: '' is not a non-negative integer"]
    assert s["results"]["crypto_ops"] == [] and s["results"]["overhead_paired"] == [] and "attack" in s["tables"]
    # the same damage in a file that has its trailer is not an unfinished run: it stays a hard error
    lines = synth.overhead_paired().splitlines()
    lines[30] = lines[30][:-9]
    (run_dir / "overhead" / "overhead_paired.csv").write_text("\n".join(lines) + "\n")
    with pytest.raises(csvio.CsvError, match=r"overhead_paired\.csv:31: \d fields, expected 5"):
        make_tables.run(run_dir, tmp_path / "out2", **PARAMS)


def test_the_receiver_of_a_killed_sender_is_invalid_with_it(tmp_path):
    """A transmitter killed while writing (the likeliest invalid sender of a periodic run) leaves a cut row and no
    trailer. Its receiver's file is sound and is invalid with it, in the same list: not 'a receiver without a sender'."""
    run_dir = synth.make_run(tmp_path / "run")
    cut = harness_lines(synth.periodic_tx_two_streams(), tail=())
    (run_dir / "periodic_2s" / "periodic_tx.csv").write_text(cut[:cut.rstrip().rfind(",")] + ",")  # the last row lacks its last number
    (run_dir / "periodic_2s" / "periodic_rx.csv").write_text(harness_lines(synth.periodic_rx_two_streams()))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    bad = {f["source"]: f["reasons"] for f in s["invalid_runs"]}
    trailer = "trailer missing (freq_khz_end, wall_s, cpu_s): the run did not finish"
    assert bad["periodic_2s/periodic_tx.csv"][0] == trailer and "unreadable row: periodic_tx.csv:" in bad["periodic_2s/periodic_tx.csv"][-1]
    assert bad["periodic_2s/periodic_rx.csv"] == [
        f"the sender's file of this pair, periodic_tx.csv, is invalid ({trailer}): the pair is invalid as a pair"]
    assert "periodic_2s/periodic_rx.csv" not in [e["path"] for e in s["skipped_csv"]]
    assert [r["source"] for r in s["results"]["periodic"]] == ["periodic_1s/periodic_tx.csv"]


def test_files_without_self_checks_are_analysed_unchecked(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    plain = "".join(ln for ln in synth.overhead_paired().splitlines(keepends=True) if not ln.startswith("#"))
    (run_dir / "overhead" / "overhead_paired.csv").write_text(plain)  # a hand-made file: no comment lines at all
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    paired = s["results"]["overhead_paired"][0]
    assert paired["validity"] is None and paired["mode"] is None and paired["header"] == {} and s["invalid_runs"] == []
    assert "overhead/overhead_paired.csv" not in (tmp_path / "out" / "tables" / "validity.md").read_text()
    assert paired["ops"][0]["n_pairs"] == 10


def test_malformed_row_stops_the_run_with_file_and_line(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    with open(run_dir / "attack" / "attack.csv", "a") as f:
        f.write("replay,20,0,freshness\n")
    with pytest.raises(csvio.CsvError, match=r"attack\.csv:82: 4 fields"):
        make_tables.run(run_dir, tmp_path / "out", **PARAMS)


def test_analysis_error_names_the_file(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "periodic_1s" / "periodic_tx.csv").write_text(synth.periodic_tx_two_streams(deadline_ns=None))
    with pytest.raises(ValueError, match=r"periodic_1s/periodic_tx\.csv: missing header key\(s\) \['deadline_ns'\]"):
        make_tables.run(run_dir, tmp_path / "out", **PARAMS)


def test_throughput_ladders_are_grouped_by_directory_and_header_and_orphan_rx_is_listed(tmp_path):
    run_dir = tmp_path / "run"
    (run_dir / "tput").mkdir(parents=True)
    four_cores = (*synth.TPUT_META[:3], "cores=4", synth.TPUT_META[4])
    for host in ("iris", "baolong"):
        for rate in (100, 200):
            (run_dir / "tput" / f"throughput_{host}_{rate}.csv").write_text(synth.throughput(host, rate))
        (run_dir / "tput" / f"throughput_4c_{host}_100.csv").write_text(synth.throughput(host, 100, four_cores))
    (run_dir / "tput" / "periodic_rx.csv").write_text(synth.periodic_rx_two_streams())
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    four, one = s["results"]["throughput"]  # same directory, two ladders: the header tells them apart
    assert (four["source"], four["cores"], one["source"], one["cores"]) == ("tput", 4, "tput", 1)
    assert [f["source"] for f in four["files"]] == ["tput/throughput_4c_baolong_100.csv", "tput/throughput_4c_iris_100.csv"]
    assert len(one["files"]) == 4 and [st["sustained"] for st in one["saturation"]["steps"]] == [True, False]
    assert four["saturation"]["saturation_pps"] == 100 and four["saturation"]["steps"][0]["delivered_pps"] == 100
    assert s["skipped_csv"] == [{"path": "tput/periodic_rx.csv", "header_matches_schema": "periodic_rx",
                                 "reason": "periodic_rx file without a matching periodic_tx file"}]
    # the two hosts of a ladder must agree on the header: a different commit would split it into two ladders with
    # the same id, which is refused before anything is written
    (run_dir / "tput" / "throughput_4c_iris_100.csv").write_text(synth.throughput("iris", 100, (*four_cores[:4], "commit=fff0000")))
    with pytest.raises(ValueError, match=r"duplicate number key 'throughput\.mldsa65-c4\.\w+' from tput and tput: .*disagree in a "
                                         r"header key such as commit"):
        make_tables.run(run_dir, tmp_path / "out1", **PARAMS)
    assert not (tmp_path / "out1").exists()
    (run_dir / "tput" / "throughput_4c_iris_100.csv").write_text(synth.throughput("iris", 100, four_cores))
    (run_dir / "tput" / "throughput_iris_100.csv").write_text(synth.throughput("iris", 100, synth.TPUT_META[1:]))
    with pytest.raises(ValueError, match=r"tput/throughput_iris_100\.csv: missing header key\(s\) \['tx_host'\]"):
        make_tables.run(run_dir, tmp_path / "out2", **PARAMS)


def test_throughput_file_with_an_impossible_cpu_sample_is_invalid_and_a_one_tick_step_is_counted(tmp_path):
    """In one second the busy jiffies of the sender's 100 PDU/s file grow by 225 while the total grows by 100. The
    file is listed as invalid with that reason, its step is not judged, and no utilisation is formed from it. In the
    receiver's 200 PDU/s file busy grows once by one tick more than total (101 against 100): rounding, the
    file stays valid, the step is counted and the count is a key and a note in the validity line."""
    run_dir = synth.make_run(tmp_path / "run")
    rows = [list(r) for r in synth.throughput_rows("iris", 100)]
    for r in rows[8:]:
        r[4] += 200
    (run_dir / "throughput_1core" / "throughput_iris_100.csv").write_text(synth.text(synth.TPUT_HEADER, rows, synth.TPUT_META))
    rows = [list(r) for r in synth.throughput_rows("baolong", 200)]
    for r in rows[8:]:
        r[4] += 86  # busy 15 + 86 = 101 against total 100 in that second
    (run_dir / "throughput_1core" / "throughput_baolong_200.csv").write_text(synth.text(synth.TPUT_HEADER, rows, synth.TPUT_META))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    (bad,) = s["invalid_runs"]
    assert (bad["source"], bad["experiment"], bad["valid"]) == ("throughput_1core/throughput_iris_100.csv", "throughput", False)
    assert bad["reasons"] == ["1 sample step(s) in which the busy jiffies grew by 2 or more ticks more than the total jiffies "
                              "(first: t_ns 13000000000)"]
    (t,) = s["results"]["throughput"]
    step = next(st for st in t["saturation"]["steps"] if st["offered_pps"] == 100)
    assert step["sustained"] is None and step["across"]["tx_cpu_util"] is None and step["across"]["rx_cpu_util"]["mean"] == 0.1
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        rows = {r["key"]: r for r in csv.DictReader(f)}
    assert "throughput.mldsa65-c1.r100.tx_cpu_util_mean" not in rows and "throughput.mldsa65-c1.r200.tx_cpu_util_mean" in rows
    # busy 9 x 15 + 86 = 221 of total 9 x 100 + 1 = 901 jiffies in the steady window
    assert float(rows["throughput.mldsa65-c1.r200.rx.cpu_util"]["value"]) == pytest.approx(221 / 901)
    assert (rows["throughput.mldsa65-c1.r200.rx.cpu_one_tick_clamps.k"]["value"], rows["throughput.mldsa65-c1.r200.rx.cpu_one_tick_clamps.k"]["n"]) == ("1", "19")
    assert rows["throughput.mldsa65-c1.r200.tx.cpu_one_tick_clamps.k"]["value"] == "0"
    assert "throughput.mldsa65-c1.r100.tx.cpu_one_tick_clamps.k" not in rows  # the invalid file has no keys
    validity = (tmp_path / "out" / "tables" / "validity.md").read_text()
    assert "busy jiffies grew by 2 or more ticks more than the total jiffies" in validity
    line = next(ln for ln in validity.splitlines() if "throughput_baolong_200.csv" in ln)
    assert "| valid |" in line and "1 of 19 sample steps with busy one tick above total, counted as fully busy" in line
    with pytest.raises(SystemExit) as e:
        make_tables.main([str(run_dir), "--out", str(tmp_path / "cli"), "--warmup", "10", "--block-len", "5", "--n-boot", "20",
                          "--sim-draws", "0", "--trim", "5", "--no-figures"])
    assert e.value.code == make_tables.EXIT_INVALID


def test_partitioned_ladder_is_summed_per_rate_step(tmp_path):
    """A two-process run as run_bench_net.sh leaves it: one file pair per partition, each offering half the rate."""
    run_dir = tmp_path / "run"
    (run_dir / "throughput").mkdir(parents=True)
    for host, role in (("iris", "tx"), ("baolong", "rx")):
        for part in (0, 1):
            (run_dir / "throughput" / f"throughput_{role}_200pps_rep1_p{part}.csv").write_text(
                synth.throughput(host, 100, (*synth.TPUT_META, f"partition={part}", "mainfunction=cyclic", "mf_period_us=1000")))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    (t,) = s["results"]["throughput"]
    assert (t["cores"], t["partitions"], t["mainfunction"], t["mf_period_us"], "partition" in t) == (2, 2, "cyclic", 1000, False)
    assert (t["saturation"]["saturation_pps"], len(t["rows"]), len(t["parts"]), len(t["files"])) == (200, 2, 4, 4)
    assert s["figures"]["status"] in ("ok", "skipped: matplotlib is not installed")  # a plotting error is swallowed by design
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        rows = {r["key"]: r for r in csv.DictReader(f)}
    rx = rows["throughput.mldsa65-c2-cyclic-mf1ms.r200.rep1.rx.pps_mean"]  # the file names carry rep1
    assert (float(rx["value"]), rx["source_file"]) == \
        (200, "throughput/throughput_rx_200pps_rep1_p0.csv + throughput/throughput_rx_200pps_rep1_p1.csv")
    assert (rows["throughput.mldsa65-c2-cyclic-mf1ms.partitions"]["value"], float(rows["throughput.mldsa65-c2-cyclic-mf1ms.saturation_pps"]["value"])) == ("2", 200)
    assert "throughput.mldsa65-c2-cyclic-mf1ms.r200.rep1.tx.sendq_slope_bytes_per_s" in rows
    assert "throughput.mldsa65-c2-cyclic-mf1ms.r200.rep1.tx.sendq_slope_lo95_onesided_bytes_per_s" not in rows  # no bound for a sum
    # ... but the growth the verdict compares is the largest of the partitions' bounds, and one PDU is the host's payload
    # over the PDUs of both processes: (340,000 - 66 * 250) / 200
    assert "largest of their bounds" in rows["throughput.mldsa65-c2-cyclic-mf1ms.r200.rep1.tx.sendq_growth_lo95_bytes"]["how"]
    assert float(rows["throughput.mldsa65-c2-cyclic-mf1ms.r200.rep1.tx.queued_bytes_per_pdu"]["value"]) == 1617.5
    assert (rows["throughput.mldsa65-c2-cyclic-mf1ms.r200.rep1.offered_pdus"]["value"],
            rows["throughput.mldsa65-c2-cyclic-mf1ms.r200.rep1.lost_pdus"]["value"]) == ("1800", "0")  # both partitions
    # the ladder column is the id of the keys, so a cyclic and an event ladder of one directory can be told apart
    md = [ln.split(" | ") for ln in (tmp_path / "out" / "tables" / "throughput.md").read_text().splitlines()
          if "| throughput | mldsa65-c2-cyclic-mf1ms |" in ln]
    # bytes per PDU on the wire exist for the sum only: the interface counters are the host's, not one partition's
    # (340,000 bytes/s on the interface, 200 PDU/s over both partitions)
    assert [ln[13] for ln in md] == ["1700.0", "1700.0", "–", "–", "–", "–"]
    assert {ln[11] for ln in md} == {"–"}  # process CPU: these files have no proc_cpu_ns column
    assert [(ln[2], ln[3], ln[4]) for ln in md] == [  # files in name order: the rx host first, sums before their parts
        ("200", "baolong", "sum of 2"), ("200", "iris", "sum of 2"), ("100", "baolong", "0"), ("100", "baolong", "1"),
        ("100", "iris", "0"), ("100", "iris", "1")]


def test_ladder_sensitivity_line_over_the_repetitions_without_a_retransmission(tmp_path):
    """Three repetitions at 100 PDU/s. In the third the transmitter's connection retransmitted one segment and the
    receiver delivered 99 PDU/s (9 of 900 lost). Over all repetitions the step is not sustained; over the two without a
    retransmission it is. Both are reported, the second beside the first, with what it leaves out."""
    run_dir = tmp_path / "run"
    (run_dir / "throughput").mkdir(parents=True)
    for k, rx_steady, retrans in ((1, None, 0), (2, None, 0), (3, (99,), 1)):
        (run_dir / "throughput" / f"throughput_tx_100pps_rep{k}.csv").write_text(
            synth.throughput("iris", 100, (*synth.TPUT_META, f"tcp_total_retrans_in_window={retrans}")))
        (run_dir / "throughput" / f"throughput_rx_100pps_rep{k}.csv").write_text(synth.throughput("baolong", 100, steady=rx_steady))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    sat = s["results"]["throughput"][0]["saturation"]
    assert (sat["saturation_pps"], sat["no_retrans"]["saturation_pps"], sat["no_retrans"]["reps_left_out"]) == (None, 100, 1)
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        rows = {r["key"]: r for r in csv.DictReader(f)}
    ladder, step = "throughput.mldsa65-c1.", "throughput.mldsa65-c1.r100."
    assert ladder + "saturation_pps" not in rows and rows[ladder + "no_retrans.saturation_pps"]["value"] == "100.0"
    assert [rows[ladder + "no_retrans." + k]["value"] for k in ("reps_left_out", "files_with_retrans", "files_unknown")] == ["1", "1", "0"]
    assert (rows[step + "n_reps"]["value"], rows[step + "sustained_reps"]["value"]) == ("3", "2")
    assert (rows[step + "no_retrans.n_reps"]["value"], rows[step + "no_retrans.sustained_reps"]["value"]) == ("2", "2")
    assert (float(rows[step + "delivered_pps_mean"]["value"]), float(rows[step + "no_retrans.delivered_pps_mean"]["value"])) == \
        (pytest.approx(299 / 3), 100)
    assert (float(rows[step + "loss_ratio_max"]["value"]), float(rows[step + "no_retrans.loss_ratio_max"]["value"])) == (0.01, 0)
    assert "without a retransmitted segment" in rows[step + "no_retrans.delivered_pps_mean"]["how"]
    assert step + "no_retrans.tx_cpu_util_mean" not in rows and step + "no_retrans.sendq_max_bytes_max" not in rows  # delivery figures only
    line = next(ln for ln in (tmp_path / "out" / "tables" / "throughput_no_retrans.md").read_text().splitlines() if ln.startswith("| throughput |"))
    assert line == ("| throughput | mldsa65-c1 | 100 | 3 | 2 | 1 | 0 | 99.67 | 100.00 | 1% | 0% | not sustained | sustained | – | 100 |")
    note = (tmp_path / "out" / "tables" / "throughput_no_retrans.md").read_text()
    assert "never instead of them" in note and "1 repetition(s) left out" in note
    # a ladder whose files give no count has no second line: no table, no keys
    for k in (1, 2, 3):
        (run_dir / "throughput" / f"throughput_tx_100pps_rep{k}.csv").write_text(synth.throughput("iris", 100))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert "throughput_no_retrans" not in s["tables"] and not (tmp_path / "out" / "tables" / "throughput_no_retrans.md").exists()
    assert "no_retrans" not in (tmp_path / "out" / "numbers.csv").read_text()
    assert "no transmitter file gives tcp_total_retrans_in_window" in (tmp_path / "out" / "tables" / "throughput_saturation.md").read_text()


def test_repetitions_of_a_ladder_are_analysed_one_by_one_and_summarised_per_step(tmp_path):
    """Files as the driver names them, all in one directory: throughput_{tx,rx}_<rate>pps_rep<k>.csv.
    The receiver delivers 100 PDUs/s in repetitions 1 and 2 and 99 in repetition 3 (9 of 900 lost)."""
    run_dir = tmp_path / "run"
    (run_dir / "throughput").mkdir(parents=True)
    for k, rx_steady in ((1, None), (2, None), (3, (99,))):
        (run_dir / "throughput" / f"throughput_tx_100pps_rep{k}.csv").write_text(synth.throughput("iris", 100))
        (run_dir / "throughput" / f"throughput_rx_100pps_rep{k}.csv").write_text(synth.throughput("baolong", 100, steady=rx_steady))
    # the header's '# rep=' line wins over the file name: these two files are repetition 7
    for role, host in (("tx", "iris"), ("rx", "baolong")):
        (run_dir / "throughput" / f"throughput_{role}_100pps_rep4.csv").write_text(synth.throughput(host, 100, (*synth.TPUT_META, "rep=7")))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    (t,) = s["results"]["throughput"]
    assert (t["reps"], "rep" in t, len(t["rows"]), s["figures"]["status"] in ("ok", "skipped: matplotlib is not installed")) == \
        ([1, 2, 3, 7], False, 8, True)
    (step,) = t["saturation"]["steps"]
    assert (step["n_reps"], step["sustained_reps"], step["sustained"], t["saturation"]["saturation_pps"]) == (4, 3, False, None)
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        rows = {r["key"]: r for r in csv.DictReader(f)}
    base = "throughput.mldsa65-c1.r100"
    assert (rows[base + ".n_reps"]["value"], rows[base + ".sustained_reps"]["value"], rows[base + ".delivered_pps_mean"]["n"]) == ("4", "3", "4")
    assert float(rows[base + ".delivered_pps_mean"]["value"]) == 99.75 and float(rows[base + ".delivered_pps_min"]["value"]) == 99
    assert base + ".delivered_pps_t95_lo" in rows and base + ".loss_ratio_max" in rows and base + ".rx_cpu_util_mean" in rows
    # loss ratios 0, 0, 1%, 0: the Student-t interval of their mean would start below zero; a proportion's is clamped
    assert (rows[base + ".loss_ratio_mean"]["formatted"], rows[base + ".loss_ratio_t95_lo"]["formatted"]) == (r"0.25\%", r"0\%")
    assert float(rows[base + ".loss_ratio_t95_lo"]["value"]) == 0 and float(rows[base + ".loss_ratio_t95_hi"]["value"]) > 0.01
    assert all("bounds clamped to the range of a proportion" in rows[base + k]["how"]
               for k in (".loss_ratio_t95_lo", ".loss_ratio_t95_hi", ".tx_cpu_util_t95_hi", ".rx_cpu_util_t95_lo"))
    # the CPU figures come from tick-based accounting: they stay in the CSV and are no manuscript numbers
    held_back = dict(ln.split("\t") for ln in (tmp_path / "out" / "suppressed_keys.txt").read_text().splitlines()
                     if ln and not ln.startswith("#"))
    cpu = [k for k in rows if "cpu_util" in k]
    assert len(cpu) >= 18 and all(held_back.get(k) == throughput.CPU_NOT_QUOTED for k in cpu)
    assert {base + ".tx_cpu_util_mean", base + ".rx_cpu_util_t95_lo", base + ".tx_cpu_util_max", base + ".rep3.rx.cpu_util"} <= set(cpu)
    tex = (tmp_path / "out" / "numbers.tex").read_text()
    assert "cpu_util" not in tex and base + ".rep3.rx.cpu_one_tick_clamps.k" in tex and base + ".loss_ratio_t95_lo" in tex
    assert throughput.CPU_NOT_QUOTED == ("tick-based CPU accounting of these kernels misses work that starts on a timer; "
                                         "not a utilisation to quote")
    assert all("tick-based" in (tmp_path / "out" / "tables" / f"{name}.md").read_text() for name in ("throughput", "throughput_steps"))
    assert "clamped" not in rows[base + ".delivered_pps_t95_lo"]["how"]
    assert (rows[base + ".rep3.lost_pdus"]["value"], rows[base + ".rep3.offered_pdus"]["value"], rows[base + ".rep7.lost_pdus"]["value"]) == \
        ("9", "900", "0")
    assert rows[base + ".rep3.loss_ratio"]["source_file"] == "throughput/throughput_tx_100pps_rep3.csv + throughput/throughput_rx_100pps_rep3.csv"
    assert float(rows[base + ".rep3.rx.pps_mean"]["value"]) == 99 and base + ".rx.pps_mean" not in rows and base + ".rep4.lost_pdus" not in rows
    tables = tmp_path / "out" / "tables"
    reps = [ln.split(" | ") for ln in (tables / "throughput_reps.md").read_text().splitlines() if "| throughput | mldsa65-c1 |" in ln]
    # rep, offered, not delivered, of which dropped at release, loss ratio, sustained
    assert [(ln[3], ln[5], ln[6], ln[7], ln[8], ln[13].rstrip(" |")) for ln in reps] == [
        ("1", "900", "0", "0", "0%", "yes"), ("2", "900", "0", "0", "0%", "yes"), ("3", "900", "9", "0", "1%", "no"),
        ("7", "900", "0", "0", "0%", "yes")]
    # what the queue verdict compares stands beside it. The synthetic queue alternates 8000 / 6000 bytes over t = 0..9 s:
    # Sxx = 82.5, Sxy = -5000, Syy = 1e7, so the slope is -5000/82.5 bytes/s with the standard error below; one PDU is
    # (340,000 bytes - 66 * 250 packets) / 100 PDUs = 3,235 bytes
    bound = 9 * (-5000 / 82.5 - sps.t.ppf(0.95, 8) * math.sqrt((1e7 - 5000**2 / 82.5) / 8 / 82.5))
    assert "| queue growth bound (B) | one queued PDU (B) | send queue growing | sustained |" in (tables / "throughput_reps.md").read_text()
    assert {(ln[10], ln[11], ln[12]) for ln in reps} == {(f"{bound:.1f}", "3235.0", "no")}
    growth, size = rows[base + ".rep3.tx.sendq_growth_lo95_bytes"], rows[base + ".rep3.tx.queued_bytes_per_pdu"]
    assert float(growth["value"]) == pytest.approx(bound) and float(size["value"]) == 3235
    assert "at least" in growth["how"] and "66 bytes" in size["how"] and "loopback" in size["how"]
    assert base + ".rep3.rx.sendq_growth_lo95_bytes" not in rows and base + ".rep3.rx.queued_bytes_per_pdu" not in rows
    assert "above 0" not in rows[base + ".rep3.tx.sendq_slope_lo95_onesided_bytes_per_s"]["how"]
    # the verdict's key says which size of a PDU the rule uses
    assert "at least one PDU as it is queued" in rows[base + ".sustained_reps"]["how"] and "66 bytes" in rows[base + ".sustained_reps"]["how"]
    assert "| offered PDUs | not delivered | dropped at release | loss ratio |" in (tables / "throughput_reps.md").read_text()
    assert "of which" not in (tables / "throughput_reps.md").read_text()  # the drops are no subset of the PDUs not delivered
    assert "not delivered inside the window" in (tables / "throughput_reps.md").read_text()
    exact = sps.binomtest(9, 900).proportion_ci(0.95, method="exact")  # scipy's own route to the interval of 9 of 900
    assert f"| 1% | [{100 * exact.low:.5g}%, {100 * exact.high:.5g}%] |" in (tables / "throughput_reps.md").read_text()
    steps = (tables / "throughput_steps.md").read_text()
    assert "| 100 | delivered (PDU/s) | 4 | 99.75 | [98.95, 100.55] | 99.00 | 100.00 |" in steps
    # the Student-t interval of the loss ratio is -0.546% to 1.046%; a proportion's lower end is clamped to 0
    assert "| 100 | loss ratio | 4 | 0.25% | [0%, 1.0456%] | 0% | 1% |" in steps and "clamped to [0, 1]" in steps
    assert "| 100 | dropped at release, share of the offered PDUs (tx host) | 4 | 0% | [0%, 0%] | 0% | 0% |" in steps
    verdict = (tables / "throughput_saturation.md").read_text()
    pooled = sps.binomtest(9, 3600).proportion_ci(0.95, method="exact")  # secondary: the four repetitions' counts pooled
    assert ("| 100 | 4 | 99.75 | 1% | 0% | no | 3 of 4 | not sustained | – | 0.25% | "
            f"[{100 * pooled.low:.5g}%, {100 * pooled.high:.5g}%] |") in verdict
    assert "loss ratio is at most 0.001" in verdict and "first and last 5 samples of each file dropped (--trim 5)" in verdict
    assert "not growing" in verdict and "secondary" in verdict
    assert (rows[base + ".loss_pooled"]["value"], rows[base + ".lost_pdus_pooled"]["value"], rows[base + ".offered_pdus_pooled"]["value"]) == \
        ("0.0025", "9", "3600")
    assert base + ".loss_pooled_cp95_hi" in rows and "secondary" in rows[base + ".loss_pooled"]["how"]


def test_throughput_default_is_every_sample_and_the_saturation_point_stops_at_the_first_step_that_fails(tmp_path):
    """Steps 100 (sustained), 200 (queue grows) and 300 (behaves like 100): the saturation point is 100."""
    run_dir = tmp_path / "run"
    (run_dir / "tput").mkdir(parents=True)
    for host in ("iris", "baolong"):
        for offered, like in ((100, 100), (200, 200), (300, 100)):
            (run_dir / "tput" / f"throughput_{host}_{offered}.csv").write_text(synth.throughput(host, like, offered=offered))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    (t,) = s["results"]["throughput"]
    assert (t["saturation"]["saturation_pps"], t["saturation"]["range_ended_at"], t["saturation"]["non_monotone"]) == (100, 200, [300])
    md = (tmp_path / "out" / "tables" / "throughput_saturation.md").read_text()
    assert "non-monotone: tput mldsa65-c1: 300 PDU/s sustained above 200 PDU/s, the first step that is not" in md
    assert "| 1 of 1 | sustained, above the sustained range | 100 |" in md
    assert "| directory | ladder | offered (PDU/s) | reps |" in md and "| tput | mldsa65-c1 | 300 | 1 |" in md
    numbers = {ln.split(",")[0]: ln.split(",")[1] for ln in (tmp_path / "out" / "numbers.csv").read_text().splitlines()}
    assert (numbers["throughput.mldsa65-c1.saturation_pps"], numbers["throughput.mldsa65-c1.non_monotone_steps"]) == ("100.0", "1")
    # without --trim every sample is used: the harness leaves the ramp out of its samples
    assert inspect.signature(make_tables.run).parameters["trim"].default == 0
    s = make_tables.run(run_dir, tmp_path / "out2", **{k: v for k, v in PARAMS.items() if k != "trim"})
    assert (s["params"]["trim"], {r["intervals"] for r in s["results"]["throughput"][0]["rows"]}) == (0, {19})
    assert "every sample of each file (--trim 0)" in (tmp_path / "out2" / "tables" / "throughput.md").read_text()
    make_tables.main([str(run_dir), "--out", str(tmp_path / "out3"), "--no-figures", "--sim-draws", "0"])
    assert strict_json(tmp_path / "out3" / "summary.json")["params"]["trim"] == 0


def test_optional_periodic_header_keys_reach_the_configuration_id(tmp_path):
    """Two runs of the same period that differ in how the main functions are driven do not collide."""
    run_dir = tmp_path / "run"
    for mf in ("cyclic", "event"):
        (run_dir / f"periodic_{mf}").mkdir(parents=True)
        (run_dir / f"periodic_{mf}" / "periodic_tx.csv").write_text(
            synth.periodic_tx_two_streams(mainfunction=mf, mf_period_us=1000, phase="sync", partition=0))
    make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        rows = {r["key"]: r["formatted"] for r in csv.DictReader(f)}
    for mf in ("cyclic", "event"):
        base = f"periodic.p10ms-s2-c1-mldsa65-fifo-{mf}-mf1ms-sync-part0"
        assert (rows[base + ".misses"], rows[base + ".mf_period_ms"], rows[base + ".partition"]) == ("3", "1.00", "0")
    head, _, first = [ln for ln in (tmp_path / "out" / "tables" / "periodic.md").read_text().splitlines() if ln.startswith("|")][:3]
    assert "| scheduler | main function | MF period (µs) | phase | partition | jobs |" in head
    assert "| fifo | cyclic | 1000 | sync | 0 | 24 |" in first
    plain = synth.make_run(tmp_path / "plain")  # files without the optional keys: a dash, and the id as before
    make_tables.run(plain, tmp_path / "out2", **PARAMS)
    assert "| fifo | – | – | – | – | 12 |" in (tmp_path / "out2" / "tables" / "periodic.md").read_text()


def test_partitions_of_a_periodic_cell_get_a_combined_miss_ratio(tmp_path):
    """periodic_tx_p0.csv and periodic_tx_p1.csv as the driver names them: two processes, each two streams, 3 of 24 missed."""
    run_dir = tmp_path / "run"
    (run_dir / "periodic").mkdir(parents=True)
    bench = dict(mainfunction="cyclic", mf_period_us=1000, phase="sync")
    for i in (0, 1):
        (run_dir / "periodic" / f"periodic_tx_p{i}.csv").write_text(synth.periodic_tx_two_streams(partition=i, **bench))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    (cell,) = s["results"]["periodic_cells"]
    assert (cell["source"], cell["label"], cell["files"], cell["missing_partitions"]) == \
        ("periodic", "", ["periodic/periodic_tx_p0.csv", "periodic/periodic_tx_p1.csv"], [])
    assert (cell["partitions"], cell["streams"], cell["cores"], cell["jobs"], cell["misses"], cell["miss_ratio"]) == (2, 4, 2, 48, 6, 0.125)
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        rows = {r["key"]: r for r in csv.DictReader(f)}
    both = "periodic.p10ms-s4-c2-mldsa65-fifo-cyclic-mf1ms-sync-parts2"  # streams and cores added, marked as a combination
    assert (rows[both + ".jobs"]["value"], rows[both + ".misses"]["value"], rows[both + ".miss_ratio"]["value"], rows[both + ".partitions"]["value"]) == \
        ("48", "6", "0.125", "2")
    assert both + ".miss_cp95_lo" in rows and "independent processes" in rows[both + ".miss_ratio"]["how"]
    assert rows["periodic.p0.p10ms-s2-c1-mldsa65-fifo-cyclic-mf1ms-sync-part0.misses"]["value"] == "3"  # the partitions keep theirs
    md = (tmp_path / "out" / "tables" / "periodic_combined.md").read_text()
    assert "| periodic | – | 10 | 2 | 4 | 2 | mldsa65 | fifo | 48 | 6 | 12.5% |" in md and "independent" in md
    assert ".no_retrans." not in (tmp_path / "out" / "numbers.csv").read_text()  # these files give no count: no second figure
    # the second figure of the cell: partition 1 retransmitted two segments, so it is formed over partition 0 alone
    for i, count in ((0, 0), (1, 2)):
        (run_dir / "periodic" / f"periodic_tx_p{i}.csv").write_text(
            f"# tcp_total_retrans_in_window={count}\n" + synth.periodic_tx_two_streams(partition=i, **bench))
    make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        rows = {r["key"]: r for r in csv.DictReader(f)}
    assert [rows[both + ".no_retrans." + k]["value"] for k in ("partitions", "left_out_retransmitted", "left_out_unknown", "jobs", "misses",
                                                                "miss_ratio")] == ["1", "1", "0", "24", "3", "0.125"]
    assert both + ".no_retrans.miss_cp95_hi" in rows and rows[both + ".miss_ratio"]["value"] == "0.125"  # the first figure stays
    assert "never instead of" in rows[both + ".no_retrans.miss_ratio"]["how"]
    line = next(ln for ln in (tmp_path / "out" / "tables" / "periodic_combined.md").read_text().splitlines() if ln.startswith("| periodic |"))
    assert "| 48 | 6 | 12.5% |" in line and line.endswith("| 1 | 1 | 0 | 24 | 3 | 12.5% | [2.66%, 32.4%] |")
    # a lone partition 0 is a single process (the harness writes partition=0 in every file): nothing to combine
    (run_dir / "periodic" / "periodic_tx_p1.csv").unlink()
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert s["results"]["periodic_cells"] == [] and "periodic_combined" not in s["tables"]
    # with '# partitions=2' the missing partition is known: the cell is listed and nothing is combined
    (run_dir / "periodic" / "periodic_tx_p0.csv").write_text(synth.periodic_tx_two_streams(partition=0, partitions=2, **bench))
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    (cell,) = s["results"]["periodic_cells"]
    assert (cell["missing_partitions"], "miss_ratio" in cell) == ([1], False)
    assert "partition 1 missing or invalid: not combined" in (tmp_path / "out" / "tables" / "periodic_combined.md").read_text()
    assert "-parts2." not in (tmp_path / "out" / "numbers.csv").read_text()


def test_handshake_keys_are_named_after_the_host_the_file_names(tmp_path):
    """One file per host. baolong's hostname is raspberrypi: the key says what the file's '# host=' line says."""
    run_dir = tmp_path / "run"
    (run_dir / "handshake").mkdir(parents=True)
    rows = synth.handshake(("host=raspberrypi", "t_min_ms=0")).splitlines(keepends=True)
    (run_dir / "handshake" / "handshake_baolong.csv").write_text("".join(ln for ln in rows if ",initiator," not in ln))
    (run_dir / "handshake" / "handshake_iris.csv").write_text("".join(ln for ln in synth.handshake(()).splitlines(keepends=True)
                                                                      if ",responder," not in ln))  # no host line: the file label
    make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    keys = (tmp_path / "out" / "numbers.csv").read_text()
    assert "handshake.raspberrypi.responder.total_p50_ms," in keys and "handshake.raspberrypi.header.t_min_ms," in keys
    assert "handshake.iris.initiator.total_p50_ms," in keys and "handshake.baolong." not in keys


def test_gateway_files_with_stages_not_recorded_are_analysed_without_them(tmp_path):
    """The gateway application writes auth_done_ns (Tx) and rx_done_ns (Rx) as 0 and says so in the header."""
    run_dir = tmp_path / "run"
    (run_dir / "e3").mkdir(parents=True)
    tx_rows = [(*r[:4], 0, r[5]) for r in synth.periodic_tx_rows()]
    rx_rows = [(*r[:2], 0, *r[3:]) for r in map(synth.rx_row, synth.periodic_tx_rows())]
    (run_dir / "e3" / "periodic_tx.csv").write_text(synth.periodic_tx_two_streams(tx_rows, not_recorded="auth_done_ns"))
    (run_dir / "e3" / "periodic_rx.csv").write_text(synth.text(synth.RX_HEADER, rx_rows, ("not_recorded=rx_done_ns",)))
    (run_dir / "e3" / "clock_offset.csv").write_text(synth.clock_offset())
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    (r,) = s["results"]["periodic"]
    assert (r["misses"], r["not_recorded"], r["auth_us"]) == (3, ["auth_done_ns"], None)
    assert (r["rx"]["delivered"], r["rx"]["not_recorded"], r["rx"]["latency"]) == (24, ["rx_done_ns"], None)
    assert s["skipped_csv"] == []  # the clock file was read; it just cannot be used without rx_done_ns
    tables = tmp_path / "out" / "tables"
    assert "| auth | not recorded |" in (tables / "periodic_times.md").read_text()
    rx_times = (tables / "periodic_rx_times.md").read_text()
    assert "| verification | not recorded |" in rx_times and "| delivery | not recorded |" in rx_times
    assert rx_times.count("not reported (rx_done_ns not recorded)") == 2  # one-way latency and end-to-end
    numbers = (tmp_path / "out" / "numbers.csv").read_text()
    assert ".response_p50_us," in numbers and ".rx_delivered," in numbers and ".rx_delivery_ratio," in numbers
    assert not [w for w in (".auth_", ".rx_verify_", ".rx_deliver_", ".latency_", ".end_to_end_") if w in numbers]


def test_handshake_table_says_what_each_total_contains(done):
    _, out, summary = done
    assert summary["results"]["handshake"][0]["header"] == {"mainfunction": "cyclic", "mf_period_us": "1000", "t_min_ms": "0"}
    md = (out / "tables" / "handshake.md").read_text()
    assert "the responder's total includes the initiator's computation and two network legs" in md and "not crypto time" in md
    row = next(ln for ln in md.splitlines() if "| initiator |" in ln)
    assert row.startswith("| handshake/handshake.csv | initiator | cyclic | 1000 | 0 | 4 | ok: 3, timeout: 1 | 2000.00 |")
    assert "| 771.00 | 771.00 | 871.00 |" in row  # compute: mean, p50, max
    phases = (out / "tables" / "handshake_phases.md").read_text()
    assert "| initiator | hash | 15.00 |" in phases and "| responder | mac | 5.00 |" in phases


LOG = ("traffic log of the load generator in an attack, throughput, calibration or negative-test directory, "
       "not a periodic experiment")


def test_traffic_logs_beside_attack_and_throughput_runs_are_not_periodic_experiments(tmp_path):
    """The generator writes periodic_tx / periodic_rx files next to attack.csv and the throughput files."""
    run_dir = synth.make_run(tmp_path / "run")
    logs = {"attack/periodic_tx.csv": synth.periodic_tx_one_stream(),  # the same header as periodic_1s: would collide
            "throughput_1core/periodic_tx_100pps_rep1.csv": synth.periodic_tx_two_streams(),
            "throughput_1core/periodic_rx_100pps_rep1.csv": synth.periodic_rx_two_streams(),
            # not even its validity is judged: a log cut short does not make the run exit with code 3
            "attack_mac/periodic_tx.csv": harness_lines(synth.periodic_tx_one_stream(), tail=()),
            # the generator's log of the bytes-per-PDU calibration
            "calibration/periodic_tx.csv": synth.periodic_tx_two_streams(), "calibration/periodic_rx.csv": synth.periodic_rx_two_streams()}
    (run_dir / "attack_mac").mkdir()
    (run_dir / "calibration").mkdir()
    for name, content in logs.items():
        (run_dir / name).write_text(content)
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert [r["source"] for r in s["results"]["periodic"]] == ["periodic_1s/periodic_tx.csv", "periodic_2s/periodic_tx.csv"]
    assert s["invalid_runs"] == []
    assert [e for e in s["skipped_csv"] if e["reason"] == LOG] == [
        {"path": name, "reason": LOG, "header_matches_schema": "periodic_rx" if "_rx" in name else "periodic_tx"}
        for name in sorted(logs)]
    # the handshake before each ladder step or attack run is session set-up, not a handshake experiment: its files are
    # listed and not read, in a step's own subdirectory or beside the throughput files, and not even a cut file counts
    setup = {"throughput_1core/handshake_100pps_rep1/handshake_tx.csv": synth.handshake(),
             "throughput_1core/handshake_100pps_rep1/handshake_rx.csv": synth.handshake(),
             "throughput_1core/handshake_rx_200pps_rep1.csv": synth.handshake(),
             "attack/handshake_tx.csv": harness_lines(synth.handshake(), tail=()),
             "calibration/handshake_rx.csv": synth.handshake()}  # the calibration ladder before a campaign ladder
    (run_dir / "throughput_1core" / "handshake_100pps_rep1").mkdir()
    for name, content in setup.items():
        (run_dir / name).write_text(content)
    s = make_tables.run(run_dir, tmp_path / "out_setup", **PARAMS)
    assert [r["source"] for r in s["results"]["handshake"]] == ["handshake/handshake.csv"] and s["invalid_runs"] == []
    assert [e for e in s["skipped_csv"] if e["reason"] == make_tables.SETUP_HANDSHAKE] == [
        {"path": name, "reason": make_tables.SETUP_HANDSHAKE, "header_matches_schema": "handshake"} for name in sorted(setup)]
    assert make_tables.SETUP_HANDSHAKE == (
        "session set-up handshake of another experiment (in an attack, throughput or calibration directory, beside a "
        "periodic file, or its header says pdu_stream other than none), not a handshake experiment")
    assert not [k for k in (tmp_path / "out_setup" / "numbers.csv").read_text().splitlines() if k.startswith("handshake.") and "pps" in k]
    # DATA_SCHEMA.md, 'Jobs given up' (handshake files): so is a handshake file with a periodic file beside it (the one
    # handshake before a periodic run) and one whose header says that a PDU stream ran beside the handshakes. A file
    # that says pdu_stream=none, or says nothing (a legacy file, a gateway's file), stays a handshake experiment
    head = ("commit=abc1234", "mainfunction=cyclic", "mf_period_us=1000", "t_min_ms=0")
    more = {"periodic_2s/handshake_tx.csv": synth.handshake(), "periodic_2s/handshake_rx.csv": synth.handshake(comments=(*head, "pdu_stream=none")),
            "hs_stream/handshake_tx.csv": synth.handshake(comments=(*head, "host=iris", "pdu_stream=periodic"))}
    kept = {"hs_none/handshake_tx.csv": synth.handshake(comments=(*head, "host=iris", "pdu_stream=none")),
            "hs_gw/handshake_gw_rx.csv": synth.handshake(comments=(*head, "host=baolong"))}
    for name, content in {**more, **kept}.items():
        (run_dir / name).parent.mkdir(exist_ok=True)
        (run_dir / name).write_text(content)
    s = make_tables.run(run_dir, tmp_path / "out_more", **PARAMS)
    assert [r["source"] for r in s["results"]["handshake"]] == sorted(["handshake/handshake.csv", *kept])
    assert [e["path"] for e in s["skipped_csv"] if e["reason"] == make_tables.SETUP_HANDSHAKE] == sorted([*setup, *more])
    for name in more:
        (run_dir / name).unlink()
    for name in kept:
        shutil.rmtree((run_dir / name).parent)
    # the rule looks at the directory the file is in, also when that directory itself is analysed
    alone = make_tables.run(run_dir / "throughput_1core", tmp_path / "out2", **PARAMS)
    assert alone["results"]["periodic"] == [] and len([e for e in alone["skipped_csv"] if e["reason"] == LOG]) == 2
    assert LOG == make_tables.TRAFFIC_LOG
    # a periodic file at the top of a run directory (the gateway delivery runs) is an experiment
    top = tmp_path / "u32_t4"
    top.mkdir()
    (top / "periodic_tx.csv").write_text(synth.periodic_tx_one_stream())
    assert len(make_tables.run(top, tmp_path / "out3", **PARAMS)["results"]["periodic"]) == 1


def test_without_a_clock_relation_latency_is_not_reported(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "periodic_2s" / "clock_offset.csv").unlink()
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    rx = s["results"]["periodic"][1]["rx"]
    assert rx["latency"] is None and rx["latency_note"] == "not reported (no clock relation)"
    rows = [ln for ln in (tmp_path / "out" / "tables" / "periodic_rx_times.md").read_text().splitlines() if "latency" in ln or "end-to-end" in ln]
    assert len(rows) == 2 + 1 and all("not reported (no clock relation)" in ln for ln in rows[1:])  # note line + two rows
    numbers = (tmp_path / "out" / "numbers.csv").read_text()
    assert "rx_verify_p50_us" in numbers and "latency" not in numbers and "end_to_end" not in numbers
    (run_dir / "periodic_2s" / "clock_offset.csv").write_text(synth.clock_offset())
    (run_dir / "periodic_2s" / "clock_offset_b.csv").write_text(synth.clock_offset())
    with pytest.raises(ValueError, match="more than one clock_offset file"):
        make_tables.run(run_dir, tmp_path / "out2", **PARAMS)
    (run_dir / "periodic_2s" / "clock_offset_b.csv").unlink()
    (run_dir / "periodic_2s" / "clock_offset.csv").write_text(synth.clock_offset(-synth.RX_AHEAD))  # wrong sign
    with pytest.raises(ValueError, match=r"periodic_2s/periodic_rx\.csv: clock relation: implausible, the fastest PDU took 14000500000 ns"):
        make_tables.run(run_dir, tmp_path / "out3", **PARAMS)


LAUNCH_NS = [640, 540, 60, 850, 570, -130]  # csm - standalone of the sign pairs of six launches, as in the probe run


def launch_run(root, diffs=LAUNCH_NS, mode="ab", name="overhead_paired_L{:02d}.csv", **kw):
    (root / "overhead").mkdir(parents=True, exist_ok=True)
    (root / "equivalence_margin.txt").write_text("0.01\n")
    for i, d in enumerate(diffs, 1):
        (root / "overhead" / name.format(i)).write_text(synth.paired_launch(i, d, mode, **kw))
    return root


def test_launch_set_within_launch_pooled_and_across_launch(tmp_path):
    s = make_tables.run(launch_run(tmp_path / "run"), tmp_path / "out", **PARAMS)
    files = s["results"]["overhead_paired"]
    assert [(f["source"], f["launch"]) for f in files][:2] == [("overhead/overhead_paired_L01.csv", 1), ("overhead/overhead_paired_L02.csv", 2)]
    assert [f["ops"][0]["hl_paired"]["estimate_us"] for f in files] == [0.64, 0.54, 0.06, 0.85, 0.57, -0.13]  # 4 equal pairs each
    (t,) = s["results"]["overhead_launch_sets"]
    assert (t["source"], t["mode"], t["n_launches"], t["n_invalid_launches"], t["margin"]) == ("overhead", "ab", 6, 0, 0.01)
    assert t["files"] == [f"overhead/overhead_paired_L{i:02d}.csv" for i in range(1, 7)]
    pooled = {o["op"]: o for o in t["pooled"]}
    assert (pooled["sign"]["n_pairs"], pooled["sign"]["n_warmup_dropped"]) == (24, 60)  # warm-up is dropped inside every launch
    assert pooled["sign"]["median_diff_us"] == pytest.approx(0.555)  # median of 24 pairs: between 0.54 and 0.57
    sign, verify = t["across_launch"]
    assert (sign["n_launches"], sign["launches"], sign["pairs_per_launch"]) == (6, [1, 2, 3, 4, 5, 6], [4] * 6)
    h = sign["hl_us"]
    assert (h["mean"], h["sd"], h["min"], h["max"]) == pytest.approx((2.53 / 6, 0.37478, -0.13, 0.85), abs=1e-5)
    assert h["t95"] == pytest.approx([0.0284, 0.8150], abs=1e-4)
    assert sign["gm_ratio"]["mean"] == pytest.approx(1 + 421.67e-6, abs=1e-7)  # a mean difference of 0.42 us in 1 ms
    assert sign["tost"]["df"] == 5 and sign["verdict"] == "equivalent within the margin"
    assert (verify["hl_us"]["mean"], verify["hl_us"]["sd"], verify["verdict"]) == (0, 0, "equivalent within the margin")
    assert {"overhead_paired", "overhead_launches", "overhead_across_launch", "overhead_order"} <= set(s["tables"])
    tables = tmp_path / "out" / "tables"
    assert len([ln for ln in (tables / "overhead_launches.md").read_text().splitlines() if ".csv" in ln]) == 12
    rows = [ln.split(" | ") for ln in (tables / "overhead_paired.md").read_text().splitlines() if "launches pooled" in ln]
    assert [r[0].lstrip("| ") for r in rows] == ["overhead (6 launches pooled)"] * 2  # the launches are not listed one by one here
    assert "within launch, optimistic" in (tables / "overhead_paired.md").read_text()
    head = (tables / "overhead_across_launch.md").read_text()
    assert "HEADLINE" in head and "| overhead | ab | sign | 6 | 0 | +0.42 | 0.37 | -0.13 | +0.85 | [+0.03, +0.81] |" in head
    f = {r["key"]: r["formatted"] for r in csv.DictReader(open(tmp_path / "out" / "numbers.csv", newline=""))}
    across = "overhead_paired.sign.across_launch."
    assert [f[across + k] for k in ("n_launches", "hl_mean_us", "hl_sd_us", "hl_min_us", "hl_max_us", "hl_t95_lo_us",
                                    "hl_t95_hi_us")] == ["6", PLUS + "0.422", "0.37", MINUS + "0.13", PLUS + "0.85",
                                                         PLUS + "0.028", PLUS + "0.815"]
    assert across + "tost_p" in f and f[across + "tost_margin"] == r"1.0\%"
    assert (f["overhead_paired.L01.sign.hl_us"], f["overhead_paired.L06.sign.hl_us"]) == (PLUS + "0.64", MINUS + "0.13")
    assert f["overhead_paired.sign.n_pairs"] == "24"  # the pooled result has the keys a single file would have


def test_launch_with_no_pairs_left_after_warmup_is_an_error_that_names_the_file(tmp_path):
    run_dir = launch_run(tmp_path / "run")
    (run_dir / "overhead" / "overhead_paired_L03.csv").write_text(synth.paired_launch(3, 60, pairs=10))  # all of it is warm-up
    with pytest.raises(ValueError, match=r"overhead/overhead_paired_L03\.csv: op sign: no pairs left after dropping seq < 10"):
        make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert not (tmp_path / "out").exists()  # not skipped silently: nothing is written


def test_launch_set_gives_no_verdict_below_five_launches_and_counts_invalid_ones(tmp_path):
    run_dir = launch_run(tmp_path / "run")
    bad_tail = ("signature_mismatches=1", "failed_calls=0", *synth.CRYPTO_TAIL)
    for i in (5, 6):  # two launches whose self-check failed: left out, and counted
        text = synth.paired_launch(i, 500).replace("# signature_mismatches=0", "# signature_mismatches=1")
        (run_dir / "overhead" / f"overhead_paired_L{i:02d}.csv").write_text(text)
    assert bad_tail  # (the same trailer shape as the valid launches, one counter changed)
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    (t,) = s["results"]["overhead_launch_sets"]
    assert (t["n_launches"], t["n_invalid_launches"], len(s["invalid_runs"])) == (4, 2, 2)
    sign = t["across_launch"][0]
    assert sign["tost"] is None and sign["verdict"] == "no verdict: 4 launch(es), fewer than 5"
    numbers = (tmp_path / "out" / "numbers.csv").read_text()
    assert "overhead_paired.sign.across_launch.hl_mean_us" in numbers and "across_launch.tost_p" not in numbers
    assert "overhead_paired.sign.across_launch.n_invalid_launches,2," in numbers
    assert "no verdict: 4 launch(es), fewer than 5" in (tmp_path / "out" / "tables" / "overhead_across_launch.md").read_text()


def test_noise_floor_launch_set_has_its_own_table_and_no_verdict(tmp_path):
    run_dir = launch_run(tmp_path / "run")
    launch_run(run_dir, [10, -20, 30, 0, -10, 5], mode="aa", name="overhead_paired_aa_L{:02d}.csv")
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    ab, aa = s["results"]["overhead_launch_sets"]
    assert (ab["mode"], aa["mode"], aa["margin"], aa["n_launches"]) == ("ab", "aa", None, 6)
    assert aa["across_launch"][0]["verdict"] == "noise floor: not judged against the margin" and aa["across_launch"][0]["tost"] is None
    assert aa["across_launch"][0]["hl_us"]["mean"] == pytest.approx(0.0025)
    floor = (tmp_path / "out" / "tables" / "overhead_noise_floor.md").read_text()
    assert "overhead (6 launches pooled)" in floor and "overhead (6 launches pooled)" in (tmp_path / "out" / "tables" / "overhead_paired.md").read_text()
    keys = {r["key"] for r in csv.DictReader(open(tmp_path / "out" / "numbers.csv", newline=""))}
    assert {"overhead_paired.sign.across_launch.tost_p", "overhead_paired.aa.sign.across_launch.hl_mean_us",
            "overhead_paired.aa-L03.sign.hl_us", "overhead_paired.L03.sign.hl_us", "overhead_paired.aa.sign.hl_us"} <= keys
    assert not [k for k in keys if ".aa" in k and "tost" in k]


def test_noise_floor_and_comparison_in_two_run_directories(tmp_path):
    """The campaign measures the A/A block first, the margin is written, then the A/B block: two run directories.
    A directory with A/A files only needs no margin; the A/B directory carries the margin and its provenance."""
    floor = tmp_path / "e2_aa"
    (floor / "overhead").mkdir(parents=True)
    for i, d in enumerate([10, -20, 30, 0, -10, 5], 1):
        (floor / "overhead" / f"overhead_paired_aa_L{i:02d}.csv").write_text(synth.paired_launch(i, d, "aa"))
    s = make_tables.run(floor, tmp_path / "out_aa", **PARAMS)  # no equivalence_margin.txt there
    (aa,) = s["results"]["overhead_launch_sets"]
    assert (aa["mode"], aa["margin"], aa["n_launches"], s["equivalence_margin"]) == ("aa", None, 6, None)
    assert "overhead_noise_floor" in s["tables"] and "overhead_paired" not in s["tables"]
    assert "noise floor: not judged against the margin" in (tmp_path / "out_aa" / "tables" / "overhead_across_launch.md").read_text()
    compare = launch_run(tmp_path / "e2_ab")
    (compare / "equivalence_margin.txt").write_text("# derived from the A/A block E2aa_s1_iris_20261123T010203Z (noise floor 0.2%)\n0.01\n")
    s = make_tables.run(compare, tmp_path / "out_ab", **PARAMS)
    assert s["equivalence_margin"] == {
        "file": "equivalence_margin.txt", "value": 0.01, "sha256": hashlib.sha256((compare / "equivalence_margin.txt").read_bytes()).hexdigest(),
        "comments": ["derived from the A/A block E2aa_s1_iris_20261123T010203Z (noise floor 0.2%)"]}
    assert "E2aa_s1_iris_20261123T010203Z" in (tmp_path / "out_ab" / "tables" / "overhead_across_launch.md").read_text()
    # one A/B file among the A/A files and the margin is required again
    (floor / "overhead" / "overhead_paired_L07.csv").write_text(synth.paired_launch(7, 100))
    with pytest.raises(FileNotFoundError, match="equivalence_margin.txt is missing"):
        make_tables.run(floor, tmp_path / "out_x", **PARAMS)


def test_launch_number_from_the_file_name_and_set_consistency(tmp_path):
    run_dir = launch_run(tmp_path / "run", name="overhead_paired_launch{}.csv", launch_line=False)  # as in the probe directory
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert [f["launch"] for f in s["results"]["overhead_paired"]] == [1, 2, 3, 4, 5, 6]
    assert s["results"]["overhead_launch_sets"][0]["n_launches"] == 6
    again = synth.paired_launch(3, 100)  # '# launch=3' in a file named L07: the header wins, and 3 is now there twice
    (run_dir / "overhead" / "overhead_paired_L07.csv").write_text(again)
    with pytest.raises(ValueError, match="launch number 3 appears in more than one"):
        make_tables.run(run_dir, tmp_path / "out2", **PARAMS)
    (run_dir / "overhead" / "overhead_paired_L07.csv").write_text(
        synth.paired_launch(7, 100).replace("commit=eed269f3cef4d4f67ab8afdf84f33f165f164624", "commit=0000000"))
    with pytest.raises(ValueError, match="launches of one set must share 'commit'"):
        make_tables.run(run_dir, tmp_path / "out3", **PARAMS)
    (run_dir / "overhead" / "overhead_paired_L07.csv").write_text(synth.paired_launch(7, 100).replace("# launch=7", "# launch=x"))
    with pytest.raises(ValueError, match="launch='x' is not a non-negative integer"):
        make_tables.run(run_dir, tmp_path / "out4", **PARAMS)


def test_launch_members_are_keyed_by_launch_number_whatever_the_file_is_called(tmp_path):
    # the harness may put '# launch=' into every file it writes, also one that is simply called overhead_paired.csv
    run_dir = tmp_path / "run"
    for i, d in enumerate(LAUNCH_NS[:2], 1):
        (run_dir / f"launch{i}").mkdir(parents=True)
        (run_dir / f"launch{i}" / "overhead_paired.csv").write_text(synth.paired_launch(i, d))
    (run_dir / "equivalence_margin.txt").write_text("0.01\n")
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    keys = {r["key"] for r in csv.DictReader(open(tmp_path / "out" / "numbers.csv", newline=""))}
    # each directory is a set of one launch: the member has the launch number, the set has the plain keys
    assert {"overhead_paired.launch1-L01.sign.hl_us", "overhead_paired.launch1.sign.hl_us",
            "overhead_paired.launch1.sign.across_launch.n_launches", "overhead_paired.launch2-L02.sign.hl_us"} <= keys
    assert [t["n_launches"] for t in s["results"]["overhead_launch_sets"]] == [1, 1]
    # the probe directory's file names give the same member keys as L01...: the number decides, not the name
    probe = launch_run(tmp_path / "probe", name="overhead_paired_launch{}.csv", launch_line=False)
    make_tables.run(probe, tmp_path / "out2", **PARAMS)
    keys = {r["key"] for r in csv.DictReader(open(tmp_path / "out2" / "numbers.csv", newline=""))}
    assert "overhead_paired.L03.sign.hl_us" in keys and not [k for k in keys if "launch3" in k]


def test_file_without_a_launch_number_beside_a_launch_set_is_refused(tmp_path):
    run_dir = launch_run(tmp_path / "run")
    (run_dir / "overhead" / "overhead_paired.csv").write_text(synth.overhead_paired())  # no launch number, same directory
    with pytest.raises(ValueError, match=r"overhead/overhead_paired\.csv: this file has no launch number but sits beside the "
                                         r"launches of a set"):
        make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert not (tmp_path / "out").exists()
    (run_dir / "overhead" / "overhead_paired.csv").rename(run_dir / "overhead" / "overhead_paired_single.csv")
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)  # a label of its own resolves it
    assert len(s["results"]["overhead_paired"]) == 7 and s["results"]["overhead_launch_sets"][0]["n_launches"] == 6
    (run_dir / "overhead" / "overhead_paired_aa.csv").write_text(synth.overhead_paired(mode="aa"))  # another mode: no clash
    assert len(make_tables.run(run_dir, tmp_path / "out", **PARAMS)["results"]["overhead_paired"]) == 8


def test_a_single_paired_file_is_one_launch_without_a_headline(done):
    _, out, summary = done
    assert summary["results"]["overhead_launch_sets"] == [] and "overhead_across_launch" not in summary["tables"]
    assert summary["results"]["overhead_paired"][0]["launch"] is None
    assert "within launch, optimistic" in (out / "tables" / "overhead_paired.md").read_text()
    assert "across_launch" not in (out / "numbers.csv").read_text()


def test_cyclictest_table_and_invalid_file(done, tmp_path):
    _, out, summary = done
    fifo, other = summary["results"]["cyclictest"]
    assert (fifo["source"], fifo["policy"], fifo["load"], fifo["samples"], fifo["max_us"], fifo["p99.9_us"]) == \
        ("cyclictest/cyclictest_fifo_cpu3.txt", "fifo", "cpu3", 1000, 40, 10)
    assert (other["policy"], other["min_us"], other["avg_us"], other["max_us"], other["p99_us"]) == ("other", 12, 18, 300, 55)
    assert "counts" not in fifo and all(not isinstance(v, list) or len(v) < 10 for v in fifo.values())  # no histogram in summary.json
    rows = [ln for ln in (out / "tables" / "cyclictest.md").read_text().splitlines() if ".txt" in ln]
    assert rows[0] == "| cyclictest/cyclictest_fifo_cpu3.txt | fifo | cpu3 | 3 | 1 | 1000 | 3 | 4 | 40 | 6 | 10 | 40 | 0 | 0 | 0 |"
    assert rows[1].endswith("| 1000 | 12 | 18 | 300 | 55 | 300 | 300 | 0 | 10 | 0 |")  # ten wake-ups later than 100 us
    # a run directory may hold nothing but cyclictest files; one cut short is reported, not analysed
    only = tmp_path / "run"
    (only / "cyclictest").mkdir(parents=True)
    (only / "cyclictest" / "cyclictest_fifo_cpu3.txt").write_text(synth.cyclictest("fifo", load="signing"))
    (only / "cyclictest" / "cyclictest_other_cpu3.txt").write_text(synth.cyclictest("other", complete=False))
    s = make_tables.run(only, tmp_path / "out", **PARAMS)
    assert s["tables"] == ["validity", "cyclictest"] and [c["load"] for c in s["results"]["cyclictest"]] == ["signing"]
    assert [(f["source"], f["experiment"]) for f in s["invalid_runs"]] == [("cyclictest/cyclictest_other_cpu3.txt", "cyclictest")]
    assert "cyclictest.fifo-signing.max_us" in (tmp_path / "out" / "numbers.csv").read_text()


def test_cyclictest_percentile_among_the_overflows_reads_above_the_last_bucket(tmp_path):
    run_dir = tmp_path / "run"
    (run_dir / "cyclictest").mkdir(parents=True)
    (run_dir / "cyclictest" / "cyclictest_fifo_cpu3.txt").write_text(synth.cyclictest("fifo", overflows=2, max_line=73))
    make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    row = next(ln for ln in (tmp_path / "out" / "tables" / "cyclictest.md").read_text().splitlines() if ".txt" in ln)
    # 50 buckets, 0..49; two wake-ups beyond them, which cannot be placed against 100 us or 1 ms
    assert row.endswith("| 1002 | 3 | 4 | 73 | 6 | > 49 | > 49 | 2 | – | – |")
    assert r"\textgreater{} 49" in (tmp_path / "out" / "tables" / "cyclictest.tex").read_text()
    numbers = (tmp_path / "out" / "numbers.csv").read_text()
    assert "cyclictest.fifo-cpu3.p99_us," in numbers and "cyclictest.fifo-cpu3.max_us," in numbers
    assert "p99_9" not in numbers and "p99_99" not in numbers  # a macro is a number; "above 49" is not one


@pytest.mark.parametrize("marker,banner,wrapper", [("DRY_RUN", "DRY RUN: not a result", r"\notaresult{"),
                                                   ("PILOT", "PILOT: not a result", r"\notaresult[PILOT]{"),
                                                   ("EXCLUDED", "EXCLUDED RUN: not a result", r"\notaresult[EXCL]{")])
def test_marked_directory_is_not_a_result_anywhere(tmp_path, marker, banner, wrapper):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / marker).write_text("not a result\n")
    (run_dir / "equivalence_margin.txt").write_text("# DRY RUN placeholder, NOT the pre-registered margin.\n0.01\n")  # fine here
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert s["not_a_result"] == marker
    for name in s["tables"]:  # the banner is the first thing in every table, in both formats
        md = (tmp_path / "out" / "tables" / f"{name}.md").read_text().splitlines()
        tex = [ln for ln in (tmp_path / "out" / "tables" / f"{name}.tex").read_text().splitlines() if not ln.startswith("%")]
        assert md[0] == f"**{banner}**"
        assert tex[1] == r"\toprule" and tex[2].startswith(r"\multicolumn{") and tex[2].endswith(rf"{{l}}{{\textbf{{{banner}}}}} \\")
    text = (tmp_path / "out" / "numbers.tex").read_text()
    lines = [ln for ln in text.splitlines() if ln.startswith(r"\expandafter")]
    assert len(lines) == s["numbers"]["keys"] and all(r"\endcsname{" + wrapper in ln for ln in lines)
    assert not any(r"\def\csname measraw@" in ln for ln in lines)  # no plain value is defined: nothing can print unmarked
    assert text.count(r"\DeclareRobustCommand{\notaresult}") == 1 and f"% {marker} directory: NOT A RESULT" in text
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        rows = list(csv.DictReader(f))
    assert all(r["formatted"].startswith(wrapper) for r in rows) and rows[0]["value"] != ""  # the audit table keeps the numbers


def test_marker_above_or_below_the_analysed_directory_marks_the_output(tmp_path):
    session = tmp_path / "runs" / "session1"
    synth.make_run(session / "iris")
    (session / "iris" / "DRY_RUN").write_text("dry\n")
    (session / "equivalence_margin.txt").write_text("0.01\n")  # the margin belongs to the directory that is analysed
    # analysing the collection that holds a dry run, or only a part of the dry run, is not a result either
    for run_dir in (session, session / "iris" / "attack"):
        s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
        assert s["not_a_result"] == "DRY_RUN" and r"\notaresult{" in (tmp_path / "out" / "numbers.tex").read_text()
    assert make_tables.run(session, tmp_path / "out", **PARAMS)["not_a_result_marker"] == "iris/DRY_RUN"
    assert make_tables.run(session / "iris" / "attack", tmp_path / "out", **PARAMS)["not_a_result_marker"] == "../DRY_RUN"


def test_figures_of_a_marked_run_carry_the_banner(tmp_path):
    pytest.importorskip("matplotlib")
    if shutil.which("pdftotext") is None:
        pytest.skip("pdftotext is needed to read the figure text")
    run_dir = synth.make_run(tmp_path / "run")
    make_tables.run(run_dir, tmp_path / "plain", **PARAMS)
    (run_dir / "PILOT").write_text("pilot\n")
    s = make_tables.run(run_dir, tmp_path / "marked", **PARAMS)

    def text(out, name):
        return subprocess.run(["pdftotext", str(out / "figures" / name), "-"], capture_output=True, text=True).stdout

    assert len(s["figures"]["written"]) == 6
    for name in s["figures"]["written"]:
        assert "PILOT: not a result" in text(tmp_path / "marked", name) and "not a result" not in text(tmp_path / "plain", name)


@pytest.mark.skipif(shutil.which("pdflatex") is None, reason="pdflatex is not installed")
@pytest.mark.parametrize("marker", [None, "DRY_RUN"])
def test_every_table_compiles_in_latex(tmp_path, marker):
    """The .tex tables are booktabs tabulars; run every one of them, with and without the banner row,
    and with every kind of row the toolkit writes (an invalid file, a launch set, a noise floor)."""
    run_dir = launch_run(synth.make_run(tmp_path / "run"))
    launch_run(run_dir, [10, -20, 30, 0, -10, 5], mode="aa", name="overhead_paired_aa_L{:02d}.csv")
    (run_dir / "overhead" / "overhead_paired.csv").rename(run_dir / "overhead" / "overhead_paired_single.csv")
    (run_dir / "overhead" / "overhead_paired_L07.csv").write_text(  # an invalid launch: its reason goes into the validity table
        synth.paired_launch(7, 100).replace("# freq_khz_end=1500000", "# freq_khz_end=600000"))
    (run_dir / "periodic_parts").mkdir()  # a cell of two partitions: the combined table
    for i in (0, 1):
        (run_dir / "periodic_parts" / f"periodic_tx_p{i}.csv").write_text(synth.periodic_tx_two_streams(partition=i))
    for rate in (100, 200):  # transmitter files that give the retransmission count: the sensitivity table of the ladder
        (run_dir / "throughput_1core" / f"throughput_iris_{rate}.csv").write_text(
            synth.throughput("iris", rate, (*synth.TPUT_META, "tcp_total_retrans_in_window=0")))
    if marker:
        (run_dir / marker).write_text("x\n")
    s = make_tables.run(run_dir, tmp_path / "out", figures=False, **PARAMS)
    assert len(s["tables"]) == 31 and len(s["invalid_runs"]) == 1  # every table the toolkit can write but the legacy one
    assert "throughput_no_retrans" in s["tables"]
    doc = ["\\documentclass{article}", "\\usepackage{booktabs}",
           "\\usepackage[paperwidth=250cm,paperheight=100cm,margin=1cm]{geometry}", "\\begin{document}\\tiny"]
    doc += [f"\\par\\medskip {name.replace('_', ' ')}\\par\\input{{tables/{name}.tex}}" for name in s["tables"]]
    (tmp_path / "out" / "doc.tex").write_text("\n".join(doc + ["\\end{document}"]) + "\n")
    r = subprocess.run(["pdflatex", "-interaction=nonstopmode", "-halt-on-error", "doc.tex"], cwd=tmp_path / "out",
                       capture_output=True, text=True, timeout=180)
    log = (tmp_path / "out" / "doc.log").read_text(errors="replace")
    assert r.returncode == 0 and "Missing character" not in log, log[-3000:]
    if shutil.which("pdftotext"):
        text = subprocess.run(["pdftotext", "-layout", "doc.pdf", "-"], cwd=tmp_path / "out", capture_output=True, text=True).stdout
        assert text.count("DRY RUN: not a result") == (len(s["tables"]) if marker else 0)
        assert "1500000 -> 600000 kHz" in text.replace("−", "-") or "1500000 –> 600000" in text  # '>' survives the font encoding


def test_placeholder_margin_without_a_marker_stops_the_run(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "equivalence_margin.txt").write_text("# DRY RUN placeholder, NOT the pre-registered margin.\n0.01\n")
    with pytest.raises(ValueError, match="calls itself a placeholder"):
        make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert not (tmp_path / "out").exists()


def test_no_recognised_files_is_an_error(tmp_path):
    (tmp_path / "x.csv").write_text("a,b\n1,2\n")
    with pytest.raises(ValueError, match="no recognised CSV"):
        make_tables.run(tmp_path, tmp_path / "out")


def test_default_output_never_lands_inside_the_run_directory(tmp_path, monkeypatch, capsys):
    run_dir = synth.make_run(tmp_path / "run")
    monkeypatch.chdir(run_dir.parent)  # default ./analysis_out/run is outside the run directory
    make_tables.main([str(run_dir), "--warmup", "10", "--block-len", "5", "--n-boot", "20", "--sim-draws", "0"])
    assert (run_dir.parent / "analysis_out" / "run" / "summary.json").is_file()
    assert "26 tables" in capsys.readouterr().out
    monkeypatch.chdir(run_dir)  # here the default would be <run_dir>/analysis_out/run
    with pytest.raises(SystemExit) as e:
        make_tables.main(["."])
    assert e.value.code == 2 and not (run_dir / "analysis_out").exists()


def test_runs_by_path_in_isolated_mode(tmp_path):
    """python3 -I keeps the current and script directories off sys.path (required for untrusted data dirs)."""
    run_dir = synth.make_run(tmp_path / "run")
    cmd = [sys.executable, "-I", str(Path(make_tables.__file__).resolve()), str(run_dir), "--out", str(tmp_path / "out"),
           "--warmup", "10", "--block-len", "5", "--n-boot", "20", "--sim-draws", "1", "--sim-jobs", "200"]
    r = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert set(strict_json(tmp_path / "out" / "summary.json")["tables"]) == TABLES


def test_the_archived_phase_file_gives_a_labelled_secondary_analysis(tmp_path):
    """The legacy phase_compare.csv (two phases per operation, one after the other): lag-1 autocorrelation per phase and
    the moving-block interval of the relative median difference beside the figures it had, every definition saying that
    the phases were not paired or interleaved and that the margins were chosen after the data."""
    rows = [(f"{phase}_{op}", i, 9_000_000 if i < 10 else base + shift + 1_000 * ((i * 7) % 10))
            for op, base in (("Sign", 1_500_000), ("Verify", 430_000))
            for phase, shift in (("A_Standalone", 0), ("B_CsmIntegrated", 3_000)) for i in range(20)]
    (tmp_path / "run" / "perf").mkdir(parents=True)
    (tmp_path / "run" / "perf" / "phase_compare.csv").write_text(synth.text("phase,seq,ns_delta", rows))
    s = make_tables.run(tmp_path / "run", tmp_path / "out", key_prefix="archive.e2", **PARAMS)
    (f,) = s["results"]["overhead_unpaired"]
    sign = f["ops"][0]
    assert (sign["op"], sign["n_standalone"], sign["n_csm"]) == ("sign", 10, 10)
    assert (sign["bootstrap"]["block_len"], sign["bootstrap"]["n_boot"]) == (5, 50)
    with open(tmp_path / "out" / "numbers.csv", newline="") as fh:
        keys = {r["key"]: r for r in csv.DictReader(fh)}
    base = "archive.e2.overhead_unpaired.perf.sign."
    # the ten values after the warm-up are 1,500 .. 1,509 us in the order 0, 7, 4, 1, 8, 5, 2, 9, 6, 3 (+3 us in the
    # second phase): the same series in both phases, so the same lag-1 coefficient
    x = np.array([(i * 7) % 10 for i in range(10, 20)], dtype=float) - 4.5
    lag1 = float(x[:-1] @ x[1:] / (x @ x))
    assert float(keys[base + "lag1_standalone"]["value"]) == pytest.approx(lag1) == float(keys[base + "lag1_csm"]["value"])
    lo, hi = (float(keys[base + f"median_rel_diff_bb90_{side}"]["value"]) for side in ("lo", "hi"))
    diff = float(keys[base + "median_rel_diff"]["value"])
    assert diff == pytest.approx(3 / 1504.5) and lo <= diff <= hi < 0.01
    sequential, post_hoc = "one after the other", "chosen after the data"
    for name in ("median_rel_diff", "mann_whitney_p", "hl_us", "cliffs_delta", "tost_m1pct_p", "tost_m2pct_gm_ratio_diff",
                 "median_rel_diff_bb90_lo", "lag1_csm"):
        assert sequential in keys[base + name]["how"] and "not paired, not interleaved" in keys[base + name]["how"], name
    for name in ("tost_m1pct_p", "tost_m2pct_p", "tost_m2pct_gm_ratio_diff_ci90_hi"):
        assert post_hoc in keys[base + name]["how"], name
    assert "within a phase" in keys[base + "lag1_standalone"]["how"] and "within a phase" in keys[base + "median_rel_diff_bb90_hi"]["how"]
    assert "blocks of 5" in keys[base + "median_rel_diff_bb90_lo"]["how"] and "50 resamples" in keys[base + "median_rel_diff_bb90_lo"]["how"]
    table = (tmp_path / "out" / "tables" / "overhead_unpaired.md").read_text()
    assert "| lag-1 standalone | lag-1 csm | block-bootstrap 90% of the rel. median diff |" in table and sequential in table
