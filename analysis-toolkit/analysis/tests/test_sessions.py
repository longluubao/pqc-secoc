"""Sessions side by side: one row per session and statistic, ranges over sessions, never a pooled estimate."""
import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from analysis import make_tables, sessions, stats
from analysis.tests import synth

PARAMS = dict(warmup=10, block_len=5, n_boot=50, sim_draws=0, figures=False)


def sign_csv(shift_ms, verify=False):
    """mldsa_sign: ten warm-up rows, then the 20 values 1 + shift, 2 + shift, ..., 20 + shift ms."""
    rows = [("mldsa_sign", s, 9_000 * synth.MS) for s in range(10)]
    rows += [("mldsa_sign", 10 + i, (i + 1 + shift_ms) * synth.MS) for i in range(20)]
    rows += [("mldsa_verify", s, 400_000 + s) for s in range(40)] if verify else []
    return synth.text("op,seq,ns", rows)


def analysed(root, name, prefix, content, marker=None, **params):
    run = root / f"run_{name}"
    (run / "crypto").mkdir(parents=True)
    (run / "crypto" / "crypto_ops.csv").write_text(content)
    if marker:
        (run / marker).write_text("x\n")
    make_tables.run(run, root / name, key_prefix=prefix, **{**PARAMS, **params})
    return root / name


@pytest.fixture(scope="module")
def three(tmp_path_factory):
    """Sessions 1, 2, 3: signing times shifted by 1, 2, 3 ms, so the median is 11.5, 12.5, 13.5 ms and 1, 2, 3
    values lie above 20 ms."""
    root = tmp_path_factory.mktemp("sessions")
    return root, [analysed(root, f"s{k}", f"e1.s{k}.iris", sign_csv(k)) for k in (1, 2, 3)]


def numbers(out):
    with open(out / "numbers.csv", newline="") as f:
        return {r["key"]: r for r in csv.DictReader(f)}


def ends_alike(out, base):
    """The statistics whose two range cells in sessions.md read alike although the two values differ."""
    cell = {}
    for line in (out / "sessions.md").read_text().splitlines():
        c = [x.strip() for x in line.strip("|").split("|")]
        if len(c) == 6 and c[2] in ("min over sessions", "max over sessions"):
            cell[c[0], c[2][:3]] = c[3]
    rows = numbers(out)
    assert cell and len(cell) == sum(k.endswith(("min_over_sessions", "max_over_sessions")) for k in rows)
    # the keys: two ends print alike only when the range key prints one value, and that key never reads 'a--a'
    for k in (k for k in rows if k.endswith(".range_over_sessions")):
        low, high = (rows[k.replace("range_over", f"{end}_over")]["formatted"] for end in ("min", "max"))
        assert rows[k]["formatted"] == (low if low == high else f"{low}--{high}"), k
    return [stat for (stat, end) in cell if end == "min" and cell[stat, "min"] == cell[stat, "max"]
            and rows[f"{base}.{stat}.min_over_sessions"]["value"] != rows[f"{base}.{stat}.max_over_sessions"]["value"]]


def test_range_over_sessions_of_the_quoted_statistics(three, tmp_path, capsys):
    _, dirs = three
    sessions.main(["--out", str(tmp_path / "all"), *map(str, dirs)])
    assert "3 sessions" in capsys.readouterr().out
    rows = numbers(tmp_path / "all")
    base = "e1.all.iris.crypto_ops.mldsa_sign."  # the session part of the prefix becomes 'all'

    def both(stat, field="value"):
        return rows[f"{base}{stat}.min_over_sessions"][field], rows[f"{base}{stat}.max_over_sessions"][field]

    # a range is its own statistic: its decimals show one significant digit of the distance between its ends and
    # nothing else. 11.5 and 13.5 ms are 2 ms apart: whole milliseconds (a tie goes to the even digit)
    assert both("p50_ms") == ("11.5", "13.5") and both("p50_ms", "formatted") == ("12", "14")
    assert both("mean_us") == ("11500.0", "13500.0") and both("mean_us", "formatted") == ("11{,}500", "13{,}500")
    assert both("exceed_20ms.k") == ("1", "3")
    assert both("exceed_5ms.p") == ("0.8", "0.9") and both("exceed_10ms.p") == ("0.55", "0.65")
    # not the decimals of the sessions' own values: a session prints 80.0% [56.3%, 94.3%], the range 80% to 90%
    assert numbers(dirs[0])["e1.s1.iris.crypto_ops.mldsa_sign.exceed_5ms.p"]["formatted"] == r"80.0\%"
    assert both("exceed_5ms.p", "formatted") == (r"80\%", r"90\%") and both("p50_ms", "n") == ("3", "3")  # n: the sessions
    assert rows[base + "p50_ms.min_over_sessions"]["how"].startswith("smallest of the 3 sessions' values (e1.s1.iris, e1.s2.iris, "
                                                                    "e1.s3.iris; no pooling) of: p50 of post-warm-up time")
    # nothing but minima, maxima and the two printed as one range: no pooled estimate, no mean over sessions
    assert all(k.endswith((".min_over_sessions", ".max_over_sessions", ".range_over_sessions")) for k in rows)
    # the third key of a statistic prints the range: both ends as the end keys print them, with an en dash
    r = rows[base + "p50_ms.range_over_sessions"]
    assert (r["formatted"], r["value"], r["unit"], r["n"]) == ("12--14", "11.5--13.5", "text", "3")  # value: the plain ends
    assert rows[base + "mean_us.range_over_sessions"]["formatted"] == "11{,}500--13{,}500"
    assert rows[base + "exceed_5ms.p.range_over_sessions"]["formatted"] == r"80\%--90\%"
    assert rows[base + "exceed_20ms.k.range_over_sessions"]["formatted"] == "1--3"
    assert r["how"].startswith("smallest to largest of the 3 sessions' values (e1.s1.iris, e1.s2.iris, e1.s3.iris; no pooling), "
                               "printed as one range, of: p50 of post-warm-up time")
    tex = (tmp_path / "all" / "numbers.tex").read_text()
    assert r"\expandafter\def\csname meas@" + base + r"p50_ms.range_over_sessions\endcsname{12--14}" in tex
    assert r"\expandafter\def\csname measraw@" + base + r"p50_ms.range_over_sessions\endcsname{11.5--13.5}" in tex
    # only the statistics the manuscript quotes
    quoted = {k[len(base):].rsplit(".", 1)[0] for k in rows}
    assert quoted == {f"{s}_{u}" for s in ("p50", "mean", "p99", "p99_9", "p99_99", "max") for u in ("us", "ms")} | \
        {"exceed_5ms.p", "exceed_10ms.p", "exceed_20ms.k"}
    assert both("max_us") == ("21000.0", "23000.0")  # the largest maximum over the sessions is .max_us.max_over_sessions


def test_range_ends_of_close_sessions_are_told_apart(three, tmp_path):
    """Three sessions of 999,000 calls with 26,480, 26,498 and 26,510 above 5 ms. Each prints 2.65% with its interval;
    the range, 2.6507% to 2.6537%, is printed with the three decimals that tell its ends apart, not as 2.7% to 2.7%.
    Their medians have narrow intervals and print with one decimal; so does the range of the median. In the third
    session nothing is above 10 ms: that end of the range is 0%."""
    _, dirs = three
    close = []
    for d, k, k10, median in zip(dirs, (26480, 26498, 26510), (434, 451, 0), (1454.333, 1455.982, 1455.1)):
        new = tmp_path / d.name
        shutil.copytree(d, new)
        summary = json.loads((new / "summary.json").read_text())
        (op,) = summary["results"]["crypto_ops"][0]["ops"]
        for threshold, count in ((5, k), (10, k10)):
            e = next(e for e in op["exceedance"] if e["threshold_ms"] == threshold)
            e.update(k=count, n=999_000, p=count / 999_000, cp95=list(stats.clopper_pearson_interval(count, 999_000)),
                     wilson95=list(stats.wilson_interval(count, 999_000)))
        op["time_us"]["p50"], op["bootstrap"]["p50_ci95_us"] = median, [median - 0.19, median + 0.2]
        (new / "summary.json").write_text(json.dumps(summary))
        close.append(new)
    sessions.main(["--out", str(tmp_path / "all"), *map(str, close)])
    rows = numbers(tmp_path / "all")
    key = "e1.all.iris.crypto_ops.mldsa_sign.exceed_5ms.p."
    assert (rows[key + "min_over_sessions"]["formatted"], rows[key + "max_over_sessions"]["formatted"]) == (r"2.651\%", r"2.654\%")
    key = "e1.all.iris.crypto_ops.mldsa_sign.p50_us."
    assert (rows[key + "min_over_sessions"]["formatted"], rows[key + "max_over_sessions"]["formatted"]) == ("1{,}454", "1{,}456")
    key = "e1.all.iris.crypto_ops.mldsa_sign.exceed_10ms.p."  # 0 of 999,000 in one session, 451 (0.0451%) in another
    assert (rows[key + "min_over_sessions"]["formatted"], rows[key + "max_over_sessions"]["formatted"]) == (r"0\%", r"0.05\%")
    # two sessions with the same values: the range prints the common value twice, with the sessions' decimals
    twin = tmp_path / "twin"
    shutil.copytree(close[1], twin)
    summary = json.loads((twin / "summary.json").read_text())
    summary["key_prefix"] = "e1.s9.iris"
    (twin / "summary.json").write_text(json.dumps(summary))
    sessions.main(["--out", str(tmp_path / "same"), str(close[1]), str(twin)])
    rows = numbers(tmp_path / "same")
    for stat, want in (("exceed_5ms.p", r"2.65\%"), ("p50_us", "1{,}456.0"), ("p50_ms", "1.4560"), ("exceed_10ms.p", r"0.045\%")):
        key = f"e1.all.iris.crypto_ops.mldsa_sign.{stat}."
        assert (rows[key + "min_over_sessions"]["formatted"], rows[key + "max_over_sessions"]["formatted"]) == (want, want)
        assert rows[key + "range_over_sessions"]["formatted"] == want  # exactly equal ends: the value once, not 'a--a'
    assert rows["e1.all.iris.crypto_ops.mldsa_sign.p50_us.range_over_sessions"]["how"].startswith(
        "the one value all 2 sessions have (e1.s2.iris, e1.s9.iris; no pooling) of: p50")
    # one session's median has an interval a tenth of a nanosecond wide and prints with four decimals; the other
    # session's median is 1.7 us away. The session's decimals do not carry into the range: whole microseconds
    narrow = tmp_path / "narrow"
    shutil.copytree(close[1], narrow)
    summary = json.loads((narrow / "summary.json").read_text())
    summary["key_prefix"] = "e1.s8.iris"
    (op,) = summary["results"]["crypto_ops"][0]["ops"]
    op["time_us"]["p50"], op["bootstrap"]["p50_ci95_us"] = 1454.3251, [1454.3250, 1454.3252]
    (narrow / "summary.json").write_text(json.dumps(summary))
    sessions.main(["--out", str(tmp_path / "capped"), str(close[1]), str(narrow)])
    rows = numbers(tmp_path / "capped")
    assert sessions.load(narrow)[2]["crypto_ops.mldsa_sign.p50_us"]["formatted"] == "1{,}454.3251"  # the session's own print
    assert rows["e1.all.iris.crypto_ops.mldsa_sign.p50_us.range_over_sessions"]["formatted"] == "1{,}454--1{,}456"
    assert rows["e1.all.iris.crypto_ops.mldsa_sign.p50_ms.range_over_sessions"]["formatted"] == "1.454--1.456"
    table = (tmp_path / "all" / "sessions.md").read_text()
    assert "| crypto_ops.mldsa_sign.exceed_5ms.p | percent | e1.s2.iris | 2.652% | 999000 | yes |" in table


@pytest.mark.parametrize("ends, unit, shown, fixed, want", [
    ((2.262947406326131, 2.263526202231888), "1", [2, 2], [None, None], 4),   # the two real tail ratios: 2.2629 to 2.2635
    ((0.01719, 0.01722), "ms", [3, 3], [None, None], 5),                       # the real HKDF means
    ((423.925, 424.537), "us", [0, 3], [None, None], 1),                       # 0.6 apart: 423.9 to 424.5, whatever a session prints
    ((424.975, 425.576), "us", [0, 0], [None, None], 1),                       # 425.0 to 425.6
    ((423.925, 425.5), "us", [5, 0], [None, None], 0),                         # 1.6 apart: whole microseconds
    ((1000.4, 25000.6), "us", [1, 1], [None, None], 0),                        # 24,000 apart: no decimal carries anything
    ((0.0026520, 0.0026571), "percent", [3, 3], [None, None], 4),              # 0.2652% and 0.2657%, counted on the percentage
    ((0.5, 0.9), "percent", [7, 1], [None, None], 0),                          # 50% and 90%
    ((1.815, 1.815), "us", [1, 1], [None, None], 1),                           # equal ends have no distance: as the sessions print
    ((1.815, 1.815), "us", [6, 6], [None, None], 6),
    ((1.815, 1.815), "us", [None, 1], [None, None], None),                     # ... which may be the general rule of the unit
    ((150.0, 420.0), "ms", [2, 2], [None, None], 0),                           # no floor from the unit's own two decimals
    ((1.5, 3.0), "ms", [2, 2], [None, None], 0),
    ((17.83, 19.29), "ms", [2, 2], [None, None], 0),                           # the real signing maxima: 18 to 19 ms
    ((11.5, 12.5), "ms", [2, 2], [None, None], 1),                             # two ties that both round to 12: one more decimal
    ((10.5, 11.5), "ms", [2, 2], [None, None], 0),                             # these round to 10 and 12
    ((0.115, 0.125), "percent", [1, 1], [None, None], 1),                      # 11.5% and 12.5% are both 12%: one more decimal
    ((0.125, 0.135), "percent", [1, 1], [None, None], 0),                      # 12.5% and 13.5% are 12% and 14%
    # the one floor: where the digit of the distance would print a non-zero end as zero, both ends get the decimals that
    # show one significant digit of the smaller non-zero end: 0.07 to 5.00 ms, 0.0004% to 0.3000%
    ((0.072, 5.0), "ms", [3, 2], [None, None], 2),
    ((0.000004, 0.003), "percent", [5, 2], [None, None], 4),
    ((0.4, 30.0), "us", [1, 1], [None, None], 1),                              # 0.4 to 30.0
    ((0.6, 30.0), "us", [1, 1], [None, None], 0),                              # 0.6 rounds to 1, not to zero: 1 to 30
    ((0.0, 0.003), "percent", [0, 2], [None, None], 1),                        # an end that is exactly zero prints 0: 0% to 0.3%
    ((0.0, 5.0), "ms", [2, 2], [None, None], 0),
    ((6.0, 7.0), "us", [0, 0], [0, 0], 0),                                     # whole microseconds of cyclictest
    ((3, 5), "count", [0, 0], [None, None], 0),
    ((1.4, 2.6), "us", [None, 1], [None, None], 0),                            # a session in scientific notation does not matter
    ((0.25, 0.75), "p", [None, None], [None, None], None),                     # a p-value has its own rule
])
def test_decimals_of_a_range(ends, unit, shown, fixed, want):
    """A range is its own statistic: its decimals show one significant digit of the distance between its two ends, and
    nothing else (no floor from the sessions' prints, none from the unit's own rule); equal ends print as the sessions
    do (the campaign rules of 2026-11-23)."""
    assert sessions.range_decimals(ends, unit, False, shown, fixed)[0] == want


def test_ends_that_differ_beyond_the_twelfth_digit_are_one_value(tmp_path, three):
    """A value is taken as exact to twelve significant digits (the distance rule). Two session values that differ only
    beyond that have no distance: they get no decimals of their own and print alike, so the range key prints the value
    once; 'a--a' would be the old defect in a new place."""
    _, dirs = three
    pair = []
    for d, mean in zip(dirs[:2], (11500.000000000002, 11500.000000000004)):
        new = tmp_path / d.name
        shutil.copytree(d, new)
        summary = json.loads((new / "summary.json").read_text())
        (op,) = summary["results"]["crypto_ops"][0]["ops"]
        op["time_us"]["mean"] = mean
        (new / "summary.json").write_text(json.dumps(summary))
        pair.append(new)
    sessions.main(["--out", str(tmp_path / "all"), *map(str, pair)])
    rows = numbers(tmp_path / "all")
    key = "e1.all.iris.crypto_ops.mldsa_sign.mean_us."
    assert rows[key + "min_over_sessions"]["value"] != rows[key + "max_over_sessions"]["value"]
    assert rows[key + "range_over_sessions"]["formatted"] == "11{,}500" == rows[key + "max_over_sessions"]["formatted"]
    assert ends_alike(tmp_path / "all", "e1.all.iris") == ["crypto_ops.mldsa_sign.mean_ms", "crypto_ops.mldsa_sign.mean_us"]


def test_a_non_zero_range_end_never_prints_as_zero():
    """The two cases of the campaign rule, as they print."""
    from analysis import make_numbers
    for ends, unit, want in (((0.072, 5.0), "ms", ["0.07", "5.00"]), ((0.000004, 0.003), "percent", [r"0.0004\%", r"0.3000\%"]),
                             ((0.0, 0.003), "percent", [r"0\%", r"0.3\%"]), ((0.6, 30.0), "us", ["1", "30"])):
        d = sessions.range_decimals(ends, unit, False, [2, 2], [None, None])[0]
        assert [make_numbers.fmt(v, unit, False, d) for v in ends] == want


def test_range_of_a_value_with_fixed_decimals_keeps_them(tmp_path):
    """The cyclictest latencies are whole microseconds and print as integers; so does their range over sessions
    (the general rule for a time below 10 us would print one decimal: 7.0)."""
    dirs = []
    for k, counts in ((1, {3: 900, 7: 99, 9: 1}), (2, {3: 900, 7: 98, 9: 2})):
        run = tmp_path / f"run{k}"
        (run / "cyclictest").mkdir(parents=True)
        (run / "cyclictest" / "cyclictest_fifo_cpu3.txt").write_text(synth.cyclictest("fifo", counts))
        make_tables.run(run, tmp_path / f"s{k}", key_prefix=f"e0.s{k}.iris", **PARAMS)
        dirs.append(tmp_path / f"s{k}")
    sessions.main(["--out", str(tmp_path / "all"), *map(str, dirs)])
    rows = numbers(tmp_path / "all")
    key = next(k for k in rows if k.endswith(".p99_us.max_over_sessions"))
    assert numbers(dirs[0])[key.replace(".all.", ".s1.").removesuffix(".max_over_sessions")]["formatted"] == "7"
    assert (rows[key]["value"], rows[key]["formatted"]) == ("7", "7")
    assert rows[key.replace("p99_us", "max_us")]["formatted"] == "9"


def test_range_of_the_tail_ratio(tmp_path, monkeypatch):
    """Two sessions whose long signing series halve per millisecond: the ratio is a quoted statistic too."""
    from analysis import crypto_ops
    monkeypatch.setattr(crypto_ops, "TAIL_MIN_N", 10_000)
    dirs = [analysed(tmp_path, f"s{k}", f"e1.s{k}.iris", synth.crypto_ops_geometric()) for k in (1, 2)]
    sessions.main(["--out", str(tmp_path / "all"), *map(str, dirs)])
    rows = numbers(tmp_path / "all")
    key = "e1.all.iris.crypto_ops.mldsa_sign.tail_ratio_per_ms."
    assert float(rows[key + "min_over_sessions"]["value"]) == pytest.approx(2) == float(rows[key + "max_over_sessions"]["value"])
    assert not [k for k in rows if "tail_ratio_lo" in k or "tail_dispersion" in k or k.endswith(".n.min_over_sessions")]
    # two sessions whose ratios differ in the fourth decimal (2.26295 and 2.26353, the first two real sessions): each
    # prints 2.26, the range tells its ends apart; a count stays whole, and equal ends print as the sessions do
    close = []
    for d, ratio in zip(dirs, (2.262947406326131, 2.263526202231888)):
        new = tmp_path / ("close_" + d.name)
        shutil.copytree(d, new)
        summary = json.loads((new / "summary.json").read_text())
        (op,) = summary["results"]["crypto_ops"][0]["ops"]
        op["tail"]["fit"]["ratio_per_ms"], op["tail"]["fit"]["ratio_ci95"] = ratio, [ratio - 0.011, ratio + 0.012]
        op["time_us"]["mean"] = 17.19 if d is dirs[0] else 17.22  # the real hkdf means: 0.01719 and 0.01722 ms
        (new / "summary.json").write_text(json.dumps(summary))
        close.append(new)
    assert numbers(dirs[0])["e1.s1.iris.crypto_ops.mldsa_sign.tail_ratio_per_ms"]["formatted"].count(".") == 1
    sessions.main(["--out", str(tmp_path / "close_all"), *map(str, close)])
    rows = numbers(tmp_path / "close_all")
    assert (rows[key + "min_over_sessions"]["formatted"], rows[key + "max_over_sessions"]["formatted"]) == ("2.2629", "2.2635")
    k20 = "e1.all.iris.crypto_ops.mldsa_sign.exceed_20ms.k."
    assert rows[k20 + "min_over_sessions"]["formatted"] == rows[k20 + "max_over_sessions"]["formatted"] and \
        "." not in rows[k20 + "max_over_sessions"]["formatted"]
    # the table beside the keys tells the same ends apart, and a session's row reads like the range end it is
    assert ends_alike(tmp_path / "close_all", "e1.all.iris") == []
    md = (tmp_path / "close_all" / "sessions.md").read_text()
    for stat, unit, low, high in (("tail_ratio_per_ms", "1", "2.2629", "2.2635"), ("mean_ms", "ms", "0.01719", "0.01722"),
                                  ("mean_us", "us", "17.19", "17.22")):
        row = f"| crypto_ops.mldsa_sign.{stat} | {unit} | "
        assert row + f"min over sessions | {low} | 2 | yes |" in md and row + f"max over sessions | {high} | 2 | yes |" in md
        assert row + f"e1.s1.iris | {low} | " in md and row + f"e1.s2.iris | {high} | " in md
    assert (rows["e1.all.iris.crypto_ops.mldsa_sign.mean_ms.min_over_sessions"]["formatted"],
            rows["e1.all.iris.crypto_ops.mldsa_sign.mean_ms.max_over_sessions"]["formatted"]) == ("0.01719", "0.01722")


def test_sessions_must_have_the_same_n_per_file_and_operation(three, tmp_path):
    """A caption states one n for all sessions: a session with another number of values stops the command."""
    root, dirs = three
    shorter = synth.text("op,seq,ns", [("mldsa_sign", s, (s + 1) * synth.MS) for s in range(29)])  # 19 values after warm-up
    odd = analysed(root, "s5", "e1.s5.iris", shorter)
    with pytest.raises(SystemExit) as e:
        sessions.main(["--out", str(tmp_path / "x"), str(dirs[0]), str(odd)])
    assert "crypto_ops.mldsa_sign.n differs between the sessions: e1.s1.iris 20, e1.s5.iris 19" in str(e.value.code)
    assert not (tmp_path / "x").exists()


def test_each_board_is_its_own_set_of_sessions(three, tmp_path):
    """The part of the prefix that varies is the session; the board stays, so every board is one command."""
    root, dirs = three
    board_b = [analysed(root, f"b{k}", f"e1.s{k}.baolong", sign_csv(k)) for k in (1, 2)]
    sessions.main(["--out", str(tmp_path / "b"), *map(str, board_b)])
    assert "e1.all.baolong.crypto_ops.mldsa_sign.p50_ms.max_over_sessions" in numbers(tmp_path / "b")
    with pytest.raises(SystemExit) as e:  # both boards at once: two parts vary
        sessions.main(["--out", str(tmp_path / "x"), str(dirs[0]), str(board_b[1])])
    assert "differ in exactly one part" in str(e.value.code)


def test_range_of_a_held_back_percentile_is_held_back(three, tmp_path):
    """p99 of 20 values has 0.2 samples above it in every session: no macro for it, and none for its range."""
    _, dirs = three
    sessions.main(["--out", str(tmp_path / "all"), *map(str, dirs)])
    tex = (tmp_path / "all" / "numbers.tex").read_text()
    assert "p50_ms.min_over_sessions" in tex and "p99_ms.min_over_sessions" not in tex
    listed = dict(ln.split("\t") for ln in (tmp_path / "all" / "suppressed_keys.txt").read_text().splitlines() if ln[:1] != "#")
    assert listed["e1.all.iris.crypto_ops.mldsa_sign.p99_ms.max_over_sessions"] == \
        "in session e1.s1.iris: p99 of 20 values: 0.2 samples lie above it, fewer than 10; the value depends on the percentile definition"
    assert "e1.all.iris.crypto_ops.mldsa_sign.p99_ms.max_over_sessions" in numbers(tmp_path / "all")  # still in the CSV


def test_sessions_table_has_one_row_per_session_and_statistic(three, tmp_path):
    _, dirs = three
    sessions.main(["--out", str(tmp_path / "all"), *map(str, dirs)])
    md = (tmp_path / "all" / "sessions.md").read_text().splitlines()
    assert "| statistic | unit | session | value | n | in numbers.tex |" in md
    for k, value in ((1, "11.50"), (2, "12.50"), (3, "13.50")):
        assert f"| crypto_ops.mldsa_sign.p50_ms | ms | e1.s{k}.iris | {value} | 20 | yes |" in md
    assert "| crypto_ops.mldsa_sign.p50_ms | ms | min over sessions | 11.50 | 3 | yes |" in md
    assert "| crypto_ops.mldsa_sign.p50_ms | ms | max over sessions | 13.50 | 3 | yes |" in md
    assert "| crypto_ops.mldsa_sign.exceed_20ms.k | count | e1.s2.iris | 2 | 20 | yes |" in md
    assert "| crypto_ops.mldsa_sign.exceed_5ms.p | percent | max over sessions | 90% | 3 | yes |" in md
    assert "| crypto_ops.mldsa_sign.p99_ms | ms | e1.s1.iris | 20.81 | 20 | no |" in md  # 1 + 1 + 0.99 x 19 ms, type 7
    assert (tmp_path / "all" / "sessions.tex").read_text().count(r"\\") > 30
    assert any("never pooled" in ln for ln in md)


def test_statistic_missing_from_a_session_gets_no_range(three, tmp_path):
    root, dirs = three
    extra = analysed(root, "s4", "e1.s4.iris", sign_csv(4, verify=True))  # only this session measured mldsa_verify
    sessions.main(["--out", str(tmp_path / "all"), *map(str, dirs), str(extra)])
    rows = numbers(tmp_path / "all")
    assert rows["e1.all.iris.crypto_ops.mldsa_sign.p50_ms.max_over_sessions"]["value"] == "14.5"
    assert not [k for k in rows if "mldsa_verify" in k]  # never a range over fewer sessions
    md = (tmp_path / "all" / "sessions.md").read_text()
    assert "| crypto_ops.mldsa_verify.p50_us | us | e1.s4.iris | 400.02 | 30 | yes |" in md  # 400.010 .. 400.039 us
    assert "| crypto_ops.mldsa_verify.p50_us | us | no range: not in e1.s1.iris, e1.s2.iris, e1.s3.iris | – | 1 | no |" in md


def test_sessions_must_be_distinct_runs_of_one_experiment(three, tmp_path):
    root, dirs = three
    cases = (([dirs[0]], "at least two"),
             ([dirs[0], dirs[0]], "same key prefix 'e1.s1.iris'"),
             ([dirs[0], analysed(root, "other_host", "e1.s2.baolong", sign_csv(2))], "differ in exactly one part"),
             ([dirs[0], analysed(root, "longer", "e1.s2.iris.x", sign_csv(2))], "differ in exactly one part"),
             ([dirs[0], analysed(root, "no_prefix", "", sign_csv(2))], "has no key prefix"),
             ([dirs[0], analysed(root, "warm", "e1.s2.iris", sign_csv(2), warmup=5)], "warmup differs"))
    for inputs, message in cases:
        with pytest.raises(SystemExit) as e:
            sessions.main(["--out", str(tmp_path / "x"), *map(str, inputs)])
        assert message in str(e.value.code)
    assert not (tmp_path / "x").exists()


def test_a_marked_session_marks_the_ranges(three, tmp_path):
    root, dirs = three
    dry = analysed(root, "dry", "e1.s9.iris", sign_csv(9), marker="DRY_RUN")
    sessions.main(["--out", str(tmp_path / "all"), str(dirs[0]), str(dry)])
    tex = (tmp_path / "all" / "numbers.tex").read_text()
    assert r"\DeclareRobustCommand{\notaresult}" in tex and r"\endcsname{\notaresult{" in tex
    assert (tmp_path / "all" / "sessions.md").read_text().startswith("**DRY RUN: not a result**")
    assert "DRY_RUN directory: the keys below are real, the values of these sessions are not results." in \
        (tmp_path / "all" / "number_keys.md").read_text()


def test_runs_by_path_in_isolated_mode(three, tmp_path):
    _, dirs = three
    cmd = [sys.executable, "-I", str(Path(sessions.__file__).resolve()), "--out", str(tmp_path / "all"), *map(str, dirs)]
    done = subprocess.run(cmd, capture_output=True, text=True, cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    keys_md = (tmp_path / "all" / "number_keys.md").read_text()
    assert "e1.all.iris.crypto_ops.mldsa_sign.p50_ms.min_over_sessions" in keys_md
    assert keys_md.startswith("# Number keys of the ranges over the sessions e1.s1.iris, ")  # not worded as one run
