"""The clocks themselves, from the probe files (E9_SPEC.md, Addendum C): segment rates between the anchors, on synthetic
exchanges whose true offset is known. Definition 7 names the known answers."""
import csv
import hashlib

import numpy as np
import pytest

from analysis import clock_rate, e2e, merge_numbers
from analysis.tests import synth
from analysis.tests.test_e2e import A0, HEAD, MS, PINNED, THETA0, US, exchanges


def drifting(ppm, start_ms=0, before=0):
    """A true offset that moves at `before` ppm until `start_ms` after A0 and at `ppm` from then on."""
    def theta(t):
        turn = A0 + start_ms * MS
        return THETA0 + (min(t, turn) - A0) * before // 1_000_000 + max(0, t - turn) * ppm // 1_000_000
    return theta


def pinned(**kw):
    """Exchanges every 100 ms whose anchors are pinned at 0, 5, 10, ... s (10 us each way there, 50 us elsewhere)."""
    return exchanges(forward=PINNED, back=PINNED, **kw)


def test_known_answer_a_constant_offset_has_rate_zero_everywhere():
    s = clock_rate.file_stats(pinned())                      # anchors at 0, 5, 10 and 15 s: three segments
    assert (s["anchors"], s["segments"], s["rate_ppm"].tolist()) == (4, 3, [0, 0, 0])
    assert (s["rate_ppm_min"], s["rate_ppm_max"], s["rate_ppm_median"], s["rate_step_ppm_max"]) == (0, 0, 0, 0)
    assert (s["offset_range_ms"], s["span_s"]) == (0, 15)


def test_known_answer_a_constant_drift_of_25_ppm():
    s = clock_rate.file_stats(pinned(theta=drifting(25)))
    for stat in ("rate_ppm_min", "rate_ppm_max", "rate_ppm_median"):
        assert s[stat] == pytest.approx(25, abs=1e-3)        # to the rounding of the stamps to whole nanoseconds
    assert s["rate_step_ppm_max"] == pytest.approx(0, abs=1e-3)
    assert s["offset_range_ms"] == pytest.approx(0.375, abs=1e-6) and s["span_s"] == 15     # 25 ppm of 15 s


def test_known_answer_the_drift_changes_from_minus_25_to_plus_500_ppm_at_an_anchor():
    """The rate turns at 10 s, where the third anchor lies; anchors at 0, 5, 10, 15 and 20 s. Offsets at the anchors by
    hand: 0, -125, -250 us, then +2,500 us per 5 s: +2,250 and +4,750 us. Range 4,750 - (-250) = 5,000 us = 5.0 ms."""
    s = clock_rate.file_stats(pinned(n=250, theta=drifting(500, start_ms=10_000, before=-25)))
    assert s["rate_ppm"].tolist() == pytest.approx([-25, -25, 500, 500], abs=0.01)
    assert (s["rate_ppm_min"], s["rate_ppm_max"]) == pytest.approx((-25, 500), abs=0.01)
    assert s["rate_ppm_median"] == pytest.approx(237.5, abs=0.01)   # an even number of segments: the mean of the two middle ones
    assert s["rate_step_ppm_max"] == pytest.approx(525, abs=0.01)
    assert s["offset_range_ms"] == pytest.approx(5.0, abs=1e-5) and s["span_s"] == 20


def quick_at(quick, **kw):
    """Exchanges of 50 us each way except those in `quick` (exchange -> (forward, back) in us): these become the anchors."""
    return exchanges(forward=lambda i: quick.get(i, (50, 50))[0] * US, back=lambda i: quick.get(i, (50, 50))[1] * US, **kw)


def test_known_answer_anchors_closer_than_two_seconds_form_no_segment():
    """Anchors at exchanges 49 and 50 of a 101 ms probe, the second 2 us off: as a segment the pair would read 2 us in
    0.101 s, 19.8 ppm. It is none; the segments are 50 -> 120 (7.07 s, -2 us: -0.283 ppm) and 120 -> 170 (rate 0)."""
    close = quick_at({49: (10, 10), 50: (12, 8), 120: (10, 10), 170: (10, 10)}, n=198, step=101 * MS)
    assert e2e.anchors(close)[4].tolist() == [49, 50, 120, 170]
    s = clock_rate.file_stats(close)
    assert (s["anchors"], s["segments"]) == (4, 2) and s["rate_ppm"].tolist() == pytest.approx([-2 / 7.07, 0], abs=1e-6)
    # the step is taken between the segments that follow each other in the list, here across the pair that forms none
    assert s["rate_step_ppm_max"] == pytest.approx(2 / 7.07, abs=1e-6)
    # every anchor enters the offset range and the span, also one that ends no segment: 49 (4.949 s) to 170 (17.17 s)
    assert s["offset_range_ms"] == pytest.approx(0.002) and s["span_s"] == pytest.approx(12.221)
    # exactly 2.0 s apart is a segment (exchanges 40 and 60 of a 100 ms probe); 1.9 s is none
    assert clock_rate.file_stats(quick_at({40: (10, 10), 60: (10, 10), 120: (10, 10), 170: (10, 10)}))["segments"] == 3
    assert clock_rate.file_stats(quick_at({41: (10, 10), 60: (10, 10), 120: (10, 10), 170: (10, 10)}))["segments"] == 2


def test_the_earlier_exchange_is_the_anchor_on_a_tie():
    """Exchanges 50 and 52 have the same delay (20 us) and offsets 2 us above and 2 us below the true one. The earlier
    one is the anchor: the first segment reads +2 us in 5 s, +0.4 ppm; with the later one it would read -0.4 ppm."""
    tie = quick_at({0: (10, 10), 50: (12, 8), 52: (8, 12), 100: (10, 10), 150: (10, 10)})
    assert e2e.anchors(tie)[4].tolist() == [0, 50, 100, 150]
    assert clock_rate.file_stats(tie)["rate_ppm"].tolist() == pytest.approx([0.4, -0.4, 0], abs=1e-9)


def test_a_file_with_fewer_than_two_segments():
    """Reading (c) of the addendum: fewer than two segments give a rate step of 0; without a segment there is no rate."""
    one = clock_rate.file_stats(pinned(n=100, theta=drifting(25)))          # anchors at 0 and 5 s: one segment
    assert (one["anchors"], one["segments"], one["rate_step_ppm_max"]) == (2, 1, 0)
    assert one["rate_ppm_min"] == one["rate_ppm_max"] == one["rate_ppm_median"] == pytest.approx(25, abs=1e-3)
    none = clock_rate.file_stats(quick_at({49: (10, 10), 50: (12, 8)}, n=99, step=101 * MS))   # two anchors 0.101 s apart
    assert (none["anchors"], none["segments"], none["rate_step_ppm_max"]) == (2, 0, 0)
    assert (none["rate_ppm_min"], none["rate_ppm_max"], none["rate_ppm_median"]) == (None, None, None)
    assert none["offset_range_ms"] == pytest.approx(0.002) and none["span_s"] == pytest.approx(0.101)
    # over the files: both count as steady (a step of 0); the file without a segment enters no rate
    o = clock_rate.overall([one, none])
    assert (o["files"], o["files_steady"], o["files_adjusted"]) == (2, 2, 0)
    assert (o["rate_ppm_min"], o["rate_ppm_steady_min"], o["rate_ppm_steady_max"]) == pytest.approx((25, 25, 25), abs=1e-3)
    o = clock_rate.overall([none])
    assert [o[k] for k in ("rate_ppm_min", "rate_ppm_max", "rate_abs_max_ppm", "rate_abs_max_pct", "rate_ppm_steady_min")] == [None] * 5
    assert (o["files_steady"], o["rate_step_ppm_max"]) == (1, 0)
    # an exchange that contradicts itself still stops the file
    with pytest.raises(ValueError, match="needs t1 <= t4"):
        clock_rate.file_stats({**pinned(), "t4_ns": pinned()["t1_ns"] - 1})


def test_over_the_files():
    steady, slow, turned = (clock_rate.file_stats(pinned(n=300, theta=t)) for t in (
        drifting(25), drifting(-8), drifting(500, start_ms=10_000, before=-25)))
    o = clock_rate.overall([steady, slow, turned])
    assert (o["files"], o["files_steady"], o["files_adjusted"]) == (3, 2, 1)
    assert (o["rate_ppm_min"], o["rate_ppm_max"], o["rate_abs_max_ppm"]) == pytest.approx((-25, 500, 500), abs=0.01)
    assert o["rate_abs_max_pct"] == pytest.approx(0.05, rel=1e-4)        # 500 ppm as a percentage: the percentage itself
    assert o["rate_step_ppm_max"] == pytest.approx(525, abs=0.01) and o["offset_range_ms_max"] == pytest.approx(7.5, abs=1e-5)
    assert (o["rate_ppm_steady_min"], o["rate_ppm_steady_max"]) == pytest.approx((-8, 25), abs=1e-3)
    # the limit itself is steady: a step of exactly 5 ppm passes, one above it does not
    assert clock_rate.overall([{**steady, "rate_step_ppm_max": 5.0}])["files_steady"] == 1
    assert clock_rate.overall([{**steady, "rate_step_ppm_max": 5.000001}])["files_steady"] == 0
    # the larger absolute value may be the negative end; without a steady file the two steady keys have no value
    o = clock_rate.overall([{**turned, "rate_ppm_min": -900.0}])
    assert (o["rate_abs_max_ppm"], o["rate_ppm_steady_min"], o["rate_ppm_steady_max"]) == (900, None, None)


# ---- the command: the list of inputs, the hashes, the files it writes ---------------------------------------------------

def probe_text(cols):
    rows = list(zip(*(cols[k].tolist() for k in ("seq", "t1_ns", "t2_ns", "t3_ns", "t4_ns"))))
    return synth.text("seq,t1_ns,t2_ns,t3_ns,t4_ns", rows, HEAD, (f"exchanges_sent={len(rows)}", f"exchanges_completed={len(rows)}"))


def staged(tmp_path, cells=("s1.a", "s1.g"), wrong_hash=None):
    """Run directories under tmp_path/runs with one probe file each and the list of inputs: s1.a drifts at 25 ppm, the
    second cell turns from -25 to +500 ppm at 10 s."""
    lines = ["# probe files: cell, run directory, file inside it, sha256"]
    for cell, where, theta in zip(cells, ("periodic/clock_probe.csv", "clock_probe.csv"),
                                  (drifting(25), drifting(500, start_ms=10_000, before=-25))):
        p = tmp_path / "runs" / f"E9_{cell.replace('.', '_').replace('/', '_')}_x" / where
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(probe_text(pinned(n=300, theta=theta)))
        digest = "0" * 64 if cell == wrong_hash else hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append("\t".join((cell, p.relative_to(tmp_path / "runs").parts[0], where, digest)))
    (tmp_path / "inputs.tsv").write_text("\n".join(lines) + "\n")
    return [str(tmp_path / "inputs.tsv"), "--runs-root", str(tmp_path / "runs"), "--out", str(tmp_path / "out"),
            "--key-prefix", "clock.t"]


def test_the_command_writes_the_keys_of_every_file_and_of_all_files(tmp_path):
    clock_rate.main(staged(tmp_path))
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        rows = {r["key"]: r for r in csv.DictReader(f)}
    per_file = ("segments", "rate_ppm_min", "rate_ppm_max", "rate_ppm_median", "rate_step_ppm_max", "offset_range_ms", "span_s")
    everything = ("files", "rate_ppm_min", "rate_ppm_max", "rate_abs_max_ppm", "rate_abs_max_pct", "rate_step_ppm_max",
                  "offset_range_ms_max", "files_steady", "files_adjusted", "rate_ppm_steady_min", "rate_ppm_steady_max")
    assert sorted(rows) == sorted([f"clock.t.{cell}.{k}" for cell in ("s1.a", "s1.g") for k in per_file]
                                  + [f"clock.t.all.{k}" for k in everything])
    shown = {k.removeprefix("clock.t."): r["formatted"] for k, r in rows.items()}
    # rates to 1 ppm with their sign, offsets to 0.1 ms, the span to 1 s, the percentage to two significant digits
    assert {k: shown[k] for k in ("s1.g.segments", "s1.g.rate_ppm_min", "s1.g.rate_ppm_max", "s1.g.rate_ppm_median",
                                  "s1.g.rate_step_ppm_max", "s1.g.offset_range_ms", "s1.g.span_s")} == {
        "s1.g.segments": "5", "s1.g.rate_ppm_min": r"\ensuremath{-}25", "s1.g.rate_ppm_max": r"\ensuremath{+}500",
        "s1.g.rate_ppm_median": r"\ensuremath{+}500", "s1.g.rate_step_ppm_max": "525", "s1.g.offset_range_ms": "7.5",
        "s1.g.span_s": "25"}
    assert {k: shown["all." + k] for k in everything} == {
        "files": "2", "rate_ppm_min": r"\ensuremath{-}25", "rate_ppm_max": r"\ensuremath{+}500", "rate_abs_max_ppm": "500",
        "rate_abs_max_pct": r"0.050\%", "rate_step_ppm_max": "525", "offset_range_ms_max": "7.5", "files_steady": "1",
        "files_adjusted": "1", "rate_ppm_steady_min": r"\ensuremath{+}25", "rate_ppm_steady_max": r"\ensuremath{+}25"}
    assert shown["s1.a.offset_range_ms"] == "0.6" and shown["s1.a.rate_step_ppm_max"] == "0"   # 25 ppm of 25 s: 0.625 ms
    one = rows["clock.t.s1.g.rate_ppm_max"]
    assert one["source_file"] == "E9_s1_g_x/clock_probe.csv" and one["unit"] == "ppm" and one["n"] == "5"
    assert "board B's clock runs faster" in one["how"] and "not which of the two clocks" in one["how"]
    # the raw value of this key is the percentage itself (Addendum C: "the same as a percentage"), 500 ppm = 0.05,
    # where every key of unit percent holds a proportion; it prints as before, and its unit says which it is
    pct = rows["clock.t.all.rate_abs_max_pct"]
    assert float(pct["value"]) == pytest.approx(0.05, rel=1e-4) and (pct["formatted"], pct["unit"]) == (r"0.050\%", "%")
    tex = (tmp_path / "out" / "numbers.tex").read_text()
    assert r"meas@clock.t.all.rate_abs_max_pct\endcsname{0.050\%}" in tex            # \meas prints 0.050%
    assert r"measraw@clock.t.all.rate_abs_max_pct\endcsname{0.05" in tex             # \measraw the percentage, 0.05
    # the directory is one the merge takes like any other
    merged = merge_numbers.merge([tmp_path / "out" / "numbers.tex"])
    assert merged[2] == 25 and "clock.t.all.files_steady" in merged[0]
    assert (tmp_path / "out" / "number_keys.md").is_file()


@pytest.mark.parametrize("change, message", [
    (dict(wrong_hash="s1.g"), "sha256"), (dict(cells=("s1.a", "s1.a")), "more than once"), (dict(cells=("s1.a", "all")), "'all'"),
    (dict(cells=("s1.a", "s1/g")), "s1/g")])
def test_a_wrong_hash_or_a_bad_cell_is_refused_and_nothing_is_written(tmp_path, change, message):
    with pytest.raises(SystemExit, match=message):
        clock_rate.main(staged(tmp_path, **change))
    assert not (tmp_path / "out").exists()


def test_a_line_of_the_list_without_its_four_fields_is_refused(tmp_path):
    args = staged(tmp_path)
    (tmp_path / "inputs.tsv").write_text("s1.a\tE9_s1_a_x\tperiodic/clock_probe.csv\n")
    with pytest.raises(SystemExit, match="four fields"):
        clock_rate.main(args)
    assert not (tmp_path / "out").exists()


def test_track_uses_the_same_anchors(tmp_path):
    """track() takes its anchors from anchors(): the latency keys and the clock keys cannot select differently."""
    cols = quick_at({7: (10, 10), 9: (10, 10), 60: (30, 10), 120: (5, 5)})
    order, tau2, theta2, delta, anchor = e2e.anchors(cols)
    tr = e2e.track(cols)
    assert anchor.tolist() == tr["anchor"].tolist() == [7, 60, 120, 150] and np.array_equal(delta, tr["delay_ns"])
    assert np.array_equal(theta2 / 2, tr["theta_ns"]) and order.tolist() == list(range(200))
    assert (tau2[anchor] - tau2[anchor[0]]).tolist() == (2 * tr["x"]).tolist()
