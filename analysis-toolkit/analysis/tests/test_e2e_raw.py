"""E9 on the raw clocks (E9_SPEC.md, Addendum E): the maps of the two boards, the conversion of the PDU stamps and the
latency, on runs generated from true time (synth.e9_run). The tests named known_answer_<n> are those of E7."""
import numpy as np
import pytest

from analysis import clock_rate, e2e
from analysis.tests import synth

MS, SEC = 1_000_000, 1_000_000_000
TRUE_MS = 4.0                                    # 3 ms to the send, 0.4 ms on the wire, 0.6 ms to the delivery


def PIN(i):
    """Delays that pin the anchors: every fiftieth exchange takes 10 us each way, the others 50 us."""
    return 10_000 if i % 50 == 0 else 50_000


def arrays(run):
    """(tx, rx, probe, maps) of a generated run as the columns e2e.analyse takes."""
    def table(rows, header, text=()):
        return {name: np.array([str(r[k]) for r in rows]) if name in text else np.array([r[k] for r in rows], dtype=np.int64)
                for k, name in enumerate(header.split(","))}
    return (table(run["tx"], synth.TX_HEADER, ("stream",)), table(run["rx"], synth.RX_HEADER, ("stream", "result")),
            table(run["probe"], synth.PROBE2_HEADER), {x: table(run["map_" + x], synth.MAP_HEADER) for x in "ab"})


def steady(**kw):
    """Both boards' CLOCK_MONOTONIC equal to their raw clock plus a constant; PDUs from 12 s to 28 s."""
    return synth.e9_run(**{"pdus": 1600, "forward": PIN, "back": PIN, "map_width": 200, "point_width": 400, **kw})


def steered(**kw):
    """E7, test 1: raw clocks 25 ppm apart, board B's CLOCK_MONOTONIC steered by +5,000 ppm (per unit of its own
    reading, E11 k) from 17 s to 27 s of its raw clock, in the middle of the PDUs."""
    return steady(rate_b_ppm=-25, steer={"b": synth.steered(5000, 17, 10)}, **kw)


def test_the_generator_gives_the_clocks_it_is_asked_for():
    """The generator stands on its own: at true time t board A's raw clock reads E9_RAW['a'] + t, board B's is 25 ppm
    slow, and a steered CLOCK_MONOTONIC is its raw clock plus the constant plus what it has gained: 5,000 ns per
    1,000,000 ns of its own reading, that is 1 s x 5,000 / 995,000 = 5,025,125 ns per second of the raw clock."""
    raw, mono = synth.e9_clocks(-25, {"b": synth.steered(5000, 17, 10)})
    assert raw("a", 40 * SEC) - raw("a", 0) == 40 * SEC and raw("b", 40 * SEC) - raw("b", 0) == 40 * SEC - 1_000_000
    assert mono("a", 20 * SEC) - raw("a", 20 * SEC) == synth.E9_MONO["a"]
    raw, mono = synth.e9_clocks(0, {"b": synth.steered(5000, 17, 10)})        # raw clocks alike: true time is board B's raw time
    gained = [mono("b", t * SEC) - raw("b", t * SEC) - synth.E9_MONO["b"] for t in (17, 18, 27, 40)]
    assert gained == [0, 5_025_125, 50_251_256, 50_251_256]
    # in the steered second CLOCK_MONOTONIC ran 1,005,025,125 ns, and 5,000 ppm of that is the gain
    assert (mono("b", 18 * SEC) - mono("b", 17 * SEC)) * 5000 // 1_000_000 == 5_025_125
    run = synth.e9_run(seconds=2, pdus=1, first=SEC, map_width=200, point_width=400)
    r1, m, r2 = run["map_a"][3]                                   # the fourth sample, at 15 ms: RAW, MONOTONIC, RAW
    assert (r1, m, r2) == (synth.E9_RAW["a"] + 15 * MS, synth.E9_RAW["a"] + 15 * MS + 100 + synth.E9_MONO["a"], synth.E9_RAW["a"] + 15 * MS + 200)
    seq, t1, t2, t3, t4, t1r, t2r, t3r, t4r, w1, w2, w3, w4 = run["probe"][1]      # the request leaves at 101 ms
    assert (t1r, t4r - t1r, t3r - t2r, (w1, w2, w3, w4)) == (synth.E9_RAW["a"] + 101 * MS, 118_000, 18_000, (400, 400, 400, 400))
    # before a send the stamp is the second raw read (the monotonic read lies before it), after a receive the first
    assert [t1 - t1r, t2 - t2r, t3 - t3r, t4 - t4r] == [synth.E9_MONO["a"] - 200, synth.E9_MONO["b"] + 200, synth.E9_MONO["b"] - 200,
                                                         synth.E9_MONO["a"] + 200]
    assert run["latency_ns"] == 4 * MS and run["tx"][0][2] == synth.E9_RAW["a"] + SEC + synth.E9_MONO["a"]


def test_known_answer_1_a_steered_clock_is_a_result_on_the_raw_clocks_and_none_on_the_monotonic_ones():
    tx, rx, probe, maps = arrays(steered())
    per_pdu = {}
    res, reasons = e2e.analyse(tx, rx, probe, maps, per_pdu=per_pdu)
    assert reasons == [] and res["n"] == 1600 and res["probe_format"] == 2
    bound = res["bound_total_us"]
    # every latency is recovered to within the bound (the true one is 4 ms; theta is taken at the release, so the
    # 25 ppm between the raw clocks leave 0.1 us in it; a stamp in the one sample interval in which the steering starts
    # is carried over up to 2 us wrong, because the line between two samples cuts the bend: the hold-out covers that)
    assert np.abs(per_pdu["latency_ns"] - 4 * MS).max() <= bound * 1e3 and np.abs(per_pdu["latency_ns"] - 4 * MS).max() < 1_000
    assert np.median(np.abs(per_pdu["latency_ns"] - 4 * MS)) == pytest.approx(99, abs=1)
    assert res["latency_ms"]["p50"] == pytest.approx(TRUE_MS, abs=3e-4) and res["latency_ms"]["max"] == pytest.approx(TRUE_MS, abs=1e-3)
    assert res["rxpart_ms"]["p50"] == pytest.approx(1.0, abs=3e-4) and res["causality_min_us"] == pytest.approx(400, abs=1)
    # the offset between the boards on the raw stamps: anchors with 10 us each way, the others certify within 50 us
    assert (res["offset_bound_us"], res["exchanges_outside"], res["causality_violations"]) == (pytest.approx(10, abs=0.01), 0, 0)
    assert res["offset_cert_us"] == res["offset_bound_total_us"] == pytest.approx(50, abs=0.01)
    assert res["drift_ppm"] == pytest.approx(-25, abs=0.01)
    # the maps. Board A is not steered: its samples lie on a constant, the bound is the half width of a sample (0.1 us).
    # Board B's line bends by 5,000 ppm where the steering starts: at 17 s of its raw clock, 17.000425 s of true time,
    # 0.425 ms after a sample. Between two samples the raw clock runs 4,999,875 ns (5 ms, 25 ppm slow). By the next
    # sample the raw clock has run 4,574,875 ns since the start of the steering: a gain of 4,574,875 x 5,000 / 995,000 =
    # 22,989 ns, and CLOCK_MONOTONIC has run 4,999,875 + 22,989 ns. The sample before the bend lies
    # 22,989 x 4,999,875 / (4,999,875 + 5,022,864) = 11,468 ns off the line through its two neighbours; at the end of
    # the steering the same reasoning gives less
    a, b = res["map"]["a"], res["map"]["b"]
    assert (a["holdout_us"], a["half_us"], a["bound_us"]) == (0, 0.1, 0.1)
    # (board B's raw clock is 25 ppm slow: the 200 ns between the two raw reads of a sample are 199 ns on it, rounded down)
    assert b["holdout_us"] == pytest.approx(11.468, abs=0.002) and b["half_us"] == 0.0995
    # the kink term (E12.1) of the interval that holds the bend: the rate goes from 0 to 5,000 ppm around it and the
    # interval is 5,022,864 ns long: 5,000 ppm x 5,022,864 ns / 4 = 6,279 ns; the hold-out is the larger of the two here
    assert a["kink_us"] == 0 and b["kink_us"] == pytest.approx(6.279, abs=0.005)
    assert b["bound_us"] == pytest.approx(b["holdout_us"] + b["half_us"], abs=1e-12) and b["bound_us"] < 20 and a["bound_us"] < 20
    assert bound == pytest.approx(res["offset_bound_total_us"] + a["bound_us"] + b["bound_us"]) and bound == pytest.approx(61.668, abs=0.005)
    # 8,001 samples of 5 ms on each board, all valid; in the range the stamps use none is more than 5 ms from the next
    assert [(m["samples"], m["samples_invalid"], m["gap_max_ms"]) for m in (a, b)] == [(8001, 0, 5.0), (8001, 0, pytest.approx(5.025, abs=1e-3))]
    # the exchanges that left board A from 12.019 s to 27.977 s (numbers 119 to 277) lie in the range of the stamps:
    # two points each on either board, and each reads the relation of the two clocks where the map has it
    assert (a["check_n"], b["check_n"], a["check_violations"], b["check_violations"]) == (318, 318, 0, 0)
    assert a["check_max_us"] == 0 and b["check_max_us"] < b["bound_us"]
    assert (res["probe_width_p50_ns"], res["probe_width_max_ns"]) == (400, 400)
    # the same exchanges on their monotonic columns: the bend of 5,000 ppm inside a segment breaks the track
    old, why = e2e.analyse_mono(tx, rx, probe)
    assert old is None and any(w.startswith("offset_bound_total_us = ") and "exceeds 100" in w for w in why)
    assert res["mono"]["verdict"] == 0 and res["mono"]["latency_p50_diff_us"] is None and res["mono"]["offset_bound_total_us"] > 100


def test_known_answer_2_steady_clocks_give_the_same_latency_on_either_clock():
    tx, rx, probe, maps = arrays(steady())
    res, reasons = e2e.analyse(tx, rx, probe, maps)
    assert reasons == [] and res["map"]["a"]["holdout_us"] == 0 == res["map"]["b"]["holdout_us"]
    old, why = e2e.analyse_mono(tx, rx, probe)
    assert why == [] and abs(old["latency_ms"]["p50"] - res["latency_ms"]["p50"]) * 1e3 <= res["bound_total_us"]
    assert res["latency_ms"]["p50"] == pytest.approx(TRUE_MS, abs=1e-6) and old["latency_ms"]["max"] == pytest.approx(TRUE_MS, abs=1e-6)
    # the stamps are carried in whole nanoseconds: with clocks that run alike every latency is the true one exactly
    per_pdu = {}
    e2e.analyse(tx, rx, probe, maps, per_pdu=per_pdu)
    assert np.abs(per_pdu["latency_ns"] - 4 * MS).max() == 0 and np.abs(per_pdu["margin_ns"] - 400_000).max() == 0
    assert res["mono"]["verdict"] == 1 and res["mono"]["latency_p50_diff_us"] == pytest.approx(0, abs=1e-3)
    assert res["mono"]["offset_bound_total_us"] == pytest.approx(50.4, abs=0.01)     # the monotonic reads lie 0.8 us wider apart
    assert res["bound_total_us"] == pytest.approx(50.2, abs=0.01)                      # 50 + 0.1 + 0.1


def without(run, board, first_ms, last_ms):
    """The run with the map samples of `board` taken between the two true times (in ms, ends included) left out."""
    keep = [row for k, row in enumerate(run["map_" + board]) if not first_ms <= k * 5 <= last_ms]
    return {**run, "map_" + board: keep}


def test_known_answer_3_a_gap_in_a_map_or_a_stamp_outside_it_is_not_a_result():
    # the samples from 15.005 s to 15.055 s missing: 60 ms between two valid samples in the range the stamps use
    res, reasons = e2e.analyse(*arrays(without(steady(), "b", 15_005, 15_055)))
    assert res is None and reasons == ["map_b.gap_max_ms = 60 exceeds 50: clock_map_b.csv has a gap between two valid samples "
                                       "in the range the stamps use"]
    # exactly 50 ms passes
    res, reasons = e2e.analyse(*arrays(without(steady(), "b", 15_005, 15_045)))
    assert reasons == [] and res["map"]["b"]["gap_max_ms"] == 50
    # a gap outside the range the stamps use (before the first release) does not count
    res, reasons = e2e.analyse(*arrays(without(steady(), "a", 5_005, 5_500)))
    assert reasons == [] and res["map"]["a"]["gap_max_ms"] == 5
    # the first valid sample of board A (12.000 s) 1 ms after the first release: that stamp cannot be converted
    res, reasons = e2e.analyse(*arrays(without(steady(map_width=0, first=11_999 * MS), "a", 0, 11_995)))
    assert res is None and len(reasons) == 1 and reasons[0].startswith("a stamp of board A lies 1 ms before the first valid sample")
    # ... and the first valid sample exactly at the first release: the stamp is carried over, but the interval it lies
    # in is the first of the file and has no neighbour on one side: its kink term cannot be formed (E12.1)
    assert e2e.analyse(*arrays(without(steady(map_width=0), "a", 0, 11_995))) == (None, [
        "clock_map_a.csv: an interval of the range the stamps use has no valid sample at least 4 ms before it or after it "
        "in the file: its kink term cannot be formed"])
    # with one more sample before it (11.995 s) the run is a result
    assert e2e.analyse(*arrays(without(steady(map_width=0), "a", 0, 11_990)))[1] == []
    # the last valid sample of board B before the last delivery
    res, reasons = e2e.analyse(*arrays(without(steady(), "b", 27_900, 40_000)))
    assert res is None and len(reasons) == 1 and "after the last valid sample of clock_map_b.csv" in reasons[0]


def test_known_answer_4_a_sample_that_was_interrupted_is_not_used():
    run = steady(map_width=lambda board, k: 6000 if (board, k) == ("b", 3000) else 200)      # the sample at 15.000 s
    res, reasons = e2e.analyse(*arrays(run))
    b = res["map"]["b"]
    assert reasons == [] and (b["samples"], b["samples_invalid"], b["gap_max_ms"], b["half_us"]) == (8001, 1, 10, 0.1)
    assert res["map"]["a"]["samples_invalid"] == 0 and res["latency_ms"]["p50"] == pytest.approx(TRUE_MS, abs=1e-6)
    # a board whose samples were all interrupted has no valid sample: not a result (E11 k)
    res, reasons = e2e.analyse(*arrays(steady(map_width=lambda board, k: 6000 if board == "b" else 200)))
    assert res is None and reasons == ["clock_map_b.csv: has no valid sample"]
    # exactly 5,000 ns is valid, and its half width enters the bound
    run = steady(map_width=lambda board, k: 5000 if (board, k) == ("b", 3000) else 200)
    b = e2e.analyse(*arrays(run))[0]["map"]["b"]
    # its monotonic read lies 2,500 ns behind its first raw read, those of its neighbours 100 ns: 5.0024 ms to the next
    assert (b["samples_invalid"], b["gap_max_ms"], b["half_us"], b["bound_us"]) == (0, pytest.approx(5.0024, abs=1e-9), 2.5, 2.5)


def test_known_answer_5_an_exchange_point_off_the_map_is_a_violation():
    tx, rx, probe, maps = arrays(steady())
    probe["t2_ns"][150] += 50_000              # the monotonic read of point 2 of exchange 150 (15.15 s), on board B
    res, reasons = e2e.analyse(tx, rx, probe, maps)
    assert res is None and reasons == ["map_b.check_violations = 1: an exchange point of board B reads the relation of its two "
                                       "clocks further from the map than map_b.bound_us (0.1 us) plus half its width; the largest "
                                       "distance is 50 us"]
    # 0.3 us off is inside: the map bound of 0.1 us plus half the point's width of 400 ns
    probe["t2_ns"][150] -= 50_000 - 300
    res, reasons = e2e.analyse(tx, rx, probe, maps)
    assert reasons == [] and (res["map"]["b"]["check_violations"], res["map"]["b"]["check_max_us"]) == (0, 0.3)
    # a point wider than 5,000 ns was interrupted and is no check point; an exchange outside the range of the stamps is none either
    probe["t2_ns"][150] += 50_000
    probe["w2_ns"][150] = 5_001
    probe["t3_ns"][100] += 50_000              # 10.1 s: before the first release
    res, reasons = e2e.analyse(tx, rx, probe, maps)
    assert reasons == [] and res["map"]["b"]["check_n"] == 317 and res["probe_width_max_ns"] == 5_001


def PIN40(i):
    """Every fiftieth exchange 10 us each way, the others 40 us: an offset bound of 40 us."""
    return 10_000 if i % 50 == 0 else 40_000


def gap_run(gap_ms):
    """E12.1, known answer 9. Board B's map is evenly spaced at 5 ms except for one gap of `gap_ms` of its
    CLOCK_MONOTONIC, which starts at the sample of 19.990 s; in the middle of the gap the clock changes its rate by
    +6,900 ppm (per unit of its own reading) and keeps it. Returns the run and the true time of the change. (The raw
    clocks run alike, so true time is board B's raw time; until the change CLOCK_MONOTONIC runs with the raw clock,
    after it 1 / 0.9931 times as fast: half a gap of it takes 0.9931 half gaps of true time.)"""
    half = gap_ms * MS // 2
    change = 19_990 * MS + half
    resumed = change + half * (1_000_000 - 6900) // 1_000_000
    times = [k * 5 * MS for k in range(3999)] + list(range(resumed, 40 * SEC + 1, 5 * MS))
    run = synth.e9_run(pdus=1600, forward=PIN40, back=PIN40, map_width=0, point_width=400,
                       steer={"b": synth.steered(6900, change / SEC, 1000)}, map_times={"b": times})
    return run, change


def test_known_answer_9_a_rate_change_inside_a_long_gap_is_paid_for_by_the_kink_term():
    run, change = gap_run(30)
    tx, rx, probe, maps = arrays(run)
    per_pdu = {}
    res, reasons = e2e.analyse(tx, rx, probe, maps, per_pdu=per_pdu)
    assert reasons == []
    b = res["map"]["b"]
    # the kink term: the rate goes from 0 to 6,900 ppm across a gap of 30 ms: 6,900 ppm x 30 ms / 4 = 51.75 us
    assert b["kink_us"] == pytest.approx(51.75, abs=0.01) and b["gap_max_ms"] == pytest.approx(30, abs=1e-5)
    # the hold-out of the two samples beside the gap sees much less: the one after the gap lies 103.5 us x 30 / 35.03 =
    # 88.6 us up the line from the sample before the gap to the next but one (138.2 us higher), 14.9 us off it
    assert b["holdout_us"] == pytest.approx(14.87, abs=0.05) and b["half_us"] == 0
    assert b["bound_us"] == b["kink_us"] and res["map"]["a"]["kink_us"] == 0
    # the true error of the straight line, at the change itself: a stamp taken there is carried 51.75 us wrong
    raw, mono = synth.e9_clocks(0, {"b": synth.steered(6900, change / SEC, 1000)})
    whole, part = e2e.to_raw(e2e.clock_map(maps["b"]), np.array([mono("b", change)], dtype=np.int64))
    assert abs((int(whole[0]) - part[0]) / 2 - raw("b", change)) == pytest.approx(51_750, abs=5)
    # with the offset bound of 40 us the run is a result, and its total covers the error of every PDU: the largest is
    # that of the PDU delivered at 20.004 s, 14 ms into the gap and 1 ms before the change, where the line (3,450 ppm
    # up from the sample before the gap) is 48.3 us off. The earlier bound, hold-out plus half width, was short
    worst_us = np.abs(per_pdu["latency_ns"] - run["latency_ns"]).max() / 1e3
    assert res["offset_bound_total_us"] == pytest.approx(40, abs=0.01) and res["bound_total_us"] == pytest.approx(91.75, abs=0.02)
    assert worst_us == pytest.approx(48.3, abs=0.1) and b["holdout_us"] + b["half_us"] < worst_us <= res["bound_total_us"]
    # the exchange that left board A at 19.998 s lies in the gap, 8 ms after its start: its two points on board B read
    # the relation 27.8 us off the line. That is inside the new bound, and it was a violation of the earlier one
    assert b["check_violations"] == 0 and b["check_max_us"] == pytest.approx(27.8, abs=0.1)
    assert b["check_max_us"] > b["holdout_us"] + b["half_us"] + 0.2          # the earlier bound plus half the point's width
    # a gap of 49 ms: 6,900 ppm x 49 ms / 4 = 84.5 us, and with the offset bound of 40 us the total is above 100 us
    res, reasons = e2e.analyse(*arrays(gap_run(49)[0]))
    assert res is None and len(reasons) == 1 and reasons[0].startswith("bound_total_us = 124.5") and "map_b.bound_us 84.5" in reasons[0]


def test_known_answer_10_two_samples_microseconds_apart_do_not_blow_up_the_kink_term():
    """E12.7. Steady clocks, read noise of up to 150 ns on every sample of board B, and one wake-up of its sampler 12 ms
    late: the sample due at 20.000 s is taken at 20.012 s and the two it owes 2 us and 4 us after that. A slope read
    between two of those three would be read noise over microseconds (300 ns in 2 us are 150,000 ppm); the slopes of the
    kink term are read over at least 4 ms, where 300 ns are at most 75 ppm: for the interval of 17 ms before the three
    (19.995 s to 20.012 s) that is at most 150 ppm x 17 ms / 4 = 0.64 us."""
    late = 20_012 * MS
    times = [t for k in range(8001) for t in [k * 5 * MS] if not 20_000 * MS <= t <= 20_010 * MS] + [late, late + 2_000, late + 4_000]
    run = steady(map_times={"b": sorted(times)}, map_noise=lambda board, k: (k * 7919 % 301 - 150) if board == "b" else 0)
    res, reasons = e2e.analyse(*arrays(run))
    b = res["map"]["b"]
    assert reasons == [] and b["samples"] == 8001 and b["gap_max_ms"] == pytest.approx(17, abs=1e-3)
    assert 0 < b["kink_us"] < 1 and b["holdout_us"] < 1 and res["map"]["a"]["kink_us"] == 0
    assert res["bound_total_us"] < 52 and res["latency_ms"]["p50"] == pytest.approx(TRUE_MS, abs=1e-3)
    # the baseline is 4 ms: the three samples 2 us apart have slopes between them of thousands of ppm
    board = e2e.clock_map(arrays(run)[3]["b"])
    close = np.flatnonzero(np.diff(board["a"]) < 10_000)
    assert close.size == 2 and np.abs(np.diff(board["m2"])[close] / 2 / np.diff(board["a"])[close]).max() > 0.01


def test_the_stamp_of_a_point_is_the_raw_read_next_to_the_datagram():
    """Points 4,000 ns wide, samples of width 0, steady clocks: every point reads exactly what the map has. With the
    mean of the two raw reads taken on the wrong side of the stamp it would be 4 us off."""
    res, reasons = e2e.analyse(*arrays(steady(map_width=0, point_width=4000)))
    assert reasons == [] and [res["map"][x][k] for x in "ab" for k in ("check_max_us", "check_violations", "bound_us")] == [0] * 6
    assert (res["probe_width_p50_ns"], res["bound_total_us"]) == (4000, pytest.approx(50, abs=1e-6))


def test_a_board_needs_its_check_points():
    """300 PDUs from 12 s to 15 s: the exchanges 119 to 148 lie in the range of the stamps, 60 points per board. A harness
    run needs 100, the gateway run 20."""
    tx, rx, probe, maps = arrays(steady(pdus=300))
    res, reasons = e2e.analyse(tx, rx, probe, maps)
    assert res is None and reasons == [f"map_{x}.check_n = 60: fewer than 100 exchange points of board {x.upper()} in the range "
                                       "the stamps use" for x in "ab"]
    res, reasons = e2e.analyse(tx, rx, probe, maps, check_min=e2e.CHECK_MIN_GATEWAY)
    assert reasons == [] and res["map"]["a"]["check_n"] == 60


def test_known_answer_7_a_format_1_file_is_refused_for_the_latency():
    tx, rx, probe, maps = arrays(steady())
    old = {k: probe[k] for k in ("seq", "t1_ns", "t2_ns", "t3_ns", "t4_ns")}
    res, reasons = e2e.analyse(tx, rx, old, maps)
    assert res is None and reasons == ["the probe file is of format 1 (no raw stamps): refused for the latency, which is "
                                       "measured on the raw clocks (E9_SPEC.md, Addendum E)"]
    # the statistics of Addendum C read either format: they take the monotonic columns
    assert clock_rate.file_stats(old)["segments"] == clock_rate.file_stats(probe)["segments"] == 7


def test_known_answer_8_what_the_maps_say_about_each_clock():
    steady_run, steered_run = (e2e.analyse(*arrays(r))[0]["clock"] for r in (steady(), steered()))
    for x in "ab":   # CLOCK_MONOTONIC = raw + constant: every window of 1 s has rate 0
        assert steady_run[x] == {"adj_ppm_min": 0, "adj_ppm_max": 0, "adj_ppm_median": 0, "adj_step_ppm_max": 0,
                                 "adj_offset_range_us": 0, "adjusted": 0}
    assert steered_run["a"]["adjusted"] == 0 and steered_run["a"]["adj_ppm_max"] == 0
    b = steered_run["b"]
    # steered by 5,000 ppm of its own reading (E11 k): every window of 1 s that lies inside the steering has the rate
    # 5,000. The steering starts 100 ns before a window does (17 s of the raw clock; the windows count from the first
    # sample's monotonic read), so the step from the window before is 5,000 as well. 10 s of the raw clock at
    # 5,000 / 995,000 are 50,251.256 us
    assert b["adj_ppm_max"] == pytest.approx(5000, abs=0.01) and b["adj_ppm_min"] == pytest.approx(0, abs=0.01)
    assert b["adj_ppm_median"] == pytest.approx(0, abs=0.01) and b["adj_step_ppm_max"] == pytest.approx(5000, abs=0.01)
    assert b["adj_offset_range_us"] == pytest.approx(50_251.256, abs=0.01) and b["adjusted"] == 1


def test_the_map_of_a_board_by_hand():
    """Five samples 10 ms apart with m = 0, 0, 30, 0, 0 us and widths 0, 2, 4, 0, 6,000 ns (the last one is not valid)."""
    base, mono0 = 1_000_000_000, 5_000_000_000
    m, width = [0, 0, 30_000, 0, 0], [0, 2_000, 4_000, 0, 6_000]
    cols = {"raw1_ns": [], "mono_ns": [], "raw2_ns": []}
    for k in range(5):
        mono = mono0 + k * 10 * MS
        mid = mono - (mono0 - base) - m[k]                 # the mean of the two raw reads: mono - (constant + m)
        for name, v in zip(cols, (mid - width[k] // 2, mono, mid + width[k] // 2)):
            cols[name].append(v)
    board = e2e.clock_map({k: np.array(v, dtype=np.int64) for k, v in cols.items()})
    assert (board["samples"], board["samples_invalid"], board["a"].tolist()) == (5, 1, [mono0 + k * 10 * MS for k in range(4)])
    # a stamp half way between the second and the third sample: m = 15 us there, so its raw value is mono - constant - 15 us
    stamps = np.array([mono0 + 15 * MS, mono0 + 12 * MS], dtype=np.int64)
    whole, part = e2e.to_raw(board, stamps)
    assert ((whole - part) / 2 - (stamps - (mono0 - base))).tolist() == [-15_000, -6_000]
    # the range the two stamps use: from the second sample (10 ms) to the third (20 ms); the gap is 10 ms, the largest
    # half width 2 us; the hold-out takes the second sample (0 against the line 0 .. 30: 15 us) and the third (30 against
    # 0 .. 0: 30 us), both with two valid neighbours; the fourth sample has an invalid neighbour and lies outside anyway
    f = e2e.map_figures(board, stamps, mono=np.array([mono0 + 18 * MS]), mean_raw2=np.array([2 * (base + 18 * MS - 24_000 - 7_000)]),
                        width=np.array([1_000]))
    assert (f["gap_max_ms"], f["half_us"], f["holdout_us"], f["bound_us"]) == (10, 2, 30, 32)
    # the kink term of the one interval of the range (10 ms to 20 ms): the intervals beside it have the slopes 0 and
    # -30 us per 10 ms, so a single change of rate inside it puts the line off by at most 3 us/ms x 10 ms / 4 = 7.5 us
    assert f["kink_us"] == 7.5
    # (E12.7: each slope is read over at least 4 ms; the samples here are 10 ms apart, so over one interval)
    # stamps between 20 ms and 30 ms: that interval is the last one between valid samples, with no sample 4 ms behind it
    last = e2e.map_figures(board, np.array([mono0 + 25 * MS]), mono=np.array([]), mean_raw2=np.array([]), width=np.array([]))
    assert (last["kink_us"], last["bound_us"], last["holdout_us"]) == (None, None, 30)
    # the kink term takes its neighbours among the VALID samples, the hold-out among the rows of the file. Six samples
    # with m = 0, 0, 30, -, 0, 0 us, the fourth not valid: the interval from 10 to 20 ms has the neighbours 0 -> 10 ms
    # (slope 0) and 20 -> 40 ms (-30 us in 20 ms): 1.5 us/ms x 10 ms / 4 = 3.75 us. The sample at 20 ms has an invalid
    # row beside it and takes no part in the hold-out, which is that of the sample at 10 ms: 15 us
    six = {"raw1_ns": [], "mono_ns": [], "raw2_ns": []}
    for k, (value, wide) in enumerate(((0, 0), (0, 0), (30_000, 0), (0, 6_000), (0, 0), (0, 0))):
        mono = mono0 + k * 10 * MS
        for name, v in zip(six, (mono - (mono0 - base) - value - wide // 2, mono, mono - (mono0 - base) - value + wide // 2)):
            six[name].append(v)
    of_six = e2e.map_figures(e2e.clock_map({k: np.array(v, dtype=np.int64) for k, v in six.items()}), stamps,
                             mono=np.array([]), mean_raw2=np.array([]), width=np.array([]))
    assert (of_six["kink_us"], of_six["holdout_us"], of_six["bound_us"], of_six["gap_max_ms"]) == (3.75, 15, 15, 10)
    # one check point at 18 ms: the map has m = 24 us there, the point reads 31 us: 7 us off, inside 32 + 0.5
    assert (f["check_n"], f["check_max_us"], f["check_violations"]) == (1, 7, 0)
    # a stamp before the first sample or after the last valid one
    with pytest.raises(ValueError, match="1 ms before the first valid sample"):
        e2e.map_figures(board, np.array([mono0 - MS]), mono=np.array([]), mean_raw2=np.array([]), width=np.array([]))
    with pytest.raises(ValueError, match="5 ms after the last valid sample"):
        e2e.map_figures(board, np.array([mono0 + 35 * MS]), mono=np.array([]), mean_raw2=np.array([]), width=np.array([]))
    # samples that are not in ascending order of their monotonic read contradict the file
    with pytest.raises(ValueError, match="ascending"):
        e2e.clock_map({"raw1_ns": np.array([5, 4]), "mono_ns": np.array([100, 90]), "raw2_ns": np.array([5, 4])})


def test_windows_of_the_adjustment_rate_by_hand():
    """Samples every 100 ms for 3.05 s; m rises by 2 us per second in the second window only. A window needs samples at
    least 0.8 s apart: the fourth one (3.0 s, 3.05 s) has none."""
    mono = np.array([k * 100 * MS for k in range(31)] + [3_050 * MS], dtype=np.int64) + 7 * SEC
    m = np.clip(mono - 8 * SEC, 0, SEC) * 2 // 1_000_000                      # 0 until 8 s, then 2 ns per ms, 2,000 ns from 9 s
    board = e2e.clock_map({"raw1_ns": mono - 1_000 - m, "mono_ns": mono, "raw2_ns": mono - 1_000 - m})
    adj = e2e.adjustment(board)
    # the windows start at 7, 8 and 9 s: first and last sample 0.9 s apart; in the second m goes from 0 to 1,800 ns: 2 ppm
    assert adj == {"adj_ppm_min": 0, "adj_ppm_max": 2, "adj_ppm_median": 0, "adj_step_ppm_max": 2, "adj_offset_range_us": 2, "adjusted": 1}
    # a rate range of 0.9 ppm is not 'adjusted' (more than 1 ppm is); one window gives a step of 0; no window gives no rate
    less = e2e.clock_map({"raw1_ns": mono - 1_000 - m * 9 // 20, "mono_ns": mono, "raw2_ns": mono - 1_000 - m * 9 // 20})
    assert (e2e.adjustment(less)["adj_ppm_max"], e2e.adjustment(less)["adjusted"]) == (pytest.approx(0.9), 0)
    one = e2e.clock_map({k: v[:10] for k, v in {"raw1_ns": mono, "mono_ns": mono, "raw2_ns": mono}.items()})
    assert e2e.adjustment(one) == {"adj_ppm_min": 0, "adj_ppm_max": 0, "adj_ppm_median": 0, "adj_step_ppm_max": 0,
                                   "adj_offset_range_us": 0, "adjusted": 0}
    none = e2e.clock_map({k: v[:5] for k, v in {"raw1_ns": mono, "mono_ns": mono, "raw2_ns": mono}.items()})
    assert e2e.adjustment(none) == {"adj_ppm_min": None, "adj_ppm_max": None, "adj_ppm_median": None, "adj_step_ppm_max": 0,
                                    "adj_offset_range_us": 0, "adjusted": None}


def test_the_rules_of_the_final_ruling_hold_on_the_raw_track():
    # the coverage rule on the raw clocks: PDUs released from 4 s have one anchor before them (anchors at 0, 5.05, ... s)
    res, reasons = e2e.analyse(*arrays(steady(first=4_000 * MS)))
    assert res is None and reasons == ["fewer than two anchors lie at or before the first release"]
    res, reasons = e2e.analyse(*arrays(steady(pdus=2400)))                # delivered until 36 s: one anchor behind
    assert res is None and reasons == ["fewer than two anchors lie at or after the last delivery"]
    # a total bound above 100 us: delays of 100.2 us each way give an offset bound of 100.2, the maps add 0.2
    res, reasons = e2e.analyse(*arrays(steady(forward=100_200, back=100_200)))
    assert res is None and reasons == ["bound_total_us = 100.4 exceeds 100 (offset_bound_total_us 100.2 + map_a.bound_us 0.1 + "
                                       "map_b.bound_us 0.1)"]
    # exactly 100 passes: 99.8 + 0.1 + 0.1
    res, reasons = e2e.analyse(*arrays(steady(forward=99_800, back=99_800)))
    assert reasons == [] and res["bound_total_us"] == pytest.approx(100, abs=1e-9) and res["offset_bound_total_us"] == 99.8
    # causality against the total bound: a reception read 50.3 us before the send is beyond 50.2
    tx, rx, probe, maps = arrays(steady())
    rx["rx_done_ns"][700] -= 450_300
    res, reasons = e2e.analyse(tx, rx, probe, maps)
    assert res is None and reasons[0].startswith("causality_violations = 1: ") and "(50.2 us)" in reasons[0]
    rx["rx_done_ns"][700] += 200                                         # 50.1 us before: inside
    res, reasons = e2e.analyse(tx, rx, probe, maps)
    assert reasons == [] and (res["causality_min_us"], res["causality_violations"]) == (pytest.approx(-50.1, abs=1e-6), 0)
    # a probe with a gap of more than a second, on the raw stamps
    run = steady()
    run["probe"] = [row for row in run["probe"] if not 150 < row[0] < 162]   # 12 x 101 ms, and 40 us: 150 is a quick one
    res, reasons = e2e.analyse(*arrays(run))
    assert res is None and reasons == ["probe_gap_max_ms = 1212.04 exceeds 1000: the probe has a gap of more than 1 s"]


# ---- a generated run as files, through make_tables ---------------------------------------------------------------------

import csv  # noqa: E402

from analysis import make_tables  # noqa: E402
from analysis.tests.test_make_tables import PARAMS  # noqa: E402


def test_the_steered_run_as_files(tmp_path):
    """The run of known answer 1 written as a run directory: the keys are those of the arrays, and the printed forms
    are what the documents get."""
    run = steered()
    d = tmp_path / "run" / "periodic"
    d.mkdir(parents=True)
    head = ("tool=bench_clock_probe", "commit=abc1234abc12", "host_a=iris", "host_b=baolong", "clock=CLOCK_MONOTONIC", "format=2",
            "clock_raw=CLOCK_MONOTONIC_RAW", "interval_ms=101", "port=50123", "cpu_a=1", "cpu_b=1")
    n = len(run["probe"])
    (d / "periodic_tx.csv").write_text(synth.text(synth.TX_HEADER, run["tx"], synth.tx_meta(1)))
    (d / "periodic_rx.csv").write_text(synth.text(synth.RX_HEADER, run["rx"]))
    (d / "clock_probe.csv").write_text(synth.text(synth.PROBE2_HEADER, run["probe"], head, (f"exchanges_sent={n}", f"exchanges_completed={n}")))
    for x in "ab":
        rows = run["map_" + x]
        map_head = ("tool=bench_clock_probe", "commit=abc1234abc12", f"host={'iris' if x == 'a' else 'baolong'}", f"role={x}",
                    "clock=CLOCK_MONOTONIC", "clock_raw=CLOCK_MONOTONIC_RAW", "interval_ms=5", "cpu=1")
        (d / f"clock_map_{x}.csv").write_text(synth.text(synth.MAP_HEADER, rows, map_head, (f"samples={len(rows)}", "samples_dropped=0")))
    s = make_tables.run(tmp_path / "run", tmp_path / "out", **PARAMS)
    assert s["invalid_runs"] == [] and s["skipped_csv"] == []
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        rows = {r["key"].removeprefix("periodic.p10ms-s1-c1-mldsa65-fifo.e2e."): r for r in csv.DictReader(f) if ".e2e." in r["key"]}
    assert len(rows) == 60                                 # 61 less mono.latency_p50_diff_us: the monotonic columns give no result
    want, _ = e2e.analyse(*arrays(run))
    assert float(rows["bound_total_us"]["value"]) == want["bound_total_us"] and float(rows["latency_p50_ms"]["value"]) == want["latency_ms"]["p50"]
    shown = {k: r["formatted"] for k, r in rows.items()}
    assert {k: shown[k] for k in ("n", "latency_p50_ms", "latency_max_ms", "offset_bound_total_us", "map_a.bound_us", "map_b.bound_us",
                                  "bound_total_us", "map_b.holdout_us", "map_b.half_us", "map_b.kink_us", "map_b.gap_max_ms", "map_b.check_n",
                                  "clock_a.adjusted", "clock_b.adjusted", "clock_b.adj_ppm_max", "clock_b.adj_ppm_min",
                                  "clock_b.adj_offset_range_us", "mono.verdict", "probe_width_max_ns", "drift_ppm")} == {
        "n": "1{,}600", "latency_p50_ms": "4.00", "latency_max_ms": "4.00", "offset_bound_total_us": "50.0", "map_a.bound_us": "0.1",
        "map_b.bound_us": "11.6", "bound_total_us": "61.7", "map_b.holdout_us": "11.5", "map_b.half_us": "0.1",
        "map_b.kink_us": "6.3",
        "map_b.gap_max_ms": "5.02", "map_b.check_n": "318", "clock_a.adjusted": "0", "clock_b.adjusted": "1",
        "clock_b.adj_ppm_max": r"\ensuremath{+}5{,}000.00", "clock_b.adj_ppm_min": "0.00", "clock_b.adj_offset_range_us": "50{,}251",
        "mono.verdict": "0", "probe_width_max_ns": "400", "drift_ppm": r"\ensuremath{-}25.0"}
    table = (tmp_path / "out" / "tables" / "e2e.md").read_text()
    # 1,600 PDUs: fewer than ten lie above the 99.9th percentile, so the table prints a dash there
    assert "| periodic/periodic_tx.csv | p10ms-s1-c1-mldsa65-fifo | 1600 | 4.000 | 4.000 | – | 4.001 | 1.000 | 61.7 |" in table
