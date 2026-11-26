"""E9, end-to-end latency across the two boards (E9_SPEC.md, 'Interface details'): the offset track of clock_probe.csv and
the per-PDU quantities, on synthetic exchanges whose true offset is known."""
import numpy as np
import pytest

from analysis import e2e

A0 = 119_899_302_191_756           # clock A at the first exchange: the size of the spec's example row
THETA0 = -19_958_353_450_209       # clock B minus clock A there
US, MS, SEC = 1_000, 1_000_000, 1_000_000_000


def exchanges(n=200, step=100 * MS, forward=50 * US, back=50 * US, served=18 * US, theta=lambda t: THETA0, skip=(), start=A0):
    """Completed exchanges, one every `step` on clock A: the request takes `forward` ns to B, B replies `served` ns
    later, the reply takes `back` ns. `forward` and `back` may be functions of the exchange number; `theta(t)` is the
    true offset, clock B minus clock A, at the time t of clock A. Exchanges in `skip` were lost."""
    rows = []
    for i in range(n):
        if i in skip:
            continue
        f, r = (v(i) if callable(v) else v for v in (forward, back))
        t1 = start + i * step
        arrive, leave = t1 + f, t1 + f + served
        rows.append((i, t1, arrive + theta(arrive), leave + theta(leave), leave + r))
    return {k: np.array(v, dtype=np.int64) for k, v in zip(("seq", "t1_ns", "t2_ns", "t3_ns", "t4_ns"), zip(*rows))}


def PINNED(i):
    """Delays that pin the anchors: every fiftieth exchange takes 10 us each way, the others 50 us."""
    return (10 if i % 50 == 0 else 50) * US


def pdus(n=40, first=A0 + 6 * SEC, period=10 * MS, response=3 * MS, wire=400 * US, receive=600 * US, theta=lambda t: THETA0):
    """`n` jobs of one stream on board A (released every `period`, sent `response` later) and their rows on board B:
    received `wire` ns after the send, delivered `receive` ns after that. True latency = response + wire + receive."""
    release = first + period * np.arange(n, dtype=np.int64)
    sent = release + response
    rx_done = sent + wire + np.array([theta(int(t)) for t in sent + wire], dtype=np.int64)
    deliver = sent + wire + receive + np.array([theta(int(t)) for t in sent + wire + receive], dtype=np.int64)
    tx = {"stream": np.array(["0"] * n), "seq": np.arange(n, dtype=np.int64), "release_ns": release, "send_done_ns": sent}
    rx = {"stream": np.array(["0"] * n), "seq": np.arange(n, dtype=np.int64), "rx_done_ns": rx_done,
          "verify_done_ns": rx_done + receive - 20 * US, "deliver_ns": deliver, "result": np.array(["ok"] * n, dtype="<U14")}
    return tx, rx


def test_known_offset_gives_the_true_latency(tmp_path):
    """Equal delays in both directions: every exchange gives the true offset, and the latency of a PDU is the true one."""
    probe = exchanges()
    tr = e2e.track(probe)
    # 200 exchanges of 100 ms from the first tau: four windows of 5 s with 50 each; equal delays, so the earliest is the anchor
    assert (tr["anchors"], tr["probes_completed"], tr["anchor_seq"].tolist()) == (4, 200, [0, 50, 100, 150])
    assert tr["offset_bound_us"] == 50 and tr["probe_delay_min_us"] == tr["probe_delay_p50_us"] == 100  # delta = 50 + 50 us
    assert tr["probe_gap_max_ms"] == 100 and tr["drift_ppm"] == 0
    res, reasons = e2e.analyse_mono(*pdus(), probe)
    assert reasons == [] and res["n"] == 40
    assert res["latency_ms"] == {"mean": 4.0, "p50": 4.0, "p90": 4.0, "p99": 4.0, "p99.9": 4.0, "max": 4.0}  # 3 + 0.4 + 0.6 ms
    assert res["rxpart_ms"] == {"p50": 1.0, "p99": 1.0, "max": 1.0}                                     # 0.4 + 0.6 ms
    assert (res["causality_min_us"], res["causality_violations"]) == (400, 0)                           # rx_done - send_done
    assert (res["offset_cert_us"], res["offset_bound_total_us"], res["exchanges_outside"]) == (50, 50, 0)
    assert {k: res[k] for k in ("offset_bound_us", "anchors", "probes_completed", "probe_gap_max_ms", "drift_ppm")} == {
        "offset_bound_us": 50, "anchors": 4, "probes_completed": 200, "probe_gap_max_ms": 100, "drift_ppm": 0}


def test_known_drift_is_followed_between_the_anchors():
    """Clock B gains 20 ppm on clock A: 100 us per 5 s window. The straight line between the anchors follows it; the
    offset of the nearest anchor alone would be off by up to 50 us. The spec takes theta at the sender's time stamp, so
    what the offset gains while the PDU is under way stays in the figure: 20 ppm of 4 ms is 80 ns, of 1 ms 20 ns."""
    def drifting(t):
        return THETA0 + (t - A0) * 20 // 1_000_000
    probe = exchanges(forward=PINNED, back=PINNED, theta=drifting)   # anchors at 0, 5, 10 and 15 s
    tr = e2e.track(probe)
    assert tr["drift_ppm"] == pytest.approx(20, abs=1e-3) and tr["offset_bound_us"] == 10
    res, reasons = e2e.analyse_mono(*pdus(n=300, theta=drifting), probe)      # 3 s of PDUs, from the second window into the third
    assert reasons == [] and res["n"] == 300
    for stat in ("mean", "p50", "max"):  # to the rounding of the time stamps to whole nanoseconds
        assert res["latency_ms"][stat] == pytest.approx(4.000080, abs=5e-6)
    assert res["rxpart_ms"]["p50"] == pytest.approx(1.000020, abs=5e-6) and res["causality_min_us"] == pytest.approx(400.008, abs=5e-3)


def test_asymmetric_delay_keeps_the_truth_inside_the_bound():
    """80 us to B and 20 us back: every offset sample is 30 us off, and the true offset still lies within theta +- delta/2.
    The latency is off by the same 30 us, inside the bound of 50 us that is printed beside it."""
    probe = exchanges(forward=80 * US, back=20 * US)
    tr = e2e.track(probe)
    theta, half = tr["theta_ns"], tr["delay_ns"] / 2
    assert np.all(np.abs(theta - THETA0) <= half) and np.all(theta - THETA0 == 30 * US) and tr["offset_bound_us"] == 50
    res, reasons = e2e.analyse_mono(*pdus(), probe)
    assert reasons == []
    error_us = (res["latency_ms"]["p50"] - 4.0) * 1000
    assert error_us == pytest.approx(-30) and abs(error_us) <= res["offset_bound_us"]
    assert res["causality_min_us"] == pytest.approx(370)  # the wire time of 400 us reads 30 us short, far above -50


def test_the_anchor_of_a_window_is_its_exchange_with_the_smallest_delay():
    """Delays of 40 + 40 us, except exchanges 7 and 9 (10 + 10 us: a tie, the earlier one is the anchor), exchange 60
    (30 + 10 us) and exchange 120 (5 + 5 us). The bound is the largest half delay among the anchors of the region, the
    second to the second-to-last one (here 20 us, exchange 60): not the 40 us of the last anchor, which only delimits,
    and not among all exchanges."""
    quick = {7: (10, 10), 9: (10, 10), 60: (30, 10), 120: (5, 5)}
    probe = exchanges(forward=lambda i: quick.get(i, (40, 40))[0] * US, back=lambda i: quick.get(i, (40, 40))[1] * US)
    tr = e2e.track(probe)
    assert tr["anchor_seq"].tolist() == [7, 60, 120, 150]      # the last window has no quick exchange: its first one
    assert (tr["offset_bound_us"], tr["probe_delay_min_us"], tr["probe_delay_p50_us"]) == (20, 10, 80)
    # exchange 60 is 10 us off (asymmetric), the others are exact: the track is the straight line through them
    assert (tr["theta_ns"][tr["anchor"]] - THETA0).tolist() == [0, 10 * US, 0, 0]


def test_a_gap_of_more_than_a_second_is_not_a_result():
    """Exchanges 20 to 28 lost: 1,000 ms between two completed exchanges, which passes; with exchange 29 lost as well
    it is 1,100 ms. A window without any exchange has no anchor."""
    res, reasons = e2e.analyse_mono(*pdus(), exchanges(skip=range(20, 29)))
    assert reasons == [] and res["probe_gap_max_ms"] == 1000 and res["probes_completed"] == 191
    res, reasons = e2e.analyse_mono(*pdus(), exchanges(skip=range(20, 30)))
    assert res is None and reasons == ["probe_gap_max_ms = 1100 exceeds 1000: the probe has a gap of more than 1 s"]
    tr = e2e.track(exchanges(skip=range(50, 100)))  # the whole second window
    assert (tr["anchors"], tr["anchor_seq"].tolist(), tr["probe_gap_max_ms"]) == (3, [0, 100, 150], 5100)


def test_a_pdu_received_before_it_was_sent_is_not_a_result():
    """The bound is 50 us. A PDU whose reception reads exactly 50 us before its send is at the limit and passes; one
    nanosecond more is a violation, and one violation excludes the run."""
    tx, rx = pdus()
    rx["rx_done_ns"][5] = tx["send_done_ns"][5] + THETA0 - 50 * US
    res, reasons = e2e.analyse_mono(tx, rx, exchanges())
    assert reasons == [] and (res["causality_min_us"], res["causality_violations"]) == (-50, 0)
    rx["rx_done_ns"][5] -= 1
    res, reasons = e2e.analyse_mono(tx, rx, exchanges())
    assert res is None and reasons == ["causality_violations = 1: a delivered PDU was received more than the total offset "
                                       "bound (50 us) before it was sent; smallest margin -50.001 us"]


def test_the_offset_bound_and_the_coverage_rules():
    # delays of 100 + 100 us: the bound is exactly 100 us and passes; one nanosecond more in each direction does not
    res, reasons = e2e.analyse_mono(*pdus(), exchanges(forward=100 * US, back=100 * US))
    assert reasons == [] and res["offset_bound_us"] == 100
    res, reasons = e2e.analyse_mono(*pdus(), exchanges(forward=100 * US + 1, back=100 * US + 1))
    assert res is None and reasons == ["offset_bound_total_us = 100.001 exceeds 100"]
    # coverage (amendment 1a): two anchors at or before the first release and two at or after the last delivery. The
    # anchors are at 0, 5, 10 and 15 s. A first release 1 ms after the second anchor passes; one at 4 s does not
    assert e2e.analyse_mono(*pdus(first=A0 + 5 * SEC + MS), exchanges())[1] == []
    assert e2e.analyse_mono(*pdus(first=A0 + 4 * SEC), exchanges()) == (None, ["fewer than two anchors lie at or before the first release"])
    # PDUs released until 11 s are delivered after the third anchor (10 s): only one anchor lies behind them
    assert e2e.analyse_mono(*pdus(n=500), exchanges()) == (None, ["fewer than two anchors lie at or after the last delivery"])
    # with fewer than four anchors nothing can be said
    assert e2e.analyse_mono(*pdus(), exchanges(n=140)) == (None, ["3 anchor(s) in the probe file: fewer than four"])
    # nothing delivered, or a delivered PDU without a send time: no latency can be formed
    tx, rx = pdus()
    rx["result"][:] = "auth_fail"
    assert e2e.analyse_mono(tx, rx, exchanges()) == (None, ["no delivered PDU of the receiver's file is in the sender's file"])
    tx, rx = pdus()
    tx["send_done_ns"][3] = 0
    assert e2e.analyse_mono(tx, rx, exchanges())[1] == ["1 delivered PDU(s) whose row in the sender's file has no send_done_ns"]


def test_rows_join_on_stream_and_seq_and_only_ok_rows_count():
    """Two streams whose rows are not in the same order in the two files; a rejected row and a row the sender never
    logged take no part."""
    tx, rx = pdus(n=6)
    tx["stream"] = np.array(["0", "0", "0", "1", "1", "1"])
    tx["seq"] = np.array([0, 1, 2, 0, 1, 2])
    order = np.array([4, 0, 5, 2, 1, 3])
    rx = {k: (tx[k] if k in ("stream", "seq") else v)[order] for k, v in rx.items()}
    rx["result"][0] = "freshness_fail"          # stream 1 seq 1
    rx["seq"][2] = 9                             # stream 1 seq 9: not in the sender's file
    res, reasons = e2e.analyse_mono(tx, rx, exchanges())
    assert reasons == [] and res["n"] == 4 and res["latency_ms"]["max"] == res["latency_ms"]["p50"] == 4.0


def test_too_few_exchanges_a_contradicting_exchange_or_a_repeated_job_are_not_a_result():
    """Rulings of 2026-11-24: a probe file with fewer than two completed exchanges, or with a row that contradicts
    itself, is invalid (listed, no key), not an error that stops the run. A sender whose rows repeat a stream and seq
    (a gateway that was started again) gives no unique row to join."""
    assert e2e.analyse_mono(*pdus(), exchanges(n=1)) == (None, ["1 completed exchange(s) in the probe file: fewer than two"])
    assert e2e.analyse_mono(*pdus(), {k: v[:0] for k, v in exchanges().items()}) == (
        None, ["0 completed exchange(s) in the probe file: fewer than two"])
    probe = exchanges()
    probe["t4_ns"][3] = probe["t1_ns"][3] - 1
    assert e2e.analyse_mono(*pdus(), probe) == (None, ["the probe file contradicts itself: data row 4: an exchange needs t1 <= t4, "
                                                  "t2 <= t3 and a delay (t4 - t1) - (t3 - t2) that is not negative"])
    tx, rx = pdus()
    tx["seq"][7] = 3
    assert e2e.analyse_mono(tx, rx, exchanges()) == (None, ["the sender's rows have a stream and seq more than once: the receiver's "
                                                       "rows cannot be joined"])


@pytest.mark.parametrize("column, value", [("t4_ns", A0 - 1), ("t3_ns", A0 + THETA0), ("t4_ns", A0 + 10 * US)])
def test_an_exchange_that_contradicts_itself_is_an_error(column, value):
    """t4 before t1, t3 before t2, or a reply that arrives sooner than the server held it (a negative delay)."""
    probe = exchanges()
    probe[column][0] = value
    with pytest.raises(ValueError, match="data row 1"):
        e2e.track(probe)


# ---- through make_tables: files, keys, the table, and what a run without the probe keeps -------------------------------

import csv  # noqa: E402

from analysis import make_tables  # noqa: E402
from analysis.tests import synth  # noqa: E402
from analysis.tests.test_make_numbers import SUMMARY_ONLY, uncovered  # noqa: E402
from analysis.tests.test_make_tables import PARAMS  # noqa: E402

LATER = 20_000 * MS  # the synthetic jobs start at 1 s; two anchors must lie before the first release, so they run 20 s later


def later(row):
    """A sender's row (stream, seq, release, start, auth_done, send_done) with its times LATER."""
    return (*row[:2], *(t + LATER for t in row[2:]))


JOBS = [later(synth._job(0, s, 0, 3)) for s in range(12)]  # released at 21.00 .. 21.11 s of clock A, sent 3 ms later
TWO_STREAMS = [later(r) for r in synth.periodic_tx_rows()]  # the two-stream file of synth, as late
HEAD = ("tool=bench_clock_probe", "commit=abc1234abc12", "host_a=iris", "host_b=baolong", "clock=CLOCK_MONOTONIC",
        "interval_ms=500", "port=50123", "cpu_a=1", "cpu_b=1")


# each board's CLOCK_MONOTONIC minus its raw clock, steady; negative, because the synthetic clocks start near zero
RAW_BEHIND = {"a": -3_456_789_013, "b": -1_234_567_891}
HEAD2 = (*HEAD, "format=2", "clock_raw=CLOCK_MONOTONIC_RAW")
BURST = [21_002 * MS + k * 1_800 * US for k in range(60)]  # exchanges around the synthetic jobs, 21.002 s to 21.108 s


def probe_file(quick=30, slow=50, n=62, completed=None, shift=0, footer=True, raw=True, burst=BURST):
    """clock_probe.csv for the synthetic pair, whose receiver clock is 7 s ahead (synth.RX_AHEAD): an exchange every
    500 ms from 0.1 s to 30.6 s of clock A, `slow` us each way (the first one `quick` us each way), the server holding
    it 20 us. Seven windows of 5 s, their anchors the exchanges 0, 10, .., 60 at 0.1, 5.1, .., 30.1 s: five lie before
    the first release (21.0 s) and two after the last delivery.

    Format 2 (Addendum E), unless `raw` is False: each board's CLOCK_MONOTONIC is its raw clock plus RAW_BEHIND, the raw
    stamps follow from that and every point has width 0. A probe that runs beyond the jobs also has the sixty exchanges
    of BURST around them (`slow` us each way, so no anchor moves): the points that check the maps, 120 on each board."""
    times = [100 * MS + i * 500 * MS + shift for i in range(n)]
    times += burst if raw and times[-1] > BURST[-1] else []
    rows = []
    for i, t1 in enumerate(times):
        way = (quick if i == 0 else slow) * US
        row = (i, t1, t1 + way + synth.RX_AHEAD, t1 + way + 20 * US + synth.RX_AHEAD, t1 + 2 * way + 20 * US)
        rows.append((*row, *(t - RAW_BEHIND[x] for t, x in zip(row[1:], "abba")), 0, 0, 0, 0) if raw else row)
    tail = (f"exchanges_sent={len(rows)}", f"exchanges_completed={len(rows) if completed is None else completed}") if footer else ()
    return synth.text(synth.PROBE2_HEADER if raw else "seq,t1_ns,t2_ns,t3_ns,t4_ns", rows, HEAD2 if raw else HEAD, tail)


def clock_maps(dropped=0, **change):
    """clock_map_a.csv and clock_map_b.csv for the synthetic pair: a sample every 5 ms from 20.5 s to 22.0 s of clock A
    (the jobs lie at 21.0 to 21.13 s), width 0, each board's CLOCK_MONOTONIC its raw clock plus RAW_BEHIND. `change` maps
    a file name to a function of its rows; `dropped` is the samples_dropped line of board B's file."""
    files = {}
    for x, ahead in (("a", 0), ("b", synth.RX_AHEAD)):
        name = f"clock_map_{x}.csv"
        rows = [(t - RAW_BEHIND[x], t, t - RAW_BEHIND[x]) for t in (20_500 * MS + ahead + k * 5 * MS for k in range(301))]
        rows = change[name](rows) if name in change else rows
        head = ("tool=bench_clock_probe", "commit=abc1234abc12", f"host={'iris' if x == 'a' else 'baolong'}", f"role={x}",
                "clock=CLOCK_MONOTONIC", "clock_raw=CLOCK_MONOTONIC_RAW", "interval_ms=5", "cpu=1")
        files[name] = synth.text(synth.MAP_HEADER, rows, head, (f"samples={len(rows)}", f"samples_dropped={dropped if x == 'b' else 0}"))
    return files


# the keys Addendum E adds to a run of the synthetic pair: steady clocks and widths of 0, so both maps are exact; 301
# samples per board; the check points are the two points per board of the 60 exchanges of BURST and of the one at 21.1 s
RAW_KEYS = {"bound_total_us": 50, "probe_format": 2, "probe_width_p50_ns": 0, "probe_width_max_ns": 0,
            **{f"map_{x}.{k}": v for x in "ab" for k, v in (
                ("samples", 301), ("samples_invalid", 0), ("gap_max_ms", 5), ("holdout_us", 0), ("kink_us", 0), ("half_us", 0),
                ("bound_us", 0),
                ("check_n", 122), ("check_max_us", 0), ("check_violations", 0))},
            # one window of 1 s has samples 0.8 s apart (20.5 s to 21.495 s): one rate, 0
            **{f"clock_{x}.{k}": 0 for x in "ab" for k in ("adj_ppm_min", "adj_ppm_max", "adj_ppm_median", "adj_step_ppm_max",
                                                           "adj_offset_range_us", "adjusted")},
            "mono.verdict": 1, "mono.offset_bound_total_us": 50, "mono.latency_p50_diff_us": 0}


def write_probe(d, probe=None, maps=None):
    """The probe file in `d` (format 2 unless given otherwise) with the clock maps of the two boards beside it."""
    (d / "clock_probe.csv").write_text(probe_file() if probe is None else probe)
    for name, text in (clock_maps() if maps is None else maps).items():
        (d / name).write_text(text)


def run(tmp_path, name, probe=None, rx_rows=None, rx_comments=(), maps=None):
    d = tmp_path / name / "periodic"
    d.mkdir(parents=True)
    (d / "periodic_tx.csv").write_text(synth.text(synth.TX_HEADER, JOBS, synth.tx_meta(1)))
    (d / "periodic_rx.csv").write_text(synth.text(synth.RX_HEADER, [synth.rx_row(r) for r in JOBS] if rx_rows is None else rx_rows,
                                                  rx_comments))
    if probe is not None:
        write_probe(d, probe, maps)
    s = make_tables.run(tmp_path / name, tmp_path / (name + "_out"), **PARAMS)
    with open(tmp_path / (name + "_out") / "numbers.csv", newline="") as f:
        return s, {r["key"]: r for r in csv.DictReader(f)}


def test_a_periodic_run_with_a_clock_probe_gets_the_e2e_keys_and_keeps_every_other_key(tmp_path):
    plain, without = run(tmp_path, "plain")
    s, rows = run(tmp_path, "probed", probe_file())
    assert s["invalid_runs"] == [] and plain["invalid_runs"] == []
    new = {k: r for k, r in rows.items() if k not in without}
    assert {k: (r["value"], r["formatted"]) for k, r in rows.items() if k in without} == \
        {k: (r["value"], r["formatted"]) for k, r in without.items()}                      # nothing else moved
    base = "periodic.p10ms-s1-c1-mldsa65-fifo.e2e."
    assert all(k.startswith(base) for k in new)
    # each PDU: 3 ms to the send, 0.5 ms to the reception, 0.45 ms to the delivery; the anchors' delays are 60 and 100 us
    assert {k.removeprefix(base): float(r["value"]) for k, r in new.items()} == pytest.approx({
        "n": 12, "latency_mean_ms": 3.95, "latency_p50_ms": 3.95, "latency_p90_ms": 3.95, "latency_p99_ms": 3.95,
        "latency_p99_9_ms": 3.95, "latency_max_ms": 3.95, "rxpart_p50_ms": 0.95, "rxpart_p99_ms": 0.95, "rxpart_max_ms": 0.95,
        "offset_bound_us": 50, "offset_cert_us": 50, "offset_bound_total_us": 50, "exchanges_outside": 0,
        "anchors": 7, "probes_completed": 122, "probe_delay_min_us": 60, "probe_delay_p50_us": 100,
        "probe_gap_max_ms": 500.02, "drift_ppm": 0, "causality_min_us": 500, "causality_violations": 0, **RAW_KEYS})
    assert len(new) == 61                                                                  # the 22 of the FINAL ruling and 39 of Addendum E
    assert new[base + "latency_max_ms"]["formatted"] == "3.95"
    # every bound prints one decimal, so that the printed terms add up to the printed total within rounding; the
    # adjustment rates print two, the widths whole nanoseconds
    assert [new[base + k]["formatted"] for k in ("offset_bound_us", "offset_cert_us", "offset_bound_total_us", "map_a.bound_us",
                                                  "map_b.bound_us", "bound_total_us")] == ["50.0", "50.0", "50.0", "0.0", "0.0", "50.0"]
    assert [new[base + k]["formatted"] for k in ("clock_b.adj_ppm_max", "probe_width_max_ns", "map_a.gap_max_ms")] == ["0.00", "0", "5.00"]
    assert new[base + "n"]["source_file"] == "periodic/clock_probe.csv"
    assert new[base + "map_b.samples"]["source_file"] == "periodic/clock_map_b.csv"
    # twelve PDUs: no percentile has ten samples above it, so they stay in numbers.csv and are no macros; the maximum is one
    tex = (tmp_path / "probed_out" / "numbers.tex").read_text()
    assert base + "latency_max_ms" in tex and base + "latency_p50_ms" not in tex and base + "latency_p99_9_ms" not in tex
    # the diagnostic keys of the monotonic columns are in numbers.csv and never a macro
    held_back = (tmp_path / "probed_out" / "suppressed_keys.txt").read_text()
    for k in ("mono.verdict", "mono.offset_bound_total_us", "mono.latency_p50_diff_us"):
        assert base + k not in tex and f"{base + k}\tdiagnostic of Addendum E" in held_back
    assert base + "bound_total_us" in tex and base + "clock_b.adjusted" in tex
    assert "bound_total_us" in new[base + "latency_p50_ms"]["how"] and "2,000 ms" in new[base + "offset_cert_us"]["how"]
    assert "CLOCK_MONOTONIC_RAW" in new[base + "latency_p50_ms"]["how"]
    for key, words in (("latency_p50_ms", "deliver_ns - theta(release_ns) - release_ns"), ("offset_bound_us", "delta / 2"),
                       ("rxpart_p50_ms", "deliver_ns - theta(send_done_ns) - send_done_ns"),
                       ("causality_min_us", "rx_done_ns - theta(send_done_ns) - send_done_ns"), ("drift_ppm", "least squares")):
        assert words in new[base + key]["how"]
    assert not [leaf for leaf in uncovered(s["results"], SUMMARY_ONLY)[0] if "e2e" in leaf]  # every figure has its key
    table = (tmp_path / "probed_out" / "tables" / "e2e.md").read_text()
    assert "| periodic/periodic_tx.csv | p10ms-s1-c1-mldsa65-fifo | 12 | – | – | – | 3.950 | – | 50.0 |" in table
    assert not (tmp_path / "plain_out" / "tables" / "e2e.md").exists() and "e2e" not in plain["results"]["periodic"][0]


def test_a_run_that_breaks_an_e9_rule_is_listed_and_gets_no_e2e_key(tmp_path):
    def listed(name, probe, **kw):
        s, rows = run(tmp_path, name, probe, **kw)
        without = run(tmp_path, name + "_without_the_probe", **kw)[1]
        assert {k: r["value"] for k, r in rows.items()} == {k: r["value"] for k, r in without.items()}  # the pair's keys stay
        return [(f["source"], f["experiment"], f["reasons"]) for f in s["invalid_runs"]]

    probe = "periodic/clock_probe.csv"
    # every exchange 101 us each way: the anchors' delay is 202 us
    assert listed("bound", probe=probe_file(quick=101, slow=101)) == [(probe, "e2e", [
        "bound_total_us = 101 exceeds 100 (offset_bound_total_us 101 + map_a.bound_us 0 + map_b.bound_us 0)"])]
    # ... while one slow exchange is simply not an anchor: the run is a result, with a bound of 50 us
    s, rows = run(tmp_path, "one_slow", probe_file(quick=101))
    assert s["invalid_runs"] == [] and rows["periodic.p10ms-s1-c1-mldsa65-fifo.e2e.offset_bound_us"]["value"] == "50.0"
    # the probe started 17 s late: only its first anchor (17.1 s) lies before the first release (21.0 s)
    assert listed("late", probe=probe_file(shift=17_000 * MS)) == [
        (probe, "e2e", ["fewer than two anchors lie at or before the first release"])]
    # the probe ended at 25.6 s: only the anchor at 25.1 s lies after the last delivery
    assert listed("short", probe=probe_file(n=52)) == [(probe, "e2e", ["fewer than two anchors lie at or after the last delivery"])]
    # the probe ended at 14.6 s: three anchors
    assert listed("few", probe=probe_file(n=30)) == [(probe, "e2e", ["3 anchor(s) in the probe file: fewer than four"])]
    # a PDU received 60 us before it was sent, beyond the bound of 50 us
    early = [synth.rx_row(r, latency_us=-60 if r[1] == 4 else 500, verify_us=990 if r[1] == 4 else 430) for r in JOBS]
    assert listed("early", probe=probe_file(), rx_rows=early) == [(probe, "e2e", [
        "causality_violations = 1: a delivered PDU was received more than the total bound (50 us) before it was "
        "sent; smallest margin -60 us"])]
    # the footer of the probe file: the count of its rows, as for every file (CAMPAIGN.md, 'Invalid files')
    assert listed("cut", probe=probe_file(completed=63)) == [(probe, "e2e", ["exchanges_completed=63, but the file has 122 rows"])]
    assert listed("no_footer", probe=probe_file(footer=False)) == [
        (probe, "e2e", ["no exchanges_completed line: the probe did not write its footer"])]
    # a receiver's file without reception time stamps: the causality rule cannot be judged
    silent = [(*synth.rx_row(r)[:2], 0, *synth.rx_row(r)[3:]) for r in JOBS]
    assert listed("silent", probe=probe_file(), rx_rows=silent, rx_comments=("not_recorded=rx_done_ns",)) == [
        (probe, "e2e", ["rx_done_ns is declared not recorded in periodic_rx.csv: the causality rule cannot be judged"])]
    # Addendum E, known answer 6: a map that lost samples
    assert listed("dropped", probe=probe_file(), maps=clock_maps(dropped=3)) == [
        (probe, "e2e", ["clock_map_b.csv: samples_dropped=3: the probe lost samples of the map"])]
    # a map that is not there, one whose footer is missing, one whose count of its samples is wrong
    only_a = {k: v for k, v in clock_maps().items() if k == "clock_map_a.csv"}
    assert listed("no_map", probe=probe_file(), maps=only_a) == [(probe, "e2e", ["clock_map_b.csv is missing beside the probe file of format 2"])]
    cut = {**clock_maps(), "clock_map_a.csv": clock_maps()["clock_map_a.csv"].split("# samples=")[0]}
    assert listed("map_cut", probe=probe_file(), maps=cut) == [
        (probe, "e2e", ["clock_map_a.csv: no samples line: the probe did not write its footer"])]
    wrong = {**clock_maps(), "clock_map_a.csv": clock_maps()["clock_map_a.csv"].replace("# samples=301", "# samples=300")}
    assert listed("map_count", probe=probe_file(), maps=wrong) == [(probe, "e2e", ["clock_map_a.csv: samples=300, but the file has 301 rows"])]
    # the samples from 21.025 s to 21.075 s missing in board A's map: 60 ms without a sample where the stamps are
    holed = clock_maps(**{"clock_map_a.csv": lambda rows: rows[:105] + rows[116:]})
    assert listed("map_gap", probe=probe_file(), maps=holed) == [(probe, "e2e", [
        "map_a.gap_max_ms = 60 exceeds 50: clock_map_a.csv has a gap between two valid samples in the range the stamps use"])]
    # known answer 7: a probe file of format 1 is refused for the latency, by name; its maps, if any, are not read
    assert listed("format_1", probe=probe_file(raw=False), maps={}) == [(probe, "e2e", [e2e.FORMAT_1])]
    assert "format 1" in e2e.FORMAT_1
    # too few exchange points where the stamps are: 12 exchanges of the burst and the one at 21.1 s give 26 per board,
    # which a harness run does not accept (100) ...
    assert listed("points", probe=probe_file(burst=BURST[:12])) == [(probe, "e2e", [
        f"map_{x}.check_n = 26: fewer than 100 exchange points of board {x.upper()} in the range the stamps use" for x in "ab"])]
    # E12.2: the three probe files must be those of one run. One reason per line that is not what it must be
    maps = clock_maps()

    def changed(name, old, new):
        assert old in maps[name]
        return {**maps, name: maps[name].replace(old, new)}

    for case, files, why in (
            ("role", changed("clock_map_a.csv", "# role=a\n", "# role=b\n"), "clock_map_a.csv: role=b, but the file name says role a"),
            ("no_role", changed("clock_map_a.csv", "# role=a\n", ""), "clock_map_a.csv: role=None, but the file name says role a"),
            ("host", changed("clock_map_b.csv", "# host=baolong\n", "# host=iris\n"),
             "clock_map_b.csv: host=iris, but clock_probe.csv says host_b=baolong"),
            ("commit", changed("clock_map_b.csv", "# commit=abc1234abc12\n", "# commit=000000000000\n"),
             "the commit lines of the three probe files differ: clock_probe.csv abc1234abc12, clock_map_a.csv abc1234abc12, "
             "clock_map_b.csv 000000000000"),
            ("clock_raw", changed("clock_map_b.csv", "# clock_raw=CLOCK_MONOTONIC_RAW\n", "# clock_raw=CLOCK_BOOTTIME\n"),
             "clock_map_b.csv: clock_raw=CLOCK_BOOTTIME, not CLOCK_MONOTONIC_RAW"),
            ("interval", changed("clock_map_a.csv", "# interval_ms=5\n", "# interval_ms=10\n"), "clock_map_a.csv: interval_ms=10, not 5")):
        assert listed("identity_" + case, probe=probe_file(), maps=files) == [(probe, "e2e", [why])], case
    assert listed("identity_probe", probe=probe_file().replace("# clock_raw=CLOCK_MONOTONIC_RAW\n", "# clock_raw=CLOCK_REALTIME\n")) == [
        (probe, "e2e", ["clock_probe.csv: clock_raw=CLOCK_REALTIME, not CLOCK_MONOTONIC_RAW"])]
    # E11 j: what the maps say about a run that is not a result is on record in summary.json, and is no key
    s, rows = run(tmp_path, "on_record", probe_file(quick=101, slow=101))
    (entry,) = s["invalid_runs"]
    (record,) = entry["record"]
    assert record["pair"] == "periodic/periodic_tx.csv" and record["map"]["a"]["samples"] == 301 and record["map"]["b"]["check_n"] == 122
    assert record["clock"]["b"] == {"adj_ppm_min": 0, "adj_ppm_max": 0, "adj_ppm_median": 0, "adj_step_ppm_max": 0,
                                    "adj_offset_range_us": 0, "adjusted": 0}
    assert not [k for k in rows if ".e2e." in k]
    # with three anchors no stamp is carried over: the clocks are on record, the map figures are not; format 1 has no map
    (entry,) = run(tmp_path, "few_on_record", probe_file(n=30))[0]["invalid_runs"]
    assert list(entry["record"][0]) == ["pair", "clock"] and entry["record"][0]["clock"]["a"]["adjusted"] == 0
    assert "record" not in run(tmp_path, "format_1_on_record", probe_file(raw=False), maps={})[0]["invalid_runs"][0]
    # a header that says another format than the columns
    assert listed("header", probe=probe_file().replace("# format=2\n", "")) == [
        (probe, "e2e", ["the header says format=None, but the columns are those of format 2"])]


def test_a_probe_file_without_a_pair_is_listed_and_two_in_a_directory_are_refused(tmp_path):
    d = tmp_path / "run" / "periodic"
    d.mkdir(parents=True)
    (d / "periodic_tx.csv").write_text(synth.text(synth.TX_HEADER, JOBS, synth.tx_meta(1)))
    write_probe(d, probe_file())
    s = make_tables.run(tmp_path / "run", tmp_path / "out", **PARAMS)
    assert s["invalid_runs"] == [] and sorted(s["skipped_csv"], key=lambda e: e["path"]) == [
        *({"path": f"periodic/clock_map_{x}.csv", "reason": make_tables.MAP_NOT_USED, "header_matches_schema": "clock_map"} for x in "ab"),
        {"path": "periodic/clock_probe.csv", "reason": "clock_probe file not used: no analysed periodic_rx file in its directory",
         "header_matches_schema": "clock_probe"}]
    (d / "clock_probe_b.csv").write_text(probe_file())
    with pytest.raises(ValueError, match="more than one clock_probe file"):
        make_tables.run(tmp_path / "run", tmp_path / "out2", **PARAMS)


# ---- cell g: the gateway binaries on both boards (a FUNCTIONAL directory with the probe file beside the gateway files) ---

from analysis.tests import test_functional as tf  # noqa: E402


def gateway_run(tmp_path, name, probe=None, verified_us=900, nodelay=("1",), extra=None):
    """Twelve PDUs of one stream: submitted every 10 ms from 21.0 s of clock A, sent 3 ms later; verified `verified_us`
    after the send and delivered 50 us after that, on a clock 7 s ahead. The gateway records no rx_done_ns."""
    sent = [later((0, k, 1000 * MS + k * 10 * MS, 1000 * MS + k * 10 * MS + 1, 0, 1003 * MS + k * 10 * MS)) for k in range(12)]
    sent = [(*r[:4], 0, r[5]) for r in sent]  # the gateway records no auth_done_ns
    got = [(0, k, 0, r[5] + synth.RX_AHEAD + verified_us * US, r[5] + synth.RX_AHEAD + (verified_us + 50) * US, "ok") for k, r in enumerate(sent)]
    files = {"app_tx.csv": tf.lines(("loop=closed", "commit=abc1234", "host=iris", "role=tx", "profile=mldsa65", "streams=1",
                                     "payload_len=8", "period_cycles=10", "count=12", "not_recorded=auth_done_ns"),
                                    "stream,seq,submit_ns,start_ns,auth_done_ns,send_done_ns", sent, nodelay),
             "app_rx.csv": tf.lines(("commit=abc1234", "role=rx", "profile=mldsa65", "count=0", "not_recorded=rx_done_ns"),
                                    "stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result", got, ("1",)),
             "rx_payload.csv": tf.payload([(0, k) for k in range(12)])}
    if probe is not None:
        files.update({"clock_probe.csv": probe, **clock_maps()})
    return tf.run(tmp_path, name, {**files, **(extra or {})})


def test_a_functional_run_with_a_clock_probe_gets_the_e2e_keys_under_functional(tmp_path):
    plain, without = gateway_run(tmp_path, "plain")
    s, rows = gateway_run(tmp_path, "probed", probe_file())
    assert s["invalid_runs"] == [] and plain["invalid_runs"] == [] and s["skipped_csv"] == plain["skipped_csv"] == []
    assert {k: (r["value"], r["formatted"]) for k, r in rows.items() if k in without} == \
        {k: (r["value"], r["formatted"]) for k, r in without.items()}                      # the counts of the run are untouched
    new = {k.removeprefix("functional.e2e."): r for k, r in rows.items() if k not in without}
    # 3 ms to the send, 0.9 ms to the verification, 0.05 ms to the delivery
    assert {k: float(r["value"]) for k, r in new.items()} == pytest.approx({
        "n": 12, "latency_mean_ms": 3.95, "latency_p50_ms": 3.95, "latency_p90_ms": 3.95, "latency_p99_ms": 3.95,
        "latency_p99_9_ms": 3.95, "latency_max_ms": 3.95, "rxpart_p50_ms": 0.95, "rxpart_p99_ms": 0.95, "rxpart_max_ms": 0.95,
        "offset_bound_us": 50, "offset_cert_us": 50, "offset_bound_total_us": 50, "exchanges_outside": 0,
        "anchors": 7, "probes_completed": 122, "probe_delay_min_us": 60, "probe_delay_p50_us": 100,
        "probe_gap_max_ms": 500.02, "drift_ppm": 0, "causality_min_us": 900, "causality_violations": 0, **RAW_KEYS})
    assert new["map_a.samples"]["source_file"] == "clock_map_a.csv"
    # the definitions name the gateway's time stamps: the submission, and the verification in place of the reception
    assert "deliver_ns - theta(submit_ns) - submit_ns" in new["latency_p50_ms"]["how"]
    assert "verify_done_ns - theta(send_done_ns) - send_done_ns" in new["causality_min_us"]["how"]
    assert "rx_done_ns" not in new["causality_min_us"]["how"] and new["n"]["source_file"] == "clock_probe.csv"
    table = (tmp_path / "probed_out" / "tables" / "e2e.md").read_text()
    assert "| . | gateway binaries, mldsa65 | 12 | – | – | – | 3.950 | – | 50.0 |" in table


def test_the_gateway_run_needs_twenty_check_points(tmp_path):
    """E11 d: 20 exchange points per board in the gateway run, where a harness run needs 100. 26 pass, 18 do not."""
    s, rows = gateway_run(tmp_path, "enough", probe_file(burst=BURST[:12]))
    assert s["invalid_runs"] == [] and rows["functional.e2e.map_a.check_n"]["value"] == "26"
    s, rows = gateway_run(tmp_path, "few", probe_file(burst=BURST[:8]))
    assert [f["reasons"] for f in s["invalid_runs"]] == [[
        f"map_{x}.check_n = 18: fewer than 20 exchange points of board {x.upper()} in the range the stamps use" for x in "ab"]]
    assert not [k for k in rows if ".e2e." in k] and "functional.delivered" in rows


def test_the_probe_files_of_a_gateway_run_must_be_those_of_one_run(tmp_path):
    """E12.2 beside the gateway's files: a map that says it is the other board's is not a result."""
    wrong = clock_maps()["clock_map_a.csv"].replace("# role=a\n", "# role=b\n")
    s, rows = gateway_run(tmp_path, "role", probe_file(), extra={"clock_map_a.csv": wrong})
    assert [(f["source"], f["reasons"]) for f in s["invalid_runs"]] == [
        ("clock_probe.csv", ["clock_map_a.csv: role=b, but the file name says role a"])]
    assert not [k for k in rows if ".e2e." in k] and "functional.delivered" in rows


def test_a_functional_run_that_breaks_an_e9_rule_keeps_its_counts(tmp_path):
    without = gateway_run(tmp_path, "plain", verified_us=-60)[1]
    s, rows = gateway_run(tmp_path, "early", probe_file(), verified_us=-60)  # verified 60 us before the send: beyond 50 us
    assert {k: r["value"] for k, r in rows.items()} == {k: r["value"] for k, r in without.items()}
    assert [(f["source"], f["experiment"], f["reasons"]) for f in s["invalid_runs"]] == [("clock_probe.csv", "e2e", [
        "causality_violations = 12: a delivered PDU was received more than the total bound (50 us) before it was "
        "sent; smallest margin -60 us"])]
    # an invalid functional run: its probe file is listed with its other files, and there is no E9 verdict
    s, rows = gateway_run(tmp_path, "nagle", probe_file(), nodelay=("0",))
    assert [f["source"] for f in s["invalid_runs"]] == ["FUNCTIONAL"] and not [k for k in rows if ".e2e." in k]
    assert {"path": "clock_probe.csv", "reason": make_tables.FUNCTIONAL_INVALID, "header_matches_schema": "clock_probe"} in s["skipped_csv"]


def test_a_probe_file_that_was_cut_or_holds_too_few_exchanges_is_listed_and_the_pair_keeps_its_keys(tmp_path):
    """Three files a probe can leave: header and footer without a row, a single exchange, and a row cut in the middle
    with no footer (a killed probe). None stops the run."""
    without = run(tmp_path, "plain")[1]
    whole = probe_file()
    head = whole[:whole.index("\n", whole.index("seq,t1_ns")) + 1]            # the comment lines and the column line
    first = whole[len(head):].splitlines(keepends=True)[0]
    cut = whole[:whole.index("# exchanges_sent")].rstrip("\n")[:-25] + "\n"   # the last row loses its end, and the footer
    cases = {"empty": (head + "# exchanges_sent=0\n# exchanges_completed=0\n", ["0 completed exchange(s) in the probe file: fewer than two"]),
             "single": (head + first + "# exchanges_sent=1\n# exchanges_completed=1\n",
                        ["1 completed exchange(s) in the probe file: fewer than two"]),
             "killed": (cut, None)}
    for name, (content, reasons) in cases.items():
        s, rows = run(tmp_path, name, content)
        assert {k: r["value"] for k, r in rows.items()} == {k: r["value"] for k, r in without.items()}, name
        ((source, experiment, found),) = [(f["source"], f["experiment"], f["reasons"]) for f in s["invalid_runs"]]
        assert (source, experiment) == ("periodic/clock_probe.csv", "e2e")
        if reasons:
            assert found == reasons, name
        else:
            assert found[0] == "no exchanges_completed line: the probe did not write its footer" and found[1].startswith("unreadable row: ")
            assert "clock_probe.csv" in found[1] and len(found) == 2
    # a row that cannot be read in a file that has its footer is no killed probe: that stays an error
    broken = whole.replace(first, first.replace(",", ";", 1))
    with pytest.raises(Exception, match="clock_probe.csv"):
        run(tmp_path, "broken", broken)


def test_sessions_of_one_e9_cell_give_ranges_and_may_differ_in_the_delivered_pdus(tmp_path):
    """Cell a has three sessions. The number of delivered PDUs is an outcome, not a design count: a session in which one
    PDU was not delivered must not stop the comparison. The offset bound is printed beside every latency, so it gets
    its range like the latency figures."""
    from analysis import sessions
    dirs = []
    for k, (slow, latency_us, rx_jobs) in enumerate(((50, 500, JOBS), (40, 520, JOBS[:-1])), 1):
        d = tmp_path / f"run{k}" / "periodic"
        d.mkdir(parents=True)
        (d / "periodic_tx.csv").write_text(synth.text(synth.TX_HEADER, JOBS, synth.tx_meta(1)))
        (d / "periodic_rx.csv").write_text(synth.text(synth.RX_HEADER, [synth.rx_row(r, latency_us=latency_us) for r in rx_jobs]))
        write_probe(d, probe_file(slow=slow))
        s = make_tables.run(tmp_path / f"run{k}", tmp_path / f"analysis{k}", key_prefix=f"e9.s{k}.a", **PARAMS)
        assert s["invalid_runs"] == []
        dirs.append(str(tmp_path / f"analysis{k}"))
    sessions.main([*dirs, "--out", str(tmp_path / "all")])
    with open(tmp_path / "all" / "numbers.csv", newline="") as f:
        rows = {r["key"]: r["formatted"] for r in csv.DictReader(f)}
    base = "e9.all.a.periodic.p10ms-s1-c1-mldsa65-fifo.e2e."
    assert rows[base + "latency_max_ms.range_over_sessions"] == "3.95--3.97"       # 3 + 0.5 (0.52) + 0.45 ms
    assert rows[base + "offset_bound_us.range_over_sessions"] == "40--50"         # the anchors' half delay of each session
    assert (rows[base + "offset_bound_us.min_over_sessions"], rows[base + "offset_bound_us.max_over_sessions"]) == ("40", "50")
    # ... and so do the offset bound in total and the total bound of Addendum E, the figure the table prints
    assert rows[base + "offset_bound_total_us.range_over_sessions"] == "40--50"
    assert rows[base + "bound_total_us.range_over_sessions"] == "40--50"


# ---- cells c, h and i: several streams, both variants in one file, an unrelated flow on the link ------------------------

BG = ("rate_offered_bit_s=50000000", "rate_achieved_bit_s=49999924", "pattern=writes at gaps uniform in 0.5 to 1.5 ms (seeded)",
      "seed=20261124", "bytes_sent=265257923", "bytes_received=265257923", "writes=42505", "source_host=iris", "sink_host=raspberrypi")


def two_streams(tmp_path, name, probe=True, extra=None, **tx_override):
    """The synthetic two-stream pair with a probe: stream 0 responds after 2 ms eight times and after 10, 11, 12 and
    13 ms; stream 1 after 3 ms, eleven of its twelve jobs delivered; 0.95 ms from the send to the delivery."""
    d = tmp_path / name / "periodic"
    d.mkdir(parents=True)
    (d / "periodic_tx.csv").write_text(synth.periodic_tx_two_streams(rows=TWO_STREAMS, **tx_override))
    (d / "periodic_rx.csv").write_text(synth.text(synth.RX_HEADER, [synth.rx_row(r) for r in TWO_STREAMS[:-1]]))
    if probe:
        write_probe(d, probe_file())
    for rel, content in (extra or {}).items():
        (tmp_path / name / rel).write_text(content)
    s = make_tables.run(tmp_path / name, tmp_path / (name + "_out"), **PARAMS)
    with open(tmp_path / (name + "_out") / "numbers.csv", newline="") as f:
        return s, {r["key"]: r for r in csv.DictReader(f)}


def test_a_file_with_several_streams_gets_the_latency_of_each_stream(tmp_path):
    """Rulings of 2026-11-25: per stream n, median, p99, p99.9 and maximum of the latency under e2e.stream<k>; the keys
    over all streams stay. With profile both the stream says which variant it is."""
    s, rows = two_streams(tmp_path, "both", profile="both", stream_profiles="mldsa65,mac")
    assert s["invalid_runs"] == []
    base = "periodic.p10ms-s2-c1-both-fifo.e2e."               # the configuration id says that the file holds both variants
    got = {k.removeprefix(base): r["value"] for k, r in rows.items() if k.startswith(base + "stream")}
    assert {k: float(v) for k, v in got.items() if not k.endswith("profile")} == pytest.approx({
        # stream 0: 2.95 ms eight times, then 10.95, 11.95, 12.95, 13.95 ms: positions 10.89 and 10.989 of 0..11
        "stream0.n": 12, "stream0.latency_p50_ms": 2.95, "stream0.latency_p99_ms": 12.95 + 0.89, "stream0.latency_p99_9_ms": 12.95 + 0.989,
        "stream0.latency_max_ms": 13.95,
        "stream1.n": 11, "stream1.latency_p50_ms": 3.95, "stream1.latency_p99_ms": 3.95, "stream1.latency_p99_9_ms": 3.95,
        "stream1.latency_max_ms": 3.95})
    assert (got["stream0.profile"], got["stream1.profile"]) == ("mldsa65", "mac")
    assert rows[base + "stream1.profile"]["unit"] == "text" and float(rows[base + "n"]["value"]) == 23   # all streams, as before
    assert "stream 1" in rows[base + "stream1.latency_max_ms"]["how"]
    # the same file with one variant: the per-stream latency keys, no profile key; and nothing but e2e keys differs
    s, plain = two_streams(tmp_path, "sig")
    base = "periodic.p10ms-s2-c1-mldsa65-fifo.e2e."
    assert sorted(k.removeprefix(base) for k in plain if k.startswith(base + "stream")) == sorted(
        f"stream{k}.{name}" for k in (0, 1) for name in ("n", "latency_p50_ms", "latency_p99_ms", "latency_p99_9_ms", "latency_max_ms"))
    # one stream: no per-stream keys
    assert not [k for k in run(tmp_path, "one", probe_file())[1] if ".e2e.stream" in k]


def test_the_unrelated_flow_of_a_run_has_keys_and_a_failed_flow_is_no_result(tmp_path):
    """DATA_SCHEMA.md, background_traffic.txt (E9, cell i): keys under <configuration>.bg.; verdict FAIL, or one of the
    driver's markers BG_INVALID and E9_INVALID in the run directory, makes the e2e keys of the directory not a result."""
    def flow(verdict):
        return {"background_traffic.txt": "".join(f"{line}\n" for line in (*BG, f"verdict={verdict}"))}

    s, rows = two_streams(tmp_path, "pass", extra=flow("PASS"))
    base = "periodic.p10ms-s2-c1-mldsa65-fifo."
    assert s["invalid_runs"] == [] and base + "e2e.n" in rows
    assert {k.removeprefix(base + "bg."): r["value"] for k, r in rows.items() if k.startswith(base + "bg.")} == {
        "rate_offered_mbit_s": "50.0", "rate_achieved_mbit_s": "49.999924", "bytes_sent": "265257923", "bytes_received": "265257923",
        "verdict": "PASS"}
    assert rows[base + "bg.verdict"]["unit"] == "text" and rows[base + "bg.bytes_sent"]["source_file"] == "background_traffic.txt"
    probe = "periodic/clock_probe.csv"
    s, rows = two_streams(tmp_path, "fail", extra=flow("FAIL: achieved below 95 % of offered"))
    assert [(f["source"], f["reasons"]) for f in s["invalid_runs"]] == [
        (probe, ["background_traffic.txt: verdict=FAIL: achieved below 95 % of offered"])]
    assert base + "e2e.n" not in rows and rows[base + "bg.verdict"]["value"] == "FAIL"   # the flow keeps its keys
    for marker, text in (("BG_INVALID", "the flow ended early"), ("E9_INVALID", "probe gap")):
        s, rows = two_streams(tmp_path, marker, extra={marker: text + "\n"})
        assert [(f["source"], f["reasons"]) for f in s["invalid_runs"]] == [(probe, [f"marker {marker} in the run directory: {text}"])]
        assert base + "e2e.n" not in rows and base + "jobs" in rows
    # without a probe there is nothing to make invalid: the flow's keys, and every periodic key as before
    s, rows = two_streams(tmp_path, "no_probe", probe=False, extra=flow("PASS"))
    assert s["invalid_runs"] == [] and base + "bg.verdict" in rows
    # a record without its verdict line was cut: no keys, and no result
    s, rows = two_streams(tmp_path, "cut", extra={"background_traffic.txt": "".join(f"{line}\n" for line in BG)})
    assert [f["reasons"] for f in s["invalid_runs"]] == [["background_traffic.txt: no verdict line"]] and base + "bg.bytes_sent" not in rows


@pytest.mark.parametrize("streams", [3, 5, 6, 8])
def test_a_periodic_file_of_any_number_of_streams_is_analysed(tmp_path, streams):
    """E6x runs 3, 5, 6 and 8 streams in one sender process: nothing in the toolkit is made for 1, 2 or 4. Every stream
    has its keys, with and without a clock probe."""
    jobs = [later(synth._job(k, s, 0, 2 + k)) for k in range(streams) for s in range(12)]   # stream k responds after 2 + k ms
    d = tmp_path / "run" / "periodic"
    d.mkdir(parents=True)
    (d / "periodic_tx.csv").write_text(synth.text(synth.TX_HEADER, jobs, synth.tx_meta(streams)))
    (d / "periodic_rx.csv").write_text(synth.text(synth.RX_HEADER, [synth.rx_row(r) for r in jobs]))
    plain = make_tables.run(tmp_path / "run", tmp_path / "plain", **PARAMS)
    write_probe(d, probe_file())
    s = make_tables.run(tmp_path / "run", tmp_path / "probed", **PARAMS)
    assert s["invalid_runs"] == plain["invalid_runs"] == []
    (r,) = s["results"]["periodic"]
    assert (r["streams"], len(r["per_stream"]), len(r["rx"]["per_stream"]), r["jobs"]) == (streams, streams, streams, 12 * streams)
    assert [(ps["stream"], ps["n"], ps["latency_ms"]["max"]) for ps in r["e2e"]["per_stream"]] == [
        (str(k), 12, pytest.approx(2 + k + 0.95)) for k in range(streams)]
    with open(tmp_path / "probed" / "numbers.csv", newline="") as f:
        keys = [row["key"] for row in csv.DictReader(f)]
    base = f"periodic.p10ms-s{streams}-c1-mldsa65-fifo."
    assert all(f"{base}s{k}.jobs" in keys and f"{base}e2e.stream{k}.latency_max_ms" in keys for k in range(streams))


# ---- the two tests of the method (a probetest directory): same host, and both directions at once -----------------------

def test_same_host_exchanges_have_a_true_offset_of_zero():
    """Client and server on one board: the true offset is zero, so every exchange must give |theta| <= delta / 2.
    30 us one way and 10 us back: theta is 10 us, half the delay 20 us. A clock that jumps 100 us between two reads is
    outside."""
    probe = exchanges(forward=30 * US, back=10 * US, theta=lambda t: 0)
    assert e2e.same_host(probe) == {"exchanges": 200, "anchors": 4, "offset_bound_us": 20, "theta_beyond_half_delay": 0}
    probe["t2_ns"][17] += 100 * US
    probe["t3_ns"][17] += 100 * US
    assert e2e.same_host(probe)["theta_beyond_half_delay"] == 1
    # the bound of this test is over ALL anchors (ruled 2026-11-25; only e2e.offset_bound_us leaves the end anchors out):
    # exchange 200, alone in a fifth window, takes 300 us each way and sets it
    slow = exchanges(n=201, forward=lambda i: (300 if i == 200 else 30) * US, back=lambda i: (300 if i == 200 else 10) * US,
                     theta=lambda t: 0)
    assert e2e.same_host(slow) == {"exchanges": 201, "anchors": 5, "offset_bound_us": 300, "theta_beyond_half_delay": 0}
    assert e2e.track(slow)["offset_bound_us"] == 20


def test_two_directions_at_once_must_cancel():
    """One probe with its client on board A and one with its client on board B, at the same time: theta_AB + theta_BA
    is zero for a perfect measurement and must stay within the sum of the two bounds. Compared are the anchors of the
    region of each track, the second to the second-to-last, whose instant lies in the region of the other track, ends
    included (E11 m of the spec: the end segments of a track are not certified and take no part)."""
    b0 = A0 + THETA0                                              # clock B at the instant clock A reads A0
    ab, ba = exchanges(), exchanges(start=b0, theta=lambda t: -THETA0)
    # anchors at 0, 5, 10 and 15 s on either track: those at 5 and 10 s are the region, and each lies on an end of the other's
    assert e2e.two_directions(ab, ba) == {"anchors_compared": 4, "theta_sum_max_us": 0, "limit_us": 100}
    # 80 us to B and 20 us back in the A to B probe: its offsets are 30 us off, and so is every sum (its anchor at 10 s
    # then lies 30 us beyond the other track's region and is not compared)
    assert e2e.two_directions(exchanges(forward=80 * US, back=20 * US), ba) == {
        "anchors_compared": 3, "theta_sum_max_us": pytest.approx(30), "limit_us": 100}
    # the B to A probe started 6 s later: its region runs from 11 to 16 s, the other one from 5 to 10 s: nothing to compare
    late = exchanges(start=b0 + 6 * SEC, theta=lambda t: -THETA0)
    assert e2e.two_directions(ab, late) == {"anchors_compared": 0, "theta_sum_max_us": None, "limit_us": 100}
    # ... and with 40 s of each: regions 5 to 30 s and 11 to 36 s; the A to B anchors at 15, 20, 25 and 30 s lie in the
    # other region, and the B to A anchors at 11, 16, 21 and 26 s
    assert e2e.two_directions(exchanges(n=400), exchanges(n=400, start=b0 + 6 * SEC, theta=lambda t: -THETA0)) == {
        "anchors_compared": 8, "theta_sum_max_us": 0, "limit_us": 100}
    # a track with three anchors has no region
    assert e2e.two_directions(exchanges(n=140), ba) == {"anchors_compared": 0, "theta_sum_max_us": None, "limit_us": None}
    # clock B gains 20 ppm: each track follows it, and the sum still cancels to the rounding of the stamps
    def gaining(t):
        return THETA0 + (t - A0) * 20 // 1_000_000
    drift = e2e.two_directions(exchanges(theta=gaining), exchanges(start=b0, theta=lambda t: -gaining(t + THETA0 * -1)))
    assert drift["anchors_compared"] >= 2 and drift["theta_sum_max_us"] == pytest.approx(0, abs=0.02)


def probetest_dir(tmp_path, name, zero_shift=0, ba_completed=None):
    """A run directory with a probetest directory as the driver leaves it: zero_<host>.csv for each board and the pair."""
    d = tmp_path / name / "probetest"
    d.mkdir(parents=True)

    def write(file, cols, host_a, host_b, completed=None):
        rows = list(zip(*(cols[k].tolist() for k in ("seq", "t1_ns", "t2_ns", "t3_ns", "t4_ns"))))
        head = ("tool=bench_clock_probe", "commit=abc1234abc12", f"host_a={host_a}", f"host_b={host_b}", "clock=CLOCK_MONOTONIC",
                "interval_ms=100", "port=50105", "cpu_a=1", "cpu_b=2", f"exchanges_sent={len(rows)}",
                f"exchanges_completed={len(rows) if completed is None else completed}")   # the real files carry them above the rows
        (d / file).write_text(synth.text("seq,t1_ns,t2_ns,t3_ns,t4_ns", rows, head))

    zero = exchanges(forward=30 * US, back=10 * US, theta=lambda t: 0)
    zero["t2_ns"][17] += zero_shift
    zero["t3_ns"][17] += zero_shift
    write("zero_iris.csv", zero, "iris", "iris")
    write("zero_baolong.csv", exchanges(n=60, forward=25 * US, back=25 * US, theta=lambda t: 0), "raspberrypi", "raspberrypi")
    write("pair_ab.csv", exchanges(forward=80 * US, back=20 * US), "iris", "raspberrypi")
    write("pair_ba.csv", exchanges(start=A0 + THETA0, theta=lambda t: -THETA0), "raspberrypi", "iris", ba_completed)
    (tmp_path / name / "probetest.txt").write_text("the driver's own record; not read\n")
    s = make_tables.run(tmp_path / name, tmp_path / (name + "_out"), key_prefix="e9.probetest", **PARAMS)
    with open(tmp_path / (name + "_out") / "numbers.csv", newline="") as f:
        return s, {r["key"]: r for r in csv.DictReader(f)}


def test_a_probetest_directory_gets_the_keys_of_the_two_tests(tmp_path):
    s, rows = probetest_dir(tmp_path, "sound")
    assert s["invalid_runs"] == [] and s["skipped_csv"] == []
    got = {k.removeprefix("e9.probetest.probetest."): r["value"] for k, r in rows.items() if ".probetest.probetest." in k}
    assert {k: float(v) for k, v in got.items()} == pytest.approx({
        "zero.iris.exchanges": 200, "zero.iris.anchors": 4, "zero.iris.offset_bound_us": 20, "zero.iris.theta_beyond_half_delay.k": 0,
        "zero.raspberrypi.exchanges": 60, "zero.raspberrypi.anchors": 2, "zero.raspberrypi.offset_bound_us": 25,
        "zero.raspberrypi.theta_beyond_half_delay.k": 0,
        "pair.anchors_compared": 3, "pair.theta_sum_max_us": 30, "pair.limit_us": 100})
    assert rows["e9.probetest.probetest.zero.raspberrypi.exchanges"]["source_file"] == "probetest/zero_baolong.csv"
    assert "delta / 2" in rows["e9.probetest.probetest.zero.iris.theta_beyond_half_delay.k"]["how"]
    assert "sum of the two total bounds" in rows["e9.probetest.probetest.pair.limit_us"]["how"]
    # a jump of the clock on one board shows as an exchange outside: the key says 1, the test of the method has failed
    assert probetest_dir(tmp_path, "jump", zero_shift=100 * US)[1]["e9.probetest.probetest.zero.iris.theta_beyond_half_delay.k"]["value"] == "1"
    # a file whose own count of its exchanges is wrong is listed, and the pair it belongs to has no keys
    s, rows = probetest_dir(tmp_path, "cut", ba_completed=201)
    assert [(f["source"], f["experiment"], f["reasons"]) for f in s["invalid_runs"]] == [
        ("probetest/pair_ba.csv", "probetest", ["exchanges_completed=201, but the file has 200 rows"])]
    assert not [k for k in rows if ".pair." in k] and "e9.probetest.probetest.zero.iris.exchanges" in rows


def test_a_probetest_of_format_2_is_judged_on_the_raw_stamps(tmp_path):
    """E11 f. Same host: on the raw stamps the offset is zero (30 us one way, 10 us back: theta 10 us, half the delay
    20 us); the monotonic reads of the server's two points are written 100 us later, so that on the monotonic columns
    every exchange would lie beyond half its delay. A clock map in the directory is recognised by its header row
    whatever its name, and is not taken for a probe file."""
    d = tmp_path / "run" / "probetest"
    d.mkdir(parents=True)

    def write(file, cols, host_a, host_b, raw=True, shift=0):
        rows = [(i, t1, t2 + shift, t3 + shift, t4, t1, t2, t3, t4, 0, 0, 0, 0) if raw else (i, t1, t2, t3, t4)
                for i, t1, t2, t3, t4 in zip(*(cols[k].tolist() for k in ("seq", "t1_ns", "t2_ns", "t3_ns", "t4_ns")))]
        head = ("tool=bench_clock_probe", "commit=abc1234abc12", f"host_a={host_a}", f"host_b={host_b}", "clock=CLOCK_MONOTONIC",
                "interval_ms=100", "port=50105", "cpu_a=1", "cpu_b=2", *(("format=2", "clock_raw=CLOCK_MONOTONIC_RAW") if raw else ()))
        (d / file).write_text(synth.text(synth.PROBE2_HEADER if raw else "seq,t1_ns,t2_ns,t3_ns,t4_ns", rows, head,
                                         (f"exchanges_sent={len(rows)}", f"exchanges_completed={len(rows)}")))

    write("zero_iris.csv", exchanges(forward=30 * US, back=10 * US, theta=lambda t: 0), "iris", "iris", shift=100 * US)
    write("pair_ab.csv", exchanges(forward=80 * US, back=20 * US), "iris", "raspberrypi", shift=100 * US)
    write("pair_ba.csv", exchanges(start=A0 + THETA0, theta=lambda t: -THETA0), "raspberrypi", "iris", shift=100 * US)
    (d / "zero_iris_map.csv").write_text(clock_maps()["clock_map_a.csv"])
    s = make_tables.run(tmp_path / "run", tmp_path / "out", key_prefix="e9.probetest", **PARAMS)
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        got = {r["key"].removeprefix("e9.probetest.probetest."): float(r["value"]) for r in csv.DictReader(f) if ".probetest.probetest." in r["key"]}
    assert s["invalid_runs"] == [] and got == pytest.approx({
        "zero.iris.exchanges": 200, "zero.iris.anchors": 4, "zero.iris.offset_bound_us": 20, "zero.iris.theta_beyond_half_delay.k": 0,
        "pair.anchors_compared": 3, "pair.theta_sum_max_us": 30, "pair.limit_us": 100})
    assert s["skipped_csv"] == [{"path": "probetest/zero_iris_map.csv", "reason": "file name not recognised", "header_matches_schema": "clock_map"}]
    # one file of the pair in format 1: the two cannot be compared
    write("pair_ba.csv", exchanges(start=A0 + THETA0, theta=lambda t: -THETA0), "raspberrypi", "iris", raw=False)
    s = make_tables.run(tmp_path / "run", tmp_path / "out2", key_prefix="e9.probetest", **PARAMS)
    assert [(f["source"], f["reasons"]) for f in s["invalid_runs"]] == [("probetest/pair_ba.csv", [
        "pair_ab.csv and pair_ba.csv are of different probe formats: one has raw stamps, the other has none"])]


# ---- follow-ups: the driver's markers beside gateway files, a zero-byte probe file, sessions of a multi-stream cell ------

def test_the_drivers_markers_also_judge_a_gateway_directory(tmp_path):
    s, rows = gateway_run(tmp_path, "marked", probe_file(), extra={"E9_INVALID": "probe gap above 1 s\n"})
    assert [(f["source"], f["reasons"]) for f in s["invalid_runs"]] == [
        ("clock_probe.csv", ["marker E9_INVALID in the run directory: probe gap above 1 s"])]
    assert not [k for k in rows if ".e2e." in k] and "functional.delivered" in rows


def test_a_zero_byte_probe_file_is_what_a_killed_probe_leaves(tmp_path):
    """DATA_SCHEMA.md: 'A client that was killed otherwise leaves an empty file.' Listed, the keys of the run kept,
    in a periodic directory, beside gateway files and in a probetest directory."""
    without = run(tmp_path, "plain")[1]
    s, rows = run(tmp_path, "periodic_empty", "")
    assert {k: r["value"] for k, r in rows.items()} == {k: r["value"] for k, r in without.items()}
    ((source, reasons),) = [(f["source"], f["reasons"]) for f in s["invalid_runs"]]
    assert source == "periodic/clock_probe.csv" and reasons[0] == "no exchanges_completed line: the probe did not write its footer"
    s, rows = gateway_run(tmp_path, "gateway_empty", "")
    assert [f["source"] for f in s["invalid_runs"]] == ["clock_probe.csv"] and "functional.delivered" in rows and not [k for k in rows if ".e2e." in k]
    s, rows = probetest_dir(tmp_path, "sound")
    (tmp_path / "sound" / "probetest" / "zero_iris.csv").write_text("")
    s = make_tables.run(tmp_path / "sound", tmp_path / "sound_again", key_prefix="e9.probetest", **PARAMS)
    assert [f["source"] for f in s["invalid_runs"]] == ["probetest/zero_iris.csv"]
    assert [z["host"] for z in s["results"]["probetest"][0]["zero"]] == ["raspberrypi"] and s["results"]["probetest"][0]["pair"]


def test_sessions_of_a_cell_with_several_streams_may_differ_in_what_each_stream_delivered(tmp_path):
    from analysis import sessions
    dirs = []
    for k, lost in enumerate((0, 1), 1):  # the second session delivers one PDU of stream 0 less
        d = tmp_path / f"run{k}" / "periodic"
        d.mkdir(parents=True)
        (d / "periodic_tx.csv").write_text(synth.periodic_tx_two_streams(rows=TWO_STREAMS))
        rows = [synth.rx_row(r) for r in TWO_STREAMS[lost:-1]]
        (d / "periodic_rx.csv").write_text(synth.text(synth.RX_HEADER, rows))
        write_probe(d, probe_file())
        assert make_tables.run(tmp_path / f"run{k}", tmp_path / f"analysis{k}", key_prefix=f"e9.s{k}.c", **PARAMS)["invalid_runs"] == []
        dirs.append(str(tmp_path / f"analysis{k}"))
    sessions.main([*dirs, "--out", str(tmp_path / "all")])  # e2e.n 23 and 22, e2e.stream0.n 12 and 11: no error
    with open(tmp_path / "all" / "numbers.csv", newline="") as f:
        keys = [r["key"] for r in csv.DictReader(f)]
    assert "e9.all.c.periodic.p10ms-s2-c1-mldsa65-fifo.e2e.stream0.latency_max_ms.range_over_sessions" in keys


# ---- the final ruling on the clock track (2026-11-25): what the probe certifies between the anchors ---------------------
# cert_j = |track(tau_j) - theta_j| + delta_j / 2 for every exchange between the second and the second-to-last anchor;
# offset_cert_us = T(2 s), the smallest T whose certified exchanges, with the two ends of the region, are never more than
# 2,000 ms apart; offset_bound_total_us = max(offset_bound_us, offset_cert_us); not a result above 100 us.

def step_at(ms):
    """Clock B gains 100 ppm on clock A from `ms` after A0 on."""
    return lambda t: THETA0 + max(0, t - (A0 + ms * MS)) * 100 // 1_000_000


def test_known_answer_a_rate_step_in_the_middle_of_a_segment_is_not_a_result():
    """Anchors at 0, 5, 10 and 15 s (10 us each way), the other exchanges 50 us each way; the rate steps by 100 ppm at
    7.5 s, the middle of the segment from 5 s to 10 s. The line through the anchors rises at 50 ppm there and is off
    by 50 ppm x the distance to the nearer anchor. Certified points no more than 2 s apart from 5 s to 10 s: the best
    are at 6.5 s and 8.5 s, where the line is 75 us off and the exchange's own half delay is 50 us: T = 125 us."""
    probe = exchanges(forward=PINNED, back=PINNED, theta=step_at(7_500))
    tr = e2e.track(probe)
    assert tr["anchor_seq"].tolist() == [0, 50, 100, 150] and tr["offset_bound_us"] == 10
    assert tr["offset_cert_us"] == pytest.approx(125, abs=0.05) and tr["offset_bound_total_us"] == tr["offset_cert_us"]
    assert tr["exchanges_outside"] == 0                  # the bound says 125 us, and no exchange contradicts that
    res, reasons = e2e.analyse_mono(*pdus(), probe)
    assert res is None and len(reasons) == 1 and reasons[0].startswith("offset_bound_total_us = 125") and "exceeds 100" in reasons[0]


def test_known_answer_a_rate_step_in_a_long_segment_between_two_short_ones_is_not_a_result():
    """Anchors at exchanges 49, 50, 148 and 149 of a 101 ms probe: a segment of 9.9 s between two of 0.1 s, the case in
    which the line through an anchor's neighbours sees nothing. The rate steps by 100 ppm at 10 s, the middle of the
    long segment: the line is up to 247 us off, and the certified bound is above 200 us."""
    quick = {49: 10, 50: 10, 148: 10, 149: 10}
    probe = exchanges(n=198, step=101 * MS, forward=lambda i: quick.get(i, 50) * US, back=lambda i: quick.get(i, 50) * US,
                      theta=step_at(10_000))
    tr = e2e.track(probe)
    assert tr["anchor_seq"].tolist() == [49, 50, 148, 149] and 200 < tr["offset_cert_us"] < 300
    res, reasons = e2e.analyse_mono(*pdus(), probe)
    assert res is None and reasons[0].startswith("offset_bound_total_us = ") and "exceeds 100" in reasons[0]


def test_known_answer_two_close_anchors_at_a_constant_offset_stay_valid():
    """Anchors at exchanges 49 and 50, 101 ms apart, the second 2 us off (12 us there, 8 us back); the offset is
    constant. A term built from the slopes of neighbouring segments made 36 us of this. Here the line is at most 2 us
    off, every other exchange certifies it within its own half delay of 50 us plus that: T is just under 52 us."""
    quick = {49: (10, 10), 50: (12, 8), 120: (10, 10), 170: (10, 10)}
    probe = exchanges(n=198, step=101 * MS, forward=lambda i: quick.get(i, (50, 50))[0] * US, back=lambda i: quick.get(i, (50, 50))[1] * US)
    tr = e2e.track(probe)
    assert tr["anchor_seq"].tolist() == [49, 50, 120, 170] and tr["offset_bound_us"] == 10
    assert 50 < tr["offset_cert_us"] <= 52 and tr["offset_bound_total_us"] == tr["offset_cert_us"] and tr["exchanges_outside"] == 0
    res, reasons = e2e.analyse_mono(*pdus(), probe)           # PDUs from 6.0 s: between the second and the third anchor
    assert reasons == [] and res["offset_cert_us"] == tr["offset_cert_us"]


def test_known_answer_a_constant_drift_stays_valid():
    """Clock B gains 100 ppm throughout: the line through the anchors follows it, and every exchange certifies the track
    within its own half delay."""
    def constant(t):
        return THETA0 + (t - A0) * 100 // 1_000_000
    probe = exchanges(forward=PINNED, back=PINNED, theta=constant)
    tr = e2e.track(probe)
    assert tr["drift_ppm"] == pytest.approx(100, abs=1e-3) and tr["offset_cert_us"] == pytest.approx(50, abs=0.01)
    assert tr["offset_bound_total_us"] == tr["offset_cert_us"] and tr["exchanges_outside"] == 0
    res, reasons = e2e.analyse_mono(*pdus(theta=constant), probe)
    assert reasons == [] and res["offset_bound_total_us"] == pytest.approx(50, abs=0.01)


def test_the_certified_bound_takes_the_best_exchanges_two_seconds_apart():
    """T(2 s) is the smallest bound whose certified exchanges leave no distance above 2,000 ms. All exchanges 50 us each
    way but one in every ten, which takes 20 us each way: those certify within 20 us and are 1 s apart, so T = 20 us and
    the total is the bound of the anchors, 20 us. With the quick ones 2.1 s apart, the slow ones are needed: T = 50 us."""
    often = exchanges(forward=lambda i: (20 if i % 10 == 0 else 50) * US, back=lambda i: (20 if i % 10 == 0 else 50) * US)
    tr = e2e.track(often)
    assert (tr["offset_bound_us"], tr["offset_cert_us"], tr["offset_bound_total_us"]) == (20, 20, 20)
    rarely = exchanges(forward=lambda i: (20 if i % 21 == 0 or i % 50 == 0 else 50) * US, back=lambda i: (20 if i % 21 == 0 or i % 50 == 0 else 50) * US)
    tr = e2e.track(rarely)
    assert (tr["offset_bound_us"], tr["offset_cert_us"], tr["offset_bound_total_us"]) == (20, 50, 50)
    # fewer than four anchors: there is no region, and nothing is certified
    tr = e2e.track(exchanges(n=140))
    assert (tr["offset_bound_us"], tr["offset_cert_us"], tr["offset_bound_total_us"], tr["exchanges_outside"]) == (None, None, None, 0)
    # a hole of 2.6 s in the region: no bound exists (the gap rule of the probe fires as well)
    holed = exchanges(skip=range(60, 85))
    assert e2e.track(holed)["offset_cert_us"] is None
    assert e2e.analyse_mono(*pdus(), holed) == (None, [
        "probe_gap_max_ms = 2600 exceeds 1000: the probe has a gap of more than 1 s",
        "no certified bound: between the second and the second-to-last anchor the completed exchanges leave more than 2000 ms"])


def test_the_first_and_the_last_anchor_only_delimit():
    """Addition to the final ruling: offset_bound_us is the largest half delay among the anchors of the region. The
    last window of a probe file is partial and may hold one exchange, which is then an anchor whatever its delay: here
    exchange 200, alone in the fifth window with 825 us each way, and the whole first window is as slow (exchanges 0
    to 50; a slow exchange's tau is 775 us later, which moves the windows by as much). The anchors of the region
    (exchanges 51, 101, 151) take 50 us each way: the bound is 50 us, and the run is a result."""
    slow = lambda i: (825 if i <= 50 or i == 200 else 50) * US  # noqa: E731
    probe = exchanges(n=201, forward=slow, back=slow)
    tr = e2e.track(probe)
    assert tr["anchor_seq"].tolist() == [0, 51, 101, 151, 200] and tr["delay_ns"][tr["anchor"]].tolist() == [
        1650 * US, 100 * US, 100 * US, 100 * US, 1650 * US]
    assert (tr["offset_bound_us"], tr["offset_cert_us"], tr["offset_bound_total_us"], tr["exchanges_outside"]) == (50, 50, 50, 0)
    res, reasons = e2e.analyse_mono(*pdus(), probe)             # PDUs from 6.0 s to 6.4 s: two anchors on either side
    assert reasons == [] and (res["offset_bound_us"], res["offset_bound_total_us"], res["anchors"]) == (50, 50, 5)
    # a slow anchor inside the region does set the bound: the second window (exchanges 50 to 99) at 120 us each way
    inside = lambda i: (120 if 50 <= i < 100 else 50) * US  # noqa: E731
    tr = e2e.track(exchanges(n=250, forward=inside, back=inside))
    assert tr["anchor_seq"].tolist() == [0, 50, 100, 150, 200] and tr["offset_bound_us"] == 120


def test_an_exchange_outside_the_claimed_bound_is_not_a_result():
    """Every completed exchange between the first and the last anchor must lie within its own half delay plus the
    total bound of the track. One whose offset is 300 us away (half delay 50 us, bound 50 us) contradicts the bound."""
    probe = exchanges()
    probe["t2_ns"][70] += 300 * US
    probe["t3_ns"][70] += 300 * US
    tr = e2e.track(probe)
    assert (tr["exchanges_outside"], tr["offset_bound_total_us"], tr["anchor_seq"].tolist()) == (1, 50, [0, 50, 100, 150])
    res, reasons = e2e.analyse_mono(*pdus(), probe)
    assert res is None and reasons == ["exchanges_outside = 1: a completed exchange lies further from the track than half its "
                                       "delay plus offset_bound_total_us (50 us)"]
    # exactly at the limit (100 us away: half delay 50 + bound 50) it is inside; an exchange before the second anchor
    # or after the second-to-last one is not judged (amendment 3a)
    probe = exchanges()
    probe["t2_ns"][70] += 100 * US
    probe["t3_ns"][70] += 100 * US
    for outside_the_region in (17, 130):
        probe["t2_ns"][outside_the_region] += 300 * US
        probe["t3_ns"][outside_the_region] += 300 * US
    assert e2e.track(probe)["exchanges_outside"] == 0


def test_the_probe_interval_is_not_assumed():
    """The probe now sends every 101 ms: the windows, the anchors and the latency come from the time stamps alone."""
    probe = exchanges(step=101 * MS)
    tr = e2e.track(probe)
    assert (tr["anchors"], tr["anchor_seq"].tolist(), tr["probe_gap_max_ms"]) == (5, [0, 50, 100, 149, 199], 101)   # 5.05, 10.1, 15.049, 20.099 s
    res, reasons = e2e.analyse_mono(*pdus(), probe)
    assert reasons == [] and res["latency_ms"]["p50"] == 4.0
