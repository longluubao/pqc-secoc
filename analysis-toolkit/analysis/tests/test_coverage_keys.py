"""Keys asked for by the coverage audit of 2026-11-25: figures the documents print for which no key existed. Each is a
plain ratio of quantities the toolkit already read; the tests derive every value by hand from the synthetic files."""
import csv

import pytest

from analysis import make_tables
from analysis.tests.test_e2e import run, two_streams
from analysis.tests.test_make_numbers import out, table  # noqa: F401  (the synthetic full run and its keys)
from analysis.tests.test_make_tables import PARAMS


def test_the_measured_utilisation_of_a_periodic_cell(tmp_path):
    """The share of the run that the sender spent authenticating: the time covered by the intervals from start_ns to
    auth_done_ns of its jobs, over the time from the file's first release to its last send. The intervals of the
    streams of one process overlap (the jobs of a cycle start together and are authenticated one after the other),
    so the covered time is taken, not the sum of the interval lengths."""
    s, rows = run(tmp_path, "one")
    base = "periodic.p10ms-s1-c1-mldsa65-fifo."
    # twelve jobs released every 10 ms from 21.000 s: started 1 ms after the release, authenticated 1.5 ms later, sent
    # 3 ms after the release. 12 x 1.5 ms = 18 ms in the call, from the first release to the last send 110 + 3 = 113 ms
    assert float(rows[base + "auth_utilisation"]["value"]) == pytest.approx(18 / 113)
    assert (rows[base + "auth_utilisation"]["formatted"], rows[base + "auth_utilisation"]["unit"], rows[base + "auth_utilisation"]["n"]) == (
        r"16\%", "percent", "12")
    assert "start_ns" in rows[base + "auth_utilisation"]["how"] and "covered" in rows[base + "auth_utilisation"]["how"]
    # the receiver's stamps do not carry the time of the verification call (the interval from reception to the decision
    # holds the wait for the next cycle of its main function): there is no such key
    assert not [k for k in rows if "verify_utilisation" in k]
    # two streams in one sender process. In ms from 21.000 s, stream 0 is in the call from 10 s + 1 to 10 s + r - 0.5 for
    # its responses r = 2, 12, 13, 2, 2, 11, 2, 2, 2, 2, 10, 2, and stream 1 from 10 s + 6 to 10 s + 7.5. Covered:
    # [1, 1.5], [6, 7.5], [11, 32.5] (jobs 1 and 2 of stream 0 run into each other and hold three intervals inside),
    # [36, 37.5], [41, 41.5], [46, 47.5], [51, 60.5], [61, 61.5], [66, 67.5], [71, 71.5], [76, 77.5], [81, 81.5],
    # [86, 87.5], [91, 91.5], [96, 97.5], [101, 109.5], [111, 111.5], [116, 117.5]: 55 ms, where the lengths add up to
    # 62 ms. The last send is that of stream 1 at 21.118 s: 118 ms
    s, rows = two_streams(tmp_path, "two", probe=False)
    base = "periodic.p10ms-s2-c1-mldsa65-fifo."
    assert float(rows[base + "auth_utilisation"]["value"]) == pytest.approx(55 / 118)
    assert rows[base + "auth_utilisation"]["n"] == "24"


def test_the_time_covered_by_intervals():
    from analysis import periodic
    import numpy as np
    ns = lambda *v: np.array(v, dtype=np.int64)  # noqa: E731
    assert periodic.covered_ns(ns(0, 10, 20), ns(5, 15, 25)) == 15                 # apart
    assert periodic.covered_ns(ns(0, 0, 0), ns(5, 10, 15)) == 15                   # started together, done one after the other
    assert periodic.covered_ns(ns(20, 0, 3), ns(25, 10, 4)) == 15                  # any order; one inside another
    assert periodic.covered_ns(ns(0, 5), ns(5, 9)) == 9 and periodic.covered_ns(ns(), ns()) == 0


def test_line_and_law_against_the_measured_percentiles_of_the_same_run(out, table):  # noqa: F811
    """The counting run of the synthetic set: 20 calls with 1 round eight times, 2 five times, 3 three times, 4 twice,
    then 6 and 20 rounds, at 100 us + 250 us per round. Line and law give 600, 2,600 and 3,600 us for the median, the
    99th and the 99.9th percentile; measured are 600 us, 4,435 us (1,600 + 0.81 x 3,500) and 5,033.5 us."""
    rows = table[0]
    law = "crypto_attrib.sign_attrib_p8.line_and_law."
    assert [float(rows[law + k]["value"]) for k in ("p50_cpu_rel_diff", "p99_cpu_rel_diff", "p99_9_cpu_rel_diff")] == \
        pytest.approx([0, 2600 / 4435 - 1, 3600 / 5033.5 - 1])
    assert rows[law + "p99_cpu_rel_diff"]["unit"] == "percent" and rows[law + "p50_cpu_rel_diff"]["formatted"] == r"0\%"
    assert "cpu_p99" in rows[law + "p99_cpu_rel_diff"]["how"] and "minus 1" in rows[law + "p99_cpu_rel_diff"]["how"]
    # a difference from a percentile that is held back (20 calls: fewer than ten lie above the 99th) is held back with it
    tex = (out[0] / "numbers.tex").read_text()
    assert law + "p50_cpu_rel_diff" in tex and law + "p99_cpu_rel_diff" not in tex and law + "p99_9_cpu_rel_diff" not in tex


CAPTURE = "captured_frames_with_payload=4504\ntcp_payload_bytes=4999575\nframe_bytes_as_captured=5296839\n# jobs_confirmed=1500\n"


def captured(tmp_path, name, content, where="calibration"):
    d = tmp_path / name / where
    d.mkdir(parents=True)
    (d / "capture_iris.txt").write_text(content)
    s = make_tables.run(tmp_path / name, tmp_path / (name + "_out"), **PARAMS)
    with open(tmp_path / (name + "_out") / "numbers.csv", newline="") as f:
        return s, {r["key"]: r for r in csv.DictReader(f) if not r["key"].startswith("run.")}


def test_the_capture_of_the_calibration_run(tmp_path):
    """calibration/capture_<host>.txt: the frames with TCP payload that the sending board's capture holds, their
    bytes, and the PDUs the sender confirmed. 4,504 frames for 1,500 PDUs: 3.0027 frames per PDU (the four frames
    beyond 3 x 1,500 belong to the set-up of the session, which the capture holds as well)."""
    s, rows = captured(tmp_path, "cal", CAPTURE)
    base = "capture.calibration.iris."
    assert {k.removeprefix(base): float(r["value"]) for k, r in rows.items()} == pytest.approx({
        "frames_with_payload": 4504, "tcp_payload_bytes": 4999575, "frame_bytes": 5296839, "jobs_confirmed": 1500,
        "frames_per_pdu": 4504 / 1500, "frame_bytes_per_frame": 5296839 / 4504, "tcp_payload_bytes_per_frame": 4999575 / 4504})
    assert [rows[base + k]["formatted"] for k in ("frames_per_pdu", "frame_bytes_per_frame", "tcp_payload_bytes_per_frame", "frames_with_payload")] == [
        "3.00", "1{,}176", "1{,}110", "4{,}504"]
    assert rows[base + "frames_per_pdu"]["source_file"] == "calibration/capture_iris.txt" and "session" in rows[base + "frames_per_pdu"]["how"]
    assert s["invalid_runs"] == [] and s["skipped_csv"] == []
    # in the run directory itself the key has no directory part
    assert "capture.iris.frames_per_pdu" in captured(tmp_path, "root", CAPTURE, where=".")[1]
    # a file of the name that lacks one of its four lines is damaged: an error that names it
    with pytest.raises(ValueError, match="capture_iris.txt.*jobs_confirmed"):
        captured(tmp_path, "cut", CAPTURE.replace("# jobs_confirmed=1500\n", ""))
    # ... and one without any of them is no capture file: with nothing else in the directory there is nothing to analyse
    with pytest.raises(ValueError, match="no recognised"):
        captured(tmp_path, "other", "notes\n")
