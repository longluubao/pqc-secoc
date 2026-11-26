"""Negative handshake tests: the oracle's record line (hsneg.txt) and the counts of the two ends' handshake files."""
import csv

import pytest

from analysis import hsneg, make_tables, merge_numbers
from analysis.tests import synth
from analysis.tests.test_make_tables import PARAMS

# two lines as the harness's oracle writes them (loopback, dry-run data), 2026-11-23
T1 = ("test=1 variant=none repetitions=3 attacked=4 verdict=PASS expected_tx=ok:1,sig_fail:3,timeout:3 "
      "seen_tx=ok:1,sig_fail:4,timeout:3 expected_rx=ok:1,timeout:3 seen_rx=ok:1,timeout:3,state:1 repetitions_done=3 runs=1 "
      "runs_passed=1 pdus_sent=1400 pdus_delivered=1400 pdus_rejected=0 pdus_given_up=0 installs_tx=1 installs_rx=1 "
      "tcp_nodelay_tx=1 tcp_nodelay_rx=1")
T12 = ("test=12 variant=flip repetitions=1 attacked=1 verdict=PASS expected_tx=ok:2,mac_fail:1,timeout:1 "
       "seen_tx=ok:2,mac_fail:1,timeout:1 expected_rx=ok:3 seen_rx=ok:3 repetitions_done=1 runs=1 runs_passed=1 pdus_sent=900 "
       "pdus_delivered=900 pdus_rejected=0 pdus_given_up=0 installs_tx=3 installs_rx=3 tcp_nodelay_tx=1 tcp_nodelay_rx=1")
GW = ("tool=SecOC gateway", "commit=abc1234", "mainfunction=cyclic", "mf_period_us=1000", "t_min_ms=1000", "tcp_nodelay=1")


def record(tmp_path, line=T1, last="PASS", before="test 1: A ['ok', 'sig_fail']\n"):
    p = tmp_path / "hsneg.txt"
    p.write_text(before + (line + "\n" if line else "") + last + "\n")
    return p


def side(role, results, host, comments=GW):
    """A gateway's handshake file: one row per result, in order; an ok row has a total and stage times."""
    rows = [(i, role, r, *((2_000_000, 4575, 4511, 100_000, 0, 50_000, 400_000, 100_000, 1_000, 15_000, 5_000) if r == "ok"
                           else (9_000_000, 1225, 0, 0, 0, 0, 0, 0, 0, 0, 0))) for i, r in enumerate(results)]
    return synth.text(synth.HANDSHAKE_HEADER, rows, (*comments, f"host={host}"))


TX1, RX1 = ["ok", "sig_fail", "timeout"] + ["sig_fail", "timeout"] * 2 + ["sig_fail"], ["ok", "timeout", "timeout", "timeout", "state"]


def numbers(out):
    with open(out / "numbers.csv", newline="") as f:
        return {r["key"]: r for r in csv.DictReader(f)}


def test_record_line_known_values(tmp_path):
    r = hsneg.read(record(tmp_path))
    assert (r["test"], r["variant"], r["verdict"], r["repetitions"], r["attacked"], r["repetitions_done"]) == (1, "none", "PASS", 3, 4, 3)
    assert r["expected_tx"] == {"ok": 1, "sig_fail": 3, "timeout": 3} and r["seen_tx"] == {"ok": 1, "sig_fail": 4, "timeout": 3}
    assert r["expected_rx"] == {"ok": 1, "timeout": 3} and r["seen_rx"] == {"ok": 1, "timeout": 3, "state": 1}
    assert [r[k] for k in ("runs", "runs_passed", "pdus_sent", "pdus_delivered", "pdus_rejected", "pdus_given_up", "installs_tx",
                           "installs_rx", "tcp_nodelay_tx", "tcp_nodelay_rx")] == [1, 1, 1400, 1400, 0, 0, 1, 1, 1, 1]
    r = hsneg.read(record(tmp_path, T12))
    assert (r["test"], r["variant"], r["seen_tx"], r["seen_rx"], r["installs_rx"]) == (12, "flip", {"ok": 2, "mac_fail": 1, "timeout": 1}, {"ok": 3}, 3)
    # an empty list is 'none'; -1 is a read-back that failed
    r = hsneg.read(record(tmp_path, T1.replace("expected_rx=ok:1,timeout:3", "expected_rx=none").replace("tcp_nodelay_rx=1", "tcp_nodelay_rx=-1")
                          .replace("verdict=PASS", "verdict=FAIL"), last="REJECT"))
    assert r["expected_rx"] == {} and r["tcp_nodelay_rx"] == -1 and r["verdict"] == "FAIL"


def test_a_file_without_the_record_line_gives_no_record(tmp_path):
    """The format before 2026-11-23 10:41 (every hsneg.txt of the dry runs so far): lines for a reader and a last line."""
    assert hsneg.read(record(tmp_path, line=None, last="REJECT")) is None


@pytest.mark.parametrize("line, last, message", [
    (T1 + "\n" + T12, "PASS", "2 lines start with 'test='"),
    (T1.replace("variant=none repetitions=3", "repetitions=3 variant=none"), "PASS", "not the fields of the record in their order"),
    (T1.replace(" tcp_nodelay_rx=1", ""), "PASS", "not the fields of the record in their order"),
    (T1.replace("attacked=4", "attacked=4  "), "PASS", "not the fields of the record in their order"),  # two blanks: an empty field
    (T1.replace("variant=none", "variant=replay"), "PASS", "variant='replay'"),
    (T1.replace("test=1 ", "test=13 "), "PASS", "test='13' is not a test number"),
    (T1.replace("attacked=4", "attacked=four"), "PASS", "attacked='four' is not a count"),
    (T1.replace("pdus_given_up=0", "pdus_given_up=-1"), "PASS", "pdus_given_up='-1' is not a count"),
    (T1.replace("tcp_nodelay_tx=1", "tcp_nodelay_tx=2"), "PASS", "tcp_nodelay_tx='2'"),
    (T1.replace("seen_tx=ok:1,sig_fail:4,timeout:3", "seen_tx=ok:1,replayed:4"), "PASS", "seen_tx"),
    (T1.replace("seen_tx=ok:1,sig_fail:4,timeout:3", "seen_tx=timeout:3,ok:1"), "PASS", "seen_tx"),  # not in the schema's order
    (T1.replace("seen_tx=ok:1,sig_fail:4,timeout:3", "seen_tx=ok:0"), "PASS", "seen_tx"),  # only classes that occur
    (T1.replace("verdict=PASS", "verdict=OK"), "PASS", "verdict='OK'"),
    (T1, "REJECT", "verdict=PASS but the last line is 'REJECT'"),
    (T1.replace("verdict=PASS", "verdict=FAIL"), "PASS", "verdict=FAIL but the last line is 'PASS'"),
])
def test_a_malformed_record_is_an_error(tmp_path, line, last, message):
    with pytest.raises(ValueError, match="hsneg.txt.*" + message.replace("(", r"\(").replace(")", r"\)")):
        hsneg.read(record(tmp_path, line, last))


def run_dir(tmp_path, name, files, line=T1, last="PASS"):
    d = tmp_path / name
    for rel, content in files.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(content)
    if line is not False:
        record(d, line, last)
    return d


def test_negative_test_gives_counts_per_side_and_the_verdict_and_no_timing(tmp_path):
    """DATA_SCHEMA.md: the handshake files of a negative test give counts per result class and side as keys and no
    timing statistic; the oracle's verdict is read from its record. Known answer: the first real record line."""
    d = run_dir(tmp_path, "t1", {"hstest/handshake_gw_tx.csv": side("initiator", TX1, "iris"),
                                 "hstest/handshake_gw_rx.csv": side("responder", RX1, "baolong")})
    s = make_tables.run(d, tmp_path / "out", **PARAMS)
    assert s["results"]["handshake"] == [] and s["invalid_runs"] == [] and len(s["results"]["hsneg"]) == 1
    (t,) = s["results"]["hsneg"]
    assert t["sides"] == {"initiator": {"n": 8, "results": {"ok": 1, "sig_fail": 4, "timeout": 3}},
                          "responder": {"n": 5, "results": {"ok": 1, "timeout": 3, "state": 1}}}
    assert [f["source"] for f in t["files"]] == ["hstest/handshake_gw_rx.csv", "hstest/handshake_gw_tx.csv"] and t["record_file"] == "hsneg.txt"
    rows = numbers(tmp_path / "out")
    got = {k.removeprefix("hsneg.t1."): r["formatted"] for k, r in rows.items() if k.startswith("hsneg.")}
    assert got == {"initiator.n": "8", "initiator.result_ok": "1", "initiator.result_sig_fail": "4", "initiator.result_timeout": "3",
                   "responder.n": "5", "responder.result_ok": "1", "responder.result_timeout": "3", "responder.result_state": "1",
                   "verdict": "PASS", "repetitions": "3", "repetitions_done": "3", "attacked": "4", "runs": "1", "runs_passed": "1",
                   "pdus_sent": "1{,}400", "pdus_delivered": "1{,}400", "pdus_rejected": "0", "pdus_given_up": "0",
                   "installs_tx": "1", "installs_rx": "1"}
    assert (rows["hsneg.t1.verdict"]["value"], rows["hsneg.t1.verdict"]["unit"]) == ("PASS", "text")
    assert rows["hsneg.t1.initiator.result_sig_fail"]["n"] == "8" and "hstest" in rows["hsneg.t1.initiator.n"]["source_file"]
    # no timing statistic of any kind: not as a key, not in the summary, and not in the handshake tables
    assert not [k for k in rows if k.startswith("handshake.")]
    assert "total_us" not in str(t) and "compute_us" not in str(t) and "phases_us" not in str(t)
    tex = (tmp_path / "out" / "numbers.tex").read_text()
    assert r"\expandafter\def\csname meas@hsneg.t1.verdict\endcsname{PASS}" in tex
    assert r"\expandafter\def\csname measraw@hsneg.t1.verdict\endcsname{PASS}" in tex  # the plain form of a word is the word
    merge_numbers.main([str(tmp_path / "out"), "--out", str(tmp_path / "all.tex")])  # a word survives the merge of the campaign
    assert r"\csname meas@hsneg.t1.verdict\endcsname{PASS}" in (tmp_path / "all.tex").read_text()
    table = (tmp_path / "out" / "tables" / "hsneg.md").read_text()
    assert "| hstest | 1 | none | PASS | 3 | 3 | 4 | 1 | 1 | ok: 1, sig_fail: 4, timeout: 3 | ok: 1, timeout: 3, state: 1 |" in table
    assert not (tmp_path / "out" / "tables" / "handshake.md").exists() or "hstest" not in (tmp_path / "out" / "tables" / "handshake.md").read_text()


def test_negative_test_without_a_record_line_has_counts_and_no_verdict(tmp_path):
    """The dry runs so far: hsneg.txt has no 'test=' line. The counts are keyed by the directory, and nothing says
    which test it was or what the oracle found."""
    files = {"hstest/handshake_gw_tx.csv": side("initiator", TX1, "iris"), "hstest/handshake_gw_rx.csv": side("responder", RX1, "baolong")}
    for name, line in (("old", None), ("none", False)):  # an older record, and no hsneg.txt at all
        s = make_tables.run(run_dir(tmp_path, name, files, line=line, last="REJECT"), tmp_path / (name + "_out"), **PARAMS)
        (t,) = s["results"]["hsneg"]
        assert t["record"] is None and t["record_file"] == (None if line is False else "hsneg.txt")
        rows = numbers(tmp_path / (name + "_out"))
        assert sorted(k for k in rows if k.startswith("hsneg.")) == sorted(
            f"hsneg.hstest.{k}" for k in ("initiator.n", "initiator.result_ok", "initiator.result_sig_fail", "initiator.result_timeout",
                                          "responder.n", "responder.result_ok", "responder.result_timeout", "responder.result_state"))


def test_a_batch_is_one_test_with_its_counts_added_over_the_runs(tmp_path):
    """Tests 11 and 12 are batches of short runs hstest/r001, r002, ...: one record line for the batch, the counts
    added over the runs, and no keys per run (each run's own hsneg.txt is not a record of the batch)."""
    files = {}
    for k in (1, 2, 3):
        files[f"hstest/r00{k}/handshake_gw_tx.csv"] = side("initiator", ["ok", "mac_fail", "timeout", "ok"], "iris")
        files[f"hstest/r00{k}/handshake_gw_rx.csv"] = side("responder", ["ok", "ok", "ok"], "baolong")
        files[f"hstest/r00{k}/hsneg.txt"] = T12 + "\nPASS\n"
    batch = (T12.replace("repetitions=1 attacked=1", "repetitions=3 attacked=3").replace("seen_tx=ok:2,mac_fail:1,timeout:1", "seen_tx=ok:6,mac_fail:3,timeout:3")
             .replace("seen_rx=ok:3", "seen_rx=ok:9").replace("runs=1 runs_passed=1", "runs=3 runs_passed=3"))
    s = make_tables.run(run_dir(tmp_path, "t12", files, line=batch), tmp_path / "out", **PARAMS)
    (t,) = s["results"]["hsneg"]
    assert t["sides"] == {"initiator": {"n": 12, "results": {"ok": 6, "mac_fail": 3, "timeout": 3}}, "responder": {"n": 9, "results": {"ok": 9}}}
    assert len(t["files"]) == 6 and s["invalid_runs"] == []
    rows = numbers(tmp_path / "out")
    assert rows["hsneg.t12-flip.initiator.result_mac_fail"]["formatted"] == "3" and rows["hsneg.t12-flip.runs_passed"]["formatted"] == "3"
    assert not [k for k in rows if "r00" in k or k.startswith("handshake.")]


def test_a_record_that_disagrees_with_the_files_makes_the_test_invalid(tmp_path):
    """The oracle counted the same two files: seen_tx / seen_rx of its record must be the counts found here."""
    d = run_dir(tmp_path, "t1", {"hstest/handshake_gw_tx.csv": side("initiator", TX1, "iris"),
                                 "hstest/handshake_gw_rx.csv": side("responder", RX1, "baolong")},
                line=T1.replace("seen_tx=ok:1,sig_fail:4,timeout:3", "seen_tx=ok:1,sig_fail:3,timeout:3"))
    s = make_tables.run(d, tmp_path / "out", **PARAMS)
    assert s["results"]["hsneg"] == [] and not [k for k in numbers(tmp_path / "out") if k.startswith("hsneg.")]
    assert [(f["source"], f["experiment"], f["reasons"]) for f in s["invalid_runs"]] == [("hsneg.txt", "hsneg", [
        "seen_tx=ok: 1, sig_fail: 3, timeout: 3 in the record, but the initiator's handshake files below hstest have "
        "ok: 1, sig_fail: 4, timeout: 3"])]
    assert "hsneg.txt" in (tmp_path / "out" / "tables" / "validity.md").read_text()


def test_an_invalid_handshake_file_takes_the_negative_test_with_it(tmp_path):
    """A gateway file that does not read tcp_nodelay=1 is invalid like any networked harness file; counts of one side
    alone are not a test, so the other file is listed and the test has no keys."""
    d = run_dir(tmp_path, "t1", {"hstest/handshake_gw_tx.csv": side("initiator", TX1, "iris", comments=(*GW[:-1], "tcp_nodelay=0")),
                                 "hstest/handshake_gw_rx.csv": side("responder", RX1, "baolong")})
    s = make_tables.run(d, tmp_path / "out", **PARAMS)
    assert s["results"]["hsneg"] == [] and [f["source"] for f in s["invalid_runs"]] == ["hstest/handshake_gw_tx.csv"]
    assert {"path": "hstest/handshake_gw_rx.csv", "reason": "another handshake file of this negative test is invalid"} in \
        [{k: e[k] for k in ("path", "reason")} for e in s["skipped_csv"]]


def test_a_handshake_file_whose_footer_contradicts_it_takes_the_negative_test_with_it(tmp_path):
    """CAMPAIGN.md, 'Invalid files': the count of a file's rows in its footer, and rows_lost, judge the handshake files of
    a negative test as they judge any file."""
    def run(name, *tail):
        d = run_dir(tmp_path, name, {"hstest/handshake_gw_tx.csv": side("initiator", TX1, "iris") + "".join(f"# {c}\n" for c in tail),
                                     "hstest/handshake_gw_rx.csv": side("responder", RX1, "baolong")})
        s = make_tables.run(d, tmp_path / (name + "_out"), **PARAMS)
        return len(s["results"]["hsneg"]), {f["source"]: f["reasons"] for f in s["invalid_runs"]}

    assert run("sound", f"rows={len(TX1)}", "rows_lost=0") == (1, {})
    assert run("cut", f"rows={len(TX1) + 2}", "rows_lost=0") == (
        0, {"hstest/handshake_gw_tx.csv": [f"rows={len(TX1) + 2}, but the file has {len(TX1)} rows"]})
    assert run("lost", f"rows={len(TX1)}", "rows_lost=1") == (0, {"hstest/handshake_gw_tx.csv": ["rows_lost=1: rows of the log were lost"]})


def test_the_older_layout_with_the_harness_as_transmitter(tmp_path):
    """Earlier negative-test runs had the harness on the transmitting end: its handshake file says pdu_stream=periodic
    and its traffic log periodic_tx.csv is beside it. In a negative-test directory these are the test's files, not a
    set-up handshake and not a periodic experiment, and the log's jobs lines judge the handshake files beside it."""
    net = ("tool=bench_net_tx", "commit=abc1234", "mainfunction=cyclic", "mf_period_us=1000", "t_min_ms=1000", "tcp_nodelay=1",
           "pdu_stream=periodic")
    files = {"hstest/handshake_tx.csv": side("initiator", TX1, "iris", comments=net),
             "hstest/handshake_gw_rx.csv": side("responder", RX1, "baolong")}
    log = synth.periodic_tx_one_stream()
    for name, jobs, reasons in (("sound", ("jobs_started=1400", "jobs_confirmed=1400"), None),
                                ("given_up", ("jobs_started=1400", "jobs_confirmed=1398"),
                                 "2 job(s) started and not confirmed (jobs_started=1400, jobs_confirmed=1398 (read from periodic_tx.csv))"),
                                ("silent", (), "jobs_started / jobs_confirmed missing in periodic_tx.csv: whether every started job was "
                                               "confirmed is not recorded")):
        d = run_dir(tmp_path, name, {**files, "hstest/periodic_tx.csv": log + "".join(f"# {j}\n" for j in jobs)})
        s = make_tables.run(d, tmp_path / (name + "_out"), **PARAMS)
        assert s["results"]["periodic"] == [] and s["results"]["handshake"] == []
        assert {"path": "hstest/periodic_tx.csv", "reason": make_tables.TRAFFIC_LOG} in [{k: e[k] for k in ("path", "reason")} for e in s["skipped_csv"]]
        assert not [e for e in s["skipped_csv"] if e["reason"] == make_tables.SETUP_HANDSHAKE]
        if reasons is None:
            assert s["invalid_runs"] == [] and numbers(tmp_path / (name + "_out"))["hsneg.t1.initiator.n"]["formatted"] == "8"
        else:
            assert {f["source"]: f["reasons"] for f in s["invalid_runs"]} == {"hstest/handshake_gw_rx.csv": [reasons], "hstest/handshake_tx.csv": [reasons]}
            assert s["results"]["hsneg"] == []
