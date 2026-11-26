"""Parser: comments and blank lines ignored, header validated, malformed rows raise with file:line."""
import numpy as np
import pytest

from analysis import csvio
from analysis.tests import synth


def put(tmp_path, name, content):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def test_comments_blank_lines_and_metadata(tmp_path):
    p = put(tmp_path, "crypto_ops.csv",
            "# period_ns=10\n# free text, not key value\n\nop,seq,ns\nmldsa_sign,0,100\n#,SKIPPED,x\n\n  mldsa_sign,1,200  \n")
    meta, cols = csvio.read_csv(p, "crypto_ops")
    assert meta == {"period_ns": "10"}
    assert cols["op"].tolist() == ["mldsa_sign", "mldsa_sign"]
    assert cols["seq"].tolist() == [0, 1] and cols["ns"].tolist() == [100, 200]
    assert cols["ns"].dtype == np.int64


@pytest.mark.parametrize("content,where", [
    ("op,seq,nanos\nmldsa_sign,0,1\n", ":1: header"),
    ("seq,op,ns\n0,mldsa_sign,1\n", ":1: header"),
    ("op,seq,ns\nmldsa_sign,0\n", ":2: 2 fields"),
    ("op,seq,ns\nmldsa_sign,0,1,9\n", ":2: 4 fields"),
    ("op,seq,ns\nmldsa_sign,0,1\n# c\nmldsa_sign,x,1\n", ":4: column seq"),
    ("op,seq,ns\nmldsa_sign,0,-5\n", ":2: column ns"),
    ("op,seq,ns\nmldsa_sign,0,1.5\n", ":2: column ns"),
    ("op,seq,ns\nmldsa_sign,0,\n", ":2: column ns"),
    ("op,seq,ns\nrsa_sign,0,1\n", ":2: column op"),
    ("# only a comment\n", "no header"),
    ("", "no header"),
])
def test_malformed_input_raises_with_location(tmp_path, content, where):
    p = put(tmp_path, "crypto_ops.csv", content)
    with pytest.raises(csvio.CsvError) as e:
        csvio.read_csv(p, "crypto_ops")
    assert str(p) in str(e.value) and where in str(e.value)


def test_number_and_label_columns(tmp_path):
    row = "5,iris,100.5,1,2,3,4,5,6,7,8,9\n"
    meta, cols = csvio.read_csv(put(tmp_path, "throughput.csv", synth.TPUT_HEADER + "\n" + row), "throughput")
    assert cols["offered_pps"].tolist() == [100.5] and cols["host"].tolist() == ["iris"]
    for bad in ("5,iris,nan,1,2,3,4,5,6,7,8,9\n", "5,iris,-1,1,2,3,4,5,6,7,8,9\n", "5,,100,1,2,3,4,5,6,7,8,9\n"):
        with pytest.raises(csvio.CsvError):
            csvio.read_csv(put(tmp_path, "throughput.csv", synth.TPUT_HEADER + "\n" + bad), "throughput")


def test_comment_lines_below_the_rows_are_metadata_too(tmp_path):
    p = put(tmp_path, "crypto_ops.csv", "# freq_khz_start=1500000\n# throttled_start=throttled=0x0\nop,seq,ns\nmldsa_sign,0,100\n"
                                        "# failed_calls=0\n#freq_khz_end = 1400000\n# wall_s=18.608\n")
    meta, cols = csvio.read_csv(p, "crypto_ops")
    assert meta == {"freq_khz_start": "1500000", "throttled_start": "throttled=0x0", "failed_calls": "0",
                    "freq_khz_end": "1400000", "wall_s": "18.608"}
    assert cols["ns"].tolist() == [100]


HEAD = {"tool": "bench_overhead_paired", "freq_khz_start": "1500000", "mlockall": "ok"}
TAIL = {"signature_mismatches": "0", "failed_calls": "0", "freq_khz_end": "1500000", "wall_s": "18.608", "cpu_s": "18.612"}
CLEAN = {"valid": True, "reasons": [], "warnings": [], "signature_mismatches": 0, "failed_calls": 0, "mlockall": "ok",
         "freq_khz_start": 1500000, "freq_khz_end": 1500000, "cpu_share": 18.612 / 18.608, "throttled_start": None,
         "throttled_end": None, "env_throttled": None, "throttled": None}


def env(*readings, host="iris"):
    return {"host": host, "throttled": [(label, f"throttled={value}") for label, value in zip(("before", "after"), readings)]}


def check(change=None, kind="overhead_paired", env=None):
    meta = {k: v for k, v in {**HEAD, **TAIL, **(change or {})}.items() if v is not None}
    return csvio.validity(meta, kind, env)


def test_validity_of_a_complete_clean_run():
    assert check({"mode": "ab"}) == CLEAN
    assert check(env=env("0x0", "0x0")) == {**CLEAN, "throttled": False,
                                             "env_throttled": ["before: throttled=0x0", "after: throttled=0x0"]}
    assert csvio.validity({}, "overhead_paired") is None  # a file without any self-check lines: nothing to check
    assert csvio.validity({"period_ns": "5"}, "crypto_ops") is None


@pytest.mark.parametrize("change,reason", [
    ({"signature_mismatches": "3"}, "signature_mismatches=3"),
    ({"failed_calls": "1"}, "failed_calls=1"),
    ({"signature_mismatches": None}, "trailer missing (signature_mismatches): the run did not finish"),
    ({"signature_mismatches": None, "failed_calls": None, "freq_khz_end": None, "wall_s": None, "cpu_s": None},
     "trailer missing (freq_khz_end, wall_s, cpu_s, signature_mismatches, failed_calls): the run did not finish"),
    ({"cpu_s": None}, "trailer missing (cpu_s): the run did not finish"),  # the CPU share cannot be checked: not valid
    ({"mlockall": None}, "mlockall line missing"),
    ({"mlockall": "failed (ENOMEM)"}, "mlockall=failed (ENOMEM)"),
    ({"freq_khz_end": "600000"}, "CPU frequency changed during the run (1500000 -> 600000 kHz)"),
    ({"cpu_s": "17.9"}, "cpu_s/wall_s = 0.962, below 0.97: the core was shared"),
    ({"throttled_start": "throttled=0x0", "throttled_end": "throttled=0x50005"},
     "throttling active (file: get_throttled 0x0 -> 0x50005)"),
    ({"throttled_start": "throttled=0x0", "throttled_end": "throttled=0x50000"},
     "get_throttled changed during the run (file: 0x0 -> 0x50000)"),
])
def test_validity_invalid_runs(change, reason):
    v = check(change)
    assert v["valid"] is False and v["reasons"] == [reason]


def test_validity_cpu_share_threshold():
    assert check({"cpu_s": "18.05"})["valid"] and check({"cpu_s": "18.05"})["cpu_share"] == pytest.approx(0.97001, abs=1e-5)
    assert not check({"cpu_s": "18.04"})["valid"]  # 0.9695


@pytest.mark.parametrize("readings,reason", [
    (("0x0", "0x4"), "throttling active (env file of iris: get_throttled 0x0 -> 0x4)"),        # throttled now, after the run
    (("0x1", "0x1"), "throttling active (env file of iris: get_throttled 0x1 -> 0x1)"),        # under-voltage now, both times
    (("0x0", "0x20000"), "get_throttled changed during the run (env file of iris: 0x0 -> 0x20000)"),
    (("0x50000", "0x70000"), "get_throttled changed during the run (env file of iris: 0x50000 -> 0x70000)"),
])
def test_validity_env_file_throttling_invalidates(readings, reason):
    v = check(env=env(*readings))
    assert not v["valid"] and v["reasons"] == [reason] and v["throttled"] is True


def test_validity_sticky_bits_from_before_the_run_are_a_warning():
    v = check(env=env("0x50000", "0x50000"))
    assert v["valid"] and v["throttled"] is True
    assert v["warnings"] == ["throttling had occurred before the run (env file of iris: get_throttled 0x50000 -> 0x50000, "
                             "sticky bits only)"]


def test_validity_unknown_readings_are_not_zero():
    v = check({"freq_khz_start": "unavailable"}, env=env("unavailable", "unavailable"))
    assert v["valid"] and v["throttled"] is None and v["freq_khz_start"] is None and v["warnings"] == []
    assert v["env_throttled"] == ["before: throttled=unavailable", "after: throttled=unavailable"]
    assert check()["throttled"] is None  # no reading at all: unknown as well
    v = check({"throttled_start": "throttled=0x0", "throttled_end": "0x0"})
    assert v["valid"] and v["throttled"] is False
    assert check({"throttled_start": "throttled=0x0"})["throttled"] is None  # the end reading is missing


def test_validity_trailer_expected_per_kind_and_only_from_a_harness():
    assert check({"signature_mismatches": None, "failed_calls": None}, "crypto_ops")["valid"]  # no counters in crypto_ops
    assert check({"freq_khz_end": None}, "crypto_ops")["reasons"] == ["trailer missing (freq_khz_end): the run did not finish"]
    hand_made = csvio.validity({"signature_mismatches": "0"}, "overhead_paired")  # no '# tool=': no trailer is expected
    assert hand_made["valid"] and hand_made["failed_calls"] is None and hand_made["cpu_share"] is None
    assert csvio.validity({}, "overhead_paired", env("0x0", "0x4"))["reasons"] != []  # the env file still applies


def test_validity_of_networked_harness_files():
    """bench_net files carry the same lines as the single-node ones, but a gateway process waits for
    its period: the CPU-share rule is for pinned single-thread runs only."""
    no_counters = {"signature_mismatches": None, "failed_calls": None, **TRANSPORT}
    for kind in ("periodic_tx", "periodic_rx", "throughput"):
        v = check({**no_counters, "cpu_s": "4.333"}, kind)
        assert v["valid"] and v["cpu_share"] == pytest.approx(4.333 / 18.608)  # reported, not judged
        assert check({**no_counters, "freq_khz_end": None}, kind)["reasons"] == ["trailer missing (freq_khz_end): the run did not finish"]
        assert check({**no_counters, "mlockall": None}, kind)["reasons"] == ["mlockall line missing"]
        assert check({**no_counters, "mlockall": "failed (ENOMEM)"}, kind)["reasons"] == ["mlockall=failed (ENOMEM)"]
        assert check({**no_counters, "freq_khz_end": "600000"}, kind)["valid"] is False
        assert check(no_counters, kind, env("0x0", "0x4"))["valid"] is False
    assert not check({**no_counters, "cpu_s": "4.333"}, "crypto_ops")["valid"]
    # a handshake file: no trailer line is required, the transport line is (below)
    bare = csvio.validity({"tool": "bench_handshake", "host": "iris", "tcp_nodelay": "1"}, "handshake")
    assert bare["valid"] and bare["mlockall"] is None and bare["cpu_share"] is None
    assert csvio.validity({"tool": "bench_handshake", "mlockall": "failed", "tcp_nodelay": "1"}, "handshake")["reasons"] == ["mlockall=failed"]
    assert csvio.validity({"freq_khz_start": "1500000", "freq_khz_end": "600000"}, "handshake")["valid"] is False


TRANSPORT = {"tcp_nodelay": "1", "tcp_connections_at_first_release": "1", "tcp_connections_at_end": "1",
             "jobs_started": "2400", "jobs_confirmed": "2400"}
NAGLE = "Nagle's algorithm was not switched off on this connection"
NO_LINE = "no tcp_nodelay line: whether Nagle's algorithm was off on this connection is not recorded"


@pytest.mark.parametrize("kind", ["periodic_tx", "periodic_rx", "throughput", "handshake", "attack"])
def test_a_networked_harness_file_needs_tcp_nodelay_1(kind):
    """DATA_SCHEMA.md, 'Transport keys': the value read back with getsockopt must be exactly 1."""
    base = {"tool": "bench_net_tx", "host": "iris", "tx_host": "iris", "rx_host": "baolong", "mlockall": "ok", "freq_khz_start": "1500000",
            "freq_khz_end": "1500000", "wall_s": "20", "cpu_s": "4", **TRANSPORT}
    assert csvio.validity(base, kind)["valid"]
    assert csvio.validity({**base, "tcp_nodelay": "0"}, kind)["reasons"] == [f"tcp_nodelay=0: {NAGLE}"]
    for value in ("-1", "", "2", "yes", " 1x"):  # -1: the option could not be read back; the others are no read-back at all
        assert csvio.validity({**base, "tcp_nodelay": value}, kind)["reasons"] == [
            f"tcp_nodelay={value}: not a read-back of 1, so whether Nagle's algorithm was off on this connection is not known"]
    missing = {k: v for k, v in base.items() if k != "tcp_nodelay"}
    assert csvio.validity(missing, kind)["reasons"] == [NO_LINE]
    # the value may have been read from the traffic log beside the file: the reason names that file
    log = "periodic_tx_100pps_rep1.csv"
    assert csvio.validity({**base, "tcp_nodelay": "0", csvio.TRANSPORT_FROM: {"tcp_nodelay": log}}, kind)["reasons"] == \
        [f"tcp_nodelay=0 (read from {log}): {NAGLE}"]
    # and only then: a line of the file itself is not said to come from the log that gave other lines
    assert csvio.validity({**base, "tcp_nodelay": "0", csvio.TRANSPORT_FROM: {"jobs_started": log}}, kind)["reasons"] == \
        [f"tcp_nodelay=0: {NAGLE}"]
    # retransmissions never make a file invalid
    assert csvio.validity({**base, "tcp_total_retrans_in_window": "7", "tcp_total_rto_in_window": "1"}, kind)["valid"]


def test_a_file_with_several_connections_needs_no_delay_on_every_one(tmp_path):
    """A gateway process writes one '# tcp_nodelay=' line per TCP connection it had (a restart of its peer gives a
    second). The gate must fail closed: 1 only while every line reads 1. Keeping the last line let a file that read 0
    and then 1 pass."""
    head = "# tool=SecOC gateway\n# host=iris\n"
    rows = synth.HANDSHAKE_HEADER + "\n0,initiator,ok,17214574,4575,4511,1771963,0,129944,4990814,522593,144315,219387,85685\n"
    for lines, kept in ((("1", "1"), "1"), (("0", "1"), "0"), (("1", "0"), "0"), (("1", "-1", "1"), "-1"), (("0", "-1"), "0"), (("1",), "1")):
        p = tmp_path / "handshake_gw_tx.csv"
        # the lines of the real files: one above the rows, the others below
        p.write_text(head + f"# tcp_nodelay={lines[0]}\n" + rows + "".join(f"# tcp_nodelay={v}\n" for v in lines[1:]))
        assert csvio.read_meta(p)["tcp_nodelay"] == kept == csvio.load(p)[1]["tcp_nodelay"], lines
        assert csvio.validity(csvio.load(p)[1], "handshake")["valid"] is (kept == "1")
        assert csvio.all_values(p, "tcp_nodelay") == list(lines)  # every line, for a count of the connections
    # any other key: the later line replaces the earlier one, as before
    p.write_text(head + "# session_id=aa\n" + rows + "# session_id=bb\n")
    assert csvio.read_meta(p)["session_id"] == "bb" == csvio.load(p)[1]["session_id"]


def test_transport_lines_are_for_networked_harness_files_only():
    for kind in ("crypto_ops", "overhead_paired", "sign_attrib"):  # single-node harness files have no connection
        v = csvio.validity({"tool": "bench_x", "mlockall": "ok", "freq_khz_start": "1500000", "freq_khz_end": "1500000", "wall_s": "20",
                            "cpu_s": "19.9", "signature_mismatches": "0", "failed_calls": "0"}, kind)
        assert v["valid"], v["reasons"]
    # a file without '# tool=' is hand-made or legacy: not judged by lines a harness would have written
    assert csvio.validity({"period_ns": "5"}, "periodic_tx") is None
    assert csvio.validity({"mlockall": "ok"}, "periodic_tx")["valid"]


def test_a_transmitter_file_is_invalid_when_its_connection_was_established_again():
    """tcp_connections_at_first_release and tcp_connections_at_end of the transmitter's process must both be there
    and be equal; the receiver's file carries no such lines and needs none."""
    base = {"tool": "bench_net_tx", "host": "iris", "tx_host": "iris", "rx_host": "baolong", "mlockall": "ok", "freq_khz_start": "1500000",
            "freq_khz_end": "1500000", "wall_s": "20", "cpu_s": "4", **TRANSPORT}
    again = "the TCP connection was established again inside the measured window (tcp_connections_at_first_release=1, tcp_connections_at_end=2)"
    absent = ("tcp_connections_at_first_release / tcp_connections_at_end missing: whether the connection was established again "
              "inside the measured window is not recorded")
    for kind in ("periodic_tx", "throughput"):  # the throughput file here is the tx host's (host = tx_host)
        assert csvio.validity({**base, "tcp_connections_at_end": "2"}, kind)["reasons"] == [again]
        assert csvio.validity({k: v for k, v in base.items() if k != "tcp_connections_at_end"}, kind)["reasons"] == [absent]
        assert csvio.validity({**base, "tcp_connections_at_first_release": "-1", "tcp_connections_at_end": "-1"}, kind)["reasons"] == \
            ["tcp_connections_at_first_release=-1, tcp_connections_at_end=-1: not counts, so whether the connection was established "
             "again inside the measured window is not known"]
        assert csvio.validity({**base, "tcp_connections_at_first_release": "3", "tcp_connections_at_end": "3"}, kind)["valid"]
    no_lines = {k: v for k, v in base.items() if not k.startswith("tcp_connections")}
    for kind in ("periodic_rx", "handshake", "attack"):
        assert csvio.validity(no_lines, kind)["valid"]
    assert csvio.validity({**no_lines, "host": "baolong"}, "throughput")["valid"]  # the rx host's sampler file


def test_a_transmitter_file_is_invalid_when_a_started_job_was_not_confirmed():
    """DATA_SCHEMA.md, 'Jobs given up': a networked timing file is invalid when jobs_started differs from
    jobs_confirmed (the schema: a job was given up without a confirmation and its row received the next PDU). The two
    lines are in the transmitter's footer; a file without them does not say, and that is not 'all confirmed'."""
    base = {"tool": "bench_net_tx", "host": "iris", "tx_host": "iris", "rx_host": "baolong", "mlockall": "ok", "freq_khz_start": "1500000",
            "freq_khz_end": "1500000", "wall_s": "20", "cpu_s": "4", **TRANSPORT}
    absent = "jobs_started / jobs_confirmed missing: whether every started job was confirmed is not recorded"
    for kind in ("periodic_tx", "throughput"):  # the throughput file here is the tx host's (host = tx_host)
        assert csvio.validity(base, kind)["valid"]
        assert csvio.validity({**base, "jobs_started": "1200", "jobs_confirmed": "1191"}, kind)["reasons"] == [
            "9 job(s) started and not confirmed (jobs_started=1200, jobs_confirmed=1191)"]
        assert csvio.validity({**base, "jobs_confirmed": "2401"}, kind)["reasons"] == [
            "jobs_started=2400, jobs_confirmed=2401 differ: more jobs confirmed than started"]
        assert csvio.validity({k: v for k, v in base.items() if k != "jobs_confirmed"}, kind)["reasons"] == [absent]
        assert csvio.validity({**base, "jobs_started": "-1", "jobs_confirmed": ""}, kind)["reasons"] == [
            "jobs_started=-1, jobs_confirmed=: not counts, so whether every started job was confirmed is not known"]
        # the footer says how the difference divides: jobs with a failed confirmation, and the rest given up without one
        nine = {**base, "jobs_started": "1200", "jobs_confirmed": "1191"}
        counts = "9 job(s) started and not confirmed (jobs_started=1200, jobs_confirmed=1191)"
        assert csvio.validity({**nine, "tx_confirmations_failed": "0"}, kind)["reasons"] == [
            counts + ", of which 0 with a failed confirmation (tx_confirmations_failed) and 9 given up without one"]
        assert csvio.validity({**nine, "tx_confirmations_failed": "4"}, kind)["reasons"] == [
            counts + ", of which 4 with a failed confirmation (tx_confirmations_failed) and 5 given up without one"]
        for odd in ("10", "-1", "many"):  # more failures than jobs, or no count: the two counts alone
            assert csvio.validity({**nine, "tx_confirmations_failed": odd}, kind)["reasons"] == [counts]
        # releases dropped at a full queue are not a reason: started and confirmed still agree
        assert csvio.validity({**base, "jobs_released": "5100", "jobs_dropped_at_release": "189", "jobs_started": "4911",
                               "jobs_confirmed": "4911"}, kind)["valid"]
        # read from the traffic log beside a sampler file: the reason names it
        assert csvio.validity({**base, "jobs_confirmed": "2399", csvio.TRANSPORT_FROM: {"jobs_started": "p.csv", "jobs_confirmed": "p.csv"}},
                              kind)["reasons"] == ["1 job(s) started and not confirmed (jobs_started=2400, jobs_confirmed=2399 "
                                                   "(read from p.csv))"]
    no_lines = {k: v for k, v in base.items() if not k.startswith("jobs_")}
    for kind in ("periodic_rx", "handshake", "attack"):  # no transmitter files: no such lines, none needed
        assert csvio.validity(no_lines, kind)["valid"]
    assert csvio.validity({**no_lines, "host": "baolong"}, "throughput")["valid"]  # the rx host's sampler file


def test_transport_counts_of_the_measured_window():
    """The three counts of a transmitter's connection in the measured window. -1 means the kernel or the board's
    header did not give the field: unknown, never 0. So does a missing line. Anything else that is no count is an error."""
    retrans, dsack, rto = csvio.TRANSPORT_COUNTS
    assert (retrans, dsack, rto) == ("tcp_total_retrans_in_window", "tcp_dsack_dups_in_window", "tcp_total_rto_in_window")
    assert csvio.transport_counts({retrans: "3", dsack: "0", rto: "-1"}) == {retrans: 3, dsack: 0, rto: None}
    assert csvio.transport_counts({retrans: "12"}) == {retrans: 12, dsack: None, rto: None}
    assert csvio.transport_counts({}) == {retrans: None, dsack: None, rto: None}
    for bad in ("", "x", "-2", "1.5", "3 segments"):
        with pytest.raises(ValueError, match="tcp_dsack_dups_in_window=.* is neither a count nor -1"):
            csvio.transport_counts({dsack: bad})


def test_validity_counter_must_be_a_number():
    with pytest.raises(ValueError, match="signature_mismatches='none'"):
        check({"signature_mismatches": "none"})


def test_read_env_file(tmp_path):
    p = put(tmp_path, "env_iris.txt", "===== before 2026-11-23T00:42:59+07:00 =====\nhostname=iris\nkernel=6.18\n"
                                      "throttled=throttled=0x0\neth0_speed_mbit=100\n"
                                      "===== after 2026-11-23T00:44:51+07:00 =====\nhostname=iris\nthrottled=throttled=0x50000\n")
    assert csvio.read_env(p) == {"host": "iris", "throttled": [("before", "throttled=0x0"), ("after", "throttled=0x50000")]}
    p = put(tmp_path, "env_pi5.txt", "===== before x =====\nthrottled=unavailable\n")  # no hostname line: from the file name
    assert csvio.read_env(p) == {"host": "pi5", "throttled": [("before", "unavailable")]}


def test_run_markers(tmp_path):
    run = tmp_path / "runs" / "session1"
    (run / "overhead").mkdir(parents=True)
    assert csvio.marker(run) is None and csvio.markers(run) == []
    excluded = put(run, "EXCLUDED", "gates_iris.txt: the board reached 80.8 C\n")
    assert csvio.marker(run) == ("EXCLUDED", excluded)  # a run the harness excluded is not a result either
    pilot = put(run, "PILOT", "pilot\n")
    assert csvio.marker(run) == ("PILOT", pilot)
    dry = put(run, "DRY_RUN", "dry\n")
    assert csvio.marker(run) == ("DRY_RUN", dry)  # DRY_RUN wins over PILOT, PILOT over EXCLUDED
    assert csvio.markers(run) == [("DRY_RUN", dry), ("PILOT", pilot), ("EXCLUDED", excluded)]  # all of them are on record
    assert csvio.markers(run / "overhead") == csvio.markers(tmp_path / "runs") == csvio.markers(run)
    excluded.unlink()
    # a marker covers everything below it: analysing a subdirectory of a dry run is still a dry run
    assert csvio.marker(run / "overhead") == ("DRY_RUN", dry)
    # and a collection that contains a marked run is marked as a whole
    assert csvio.marker(tmp_path / "runs") == ("DRY_RUN", dry)
    dry.unlink()
    pilot.unlink()
    assert csvio.marker(tmp_path / "runs") is None and csvio.marker(run / "overhead") is None


def test_one_throttle_reading_cannot_show_that_nothing_happened():
    assert csvio.throttling(["throttled=0x0"], "x") == (None, [], [])  # a 'before' block only: unknown, not "no"
    assert csvio.throttling(["throttled=0x50000"], "x") == (True, [], [])  # bits seen, but nothing to compare with
    assert csvio.throttling(["throttled=0x0", "unavailable"], "x") == (None, [], [])
    assert csvio.throttling(["throttled=0x4"], "x")[1] == ["throttling active (x: get_throttled 0x4)"]  # active is active
    assert csvio.throttling(["throttled=0x0", "throttled=0x0"], "x") == (False, [], [])
    v = check(env=env("0x0"))
    assert v["valid"] and v["throttled"] is None and v["env_throttled"] == ["before: throttled=0x0"]


def test_signed_integer_column_only_where_the_schema_allows_it(tmp_path):
    p = put(tmp_path, "clock_offset.csv", synth.CLOCK_HEADER + "\n10,-5,3,ptp\n20,+7,4,ptp\n30,0,5,ptp\n")
    _, cols = csvio.read_csv(p, "clock_offset")
    assert cols["offset_ns"].tolist() == [-5, 7, 0] and cols["offset_ns"].dtype == np.int64
    for bad in ("10,--5,3,ptp", "10,1.5,3,ptp", "10,-,3,ptp", "-10,5,3,ptp", "10,5,-3,ptp"):  # t_ns and rtt_ns stay unsigned
        with pytest.raises(csvio.CsvError, match=":2: column"):
            csvio.read_csv(put(tmp_path, "clock_offset.csv", synth.CLOCK_HEADER + "\n" + bad + "\n"), "clock_offset")


@pytest.mark.parametrize("name,kind", [
    ("crypto_ops.csv", "crypto_ops"), ("crypto_ops_pi4.csv", "crypto_ops"), ("periodic_tx-10ms.csv", "periodic_tx"),
    ("periodic_rx.csv", "periodic_rx"), ("throughput.1core.csv", "throughput"), ("overhead_paired.csv", "overhead_paired"),
    ("attack.csv", "attack"), ("handshake.csv", "handshake"), ("attack_raw.csv", "attack_raw"),
    ("clock_offset.csv", "clock_offset"),
    ("phase_compare.csv", "phase_compare"), ("tx_perf_10k.csv", "tx_perf_10k"),
    ("rss_track.csv", None), ("crypto_opsx.csv", None), ("crypto_ops.txt", None),
])
def test_kind_of(name, kind):
    assert csvio.kind_of(name) == kind


def test_discover_lists_unrecognised_files_and_flags_misnamed_data(tmp_path):
    put(tmp_path, "a/crypto_ops.csv", synth.crypto_ops())
    put(tmp_path, "b/sign_times.csv", "# note\n" + synth.crypto_ops())  # right header, wrong name
    put(tmp_path, "b/other.csv", "x,y\n1,2\n")
    put(tmp_path, "notes.txt", "hello")
    known, skipped = csvio.discover(tmp_path)
    assert [p.relative_to(tmp_path).as_posix() for p in known] == ["a/crypto_ops.csv"]
    assert skipped == [
        {"path": "b/other.csv", "reason": "file name not recognised", "header_matches_schema": None},
        {"path": "b/sign_times.csv", "reason": "file name not recognised", "header_matches_schema": "crypto_ops"}]


def test_recognised_name_with_wrong_header_is_an_error(tmp_path):
    with pytest.raises(csvio.CsvError, match="header"):
        csvio.load(put(tmp_path, "attack_summary.csv", "vector,count\nreplay,3\n"))


def test_load_legacy_tx_perf(tmp_path):
    p = put(tmp_path, "tx_perf_10k.csv", "seq,phase,ns_delta,wallclock_ns\n0,keygen,900,1\n0,sign,100,2\n1,sign,200,3\n0,verify,50,4\n")
    kind, meta, cols = csvio.load(p)
    assert kind == "crypto_ops" and meta["legacy"] == "tx_perf_10k"
    assert cols["op"].tolist() == ["keygen", "sign", "sign", "verify"] and cols["ns"].tolist() == [900, 100, 200, 50]


def test_load_legacy_phase_compare(tmp_path):
    p = put(tmp_path, "phase_compare.csv",
            "phase,seq,ns_delta\nA_Standalone_Sign,0,10\nB_CsmIntegrated_Sign,0,11\nA_Standalone_Verify,3,5\n"
            "#,SKIPPED,Phase_C_SecOCLoopback_requires_guard\n")
    kind, _, cols = csvio.load(p)
    assert kind == "overhead_unpaired"
    assert cols["op"].tolist() == ["sign", "sign", "verify"]
    assert cols["arm"].tolist() == ["standalone", "csm", "standalone"]
    assert cols["seq"].tolist() == [0, 0, 3] and cols["ns"].tolist() == [10, 11, 5]
    with pytest.raises(csvio.CsvError, match="unknown legacy"):
        csvio.load(put(tmp_path, "phase_compare.csv", "phase,seq,ns_delta\nC_Loopback_Sign,0,10\n"))


def test_load_legacy_attack(tmp_path):
    p = put(tmp_path, "attack_raw.csv",
            "vector,iter,detected,duration_ns,reason\nBENIGN,0,0,3500,OK\nREPLAY,0,1,70,FRESH_REPLAY\n"
            "BIT_FLIP,0,1,440,SIG_INVALID\nSIG_TAMPER,0,1,441,SIG_INVALID\nFRESHNESS_ROLLBACK,0,1,300,FRESH_ROLLBACK\n")
    kind, meta, cols = csvio.load(p)
    assert kind == "attack" and meta["legacy"] == "attack_raw"
    assert cols["vector"].tolist() == ["benign", "replay", "bitflip", "auth_tamper", "freshness_rollback"]
    assert cols["delivered"].tolist() == ["1", "0", "0", "0", "0"]
    assert cols["reject_stage"].tolist() == ["none", "freshness", "auth", "auth", "freshness"]
    assert cols["detect_ns"].tolist() == [3500, 70, 440, 441, 300]
    with pytest.raises(csvio.CsvError, match="unknown legacy"):
        csvio.load(put(tmp_path, "attack_raw.csv", "vector,iter,detected,duration_ns,reason\nDOS,0,1,5,OK\n"))
