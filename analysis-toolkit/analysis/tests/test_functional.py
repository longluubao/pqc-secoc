"""Functional runs of the gateway binaries (a directory with the marker FUNCTIONAL): counts only, never a time.

The fixtures have the layout of the real acceptance runs of 2026-11-23: comment lines, the header row, one
'# tcp_nodelay=' line per TCP connection, the rows; parts of a replaced process as app_rx2.csv and so on; the
driver's joined *_all.csv beside them."""
import csv

import pytest

from analysis import functional, make_tables
from analysis.tests import synth
from analysis.tests.test_make_tables import PARAMS

GW = ("tool=SecOC gateway", "commit=abc1234", "mainfunction=cyclic", "mf_period_us=1000", "t_min_ms=1000")


def lines(head, header, rows, nodelay):
    """A gateway file: the first connection's line stands below the header row, a later connection's after the rows."""
    return ("".join(f"# {c}\n" for c in head) + header + "\n" + "".join(f"# tcp_nodelay={v}\n" for v in nodelay[:1])
            + "".join(",".join(map(str, r)) + "\n" for r in rows) + "".join(f"# tcp_nodelay={v}\n" for v in nodelay[1:]))


def app_tx(rows, streams=1, host="iris", nodelay=("1",), payload_len=8):
    """rows: (stream, seq) of a PDU; the transmitter writes a row only when the transmission is confirmed."""
    head = ("loop=closed", "commit=abc1234", f"host={host}", "role=tx", "profile=mldsa65", f"streams={streams}",
            f"payload_len={payload_len}", "period_cycles=10", "count=5", "not_recorded=auth_done_ns")
    return lines(head, "stream,seq,submit_ns,start_ns,auth_done_ns,send_done_ns",
                 [(r[0], r[1], 1000, 1001, 0, 2000) for r in rows], nodelay)


def app_rx(rows, nodelay=("1",)):
    """rows: (stream, seq) delivered, or (stream, seq, result)."""
    head = ("commit=abc1234", "role=rx", "profile=mldsa65", "count=0", "not_recorded=rx_done_ns")
    return lines(head, "stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result",
                 [(r[0], r[1], 0, 5000, 5001 if len(r) < 3 or r[2] == "ok" else 0, r[2] if len(r) > 2 else "ok") for r in rows], nodelay)


def payload(rows, nodelay=("1",)):
    """rows: (stream, seq) with the pattern of the gateway application, or (stream, seq, hex)."""
    head = ("commit=abc1234", "role=rx", "profile=mldsa65", "count=0")
    return lines(head, "stream,seq,payload_hex", [(r[0], r[1], r[2] if len(r) > 2 else f"{r[0]:02x}000000{r[1]:08x}") for r in rows], nodelay)


def handshake(role, results, host, nodelay=("1",)):
    rows = [(i, role, r, *((2_000_000, 4575, 4511, 100_000, 0, 50_000, 400_000, 100_000, 1_000, 15_000, 5_000) if r == "ok"
                           else (9_000_000, 1225, 0, 0, 0, 0, 0, 0, 0, 0, 0))) for i, r in enumerate(results)]
    return lines((*GW, f"host={host}"), synth.HANDSHAKE_HEADER, rows, nodelay)


def run(tmp_path, name, files, marker=True, at=""):
    d = tmp_path / name / at
    d.mkdir(parents=True)
    if marker:
        (d / "FUNCTIONAL").write_text("Functional run: delivery and rejection counts only. Nothing here is a timing result.\n")
    for rel, content in files.items():
        (d / rel).write_text(content)
    s = make_tables.run(tmp_path / name, tmp_path / (name + "_out"), **PARAMS)
    with open(tmp_path / (name + "_out") / "numbers.csv", newline="") as f:
        return s, {r["key"]: r for r in csv.DictReader(f)}


def plain(stream, seqs):
    return [(stream, q) for q in seqs]


SOUND = {"app_tx.csv": app_tx(plain(0, range(5)) + plain(1, range(5)), streams=2), "app_rx.csv": app_rx(plain(0, range(5)) + plain(1, range(5))),
         "rx_payload.csv": payload(plain(0, range(5)) + plain(1, range(5))),
         "handshake_tx.csv": handshake("initiator", ["ok"], "iris"), "handshake_rx.csv": handshake("responder", ["ok"], "baolong")}


def test_matching_the_delivered_against_the_sent_sequence():
    """in_order: each delivered sequence number is looked for in the sent sequence after the last one found."""
    assert functional.in_order([0, 1, 2, 3], [0, 1, 2, 3]) == [True] * 4
    assert functional.in_order([0, 1, 2, 3, 4], [0, 1, 3, 2, 4]) == [True, True, True, False, True]  # 2 arrives after 3
    assert functional.in_order([0, 1, 2], [0, 1, 1, 2]) == [True, True, False, True]                 # a second copy of 1
    assert functional.in_order([0, 1, 2], [0, 7, 2]) == [True, False, True]                          # 7 was never sent
    assert functional.in_order([0, 1, 2, 0, 1, 2, 3], [0, 1, 2, 0, 1, 2, 3]) == [True] * 7           # a restarted transmitter counts from 0
    assert functional.in_order([0, 1, 2, 3], [2, 3]) == [True, True] and functional.in_order([], [0]) == [False]
    # the payload of the contract: byte 0 the stream index, bytes 1 to 3 zero, bytes 4 to 7 the sequence number
    assert functional.pattern("2", 2499, 8) == "02000000000009c3" and functional.pattern("3", 0, 8) == "0300000000000000"
    assert functional.pattern("1", 0x01020304, 8) == "0100000001020304" and functional.pattern("255", 2 ** 32 - 1, 8) == "ff000000ffffffff"
    assert functional.pattern("0", 2 ** 32, 8) is None   # no 32-bit sequence number
    assert functional.pattern("0", 1, 4) is None         # the pattern is defined for eight bytes only


def test_a_sound_run_gives_counts_per_stream_and_never_a_time(tmp_path):
    s, rows = run(tmp_path, "sound", SOUND)
    assert s["invalid_runs"] == [] and s["results"]["handshake"] == [] and len(s["results"]["functional"]) == 1
    got = {k.removeprefix("functional."): r["formatted"] for k, r in rows.items() if k.startswith("functional.")}
    assert got == {
        "streams": "2", "tx.parts": "1", "rx.parts": "1", "sent": "10", "delivered": "10",
        "delivered_in_order": "10", "lost": "0", "delivered_byte_exact": "10", "rejected": "0", "rejected_freshness_fail": "0",
        "rejected_auth_fail": "0", "rejected_framing_fail": "0",
        "s0.sent": "5", "s0.delivered": "5", "s0.delivered_in_order": "5", "s0.delivered_byte_exact": "5", "s0.lost": "0",
        "s1.sent": "5", "s1.delivered": "5", "s1.delivered_in_order": "5", "s1.delivered_byte_exact": "5", "s1.lost": "0",
        "initiator.n": "1", "initiator.result_ok": "1", "responder.n": "1", "responder.result_ok": "1",
        "tx.tcp_connections": "1", "tx.tcp_nodelay_1": "1", "rx.tcp_connections": "1", "rx.tcp_nodelay_1": "1"}
    # counts only: no key of the directory is a time, no handshake is timed, and the marker is not a 'not a result' marker
    assert not [k for k in rows if k.startswith("handshake.") or (k.startswith("functional.") and k.endswith(("_us", "_ms", "_ns")))]
    assert not [k for k, r in rows.items() if r["unit"] not in ("count", "id") and not k.startswith("run.")]
    assert "notaresult" not in (tmp_path / "sound_out" / "numbers.tex").read_text() and s["not_a_result"] is None
    assert "total_us" not in str(s["results"]["functional"]) and "handshake" not in s["tables"]
    table = (tmp_path / "sound_out" / "tables" / "functional.md").read_text()
    assert "| . | mldsa65 | 2 | 1 | 1 | 10 | 10 | 10 | 10 | 0 | 0 | 0 | ok: 1 | ok: 1 | 1 | 1 |" in table
    assert "does not test the sequence number independently of the payload" in table and "writes no row" in table
    assert rows["functional.delivered"]["n"] == "10" and rows["functional.s1.delivered"]["n"] == "5"  # n: the PDUs sent


def test_parts_of_a_replaced_process_are_added_and_the_joined_files_are_not_read(tmp_path):
    """A receiver replaced after two PDUs (two PDUs meet the new one before its session: freshness_fail, seq -1), then
    a transmitter replaced after five, which counts from 0 again. Ten parts in all, read in numeric order; the driver's
    *_all.csv hold the same rows again and are listed, not read."""
    files = {"app_tx.csv": app_tx(plain(0, range(5)), nodelay=("1", "1")), "app_tx2.csv": app_tx(plain(0, range(3))),
             "app_tx_all.csv": app_tx(plain(0, range(5)) + plain(0, range(3)), nodelay=("1", "1", "1")),
             "app_rx.csv": app_rx(plain(0, range(2))),
             "app_rx2.csv": app_rx([(0, -1, "freshness_fail"), (0, -1, "freshness_fail"), (0, 4)] + plain(0, range(3)), nodelay=("1", "1")),
             "app_rx_all.csv": app_rx(plain(0, range(2)) + [(0, -1, "freshness_fail")] * 2 + [(0, 4)] + plain(0, range(3)), nodelay=("1", "1", "1")),
             "rx_payload.csv": payload(plain(0, range(2))), "rx_payload2.csv": payload([(0, 4)] + plain(0, range(3)), nodelay=("1", "1")),
             "rx_payload_all.csv": payload(plain(0, range(2)) + [(0, 4)] + plain(0, range(3))),
             "handshake_tx.csv": handshake("initiator", ["ok", "ok"], "iris", nodelay=("1", "1")),
             "handshake_tx2.csv": handshake("initiator", ["ok"], "iris"),
             "handshake_tx_all.csv": handshake("initiator", ["ok", "ok", "ok"], "iris"),
             "handshake_rx.csv": handshake("responder", ["ok"], "baolong"),
             "handshake_rx2.csv": handshake("responder", ["timeout", "ok", "ok"], "baolong", nodelay=("1", "1"))}
    s, rows = run(tmp_path, "parts", files)
    f = {k.removeprefix("functional."): r["formatted"] for k, r in rows.items() if k.startswith("functional.")}
    assert (f["tx.parts"], f["rx.parts"], f["sent"], f["delivered"], f["delivered_in_order"], f["delivered_byte_exact"]) == ("2", "2", "8", "6", "6", "6")
    assert (f["rejected"], f["rejected_freshness_fail"], f["rejected_auth_fail"]) == ("2", "2", "0")
    assert (f["initiator.n"], f["initiator.result_ok"], f["responder.n"], f["responder.result_ok"], f["responder.result_timeout"]) == ("3", "3", "4", "3", "1")
    assert (f["tx.tcp_connections"], f["tx.tcp_nodelay_1"], f["rx.tcp_connections"], f["rx.tcp_nodelay_1"]) == ("3", "3", "3", "3")
    joined = sorted(e["path"] for e in s["skipped_csv"] if e["reason"] == make_tables.JOINED)
    assert joined == ["app_rx_all.csv", "app_tx_all.csv", "handshake_tx_all.csv", "rx_payload_all.csv"] and s["invalid_runs"] == []
    (t,) = s["results"]["functional"]
    assert [p["source"] for p in t["files"]] == ["app_tx.csv", "app_tx2.csv", "app_rx.csv", "app_rx2.csv", "rx_payload.csv", "rx_payload2.csv",
                                                 "handshake_tx.csv", "handshake_tx2.csv", "handshake_rx.csv", "handshake_rx2.csv"]
    # numeric order of the parts: part 10 comes after part 2 (as text it would come before)
    many = {**SOUND, "app_rx.csv": app_rx(plain(0, [0])), "rx_payload.csv": payload(plain(0, [0])),
            **{f"app_rx{k}.csv": app_rx(plain(0, [k - 1])) for k in range(2, 11)},
            **{f"rx_payload{k}.csv": payload(plain(0, [k - 1])) for k in range(2, 11)},
            "app_tx.csv": app_tx(plain(0, range(10)))}
    s, rows = run(tmp_path, "many", many)
    assert (rows["functional.rx.parts"]["formatted"], rows["functional.delivered_in_order"]["formatted"]) == ("10", "10")


def test_rejections_order_and_payload_are_counted_against_what_was_sent(tmp_path):
    """Eight forged PDUs before the session (freshness_fail) and three tampered ones (auth_fail), seq -1 as the
    receiver cannot number them; of the six genuine PDUs 0..5, number 3 arrives before 2, number 4 twice, 5 not at
    all, and the payload of number 1 has a byte that is not of the pattern. Byte-exact is a delivered PDU that is in
    the transmitter's order and has the pattern: 0, 3 and the first 4."""
    rx_rows = [(0, -1, "freshness_fail")] * 8 + [(0, 0), (0, 1), (0, -1, "auth_fail"), (0, 3), (0, 2)] + [(0, -1, "auth_fail")] * 2 + [(0, 4), (0, 4)]
    files = {**SOUND, "app_tx.csv": app_tx(plain(0, range(6))), "app_rx.csv": app_rx(rx_rows),
             "rx_payload.csv": payload([(0, 0), (0, 1, "0000ff0000000001"), (0, 3), (0, 2), (0, 4), (0, 4)])}
    s, rows = run(tmp_path, "forged", files)
    f = {k.removeprefix("functional."): r["formatted"] for k, r in rows.items() if k.startswith("functional.")}
    assert (f["sent"], f["delivered"], f["delivered_in_order"], f["delivered_byte_exact"]) == ("6", "6", "4", "3")
    assert "functional.sent_unconfirmed" not in rows  # a row of app_tx is a confirmed PDU: there is nothing else to count
    assert (f["rejected"], f["rejected_freshness_fail"], f["rejected_auth_fail"], f["rejected_framing_fail"]) == ("11", "8", "3", "0")
    assert s["invalid_runs"] == []


def test_a_run_in_which_nothing_was_sent_is_a_result_with_zeros(tmp_path):
    """A receiver with the wrong peer key: every handshake fails and no PDU is sent. The files are there with their
    header rows: that is a complete run whose counts are zero, not a missing one."""
    files = {"app_tx.csv": app_tx([], streams=2), "app_rx.csv": app_rx([]), "rx_payload.csv": payload([]),
             "handshake_tx.csv": handshake("initiator", ["timeout"] * 6, "baolong"),
             "handshake_rx.csv": handshake("responder", ["unknown_id"] * 7, "baolong")}  # a loopback run: both ends on one host
    s, rows = run(tmp_path, "wrongkey", files)
    f = {k.removeprefix("functional."): r["formatted"] for k, r in rows.items() if k.startswith("functional.")}
    assert s["invalid_runs"] == [] and (f["sent"], f["delivered"], f["delivered_in_order"], f["delivered_byte_exact"], f["rejected"]) == ("0",) * 5
    assert (f["s0.sent"], f["s1.delivered"], f["streams"]) == ("0", "0", "2")
    assert (f["initiator.n"], f["initiator.result_ok"], f["initiator.result_timeout"], f["responder.result_unknown_id"]) == ("6", "0", "6", "7")
    assert not [k for k in f if "ratio" in k or "share" in k]  # counts only: no 0 / 0


def test_a_marked_directory_without_its_files_is_incomplete_not_a_result(tmp_path):
    """A run cut off before the gateways wrote anything leaves the marker alone; one that lost a side lacks that
    side's file. Neither stops the analysis and neither has a key: they are listed as invalid."""
    s, rows = run(tmp_path, "cut", {"cmd.txt": "x\n"})
    assert not [k for k in rows if k.startswith("functional.")] and s["results"]["functional"] == []
    assert [(f["source"], f["experiment"], f["reasons"]) for f in s["invalid_runs"]] == [("FUNCTIONAL", "functional", [make_tables.NO_FUNCTIONAL_RUN])]
    for missing, reason in (("app_rx.csv", "no app_rx*.csv: the receiving side's record is missing, the run is incomplete"),
                            ("app_tx.csv", "no app_tx*.csv: the transmitting side's record is missing, the run is incomplete"),
                            ("rx_payload.csv", "no rx_payload*.csv: the delivered payloads are missing, the run is incomplete")):
        s, rows = run(tmp_path, "without_" + missing[:-4], {k: v for k, v in SOUND.items() if k != missing})
        assert [f["reasons"] for f in s["invalid_runs"]] == [[reason]] and not [k for k in rows if k.startswith("functional.")]
        assert {e["reason"] for e in s["skipped_csv"]} == {make_tables.FUNCTIONAL_INVALID}  # the files that are there are listed
    # a process killed while writing leaves a cut row (these files have no trailer): incomplete, not a crash
    whole = app_rx(plain(0, range(5)) + plain(1, range(5)), nodelay=("1",))
    s, rows = run(tmp_path, "cut_row", {**SOUND, "app_rx.csv": whole[:whole.rstrip().rfind(",")]})
    assert [f["reasons"] for f in s["invalid_runs"]] == [["cannot be read: app_rx.csv:17: 5 fields, expected 6: '1,4,0,5000,5001'"]]
    # so does a file with other columns (a gateway of another commit): the reason says which header was found
    s, rows = run(tmp_path, "other_columns", {**SOUND, "app_tx.csv": SOUND["app_tx.csv"].replace("submit_ns", "release_ns")})
    assert [f["reasons"] for f in s["invalid_runs"]] == [[
        "cannot be read: app_tx.csv:11: header 'stream,seq,release_ns,start_ns,auth_done_ns,send_done_ns' is not the app_tx header "
        "'stream,seq,submit_ns,start_ns,auth_done_ns,send_done_ns'"]]
    # the payload file must list the delivered rows, in their order: anything else is not the record of this run
    s, rows = run(tmp_path, "other_payloads", {**SOUND, "rx_payload.csv": payload(plain(0, range(5)) + plain(1, range(4)))})
    assert [f["reasons"] for f in s["invalid_runs"]] == [[
        "rx_payload*.csv has 9 rows, app_rx*.csv has 10 delivered rows: the payload file does not list the delivered PDUs"]]
    s, rows = run(tmp_path, "payload_order", {**SOUND, "rx_payload.csv": payload(plain(1, range(5)) + plain(0, range(5)))})
    assert [f["reasons"] for f in s["invalid_runs"]] == [[
        "rx_payload*.csv row 1 is stream 1 seq 0, delivered row 1 of app_rx*.csv is stream 0 seq 0: the payload file does not "
        "list the delivered PDUs in their order"]]


def test_only_a_marked_directory_is_a_functional_run_and_nothing_in_it_is_timed(tmp_path):
    """The gateways' files also lie in attack and negative-test directories, where they stay unread. Inside a marked
    directory nothing is a timing result: its handshake files are counted, and any other timing file is listed."""
    s, rows = run(tmp_path, "unmarked", {**SOUND, "crypto_ops.csv": synth.crypto_ops()}, marker=False)
    assert s["results"]["functional"] == [] and not [k for k in rows if k.startswith("functional.")]
    assert sorted(e["path"] for e in s["skipped_csv"] if e["reason"] == "file name not recognised") == ["app_rx.csv", "app_tx.csv", "rx_payload.csv"]
    assert len(s["results"]["handshake"]) == 2  # without the marker these are handshake files like any other
    s, rows = run(tmp_path, "marked", {**SOUND, "periodic_tx.csv": synth.periodic_tx_one_stream(), "crypto_ops.csv": synth.crypto_ops()})
    assert s["results"]["periodic"] == [] and s["results"]["crypto_ops"] == [] and s["results"]["handshake"] == []
    assert sorted(e["path"] for e in s["skipped_csv"] if e["reason"] == make_tables.NOT_TIMED) == ["crypto_ops.csv", "periodic_tx.csv"]
    assert rows["functional.delivered"]["formatted"] == "10" and not [k for k in rows if k.endswith(("_us", "_ms"))]
    # several marked directories below one run directory: each is its own run, keyed by its directory
    for name in ("run_a", "run_b"):
        (tmp_path / "several" / name).mkdir(parents=True)
        for rel, content in {**SOUND, "FUNCTIONAL": "x\n"}.items():
            (tmp_path / "several" / name / rel).write_text(content)
    s = make_tables.run(tmp_path / "several", tmp_path / "several_out", **PARAMS)
    assert [t["source"] for t in s["results"]["functional"]] == ["run_a", "run_b"]
    keys = (tmp_path / "several_out" / "numbers.csv").read_text()
    assert "functional.run_a.delivered," in keys and "functional.run_b.s1.sent," in keys


def test_byte_exact_is_judged_for_eight_byte_payloads_only(tmp_path):
    """The payload pattern is defined for payload_len=8. For another length nothing says what the bytes should be: no
    byte-exact key."""
    files = {**SOUND, "app_tx.csv": app_tx(plain(0, range(5)) + plain(1, range(5)), streams=2, payload_len=16)}
    s, rows = run(tmp_path, "len16", files)
    assert "functional.delivered_byte_exact" not in rows and "functional.s0.delivered_byte_exact" not in rows
    assert rows["functional.delivered_in_order"]["formatted"] == "10"
    assert s["invalid_runs"] == [] and "not judged" in (tmp_path / "len16_out" / "tables" / "functional.md").read_text()


def test_every_connection_of_a_functional_run_must_read_tcp_nodelay_1(tmp_path):
    """DATA_SCHEMA.md, 'Functional runs': a read-back other than 1 on any connection makes the run invalid, and so does
    a file without any read-back line when its process carried PDUs. The read-backs of a valid run are keys as well."""
    two = app_rx(plain(0, range(5)) + plain(1, range(5)), nodelay=("1", "1"))
    s, rows = run(tmp_path, "two", {**SOUND, "app_rx.csv": two})
    assert s["invalid_runs"] == [] and (rows["functional.rx.tcp_connections"]["formatted"], rows["functional.rx.tcp_nodelay_1"]["formatted"]) == ("2", "2")
    for name, files, reasons in (
            ("second_0", {"app_rx.csv": two.replace("# tcp_nodelay=1\n", "# tcp_nodelay=0\n").replace("# tcp_nodelay=0\n", "# tcp_nodelay=1\n", 1)},
             ["app_rx.csv: TCP connection 2 of 2 reads tcp_nodelay=0, not 1"]),
            ("unread", {"handshake_tx.csv": handshake("initiator", ["ok"], "iris", nodelay=("-1",))},
             ["handshake_tx.csv: TCP connection 1 of 1 reads tcp_nodelay=-1, not 1"]),
            ("no_line", {"app_tx.csv": app_tx(plain(0, range(5)) + plain(1, range(5)), streams=2, nodelay=())},
             ["app_tx.csv: no tcp_nodelay line although its process carried PDUs: no connection was read back"]),
            ("no_line_beside", {"rx_payload.csv": payload(plain(0, range(5)) + plain(1, range(5)), nodelay=())},
             ["rx_payload.csv: no tcp_nodelay line although its process carried PDUs: no connection was read back"])):
        s, rows = run(tmp_path, name, {**SOUND, **files})
        assert [f["reasons"] for f in s["invalid_runs"]] == [reasons] and not [k for k in rows if k.startswith("functional.")]
    # a run without a session carried no PDU: files without a line (a gateway from before the read-back) do not make it
    # invalid; no connection is counted
    quiet = {"app_tx.csv": app_tx([], nodelay=()), "app_rx.csv": app_rx([], nodelay=()), "rx_payload.csv": payload([], nodelay=()),
             "handshake_tx.csv": handshake("initiator", ["timeout"], "iris", nodelay=()),
             "handshake_rx.csv": handshake("responder", ["unknown_id"], "iris", nodelay=())}
    s, rows = run(tmp_path, "quiet", quiet)
    assert s["invalid_runs"] == [] and (rows["functional.tx.tcp_connections"]["formatted"], rows["functional.sent"]["formatted"]) == ("0", "0")
