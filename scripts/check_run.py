#!/usr/bin/env python3
"""Check a Tx/Rx run of the gateway applications (app_tx.csv, app_rx.csv: functional evidence from a
closed-loop sender, not the periodic files of DATA_SCHEMA.md): every PDU sent was delivered once,
in order, byte-exact; the only rejected PDUs are the ones the run injected on purpose; both files
come from the expected commit; and, for runs over eth0, the link did not change under the run.
With several streams (column "stream" = signature stream 0..7) every check is made per stream and
expected_count is the number of PDUs per stream.

Usage: check_run.py <app_tx.csv> <app_rx.csv> [expected_count]
                    [--payload rx_payload.csv] [--expect auth_fail=1,framing_fail=0] [--none-delivered]
                    [--commit <hash>] [--env env_<host>.txt ...]
                    [--handshake handshake_tx.csv handshake_rx.csv] [--expect-hs "tx:ok=1 rx:ok=1"] [--no-pdu]
Exit code 0 only if all checks pass.
"""
import argparse
import csv
import sys

TX_COLUMNS = ["stream", "seq", "submit_ns", "start_ns", "auth_done_ns", "send_done_ns"]
RX_COLUMNS = ["stream", "seq", "rx_done_ns", "verify_done_ns", "deliver_ns", "result"]
HS_COLUMNS = "seq,role,result,total_ns,bytes_tx,bytes_rx,keygen_ns,encaps_ns,decaps_ns,sign_ns,verify_ns,kdf_ns,hash_ns,mac_ns".split(",")
FAILURES = ["freshness_fail", "auth_fail", "framing_fail"]
# env_<host>.txt fields that must read the same before and after a run over eth0
LINK_SAME = ["eth0_carrier_changes", "eth0_addr", "eth0_rbuf_ovflow_cnt", "eth0_eee", "eth0_speed_mbit", "throttled"]
LINK_DELTA = ["TcpRetransSegs", "TcpExtTCPTimeouts"]


def read_csv(path):
    """-> (comment key/values in order, column names, rows as dicts)"""
    keys, lines = [], []
    with open(path, newline="") as f:
        for line in f:
            if line.startswith("#"):
                if "=" in line:
                    keys.append(tuple(line[1:].strip().split("=", 1)))
            else:
                lines.append(line)
    reader = csv.DictReader(lines)
    return keys, reader.fieldnames, list(reader)


def nodelay_check(name, keys):
    """The gateway writes "# tcp_nodelay=<v>" into each log for every TCP connection it has: the value its
    socket reports (getsockopt), not the configured one. At least one line, and every one of them 1."""
    values = [v for k, v in keys if k.strip() == "tcp_nodelay"]
    return ("%s: TCP_NODELAY read back from the socket is 1 for every connection (%s)" % (name, ",".join(values) or "no line"),
            bool(values) and all(v == "1" for v in values))


def read_env(path):
    """-> {"before": {...}, "after": {...}} of the last before/after pair in the file"""
    blocks, label = {}, None
    with open(path) as f:
        for line in f:
            if line.startswith("====="):
                label = line.split()[1]
                blocks[label] = {}
            elif label and "=" in line:
                key, value = line.rstrip("\n").split("=", 1)
                blocks[label][key] = value
    return blocks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tx")
    ap.add_argument("rx")
    ap.add_argument("count", nargs="?", type=int)
    ap.add_argument("--payload")
    ap.add_argument("--expect", default="")
    ap.add_argument("--none-delivered", action="store_true")
    ap.add_argument("--no-pdu", action="store_true", help="no session came about: no Tx row and no Rx row at all")
    ap.add_argument("--restart", choices=["rx", "tx"], help="that gateway process was replaced during the run (merged logs)")
    ap.add_argument("--lost-run", action="store_true",
                    help="one run of consecutive PDUs per stream may be lost (sent while the receiver had no session)")
    ap.add_argument("--handshake", nargs=2, metavar=("TX_CSV", "RX_CSV"), help="handshake.csv of the two gateways")
    ap.add_argument("--expect-hs", default="tx:ok=1 rx:ok=1",
                    help="result counts per side, e.g. 'tx:timeout=1+ rx:unknown_id=1+' (n+ = at least n)")
    ap.add_argument("--commit")
    ap.add_argument("--env", nargs="*", default=[])
    a = ap.parse_args()

    expect = dict.fromkeys(FAILURES, 0)
    for item in filter(None, a.expect.split(",")):
        name, n = item.split("=")
        assert name in expect, name
        expect[name] = int(n)

    tx_keys, tx_cols, tx = read_csv(a.tx)
    rx_keys, rx_cols, rx = read_csv(a.rx)
    results = {}
    for r in rx:
        results[r["result"]] = results.get(r["result"], 0) + 1
    ok = [r for r in rx if r["result"] == "ok"]
    framing = [r for r in rx if r["result"] == "framing_fail"]
    streams = sorted({r["stream"] for r in tx}, key=int)
    tx_seq = {st: [int(r["seq"]) for r in tx if r["stream"] == st] for st in streams}
    rx_seq = {st: [int(r["seq"]) for r in ok if r["stream"] == st] for st in streams}

    checks = [
        ("Tx columns are " + ",".join(TX_COLUMNS), tx_cols == TX_COLUMNS),
        ("Tx file says loop=closed", dict(tx_keys).get("loop") == "closed"),
        ("Tx file says streams=%d and has rows of that many streams" % len(streams), dict(tx_keys).get("streams") == str(len(streams))),
        ("Tx and Rx files carry the same commit", bool(dict(tx_keys).get("commit")) and dict(tx_keys).get("commit") == dict(rx_keys).get("commit")),
        ("Tx and Rx files are of the same variant (profile=%s)" % dict(tx_keys).get("profile", "not recorded"),
         dict(tx_keys).get("profile") == dict(rx_keys).get("profile")),
        ("Rx columns are " + ",".join(RX_COLUMNS), rx_cols == RX_COLUMNS),
        nodelay_check("Tx file", tx_keys),
        nodelay_check("Rx file", rx_keys),
        ("Tx rows of every stream are seq 0..N-1 without gap or repeat", all(q == list(range(len(q))) for q in tx_seq.values())),
        ("nothing delivered", ok == []) if a.none_delivered else
        ("per stream, delivered seq list equals sent seq list (count, order, no duplicate)", rx_seq == tx_seq),
        ("delivered rows belong to the streams that were sent", a.none_delivered or {r["stream"] for r in ok} <= set(streams)),
        ("framing_fail rows have stream -1 and seq -1", all(r["stream"] == "-1" and r["seq"] == "-1" for r in framing)),
        ("auth_fail and freshness_fail rows belong to the streams that were sent",
         all(r["stream"] in set(streams) for r in rx if r["result"] in ("auth_fail", "freshness_fail"))),
        ("no result other than ok and the three failure classes", set(results) <= set(FAILURES) | {"ok"}),
    ]
    for name in FAILURES:
        checks.append(("%s rows: %d expected" % (name, expect[name]), results.get(name, 0) == expect[name]))
    def replace_check(prefix, new):
        """the check whose name starts with <prefix> gives way to another rule"""
        index = [i for i, c in enumerate(checks) if c[0].startswith(prefix)]
        assert len(index) == 1, prefix
        checks[index[0]] = new

    if a.restart == "tx":
        # two transmitter processes: every stream is numbered from 0 twice
        def two_runs(q):
            k = q.index(0, 1) if 0 in q[1:] else len(q)
            return q == list(range(k)) + list(range(len(q) - k))
        replace_check("Tx rows of every stream are seq 0..N-1",
                      ("Tx rows of every stream are two runs of seq 0..n-1 (the transmitter was replaced once)",
                       all(two_runs(q) for q in tx_seq.values())))
    if a.restart == "rx" or a.lost_run:
        # the receiver was replaced: per stream the delivered list is the sent list without one run of
        # consecutive PDUs (those sent while no receiver ran or before the new session)
        gaps = {}
        for st in streams:
            sent, got = tx_seq[st], rx_seq[st]
            head = 0
            while head < len(got) and head < len(sent) and got[head] == sent[head]:
                head += 1
            tail = len(got) - head
            gaps[st] = len(sent) - len(got) if (tail == 0 or got[head:] == sent[len(sent) - tail:]) else None
        lost = sum(g for g in gaps.values() if g is not None)
        replace_check("per stream, delivered seq list equals sent seq list",
                      ("per stream, delivered = sent without one run of consecutive PDUs lost at the restart (lost per stream: %s)" % gaps,
                       all(g is not None and g >= 0 for g in gaps.values())))
        checks = [c for c in checks if not c[0].startswith("freshness_fail rows:")]
        checks.append(("freshness_fail rows (%d) are not more than the PDUs lost at the restart (%d)" % (results.get("freshness_fail", 0), lost),
                       results.get("freshness_fail", 0) <= lost))
    if a.no_pdu:
        # the transmitter holds everything while there is no session, so neither log has a row
        checks = [("the transmitter released no PDU (no session)", tx == []),
                  ("the receiver logged no outcome", rx == []),
                  ("Tx and Rx files carry the same commit", bool(dict(tx_keys).get("commit")) and dict(tx_keys).get("commit") == dict(rx_keys).get("commit"))]
    if a.handshake:
        want = {}
        for item in a.expect_hs.split():
            side, counts = item.split(":")
            want[side] = dict(c.split("=") for c in counts.split(","))
        for side, role, path in (("tx", "initiator", a.handshake[0]), ("rx", "responder", a.handshake[1])):
            hs_keys, hs_cols, hs = read_csv(path)
            got = {}
            for r in hs:
                got[r["result"]] = got.get(r["result"], 0) + 1
            fits = set(got) <= set(want.get(side, {}))
            for name, n in want.get(side, {}).items():
                fits = fits and (got.get(name, 0) >= int(n[:-1]) if n.endswith("+") else got.get(name, 0) == int(n))
            checks.append(("handshake.csv of the %s side: columns of the schema, every row role %s" % (side, role),
                           hs_cols == HS_COLUMNS and all(r["role"] == role for r in hs)))
            checks.append(("handshake attempts on the %s side: %s, expected %s" % (side, got, want.get(side, {})), fits))
            checks.append(("handshake.csv of the %s side carries the commit of the PDU logs" % side,
                           dict(hs_keys).get("commit") == dict(tx_keys).get("commit")))
            checks.append(nodelay_check("handshake.csv of the %s side" % side, hs_keys))
    if a.count is not None and not a.no_pdu:
        checks.insert(0, ("%d PDUs sent on each of %d stream(s)" % (a.count, len(streams)),
                          len(streams) > 0 and all(len(q) == a.count for q in tx_seq.values())))
    if a.commit:
        # a failed build must not let an older binary run under a new commit name
        checks.append(("the binaries are commit %s" % a.commit, dict(tx_keys).get("commit") == a.commit))

    payload_ok = None
    if a.payload:
        p_keys, p_cols, p = read_csv(a.payload)
        checks.append(nodelay_check("payload file", p_keys))
        # payload: stream in the first byte, seq big-endian in the last four
        payload_ok = sum(1 for r in p if r["payload_hex"] == "%02x000000%08x" % (int(r["stream"]), int(r["seq"])))
        checks.append(("payload columns are stream,seq,payload_hex", p_cols == ["stream", "seq", "payload_hex"]))
        checks.append(("one payload row per delivered PDU, same order", [(r["stream"], r["seq"]) for r in p] == [(r["stream"], r["seq"]) for r in ok]))
        checks.append(("every delivered payload is its stream number followed by the big-endian seq", payload_ok == len(p)))

    info = []
    for path in a.env:
        env = read_env(path)
        before, after = env.get("before", {}), env.get("after", {})
        host = after.get("hostname", path)
        for key in LINK_SAME:
            checks.append(("%s: %s unchanged (%s)" % (host, key, before.get(key)),
                           key in before and before.get(key) == after.get(key)))
        checks.append(("%s: EEE disabled" % host, after.get("eth0_eee") == "disabled"))
        # low four bits of get_throttled: under-voltage, frequency capped or throttled right now
        thr = after.get("throttled", "").split("=")[-1]
        checks.append(("%s: no throttling active now (%s)" % (host, thr), thr.startswith("0x") and int(thr, 16) & 0xF == 0))
        for key in LINK_DELTA:
            if key in before and key in after:
                info.append("%s: %s +%d (host-wide counter, includes the ssh sessions over wlan0)"
                            % (host, key, int(after[key]) - int(before[key])))

    print("streams=%d sent=%d delivered=%d byte_exact=%s results=%s" % (len(streams), len(tx), len(ok), payload_ok, results))
    failed = 0
    for name, passed in checks:
        print("%s  %s" % ("PASS" if passed else "FAIL", name))
        failed += 0 if passed else 1
    for line in info:
        print("INFO  " + line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
