#!/usr/bin/env python3
"""Oracle of the on-wire handshake tests (SPEC.md "Negative tests") over one hstest directory.

    check_hsneg.py <hstest directory> <test> <reps>
    check_hsneg.py --batch <hstest directory with r001, r002, ...> <test> <reps per run>
    check_hsneg.py --selftest

Output: lines for a reader, then ONE record line (DATA_SCHEMA.md), then PASS or REJECT:
    test=<n> variant=<none|drop|sig|mac|key|flip> repetitions=<asked> attacked=<handshakes edited, messages
    injected or probes sent> verdict=<PASS|FAIL> expected_tx=<result:count,...> seen_tx=<...> expected_rx=<...>
    seen_rx=<...> repetitions_done=<k> runs=<n> runs_passed=<n> pdus_sent=<n> pdus_delivered=<n>
    pdus_rejected=<n> pdus_given_up=<n> installs_tx=<n> installs_rx=<n> tcp_nodelay_tx=<1|0|-1> tcp_nodelay_rx=<1|0|-1>
tx is the initiator, rx the responder. expected_* are the rows of the first handshake plus those of the complete
repetitions found; seen_* are all rows of the side's handshake file (a run may end inside one more repetition).
Over a batch the counts are summed over its runs and the verdict is PASS only when every run passed.

<test> is one of: 1 2 3 4 5 6 7 8 9 10 11drop 11sig 11mac 11key 12drop 12flip. The directory is what
run_bench_net.sh hstest leaves. Initiator A: the gateway (handshake_gw_tx.csv, its console tx.log,
app_tx.csv) or the harness (handshake_tx.csv, periodic_tx.csv). Responder B: the gateway
(handshake_gw_rx.csv, gw_rx_banner.txt, app_rx.csv) or the harness (handshake_rx.csv, periodic_rx.csv).
Also hs_edits.csv, and side_probes_*.txt for tests 9 and 10.

What must hold (exit status 0 only then):
  - each side's attempt record is: ok (session 1), then the rows of the attacked handshake, repeated at
    least <reps> times (EXPECT below; the run may end inside the last repetition);
  - tests 1 to 10: both sides still name session 1 with installation counter 1, and every PDU the
    transmitter sent was delivered, none rejected;
  - tests 11 and 12 (every second handshake attacked, the one after it genuine): both sides end in the
    same session; A installed twice per repetition; B once (11: only the genuine handshake) or twice
    (12); test 12 loses no PDU; test 11 may, the number is printed, and the last 100 PDUs sent are
    delivered;
  - the proxy logged at least <reps> edits or injections (not tests 9, 10);
  - tests 9, 10: no handshake row beyond the first ok, no UDP listener on the old port on either board,
    no answer to the datagrams, the second TCP connection got no byte back and was closed or refused;
  - both ends report TCP_NODELAY = 1 for every TCP connection they had (the gateway's '# tcp_nodelay='
    lines in app_tx.csv / app_rx.csv, a harness's header line): CAMPAIGN.md.
"""
import csv
from collections import Counter
import os
import re
import sys

# rows per attacked handshake: (initiator A, responder B); "discard" rows first, then the row that ends the attempt
STAY = {
    "1": (["sig_fail", "timeout"], ["timeout"]),      # foreign ek: B signs another transcript
    "2": (["sig_fail", "timeout"], ["timeout"]),      # other ct
    "3": (["sig_fail", "timeout"], ["timeout"]),      # sig_B by another key
    "4": (["mac_fail"], ["timeout"]),                 # only mac_B altered
    "5": (["state"], ["timeout"]),                    # old M1 sent to B: A gets an M2 it did not ask for
    "6": (["sig_fail", "timeout"], ["timeout"]),      # old M2 in place of the live one
    "7": ([], ["state"]),                             # old M3 sent to B with nothing pending
    "8": (["timeout"], ["unknown_id"]),               # ID_A altered
    "9": ([], []), "10": ([], []),
}
# attacked handshake followed by the genuine one: (A rows, B rows, installations of B per repetition)
ALTERNATE = {
    "11drop": (["timeout", "ok"], ["timeout", "ok"], 1),
    "11sig": (["timeout", "ok"], ["sig_fail", "timeout", "ok"], 1),
    "11mac": (["timeout", "ok"], ["mac_fail", "ok"], 1),
    "11key": (["timeout", "ok"], ["sig_fail", "timeout", "ok"], 1),
    "12drop": (["timeout", "ok"], ["ok", "ok"], 2),
    "12flip": (["mac_fail", "timeout", "ok"], ["ok", "ok"], 2),
}


def repetitions(rows, pattern):
    """Complete repetitions of `pattern` after the leading 'ok', or None if the rows are not
    ok + pattern * k + a beginning of pattern. The run may end inside a repetition: when the connection
    closes while an attempt is open, the component ends that attempt with one last row 'state'."""
    if not rows or rows[0] != "ok":
        return None
    rest = rows[1:]
    if not pattern:
        return 0 if not rest else None
    for body in ((rest, rest[:-1]) if rest[-1:] == ["state"] else (rest,)):
        k, tail = divmod(len(body), len(pattern))
        if body == pattern * k + pattern[:tail]:
            return k
    return None


def judge(test, reps, a_rows, b_rows, a, b, results, sent, edits, probes="", nodelay=("1", "1")):
    """List of failures. a, b: {'first': sid, 'last': sid, 'installs': n}; results: the receiver's result
    column in order; sent: PDUs the transmitter got confirmed; edits: rows of the proxy's handshake log;
    nodelay: end_nodelay() of the initiator's and the responder's log."""
    bad = []
    if tuple(nodelay) != ("1", "1"):
        bad.append(f"TCP_NODELAY read back: initiator {nodelay[0]}, responder {nodelay[1]}; both must be 1 on every connection")
    stay = test in STAY
    if not stay and test not in ALTERNATE:
        return [f"unknown test {test!r}"]
    pattern_a, pattern_b = (STAY[test] if stay else ALTERNATE[test][:2])
    counts = []
    for side, rows, pattern in (("A", a_rows, pattern_a), ("B", b_rows, pattern_b)):
        k = repetitions(rows, pattern)
        if k is None:
            bad.append(f"{side}: attempt record {rows} is not ok + {pattern} repeated")
        elif pattern:
            counts.append(k)
    if test not in ("9", "10"):
        if counts and min(counts) < reps:
            bad.append(f"{min(counts)} complete repetitions, {reps} wanted")
        if edits < reps:
            bad.append(f"the proxy logged {edits} edits or injections, {reps} wanted")
    delivered, rejected = results.count("ok"), len(results) - results.count("ok")
    if stay:
        for side, m in (("A", a), ("B", b)):
            if m["last"] != m["first"] or m["installs"] != 1:
                bad.append(f"{side}: session {m['first']} -> {m['last']}, installation counter {m['installs']}: session 1 did not stay")
        if a["first"] != b["first"]:
            bad.append(f"the two sides never agreed on session 1 ({a['first']} / {b['first']})")
        if delivered != sent or rejected:
            bad.append(f"{sent} PDUs sent, {delivered} delivered, {rejected} rejected: session 1 did not keep working")
    else:
        k = min(counts) if counts else 0
        per_b = ALTERNATE[test][2]
        if a["last"] != b["last"]:
            bad.append(f"the two sides end in different sessions ({a['last']} / {b['last']})")
        if a["installs"] != 1 + 2 * k or b["installs"] != 1 + per_b * k:
            bad.append(f"installation counters A {a['installs']} B {b['installs']}, expected {1 + 2 * k} and {1 + per_b * k} for {k} repetitions")
        if test.startswith("12") and (delivered != sent or rejected):
            bad.append(f"{sent} PDUs sent, {delivered} delivered, {rejected} rejected: delivery was interrupted")
        if results[-100:].count("ok") != min(100, len(results)) or not results:
            bad.append("the last 100 PDU rows are not all delivered: delivery did not resume")
    if test in ("9", "10"):
        if re.search(r"udp_listeners=[1-9]", probes) or probes.count("probe=listeners") < 2:
            bad.append("a UDP listener on the old control port, or the listener probe did not run on both boards")
        udp = [(int(c), int(a)) for c, a in re.findall(r"probe=udp .*count=(\d+) answers=(\d+)", probes)]
        if test == "9" and (len(udp) < 2 or any(a for _, a in udp) or max(c for c, _ in udp) < reps):
            bad.append(f"UDP datagrams (count, answers) {udp}: wanted before and inside the session, {reps} or more, none answered")
        tcp = [tuple(int(x) for x in m) for m in re.findall(r"probe=tcp .*count=(\d+) no_answer=(\d+) answered=(\d+) still_open=(\d+)", probes)]
        if test == "10" and (not tcp or any(c < reps or n != c or a or o for c, n, a, o in tcp)):
            bad.append(f"second TCP connections (count, no answer, answered, still open) {tcp}: wanted {reps} or more, each refused or closed without an answer")
    return bad


def read(path):
    with open(path, newline="", errors="replace") as f:
        lines = f.read().splitlines()
    meta = dict(l[1:].strip().split("=", 1) for l in lines if l.startswith("#") and "=" in l)
    return list(csv.DictReader(l for l in lines if not l.startswith("#"))), meta


def end_nodelay(path):
    """'1' when the file has at least one '# tcp_nodelay=' line and every one says 1, '0' when one says 0,
    None otherwise (as in join_attack.py; the scripts run isolated and share no module)."""
    values = []
    if os.path.exists(path):
        with open(path, errors="replace") as f:
            values = [line.strip().split("=", 1)[1] for line in f if line.startswith("# tcp_nodelay=")]
    if "0" in values:
        return "0"
    return "1" if values and set(values) == {"1"} else None


def console_sessions(path):
    """First and last session and the installation counter from a gateway's '[App_Hs] keys installed' lines."""
    with open(path, errors="replace") as f:
        installs = re.findall(r"keys installed: installation (\d+), sid ([0-9a-f]{8})", f.read())
    if not installs:
        return {"first": None, "last": None, "installs": 0}
    return {"first": installs[0][1], "last": installs[-1][1], "installs": int(installs[-1][0])}


RESULT_ORDER = ("ok", "bad_ver", "bad_len", "unknown_id", "sig_fail", "mac_fail", "timeout", "state")


def counts_text(counter):
    """'ok:1,sig_fail:3,timeout:3': the result classes that occur, in the order of the schema; 'none' if empty."""
    return ",".join(f"{k}:{counter[k]}" for k in RESULT_ORDER if counter.get(k)) or "none"


def expected_counts(rows, pattern):
    """(counts of the first handshake plus the complete repetitions of the pattern found in rows, their number)."""
    done = repetitions(rows, pattern) or 0
    return Counter(["ok"] + list(pattern) * done), done


def evaluate(d, test, reps):
    """One hstest directory: (the values of the record line, the list of failures, the lines for a reader)."""
    if os.path.exists(f"{d}/handshake_gw_tx.csv"):      # a gateway logs its installations on its console
        a_rows = read(f"{d}/handshake_gw_tx.csv")[0]
        a = console_sessions(f"{d}/tx.log")
        traffic = read(f"{d}/app_tx.csv")[0]
        sent = sum(1 for r in traffic if r["send_done_ns"] != "0")
        given_up = len(traffic) - sent
        a_nodelay = end_nodelay(f"{d}/app_tx.csv")
    else:
        a_nodelay = end_nodelay(f"{d}/periodic_tx.csv")
        a_rows, a_meta = read(f"{d}/handshake_tx.csv")
        a = {"first": a_meta.get("session_id_first"), "last": a_meta.get("session_id"), "installs": int(a_meta.get("hs_installs", -1))}
        tx_meta = read(f"{d}/periodic_tx.csv")[1]
        sent = int(tx_meta.get("jobs_confirmed", -1))
        given_up = int(tx_meta.get("jobs_started", -1)) - sent
    if os.path.exists(f"{d}/handshake_gw_rx.csv"):
        b_rows = read(f"{d}/handshake_gw_rx.csv")[0]
        b = console_sessions(f"{d}/gw_rx_banner.txt")
        results = [r["result"] for r in read(f"{d}/app_rx.csv")[0]]
        b_nodelay = end_nodelay(f"{d}/app_rx.csv")
    else:
        b_nodelay = end_nodelay(f"{d}/periodic_rx.csv")
        b_rows, b_meta = read(f"{d}/handshake_rx.csv")
        b = {"first": b_meta.get("session_id_first"), "last": b_meta.get("session_id"), "installs": int(b_meta.get("hs_installs", -1))}
        results = [r["result"] for r in read(f"{d}/periodic_rx.csv")[0]]
    edits = len(read(f"{d}/hs_edits.csv")[0]) if os.path.exists(f"{d}/hs_edits.csv") else 0
    probes = ""
    for name in ("side_probes_tx.txt", "side_probes_rx.txt"):
        if os.path.exists(f"{d}/{name}"):
            with open(f"{d}/{name}", errors="replace") as f:
                probes += f.read()
    a_results, b_results = [r["result"] for r in a_rows], [r["result"] for r in b_rows]
    bad = judge(test, reps, a_results, b_results, a, b, results, sent, edits, probes, (a_nodelay, b_nodelay))
    if given_up:    # CAMPAIGN.md: a traffic log with a job given up without a confirmation is invalid
        bad.append(f"{given_up} PDUs of the transmitter were given up without a confirmation: the traffic log is invalid")
    pattern_a, pattern_b = (STAY[test] if test in STAY else ALTERNATE[test][:2]) if (test in STAY or test in ALTERNATE) else ([], [])
    expected_a, done_a = expected_counts(a_results, pattern_a)
    expected_b, done_b = expected_counts(b_results, pattern_b)
    if test == "9":         # the datagrams sent inside the session
        attacked = max([int(c) for c in re.findall(r"probe=udp .*count=(\d+)", probes)] or [0])
    elif test == "10":      # the second TCP connections
        attacked = sum(int(c) for c in re.findall(r"probe=tcp .*count=(\d+)", probes))
    else:
        attacked = edits
    values = {"repetitions": reps, "attacked": attacked, "passed": int(not bad), "runs": 1,
              "expected_tx": expected_a, "seen_tx": Counter(a_results), "expected_rx": expected_b, "seen_rx": Counter(b_results),
              "repetitions_done": min([n for n, pattern in ((done_a, pattern_a), (done_b, pattern_b)) if pattern] or [0]),
              "pdus_sent": sent, "pdus_delivered": results.count("ok"), "pdus_rejected": len(results) - results.count("ok"),
              "pdus_given_up": given_up, "installs_tx": a["installs"], "installs_rx": b["installs"],
              "nodelay_tx": [a_nodelay], "nodelay_rx": [b_nodelay]}
    text = [f"test {test}: A {a_results}", f"test {test}: B {b_results}",
            f"test {test}: A session {a['first']} -> {a['last']} installs {a['installs']}; B session {b['first']} -> {b['last']} installs {b['installs']}; "
            f"PDUs sent {sent}, delivered {results.count('ok')}, rejected {len(results) - results.count('ok')}; proxy actions {edits}"]
    return values, bad, text


def record_line(test, runs):
    """The one machine-readable line of a test (DATA_SCHEMA.md), over one run or over the runs of a batch:
    counts are summed over the runs, the verdict is PASS only when every run passed."""
    number, variant = re.fullmatch(r"(\d+)([a-z]*)", test).groups()
    total = lambda key: sum(r[key] for r in runs)
    merged = lambda key: sum((r[key] for r in runs), Counter())

    def nodelay(key):
        values = [v for r in runs for v in r[key]]
        return 0 if "0" in values else 1 if set(values) == {"1"} else -1

    return (f"test={number} variant={variant or 'none'} repetitions={total('repetitions')} attacked={total('attacked')} "
            f"verdict={'PASS' if total('passed') == len(runs) else 'FAIL'} "
            f"expected_tx={counts_text(merged('expected_tx'))} seen_tx={counts_text(merged('seen_tx'))} "
            f"expected_rx={counts_text(merged('expected_rx'))} seen_rx={counts_text(merged('seen_rx'))} "
            f"repetitions_done={total('repetitions_done')} runs={len(runs)} runs_passed={total('passed')} "
            f"pdus_sent={total('pdus_sent')} pdus_delivered={total('pdus_delivered')} pdus_rejected={total('pdus_rejected')} "
            f"pdus_given_up={total('pdus_given_up')} installs_tx={total('installs_tx')} installs_rx={total('installs_rx')} "
            f"tcp_nodelay_tx={nodelay('nodelay_tx')} tcp_nodelay_rx={nodelay('nodelay_rx')}")


def main():
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    batch = sys.argv[1:2] == ["--batch"]
    args = sys.argv[2:] if batch else sys.argv[1:]
    if len(args) != 3:
        print(__doc__)
        return 2
    d, test, reps = args[0], args[1], int(args[2])
    if not batch:
        values, bad, text = evaluate(d, test, reps)
        print("\n".join(text + [f"FAIL: {line}" for line in bad]))
        print(record_line(test, [values]))
        print("PASS" if not bad else "REJECT")
        return 0 if not bad else 1
    # a batch: the directories r001.. of <d>, each one run judged on its own; <d>/rNNN/hsneg.txt gets its lines
    runs = []
    for name in sorted(n for n in os.listdir(d) if re.fullmatch(r"r\d{3}", n)):
        try:
            values, bad, text = evaluate(f"{d}/{name}", test, reps)
        except (OSError, KeyError, ValueError) as e:        # a run that left no readable record did not pass
            values, bad, text = None, [f"no readable record: {e}"], []
        with open(f"{d}/{name}/hsneg.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(text + [f"FAIL: {line}" for line in bad] + ([record_line(test, [values])] if values else [])
                              + ["PASS" if not bad else "REJECT"]) + "\n")
        print(f"{name}: {'PASS' if not bad else 'REJECT'}" + "".join(f"; {line}" for line in bad))
        runs.append(values)
    readable = [r for r in runs if r]
    ok = bool(runs) and len(readable) == len(runs) and all(r["passed"] for r in runs)
    if readable:
        line = record_line(test, readable)
        if len(readable) != len(runs):      # a run without a record: the line must not say PASS, and it counts as a run
            line = line.replace("verdict=PASS", "verdict=FAIL").replace(f"runs={len(readable)} ", f"runs={len(runs)} ")
        print(line)
    print("PASS" if ok else "REJECT")
    return 0 if ok else 1


def selftest():
    s1 = {"first": "aa", "last": "aa", "installs": 1}
    ok_pdus = ["ok"] * 300
    checks = []
    a1 = ["ok"] + ["sig_fail", "timeout"] * 3 + ["sig_fail"]        # the run ended inside the fourth repetition
    b1 = ["ok"] + ["timeout"] * 4
    checks.append(judge("1", 3, a1, b1, s1, s1, ok_pdus, 300, 4) == [])
    checks.append(judge("1", 4, a1, b1, s1, s1, ok_pdus, 300, 4) != [])                                # one repetition short
    checks.append(judge("1", 3, a1, b1, s1, {"first": "aa", "last": "bb", "installs": 2}, ok_pdus, 300, 4) != [])  # B installed
    checks.append(judge("1", 3, a1, b1, s1, s1, ok_pdus[:-1] + ["auth_fail"], 300, 4) != [])           # a PDU rejected
    checks.append(judge("1", 3, ["ok", "timeout"] * 2, b1, s1, s1, ok_pdus, 300, 4) != [])             # A's rows off pattern
    checks.append(judge("1", 3, a1, ["ok"] + ["timeout"] * 3 + ["state"], s1, s1, ok_pdus, 300, 4) == []   # the connection closed inside the fourth
                  and judge("1", 3, a1, ["ok", "timeout", "state", "timeout", "timeout"], s1, s1, ok_pdus, 300, 4) != [])
    checks.append(judge("1", 3, a1, b1, s1, s1, ok_pdus, 300, 2) != [])                                # the proxy did less
    checks.append(judge("1", 3, a1, b1, s1, s1, ok_pdus, 300, 4, "", ("1", None)) != []                # an end without a read-back
                  and judge("1", 3, a1, b1, s1, s1, ok_pdus, 300, 4, "", ("0", "1")) != [])
    checks.append(judge("7", 2, ["ok"], ["ok", "state", "state"], s1, s1, ok_pdus, 300, 2) == [])
    checks.append(judge("7", 2, ["ok", "state"], ["ok", "state", "state"], s1, s1, ok_pdus, 300, 2) != [])   # A must see nothing
    a11 = ["ok"] + ["timeout", "ok"] * 2
    b11 = ["ok"] + ["sig_fail", "timeout", "ok"] * 2
    end_a, end_b = {"first": "aa", "last": "cc", "installs": 5}, {"first": "aa", "last": "cc", "installs": 3}
    lossy = ["ok"] * 100 + ["freshness_fail"] * 30 + ["ok"] * 170
    checks.append(judge("11sig", 2, a11, b11, end_a, end_b, lossy, 300, 2) == [])
    checks.append(judge("11sig", 2, a11, b11, end_a, {"first": "aa", "last": "cc", "installs": 5}, lossy, 300, 2) != [])  # B installed too
    checks.append(judge("11sig", 2, a11, b11, end_a, end_b, lossy[:-50] + ["auth_fail"] * 50, 300, 2) != [])             # no recovery
    checks.append(judge("12drop", 2, a11, ["ok"] + ["ok", "ok"] * 2, end_a, {"first": "aa", "last": "cc", "installs": 5}, ok_pdus, 300, 2) == [])
    checks.append(judge("12drop", 2, a11, ["ok"] + ["ok", "ok"] * 2, end_a, {"first": "aa", "last": "cc", "installs": 5}, lossy, 300, 2) != [])
    probes = ("probe=udp to=h:60500 sent_bytes=1191 count=1 answers=0\nprobe=listeners port=60500 udp_listeners=0\n"
              "probe=udp to=h:60500 sent_bytes=1191 count=100 answers=0\nprobe=listeners port=60500 udp_listeners=0\n"
              "probe=tcp from=x to=x:50104 connect=ok sent_bytes=1225 received_bytes=0 closed_by_peer_ms=3 count=100 no_answer=100 answered=0 still_open=0\n")
    checks.append(judge("9", 100, ["ok"], ["ok"], s1, s1, ok_pdus, 300, 0, probes) == [] and judge("10", 100, ["ok"], ["ok"], s1, s1, ok_pdus, 300, 0, probes) == [])
    checks.append(judge("9", 100, ["ok"], ["ok"], s1, s1, ok_pdus, 300, 0, probes.replace("udp_listeners=0", "udp_listeners=1", 1)) != [])
    checks.append(judge("9", 100, ["ok"], ["ok"], s1, s1, ok_pdus, 300, 0, probes.replace("count=100 answers=0", "count=100 answers=1")) != [])
    checks.append(judge("10", 100, ["ok"], ["ok"], s1, s1, ok_pdus, 300, 0, probes.replace("no_answer=100 answered=0", "no_answer=99 answered=1")) != [])
    checks.append(judge("10", 101, ["ok"], ["ok"], s1, s1, ok_pdus, 300, 0, probes) != [])             # one connection short
    checks.append(judge("10", 100, ["ok"], ["ok", "timeout"], s1, s1, ok_pdus, 300, 0, probes) != [])  # B answered the M1
    # the record line: counts in the order of the schema, summed over the runs of a batch, PASS only if every run passed
    run = {"repetitions": 1, "attacked": 1, "passed": 1, "runs": 1, "expected_tx": Counter(ok=2, timeout=1), "seen_tx": Counter(timeout=1, ok=2),
           "expected_rx": Counter(ok=2, sig_fail=1, timeout=1), "seen_rx": Counter(ok=2, sig_fail=1, timeout=1), "repetitions_done": 1,
           "pdus_sent": 600, "pdus_delivered": 300, "pdus_rejected": 300, "pdus_given_up": 0, "installs_tx": 3, "installs_rx": 2,
           "nodelay_tx": ["1"], "nodelay_rx": ["1"]}
    line = record_line("11sig", [run, dict(run, passed=0, nodelay_rx=[None])])
    checks.append(line.startswith("test=11 variant=sig repetitions=2 attacked=2 verdict=FAIL expected_tx=ok:4,timeout:2 seen_tx=ok:4,timeout:2 "
                                  "expected_rx=ok:4,sig_fail:2,timeout:2 seen_rx=ok:4,sig_fail:2,timeout:2 repetitions_done=2 runs=2 runs_passed=1 ")
                  and line.endswith("pdus_sent=1200 pdus_delivered=600 pdus_rejected=600 pdus_given_up=0 installs_tx=6 installs_rx=4 tcp_nodelay_tx=1 tcp_nodelay_rx=-1"))
    checks.append(record_line("4", [run]).startswith("test=4 variant=none repetitions=1 attacked=1 verdict=PASS ")
                  and expected_counts(["ok", "sig_fail", "timeout", "sig_fail"], ["sig_fail", "timeout"]) == (Counter(ok=1, sig_fail=1, timeout=1), 1)
                  and counts_text(Counter()) == "none")
    print(f"selftest: {len(checks)} checks, {checks.count(False)} failed")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
