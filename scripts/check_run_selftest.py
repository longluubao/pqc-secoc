#!/usr/bin/env python3
"""Self-test of check_run.py on small synthetic logs: python3 scripts/check_run_selftest.py
Each case names the exit code check_run.py must give (0 = every check passes)."""
import os
import subprocess
import sys
import tempfile

CHECK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_run.py")
TXH = ("# loop=closed\n# commit=abc\n# host=h\n# role=tx\n# streams=1\n# payload_len=8\n# period_cycles=10\n# count=10\n"
       "# not_recorded=auth_done_ns\nstream,seq,submit_ns,start_ns,auth_done_ns,send_done_ns\n")
RXH = "# commit=abc\n# role=rx\n# count=0\n# not_recorded=rx_done_ns\nstream,seq,rx_done_ns,verify_done_ns,deliver_ns,result\n"
PH = "# commit=abc\n# role=rx\n# count=0\nstream,seq,payload_hex\n"
HS = "# tool=x\n# commit=abc\nseq,role,result,total_ns,bytes_tx,bytes_rx,keygen_ns,encaps_ns,decaps_ns,sign_ns,verify_ns,kdf_ns,hash_ns,mac_ns\n"
ND = "# tcp_nodelay=1\n"   # written by the gateway when its TCP connection is up, behind the column line
# cases whose logs differ in that line: name -> (line in the transmitter's logs, line in the receiver's logs)
NODELAY = {"TCP_NODELAY read back as 0 on the receiver": (ND, "# tcp_nodelay=0\n"),
           "no read-back line in the transmitter's logs": ("", ND),
           "second connection of the receiver read back 0": (ND, ND + "# tcp_nodelay=0\n")}
OK2 = "tx:ok=2 rx:ok=2"
OK1 = "tx:ok=1 rx:ok=1"
ALL = list(range(10))
CASES = [  # name, sent seq, receiver rows (int = delivered seq, str = a failure row), options, initiator rows, responder rows, expectation, exit code
    ("plain, all delivered", ALL, ALL, [], ["ok"], ["ok"], OK1, 0),
    ("plain, one PDU lost", ALL, [0, 1, 2, 4, 5, 6, 7, 8, 9], [], ["ok"], ["ok"], OK1, 1),
    ("handshake: one attempt too many", ALL, ALL, [], ["ok", "ok"], ["ok"], OK1, 1),
    ("receiver replaced: one run lost, two of them seen without a session", ALL, [0, 1, 2, "freshness_fail", "freshness_fail", 6, 7, 8, 9],
     ["--restart", "rx"], ["ok", "ok"], ["ok", "ok"], OK2, 0),
    ("receiver replaced: two separate gaps", ALL, [0, 1, 3, 4, 6, 7, 8, 9], ["--restart", "rx"], ["ok", "ok"], ["ok", "ok"], OK2, 1),
    ("receiver replaced: more freshness failures than PDUs lost", ALL, [0, 1, 2, "freshness_fail", "freshness_fail", 4, 5, 6, 7, 8, 9],
     ["--restart", "rx"], ["ok", "ok"], ["ok", "ok"], OK2, 1),
    ("receiver replaced: more than one handshake after it", ALL, [0, 1, 2, 6, 7, 8, 9], ["--restart", "rx"], ["ok", "timeout", "ok"], ["ok", "ok"], OK2, 1),
    ("transmitter replaced: two runs from 0", [0, 1, 2, 3, 0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 0, 1, 2, 3, 4, 5],
     ["--restart", "tx"], ["ok", "ok"], ["ok", "ok"], OK2, 0),
    ("transmitter replaced: second run does not start at 0", [0, 1, 2, 3, 1, 2, 3, 4, 5, 6], [0, 1, 2, 3, 1, 2, 3, 4, 5, 6],
     ["--restart", "tx"], ["ok", "ok"], ["ok", "ok"], OK2, 1),
    ("no session: no PDU row, timeouts and unknown_id", [], [], ["--no-pdu"], ["timeout", "timeout"], ["unknown_id"], "tx:timeout=1+ rx:unknown_id=1+", 0),
    ("no session expected, but a PDU was released", [0], [], ["--no-pdu"], ["timeout"], ["unknown_id"], "tx:timeout=1+ rx:unknown_id=1+", 1),
    ("TCP_NODELAY read back as 0 on the receiver", ALL, ALL, [], ["ok"], ["ok"], OK1, 1),
    ("no read-back line in the transmitter's logs", ALL, ALL, [], ["ok"], ["ok"], OK1, 1),
    ("second connection of the receiver read back 0", ALL, ALL, [], ["ok"], ["ok"], OK1, 1),
]


def main():
    wrong = 0
    with tempfile.TemporaryDirectory() as d:
        f = lambda n: os.path.join(d, n)
        for name, sent, got, opts, hs_tx, hs_rx, expect_hs, want in CASES:
            delivered = [q for q in got if isinstance(q, int)]
            nd_tx, nd_rx = NODELAY.get(name, (ND, ND))
            open(f("t"), "w").write(TXH + nd_tx + "".join("0,%d,1,2,0,3\n" % q for q in sent))
            open(f("r"), "w").write(RXH + nd_rx + "".join("0,%d,0,5,6,ok\n" % q if isinstance(q, int) else "0,-1,0,5,0,%s\n" % q for q in got))
            open(f("p"), "w").write(PH + nd_rx + "".join("0,%d,%s\n" % (q, (bytes(4) + q.to_bytes(4, "big")).hex()) for q in delivered))
            for path, role, rows, nd in ((f("ht"), "initiator", hs_tx, nd_tx), (f("hr"), "responder", hs_rx, nd_rx)):
                open(path, "w").write(HS + nd + "".join("%d,%s,%s,1,2,3,0,0,0,0,0,0,0,0\n" % (i, role, r) for i, r in enumerate(rows)))
            rc = subprocess.run([sys.executable, CHECK, f("t"), f("r"), "10", "--payload", f("p"), "--commit", "abc",
                                 "--handshake", f("ht"), f("hr"), "--expect-hs", expect_hs] + opts,
                                capture_output=True, text=True).returncode
            print("%s  %s (exit %d, expected %d)" % ("ok  " if rc == want else "WRONG", name, rc, want))
            wrong += rc != want
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
