#!/usr/bin/env python3
"""Build attack.csv (DATA_SCHEMA.md) from what the attacker sent and what the receiver decided.

    join_attack.py <proxy_log.csv> <receiver log> --out attack.csv --commit HASH --oracle NAME
        receiver log and --oracle: the gateway application's CSV (gateway_app_log: the oracle for
        delivered or not and the reject stage; it has no reception time, so detect_ns is 0), or
        bench_net_rx's periodic_rx.csv (harness_receiver: a separate run of the same vectors that
        supplies detect_ns); both have the periodic_rx columns
    join_attack.py --selftest

The proxy's log and the receiver's log are written independently, on the two sides of the TCP
connection. TCP keeps the order and the receiver logs one row per PDU in arrival order, so row i
of one file is row i of the other. That is checked, not assumed: the counts must be equal and
every delivered PDU must carry the sequence number the proxy saw for it; otherwise nothing is
written and the exit code is 2.

Exit code 0: every attacked PDU was rejected before delivery and every benign PDU was delivered.
Exit code 3: attack.csv is written, but at least one PDU contradicts that.
"""
import argparse
import hashlib
import tempfile
import sys

STAGE = {"ok": "none", "freshness_fail": "freshness", "auth_fail": "auth", "framing_fail": "framing"}


def rows(path, header):
    with open(path, encoding="utf-8") as f:
        lines = [s.rstrip("\n") for s in f if s.strip() and not s.startswith("#")]
    if not lines or lines[0] != header:
        raise SystemExit(f"{path}: header is not {header!r}")
    width = header.count(",")
    return [dict(zip(header.split(","), s.split(",", width))) for s in lines[1:]]


def join(proxy, rx):
    """(attack rows, summary) or raises ValueError when the two logs do not line up."""
    if len(proxy) != len(rx):
        raise ValueError(f"the proxy sent {len(proxy)} PDUs, the receiver logged {len(rx)}")
    out, wrong = [], []
    for i, (p, r) in enumerate(zip(proxy, rx)):
        delivered = r["result"] == "ok"
        if delivered and r["seq"] != p["src_seq"]:
            raise ValueError(f"row {i}: the receiver delivered seq {r['seq']}, the proxy sent seq {p['src_seq']}")
        # the gateway application does not log rx_done_ns (0): no detection time can be given then
        timed = not delivered and r["result"] != "framing_fail" and int(r["rx_done_ns"]) > 0
        detect = int(r["verify_done_ns"]) - int(r["rx_done_ns"]) if timed else 0
        if p["vector"] != "other":      # PDUs the proxy only passed on are not attack.csv vectors
            out.append((p["vector"], p["iter"], int(delivered), STAGE[r["result"]], detect))
        if delivered != (p["vector"] == "benign"):
            wrong.append(f"row {i}: {p['vector']} PDU (seq {p['src_seq']}, {p['detail']}) -> {r['result']}")
    return out, wrong


def selftest():
    def p(vector, it, seq):
        return {"index": "0", "vector": vector, "iter": str(it), "src_seq": str(seq), "detail": ""}

    def r(seq, result, rx_done=100, verify=150):
        return {"stream": "2", "seq": str(seq), "rx_done_ns": str(rx_done), "verify_done_ns": str(verify),
                "deliver_ns": "160" if result == "ok" else "0", "result": result}

    proxy = [p("benign", 0, 0), p("benign", 1, 1), p("replay", 0, 1), p("auth_tamper", 0, 2), p("benign", 2, 3)]
    rx = [r(0, "ok"), r(1, "ok"), r(1, "freshness_fail"), r(2, "auth_fail"), r(3, "ok")]
    checks = []
    out, wrong = join(proxy, rx)
    checks.append(wrong == [] and out[2] == ("replay", "0", 0, "freshness", 50) and out[0] == ("benign", "0", 1, "none", 0))
    out, wrong = join(proxy, rx[:3] + [r(2, "ok")] + rx[4:])            # a tampered PDU got through
    checks.append(len(wrong) == 1 and out[3][2] == 1)
    out, wrong = join(proxy, rx[:4] + [r(3, "auth_fail")])              # a benign PDU was rejected
    checks.append(len(wrong) == 1 and out[4][2] == 0)
    for bad in (rx[:4], rx[:4] + [r(9, "ok")]):                         # count differs; sequence numbers shifted
        try:
            join(proxy, bad)
            checks.append(False)
        except ValueError:
            checks.append(True)
    checks.append([both_nodelay(*x) for x in (("1", "1"), ("1", "0"), ("0", None), ("1", None), (None, None))] == [1, 0, 0, -1, -1])
    with tempfile.TemporaryDirectory() as d:
        def end(text):
            with open(f"{d}/f", "w", encoding="utf-8") as f:
                f.write(text)
            return end_nodelay(f"{d}/f")
        gateway = "# commit=x\nstream,seq,result\n# tcp_nodelay=1\n0,0,ok\n"
        checks.append([end(gateway), end(gateway + "# tcp_nodelay=1\n"), end(gateway + "# tcp_nodelay=0\n"), end("# commit=x\n0,0,ok\n"),
                       end("# tcp_nodelay=-1\n"), end_nodelay(None)] == ["1", "1", "0", None, None, None])
    print(f"selftest: {len(checks)} checks, {checks.count(False)} failed")
    return 0 if all(checks) else 1


def end_nodelay(path):
    """TCP_NODELAY of one end as its own file reports it: '1' when the file has at least one
    '# tcp_nodelay=' line and every one says 1 (a harness writes one in its header, the gateway one per
    TCP connection it had, behind the column line), '0' when one says 0, None when there is none or
    one says anything else."""
    values = []
    if path:
        with open(path, encoding="utf-8", errors="replace") as f:
            values = [line.strip().split("=", 1)[1] for line in f if line.startswith("# tcp_nodelay=")]
    if "0" in values:
        return "0"
    return "1" if values and set(values) == {"1"} else None


def both_nodelay(tx, rx):
    """1 only when both ends read TCP_NODELAY back as 1; 0 when an end reads 0; -1 when an end has no
    read-back and none reads 0."""
    if "0" in (tx, rx):
        return 0
    return 1 if (tx, rx) == ("1", "1") else -1


def main():
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("proxy_log")
    ap.add_argument("rx_file")
    ap.add_argument("--out", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--oracle", required=True, choices=("gateway_app_log", "harness_receiver"))
    ap.add_argument("--tx-file", help="the transmitter's periodic_tx.csv: its tcp_nodelay read-back goes into the header")
    args = ap.parse_args()
    proxy = rows(args.proxy_log, "index,vector,iter,src_seq,detail")
    rx = rows(args.rx_file, "stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result")
    try:
        out, wrong = join(proxy, rx)
    except ValueError as e:
        print(f"the two logs do not line up, no attack.csv written: {e}", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(f"# tool=join_attack\n# commit={args.commit}\n# oracle={args.oracle}\n")
        for label, path in (("proxy_log", args.proxy_log), ("rx_file", args.rx_file)):
            with open(path, "rb") as src:
                f.write(f"# {label}_sha256={hashlib.sha256(src.read()).hexdigest()}\n")
        tx_nodelay, rx_nodelay = end_nodelay(args.tx_file), end_nodelay(args.rx_file)
        f.write(f"# tcp_nodelay={both_nodelay(tx_nodelay, rx_nodelay)}\n# tcp_nodelay_tx={tx_nodelay or -1}\n# tcp_nodelay_rx={rx_nodelay or -1}\n")
        f.write(f"# pdus={len(out)}\n# contradicting_pdus={len(wrong)}\n")
        f.write("vector,iter,delivered,reject_stage,detect_ns\n")
        for row in out:
            f.write(",".join(str(x) for x in row) + "\n")
    counts = {}
    for vector, _, delivered, stage, _ in out:
        key = (vector, "delivered" if delivered else stage)
        counts[key] = counts.get(key, 0) + 1
    for (vector, outcome), n in sorted(counts.items()):
        print(f"{vector}: {n} {outcome}")
    for line in wrong[:20]:
        print(line, file=sys.stderr)
    return 3 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
