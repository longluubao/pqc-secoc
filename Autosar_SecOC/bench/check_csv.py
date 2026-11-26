#!/usr/bin/env python3
"""Fail when a harness CSV violates DATA_SCHEMA.md.

    check_csv.py <file.csv> [...]     exit 1 and list the violations of the first bad file
    check_csv.py --selftest           prove that the checks reject broken files

Covered: crypto_ops, sign_attrib, overhead_paired, periodic_tx, periodic_rx, throughput, attack,
handshake and clock_probe files.
Checked: exact header row, column count, field types, allowed values, seq contiguous from 0 where
the schema demands it, cumulative columns that never go backwards, stage timestamps in order, no
blank lines, at least one data row, and the '# key=value' comment lines the file must carry.
Standard library only: it runs on the Pis.
"""
import sys

COMMON = ("commit", "host", "compile_flags", "liboqs_version", "cpu_affinity", "governor", "freq_khz_start")
OPS = {"mldsa_keygen", "mldsa_sign", "mldsa_verify", "mlkem_keygen", "mlkem_encaps", "mlkem_decaps",
       "hkdf", "hmac_gen", "hmac_verify"}
RESULTS = {"ok", "freshness_fail", "auth_fail", "framing_fail"}


def _tx_stages(r):
    t = [int(r[c]) for c in ("release_ns", "start_ns", "auth_done_ns", "send_done_ns")]
    reached = [x for x in t if x > 0]
    if t[0] == 0 or reached != sorted(reached) or 0 in t[:len(reached)]:
        return "stages must satisfy 0 < release <= start <= auth_done <= send_done, 0 only for stages not reached"


def _rx_stages(r):
    rx, ver, dlv = (int(r[c]) for c in ("rx_done_ns", "verify_done_ns", "deliver_ns"))
    framing = r["result"] == "framing_fail"
    if framing != (r["stream"] == "-1" and r["seq"] == "-1") or (not framing and "-" in r["stream"] + r["seq"]):
        return "stream = seq = -1 exactly for framing_fail rows, no other negative value"
    if r["result"] == "ok" and not 0 < rx <= ver <= dlv:
        return "an ok row needs 0 < rx_done <= verify_done <= deliver"
    if r["result"] != "ok" and (dlv != 0 or (framing and ver != 0) or (not framing and not 0 < rx <= ver)):
        return "a rejected row has deliver = 0, and rx_done <= verify_done unless it is a framing_fail (verify_done = 0)"


def _attrib(r):
    # the CPU-time reads sit inside the wall-time reads; 2 us covers the resolution of the two clocks
    if int(r["wall_ns"]) < int(r["cpu_ns"]) - 2000:
        return "wall_ns is more than 2 us below cpu_ns: the thread cannot compute longer than the call lasted"


def _attack(r):
    if (r["delivered"] == "1") != (r["reject_stage"] == "none"):
        return "delivered = 1 exactly when reject_stage is none"


def _probe(r):
    t1, t2, t3, t4 = (int(r[c]) for c in ("t1_ns", "t2_ns", "t3_ns", "t4_ns"))
    if t4 < t1 or t3 < t2 or (t4 - t1) - (t3 - t2) < 0:
        return "an exchange needs t1 <= t4, t2 <= t3 and a delay (t4 - t1) - (t3 - t2) that is not negative"


# per header: ints (>= 0), sints, floats, enums, seq_by (column whose values each count seq from 0; None: the file),
# rising (cumulative columns), row (extra per-row rule), keys (mandatory '# key=value' lines)
SCHEMAS = {
    "op,seq,ns": dict(ints=("seq", "ns"), enums={"op": OPS}, seq_by="op", keys=COMMON + ("n", "msg_bytes")),
    "seq,wall_ns,cpu_ns": dict(ints=("seq", "wall_ns", "cpu_ns"), seq_by=None, row=_attrib,
                               keys=COMMON + ("n", "msg_bytes", "ctx_bytes", "clock_order", "cpu_timer_overhead_ns")),
    "seq,wall_ns,cpu_ns,shake_calls": dict(
        ints=("seq", "wall_ns", "cpu_ns", "shake_calls"), seq_by=None, row=_attrib,
        keys=COMMON + ("n", "msg_bytes", "ctx_bytes", "clock_order", "cpu_timer_overhead_ns", "shake_counted",
                       "shake_calls_min", "shake_calls_step")),
    "seq,order,op,standalone_ns,csm_ns": dict(
        ints=("seq", "standalone_ns", "csm_ns"), enums={"op": {"sign", "verify"}, "order": {"AB", "BA"}}, seq_by="op",
        keys=COMMON + ("n", "msg_bytes", "rng", "seed", "mode")),
    "stream,seq,release_ns,start_ns,auth_done_ns,send_done_ns": dict(
        ints=("seq", "release_ns", "start_ns", "auth_done_ns", "send_done_ns"), seq_by="stream", row=_tx_stages,
        keys=COMMON + ("period_ns", "deadline_ns", "streams", "cores", "profile", "scheduler", "payload_bytes", "mlockall",
                       "jobs_started", "jobs_confirmed"),
        # CAMPAIGN.md: the only loss a valid file may show is jobs_dropped_at_release
        equal=(("jobs_started", "jobs_confirmed", "a job was given up without a confirmation and its SecOC row got the next PDU"),)),
    "stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result": dict(
        ints=("rx_done_ns", "verify_done_ns", "deliver_ns"), sints=("stream", "seq"), enums={"result": RESULTS},
        row=_rx_stages, keys=COMMON + ("mlockall",)),
    "t_ns,host,offered_pps,pdus_done,cpu_busy_jiffies,cpu_total_jiffies,if_tx_bytes,if_tx_packets,if_rx_bytes,"
    "if_rx_packets,sendq_bytes,drops": dict(
        ints=("t_ns", "pdus_done", "cpu_busy_jiffies", "cpu_total_jiffies", "if_tx_bytes", "if_tx_packets",
              "if_rx_bytes", "if_rx_packets", "sendq_bytes", "drops"), floats=("offered_pps",),
        rising=("t_ns", "pdus_done", "cpu_busy_jiffies", "cpu_total_jiffies", "if_tx_bytes", "if_tx_packets",
                "if_rx_bytes", "if_rx_packets", "drops"),
        keys=COMMON + ("tx_host", "rx_host", "profile", "cores")),
    "t_ns,host,offered_pps,pdus_done,cpu_busy_jiffies,cpu_total_jiffies,if_tx_bytes,if_tx_packets,if_rx_bytes,"
    "if_rx_packets,sendq_bytes,drops,proc_cpu_ns": dict(
        ints=("t_ns", "pdus_done", "cpu_busy_jiffies", "cpu_total_jiffies", "if_tx_bytes", "if_tx_packets",
              "if_rx_bytes", "if_rx_packets", "sendq_bytes", "drops", "proc_cpu_ns"), floats=("offered_pps",),
        rising=("t_ns", "pdus_done", "cpu_busy_jiffies", "cpu_total_jiffies", "if_tx_bytes", "if_tx_packets",
                "if_rx_bytes", "if_rx_packets", "drops", "proc_cpu_ns"),
        keys=COMMON + ("tx_host", "rx_host", "profile", "cores")),
    "seq,role,result,total_ns,bytes_tx,bytes_rx,keygen_ns,encaps_ns,decaps_ns,sign_ns,verify_ns,kdf_ns,hash_ns,mac_ns": dict(
        ints=("seq", "total_ns", "bytes_tx", "bytes_rx", "keygen_ns", "encaps_ns", "decaps_ns", "sign_ns", "verify_ns",
              "kdf_ns", "hash_ns", "mac_ns"), seq_by=None,
        enums={"role": {"initiator", "responder"},
               "result": {"ok", "bad_ver", "bad_len", "unknown_id", "sig_fail", "mac_fail", "timeout", "state"}},
        keys=("commit", "host", "mainfunction", "mf_period_us", "t_min_ms")),
    # only completed exchanges are rows: seq has gaps where one was lost, and never goes back
    "seq,t1_ns,t2_ns,t3_ns,t4_ns": dict(
        ints=("seq", "t1_ns", "t2_ns", "t3_ns", "t4_ns"), rising=("seq", "t1_ns"), row=_probe,
        keys=("tool", "commit", "host_a", "host_b", "clock", "interval_ms", "port", "cpu_a", "cpu_b",
              "exchanges_sent", "exchanges_completed")),
    "vector,iter,delivered,reject_stage,detect_ns": dict(
        ints=("iter", "detect_ns"), row=_attack,
        enums={"vector": {"benign", "replay", "bitflip", "auth_tamper", "freshness_rollback", "session_replay"}, "delivered": {"0", "1"},
               "reject_stage": {"none", "framing", "freshness", "auth"}},
        keys=("commit", "oracle")),
}


def _is_int(v, signed=False):
    return v.isascii() and (v[1:] if signed and v.startswith("-") else v).isdigit()


def _is_float(v):
    try:
        return 0 <= float(v) < float("inf")
    except ValueError:
        return False


def check(lines):
    """Violations found in the lines of one CSV file (empty list = valid)."""
    errors, meta, next_seq, last, spec, names, rows = [], {}, {}, {}, None, None, 0
    for no, line in enumerate(lines, 1):
        line = line.rstrip("\r\n")
        if not line.strip():
            errors.append(f"line {no}: blank line")
        elif line.startswith("#"):
            key, sep, value = line[1:].partition("=")
            if sep:
                meta[key.strip()] = value.strip()
        elif spec is None:
            if line not in SCHEMAS:
                return [f"line {no}: header {line!r} is not a DATA_SCHEMA.md header"]
            spec, names = SCHEMAS[line], line.split(",")
        else:
            fields = line.split(",")
            if len(fields) != len(names):
                errors.append(f"line {no}: {len(fields)} fields, expected {len(names)}")
                continue
            r = dict(zip(names, fields))
            rows += 1
            bad = [c for c in spec.get("ints", ()) if not _is_int(r[c])]
            bad += [c for c in spec.get("sints", ()) if not _is_int(r[c], signed=True)]
            bad += [c for c in spec.get("floats", ()) if not _is_float(r[c])]
            bad += [c for c, allowed in spec.get("enums", {}).items() if r[c] not in allowed]
            if bad:
                errors.append(f"line {no}: bad value in {', '.join(bad)}")
                continue
            if "seq_by" in spec:
                group = f"{spec['seq_by']} {r[spec['seq_by']]}" if spec["seq_by"] else "the file"
                want = next_seq.get(group, 0)
                if int(r["seq"]) != want:
                    errors.append(f"line {no}: seq {r['seq']} for {group}, expected {want}")
                next_seq[group] = int(r["seq"]) + 1
            down = [c for c in spec.get("rising", ()) if int(r[c]) < last.get(c, 0)]
            if down:
                errors.append(f"line {no}: {', '.join(down)} went backwards")
            last = {c: int(r[c]) for c in spec.get("rising", ())}
            rule = spec["row"](r) if "row" in spec else None
            if rule:
                errors.append(f"line {no}: {rule}")
    if spec is None:
        return errors + ["no header row"]
    if rows == 0:
        errors.append("no data rows")
    errors += [f"missing comment line '# {k}=...'" for k in spec["keys"] if not meta.get(k)]
    errors += [f"{a}={meta.get(a)} differs from {b}={meta.get(b)}: {why}" for a, b, why in spec.get("equal", ()) if meta.get(a) != meta.get(b)]
    return errors


def selftest():
    keys = sorted({k for spec in SCHEMAS.values() for k in spec["keys"]})
    meta = "".join(f"# {k}=x\n" for k in keys)
    tput = "t_ns,host,offered_pps,pdus_done,cpu_busy_jiffies,cpu_total_jiffies,if_tx_bytes,if_tx_packets,if_rx_bytes," \
           "if_rx_packets,sendq_bytes,drops\n"
    good = {
        "crypto_ops": meta + "op,seq,ns\nmldsa_sign,0,1500000\nmldsa_sign,1,1400000\nhkdf,0,9000\n# freq_khz_end=1\n",
        "sign_attrib": meta + "seq,wall_ns,cpu_ns\n0,1500000,1499000\n1,21100000,1600000\n2,1400000,1401500\n",
        "sign_attrib_shake": meta + "seq,wall_ns,cpu_ns,shake_calls\n0,1500000,1499000,9\n1,3100000,3099000,23\n",
        "overhead_paired": meta + "seq,order,op,standalone_ns,csm_ns\n0,AB,sign,10,11\n1,BA,sign,10,11\n0,AB,verify,5,6\n",
        "periodic_tx": meta + "stream,seq,release_ns,start_ns,auth_done_ns,send_done_ns\n2,0,100,110,120,130\n"
                              "2,1,200,0,0,0\n2,2,300,310,320,0\n",
        "periodic_rx": meta + "stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result\n2,0,100,110,120,ok\n"
                              "2,0,200,210,0,freshness_fail\n-1,-1,300,0,0,framing_fail\n",
        "throughput": meta + tput + "100,a,300,1,5,10,100,2,50,1,0,0\n200,a,300,2,6,20,200,4,60,2,3000,0\n",
        "throughput_cpu": meta + tput.replace("drops\n", "drops,proc_cpu_ns\n")
                          + "100,a,300,1,5,10,100,2,50,1,0,0,500\n200,a,300,2,6,20,200,4,60,2,3000,0,900\n",
        "attack": meta + "vector,iter,delivered,reject_stage,detect_ns\nbenign,0,1,none,0\nreplay,0,0,freshness,900\n",
        "handshake": meta + "seq,role,result,total_ns,bytes_tx,bytes_rx,keygen_ns,encaps_ns,decaps_ns,sign_ns,verify_ns,kdf_ns,hash_ns,mac_ns\n"
                            "0,initiator,ok,9000000,4575,4511,90000,0,95000,1900000,430000,20000,9000,7000\n",
        "clock_probe": meta + "seq,t1_ns,t2_ns,t3_ns,t4_ns\n1,100,5000,5010,200\n3,300,5200,5215,410\n",
    }
    broken = {
        "probe reply before its request": ("clock_probe", "1,100,5000,5010,200", "1,100,5010,5000,200"),
        "probe longer in the server than the round trip": ("clock_probe", "3,300,5200,5215,410", "3,300,5200,5415,410"),
        "probe seq backwards": ("clock_probe", "3,300,", "0,300,"),
        "probe without its count": ("clock_probe", "# exchanges_completed=x\n", ""),
        "wrong header": ("crypto_ops", "op,seq,ns\n", "op,seq,nanos\n"),
        "missing column": ("crypto_ops", "mldsa_sign,1,1400000", "mldsa_sign,1"),
        "unknown op": ("crypto_ops", "hkdf,0", "hkdf2,0"),
        "seq gap": ("crypto_ops", "mldsa_sign,1,", "mldsa_sign,2,"),
        "seq not from 0": ("crypto_ops", "hkdf,0,", "hkdf,1,"),
        "negative time": ("crypto_ops", "hkdf,0,9000", "hkdf,0,-9000"),
        "blank line": ("crypto_ops", "hkdf,0,9000\n", "hkdf,0,9000\n\n"),
        "no rows": ("crypto_ops", "mldsa_sign,0,1500000\nmldsa_sign,1,1400000\nhkdf,0,9000\n", ""),
        "missing commit line": ("crypto_ops", "# commit=x\n", ""),
        "bad order": ("overhead_paired", "1,BA,sign", "1,B,sign"),
        "paired seq gap": ("overhead_paired", "1,BA,sign", "3,BA,sign"),
        "paired unknown op": ("overhead_paired", "0,AB,verify", "0,AB,keygen"),
        "missing seed line": ("overhead_paired", "# seed=x\n", ""),
        "tx seq gap": ("periodic_tx", "2,1,200,0,0,0", "2,5,200,0,0,0"),
        "tx start before release": ("periodic_tx", "2,0,100,110,120,130", "2,0,100,90,120,130"),
        "tx send without auth": ("periodic_tx", "2,2,300,310,320,0", "2,2,300,310,0,330"),
        "tx no release": ("periodic_tx", "2,1,200,0,0,0", "2,1,0,0,0,0"),
        "tx missing period": ("periodic_tx", "# period_ns=x\n", ""),
        "tx job given up": ("periodic_tx", "# jobs_confirmed=x\n", "# jobs_confirmed=y\n"),
        "rx unknown result": ("periodic_rx", "2,0,100,110,120,ok", "2,0,100,110,120,fine"),
        "rx ok not delivered": ("periodic_rx", "2,0,100,110,120,ok", "2,0,100,110,0,ok"),
        "rx rejected but delivered": ("periodic_rx", "2,0,200,210,0,freshness_fail", "2,0,200,210,220,freshness_fail"),
        "rx framing with a stream": ("periodic_rx", "-1,-1,300,0,0,framing_fail", "2,7,300,0,0,framing_fail"),
        "rx negative seq": ("periodic_rx", "2,0,100,110,120,ok", "2,-1,100,110,120,ok"),
        "throughput counter backwards": ("throughput", "200,a,300,2,6,20", "200,a,300,0,6,20"),
        "throughput time backwards": ("throughput", "200,a,300,2", "50,a,300,2"),
        "throughput missing rx_host": ("throughput", "# rx_host=x\n", ""),
        "throughput process CPU time backwards": ("throughput_cpu", "3000,0,900", "3000,0,100"),
        "sign_attrib more cpu than wall": ("sign_attrib", "2,1400000,1401500", "2,1400000,1403000"),
        "sign_attrib seq gap": ("sign_attrib", "2,1400000,1401500", "3,1400000,1401500"),
        "sign_attrib_shake without a count": ("sign_attrib_shake", "1,3100000,3099000,23", "1,3100000,3099000,"),
        "attack unknown vector": ("attack", "replay,0,0,freshness,900", "resend,0,0,freshness,900"),
        "handshake unknown result": ("handshake", "0,initiator,ok,", "0,initiator,fine,"),
        "attack without its oracle": ("attack", "# oracle=x\n", ""),
        "attack delivered and rejected": ("attack", "replay,0,0,freshness,900", "replay,0,1,freshness,900"),
        "attack rejected nowhere": ("attack", "replay,0,0,freshness,900", "replay,0,0,none,900"),
    }
    failed = [f"valid {kind} file rejected: {check(text.splitlines(True))}" for kind, text in good.items()
              if check(text.splitlines(True))]
    for name, (kind, old, new) in broken.items():
        assert old in good[kind], name
        if not check(good[kind].replace(old, new, 1).splitlines(True)):
            failed.append(f"broken file accepted: {name}")
    for f in failed:
        print(f, file=sys.stderr)
    print(f"selftest: {len(good)} valid files, {len(broken)} broken files, {len(failed)} wrong verdicts")
    return 1 if failed else 0


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    for path in argv:
        with open(path, encoding="utf-8", newline="") as f:
            errors = check(f)
        if errors:
            print(f"{path}: {len(errors)} violation(s)", file=sys.stderr)
            for e in errors[:10]:
                print(f"  {e}", file=sys.stderr)
            return 1
        print(f"{path}: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
