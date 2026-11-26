"""Independent second reading of an E5 run directory (handshake timing) or of a negative handshake test, compared key by
key with the toolkit.

usage: python3 -I handshake_compare.py <run_dir> <analysis_dir> <key_prefix>      (python3 -I handshake_compare.py --self-test)
Standard library only. Reads the raw files itself (DATA_SCHEMA.md; '#' lines are skipped wherever they stand):
E5, <run_dir>/handshake/handshake_*.csv (seq,role,result,total_ns,bytes_tx,bytes_rx,<stage>_ns ...), per file and role:
  attempts    rows; successes = rows with result ok; failed = the others; rows per result
  times       over the successful rows only, in ms, percentiles of type 7: median, p99 and maximum of total_ns; median
              and p99 of every stage the role uses (a stage that is 0 in every successful row is not used and must
              have no toolkit key) and of the sum of the stage columns (the role's own computation); the same
              percentiles also in us
  per PDU     mean of the sum of the stage columns over the successful rows, divided by SESSION = 1,000 PDUs (the
              session length the key's definition assumes, not the number of rows), in ms and us; over both roles
              the initiator's figure plus the responder's, only when the valid files hold exactly one initiator and
              one responder, each with a success (otherwise the toolkit must have no such key)
  bytes       median, smallest and largest bytes_tx and bytes_rx of the successful rows
  A file with '# pdu_stream=' other than none is a set-up handshake of another experiment, and a file without
  tcp_nodelay = 1 or without its footer is invalid: both must have no toolkit key.
Negative test, <run_dir>/hsneg.txt and every handshake*.csv below <run_dir>/hstest (a batch has r001, r002, ...):
  counts      rows per role and per result over all those files (a gateway also writes a row for a discarded message)
  record      the one line 'test=...' of hsneg.txt: its counts are compared with the toolkit's keys; its seen_tx /
              seen_rx must be the own counts of the initiator / responder; its verdict must fit the last line (PASS
              with PASS, FAIL with REJECT) and the schema's rules (pdus_given_up > 0 or a tcp_nodelay other than 1
              is FAIL); for a batch the counts must be the sums over hstest/r*/hsneg.txt and runs_passed the number
              of their PASS verdicts. The verdict is the one text key that is compared with the toolkit.
Exit 0 only if at least 15 keys per role (E5) or 10 keys (negative test) were compared and nothing differs.
"""
import csv
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path
from statistics import median

STAGES = ("keygen", "encaps", "decaps", "sign", "verify", "kdf", "hash", "mac")
RESULTS = ("ok", "bad_ver", "bad_len", "unknown_id", "sig_fail", "mac_fail", "timeout", "state")
SIDES = {"initiator": "tx", "responder": "rx"}
UNITS = (("ms", 1e6), ("us", 1e3))      # ns per unit
SESSION = 1000      # PDUs that one handshake serves in the *_per_pdu_session1000_* keys: the definition's assumption
SUMMED = ("repetitions", "attacked", "repetitions_done", "pdus_sent", "pdus_delivered", "pdus_rejected", "pdus_given_up",
          "installs_tx", "installs_rx")


AGREED = []      # the full names of the keys that were compared with a toolkit value and are equal (Addendum F4)


def record_compared(analysis_dir, keys):
    """Addendum F4: <analysis_dir>/own_compared_keys.txt, the keys that this call compared with a toolkit value and found
    equal, one per line, sorted. Under e9_compare.py (OWN_COMPARED_KEYS=add) the readers of one call add to one file;
    a direct call writes its own set. A call that does not end in agreement leaves no key of its own."""
    path = Path(analysis_dir) / "own_compared_keys.txt"
    if path.parent.is_dir():
        old = path.read_text().split() if os.environ.get("OWN_COMPARED_KEYS") == "add" and path.exists() else []
        path.write_text("".join(k + "\n" for k in sorted({*old, *keys})))


def read(path):
    """({key: value} of the '# key=value' lines anywhere in the file, rows as dicts of text)."""
    meta, cols, rows = {}, None, []
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("#"):
            k, _, v = line[1:].strip().partition("=")
            meta[k] = v
        elif line.strip() and cols is None:
            cols = line.split(",")
        elif line.strip():
            rows.append(dict(zip(cols, line.split(","))))
    return meta, rows


def pct(values, p):
    """Percentile of type 7 (Hyndman and Fan): linear between the order statistics around (n - 1) p / 100."""
    x = sorted(values)
    h = (len(x) - 1) * p / 100
    i = math.floor(h)
    return x[i] + (h - i) * (x[min(i + 1, len(x) - 1)] - x[i])


def counts(rows):
    """{role: Counter of results} with ok always present."""
    out = {}
    for r in rows:
        out.setdefault(r["role"], Counter(ok=0))[r["result"]] += 1
    return out


def count_keys(rows):
    """{<role>.n and <role>.result_<result>: rows}; ok also when it is 0, the other results when they occur."""
    return {f"{role}.{name}": v for role, c in counts(rows).items()
            for name, v in (("n", sum(c.values())), *((f"result_{res}", n) for res, n in c.items()))}


def own_e5(rows):
    """{<role>.<toolkit name>: own value} of one handshake file of E5."""
    k = count_keys(rows)
    for role in counts(rows):
        ok = [r for r in rows if r["role"] == role and r["result"] == "ok"]
        k[f"{role}.ok"], k[f"{role}.failed"] = len(ok), k[f"{role}.n"] - len(ok)
        times = {"total": [int(r["total_ns"]) for r in ok], "compute": [sum(int(r[s + "_ns"]) for s in STAGES) for r in ok],
                 **{s: [int(r[s + "_ns"]) for r in ok] for s in STAGES}}
        for name, ns in times.items():
            used = bool(ns) and (name in ("total", "compute") or any(ns))
            for unit, div in UNITS:
                k[f"{role}.{name}_p50_{unit}"] = pct(ns, 50) / div if used else None
                k[f"{role}.{name}_p99_{unit}"] = pct(ns, 99) / div if used else None
        for unit, div in UNITS:
            k[f"{role}.compute_mean_per_pdu_session{SESSION}_{unit}"] = sum(times["compute"]) / len(ok) / SESSION / div if ok else None
        k[f"{role}.total_max_ms"] = max(times["total"]) / 1e6 if ok else None
        for col in ("bytes_tx", "bytes_rx"):
            b = [int(r[col]) for r in ok]
            k.update({f"{role}.{col}_median": median(b) if b else None, f"{role}.{col}_min": min(b) if b else None,
                      f"{role}.{col}_max": max(b) if b else None})
    return k


def both_roles(per_role):
    """{toolkit name: own value} of the keys over both roles: the initiator's computation per PDU plus the responder's.
    `per_role` = {role: [the own keys of that role, one dict per valid file]}. None (the toolkit must have no such key)
    unless there is exactly one initiator and one responder and both have a success."""
    out = {}
    for unit, _ in UNITS:
        name = f"compute_mean_per_pdu_session{SESSION}_{unit}"
        parts = [k[f"{role}.{name}"] for role in SIDES for k in per_role.get(role, [])]
        one = all(len(per_role.get(role, [])) == 1 for role in SIDES) and None not in parts
        out[name] = sum(parts) if one else None
    return out


def record(path):
    """(the fields of the one 'test=' line of an hsneg.txt as text, its last line); ({}, last line) without exactly one."""
    lines = [s.strip() for s in Path(path).read_text(errors="replace").splitlines() if s.strip()]
    found = [s for s in lines if s.startswith("test=")]
    return (dict(f.partition("=")[::2] for f in found[0].split(" ")) if len(found) == 1 else {}), (lines[-1] if lines else "")


def as_list(c):
    """Counts per result as the record writes them: result:count of the results that occur, in the schema's order."""
    return ",".join(f"{r}:{c[r]}" for r in RESULTS if c.get(r)) or "none"


def record_faults(rec, last, own_counts, runs):
    """What is wrong with a record line: [(what, own value, value of hsneg.txt)]. `runs` are the record()s of the runs
    of a batch."""
    out = []
    if not rec:
        return [("exactly one line that starts with test=", "none or several", "one")]
    for role, side in SIDES.items():
        mine = as_list(own_counts.get(role, {}))
        if mine != rec.get(f"seen_{side}"):
            out.append((f"seen_{side} against the {role}'s handshake files", mine, rec.get(f"seen_{side}")))
    if (rec.get("verdict"), last) not in (("PASS", "PASS"), ("FAIL", "REJECT")):
        out.append(("verdict and last line", "PASS with PASS or FAIL with REJECT", f"verdict={rec.get('verdict')}, last line {last}"))
    must_fail = rec.get("pdus_given_up") != "0" or rec.get("tcp_nodelay_tx") != "1" or rec.get("tcp_nodelay_rx") != "1"
    if must_fail and rec.get("verdict") == "PASS":
        out.append(("verdict by the schema's rules (pdus_given_up, tcp_nodelay)", "FAIL", "PASS"))
    if runs:
        sums = {f: str(sum(int(r.get(f, 0)) for r, _ in runs)) for f in SUMMED}
        sums.update(runs=str(len(runs)), runs_passed=str(sum(r.get("verdict") == "PASS" for r, _ in runs)))
        out += [(f"{f} of the batch against its runs", v, rec.get(f)) for f, v in sums.items() if v != rec.get(f)]
        if (rec.get("verdict") == "PASS") != (sums["runs_passed"] == sums["runs"]):
            out.append(("verdict of the batch", "PASS only when every run passed", rec.get("verdict")))
    return out


def toolkit(analysis_dir, start, source=None):
    """({key: value} of the toolkit keys that begin with `start` (and have that source_file), text rows left out; the
    text rows)."""
    with open(Path(analysis_dir) / "numbers.csv", newline="") as f:
        rows = [r for r in csv.DictReader(f) if r["key"].startswith(start) and (source is None or r["source_file"] == source)]
    return {r["key"]: r["value"] for r in rows if r["unit"] != "text"}, {r["key"]: r["value"] for r in rows if r["unit"] == "text"}


def compare(head, own, theirs):
    """Prints each difference; returns their number. A key the toolkit lacks is a difference; an own None says the
    toolkit must not have the key. Counts are compared exactly, other values to nine digits."""
    bad = 0
    for key, a in own.items():
        b = theirs.get(key)
        if a is None and b is None:
            continue
        if a is None or b is None or not (float(b) == a if isinstance(a, int) else
                                          math.isclose(a, float(b), rel_tol=1e-9, abs_tol=1e-12)):
            bad += 1
            print(f"DIFF {head}{key}: own {a}, toolkit {b}")
        else:
            AGREED.append(head + key)
    return bad


def e5(run_dir, analysis_dir, prefix):
    """Returns (differences, True when every role had enough keys)."""
    bad, enough, per_role = 0, True, {}
    for p in sorted((run_dir / "handshake").glob("handshake_*.csv")):
        meta, rows = read(p)
        full, _ = toolkit(analysis_dir, prefix + ".handshake.", f"handshake/{p.name}")
        theirs, head = {}, ""      # anchored on the .<role>. part of the key, whatever stands before it
        for key, v in full.items():
            m = re.search(r"^(.*\.)((?:initiator|responder)\..+)$", key)
            if m:
                head, theirs[m[2]] = m[1], v
        why = [f"pdu_stream={meta.get('pdu_stream')}: a set-up handshake"] if meta.get("pdu_stream") != "none" else []
        why += [f"tcp_nodelay={meta.get('tcp_nodelay')}"] if meta.get("tcp_nodelay") != "1" else []
        why += ["no footer (interrupted)"] if "wall_s" not in meta else []
        if why:
            print(f"{p.name}: not a timing file of E5 by the own rules: " + "; ".join(why))
            print(f"DIFF {head}*: own INVALID, toolkit has {len(theirs)} keys" if theirs else f"{p.name}: the toolkit has no key either: consistent")
            bad, enough = bad + bool(theirs), False
            continue
        own = own_e5(rows)
        for role in counts(rows):
            mine = {k: v for k, v in own.items() if k.startswith(role + ".")}
            per_role.setdefault(role, []).append(mine)
            diffs, compared = compare(head or f"{prefix}.handshake.<no key of {p.name}>.", mine, theirs), sum(v is not None for v in mine.values())
            bad, enough = bad + diffs, enough and compared >= 15
            ms = {k: "n/a" if v is None else f"{v:.3f}" for k, v in mine.items()}
            stages = ", ".join(f"{s} {ms[f'{role}.{s}_p50_ms']}/{ms[f'{role}.{s}_p99_ms']}" for s in (*STAGES, "compute") if mine[f"{role}.{s}_p50_ms"] is not None)
            print(f"{p.name} {role} (host {meta.get('host')}): attempts {mine[f'{role}.n']}, ok {mine[f'{role}.ok']}, failed {mine[f'{role}.failed']}; "
                  f"total ms p50 {ms[f'{role}.total_p50_ms']}, p99 {ms[f'{role}.total_p99_ms']}, max {ms[f'{role}.total_max_ms']}; stages ms p50/p99: {stages}; "
                  f"compute mean per PDU of a session of {SESSION} PDUs {ms[f'{role}.compute_mean_per_pdu_session{SESSION}_us'] if mine[f'{role}.compute_mean_per_pdu_session{SESSION}_us'] is None else mine[f'{role}.compute_mean_per_pdu_session{SESSION}_us']} us; "
                  f"bytes sent {mine[f'{role}.bytes_tx_median']}, received {mine[f'{role}.bytes_rx_median']} (medians); keys compared {compared}, "
                  f"differences {diffs}; toolkit keys of the role not recomputed here: {len([k for k in theirs if k.startswith(role + '.') and k not in mine])}")
    head = prefix + ".handshake.both_roles."
    mine = both_roles(per_role)
    diffs = compare(head, mine, {k[len(head):]: v for k, v in toolkit(analysis_dir, head)[0].items()})
    us = mine[f"compute_mean_per_pdu_session{SESSION}_us"]
    print(f"both roles: compute mean per PDU of a session of {SESSION} PDUs {'n/a' if us is None else us} us; "
          f"keys compared {sum(v is not None for v in mine.values())}, differences {diffs}")
    return bad + diffs, enough


def negative(run_dir, analysis_dir, prefix):
    """Returns (differences, True when enough keys were compared)."""
    files = sorted((run_dir / "hstest").rglob("handshake*.csv"))
    rows = [r for p in files for r in read(p)[1]]
    rec, last = record(run_dir / "hsneg.txt")
    runs = [record(p) for p in sorted((run_dir / "hstest").glob("r*/hsneg.txt"))]
    full, text = toolkit(analysis_dir, prefix + ".hsneg.")
    head = os.path.commonprefix([*full, *text])
    head = head[:head.rfind(".") + 1] or prefix + ".hsneg.<no key>."
    theirs = {k[len(head):]: v for k, v in full.items()}
    own = {**count_keys(rows), **{f: int(rec[f]) for f in (*SUMMED, "runs", "runs_passed") if rec.get(f, "").isdigit()}}
    own.update({k: None for k in theirs if re.match(r"(initiator|responder)\.result_", k) and k not in own})   # a result only the toolkit counts
    bad = compare(head, own, theirs)
    verdict = text.get(head + "verdict")
    if verdict != rec.get("verdict"):
        bad += 1
        print(f"DIFF {head}verdict: own {rec.get('verdict')}, toolkit {verdict}")
    else:
        AGREED.append(head + "verdict")
    faults = record_faults(rec, last, counts(rows), runs)
    for what, a, b in faults:
        print(f"DIFF record, {what}: own {a}, hsneg.txt {b}")
    c = counts(rows)
    print(f"negative test {rec.get('test')} variant {rec.get('variant')}: " + "; ".join(f"{role} {as_list(c.get(role, {}))}" for role in SIDES)
          + f" ({len(rows)} rows in {len(files)} handshake files); oracle: verdict={rec.get('verdict')}, last line {last}, runs {rec.get('runs')}, "
          f"passed {rec.get('runs_passed')}, attacked {rec.get('attacked')}, PDUs sent {rec.get('pdus_sent')}, delivered {rec.get('pdus_delivered')}, "
          f"rejected {rec.get('pdus_rejected')}, given up {rec.get('pdus_given_up')}; keys compared {len(own) + 1}, differences {bad}, "
          f"faults of the record {len(faults)}")
    return bad + len(faults), len(own) + 1 >= 10


def self_test():
    assert pct([1, 2, 3, 4], 50) == 2.5 and pct([7], 99) == 7 and math.isclose(pct(range(1, 101), 99), 99.01)

    def hs(role, result, total, keygen=0, sign=0, tx=10, rx=20):
        return {"role": role, "result": result, "total_ns": str(total), "bytes_tx": str(tx), "bytes_rx": str(rx),
                **{s + "_ns": "0" for s in STAGES}, "keygen_ns": str(keygen), "sign_ns": str(sign)}

    rows = [hs("initiator", "ok", 3_000_000, keygen=1000, sign=5000), hs("initiator", "timeout", 9_000_000_000, keygen=7),
            hs("initiator", "ok", 5_000_000, keygen=3000, sign=7000, tx=12), hs("responder", "sig_fail", 1)]
    k = own_e5(rows)
    assert k["initiator.n"] == 3 and k["initiator.ok"] == 2 and k["initiator.failed"] == 1 and k["initiator.result_timeout"] == 1
    assert k["initiator.total_p50_ms"] == 4.0 and k["initiator.total_max_ms"] == 5.0          # the failed attempt is not timed
    assert k["initiator.keygen_p50_ms"] == 0.002 and k["initiator.compute_p50_ms"] == 0.008
    assert k["initiator.encaps_p50_ms"] is None                                               # a stage the role does not use
    assert k["initiator.keygen_p50_us"] == 2.0 and k["initiator.compute_p50_us"] == 8.0 and k["initiator.total_p99_us"] == 4980.0
    assert k["initiator.encaps_p99_us"] is None
    # two successes with 6,000 and 10,000 ns of computation: mean 8 us, 0.008 us per PDU of 1,000 (not 4 us = mean / rows)
    assert k["initiator.compute_mean_per_pdu_session1000_us"] == 0.008 and k["initiator.compute_mean_per_pdu_session1000_ms"] == 0.000008
    assert k["responder.compute_mean_per_pdu_session1000_us"] is None                         # no success: no mean
    ini = {n: v for n, v in k.items() if n.startswith("initiator.")}
    res = {n: v for n, v in own_e5([hs("responder", "ok", 1, keygen=1000, sign=3000)] * 3).items() if n.startswith("responder.")}
    assert res["responder.compute_mean_per_pdu_session1000_us"] == 0.004
    assert both_roles({"initiator": [ini], "responder": [res]})["compute_mean_per_pdu_session1000_us"] == 0.012
    for part in ({"initiator": [ini]}, {"initiator": [ini, ini], "responder": [res]}, {}, {"initiator": [ini], "responder":
                 [{n: v for n, v in k.items() if n.startswith("responder.")}]}):   # a role missing, twice, or without a success
        assert set(both_roles(part).values()) == {None}
    assert k["initiator.bytes_tx_median"] == 11 and k["initiator.bytes_tx_max"] == 12 and k["initiator.bytes_rx_min"] == 20
    assert k["responder.n"] == 1 and k["responder.result_ok"] == 0 and k["responder.total_p50_ms"] is None
    c = counts(rows)
    assert as_list(c["initiator"]) == "ok:2,timeout:1" and as_list(c["responder"]) == "sig_fail:1" and as_list({}) == "none"
    rec = {**{f: "4" for f in SUMMED}, "verdict": "PASS", "seen_tx": "ok:2,timeout:1", "seen_rx": "sig_fail:1", "pdus_given_up": "0",
           "tcp_nodelay_tx": "1", "tcp_nodelay_rx": "1", "runs": "2", "runs_passed": "2"}
    assert record_faults(rec, "PASS", c, []) == [] and len(record_faults(rec, "REJECT", c, [])) == 1
    assert len(record_faults({**rec, "seen_rx": "ok:1"}, "PASS", c, [])) == 1
    assert len(record_faults({**rec, "pdus_given_up": "3"}, "PASS", c, [])) == 1 and len(record_faults({}, "PASS", c, [])) == 1
    run = ({f: "2" for f in SUMMED} | {"pdus_given_up": "0", "verdict": "PASS"}, "PASS")
    assert record_faults(rec, "PASS", c, [run, run]) == []
    failed = ({**run[0], "verdict": "FAIL"}, "REJECT")
    assert len(record_faults(rec, "PASS", c, [run, failed])) == 2       # runs_passed and the verdict of the batch
    print("self-test ok")


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    self_test()
    AGREED.clear()
    run_dir, analysis_dir, prefix = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    record_compared(analysis_dir, [])    # a direct call starts the file
    for marker in ("DRY_RUN", "PILOT", "EXCLUDED"):
        if (run_dir / marker).exists():
            print(f"marker {marker}: nothing in this directory is a result")
    done = []
    if (run_dir / "handshake").is_dir():
        done.append(e5(run_dir, analysis_dir, prefix))
    if (run_dir / "hsneg.txt").exists():
        done.append(negative(run_dir, analysis_dir, prefix))
    if not done:
        raise SystemExit(f"{run_dir}: neither handshake/ nor hsneg.txt")
    ok = all(bad == 0 and enough for bad, enough in done)
    record_compared(analysis_dir, AGREED if ok else [])
    print("OWN-CHECK AGREES" if ok else "OWN-CHECK DISAGREES")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
