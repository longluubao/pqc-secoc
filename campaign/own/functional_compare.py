"""Independent second reading of a functional run of the gateway binaries, compared key by key with the toolkit.

usage: python3 -I functional_compare.py <run_dir> <analysis_dir> <key_prefix>     (python3 -I functional_compare.py --self-test)
<run_dir> is a directory with the marker FUNCTIONAL, or one that holds such directories (then each one's keys are
<key_prefix>.functional.<directory name>.<...>, as the toolkit names them).
Reads the raw files itself, with the csv module only (DATA_SCHEMA.md, 'Contract of the gateway's application logs'):
  app_tx*.csv      one row per PDU whose transmission was confirmed            -> sent, per stream
  app_rx*.csv      one row per outcome at the receiver                         -> delivered (result ok), rejected per result
  rx_payload*.csv  one row per delivered PDU, in the order of the ok rows      -> byte-exact delivery
  handshake_tx*.csv, handshake_rx*.csv                                         -> rows per role and result
  '# tcp_nodelay=' lines of the app files                                      -> TCP connections per side and how many read 1
Own rules (written from the contract, not from the toolkit's code):
  in order    per stream, the delivered sequence numbers are matched against the sent ones with one pointer that
              only moves forward; a delivered number not found after the pointer is not in order;
  lost        sent - delivered in order, per stream and per run (a rejected PDU has no delivered row and is among the
              lost; the parts of a replaced process are read in numeric order and added, no restart is recognised);
  byte exact  an in-order PDU whose 8 payload bytes are: stream index, 0, 0, 0, sequence number as 32 bit big-endian.
Compared: EVERY key <key_prefix>.functional[.<name>].* of numbers.csv must be reproduced, and every own key must be
there. Exit 0 only then. No time column is read: a functional run carries no timing result.
The one exception: the keys <key_prefix>.functional[.<name>].e2e.* of a directory with a clock probe (E9, cell g) come
from the time columns and the probe; they are e2e_compare.py's to judge and are left out here (added 2026-11-25).
"""
import csv
import os
import re
import sys
from collections import Counter
from pathlib import Path

REJECTED = ("freshness_fail", "auth_fail", "framing_fail")


def read(path):
    """(header keys before the column line, the tcp_nodelay values of the file, its rows as dicts)."""
    head, nodelay, cols, out = {}, [], None, []
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("#"):
            k, _, v = line[1:].strip().partition("=")
            if k == "tcp_nodelay":
                nodelay.append(v)
            elif cols is None:
                head[k] = v
            continue
        if not line.strip():
            continue
        cells = next(csv.reader([line]))
        if cols is None:
            cols = cells
        else:
            out.append(dict(zip(cols, cells)))
    return head, nodelay, out


def parts(directory, stem):
    """The files <stem>.csv, <stem>2.csv, ... in the order of their number (the joined *_all.csv copies are not read)."""
    found = []
    for p in Path(directory).iterdir():
        m = re.fullmatch(re.escape(stem) + r"(\d*)\.csv", p.name)
        if m:
            found.append((int(m[1] or 1), p))
    return [p for _, p in sorted(found)]


def in_order(sent, got):
    flags, i = [], 0
    for q in got:
        j = i
        while j < len(sent) and sent[j] != q:
            j += 1
        flags.append(j < len(sent))
        if j < len(sent):
            i = j + 1
    return flags


def expected_payload(stream, seq):
    return (bytes([int(stream), 0, 0, 0]) + int(seq).to_bytes(4, "big")).hex()


def own_keys(directory):
    """{key suffix: count} of one FUNCTIONAL directory."""
    k = {}
    tx = [read(p) for p in parts(directory, "app_tx")]
    rx = [read(p) for p in parts(directory, "app_rx")]
    pay = [r for p in parts(directory, "rx_payload") for r in read(p)[2]]
    if not tx or not rx:
        raise SystemExit(f"{directory}: app_tx*.csv or app_rx*.csv is missing")
    sent = {}
    for _, _, rows in tx:
        for r in rows:
            sent.setdefault(r["stream"], []).append(int(r["seq"]))
    named = tx[0][0].get("streams", "")
    if named.isdigit():
        for s in range(int(named)):
            sent.setdefault(str(s), [])
    ok, rejected = [], Counter()
    for _, _, rows in rx:
        for r in rows:
            if r["result"] == "ok":
                ok.append((r["stream"], int(r["seq"])))
            else:
                rejected[r["result"]] += 1
    if [(r["stream"], int(r["seq"])) for r in pay] != ok:
        raise SystemExit(f"{directory}: rx_payload*.csv does not list the delivered rows of app_rx*.csv in their order")
    unknown = set(rejected) - set(REJECTED)
    if unknown:
        raise SystemExit(f"{directory}: result values outside the contract: {sorted(unknown)}")
    eight = tx[0][0].get("payload_len") == "8"
    streams = sorted({*sent, *(s for s, _ in ok)}, key=int)
    tot = Counter()
    for s in streams:
        got = [(q, r["payload_hex"].lower()) for (d, q), r in zip(ok, pay) if d == s]
        flags = in_order(sent.get(s, []), [q for q, _ in got])
        vals = {"sent": len(sent.get(s, [])), "delivered": len(got), "delivered_in_order": sum(flags)}
        vals["lost"] = vals["sent"] - vals["delivered_in_order"]
        if eight:
            vals["delivered_byte_exact"] = sum(f and h == expected_payload(s, q) for f, (q, h) in zip(flags, got))
        for name, v in vals.items():
            k[f"s{s}.{name}"] = v
            tot[name] += v
    k.update(tot)
    k["streams"] = len(streams)
    k["rejected"] = sum(rejected.values())
    for r in REJECTED:
        k[f"rejected_{r}"] = rejected[r]
    roles = {}
    for stem in ("handshake_tx", "handshake_rx"):
        for p in parts(directory, stem):
            for r in read(p)[2]:
                roles.setdefault(r["role"], Counter())[r["result"]] += 1
    for role, c in roles.items():
        k[f"{role}.n"] = sum(c.values())
        k[f"{role}.result_ok"] = c["ok"]          # the toolkit prints ok also when it is 0
        for result, n in c.items():
            k[f"{role}.result_{result}"] = n
    for side, files in (("tx", tx), ("rx", rx)):
        values = [v for _, nodelay, _ in files for v in nodelay]
        k[f"{side}.parts"] = len(files)
        k[f"{side}.tcp_connections"] = len(values)
        k[f"{side}.tcp_nodelay_1"] = values.count("1")
    return k


def record_compared(analysis_dir, keys):
    """Addendum F4: <analysis_dir>/own_compared_keys.txt, the keys that this call compared with a toolkit value and found
    equal, one per line, sorted. Under e9_compare.py (OWN_COMPARED_KEYS=add) the readers of one call add to one file;
    a direct call writes its own set. A call that does not end in agreement leaves no key of its own."""
    path = Path(analysis_dir) / "own_compared_keys.txt"
    if path.parent.is_dir():
        old = path.read_text().split() if os.environ.get("OWN_COMPARED_KEYS") == "add" and path.exists() else []
        path.write_text("".join(k + "\n" for k in sorted({*old, *keys})))


def latency_key(prefix, key):
    """A key <prefix>.functional[.<name>].e2e.<...>: written from the clock probe beside the gateway files (E9, cell g)
    and judged by e2e_compare.py, not here."""
    return re.fullmatch(re.escape(prefix) + r"\.functional\.(?:[^.]+\.)?e2e\..+", key) is not None


def self_test():
    assert latency_key("e9.s1.g", "e9.s1.g.functional.e2e.n") and latency_key("t", "t.functional.run1.e2e.stream0.n")
    assert not latency_key("t", "t.functional.sent") and not latency_key("t", "t.functional.e2e_x.n") and not latency_key("t", "t.periodic.c.e2e.n")
    assert in_order([0, 1, 2, 3], [0, 2, 3]) == [True, True, True]
    assert in_order([0, 1, 2, 3], [2, 1, 3]) == [True, False, True]          # a late PDU is not in order
    assert in_order([0, 1, 0, 1], [0, 1, 0, 1]) == [True] * 4                # a restarted transmitter counts from 0 again
    assert in_order([0, 1], [0, 0]) == [True, False]                         # a duplicate is not counted twice
    assert in_order([], [5]) == [False]
    assert 4 - sum(in_order([0, 1, 2, 3], [0, 2, 3])) == 1 and 2 - sum(in_order([0, 1], [0, 0])) == 1     # lost = sent - delivered in order
    assert expected_payload("0", 1) == "0000000000000001" and expected_payload("3", 258) == "0300000000000102"
    print("self-test ok")


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    run_dir, analysis_dir, prefix = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    self_test()
    record_compared(analysis_dir, [])    # a direct call starts the file; under e9_compare.py this changes nothing
    dirs = sorted(m.parent for m in run_dir.rglob("FUNCTIONAL") if m.is_file())
    if not dirs:
        raise SystemExit(f"{run_dir}: no directory with the marker FUNCTIONAL")
    own = {}
    for d in dirs:
        base = f"{prefix}.functional" + ("" if d == run_dir else "." + d.name)
        for suffix, v in own_keys(d).items():
            own[f"{base}.{suffix}"] = v
    kit = {}
    with open(analysis_dir / "numbers.csv", newline="") as f:
        for r in csv.DictReader(f):
            if r["key"].startswith(prefix + ".functional.") and r["unit"] != "text" and not latency_key(prefix, r["key"]):
                kit[r["key"]] = r["value"]
    bad, agreed = 0, []
    for key in sorted(set(own) | set(kit)):
        a, b = own.get(key), kit.get(key)
        same = a is not None and b is not None and float(b) == a
        if not same:
            bad += 1
            print(f"DIFF {key}: own {a}, toolkit {b}")
        else:
            agreed.append(key)
    print(f"functional runs: {len(dirs)}; keys compared: {len(set(own) | set(kit))}; differences: {bad}")
    for d in dirs:
        o = own_keys(d)
        per_result = ", ".join("%s %d" % (r, o["rejected_" + r]) for r in REJECTED)
        print(f"  {d.name}: sent {o['sent']}, delivered {o['delivered']}, in order {o['delivered_in_order']}, "
              f"byte exact {o.get('delivered_byte_exact', 'n/a')}, rejected {o['rejected']} ({per_result})")
    record_compared(analysis_dir, agreed if bad == 0 and kit else [])
    print("AGREE" if bad == 0 and kit else "DISAGREE")
    sys.exit(0 if bad == 0 and kit else 1)


if __name__ == "__main__":
    main()
