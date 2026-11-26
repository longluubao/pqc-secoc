"""Independent second reading of an E4 run directory (attack injection), compared key by key with the toolkit.

usage: python3 -I attack_compare.py <run_dir> <analysis_dir> <key_prefix>      (python3 -I attack_compare.py --self-test)
Reads <run_dir>/attack/attack.csv itself (vector,iter,delivered,reject_stage,detect_ns; DATA_SCHEMA.md) and, as a second
source that does not pass through the join script, the two logs it was joined from: proxy_log.csv (what the attacker
sent, in order) and the receiver's log (periodic_rx.csv of the harness receiver or app_rx.csv of the gateway, one row
per PDU in arrival order; the one whose SHA-256 the header of attack.csv records).
Own rules, written from the contract:
  per vector  injected = rows; delivered = rows with delivered = 1 (expected 0 for an attack vector); rejected = rows
              with a reject_stage other than none, counted per stage (framing, freshness, auth); share rejected with
              the exact (Clopper-Pearson) two-sided 95 % interval
  benign      rows the attacker passed on unchanged; delivered; false rejections = not delivered, with the two-sided
              interval and the one-sided 95 % upper bound
  detection time   detect_ns of the rejected rows, per vector and per stage: number, median, p99, maximum (ms, type 7);
              only when the oracle records the instant: '# oracle=gateway_app_log' has 0 in every row, which means
              not recorded, and such a file must give NO time key
  companions  TCP keeps the order, so row i of proxy_log.csv is row i of the receiver's log: vector and iter from the
              proxy, delivered and stage from the receiver's result, detection time = verify_done_ns - rx_done_ns of
              a rejected row that has both. Rows built this way must be the rows of attack.csv one by one, a delivered
              row must carry the sequence number the proxy saw, and the transmitter's periodic_tx.csv must have as
              many confirmed jobs as the proxy took in. A missing companion is a difference.
Validity from the schema: tcp_nodelay = 1 in attack.csv and jobs_started = jobs_confirmed in periodic_tx.csv beside it;
an invalid file must have no toolkit key. Exit 0 only if at least one attack vector and benign were compared, the
companions give the same rows and nothing differs.
"""
import csv
import hashlib
import math
import os
import site
import sys
from collections import Counter
from pathlib import Path

if sys.flags.no_user_site:      # python3 -I hides the user site-packages, where numpy is installed on the measuring workstation
    site.addsitedir(site.getusersitepackages())
from scipy import optimize, stats as sps  # noqa: E402

VECTORS = ("benign", "replay", "bitflip", "auth_tamper", "freshness_rollback", "session_replay")
STAGE = {"ok": "none", "framing_fail": "framing", "freshness_fail": "freshness", "auth_fail": "auth"}


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
            rows.append(dict(zip(cols, line.split(",", len(cols) - 1))))
    return meta, rows


def pct(values, p):
    """Percentile of type 7 (Hyndman and Fan): linear between the order statistics around (n - 1) p / 100."""
    x = sorted(values)
    h = (len(x) - 1) * p / 100
    i = math.floor(h)
    return x[i] + (h - i) * (x[min(i + 1, len(x) - 1)] - x[i])


def bound(k, n, tail, upper):
    """Exact (Clopper-Pearson) bound of k out of n by its definition: the share at which the binomial tail on the far
    side of k (at most k for an upper bound, at least k for a lower one) holds `tail`."""
    if upper:
        return 1.0 if k == n else optimize.brentq(lambda p: sps.binom.cdf(k, n, p) - tail, 0, 1, xtol=1e-15, rtol=1e-14)
    return 0.0 if k == 0 else optimize.brentq(lambda p: sps.binom.sf(k - 1, n, p) - tail, 0, 1, xtol=1e-15, rtol=1e-14)


def detect(name, ns, timed, stats=("p50", "p99", "max")):
    """Number and statistics (ms) of detection times; None each (the toolkit must not have the key) when the oracle
    records no instant, and for the statistics without a value."""
    out = {f"{name}detect_n": len(ns) if timed else None}
    for s in stats:
        v = None if not (timed and ns) else max(ns) if s == "max" else pct(ns, float(s[1:]))
        out[f"{name}detect_{s}_ms"] = None if v is None else v / 1e6
    return out


def own_keys(rows, timed):
    """{toolkit key behind the head: own value} of the rows of an attack.csv."""
    k = {}
    for v in dict.fromkeys(r["vector"] for r in rows):
        mine = [r for r in rows if r["vector"] == v]
        n, rej = len(mine), [r for r in mine if r["reject_stage"] != "none"]
        k.update({f"{v}.n": n, f"{v}.delivered": sum(r["delivered"] == "1" for r in mine), f"{v}.rejected": len(rej),
                  f"{v}.rejection_rate": len(rej) / n, f"{v}.rejection_cp95_lo": bound(len(rej), n, 0.025, False),
                  f"{v}.rejection_cp95_hi": bound(len(rej), n, 0.025, True),
                  **detect(f"{v}.", [int(r["detect_ns"]) for r in rej], timed)})
        for stage in ("framing", "freshness", "auth"):
            at = [int(r["detect_ns"]) for r in mine if r["reject_stage"] == stage]
            k.update({f"{v}.{stage}.count": len(at), **detect(f"{v}.{stage}.", at, timed, ("p50", "max"))})
        if v == "benign":
            false = n - k["benign.delivered"]
            k.update({"benign.false_rejections": false, "benign.false_rejection_rate": false / n,
                      "benign.false_rejection_cp95_lo": bound(false, n, 0.025, False),
                      "benign.false_rejection_cp95_hi": bound(false, n, 0.025, True),
                      "benign.false_rejection_cp95_onesided_hi": bound(false, n, 0.05, True)})
    return k


def from_logs(proxy, rx):
    """(the rows of attack.csv as the two logs give them, row i of one with row i of the other; the delivered rows whose
    sequence number is not the one the proxy saw)."""
    out, wrong = [], 0
    for p, r in zip(proxy, rx):
        ok = r["result"] == "ok"
        wrong += ok and r["seq"] != p["src_seq"]
        both = not ok and int(r["rx_done_ns"]) > 0 and int(r["verify_done_ns"]) > 0
        if p["vector"] in VECTORS:
            out.append({"vector": p["vector"], "iter": p["iter"], "delivered": "1" if ok else "0", "reject_stage": STAGE[r["result"]],
                        "detect_ns": str(int(r["verify_done_ns"]) - int(r["rx_done_ns"]) if both else 0)})
    return out, wrong


def toolkit(analysis_dir, prefix):
    """(common head of the keys, {key behind the head: value}) of the toolkit rows of attack/attack.csv, text left out."""
    with open(Path(analysis_dir) / "numbers.csv", newline="") as f:
        mine = {r["key"]: r["value"] for r in csv.DictReader(f)
                if r["key"].startswith(prefix + ".attack.") and r["source_file"] == "attack/attack.csv" and r["unit"] != "text"}
    head = os.path.commonprefix(list(mine))
    head = head[:head.rfind(".") + 1]
    return head, {k[len(head):]: v for k, v in mine.items()}


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


def self_test():
    assert pct([1, 2, 3, 4], 50) == 2.5 and pct([7], 99) == 7 and math.isclose(pct(range(1, 101), 99), 99.01)
    assert bound(0, 650, 0.025, False) == 0 and bound(50, 50, 0.025, True) == 1
    assert math.isclose(bound(0, 650, 0.025, True), 1 - 0.025 ** (1 / 650), rel_tol=1e-12)      # closed forms at 0 and at n
    assert math.isclose(bound(0, 650, 0.05, True), 1 - 0.05 ** (1 / 650), rel_tol=1e-12)
    assert math.isclose(bound(50, 50, 0.025, False), 0.025 ** (1 / 50), rel_tol=1e-12)
    assert abs(bound(3, 10, 0.025, False) - 0.06674) < 5e-6 and abs(bound(3, 10, 0.025, True) - 0.65245) < 5e-6   # table value

    def row(vector, it, delivered, stage, ns):
        return {"vector": vector, "iter": str(it), "delivered": delivered, "reject_stage": stage, "detect_ns": str(ns)}

    rows = [row("benign", 0, "1", "none", 0), row("benign", 1, "0", "auth", 9), row("replay", 0, "0", "freshness", 1000),
            row("replay", 1, "0", "auth", 3000), row("replay", 2, "1", "none", 0)]
    k = own_keys(rows, True)
    assert k["replay.n"] == 3 and k["replay.delivered"] == 1 and k["replay.rejected"] == 2 and k["replay.freshness.count"] == 1
    assert k["replay.detect_n"] == 2 and k["replay.detect_p50_ms"] == 0.002 and k["replay.detect_max_ms"] == 0.003
    assert k["replay.framing.detect_n"] == 0 and k["replay.framing.detect_max_ms"] is None
    assert k["benign.false_rejections"] == 1 and k["benign.false_rejection_rate"] == 0.5 and k["benign.auth.count"] == 1
    k = own_keys(rows, False)                                                 # an oracle without the instant: no time key
    assert k["replay.detect_n"] is None and k["replay.auth.detect_max_ms"] is None and k["replay.rejected"] == 2
    proxy = [{"vector": v, "iter": str(i), "src_seq": str(s)} for v, i, s in (("benign", 0, 0), ("replay", 0, 0), ("other", 0, 9), ("bitflip", 0, 1))]
    rx = [{"seq": "0", "result": "ok", "rx_done_ns": "10", "verify_done_ns": "15"}, {"seq": "0", "result": "freshness_fail", "rx_done_ns": "20", "verify_done_ns": "27"},
          {"seq": "9", "result": "ok", "rx_done_ns": "30", "verify_done_ns": "31"}, {"seq": "-1", "result": "auth_fail", "rx_done_ns": "0", "verify_done_ns": "50"}]
    built, wrong = from_logs(proxy, rx)
    assert wrong == 0 and built == [row("benign", 0, "1", "none", 0), row("replay", 0, "0", "freshness", 7), row("bitflip", 0, "0", "auth", 0)]
    assert from_logs(proxy[:1], [{**rx[0], "seq": "4"}])[1] == 1              # delivered with another sequence number
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
    d = run_dir / "attack"
    if not (d / "attack.csv").exists():
        raise SystemExit(f"{run_dir}: no attack/attack.csv")
    meta, rows = read(d / "attack.csv")
    timed = meta.get("oracle") != "gateway_app_log"
    own = own_keys(rows, timed)
    head, theirs = toolkit(analysis_dir, prefix)
    head = head or prefix + ".attack.<no key>."
    tx_meta, tx_rows = read(d / "periodic_tx.csv") if (d / "periodic_tx.csv").exists() else ({}, [])
    why = [f"tcp_nodelay={meta.get('tcp_nodelay')}"] if meta.get("tcp_nodelay") != "1" else []
    if tx_meta.get("jobs_started") is None or tx_meta.get("jobs_started") != tx_meta.get("jobs_confirmed"):
        why.append(f"periodic_tx.csv: jobs_started={tx_meta.get('jobs_started')}, jobs_confirmed={tx_meta.get('jobs_confirmed')}")
    print(f"attack.csv: oracle {meta.get('oracle')} ({'detection time recorded' if timed else 'no detection time'}), {len(rows)} rows, "
          f"contradicting_pdus={meta.get('contradicting_pdus')}")
    for v in dict.fromkeys(r["vector"] for r in rows):
        stages = ", ".join(f"{s} {own[f'{v}.{s}.count']}" for s in ("framing", "freshness", "auth"))
        t = "" if not timed or not own[f"{v}.detect_n"] else (f"; detection ms p50 {own[f'{v}.detect_p50_ms']:.4f}, p99 "
                                                              f"{own[f'{v}.detect_p99_ms']:.4f}, max {own[f'{v}.detect_max_ms']:.4f} (n {own[f'{v}.detect_n']})")
        print(f"  {v}: {'passed on unchanged' if v == 'benign' else 'injected'} {own[f'{v}.n']}, delivered {own[f'{v}.delivered']}, rejected {own[f'{v}.rejected']} ({stages}){t}")
    bad = 0
    if why:
        print("attack.csv: INVALID by the own rules: " + "; ".join(why))
        print(f"DIFF {head}*: own INVALID, toolkit has {len(theirs)} keys" if theirs else "the toolkit has no key either: consistent, nothing compared")
        bad += bool(theirs)
    else:
        bad += compare(head, own, theirs)
    compared = 0 if why else sum(v is not None for v in own.values())
    print(f"keys compared {compared}, differences {bad}; toolkit keys not recomputed here: {len(set(theirs) - set(own))}")
    # the second source: the two logs the join script read
    sha = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in d.glob("*.csv")}
    rx_name = next((n for n in ("periodic_rx.csv", "app_rx.csv") if sha.get(n) == meta.get("rx_file_sha256")), None)
    diffs = []
    if sha.get("proxy_log.csv") != meta.get("proxy_log_sha256") or rx_name is None:
        diffs.append(("the two logs with the SHA-256 recorded in attack.csv", f"proxy_log.csv {'found' if sha.get('proxy_log.csv') == meta.get('proxy_log_sha256') else 'not found'}, receiver log {rx_name}", "both"))
    else:
        proxy_meta, proxy = read(d / "proxy_log.csv")
        rx = read(d / rx_name)[1]
        built, wrong = from_logs(proxy, rx)
        if len(proxy) != len(rx):
            diffs.append(("rows of the two logs", f"proxy {len(proxy)}, receiver {len(rx)}", "equal"))
        if wrong:
            diffs.append(("delivered rows with another sequence number than the proxy saw", wrong, 0))
        if built != rows:
            first = next((i for i, (a, b) in enumerate(zip(built, rows)) if a != b), min(len(built), len(rows)))
            diffs.append((f"rows built from the logs, first difference at row {first}", f"{len(built)} rows, {built[first] if first < len(built) else None}",
                          f"{len(rows)} rows, {rows[first] if first < len(rows) else None}"))
        sent = sum(r["send_done_ns"] != "0" for r in tx_rows)
        if not tx_rows or str(sent) != proxy_meta.get("pdus_in"):
            diffs.append(("PDUs the transmitter confirmed against pdus_in of the proxy", sent if tx_rows else "no periodic_tx.csv", proxy_meta.get("pdus_in")))
        results = Counter(r["result"] for r in rx)
        print(f"companions: transmitter confirmed {sent} PDUs, proxy took in {proxy_meta.get('pdus_in')} and injected {proxy_meta.get('injected')}; "
              f"{rx_name}: {len(rx)} rows (" + ", ".join(f"{k} {v}" for k, v in results.items()) + f"); rows built from the two logs: {len(built)}, "
              f"{'the same as' if built == rows else 'NOT'} the {len(rows)} rows of attack.csv")
    for what, a, b in diffs:
        print(f"DIFF companions, {what}: own {a}, attack.csv {b}")
    vectors = {r["vector"] for r in rows}
    ok = not bad and not diffs and not why and "benign" in vectors and len(vectors) > 1 and compared >= 20
    record_compared(analysis_dir, AGREED if ok else [])
    print("OWN-CHECK AGREES" if ok else "OWN-CHECK DISAGREES")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
