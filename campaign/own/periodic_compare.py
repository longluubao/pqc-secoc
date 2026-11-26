"""Independent second reading of an E6 run directory (periodic streams, deadlines), compared key by key with the toolkit.

usage: python3 -I periodic_compare.py <run_dir> <analysis_dir> <key_prefix>      (python3 -I periodic_compare.py --self-test)
Reads <run_dir>/periodic/periodic_tx*.csv and the periodic_rx*.csv of the same suffix itself (DATA_SCHEMA.md).
Own rules, written from the contract:
  header     payload_bytes: the '# payload_bytes=' line of the transmitter's file, compared as a count
  release    one row of the transmitter's file is one released job
  latency    send_done_ns - release_ns of the jobs that have a send_done_ns: release to transmit confirmation on the
             TRANSMITTER's clock (the toolkit's response_*), in ms, percentiles of type 7. It is not the arrival at
             the far end: that needs clock_offset.csv, which the campaign does not carry.
  miss       the quantity judged is that latency, against deadline_ns of the file's header (the line printed per file
             says whether it equals period_ns): a job misses when send_done_ns = 0 or send_done_ns - release_ns >
             deadline_ns (strictly). share = misses / releases with the exact (Clopper-Pearson) two-sided 95 %
             interval; longest run of misses per stream in seq order, the worst stream
  other keys every toolkit key of a pair whose kind is not in KNOWN (latency_*, end_to_end_*, any figure added to the
             toolkit later) is printed by name as NOT COMPARED; it does not change the exit code
  delivered  released jobs (stream, seq) with at least one ok row at the receiver. not delivered = releases -
             delivered is an own figure (printed); the toolkit's rx_lost is narrower: jobs with no receiver row
  receiver   verify_done_ns - rx_done_ns and deliver_ns - rx_done_ns over the ok rows, on the receiver's clock
  stages     of the transmitter, per file: queueing = start_ns - release_ns of the started jobs (the wait before the
             start), auth = auth_done_ns - start_ns of the jobs with an auth_done_ns (the time in the authentication
             call), service = send_done_ns - start_ns of the finished jobs. Of each: n (0 when no job has the stage;
             no auth_n at all when the header says not_recorded=auth_done_ns), mean, sd, min, max and the
             type-7 percentiles 50, 90, 95, 99, 99.9, 99.99, in ms and in us. The key definitions say "sd" without
             its divisor: n - 1, as the docstring of the toolkit's describe() states it (settled there)
  utilisation  auth_utilisation of a sender file: the time covered by the UNION of the closed intervals
             [start_ns, auth_done_ns] of its rows with an auth_done_ns, in whole ns, over the largest send_done_ns
             minus the smallest release_ns of all its rows. No key (the toolkit must not have it) when the header says
             not_recorded=auth_done_ns, when no job finished, or when another sender file of the directory has the
             same cpu_affinity (two processes on one core)
  cell       several transmitter files (partitions) in the directory: releases and misses added, share and interval;
             cores = the distinct cpu_affinity values of the files when every file has the line, else the sum of the
             files' cores, and the cell's name says -c<cores>-; only when every file has a cpu_affinity and all name
             the SAME core, one auth_utilisation of the cell: the union over the rows of all its files, over the span
             of all its files (no key when a file says not_recorded=auth_done_ns or has no finished job: a figure
             from a part of the processes is not the core's); a cell with fewer cores than processes: the toolkit
             must have no model_* key of its files
Validity, judged here from the schema: tcp_nodelay = 1 and a footer on both ends, tcp_connections_at_first_release =
tcp_connections_at_end, jobs_started = jobs_confirmed, one session_id; and one own rule that the schema does not
have: rows_lost = 0 in the receiver's footer. A pair that is invalid here must have no toolkit key; a valid pair must
have every key computed here. Anything else is a difference.
Exit 0 only if at least one valid pair was compared and nothing differs.
"""
import csv
import math
import os
import re
import site
import sys
from fractions import Fraction
from pathlib import Path

if sys.flags.no_user_site:      # python3 -I hides the user site-packages, where numpy is installed on the measuring workstation
    site.addsitedir(site.getusersitepackages())
from scipy import optimize, stats as sps  # noqa: E402

RESULTS = ("ok", "freshness_fail", "auth_fail", "framing_fail")
# the kinds of toolkit key of a periodic pair seen on 2026-11-23; a key outside them is named as NOT COMPARED
AGREED = []      # the full names of the keys that were compared with a toolkit value and are equal (Addendum F4)
KNOWN = re.compile(r"(s\d+\.)?(auth|queueing|response|service|rx_verify|rx_deliver|rx_reject_\w+?)_(n|mean|sd|min|max|p[\d_]+)(_ms|_us)?$"
                   r"|(s\d+\.)?(jobs|misses|longest_miss_run|max_misses_in_\d+|rx_delivered|rx_lost|rx_result_\w+)$"
                   r"|(miss_ratio|miss_(cp|wilson)95_(lo|hi)|model_\w+|not_started|unfinished|cores|streams|partition|payload_bytes"
                   r"|(period|deadline|mf_period)_(ms|us)|rx_rows|rx_delivery_ratio|rx_duplicates|rx_not_in_tx|rx_out_of_order"
                   r"|tcp_\w+_in_window)$")


def read(path):
    """({key: value} of the '# key=value' lines anywhere in the file, rows as dicts with the _ns columns and seq as int)."""
    meta, cols, rows = {}, None, []
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("#"):
            k, _, v = line[1:].strip().partition("=")
            meta[k] = v
        elif line.strip() and cols is None:
            cols = line.split(",")
        elif line.strip():
            rows.append({c: int(v) if c.endswith("_ns") or c == "seq" else v for c, v in zip(cols, line.split(","))})
    return meta, rows


def pct(values, p):
    """Percentile of type 7 (Hyndman and Fan): linear between the order statistics around (n - 1) p / 100."""
    x = sorted(values)
    h = (len(x) - 1) * p / 100
    i = math.floor(h)
    return x[i] + (h - i) * (x[min(i + 1, len(x) - 1)] - x[i])


def cp95(k, n):
    """Exact two-sided 95 % interval of k out of n, by its definition: each bound is the share at which the binomial
    tail on the far side of k holds 2.5 %."""
    lo = 0.0 if k == 0 else optimize.brentq(lambda p: sps.binom.sf(k - 1, n, p) - 0.025, 0, 1, xtol=1e-15, rtol=1e-14)
    hi = 1.0 if k == n else optimize.brentq(lambda p: sps.binom.cdf(k, n, p) - 0.025, 0, 1, xtol=1e-15, rtol=1e-14)
    return lo, hi


def longest_run(flags):
    best = run = 0
    for f in flags:
        run = run + 1 if f else 0
        best = max(best, run)
    return best


def most_in_window(flags, n):
    """The most misses in any n consecutive jobs of a stream; None (no key) when the stream has fewer than n jobs: then
    there is no window of n consecutive jobs."""
    if len(flags) < n:
        return None
    best = run = sum(flags[:n])
    for i in range(n, len(flags)):
        run += flags[i] - flags[i - n]
        best = max(best, run)
    return best


def times(name, ns):
    """Median, p99, p99.9 and maximum in ms; None each (the toolkit must not have the key) without a value."""
    return {f"{name}_p50_ms": pct(ns, 50) / 1e6 if ns else None, f"{name}_p99_ms": pct(ns, 99) / 1e6 if ns else None,
            f"{name}_p99_9_ms": pct(ns, 99.9) / 1e6 if ns else None, f"{name}_max_ms": max(ns) / 1e6 if ns else None}


def spread(name, ns):
    """{<name>_n, <name>_<statistic>_ms, <name>_<statistic>_us} of whole nanoseconds: their number, mean, sd (divisor
    n - 1), min, max and the type-7 percentiles 50, 90, 95, 99, 99.9, 99.99. Without a value the number is 0 and every
    other key None (the toolkit must not have it); the sd also with a single one. Sum and sum of squares are whole numbers, so mean and variance
    are exact before the one division."""
    x, n, total = sorted(ns), len(ns), sum(ns)
    if not n:
        v = dict.fromkeys(("mean", "sd", "min", "max", "p50", "p90", "p95", "p99", "p99_9", "p99_99"))
    else:
        v = {"mean": total / n, "sd": math.sqrt(Fraction(n * sum(t * t for t in x) - total * total, n * (n - 1))) if n > 1 else None,
             "min": x[0], "max": x[-1], **{"p" + str(p).replace(".", "_"): pct(x, p) for p in (50, 90, 95, 99, 99.9, 99.99)}}
    return {f"{name}_n": n, **{f"{name}_{s}_{unit}": None if value is None else value / per
                                       for s, value in v.items() for unit, per in (("ms", 1e6), ("us", 1e3))}}


def auth_utilisation(files):
    """The share of its span in which a core was in the authentication call. files: (header, rows) of the sender files
    of that core. Numerator: the length of the union of the closed intervals [start_ns, auth_done_ns] of the rows with
    an auth_done_ns, in whole ns; denominator: the largest send_done_ns minus the smallest release_ns over all rows.
    None (no key) when a header says not_recorded=auth_done_ns or when no job finished."""
    rows = [r for _, part in files for r in part]
    if any("auth_done_ns" in meta.get("not_recorded", "") for meta, _ in files) or not any(r["send_done_ns"] for r in rows):
        return None
    covered, end = 0, None
    for a, b in sorted((r["start_ns"], r["auth_done_ns"]) for r in rows if r["auth_done_ns"]):
        if end is None or a > end:
            covered, end = covered + b - a, b
        elif b > end:
            covered, end = covered + b - end, b
    return covered / (max(r["send_done_ns"] for r in rows) - min(r["release_ns"] for r in rows))


def share(k, n):
    lo, hi = cp95(k, n)
    return {"misses": k, "miss_ratio": k / n, "miss_cp95_lo": lo, "miss_cp95_hi": hi}


def own_tx(meta, rows):
    """{toolkit key suffix: own value} of one transmitter file."""
    deadline = int(meta["deadline_ns"])

    def miss(r):
        return r["send_done_ns"] == 0 or r["send_done_ns"] - r["release_ns"] > deadline

    lat = [r["send_done_ns"] - r["release_ns"] for r in rows if r["send_done_ns"]]
    k = {"period_ms": int(meta["period_ns"]) / 1e6, "deadline_ms": deadline / 1e6, "streams": int(meta["streams"]),
         "payload_bytes": int(meta["payload_bytes"]), "jobs": len(rows), "unfinished": sum(r["send_done_ns"] == 0 for r in rows),
         "not_started": sum(r["start_ns"] == 0 for r in rows), "response_n": len(lat), **times("response", lat),
         **share(sum(map(miss, rows)), len(rows))}
    streams = {}
    for r in sorted(rows, key=lambda r: r["seq"]):
        streams.setdefault(r["stream"], []).append(miss(r))
    for s, flags in streams.items():
        k[f"s{s}.jobs"], k[f"s{s}.misses"], k[f"s{s}.longest_miss_run"] = len(flags), sum(flags), longest_run(flags)
        k.update({f"s{s}.max_misses_in_{n}": most_in_window(flags, n) for n in (10, 100, 1000)})
    k["longest_miss_run"] = max(longest_run(f) for f in streams.values())
    for n in (10, 100, 1000):      # the worst stream, of those that have such a window
        worst = [k[f"s{s}.max_misses_in_{n}"] for s in streams if k[f"s{s}.max_misses_in_{n}"] is not None]
        k[f"max_misses_in_{n}"] = max(worst) if worst else None
    k.update(spread("queueing", [r["start_ns"] - r["release_ns"] for r in rows if r["start_ns"]]))
    k.update(spread("auth", [r["auth_done_ns"] - r["start_ns"] for r in rows if r["auth_done_ns"]]))
    if "auth_done_ns" in meta.get("not_recorded", ""):
        k["auth_n"] = None      # the stage is not recorded: no key at all, not a count of 0
    k.update(spread("service", [r["send_done_ns"] - r["start_ns"] for r in rows if r["send_done_ns"]]))
    # the transmitter's TCP counters over the measured window: the value at the end minus the value at the first release
    for name in ("total_retrans", "total_rto", "dsack_dups"):
        a, b = meta.get(f"tcp_{name}_at_first_release"), meta.get(f"tcp_{name}_at_end")
        k[f"tcp_{name}_in_window"] = None if a is None or b is None else int(b) - int(a)
    return k


def own_rx(tx_rows, meta, rows):
    """{toolkit key suffix: own value} of the receiver file of a pair."""
    jobs = [(r["stream"], r["seq"]) for r in tx_rows]
    ok = [r for r in rows if r["result"] == "ok"]
    got, seen = {(r["stream"], r["seq"]) for r in ok}, {(r["stream"], r["seq"]) for r in rows}
    k = {"rx_rows": len(rows), "rx_delivered": sum(j in got for j in jobs), "rx_lost": sum(j not in seen for j in jobs)}
    for res in RESULTS:
        k[f"rx_result_{res}"] = sum(r["result"] == res for r in rows)
    for s in dict.fromkeys(s for s, _ in jobs):
        k[f"s{s}.rx_delivered"] = sum(j in got for j in jobs if j[0] == s)
        k[f"s{s}.rx_lost"] = sum(j not in seen for j in jobs if j[0] == s)
    if "rx_done_ns" not in meta.get("not_recorded", ""):
        k.update(times("rx_verify", [r["verify_done_ns"] - r["rx_done_ns"] for r in ok]))
        k.update(times("rx_deliver", [r["deliver_ns"] - r["rx_done_ns"] for r in ok]))
    return k


def invalid(tx, rx):
    """Reasons of DATA_SCHEMA.md why a pair is no result; [] for a valid pair. rx is None without a receiver file."""
    why = ["no receiver file"] if rx is None else []
    for side, m in (("tx", tx), ("rx", rx or {})):
        if rx is not None or side == "tx":
            why += [f"{side}: tcp_nodelay={m.get('tcp_nodelay')}"] if m.get("tcp_nodelay") != "1" else []
            why += [f"{side}: no footer (interrupted)"] if "wall_s" not in m else []
    for a, b in (("tcp_connections_at_first_release", "tcp_connections_at_end"), ("jobs_started", "jobs_confirmed")):
        if tx.get(a) is None or tx.get(a) != tx.get(b):
            why.append(f"tx: {a}={tx.get(a)}, {b}={tx.get(b)}")
    if rx is not None and tx.get("session_id") != rx.get("session_id"):
        why.append(f"session_id {tx.get('session_id')} at the transmitter, {rx.get('session_id')} at the receiver")
    if rx and rx.get("rows_lost", "0") != "0":      # own rule, not in the schema: rows the receiver could not log
        why.append(f"rx: rows_lost={rx['rows_lost']}: the receiver's counts are too small")
    return why


def toolkit(analysis_dir, prefix):
    """[(key, value, source_file)] of the periodic keys of numbers.csv, text rows left out."""
    with open(Path(analysis_dir) / "numbers.csv", newline="") as f:
        return [(r["key"], r["value"], r["source_file"]) for r in csv.DictReader(f)
                if r["key"].startswith(prefix + ".periodic.") and r["unit"] != "text"]


def of_sources(kit, sources):
    """(common head of the keys, {key behind the head: value}) of the toolkit rows whose source_file is in `sources`."""
    mine = {k: v for k, v, s in kit if s in sources}
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


def record_compared(analysis_dir, keys):
    """Addendum F4: <analysis_dir>/own_compared_keys.txt, the keys that this call compared with a toolkit value and found
    equal, one per line, sorted. Under e9_compare.py (OWN_COMPARED_KEYS=add) the readers of one call add to one file;
    a direct call writes its own set. A call that does not end in agreement leaves no key of its own."""
    path = Path(analysis_dir) / "own_compared_keys.txt"
    if path.parent.is_dir():
        old = path.read_text().split() if os.environ.get("OWN_COMPARED_KEYS") == "add" and path.exists() else []
        path.write_text("".join(k + "\n" for k in sorted({*old, *keys})))


def self_test():
    assert pct([1, 2, 3, 4], 50) == 2.5 and pct([7], 99.9) == 7
    assert math.isclose(pct(range(1, 101), 99), 99.01) and math.isclose(pct([0, 10], 99.9), 9.99)
    lo, hi = cp95(0, 500)
    assert lo == 0 and math.isclose(hi, 1 - 0.025 ** (1 / 500), rel_tol=1e-12)        # closed form without a miss
    assert most_in_window([1, 0, 1, 1, 0, 0, 1], 3) == 2 and most_in_window([1, 1], 10) is None and most_in_window([1, 1], 2) == 2 and most_in_window([0] * 5 + [1] * 4, 3) == 3
    lo, hi = cp95(500, 500)
    assert hi == 1 and math.isclose(lo, 0.025 ** (1 / 500), rel_tol=1e-12)
    lo, hi = cp95(3, 10)                                                              # table value of 3 out of 10
    assert abs(lo - 0.06674) < 5e-6 and abs(hi - 0.65245) < 5e-6
    assert longest_run([0, 1, 1, 0, 1, 1, 1, 0]) == 3 and longest_run([]) == 0 and longest_run([1, 1]) == 2
    meta = {"deadline_ns": "10", "period_ns": "10", "streams": "2", "payload_bytes": "8"}

    def job(stream, seq, release, done):
        return {"stream": stream, "seq": seq, "release_ns": release, "start_ns": release + 1 if done else 0,
                "auth_done_ns": release + 3 if done else 0, "send_done_ns": done}

    rows = [job("0", 0, 100, 110), job("0", 1, 110, 121), job("0", 3, 130, 0), job("0", 2, 120, 131), job("1", 0, 100, 105),
            job("1", 1, 110, 0), job("1", 2, 120, 125), job("1", 3, 130, 0)]
    k = own_tx(meta, rows)
    assert k["jobs"] == 8 and k["misses"] == 5 and k["unfinished"] == 3 and k["response_n"] == 5     # exactly the deadline is met
    assert k["payload_bytes"] == 8 and isinstance(k["payload_bytes"], int)                           # the header line, compared as a count
    # the five finished jobs: started 1 ns after the release, authenticated 2 ns later, done 10, 11, 11, 5, 5 ns after the release
    assert k["queueing_n"] == k["auth_n"] == k["service_n"] == 5 and k["queueing_max_us"] == 0.001 and k["auth_mean_ms"] == 2e-6
    assert k["service_min_us"] == 0.004 and k["service_max_us"] == 0.010 and k["queueing_sd_ms"] == 0 and k["service_p50_ms"] == 9e-6
    # no job started: each stage counts 0 and has no other key; a stage that the header calls not recorded has no count either
    none = own_tx(meta, [job("0", 0, 100, 0), job("1", 0, 100, 0)])
    assert none["queueing_n"] == none["auth_n"] == none["service_n"] == 0 and none["auth_mean_ms"] is None and none["service_max_us"] is None
    assert own_tx({**meta, "not_recorded": "auth_done_ns"}, [{**r, "auth_done_ns": 0} for r in rows])["auth_n"] is None
    # utilisation, by hand: authentication from 10 to 20, 15 to 30 and 40 to 45 ns: the union covers 20 + 5 = 25 ns of the
    # span from the first release at 0 to the last send_done at 100
    def calls(*spans, last=100):
        return [{"release_ns": 0, "start_ns": a, "auth_done_ns": b, "send_done_ns": last} for a, b in spans]
    one = calls((10, 20), (15, 30), (40, 45))
    assert auth_utilisation([({}, one)]) == 0.25 and auth_utilisation([({}, calls((10, 20), (20, 30)))]) == 0.2      # touching intervals: 20 ns
    assert auth_utilisation([({}, calls((10, 20), (12, 18)))]) == 0.1                                                  # one inside the other
    # two sender files of one core: 10 to 20 in the first, 15 to 30 and 40 to 45 in the second, the second ends at 125: 25 / 125
    assert auth_utilisation([({}, calls((10, 20))), ({}, calls((15, 30), (40, 45), last=125))]) == 0.2
    assert auth_utilisation([({"not_recorded": "auth_done_ns"}, one)]) is None and auth_utilisation([({}, calls((10, 20), last=0))]) is None
    assert auth_utilisation([({}, one), ({"not_recorded": "auth_done_ns"}, calls((0, 0)))]) is None                    # a cell with a file that does not record the end
    assert auth_utilisation([({}, calls((0, 0), (10, 20)))]) == 0.1                                                    # a row without an auth_done_ns takes no part
    s = spread("t", [4_000_000, 1_000_000, 3_000_000, 2_000_000])      # 1, 2, 3, 4 ms: mean 2.5, variance 5/3, p90 at 3 + 0.7
    assert s["t_n"] == 4 and s["t_mean_ms"] == 2.5 and s["t_mean_us"] == 2500 and math.isclose(s["t_sd_ms"], math.sqrt(5 / 3), rel_tol=1e-15)
    assert s["t_min_us"] == 1000 and s["t_max_ms"] == 4 and s["t_p50_ms"] == 2.5 and math.isclose(s["t_p90_ms"], 3.7) and math.isclose(s["t_p99_99_us"], 3999.7)
    assert math.isclose(s["t_p95_ms"], 3.85) and math.isclose(s["t_p99_ms"], 3.97) and math.isclose(s["t_p99_9_ms"], 3.997) and len(s) == 21
    assert spread("t", [7])["t_sd_ms"] is None and spread("t", [7])["t_mean_us"] == 0.007 and spread("t", [])["t_n"] == 0 and set(spread("t", []).values()) == {0, None}
    assert k["s0.longest_miss_run"] == 3 and k["s1.longest_miss_run"] == 1 and k["longest_miss_run"] == 3   # per stream, by seq
    assert k["response_max_ms"] == 11 / 1e6 and k["response_p50_ms"] == 10 / 1e6
    rx = [{"stream": "0", "seq": 0, "result": "ok", "rx_done_ns": 1, "verify_done_ns": 3, "deliver_ns": 4},
          {"stream": "0", "seq": 0, "result": "freshness_fail", "rx_done_ns": 5, "verify_done_ns": 6, "deliver_ns": 0},
          {"stream": "0", "seq": 1, "result": "auth_fail", "rx_done_ns": 7, "verify_done_ns": 9, "deliver_ns": 0},
          {"stream": "-1", "seq": -1, "result": "framing_fail", "rx_done_ns": 9, "verify_done_ns": 0, "deliver_ns": 0}]
    k = own_rx(rows, {}, rx)
    assert k["rx_delivered"] == 1 and k["rx_lost"] == 6 and k["rx_rows"] == 4 and k["rx_result_framing_fail"] == 1
    assert k["s1.rx_lost"] == 4 and k["rx_verify_max_ms"] == 2 / 1e6 and k["rx_deliver_p50_ms"] == 3 / 1e6
    assert own_rx(rows, {"not_recorded": "rx_done_ns"}, rx).get("rx_verify_max_ms") is None
    good = {"tcp_nodelay": "1", "wall_s": "1", "tcp_connections_at_first_release": "1", "tcp_connections_at_end": "1",
            "jobs_started": "5", "jobs_confirmed": "5", "session_id": "ab"}
    assert invalid(good, good) == [] and len(invalid({**good, "tcp_connections_at_end": "9", "jobs_confirmed": "4"}, good)) == 2
    assert invalid(good, None) == ["no receiver file"] and len(invalid(good, {"tcp_nodelay": "0", "session_id": "cd"})) == 3
    assert len(invalid(good, {**good, "rows_lost": "2"})) == 1 and invalid(good, {**good, "rows_lost": "0"}) == []
    known = ("response_p99_9_ms", "rx_reject_auth_fail_n", "s3.max_misses_in_1000", "miss_cp95_hi", "tcp_total_rto_in_window", "s0.rx_result_ok")
    assert all(KNOWN.match(k) for k in known)
    assert not any(KNOWN.match(k) for k in ("latency_p50_ms", "end_to_end_max_us", "clock_rtt_max_us", "rx_minus_tx_above_min_p99_ms"))
    print("self-test ok")


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    self_test()
    run_dir, analysis_dir, prefix = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    record_compared(analysis_dir, [])    # a direct call starts the file; under e9_compare.py this changes nothing
    for marker in ("DRY_RUN", "PILOT", "EXCLUDED"):
        if (run_dir / marker).exists():
            print(f"marker {marker}: nothing in this directory is a result")
    files = sorted((run_dir / "periodic").glob("periodic_tx*.csv"))
    if not files:
        raise SystemExit(f"{run_dir}: no periodic/periodic_tx*.csv")
    kit = toolkit(analysis_dir, prefix)
    bad, valid, cell, cell_files, pairs = 0, 0, [], [], []
    txs = [(p, *read(p)) for p in files]
    cores = [meta.get("cpu_affinity") for _, meta, _ in txs]      # the core of each sender process of the directory
    for p, tx_meta, tx_rows in txs:
        rx_path = p.with_name(p.name.replace("periodic_tx", "periodic_rx", 1))
        rx_meta, rx_rows = read(rx_path) if rx_path.exists() else (None, [])
        own = {**own_tx(tx_meta, tx_rows), **own_rx(tx_rows, rx_meta or {}, rx_rows)}
        alone = tx_meta.get("cpu_affinity") is None or cores.count(tx_meta["cpu_affinity"]) == 1
        own["auth_utilisation"] = auth_utilisation([(tx_meta, tx_rows)]) if alone else None      # two processes on one core: the cell's key
        head, theirs = of_sources(kit, {f"periodic/{p.name}", f"periodic/{rx_path.name}"})
        why = invalid(tx_meta, rx_meta)
        ms = {k: "n/a" if v is None else f"{v:.3f}" for k, v in own.items() if k.startswith("response_")}
        print(f"{p.name}: deadline {own['deadline_ms']:g} ms, " + ("equal to the period" if own["deadline_ms"] == own["period_ms"] else
                                                                  f"NOT the period of {own['period_ms']:g} ms") + ", judged on send_done_ns - release_ns")
        print(f"{p.name}: releases {own['jobs']}, delivered {own['rx_delivered']}, not delivered {own['jobs'] - own['rx_delivered']} "
              f"(no receiver row: {own['rx_lost']}); latency ms p50 {ms['response_p50_ms']}, p99 {ms['response_p99_ms']}, p99.9 "
              f"{ms['response_p99_9_ms']}, max {ms['response_max_ms']} over {own['response_n']} finished; misses {own['misses']} = "
              f"{own['miss_ratio'] * 100:.4f} % [{own['miss_cp95_lo'] * 100:.4f}, {own['miss_cp95_hi'] * 100:.4f}], longest run "
              f"{own['longest_miss_run']}, not started {own['not_started']}, unfinished {own['unfinished']}")
        if why:
            print(f"{p.name}: INVALID by the own rules: " + "; ".join(why))
            if theirs:
                bad += 1
                print(f"DIFF {head}*: own INVALID, toolkit has {len(theirs)} keys of this pair")
            else:
                print(f"{p.name}: the toolkit has no key of this pair either: consistent, nothing compared")
            continue
        valid += 1
        cell.append(own)
        cell_files.append((tx_meta, tx_rows))
        pairs.append((head, theirs))
        diffs = compare(head or f"{prefix}.periodic.<no key of {p.name}>.", own, theirs)
        bad += diffs
        print(f"{p.name}: keys compared {sum(v is not None for v in own.values())}, differences {diffs}; toolkit keys of the pair not recomputed here: "
              f"{len(set(theirs) - set(own))}")
        for key in sorted(k for k in theirs if not KNOWN.match(k) and own.get(k) is None):      # a key that was recomputed above is not listed here
            print(f"NOT COMPARED {head}{key}: toolkit {theirs[key]} (a kind of key this reader does not recompute)")
    if valid > 1:      # the partitions of one cell: releases and misses are added
        jobs, misses = sum(o["jobs"] for o in cell), sum(o["misses"] for o in cell)
        own = {"partitions": valid, "streams": sum(o["streams"] for o in cell), "jobs": jobs, **share(misses, jobs)}
        pinned, counts = [meta.get("cpu_affinity") for meta, _ in cell_files], [meta.get("cores") for meta, _ in cell_files]
        own["cores"] = len(set(pinned)) if None not in pinned else sum(map(int, counts)) if None not in counts else None
        one_core = None not in pinned and len(set(pinned)) == 1
        whole = one_core and all(auth_utilisation([f]) is not None for f in cell_files)      # every process: a recorded end, a finished job
        own["auth_utilisation"] = auth_utilisation(cell_files) if whole else None
        head, theirs = of_sources(kit, {"periodic"})
        diffs = compare(head or f"{prefix}.periodic.<no key of the cell>.", own, theirs)
        bad += diffs
        if own["cores"] is not None and head and f"-c{own['cores']}-" not in head:
            bad += 1
            print(f"DIFF {head}*: the cell has {own['cores']} cores, its name does not say -c{own['cores']}-")
        if own["cores"] is not None and own["cores"] < valid:      # fewer cores than processes: no model key of a file
            bad += sum(compare(h, {k: None for k in t if k.startswith("model_")}, t) for h, t in pairs)
        print(f"cell of {valid} partitions: releases {jobs}, misses {misses} = {own['miss_ratio'] * 100:.4f} % "
              f"[{own['miss_cp95_lo'] * 100:.4f}, {own['miss_cp95_hi'] * 100:.4f}]; keys compared {len(own)}, differences {diffs}")
    if not valid:
        print("no valid pair: no key was compared, nothing of this directory can be quoted")
    record_compared(analysis_dir, AGREED if valid and not bad else [])
    print("OWN-CHECK AGREES" if valid and not bad else "OWN-CHECK DISAGREES")
    sys.exit(0 if valid and not bad else 1)


if __name__ == "__main__":
    main()
