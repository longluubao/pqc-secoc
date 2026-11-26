"""Independent second reading of an E7 run directory (rate ladder), compared key by key with the toolkit.

usage: python3 -I throughput_compare.py <run_dir> <analysis_dir> <key_prefix>      (python3 -I throughput_compare.py --self-test)
Reads <run_dir>/throughput/throughput_tx*.csv and throughput_rx*.csv itself (the calibration run: <run_dir>/calibration/,
one step of one repetition): one row per second and host, cumulative counters (DATA_SCHEMA.md). Own rules, written from
the contract:
  window      every sample of a file, first to last (the sampler starts after the ramp)
  step        files are grouped by '# offered_pps=', '# rep=' and side (tx or rx in the file name); the partitions of a
              group ('# partition=') are added and the step's rate is the sum of their offered_pps
  offered     growth of pdus_done + growth of drops on the transmitter: every job released in the window
  delivered   growth of pdus_done on the receiver (an own figure, printed; the toolkit has no key for it)
  not delivered   offered - delivered, not below 0; share = not delivered / offered with the exact 95 % interval;
              only when both sides have the same number of samples (the same seconds of the stream)
  dropped at release   growth of the transmitter's drops column (not the footer's count, which includes the ramp)
  PDU/s       mean of the per-second rates: growth of pdus_done / growth of t_ns of each interval; the rates of
              partitions are added interval by interval
  processor time per second   growth of proc_cpu_ns / growth of t_ns over the whole window, per process; partitions
              are added. Processor time of the measured process as a share of one core, not board utilisation.
  per step    over its repetitions: their number (repetitions with a file of the step), mean, smallest and largest
              delivered PDU/s and share not delivered, mean processor time per second of each side
  send queue  of the transmitter, per connection (file), over every sample: the largest sendq_bytes; the least-squares
              slope of sendq_bytes on the time since the first sample, written out here; its one-sided 95 % lower bound,
              slope - t(0.95, n - 2) x standard error; growth = slope x the file's window, bound of the growth = lower
              bound x the file's window (0 for a queue that never changes). With partitions: the largest depth is the
              deepest connection's, the growths are added, the bound is the largest of the connections' bounds
  bytes per PDU   interface bytes sent in the window / PDUs sent; as it is queued: the same less 66 bytes of Ethernet,
              IPv4 and TCP header per packet sent. Wire rate: interface bytes sent x 8 / window; tx.rx_mbit_s: the
              same of the interface bytes the transmitter's host RECEIVED (if_rx_bytes). With partitions the
              PDUs are those sent by all partitions (plain reading of the definition). The toolkit forms a ratio of mean
              rates there instead, so for a repetition with several partitions tx.queued_bytes_per_pdu and
              tx.wire_bytes_per_pdu are NOT compared and not recorded as compared: both values are printed
  CONVENTIONS TAKEN FROM THE TOOLKIT (its throughput.py, _segment and _sum, read to settle what the definitions leave
              open for ladders with several partitions; nothing else of this reader comes from the toolkit's source):
              the largest depth of a repetition is the deepest single connection's, not the sum of the connections'
              depths; the interface counters are the host's and are read in the FIRST partition's window (wire rate
              and the bytes of the two sizes above)
  sustained   a repetition (CAMPAIGN.md, rulings of 2026-11-23 18:02): the queue is not growing and the share not
              delivered is at most 0.001; growing: the bound of the growth is at least one PDU as it is queued. Per step
              the number of sustained repetitions; saturation point: the highest rate such that in it and in every
              lower step every repetition is sustained (a repetition that cannot be judged ends the range)
  capture     a capture_<host>.txt beside the sampler files (calibration run), keys <prefix>.capture.<directory>.<host>.:
              frames_with_payload, tcp_payload_bytes, frame_bytes (the lines captured_frames_with_payload,
              tcp_payload_bytes, frame_bytes_as_captured), jobs_confirmed (the line '# jobs_confirmed='),
              frames_per_pdu = frames / jobs, frame_bytes_per_frame and tcp_payload_bytes_per_frame = bytes / frames.
              The counting was done by the driver; here the lines are read and the three ratios formed. A line that
              is missing, or a jobs_confirmed other than the footer of the periodic_tx*.csv beside it, is a difference
Validity, judged here from the schema: tcp_nodelay = 1 and a footer in the sampler file; on the transmitter also
tcp_connections_at_first_release = tcp_connections_at_end, and jobs_started = jobs_confirmed in the traffic log
beside it (periodic_tx<same suffix>.csv). A side that is invalid here must have no toolkit key.
NOT recomputed: /proc/stat figures, Student-t intervals, pooled loss, the lines without a retransmission, the receiver's
interface rates.
Exit 0 only if every repetition gave at least 12 compared keys (send-queue keys not counted) and nothing differs.
"""
import csv
import math
import os
import re
import site
import sys
from pathlib import Path
from statistics import fmean

if sys.flags.no_user_site:      # python3 -I hides the user site-packages, where numpy is installed on the measuring workstation
    site.addsitedir(site.getusersitepackages())
from scipy import optimize, stats as sps  # noqa: E402

COUNTERS = ("t_ns", "pdus_done", "drops", "proc_cpu_ns")
SIDE = ("pps_mean", "proc_cpu_share", "drops", "intervals", "window_s")
LOSS = ("offered_pdus", "lost_pdus", "loss_ratio", "loss_cp95_lo", "loss_cp95_hi", "dropped_pdus")
QUEUE = ("sendq_max_bytes", "sendq_growth_bytes", "sendq_growth_lo95_bytes", "queued_bytes_per_pdu", "wire_bytes_per_pdu", "wire_mbit_s", "rx_mbit_s")
HEADER_BYTES = 66       # Ethernet 14 + IPv4 20 + TCP 32, per packet sent (definition of queued_bytes_per_pdu)
LOSS_MAX = 0.001        # CAMPAIGN.md: largest share not delivered of a sustained repetition


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
    """({key: value} of the '# key=value' lines anywhere in the file, rows as dicts with the COUNTERS as int)."""
    meta, cols, rows = {}, None, []
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("#"):
            k, _, v = line[1:].strip().partition("=")
            meta[k] = v
        elif line.strip() and cols is None:
            cols = line.split(",")
        elif line.strip():
            rows.append({c: int(v) if c in COUNTERS else v for c, v in zip(cols, line.split(","))})
    return meta, rows


def cp95(k, n):
    """Exact two-sided 95 % interval of k out of n, by its definition: each bound is the share at which the binomial
    tail on the far side of k holds 2.5 %."""
    lo = 0.0 if k == 0 else optimize.brentq(lambda p: sps.binom.sf(k - 1, n, p) - 0.025, 0, 1, xtol=1e-15, rtol=1e-14)
    hi = 1.0 if k == n else optimize.brentq(lambda p: sps.binom.cdf(k, n, p) - 0.025, 0, 1, xtol=1e-15, rtol=1e-14)
    return lo, hi


def window(rows):
    """Of one sampler file: (growth of each counter from the first to the last sample, PDU/s of each interval,
    length of each interval in ns)."""
    rows = sorted(rows, key=lambda r: r["t_ns"])
    grown = {c: rows[-1][c] - rows[0][c] for c in COUNTERS}
    dts = [b["t_ns"] - a["t_ns"] for a, b in zip(rows, rows[1:])]
    rates = [(b["pdus_done"] - a["pdus_done"]) / (dt / 1e9) for a, b, dt in zip(rows, rows[1:], dts)]
    return grown, rates, dts


def side_numbers(parts):
    """{name: value} of one side of one repetition; `parts` are the window() results of its partitions."""
    n = min(len(rates) for _, rates, _ in parts)
    return {"pps_mean": fmean(sum(rates[i] for _, rates, _ in parts) for i in range(n)),
            "proc_cpu_share": sum(g["proc_cpu_ns"] / g["t_ns"] for g, _, _ in parts),
            "drops": sum(g["drops"] for g, _, _ in parts), "intervals": n,
            "window_s": min(sum(dts[:n]) for _, _, dts in parts) / 1e9}


def loss_numbers(tx, rx):
    """{name: value} of one repetition from the window() results of both sides, and the PDUs delivered; None each when
    a side is missing or the two sides do not cover the same samples."""
    if not tx or not rx or [len(r) for _, r, _ in tx] != [len(r) for _, r, _ in rx]:
        return dict.fromkeys(LOSS), None
    dropped, delivered = sum(g["drops"] for g, _, _ in tx), sum(g["pdus_done"] for g, _, _ in rx)
    offered = sum(g["pdus_done"] for g, _, _ in tx) + dropped
    lost = max(0, offered - delivered)
    lo, hi = cp95(lost, offered)
    return {"offered_pdus": offered, "lost_pdus": lost, "loss_ratio": lost / offered, "loss_cp95_lo": lo, "loss_cp95_hi": hi,
            "dropped_pdus": dropped}, delivered


def queue(rows):
    """Of one transmitter sampler file, every sample: the largest send-queue depth; the least-squares slope of the depth
    on the seconds since the first sample; its one-sided 95 % lower bound (None with fewer than three samples: no
    residual degree of freedom); the length of the window in s; and the growth of the interface's sent bytes, of those
    bytes less the header bytes of the packets sent, and of the PDUs sent."""
    rows = sorted(rows, key=lambda r: r["t_ns"])
    t = [(r["t_ns"] - rows[0]["t_ns"]) / 1e9 for r in rows]
    q = [int(r["sendq_bytes"]) for r in rows]
    grown = {c: int(rows[-1][c]) - int(rows[0][c]) for c in ("if_tx_bytes", "if_tx_packets", "if_rx_bytes", "pdus_done")}
    n, tm, qm = len(t), fmean(t), fmean(q)
    sxx = sum((x - tm) ** 2 for x in t)
    slope = sum((x - tm) * (y - qm) for x, y in zip(t, q)) / sxx
    sse = sum((y - qm - slope * (x - tm)) ** 2 for x, y in zip(t, q))
    lo = slope - sps.t.ppf(0.95, n - 2) * math.sqrt(sse / (n - 2) / sxx) if n > 2 else None
    return {"max": max(q), "slope": slope, "lo": lo, "span": t[-1], "wire": grown["if_tx_bytes"], "received": grown["if_rx_bytes"],
            "payload": grown["if_tx_bytes"] - HEADER_BYTES * grown["if_tx_packets"], "pdus": grown["pdus_done"]}


def queue_numbers(parts):
    """{name: value} of the transmitter's send queue and interface in one repetition; `parts` are the queue() results of
    its partitions in partition order. The rules are in the head of the file."""
    first = parts[0]
    wire, payload, pdus = first["wire"], first["payload"], sum(p["pdus"] for p in parts)
    bounds = [p["lo"] * p["span"] for p in parts if p["lo"] is not None]
    return {"sendq_max_bytes": max(p["max"] for p in parts), "sendq_growth_bytes": sum(p["slope"] * p["span"] for p in parts),
            "sendq_growth_lo95_bytes": max(bounds) if len(bounds) == len(parts) else None,
            "queued_bytes_per_pdu": payload / pdus if pdus else None,
            "wire_bytes_per_pdu": wire / pdus if pdus else None, "wire_mbit_s": first["wire"] * 8 / first["span"] / 1e6,
            "rx_mbit_s": first["received"] * 8 / first["span"] / 1e6}


def sustained(q, loss_ratio):
    """Verdict of one repetition: True when the send queue is not growing (the bound of its growth is below one PDU as it
    is queued) and the share not delivered is at most LOSS_MAX; None when it cannot be judged (a side, the bound or the
    size is missing). q: queue_numbers()."""
    size, bound = q["queued_bytes_per_pdu"], q["sendq_growth_lo95_bytes"]
    return None if None in (size, bound, loss_ratio) else bool(bound < size and loss_ratio <= LOSS_MAX)


def saturation(steps):
    """steps: {rate: [verdict of each repetition]}. The highest rate such that in it and in every lower step every
    repetition is sustained; None when the lowest step is not."""
    point = None
    for rate in sorted(steps):
        if not steps[rate] or not all(v is True for v in steps[rate]):
            break
        point = rate
    return point


def capture(text, confirmed):
    """({key part: value} of one capture_<host>.txt, its faults). confirmed: jobs_confirmed of the traffic log(s) beside it,
    or None without such a log."""
    line = dict(l.lstrip("# ").strip().partition("=")[::2] for l in text.splitlines() if "=" in l)
    names = {"frames_with_payload": "captured_frames_with_payload", "tcp_payload_bytes": "tcp_payload_bytes", "frame_bytes": "frame_bytes_as_captured",
             "jobs_confirmed": "jobs_confirmed"}
    faults = [f"no line {src}=<whole number>" for src in names.values() if not line.get(src, "").isdigit()]
    several = {l.partition("=")[2].strip() for l in text.splitlines() if l.lstrip("# ").startswith("jobs_confirmed=")}
    if len(several) > 1:
        faults.append(f"jobs_confirmed lines that differ: {sorted(several)}")
    if faults:
        return {}, faults
    k = {name: int(line[src]) for name, src in names.items()}
    if confirmed is not None and k["jobs_confirmed"] != confirmed:
        faults.append(f"jobs_confirmed={k['jobs_confirmed']}, the traffic log beside it has {confirmed}")
    k.update(frames_per_pdu=k["frames_with_payload"] / k["jobs_confirmed"] if k["jobs_confirmed"] else None,
             frame_bytes_per_frame=k["frame_bytes"] / k["frames_with_payload"] if k["frames_with_payload"] else None,
             tcp_payload_bytes_per_frame=k["tcp_payload_bytes"] / k["frames_with_payload"] if k["frames_with_payload"] else None)
    return k, faults


def invalid(meta, log_meta, side):
    """Reasons of DATA_SCHEMA.md why a sampler file is no result; [] for a valid file. log_meta: the traffic log beside."""
    why = [f"tcp_nodelay={meta.get('tcp_nodelay')}"] if meta.get("tcp_nodelay") != "1" else []
    why += ["no footer (interrupted)"] if "wall_s" not in meta else []
    if side == "tx":
        for src, a, b in ((meta, "tcp_connections_at_first_release", "tcp_connections_at_end"), (log_meta, "jobs_started", "jobs_confirmed")):
            if src.get(a) is None or src.get(a) != src.get(b):
                why.append(f"{a}={src.get(a)}, {b}={src.get(b)}")
    return why


def across(values, names=("mean", "min", "max")):
    """{name: value over the repetitions}; None each (the toolkit must not have the key) when no repetition has a value."""
    values = [v for v in values if v is not None]
    return {n: f(values) if values else None for n, f in (("mean", fmean), ("min", min), ("max", max)) if n in names}


def ladder_head(keys):
    """The head of a ladder's keys: what stands before the rate step of a key (<head>r<rate>. ...), when all step keys
    agree on it; else, as before, the common head of all keys up to its last dot. A toolkit key beside the ladder (a
    figure that is not under its configuration) then does not shorten the head."""
    heads = {m[1] for m in (re.match(r"(.+?\.)r\d+\.", k) for k in keys) if m}
    if len(heads) == 1:
        return heads.pop()
    head = os.path.commonprefix(list(keys))
    return head[:head.rfind(".") + 1]


def toolkit(analysis_dir, prefix):
    """(head of the ladder's keys, {key behind the head: value}) of numbers.csv, text rows left out; a key that is not
    under the head is not this reader's."""
    with open(Path(analysis_dir) / "numbers.csv", newline="") as f:
        mine = {r["key"]: r["value"] for r in csv.DictReader(f) if r["key"].startswith(prefix + ".throughput.") and r["unit"] != "text"}
    head = ladder_head(mine)
    return head, {k[len(head):]: v for k, v in mine.items() if k.startswith(head)}


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
    def sample(t, done, drops, cpu):
        return {"t_ns": t, "pdus_done": done, "drops": drops, "proc_cpu_ns": cpu}

    # intervals of 1 s and 2 s: the mean of the per-second rates is not PDUs / window, the processor share is growth / window
    tx = window([sample(3_000_000_000, 200, 7, 600_000_000), sample(0, 0, 0, 0), sample(1_000_000_000, 100, 0, 500_000_000)])
    assert tx[1] == [100.0, 50.0] and tx[0]["drops"] == 7 and tx[2] == [1_000_000_000, 2_000_000_000]
    s = side_numbers([tx])
    assert s["pps_mean"] == 75.0 and s["proc_cpu_share"] == 0.2 and s["intervals"] == 2 and s["window_s"] == 3.0 and s["drops"] == 7
    rx = window([sample(10, 50, 0, 0), sample(1_000_000_010, 140, 0, 1), sample(3_000_000_010, 240, 0, 2)])
    k, delivered = loss_numbers([tx], [rx])
    assert delivered == 190 and k["offered_pdus"] == 207 and k["lost_pdus"] == 17 and k["dropped_pdus"] == 7 and k["loss_ratio"] == 17 / 207
    more = window([sample(0, 0, 0, 0), sample(1_000_000_000, 150, 0, 0), sample(3_000_000_000, 300, 0, 0)])
    assert loss_numbers([tx], [more])[0]["lost_pdus"] == 0                               # more delivered than offered: not below 0
    assert loss_numbers([tx], [window([sample(0, 0, 0, 0), sample(5, 9, 0, 0)])])[0]["lost_pdus"] is None    # other seconds
    assert loss_numbers([tx], None)[0]["offered_pdus"] is None
    two = side_numbers([tx, more])                                                          # two partitions are added
    assert two["pps_mean"] == fmean([250.0, 125.0]) and two["proc_cpu_share"] == 0.2 and two["drops"] == 7
    assert loss_numbers([tx, tx], [rx, rx])[0]["offered_pdus"] == 414
    lo, hi = cp95(0, 2000)
    assert lo == 0 and math.isclose(hi, 1 - 0.025 ** (1 / 2000), rel_tol=1e-12)        # closed form without a loss
    lo, hi = cp95(3, 10)                                                               # table value of 3 out of 10
    assert abs(lo - 0.06674) < 5e-6 and abs(hi - 0.65245) < 5e-6
    assert across([1.0, None, 3.0]) == {"mean": 2.0, "min": 1.0, "max": 3.0} and across([None], ("mean",)) == {"mean": None}
    ladder = ["p.throughput.c1.r100.rep1.tx.pps_mean", "p.throughput.c1.r200.loss_ratio_mean", "p.throughput.c1.saturation_pps"]
    assert ladder_head(ladder) == "p.throughput.c1." and ladder_head(ladder + ["p.throughput.capture.frames"]) == "p.throughput.c1."   # a key beside the ladder
    assert ladder_head(ladder[2:]) == "p.throughput.c1." and ladder_head(["p.throughput.c1.r100.x", "p.throughput.c2.r100.x"]) == "p.throughput."
    # a capture by hand: 6 frames with 600 bytes of payload and 996 bytes as captured for 2 PDUs: 3 frames per PDU, 166 and 100 bytes per frame
    text = "captured_frames_with_payload=6\ntcp_payload_bytes=600\nframe_bytes_as_captured=996\n# jobs_confirmed=2\n# cpu_affinity=3\n"
    k, faults = capture(text, 2)
    assert faults == [] and k == {"frames_with_payload": 6, "tcp_payload_bytes": 600, "frame_bytes": 996, "jobs_confirmed": 2, "frames_per_pdu": 3.0,
                                  "frame_bytes_per_frame": 166.0, "tcp_payload_bytes_per_frame": 100.0}
    assert capture(text + "# jobs_confirmed=2\n", 2)[1] == [] and len(capture(text + "# jobs_confirmed=3\n", 2)[1]) == 1      # the line twice: the same value, or a fault
    assert len(capture(text, 3)[1]) == 1 and capture(text, None)[1] == [] and capture(text.replace("tcp_payload_bytes=600\n", ""), 2) == ({}, ["no line tcp_payload_bytes=<whole number>"])
    good = {"tcp_nodelay": "1", "wall_s": "1", "tcp_connections_at_first_release": "1", "tcp_connections_at_end": "1"}
    jobs = {"jobs_started": "9", "jobs_confirmed": "9"}
    assert invalid(good, jobs, "tx") == [] and invalid({"tcp_nodelay": "1", "wall_s": "1"}, {}, "rx") == []
    assert len(invalid(good, {}, "tx")) == 1 and len(invalid({**good, "tcp_connections_at_end": "2"}, {**jobs, "jobs_confirmed": "8"}, "tx")) == 2
    assert len(invalid({"tcp_nodelay": "0"}, {}, "rx")) == 2

    def depth(*qs, packets=3, size=1176, pdus=1):          # one sample per second; per second `packets` of `size` bytes, `pdus` PDUs
        return queue([{"t_ns": i * 1_000_000_000, "sendq_bytes": str(q), "if_tx_bytes": str(i * packets * size),
                       "if_tx_packets": str(i * packets), "if_rx_bytes": str(i * 125), "pdus_done": i * pdus} for i, q in enumerate(qs)])

    line = depth(5, 7, 9, 11)                                                              # an exact line: bound = slope
    assert line["max"] == 11 and line["slope"] == 2.0 and line["lo"] == 2.0 and line["span"] == 3.0
    hand = depth(0, 1, 1, 2)       # by hand: slope 3/5, residual sum 0.2, standard error sqrt(0.02); t(0.95, 2) = 0.9 / sqrt(0.095)
    assert math.isclose(hand["slope"], 0.6, rel_tol=1e-14) and math.isclose(hand["lo"], 0.6 - 0.9 / math.sqrt(0.095) * math.sqrt(0.02), rel_tol=1e-12)
    flat = depth(434, 434, 434)                                                            # a queue that never changes: bound 0
    assert flat["slope"] == 0.0 and flat["lo"] == 0.0 and depth(1, 2)["lo"] is None
    one = queue_numbers([line])                                   # 3 packets of 1176 bytes per PDU: 3528 on the wire, 3330 queued
    assert one["wire_bytes_per_pdu"] == 3528.0 and one["queued_bytes_per_pdu"] == 3330.0 and one["wire_mbit_s"] == 3528 * 8 / 1e6
    assert one["sendq_max_bytes"] == 11 and one["sendq_growth_bytes"] == 6.0 and one["sendq_growth_lo95_bytes"] == 6.0
    two = queue_numbers([flat, line])             # two connections: deepest, growths added, largest bound
    assert two["sendq_max_bytes"] == 434 and two["sendq_growth_bytes"] == 6.0 and two["sendq_growth_lo95_bytes"] == 6.0
    # the first connection's window (2 s): 7056 bytes in 6 packets, 6660 without the headers, over 2 + 3 PDUs of both
    assert two["wire_bytes_per_pdu"] == 1411.2 and two["queued_bytes_per_pdu"] == 1332.0 and two["wire_mbit_s"] == one["wire_mbit_s"]
    assert queue_numbers([depth(1, 2)])["sendq_growth_lo95_bytes"] is None and queue_numbers([depth(0, 0, 0, pdus=0)])["queued_bytes_per_pdu"] is None
    assert queue_numbers([depth(0, 0, 0, size=60)])["queued_bytes_per_pdu"] == -18.0      # packets smaller than their headers: plain arithmetic, no special case

    def host(byte_counts, packets, pdus):          # samples at 0, 1 and 3 s: unequal intervals
        return queue([{"t_ns": t * 1_000_000_000, "sendq_bytes": "0", "if_tx_bytes": str(b), "if_tx_packets": str(k), "if_rx_bytes": str(b // 4),
                       "pdus_done": d} for t, b, k, d in zip((0, 1, 3), byte_counts, packets, pdus)])
    # two partitions with different byte counts. By hand, from the FIRST partition's window: 12000 bytes in 30 packets over
    # 3 s, 10020 without the headers; PDUs of both partitions 4 + 6 = 10: 1200 bytes per PDU on the wire, 1002 queued,
    # 12000 x 8 / 3 = 0.032 Mbit/s. (The second partition's window would give 2100; a mean of the per-second rates
    # 0.030 Mbit/s; a ratio of mean rates 4000 / 3.25 = 1230.8.)
    uneven = queue_numbers([host((0, 3000, 12000), (0, 10, 30), (0, 2, 4)), host((0, 9000, 21000), (0, 20, 60), (0, 1, 6))])
    assert uneven["wire_bytes_per_pdu"] == 1200.0 and uneven["queued_bytes_per_pdu"] == 1002.0 and uneven["wire_mbit_s"] == 0.032
    assert one["rx_mbit_s"] == 0.001 and uneven["rx_mbit_s"] == 0.008      # 125 bytes received per second; 3000 bytes in the first partition's 3 s
    q = {"queued_bytes_per_pdu": 3330.0, "sendq_growth_lo95_bytes": 3329.9}
    assert sustained(q, 0.001) is True and sustained(q, 0.0010001) is False            # the share not delivered may be exactly 0.001
    assert sustained({**q, "sendq_growth_lo95_bytes": 3330.0}, 0.0) is False               # a bound of exactly one PDU is growing
    assert sustained(q, None) is None and sustained(dict.fromkeys(QUEUE), 0.0) is None
    assert sustained({"queued_bytes_per_pdu": 6.0, "sendq_growth_lo95_bytes": two["sendq_growth_lo95_bytes"]}, 0.0) is False   # one of two grows
    ok = [True] * 5
    assert saturation({100: ok, 200: ok, 300: [True, False, True], 400: ok}) == 200     # a sustained step above a failed one does not count
    assert saturation({100: ok, 200: [True, None]}) == 100 and saturation({100: [False], 200: ok}) is None and saturation({100: []}) is None
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
    files = sorted((run_dir / "throughput").glob("throughput_[tr]x*.csv")) or sorted((run_dir / "calibration").glob("throughput_[tr]x*.csv"))
    if not files:
        raise SystemExit(f"{run_dir}: no throughput/ or calibration/ with throughput_tx*.csv or throughput_rx*.csv")
    sendq = {}      # (offered_pps of one partition, repetition) -> [(partition, queue())] of the valid transmitter files
    groups = {}     # (offered_pps of one partition, repetition, side) -> [(partition, window() or None for an invalid file, footer drops)]
    for p in files:
        side = p.name.split("_")[1][:2]
        meta, rows = read(p)
        log = p.with_name(p.name.replace("throughput_", "periodic_", 1))
        log_meta = read(log)[0] if log.exists() else {}
        why = invalid(meta, log_meta, side)
        if why:
            print(f"{p.name}: INVALID by the own rules: " + "; ".join(why))
        groups.setdefault((int(meta["offered_pps"]), int(meta["rep"]), side), []).append(
            (int(meta.get("partition", 0)), None if why else window(rows), log_meta.get("jobs_dropped_at_release")))
        if side == "tx" and not why:
            sendq.setdefault((int(meta["offered_pps"]), int(meta["rep"])), []).append((int(meta.get("partition", 0)), queue(rows)))
    reps = {}       # (rate of the step, repetition) -> {side: [window() per partition] or None}
    txq = {}        # (rate of the step, repetition) -> [queue() per partition]
    for (each, rep, side), members in groups.items():
        members.sort(key=lambda m: m[0])
        if side == "tx":
            txq[(each * len(members), rep)] = [q for _, q in sorted(sendq.get((each, rep), []), key=lambda m: m[0])]
        reps.setdefault((each * len(members), rep), {})[side] = (None if any(w is None for _, w, _ in members) else [w for _, w, _ in members],
                                                                 [d for _, _, d in members])
    head, theirs = toolkit(analysis_dir, prefix)
    head = head or prefix + ".throughput.<no key>."
    bad, short, own_all, verdicts = 0, 0, {}, {}      # verdicts: rate -> [sustained() of each repetition]
    for (rate, rep), sides in sorted(reps.items()):
        tx, rx = (sides.get(s, (None, []))[0] for s in ("tx", "rx"))
        own, delivered = loss_numbers(tx, rx)
        for side, parts in (("tx", tx), ("rx", rx)):
            own.update({f"{side}.{k}": v for k, v in (side_numbers(parts) if parts else dict.fromkeys(SIDE)).items()})
        judged = sum(v is not None for v in own.values())      # the 12-key rule counts the keys above, not the send queue's
        q = queue_numbers(txq[(rate, rep)]) if tx else dict.fromkeys(QUEUE)
        verdict = sustained(q, own["loss_ratio"])
        verdicts.setdefault(rate, []).append(verdict)
        # several partitions: the two sizes per PDU are own figures by the plain reading and are not compared (head of the file)
        apart = ("queued_bytes_per_pdu", "wire_bytes_per_pdu") if tx and len(txq[(rate, rep)]) > 1 else ()
        own.update({f"tx.{k}": v for k, v in q.items() if k not in apart})
        own = {f"r{rate}.rep{rep}.{k}": v for k, v in own.items()}
        own_all.update(own)
        if apart:
            print(f"{rate} PDU/s rep {rep}: bytes per PDU with {len(txq[(rate, rep)])} partitions, not compared: the toolkit forms a ratio of mean rates: "
                  + "; ".join(f"{k} own {q[k]}, toolkit {theirs.get(f'r{rate}.rep{rep}.tx.{k}', 'n/a')}" for k in apart))
        diffs, compared = compare(head, own, theirs), sum(v is not None for v in own.values())
        bad, short = bad + diffs, short + (judged < 12)
        o = {k.split(".", 2)[2]: "n/a" if v is None else v for k, v in own.items()}
        pct = "n/a" if o["loss_ratio"] == "n/a" else f"{o['loss_ratio'] * 100:.4f} % [{o['loss_cp95_lo'] * 100:.4f}, {o['loss_cp95_hi'] * 100:.4f}]"
        print(f"{rate} PDU/s rep {rep}: offered {o['offered_pdus']}, delivered {'n/a' if delivered is None else delivered}, not delivered "
              f"{o['lost_pdus']} = {pct}, dropped at release {o['dropped_pdus']} (footer of the traffic log, ramp included: "
              f"{'+'.join(str(d) for d in sides.get('tx', (None, ['n/a']))[1])}); delivered PDU/s {o['rx.pps_mean']}; processor time per second "
              f"tx {o['tx.proc_cpu_share']}, rx {o['rx.proc_cpu_share']}; window s tx {o['tx.window_s']}, rx {o['rx.window_s']}; "
              f"send queue largest {o['tx.sendq_max_bytes']}, bound of its growth {o['tx.sendq_growth_lo95_bytes']} against "
              f"{'n/a' if q['queued_bytes_per_pdu'] is None else q['queued_bytes_per_pdu']} bytes per PDU: {'not judged' if verdict is None else 'sustained' if verdict else 'not sustained'}; "
              f"keys compared {compared}, differences {diffs}" + ("" if judged >= 12 else "  FEWER THAN 12 KEYS: not a judged repetition"))
    for rate in sorted({rate for rate, _ in reps}):
        mine = [rep for r, rep in reps if r == rate]
        own = {"n_reps": len(mine), "sustained_reps": sum(v is True for v in verdicts[rate])}
        for name, key, names in (("delivered_pps", "rx.pps_mean", ("mean", "min", "max")), ("loss_ratio", "loss_ratio", ("mean", "min", "max")),
                                 ("tx_proc_cpu_share", "tx.proc_cpu_share", ("mean",)), ("rx_proc_cpu_share", "rx.proc_cpu_share", ("mean",)),
                                 *((n, "tx." + n, ("mean", "min", "max")) for n in ("sendq_max_bytes", "sendq_growth_bytes", "wire_mbit_s"))):
            own.update({f"{name}_{n}": v for n, v in across([own_all[f"r{rate}.rep{rep}.{key}"] for rep in mine], names).items()})
        own = {f"r{rate}.{k}": v for k, v in own.items()}
        own_all.update(own)
        diffs = compare(head, own, theirs)
        bad += diffs
        own = {k.split(".", 1)[1]: v for k, v in own.items()}
        print(f"{rate} PDU/s over {len(mine)} repetition(s): delivered PDU/s mean {own['delivered_pps_mean']}, share not delivered "
              f"mean {own['loss_ratio_mean']}, largest {own['loss_ratio_max']}; sustained {own['sustained_reps']} of {len(mine)}; "
              f"keys compared {sum(v is not None for v in own.values())}, differences {diffs}")
    own = {"saturation_pps": saturation(verdicts)}
    own_all.update(own)
    diffs = compare(head, own, theirs)
    bad += diffs
    print(f"saturation point: own {own['saturation_pps']} PDU/s, toolkit {theirs.get('saturation_pps', 'n/a')}; keys compared "
          f"{sum(v is not None for v in own.values())}, differences {diffs}")
    print(f"toolkit keys of the ladder not recomputed here: {len(theirs) - len([k for k in theirs if k in own_all])} (/proc/stat, "
          f"Student-t intervals, pooled loss, lines without a retransmission, mean depth and slope of the send queue, receiver interface rates; "
          f"also the two sizes per PDU of repetitions with several partitions, printed above as own figures)")
    with open(Path(analysis_dir) / "numbers.csv", newline="") as f:      # the captures beside the sampler files
        caught = {r["key"]: r["value"] for r in csv.DictReader(f) if r["key"].startswith(prefix + ".capture.") and r["unit"] != "text"}
    done = set()
    for p in sorted(files[0].parent.glob("capture_*.txt")):
        logs = [read(q)[0].get("jobs_confirmed", "") for q in sorted(p.parent.glob("periodic_tx*.csv"))]
        own, faults = capture(p.read_text(), sum(map(int, logs)) if logs and all(v.isdigit() for v in logs) else None)
        chead = f"{prefix}.capture.{p.parent.name}.{p.stem[len('capture_'):]}."
        done |= {chead + k for k in own}
        diffs = compare(chead, own, {k[len(chead):]: v for k, v in caught.items() if k.startswith(chead)}) + len(faults)
        bad += diffs
        for fault in faults:
            print(f"DIFF {chead}*: {p.name}: {fault}")
        print(f"{p.name}: " + (f"{own['frames_with_payload']} frames with payload for {own['jobs_confirmed']} PDUs: {own['frames_per_pdu']} frames per PDU, "
                               f"{own['frame_bytes_per_frame']} bytes per frame as captured, {own['tcp_payload_bytes_per_frame']} of payload; " if own else "")
              + f"keys compared {sum(v is not None for v in own.values())}, differences {diffs}")
    for key in sorted(set(caught) - done):
        print(f"NOT COMPARED {key}: toolkit {caught[key]} (no capture file of that name beside the sampler files, or a key this reader does not recompute)")
    ok = not bad and not short
    record_compared(analysis_dir, AGREED if ok else [])
    print("OWN-CHECK AGREES" if ok else "OWN-CHECK DISAGREES")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
