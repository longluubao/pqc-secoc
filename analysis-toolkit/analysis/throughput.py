"""throughput.csv: sustained open-loop load, one sample per second; one file per host per rate step."""
import numpy as np
from scipy import stats as sps

from analysis import csvio, periodic, stats

COUNTERS = ("pdus_done", "cpu_busy_jiffies", "cpu_total_jiffies", "if_tx_bytes", "if_tx_packets",
            "if_rx_bytes", "if_rx_packets", "drops")
HEADER = ("tx_host", "rx_host", "profile", "cores", "commit")
LOSS_MAX_PER_MILLE = 1  # a repetition sustains its rate when at most this many PDUs per 1000 offered are not delivered
# what the loss ratio of a ladder is (DATA_SCHEMA.md, 'Jobs given up': an end-to-end figure, never PDUs lost by the stack
# or by the network) and, beside it, what the transmitter alone dropped
NOT_DELIVERED = ("not delivered inside the window: releases the generator dropped at a full queue, PDUs sent and not yet "
                 "delivered when the window ends, or PDUs the receiver did not deliver")
DROPPED = ("releases the generator dropped at a full queue inside the window (the tx host's sampler column drops, added over "
           "the partitions; a file with a job given up is invalid, so in an analysed harness file every drop is such a release; "
           "the footer's jobs_dropped_at_release counts the whole run, ramp included, and is not used); counted on the "
           "transmitter alone, so it is no subset of the PDUs not delivered: it exceeds them when the receiver delivers, "
           "inside the window, PDUs that were sent before it")
LOSS_MAX = LOSS_MAX_PER_MILLE / 1000
HEADER_BYTES = 66  # in front of the payload of every packet the tx host sends: Ethernet 14, IPv4 20, TCP with timestamps 32
# when a send queue counts as growing (CAMPAIGN.md, ruling of 2026-11-23), and which size of a PDU the rule uses
GROWING = ("growing: the one-sided 95% lower bound of the queue's least-squares slope, times the length of the window, is at "
           "least one PDU as it is queued; with several partitions each connection is judged, and the queue grows if any does")
QUEUED_PDU = ("the bytes one PDU adds to the send queue, from the step's own tx file: the bytes the tx host's interface sent "
              f"in the window less {HEADER_BYTES} bytes of Ethernet, IPv4 and TCP header per packet sent, over the PDUs sent "
              "(the interface counters are the host's, so over the PDUs of all partitions); right on a wired link, not on "
              "the loopback interface")
NO_SIZE = "not judged: the tx file's interface counters leave no payload, so the size of one queued PDU cannot be formed"
# what proc_cpu_share is, in the words of DATA_SCHEMA.md
PROC_CPU = ("processor time of the harness process per second of wall time in the steady window, as a share of one core "
            "(growth of proc_cpu_ns over growth of t_ns, all threads of the process); it is the processor time of the "
            "process, not board utilisation: work the kernel does in other contexts is not in it, and interrupt time that "
            "interrupts the process is charged to it on these kernels")
# why no CPU figure of the sampler is a manuscript number (they stay in numbers.csv)
CPU_NOT_QUOTED = "tick-based CPU accounting of these kernels misses work that starts on a timer; not a utilisation to quote"


def config(meta):
    """The mandatory '# key=value' block of a throughput file, validated, plus the optional keys
    partition (index of the gateway process), partitions (their number), rep (repetition number),
    mainfunction and mf_period_us when the file has them. A missing mandatory key is an error."""
    missing = [k for k in HEADER if k not in meta]
    if missing:
        raise ValueError(f"missing header key(s) {missing}: the file must start with '# key=value' lines for "
                         + ", ".join(HEADER))
    c = {k: meta[k] for k in HEADER}
    if c["tx_host"] == c["rx_host"]:
        raise ValueError(f"header tx_host and rx_host are both {c['tx_host']!r}; the role of a host would be ambiguous")
    if not (c["cores"].isascii() and c["cores"].isdigit()) or int(c["cores"]) == 0:
        raise ValueError(f"header cores={c['cores']!r} is not a positive integer")
    c["cores"] = int(c["cores"])
    return {**c, **periodic.optional(meta, ("partition", "partitions", "rep", "mainfunction", "mf_period_us"))}


def _cpu_steps(cols):
    """From each sample of the file to the next (by t_ns): t_ns of the later sample, growth of the
    busy jiffies, and by how many ticks that exceeds the growth of the total jiffies."""
    order = np.argsort(cols["t_ns"], kind="stable")
    busy, total = (np.diff(cols[k][order]) for k in ("cpu_busy_jiffies", "cpu_total_jiffies"))
    return cols["t_ns"][order][1:], busy, busy - total


def consistency(cols):
    """Reasons why the two CPU counters of a file contradict themselves; any of them makes the file
    invalid. total = busy + idle + iowait, each in whole ticks, read from one /proc/stat line. From
    one sample to the next (every sample of the file) the busy jiffies must not go backwards, and
    they must not grow by 2 or more ticks more than the total jiffies (when busy stands still that
    is idle plus iowait going backwards, and the reason says so). One tick more is rounding:
    the kernel's split between idle and iowait is provisional, so the two truncated parts of their
    growing sum can read one tick less than before (see one_tick_clamps)."""
    t, busy, excess = _cpu_steps(cols)
    reasons = []
    still = (busy == 0) & (excess >= 2)  # busy stands still and the total drops: idle + iowait = total - busy went back
    back = sorted({int(excess[still].min()), int(excess[still].max())}) if still.any() else []
    for bad, what in ((busy < 0, "cpu_busy_jiffies went backwards"),
                      ((busy > 0) & (excess >= 2), "the busy jiffies grew by 2 or more ticks more than the total jiffies"),
                      (still, f"idle plus iowait went backwards by {' to '.join(map(str, back))} ticks")):
        at = np.flatnonzero(bad)
        if at.size:
            reasons.append(f"{at.size} sample step(s) in which {what} (first: t_ns {int(t[at[0]])})")
    return reasons


def one_tick_clamps(cols):
    """Sample steps of the file in which the busy jiffies grew by exactly one tick more than the
    total jiffies. Such a step is rounding, not a broken counter: it counts as fully busy (its total
    growth is raised to its busy growth), and it is counted so that a file with many is visible."""
    return int(np.count_nonzero(_cpu_steps(cols)[2] == 1))


def _queued_bytes(role, payload, pdus):
    """QUEUED_PDU: `payload` bytes sent for `pdus` PDUs (both totals of the window, or both per second). None for a
    receiver and when the counters leave no payload. The one place that says where the size comes from."""
    return payload / pdus if role == "tx" and pdus and payload > 0 else None


def _judge_queue(row, members):
    """GROWING, on the row of one step and host and on the rows of its partitions (`members`), each connection against the
    size of the step. None, not judged, where there is no size."""
    size = row["queued_bytes_per_pdu"]
    for r in (*(m for m, _ in members), row):
        r.update(queued_bytes_per_pdu=size,
                 sendq_growing=None if size is None else bool(r["sendq_growth_lower95_bytes"] >= size))


def _segment(name, cfg, cols, trim):
    """Steady-state figures of one file: one host (one gateway process of it) at one offered rate.
    All rates are counter differences over time on that host's own clock; nothing is compared across
    hosts here. Returns the row and, for summing partitions, the per-interval PDU rates and totals."""
    hosts, rates = sorted(set(cols["host"].tolist())), sorted(set(cols["offered_pps"].tolist()))
    if len(hosts) != 1 or len(rates) != 1:
        raise ValueError(f"{name}: a throughput file holds one host at one offered rate, found hosts {hosts} and "
                         f"rates {rates}")
    host, offered = hosts[0], float(rates[0])
    if host not in (cfg["tx_host"], cfg["rx_host"]):
        raise ValueError(f"{name}: host {host!r} is neither tx_host {cfg['tx_host']!r} nor rx_host {cfg['rx_host']!r}")
    role = "tx" if host == cfg["tx_host"] else "rx"
    n = cols["t_ns"].size
    if n < 2 * trim + 3:
        raise ValueError(f"{name}: {n} samples, need at least {2 * trim + 3} to drop {trim} at each end "
                         "(lower --trim for short dry runs)")
    idx = np.argsort(cols["t_ns"], kind="stable")[trim:n - trim]
    t = cols["t_ns"][idx]
    dt = np.diff(t) / 1e9
    if np.any(dt <= 0):
        raise ValueError(f"{name}: t_ns has repeated values")
    d = {k: np.diff(cols[k][idx]) for k in COUNTERS}
    for k, v in d.items():
        if k != "cpu_total_jiffies" and np.any(v < 0):  # the total is judged against the busy jiffies, below
            raise ValueError(f"{name}: cumulative counter {k} went backwards")
    if np.any(d["cpu_busy_jiffies"] - d["cpu_total_jiffies"] >= 2):  # make_tables lists such a file as invalid before this
        raise ValueError(f"{name}: the busy jiffies grew by 2 or more ticks more than the total jiffies in a sample step")
    d["cpu_total_jiffies"] = np.maximum(d["cpu_total_jiffies"], d["cpu_busy_jiffies"])  # one tick more: fully busy
    span = float(t[-1] - t[0]) / 1e9
    proc = None  # a 12-column file (written before 2026-11-23) has no processor time of the process
    if "proc_cpu_ns" in cols:
        grown = np.diff(cols["proc_cpu_ns"][idx])
        if np.any(grown < 0):
            raise ValueError(f"{name}: cumulative counter proc_cpu_ns went backwards")
        proc = float(grown.sum()) / float(t[-1] - t[0])
    tot = {k: int(v.sum()) for k, v in d.items()}
    sent, received = tot["if_tx_bytes"], tot["if_rx_bytes"]
    if (sent < received) if role == "tx" else (sent > received):  # cross-check of the header against the wire
        raise ValueError(f"{name}: the header makes {host!r} the {role} host, but its interface sent {sent} and "
                         f"received {received} bytes in the steady-state window")
    rates = d["pdus_done"] / dt
    pps_mean, pps_lo, pps_hi = stats.mean_ci(rates)
    q = cols["sendq_bytes"][idx]
    fit = sps.linregress((t - t[0]) / 1e9, q)
    slope_lo = float(fit.slope - sps.t.ppf(0.95, q.size - 2) * fit.stderr) if q.size > 2 else float(fit.slope)
    attempted = tot["pdus_done"] + tot["drops"]
    wire = sent if role == "tx" else received
    payload = sent - HEADER_BYTES * tot["if_tx_packets"]
    return {"file": name, "host": host, "role": role, "partition": cfg.get("partition"), "partitions": 1,
            "offered_pps": offered, "intervals": int(dt.size), "window_s": span,
            "pps_mean": pps_mean, "pps_ci95": [pps_lo, pps_hi],
            "cpu_util": tot["cpu_busy_jiffies"] / tot["cpu_total_jiffies"] if tot["cpu_total_jiffies"] else None,
            "cpu_one_tick_clamps": one_tick_clamps(cols), "cpu_steps": n - 1, "proc_cpu_share": proc,
            # the window counts of the transmitter's connection (csvio.transport_counts); none for a receiver
            **{k: (cfg.get("transport") or {}).get(k) if role == "tx" else None for k in csvio.TRANSPORT_COUNTS},
            "tx_mbit_s": sent * 8 / span / 1e6, "rx_mbit_s": received * 8 / span / 1e6,
            "wire_mbit_s": wire * 8 / span / 1e6, "wire_bytes_per_pdu": wire / tot["pdus_done"] if tot["pdus_done"] else None,
            "sendq_mean_bytes": float(q.mean()), "sendq_max_bytes": int(q.max()),
            "sendq_slope_bytes_per_s": float(fit.slope), "sendq_slope_lower95": slope_lo,
            "sendq_growth_bytes": float(fit.slope) * span,  # the fitted slope over the window
            # a queue whose depth never changes has slope 0 and no residual: it did not grow (linregress has no error for it)
            "sendq_growth_lower95_bytes": slope_lo * span if np.ptp(q) else 0.0, "queued_bytes_per_pdu": _queued_bytes(role, payload, tot["pdus_done"]),
            "sendq_growing": None,  # judged against the size of the step, which the partitions share (_judge_queue)
            "drops": tot["drops"], "drop_ratio": tot["drops"] / attempted if attempted else None}, \
        {"rates": rates, "dt": dt, "busy": tot["cpu_busy_jiffies"], "total": tot["cpu_total_jiffies"], "done": tot["pdus_done"],
         "drops": tot["drops"], "samples": n, "payload_per_s": payload / span}


def _sum(members):
    """One rate step on one host as the sum of its partitions (gateway processes that each offer a
    share of the rate on their own core and TCP connection). `members` is [(row, extra)] in partition
    order.

    PDUs/s: the partitions' per-second rates are added interval by interval, aligned by position
    from the start of each steady-state window (the processes are started together), over the number
    of intervals the shortest partition has; mean and Student-t 95% CI of those sums. CPU: busy /
    total jiffies summed over the partitions' cores. Drops and loss ratio: sums. Send queue: the mean
    depths add up, the maximum is the deepest single connection, the slope is the sum of the slopes
    (no confidence bound is derived for it); the bound of the growth over the window is the largest
    of the partitions' bounds, the figure the verdict compares (_judge_queue).
    The interface counters are the host's, not the process's: wire rates are those of the first
    partition's window and are never added; bytes per PDU = wire bytes/s / summed PDUs/s, and
    likewise the queued bytes per PDU (QUEUED_PDU).
    """
    rows, extra = [m[0] for m in members], [m[1] for m in members]
    n = min(e["rates"].size for e in extra)
    pps_mean, pps_lo, pps_hi = stats.mean_ci(sum(e["rates"][:n] for e in extra))
    first, total = rows[0], sum(e["total"] for e in extra)
    drops, done = sum(r["drops"] for r in rows), sum(e["done"] for e in extra)
    return {**first, "file": " + ".join(r["file"] for r in rows), "partition": None, "partitions": len(rows),
            "offered_pps": sum(r["offered_pps"] for r in rows), "intervals": n,
            "window_s": min(float(e["dt"][:n].sum()) for e in extra), "pps_mean": pps_mean, "pps_ci95": [pps_lo, pps_hi],
            "cpu_util": sum(e["busy"] for e in extra) / total if total else None,
            # each partition is its own process: their shares of a core add up; none if a file has no such column
            "proc_cpu_share": None if any(r["proc_cpu_share"] is None for r in rows) else sum(r["proc_cpu_share"] for r in rows),
            "cpu_one_tick_clamps": sum(r["cpu_one_tick_clamps"] for r in rows), "cpu_steps": sum(r["cpu_steps"] for r in rows),
            **{k: None if any(r[k] is None for r in rows) else sum(r[k] for r in rows) for k in csvio.TRANSPORT_COUNTS},
            "wire_bytes_per_pdu": first["wire_mbit_s"] * 1e6 / 8 / pps_mean if pps_mean else None,
            "sendq_mean_bytes": sum(r["sendq_mean_bytes"] for r in rows),
            "sendq_max_bytes": max(r["sendq_max_bytes"] for r in rows),
            "sendq_slope_bytes_per_s": sum(r["sendq_slope_bytes_per_s"] for r in rows), "sendq_slope_lower95": None,
            "sendq_growth_bytes": sum(r["sendq_growth_bytes"] for r in rows),  # each connection's slope over its own window
            "sendq_growth_lower95_bytes": max(r["sendq_growth_lower95_bytes"] for r in rows),
            "queued_bytes_per_pdu": _queued_bytes(first["role"], extra[0]["payload_per_s"], pps_mean),
            "drops": drops, "drop_ratio": drops / (done + drops) if done + drops else None}


def _across(values, proportion=False):
    """One value per repetition: their number, mean, minimum, maximum and the Student-t 95% interval
    of the mean (None, None for a single repetition). None when no repetition has the value.
    The interval of a mean knows no range: for a `proportion` (a loss ratio, the utilisation of the
    pinned cores) its ends are clamped to [0, 1]."""
    values = [float(v) for v in values if v is not None]
    if not values:
        return None
    mean, lo, hi = stats.mean_ci(values)
    if proportion and lo is not None:
        lo, hi = max(0.0, lo), min(1.0, hi)
    return {"n": len(values), "mean": mean, "min": min(values), "max": max(values), "t95": [lo, hi]}


def _repetition(rep, tx, rx):
    """One repetition of one rate step: `tx` and `rx` are (summed row, [(row, extra) per partition])
    or None when that host's files are missing, were left out as invalid, or lack a partition.

    Loss, from the cumulative counters of both hosts over the same sample indices (the samplers of
    the two hosts start with the first PDU after the ramp and tick once per second, so equal indices
    are equal moments of the PDU stream): offered_pdus = pdus_done + drops of the generator in the
    steady-state window (every PDU it released); lost_pdus = offered - pdus_done of the receiver,
    not below 0, each added over the partitions: the PDUs NOT_DELIVERED. It is an end-to-end count,
    not PDUs lost by the stack or by the network. dropped_pdus stands beside it: DROPPED (lost_pdus
    is clamped at 0 and nets PDUs in flight at both ends of the window, dropped_pdus does neither).
    loss_ratio = lost / offered with its exact two-sided Clopper-Pearson 95% interval
    (exact for independent PDUs; they come in bursts, so it is too narrow under overload). A tx and
    rx file with different numbers of samples cannot be compared: the repetition is then not
    judged, and no other estimator is used.

    sustained: the send queue is not growing on the tx host (GROWING) and 1000 * lost_pdus <=
    offered_pdus (LOSS_MAX, compared in whole PDUs). A repetition that fails on the loss is not
    sustained; one that passes it with a queue that could not be judged (NO_SIZE) is not judged.
    """
    r = {"rep": rep, "files": [side[0]["file"] for side in (tx, rx) if side],
         "delivered_pps": rx[0]["pps_mean"] if rx else None, "sendq_growing": tx[0]["sendq_growing"] if tx else None,
         **{k: tx[0][k] if tx else None for k in ("sendq_growth_lower95_bytes", "queued_bytes_per_pdu")},
         "offered_pdus": None, "lost_pdus": None, "dropped_pdus": None, "loss_ratio": None, "loss_cp95": None, "sustained": None,
         "note": None}
    if not (tx and rx):
        r["note"] = "not judged: the " + " and ".join(w for w, side in (("tx", tx), ("rx", rx)) if not side) + \
                    (" files are" if not (tx or rx) else " file is") + " missing, invalid or incomplete"
        return r
    ragged = [(t["samples"], x["samples"]) for (_, t), (_, x) in zip(tx[1], rx[1]) if t["samples"] != x["samples"]]
    if ragged:
        r["note"] = f"not judged: the tx and rx files have different numbers of samples {ragged[0]}"
        return r
    sent, dropped, delivered = (sum(e[k] for _, e in side[1]) for side, k in ((tx, "done"), (tx, "drops"), (rx, "done")))
    offered, lost = sent + dropped, max(0, dropped + sent - delivered)
    r.update(offered_pdus=offered, lost_pdus=lost, dropped_pdus=dropped, loss_ratio=lost / offered if offered else None,
             loss_cp95=list(stats.clopper_pearson_interval(lost, offered)) if offered else None)
    if not (offered > 0 and LOSS_MAX_PER_MILLE * offered >= 1000 * lost) or r["sendq_growing"]:
        r["sustained"] = False
    elif r["sendq_growing"] is None:
        r["note"] = NO_SIZE
    else:
        r["sustained"] = True
    return r


def _step(off, of_step, reps):
    """One rate step over the repetitions `reps`: every repetition on its own (_repetition), the
    figures across them (_across) and the step's verdict. With no repetition the step is not
    judged."""
    per_rep = [_repetition(rep, of_step.get(rep, {}).get("tx"), of_step.get(rep, {}).get("rx")) for rep in reps]
    row = {(rep, role): side[0] for rep, both in of_step.items() for role, side in both.items() if rep in reps}
    verdicts = [r["sustained"] for r in per_rep]
    growing = [r["sendq_growing"] for r in per_rep if r["sendq_growing"] is not None]
    across = {"delivered_pps": _across(r["delivered_pps"] for r in per_rep),
              "loss_ratio": _across((r["loss_ratio"] for r in per_rep), proportion=True),
              # what the transmitter alone dropped at release, as a share of the offered PDUs, of the same judged repetitions
              "tx_drop_ratio": _across((r["dropped_pdus"] / r["offered_pdus"] for r in per_rep if r["offered_pdus"]), proportion=True),
              **{f"{role}_cpu_util": _across((row[rep, role]["cpu_util"] for rep in reps if (rep, role) in row), proportion=True)
                 for role in ("tx", "rx")},
              **{f"{role}_proc_cpu_share": _across(row[rep, role]["proc_cpu_share"] for rep in reps if (rep, role) in row)
                 for role in ("tx", "rx")},  # not a proportion (several threads, summed partitions): no clamp
              **{k: _across(row[rep, "tx"][k] for rep in reps if (rep, "tx") in row)
                 for k in ("wire_mbit_s", "sendq_mean_bytes", "sendq_max_bytes", "sendq_slope_bytes_per_s", "sendq_growth_bytes")}}
    counted = [r for r in per_rep if r["offered_pdus"]]
    lost, offered = sum(r["lost_pdus"] for r in counted), sum(r["offered_pdus"] for r in counted)
    pooled = {"reps": len(counted), "lost_pdus": lost, "offered_pdus": offered, "loss_ratio": lost / offered,
              "loss_cp95": list(stats.clopper_pearson_interval(lost, offered))} if counted else None
    return {"offered_pps": off, "n_reps": len(reps), "judged_reps": sum(v is not None for v in verdicts),
            "sustained_reps": sum(v is True for v in verdicts),
            "sustained": False if False in verdicts else None if None in verdicts or not verdicts else True,
            "delivered_pps": across["delivered_pps"]["mean"] if across["delivered_pps"] else None,
            "sendq_growing": any(growing) if growing else None, "reps": per_rep, "across": across,
            "pooled_loss": pooled}


def _range(steps):
    """(saturation point, the step that ends the sustained range, sustained steps above it) of the
    steps in ascending offered rate: the highest rate such that it and every lower step are
    sustained; the first step that is not sustained or not judged ends the range."""
    saturation, ended_at, non_monotone = None, None, []
    for s in steps:
        if s["sustained"] is not True:
            ended_at = s["offered_pps"] if ended_at is None else ended_at
        elif ended_at is None:
            saturation = s["offered_pps"]
        else:
            non_monotone.append(s["offered_pps"])
    return saturation, ended_at, non_monotone


RETRANS = "tcp_total_retrans_in_window"
NO_RETRANS = ("the repetitions whose transmitter files all report tcp_total_retrans_in_window = 0; a repetition with a "
              "count above 0, or with a count that was not given, is left out; a repetition without a valid transmitter file "
              "stays, not judged as before; a step with no repetition left is not judged and ends the sustained range")


def _no_retrans(sides, reps):
    """The sensitivity line: the ladder's delivery figures a second time, over NO_RETRANS. It is
    never a replacement of the figures over all repetitions, and a retransmission never makes a
    file invalid. 'files_known' is the number of transmitter files that give the count; with none,
    nothing can be said and the caller shows no second line."""
    steps, left_out, files = [], 0, {"retransmitted": 0, "unknown": 0, "none": 0}
    for off in sorted(sides):
        state = {}
        for rep in reps:
            tx = sides[off].get(rep, {}).get("tx")
            # a repetition without its transmitter file (missing, invalid) is kept: it cannot be judged in either line,
            # and leaving it out would turn 'not judged' into a verdict for a reason that is no retransmission
            counts = [r[RETRANS] for r, _ in tx[1]] if tx else []
            for c in counts:
                files["unknown" if c is None else "retransmitted" if c else "none"] += 1
            state[rep] = "retransmitted" if any(counts) else "unknown" if None in counts else "none"
        kept = [rep for rep in reps if state[rep] == "none"]
        left_out += len(reps) - len(kept)
        steps.append({**_step(off, sides[off], kept), "kept_reps": kept, "left_out": {rep: w for rep, w in state.items() if w != "none"}})
    saturation, ended_at, non_monotone = _range(steps)
    return {"criterion": NO_RETRANS, "reps_left_out": left_out, "files_with_retrans": files["retransmitted"],
            "files_unknown": files["unknown"], "files_known": files["retransmitted"] + files["none"],
            "saturation_pps": saturation, "range_ended_at": ended_at, "non_monotone": non_monotone, "steps": steps}


def analyse(files, trim=0):
    """One ladder: `files` is a list of (name, config, cols), all with the same config() apart from
    the partition index and the repetition number ('rep', from the file's header or its name).

    Per file (one host, one offered rate), over the steady-state window (every sample of the file:
    the harness starts sampling after the ramp; `trim` drops that many samples at each end and is 0
    unless asked for, so that no verdict depends on it): PDUs/s (mean and Student-t 95% CI over the per-interval rates of pdus_done),
    CPU utilisation (busy / total jiffies over the window), interface Mbit/s, on-wire bytes per PDU
    in the host's data direction, send-queue mean and maximum, and drop ratio = drops / (pdus_done +
    drops) on that host alone.

    The role (tx or rx) comes from the header; the interface counters are only a cross-check that
    raises when they disagree with it. The send queue is called growing when the one-sided 95% lower
    bound of its least-squares slope, times the length of the window, is at least one PDU as it is
    queued (GROWING, QUEUED_PDU; ordinary regression errors, autocorrelation ignored, so the bound
    errs toward 'growing'). A growth below one PDU is 'not growing': a queue that holds a single
    PDU in its last sample has a lower bound above zero and has not grown.

    Partitions: a multi-core run is one file pair per gateway process, told apart by '# partition='
    (bench_net writes partition=0 also for a single process). The partitions that offer the same
    rate form one step, whose offered rate is the sum of theirs; 'rows' holds one row per
    repetition, step and host, the sum over its partitions (_sum; with one partition the file's own
    row), 'parts' the per-file rows when there is more than one partition, 'partitions' their number
    and 'cores' the header's cores (per process) times that number. The number of partitions is the
    '# partitions=' line when the files have one; otherwise it is the count of indices found, which
    must be 0..N-1 without a gap (a run whose last partition is missing on both hosts in every step
    cannot be seen then). Where a host lacks a partition its row is left out and listed in
    'incomplete'.

    Repetitions: the repetition is the unit of replication. Every repetition of a step is analysed
    on its own (_repetition: loss ratio and whether it sustained the rate); the 1-second samples of
    different repetitions are never pooled. Per step, 'across' gives for delivered PDUs/s, loss
    ratio, share dropped at release, CPU of each host, the tx host's wire rate and its send-queue mean, maximum and slope the
    mean over the repetitions with its Student-t 95% interval, the minimum and the maximum.
    A step is sustained only if every repetition of the ladder sustained it; it is not sustained as
    soon as one repetition did not; otherwise (a repetition that could not be judged: a missing or
    incomplete host, files of different length) it is not judged. 'pooled_loss' of a step is
    secondary: the PDUs not delivered and offered of its judged repetitions added up, with the exact interval
    of that proportion, which ignores the variation between repetitions.

    Saturation point: the highest offered rate such that it and every lower step of the ladder are
    sustained. The first step that is not sustained or not judged ends the sustained range
    ('range_ended_at'); sustained steps above it do not count and are listed as 'non_monotone'.
    Files of one ladder either all carry a repetition number or none does; two files for the same
    host, rate, repetition and partition are an error.

    'no_retrans' (in 'saturation') is the sensitivity line of the transport rules: the same step
    figures, verdicts and saturation point over the repetitions without a retransmitted segment
    (_no_retrans), next to the ones over all repetitions, never instead of them.
    """
    segs = []
    for name, cfg, cols in files:
        row, extra = _segment(name, cfg, cols, trim)
        segs.append(({**row, "rep": cfg.get("rep")}, extra))
    for key, what in (("partition", "a '# partition=' line"), ("rep", "a repetition number")):
        if len({r[key] is None for r, _ in segs}) > 1:
            raise ValueError(f"some files of the ladder have {what} and some do not")
    groups = {}  # (repetition, rate offered by one partition, role) -> partition -> (row, extra)
    for seg in segs:
        r = seg[0]
        first = groups.setdefault((r["rep"], r["offered_pps"], r["role"]), {}).setdefault(r["partition"], seg)[0]
        if first is not r:
            where = ", ".join(f"{word} {r[key]}" for key, word in (("rep", "repetition"), ("partition", "partition"))
                              if r[key] is not None)
            raise ValueError(f"{first['file']} and {r['file']} are both the {r['role']} host at {r['offered_pps']:g} pps"
                             + (f" ({where})" if where else "") + "; a repetition needs its own '# rep=' line or a file "
                             "label rep<k>")
    ladder = sorted({r["partition"] for r, _ in segs}, key=lambda p: -1 if p is None else p)
    announced = files[0][1].get("partitions")
    if announced is not None:
        beyond = [p for p in ladder if p is None or p >= announced]
        if beyond or announced < 1:
            raise ValueError(f"partition {beyond[0] if beyond else None} in a ladder of partitions={announced}")
        ladder = list(range(announced))
    elif ladder != [None] and ladder != list(range(len(ladder))):
        raise ValueError(f"partitions {ladder} of the ladder are not 0..{len(ladder) - 1}: the files of a partition are "
                         "missing")
    reps = sorted({r["rep"] for r, _ in segs}, key=lambda k: -1 if k is None else k)
    rows, incomplete, sides = [], [], {}  # sides: offered rate of the step -> repetition -> role -> (row, members)
    for (rep, each, role), found in groups.items():
        offered = each * len(ladder)
        of_step = sides.setdefault(offered, {})
        if sorted(found, key=lambda p: -1 if p is None else p) != ladder:
            incomplete.append({"offered_pps": offered, "rep": rep, "role": role, "partitions": sorted(found), "expected": ladder})
            continue
        members = [found[p] for p in ladder]
        row = members[0][0] if len(members) == 1 else _sum(members)
        _judge_queue(row, members)
        rows.append(row)
        of_step.setdefault(rep, {})[role] = (row, members)
    steps = [_step(off, sides[off], reps) for off in sorted(sides)]
    saturation, ended_at, non_monotone = _range(steps)
    return {"trim": trim, "reps": reps, "rows": rows, "parts": [r for r, _ in segs] if len(ladder) > 1 else [],
            "partitions": len(ladder), "cores": files[0][1]["cores"] * len(ladder), "incomplete": incomplete,
            "saturation": {"criterion": f"in every repetition the tx-host send queue is not growing and the loss ratio is "
                                        f"at most {LOSS_MAX:g}; {GROWING}; one PDU as it is queued: {QUEUED_PDU}; "
                                        "a step with a repetition that cannot be judged is not judged; "
                                        "saturation point: the highest rate such that it and every lower step are sustained",
                           "loss_max": LOSS_MAX, "saturation_pps": saturation, "range_ended_at": ended_at,
                           "non_monotone": non_monotone, "steps": steps, "no_retrans": _no_retrans(sides, reps)}}
