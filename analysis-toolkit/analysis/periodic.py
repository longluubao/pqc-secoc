"""periodic_tx.csv / periodic_rx.csv: periodic streams and deadline analysis."""
import numpy as np

from analysis import stats

WINDOWS = (10, 100, 1000)
HEADER = ("period_ns", "deadline_ns", "streams", "cores", "profile", "scheduler", "payload_bytes", "commit", "host")
# 'both': one signature stream and one MAC stream in one file (DATA_SCHEMA.md, 'Profile both in the periodic files'); the
# line stream_profiles then names the profile of each stream index
PROFILES, SCHEDULERS = ("mldsa65", "mac", "both"), ("other", "fifo", "fifo_isolated")
# optional '# key=value' lines of a harness file: an enumeration, or int for a non-negative integer
OPTIONAL = {"mainfunction": ("cyclic", "event"), "mf_period_us": int, "phase": ("sync", "staggered"), "partition": int,
            "partitions": int, "rep": int}
ID_KEYS = ("mainfunction", "mf_period_us", "phase", "partition")  # the optional keys that are part of a configuration id
NOT_RECORDED = "not recorded"
RESULTS = ("ok", "freshness_fail", "auth_fail", "framing_fail")
NO_CLOCK = "not reported (no clock relation)"
CLOCK_CONVENTION = "offset_ns = Rx clock - Tx clock, t_ns on the Rx clock"  # DATA_SCHEMA.md, clock_offset.csv
RTT_FLOOR_FACTOR = 100


def optional(meta, keys=(*ID_KEYS, "partitions")):
    """The optional header keys of OPTIONAL that the file has, validated; an absent key stays absent."""
    out = {}
    for k in keys:
        if k in meta:
            v, allowed = meta[k], OPTIONAL[k]
            if allowed is int:
                if not (v.isascii() and v.isdigit()):
                    raise ValueError(f"header {k}={v!r} is not a non-negative integer")
                v = int(v)
            elif v not in allowed:
                raise ValueError(f"header {k}={v!r} is not one of {list(allowed)}")
            out[k] = v
    return out


def not_recorded(meta, cols, allowed):
    """Columns named by the file's '# not_recorded=<column>[,<column>]' line: stages the writing binary
    has no timestamp for (the gateway application before its timestamp hooks), written as 0 in every
    row. Those zeros are not missed stages. Only the columns in `allowed` can be analysed that way;
    a named column that carries a value contradicts the line. Both are errors."""
    names = [c.strip() for c in meta.get("not_recorded", "").split(",") if c.strip()]
    for c in names:
        if c not in allowed:
            raise ValueError(f"not_recorded={c}: only {', '.join(allowed)} can be analysed as not recorded")
        if cols[c].any():
            raise ValueError(f"not_recorded names {c}, but {int(np.count_nonzero(cols[c]))} row(s) carry a value")
    return names


def consistency(meta, cols):
    """Reasons why the job counts in a sender's footer are not those of its rows. The harness writes both from the same
    jobs: jobs_released = rows, jobs_started = rows with a start_ns, jobs_confirmed = rows with a send_done_ns,
    jobs_dropped_at_release = rows without a start_ns (a dropped release keeps its row, with zeros). Only the lines the
    footer has are compared, and none whose column the file declares not recorded. A line that is no count is reported
    here for the two counts the jobs rule (csvio.jobs) does not judge."""
    silent = {c.strip() for c in meta.get("not_recorded", "").split(",")}
    n, started = int(cols["start_ns"].size), int(np.count_nonzero(cols["start_ns"]))
    out = []
    for key, found, what, column in (("jobs_released", n, "rows", None), ("jobs_started", started, "rows with a start_ns", "start_ns"),
                                     ("jobs_confirmed", int(np.count_nonzero(cols["send_done_ns"])), "rows with a send_done_ns",
                                      "send_done_ns"),
                                     ("jobs_dropped_at_release", n - started, "rows without a start_ns", "start_ns")):
        v = meta.get(key)
        if v is None or column in silent:
            continue
        if not (v.isascii() and v.isdigit()):
            out += [] if key in ("jobs_started", "jobs_confirmed") else [f"{key}={v} in the footer is not a count"]
        elif int(v) != found:
            out.append(f"{key}={v} in the footer, but the file has {found} {what}")
    return out


def config(meta):
    """The mandatory '# key=value' block of a Tx file, validated, with its integers converted, plus
    the optional keys (OPTIONAL) the file has. A missing mandatory key is an error; other keys are
    ignored."""
    missing = [k for k in HEADER if k not in meta]
    if missing:
        raise ValueError(f"missing header key(s) {missing}: the Tx file must start with '# key=value' lines for "
                         + ", ".join(HEADER))
    c = {k: meta[k] for k in HEADER}
    for k in ("period_ns", "deadline_ns", "streams", "cores", "payload_bytes"):
        if not (c[k].isascii() and c[k].isdigit()) or (int(c[k]) == 0 and k != "payload_bytes"):
            raise ValueError(f"header {k}={c[k]!r} is not a positive integer")
        c[k] = int(c[k])
    for k, allowed in (("profile", PROFILES), ("scheduler", SCHEDULERS)):
        if c[k] not in allowed:
            raise ValueError(f"header {k}={c[k]!r} is not one of {list(allowed)}")
    named = meta.get("stream_profiles")
    if named is None and c["profile"] == "both":
        raise ValueError("header profile=both needs the line stream_profiles, one profile per stream index")
    if named is not None:
        each = named.split(",")
        if len(each) != c["streams"] or any(p not in PROFILES[:2] for p in each):
            raise ValueError(f"header stream_profiles={named!r} does not name one profile ({' or '.join(PROFILES[:2])}) for each "
                             f"of the {c['streams']} stream(s)")
        if c["profile"] != "both" and set(each) != {c["profile"]}:
            raise ValueError(f"header stream_profiles={named!r} contradicts profile={c['profile']}")
        if c["profile"] == "both":
            c["stream_profiles"] = each
    return {**c, **optional(meta)}


def response_ns(cols):
    """Response time send_done_ns - release_ns of the jobs that finished (send_done_ns != 0)."""
    done = cols["send_done_ns"] > 0
    return (cols["send_done_ns"] - cols["release_ns"])[done]


def service_ns(cols):
    """In-service time send_done_ns - start_ns (authentication plus send, no queueing) of the jobs
    that finished."""
    done = cols["send_done_ns"] > 0
    return (cols["send_done_ns"] - cols["start_ns"])[done]


def release_offsets_ns(cols, period):
    """Release phase of each stream: release_ns of its first job modulo the period (ns)."""
    return np.array([int(cols["release_ns"][cols["stream"] == s].min()) % period
                     for s in dict.fromkeys(cols["stream"].tolist())])


def analyse_tx(meta, cols):
    """One configuration (one Tx file).

    Every released job has one row; a stage it did not reach is written as 0. A job misses its
    deadline when it did not finish (send_done_ns == 0) or send_done_ns - release_ns > deadline_ns
    (strict). Reports the miss ratio over all released jobs with its exact Clopper-Pearson and its
    Wilson 95% interval (both assume independent jobs; misses come in bursts, so either is too
    narrow under overload), per-stream longest run of consecutive
    misses and largest number of misses in any window of k consecutive jobs (k in WINDOWS; the
    configuration-level values are the worst stream), and describe() in microseconds of response
    time (send_done - release), queueing delay (start - release), authentication time (auth_done -
    start) and service time (send_done - start).

    Each time statistic covers only the jobs that reached the stages it needs (its n says how
    many), so with unfinished jobs the response-time percentiles are censored and read low; the
    miss ratio is not affected. seq must be contiguous from 0 in every stream.

    A file whose header says '# not_recorded=auth_done_ns' has no authentication timestamps (see
    not_recorded()): auth_us is then None, 'not_recorded' names the column, and everything else is
    computed as usual. Without that line an auth_done_ns of 0 in a finished job is an error.
    """
    cfg = config(meta)
    rel, start, auth, done = (cols[k] for k in ("release_ns", "start_ns", "auth_done_ns", "send_done_ns"))
    if rel.size == 0:
        raise ValueError("no jobs")
    missing = not_recorded(meta, cols, ("auth_done_ns",))
    before_send = start if missing else auth  # the last stage on file before send_done
    bad = np.flatnonzero((rel == 0) | ((start > 0) & (start < rel)) | ((auth > 0) & ((start == 0) | (auth < start)))
                         | ((done > 0) & ((before_send == 0) | (done < before_send))))
    if bad.size:
        i = int(bad[0])
        raise ValueError(f"data row {i + 1} (stream {cols['stream'][i]}, seq {int(cols['seq'][i])}): timestamps must "
                         "satisfy 0 < release_ns <= start_ns <= auth_done_ns <= send_done_ns, with 0 only for a stage "
                         "the job did not reach and every stage after it"
                         + (" (auth_done_ns is declared not recorded)" if missing else
                            "; auth_done_ns is 0 in every row: a binary without that timestamp must say "
                            "'# not_recorded=auth_done_ns'" if not auth.any() else ""))
    miss = (done == 0) | (done - rel > cfg["deadline_ns"])
    per_stream = []
    for s in dict.fromkeys(cols["stream"].tolist()):
        sel = np.flatnonzero(cols["stream"] == s)
        order = np.argsort(cols["seq"][sel], kind="stable")
        seq, m = cols["seq"][sel][order], miss[sel][order]
        wrong = np.flatnonzero(seq != np.arange(seq.size))
        if wrong.size:
            raise ValueError(f"stream {s}: seq is not contiguous from 0 (expected {int(wrong[0])}, found "
                             f"{int(seq[wrong[0]])}); every released job must have exactly one row")
        per_stream.append({"stream": s, "jobs": int(seq.size), "misses": int(m.sum()),
                           "longest_miss_run": stats.longest_run(m),
                           "max_misses_in_window": {str(k): stats.max_in_window(m, k) for k in WINDOWS}})
    if cfg["streams"] != len(per_stream):
        raise ValueError(f"header says streams={cfg['streams']} but {len(per_stream)} stream(s) have rows")
    n, k = int(miss.size), int(miss.sum())
    worst = {}
    for w in map(str, WINDOWS):
        vals = [ps["max_misses_in_window"][w] for ps in per_stream if ps["max_misses_in_window"][w] is not None]
        worst[w] = max(vals) if vals else None
    cfg["period_us"], cfg["deadline_us"] = cfg.pop("period_ns") / 1e3, cfg.pop("deadline_ns") / 1e3
    return {**cfg, "cpu_affinity": meta.get("cpu_affinity"),  # where the process was pinned: for the cores of a cell
            "not_recorded": missing, "jobs": n, "unfinished": int((done == 0).sum()),
            "not_started": int((start == 0).sum()),
            "misses": k, "miss_ratio": k / n, "miss_cp95": list(stats.clopper_pearson_interval(k, n)),
            "miss_wilson95": list(stats.wilson_interval(k, n)),
            "longest_miss_run": max(ps["longest_miss_run"] for ps in per_stream), "max_misses_in_window": worst,
            "response_us": stats.describe(response_ns(cols) / 1e3),
            "queueing_us": stats.describe((start - rel)[start > 0] / 1e3),
            "auth_us": None if missing else stats.describe((auth - start)[auth > 0] / 1e3),
            # measured: the share of the file's time span (first release to last send) with a job in the authentication
            "auth_utilisation": None if missing or not done.any() else
            covered_ns(start[auth > 0], auth[auth > 0]) / int(done.max() - rel.min()),
            "service_us": stats.describe(service_ns(cols) / 1e3), "per_stream": per_stream}


def covered_ns(start, end):
    """The time covered by at least one of the intervals [start, end] (ns, whole numbers). The jobs of the streams of
    one sender process start together in a cycle and are authenticated one after the other, so their intervals from
    start_ns to auth_done_ns overlap: the lengths add up to more than the time the process spent authenticating."""
    order = np.argsort(start, kind="stable")
    a, b = start[order], end[order]
    reached = np.maximum.accumulate(b)  # how far the intervals before and including each one reach
    return int(np.clip(b - np.maximum(a, np.r_[a[:1], reached[:-1]]), 0, None).sum())


def shared_utilisation(files):
    """The measured utilisation of one core by the authentication of several sender processes pinned to it (`files`:
    the columns of each process's file; the stamps of processes on one board are on one clock): the time covered by
    the union of the intervals [start_ns, auth_done_ns] of all rows with auth_done_ns > 0 of all files, over the time
    from the smallest release_ns to the largest send_done_ns over all files. None when no row has an authentication
    time or no job was sent."""
    start, end = (np.concatenate([c[k][c["auth_done_ns"] > 0] for c in files]) for k in ("start_ns", "auth_done_ns"))
    last, first = max(int(c["send_done_ns"].max()) for c in files), min(int(c["release_ns"].min()) for c in files)
    return covered_ns(start, end) / (last - first) if start.size and last > first else None


def combine(parts):
    """A cell measured as several partitions: `parts` are the analyse_tx() results of its sender
    processes side by side, each with its own streams and queue: independent gateway processes,
    each with its own core, or sender processes that share a core. Releases and misses are added over the
    partitions' streams: miss ratio = misses / jobs, with its exact Clopper-Pearson 95% interval
    (exact for independent jobs, too narrow when misses come in bursts). This is a combination of
    processes that ran side by side, not one system with a shared queue: streams are
    the sum, and nothing is said about runs or windows of misses across partitions. cores is the
    number of DISTINCT cores of the processes, the distinct values of their cpu_affinity line
    (E9_SPEC.md, H4: several sender processes may be pinned to one core); where a file has no such
    line, the sum of the files' cores, as before the line existed.

    'no_retrans' is the sensitivity figure of the transport rules, present when a partition's file
    gives tcp_total_retrans_in_window: the same combination over the partitions whose count is 0,
    with how many are left out for a count above 0 and for a count that was not given (unknown is
    not 0). It stands beside the figure over all partitions, never instead of it; with no partition
    left its figures are None."""
    def over(some):
        jobs, misses = sum(p["jobs"] for p in some), sum(p["misses"] for p in some)
        return {"streams": sum(p["streams"] for p in some), "jobs": jobs, "misses": misses, "miss_ratio": misses / jobs,
                "miss_cp95": list(stats.clopper_pearson_interval(misses, jobs))}

    pinned = [p.get("cpu_affinity") for p in parts]
    cores = len(set(pinned)) if all(pinned) else sum(p["cores"] for p in parts)
    out = {"partitions": len(parts), "cores": cores, **over(parts)}
    counts = [(p.get("transport") or {}).get("tcp_total_retrans_in_window") for p in parts]
    if any(c is not None for c in counts):
        quiet = [p for p, c in zip(parts, counts) if c == 0]
        out["no_retrans"] = {"partitions": len(quiet), "left_out_retransmitted": sum(1 for c in counts if c),
                             "left_out_unknown": counts.count(None),
                             **(over(quiet) if quiet else dict.fromkeys(("streams", "jobs", "misses", "miss_ratio", "miss_cp95")))}
    return out


def rx_on_tx_clock(ts, clock):
    """Rx-clock timestamps expressed on the Tx clock: ts - offset(ts), with offset_ns = Rx clock -
    Tx clock probed at Rx-clock time t_ns (DATA_SCHEMA.md). The offset is interpolated linearly
    between probes; outside the probed span the nearest probe is used, so clock drift there is not
    corrected."""
    order = np.argsort(clock["t_ns"], kind="stable")
    return ts - np.interp(ts, clock["t_ns"][order], clock["offset_ns"][order])


def _latency(tx, rx, tx_key, rx_key, clock):
    """One-way latency (rx_done on the Tx clock - send_done) and end-to-end response (deliver on the
    Tx clock - release) of each delivered job, taken at its first ok arrival. Each value is
    uncertain by about half the probe round-trip time. A fastest PDU that arrives before it was
    sent, or more than RTT_FLOOR_FACTOR probe round trips after, means the clock relation is wrong
    (typically the sign of offset_ns) and is an error."""
    if clock["t_ns"].size == 0 or clock["rtt_ns"].max() == 0:
        raise ValueError("clock_offset: need at least one probe with rtt_ns > 0 (it is the uncertainty of the offset)")
    order = np.argsort(tx_key)
    job = order[np.minimum(np.searchsorted(tx_key[order], rx_key), tx_key.size - 1)]  # candidate Tx row per Rx row
    use = np.flatnonzero((rx["result"] == "ok") & (tx_key[job] == rx_key) & (tx["send_done_ns"][job] > 0))
    use = use[np.argsort(rx["rx_done_ns"][use], kind="stable")]
    use = use[np.unique(rx_key[use], return_index=True)[1]]  # first ok arrival of each job
    job = job[use]
    one_way = rx_on_tx_clock(rx["rx_done_ns"][use], clock) - tx["send_done_ns"][job]
    rtt = float(clock["rtt_ns"].max())
    if one_way.size and one_way.min() < -rtt:
        raise ValueError(f"clock relation: a PDU was received {-one_way.min():.0f} ns before it was sent, beyond the "
                         f"largest probe round trip ({rtt:.0f} ns); expected {CLOCK_CONVENTION}")
    if one_way.size and one_way.min() > RTT_FLOOR_FACTOR * rtt:
        raise ValueError(f"clock relation: implausible, the fastest PDU took {one_way.min():.0f} ns, over "
                         f"{RTT_FLOOR_FACTOR} probe round trips ({rtt:.0f} ns); expected {CLOCK_CONVENTION}")
    arrived, t = rx["rx_done_ns"][use], clock["t_ns"]
    return {"convention": CLOCK_CONVENTION, "clock_samples": int(t.size),
            "clock_rtt_median_us": float(np.median(clock["rtt_ns"])) / 1e3, "clock_rtt_max_us": rtt / 1e3,
            "outside_clock_span": int(((arrived < t.min()) | (arrived > t.max())).sum()),
            "one_way_us": stats.describe(one_way / 1e3),
            "end_to_end_us": stats.describe((rx_on_tx_clock(rx["deliver_ns"][use], clock) - tx["release_ns"][job]) / 1e3)}


def analyse_rx(tx, rx, clock=None, meta=None):
    """Receiver side of one configuration, matched to the Tx jobs by (stream, seq). `meta` is the
    comment-line dict of the Rx file (only its not_recorded line is used).

    delivered = Tx jobs with at least one Rx row whose result is 'ok'; delivery_ratio = delivered /
    Tx jobs; lost = Tx jobs with no Rx row at all; duplicates = Rx rows beyond the first for a
    (stream, seq); out_of_order = Rx rows, taken per stream in rx_done_ns order, whose seq is lower
    than an earlier one; rx_not_in_tx = Rx rows whose (stream, seq) the sender never logged.
    A Tx job that never finished has no Rx row and so counts as lost.

    A framing_fail row is bytes that could not be attributed to a PDU: by the schema its stream and
    seq are -1, and no other row may carry -1. It is counted in by_result only and takes no part in
    the matching, the per-stream counts or the order statistics.

    Times in microseconds, describe() each: over the 'ok' rows the verification time (verify_done_ns
    - rx_done_ns) and the delivery time (deliver_ns - rx_done_ns: complete reception to hand-over to
    the application, verification included); per failure class (freshness_fail, auth_fail) the
    reject-decision time (verify_done_ns - rx_done_ns).

    Cross-host latency needs a clock relation (the columns of clock_offset.csv, see _latency);
    without one 'latency' is None and 'latency_note' says so.

    A file whose header says '# not_recorded=rx_done_ns' has no reception timestamps (see
    not_recorded()). The counts are unaffected; arrival order (out_of_order) is then the order of
    verify_done_ns, the accept/reject decisions; and nothing that is measured from reception is
    reported: verify_us and deliver_us are None, reject_us is empty and there is no latency.
    shortcut: end-to-end latency (deliver - release) would not need rx_done_ns but is not reported
    either; add it if a result ever depends on gateway files without the hook.
    """
    res, rxd, ver, dlv = rx["result"], rx["rx_done_ns"], rx["verify_done_ns"], rx["deliver_ns"]
    ok, framing = res == "ok", res == "framing_fail"
    rejected = ~ok & ~framing
    missing = not_recorded(meta or {}, rx, ("rx_done_ns",))
    first = ~framing & (ver == 0) if missing else rxd == 0  # the first timestamp a row must have
    bad = np.flatnonzero(first | (ok & ((ver < rxd) | (dlv < ver))) | (rejected & ((ver < rxd) | (dlv != 0)))
                         | (framing & ((ver != 0) | (dlv != 0))))
    if bad.size:
        i = int(bad[0])
        raise ValueError(f"data row {i + 1} (stream {rx['stream'][i]}, seq {int(rx['seq'][i])}, result {res[i]}): every row "
                         "needs 0 < rx_done_ns; ok: rx_done_ns <= verify_done_ns <= deliver_ns; freshness_fail and "
                         "auth_fail: rx_done_ns <= verify_done_ns and deliver_ns = 0; framing_fail: verify_done_ns = "
                         "deliver_ns = 0" + (" (rx_done_ns is declared not recorded: 0 < verify_done_ns instead)"
                                             if missing else "; rx_done_ns is 0 in every row: a binary without that "
                                             "timestamp must say '# not_recorded=rx_done_ns'" if not rxd.any() else ""))
    unnamed = (rx["seq"] < 0) | (rx["stream"] == "-1")
    bad = np.flatnonzero((framing & ((rx["seq"] != -1) | (rx["stream"] != "-1"))) | (~framing & unnamed))
    if bad.size:
        i = int(bad[0])
        raise ValueError(f"data row {i + 1} (stream {rx['stream'][i]}, seq {int(rx['seq'][i])}, result {res[i]}): a "
                         "framing_fail row has stream = seq = -1, and only a framing_fail row does")
    by_result = {r: int(np.count_nonzero(res == r)) for r in RESULTS}
    times = {"verify_us": None, "deliver_us": None, "reject_us": {}} if missing else {
        "verify_us": stats.describe((ver - rxd)[ok] / 1e3), "deliver_us": stats.describe((dlv - rxd)[ok] / 1e3),
        "reject_us": {r: stats.describe((ver - rxd)[res == r] / 1e3) for r in ("freshness_fail", "auth_fail")}}
    n_rows = int(res.size)
    rx = {k: v[~framing] for k, v in rx.items()}  # from here on only rows that name a job
    ok, arrival = rx["result"] == "ok", rx["verify_done_ns" if missing else "rx_done_ns"]
    labels, first, inv = np.unique(np.concatenate([tx["stream"], rx["stream"]]), return_index=True, return_inverse=True)
    appearance = np.argsort(first)  # streams in order of first appearance, not sorted as text
    rank = np.empty(labels.size, dtype=np.int64)
    rank[appearance] = np.arange(labels.size)
    stream = rank[inv]
    tx_stream, rx_stream = stream[:tx["stream"].size], stream[tx["stream"].size:]
    base = int(max(tx["seq"].max(initial=0), rx["seq"].max(initial=0))) + 1
    tx_key, rx_key = tx_stream * base + tx["seq"], rx_stream * base + rx["seq"]
    got, got_ok = np.isin(tx_key, rx_key), np.isin(tx_key, rx_key[ok])
    ooo, per_stream = 0, []
    for s, label in enumerate(labels[appearance].tolist()):
        mine, sent = rx_stream == s, tx_stream == s
        seq = rx["seq"][mine][np.argsort(arrival[mine], kind="stable")]
        if seq.size > 1:
            ooo += int(np.count_nonzero(seq[1:] < np.maximum.accumulate(seq)[:-1]))
        per_stream.append({"stream": label, "tx_jobs": int(sent.sum()), "delivered": int(got_ok[sent].sum()),
                           "lost": int((~got[sent]).sum()),
                           "by_result": {r: int(np.count_nonzero(rx["result"][mine] == r)) for r in RESULTS[:3]}})
    return {"tx_jobs": int(tx_key.size), "rx_rows": n_rows, "delivered": int(got_ok.sum()),
            "delivery_ratio": float(got_ok.mean()), "lost": int((~got).sum()),
            "duplicates": int(rx_key.size - np.unique(rx_key).size), "out_of_order": ooo,
            "rx_not_in_tx": int((~np.isin(rx_key, tx_key)).sum()), "by_result": by_result, **times,
            "per_stream": per_stream, "not_recorded": missing,
            "latency": _latency(tx, rx, tx_key, rx_key, clock) if clock is not None and not missing else None,
            "latency_note": NO_CLOCK if clock is None else "not reported (rx_done_ns not recorded)" if missing else None}
