"""End-to-end latency across the two boards (E9_SPEC.md, 'Interface details').

The two boards' monotonic clocks are not synchronised. Their offset is measured during the run by a two-way exchange
(periodic/clock_probe.csv, written by the probe client on board A: seq, t1_ns, t2_ns, t3_ns, t4_ns; t1 and t4 on clock
A, t2 and t3 on clock B), and the times a PDU has on board B are brought to clock A with it.

    offset of an exchange   theta = ((t2 - t1) - (t4 - t3)) / 2, clock B minus clock A
    its delay               delta = (t4 - t1) - (t3 - t2); the true offset lies within theta +- delta / 2
    its time on clock A     tau = (t1 + t4) / 2
    anchors                 windows of 5 s of clock A from the first tau; in each window that has an exchange, the one
                            with the smallest delta, the earliest on a tie
    theta(t)                the straight line between the two neighbouring anchors; the first or last anchor's value outside
    bound of the run        the largest delta / 2 among the anchors of the region (below); the first and the last
                            anchor only delimit: the last window is partial, and its one exchange may be a slow one

The rate between the two clocks is not constant (board B's clock is disciplined by NTP), and the bound of the anchors
says nothing about the line between them (E9_SPEC.md, 'FINAL ruling on the clock track', 2026-11-25). The probe's other
exchanges say how well the line holds:

    region                  from the second anchor to the second-to-last one (their tau; ends included); with fewer
                            than four anchors there is none
    cert of an exchange     |track(tau) - theta| + delta / 2: at its tau the track is within that of the true offset,
                            because the true offset is within delta / 2 of theta; an anchor's cert is its delta / 2
    certified bound T(G)    G = 2,000 ms; the smallest T such that the exchanges of the region with cert <= T, taken
                            with the two ends of the region, are nowhere more than G apart (0 when the ends themselves
                            are not); none when even all exchanges leave a larger distance
    total bound             the larger of the bound of the run and T(G): at instants no more than 2 s apart the probe
                            certifies the track to within it. It is not a bound for every instant
    exchanges outside       exchanges of the region whose theta is further from the track than their delta / 2 plus the
                            total bound: each proves the track off by more than that bound
Every difference is formed in integers; the first anchor's time and offset are taken off before anything is a float.
"""
from pathlib import Path

import numpy as np

WINDOW_NS = 5_000_000_000
BG_NAME = "background_traffic.txt"        # the driver's record of the unrelated flow of a run (cell i)
MARKERS = ("E9_INVALID", "BG_INVALID")    # written by the driver into the run directory: the run is no result for E9
GAP_MAX_MS = 1000   # a larger gap between two completed exchanges: not a result
CERT_GAP_NS = 2_000_000_000  # G: certified exchanges must be no further apart than this
BOUND_MAX_US = 100  # a larger total bound: not a result
COLUMNS = ("t1_ns", "t2_ns", "t3_ns", "t4_ns")


def anchors(cols):
    """The exchanges of one clock_probe.csv in the order of tau, and its anchors: (order, tau2, theta2, delta, anchor).

    `order` sorts the file's rows by tau; tau2 and theta2 are twice tau and twice theta in whole nanoseconds and delta
    the delay, each in that order; `anchor` holds the indices of the anchors among them: windows of WINDOW_NS of clock
    A from the first tau, in each window that has an exchange the one with the smallest delta, the earliest on a tie.
    An exchange with t4 before t1, t3 before t2 or a negative delay contradicts itself and is an error. The latency
    keys (track) and the clock keys (clock_rate) both take their anchors here."""
    t1, t2, t3, t4 = (np.asarray(cols[k], dtype=np.int64) for k in COLUMNS)
    if not t1.size:
        raise ValueError("no completed exchange")
    bad = np.flatnonzero((t4 < t1) | (t3 < t2) | (t4 - t1 < t3 - t2))
    if bad.size:
        raise ValueError(f"data row {int(bad[0]) + 1}: an exchange needs t1 <= t4, t2 <= t3 and a delay (t4 - t1) - (t3 - t2) "
                         "that is not negative")
    order = np.argsort(t1 + t4, kind="stable")
    t1, t2, t3, t4 = (v[order] for v in (t1, t2, t3, t4))
    tau2, theta2, delta = t1 + t4, (t2 - t1) - (t4 - t3), (t4 - t1) - (t3 - t2)  # twice tau, twice theta
    window = (tau2 - tau2[0]) // (2 * WINDOW_NS)
    by = np.lexsort((np.arange(delta.size), delta, window))  # per window: smallest delay first, then the earliest
    return order, tau2, theta2, delta, np.sort(by[np.r_[True, np.diff(window[by]) != 0]])


def track(cols):
    """The offset track of one clock_probe.csv, the exchanges taken in the order of tau.

    Returns the figures of the probe (anchors, probes_completed, offset_bound_us, probe_delay_min_us,
    probe_delay_p50_us, probe_gap_max_ms: the largest difference between the tau of consecutive exchanges, None for a
    single one; drift_ppm: least-squares slope of the anchors' theta over their tau, positive when clock B runs
    faster, None for a single anchor; offset_cert_us, offset_bound_total_us and exchanges_outside as in the module's
    text; offset_bound_us is None without a region, the other two also without a certified bound) and, for the per-PDU quantities and the
    tests: theta_ns and delay_ns of every exchange, anchor (indices) and anchor_seq. An exchange with t4 before t1,
    t3 before t2 or a negative delay contradicts itself and is an error."""
    order, tau2, theta2, delta, anchor = anchors(cols)
    origin2, ref2 = int(tau2[anchor[0]]), int(theta2[anchor[0]])
    x, y = (tau2[anchor] - origin2) / 2, (theta2[anchor] - ref2) / 2
    dx = x - x.mean()
    bound_ns, cert_ns, total_ns, outside = None, None, None, 0
    if anchor.size >= 4:  # the region: second anchor to second-to-last anchor, compared in whole nanoseconds of 2 tau
        region = (tau2 >= tau2[anchor[1]]) & (tau2 <= tau2[anchor[-2]])
        bound_ns = float(delta[anchor[1:-1]].max()) / 2  # the first and the last anchor only delimit
        off = np.abs(np.interp((tau2[region] - origin2) / 2, x, y) - (theta2[region] - ref2) / 2)  # of each exchange from the line
        cert_ns = _certified(tau2[region], off + delta[region] / 2)
        if cert_ns is not None:
            total_ns = max(bound_ns, cert_ns)
            outside = int(np.count_nonzero(off > delta[region] / 2 + total_ns))
    return {"anchors": int(anchor.size), "probes_completed": int(delta.size), "offset_bound_us": None if bound_ns is None else bound_ns / 1e3,
            "offset_cert_us": None if cert_ns is None else cert_ns / 1e3,
            "offset_bound_total_us": None if total_ns is None else total_ns / 1e3, "total_ns": total_ns, "exchanges_outside": outside,
            "probe_delay_min_us": float(delta.min()) / 1e3, "probe_delay_p50_us": float(np.quantile(delta, 0.5)) / 1e3,
            "probe_gap_max_ms": float(np.diff(tau2).max()) / 2e6 if delta.size > 1 else None,
            "drift_ppm": float(dx @ (y - y.mean()) / (dx @ dx)) * 1e6 if anchor.size > 1 else None,
            "theta_ns": theta2 / 2, "delay_ns": delta, "anchor": anchor, "anchor_seq": np.asarray(cols["seq"])[order][anchor],
            "origin2": origin2, "ref2": ref2, "x": x, "y": y,
            # for the coverage rule: twice the second anchor's time on clock A, twice the second-to-last one's on clock B
            "second_anchor_a2": int(tau2[anchor[min(1, anchor.size - 1)]]),
            "before_last_anchor_b2": int(sum(np.asarray(cols[k], dtype=np.int64)[order][anchor[max(anchor.size - 2, 0)]]
                                             for k in ("t2_ns", "t3_ns")))}


def _certified(tau2, cert):
    """T(G) of the exchanges of a region (`tau2`: twice their tau, ascending, the first and the last one the ends of
    the region; `cert` of each): the smallest T such that the exchanges with cert <= T, with the two ends, are nowhere
    more than CERT_GAP_NS apart. 0 when the ends alone are not; None when even all exchanges leave a larger distance."""
    if tau2[-1] - tau2[0] <= 2 * CERT_GAP_NS:
        return 0.0
    if np.diff(tau2).max() > 2 * CERT_GAP_NS:
        return None
    values = np.unique(cert)
    lo, hi = 0, values.size - 1  # with every exchange the distances fit, and fewer exchanges never fit better
    while lo < hi:
        mid = (lo + hi) // 2
        keep = cert <= values[mid]
        keep[0] = keep[-1] = True
        if np.diff(tau2[keep]).max() <= 2 * CERT_GAP_NS:
            hi = mid
        else:
            lo = mid + 1
    return float(values[lo])


def on_clock_a(tr, b_minus_a, t_a):
    """`b_minus_a` (a time stamp of clock B minus one of clock A, integer ns) less theta(t_a), in ns: the interval as
    one clock would have measured it."""
    return (2 * b_minus_a - tr["ref2"]) / 2 - np.interp((2 * t_a - tr["origin2"]) / 2, tr["x"], tr["y"])


def _join(tx, rx):
    """(rows of tx, rows of rx, whether the sender repeats a (stream, seq)): every receiver row with result ok whose
    (stream, seq) is in the sender's rows."""
    ok = np.flatnonzero(rx["result"] == "ok")
    if not ok.size or not tx["seq"].size:
        return ok[:0], ok[:0], False
    inv = np.unique(np.concatenate([tx["stream"], rx["stream"][ok]]), return_inverse=True)[1]
    base = int(max(tx["seq"].max(), rx["seq"][ok].max())) + 1
    tx_key, rx_key = inv[:tx["seq"].size] * base + tx["seq"], inv[tx["seq"].size:] * base + rx["seq"][ok]
    order = np.argsort(tx_key, kind="stable")
    at = np.minimum(np.searchsorted(tx_key[order], rx_key), tx_key.size - 1)
    hit = tx_key[order][at] == rx_key
    return order[at[hit]], ok[hit], bool(np.any(np.diff(tx_key[order]) == 0))


def _figures(tx, j, latency, rxpart, margin, tr, violations):
    """The figures of a run that is a result, from the per-PDU quantities in ns (`j`: the sender's rows of the joined
    PDUs) and the track."""
    q = dict(zip(("p50", "p90", "p99", "p99.9"), (np.quantile(latency, [0.5, 0.9, 0.99, 0.999]) / 1e6).tolist()))
    per_stream = []  # a file with more than one stream: the latency of each stream beside the one over all
    labels = sorted(set(tx["stream"].tolist()), key=lambda s: (not s.isdigit(), int(s) if s.isdigit() else 0, s))
    for label in labels if len(labels) > 1 else ():
        mine = latency[tx["stream"][j] == label]
        per_stream.append({"stream": label, "n": int(mine.size), "latency_ms": {
            **dict(zip(("p50", "p99", "p99.9"), (np.quantile(mine, [0.5, 0.99, 0.999]) / 1e6).tolist())),
            "max": float(mine.max()) / 1e6} if mine.size else None})
    r = dict(zip(("p50", "p99"), (np.quantile(rxpart, [0.5, 0.99]) / 1e6).tolist()))
    return {"n": int(latency.size), "latency_ms": {"mean": float(latency.mean()) / 1e6, **q, "max": float(latency.max()) / 1e6},
            "rxpart_ms": {**r, "max": float(rxpart.max()) / 1e6},
            **{k: tr[k] for k in ("offset_bound_us", "offset_cert_us", "offset_bound_total_us", "exchanges_outside", "anchors",
                                  "probes_completed", "probe_delay_min_us", "probe_delay_p50_us", "probe_gap_max_ms", "drift_ppm")},
            "causality_min_us": float(margin.min()) / 1e3, "causality_violations": violations, "per_stream": per_stream}


def analyse_mono(tx, rx, probe):
    """(figures, []) of one sender / receiver pair with the probe of its directory, or (None, reasons) when the run is
    not a result for E9.

    Per delivered PDU (a receiver row with result ok, joined with the sender's row on stream and seq):
    latency = deliver_ns - theta(release_ns) - release_ns; receive part = deliver_ns - theta(send_done_ns) -
    send_done_ns; causality margin = rx_done_ns - theta(send_done_ns) - send_done_ns. Percentiles are of type 7.
    theta is taken at the sender's time stamp, as the spec says, so what the offset changes while a PDU is under way
    (the drift times its latency: nanoseconds) stays in the figure.

    Not a result: a gap above GAP_MAX_MS between two completed exchanges; fewer than four anchors; fewer than two
    anchors at or before the first release (the second anchor's tau against the smallest release_ns, both on clock A)
    or at or after the last delivery (the second-to-last anchor's (t2 + t3) / 2 against the largest deliver_ns, both
    on clock B); no certified bound; a total bound above BOUND_MAX_US; an exchange outside the total bound; a
    delivered PDU whose causality margin is below minus the total bound. Each limit itself passes. Nor is a run whose probe file has fewer than two completed exchanges or an
    exchange that contradicts itself, whose sender repeats a (stream, seq) (a process that was started again: no
    unique row to join), in which no delivered PDU can be joined, or in which a delivered PDU has no send_done_ns.

    For the gateway's files the caller passes submit_ns as release_ns and verify_done_ns as rx_done_ns (the gateway
    records no reception time): the causality margin is then that of the verification."""
    if probe["seq"].size < 2:
        return None, [f"{probe['seq'].size} completed exchange(s) in the probe file: fewer than two"]
    try:
        tr = track(probe)
    except ValueError as e:
        return None, [f"the probe file contradicts itself: {e}"]
    j, i, repeated = _join(tx, rx)
    if repeated:
        return None, ["the sender's rows have a stream and seq more than once: the receiver's rows cannot be joined"]
    if not j.size:
        return None, ["no delivered PDU of the receiver's file is in the sender's file"]
    release, sent = tx["release_ns"][j], tx["send_done_ns"][j]
    if unsent := int(np.count_nonzero(sent == 0)):
        return None, [f"{unsent} delivered PDU(s) whose row in the sender's file has no send_done_ns"]
    latency = on_clock_a(tr, rx["deliver_ns"][i] - release, release)
    rxpart = on_clock_a(tr, rx["deliver_ns"][i] - sent, sent)
    margin = on_clock_a(tr, rx["rx_done_ns"][i] - sent, sent)
    if tr["anchors"] < 4:
        return None, [f"{tr['anchors']} anchor(s) in the probe file: fewer than four"]
    certified = tr["offset_bound_total_us"] is not None
    violations = int(np.count_nonzero(margin < -tr["offset_bound_total_us"] * 1e3)) if certified else 0  # against the total bound
    reasons = []
    if tr["probe_gap_max_ms"] is not None and tr["probe_gap_max_ms"] > GAP_MAX_MS:
        reasons.append(f"probe_gap_max_ms = {tr['probe_gap_max_ms']:g} exceeds {GAP_MAX_MS}: the probe has a gap of more than 1 s")
    if tr["second_anchor_a2"] > 2 * int(tx["release_ns"].min()):
        reasons.append("fewer than two anchors lie at or before the first release")
    if tr["before_last_anchor_b2"] < 2 * int(rx["deliver_ns"][i].max()):
        reasons.append("fewer than two anchors lie at or after the last delivery")
    if not certified:
        reasons.append("no certified bound: between the second and the second-to-last anchor the completed exchanges leave "
                       f"more than {CERT_GAP_NS // 1_000_000} ms")
    elif tr["offset_bound_total_us"] > BOUND_MAX_US:
        reasons.append(f"offset_bound_total_us = {tr['offset_bound_total_us']:g} exceeds {BOUND_MAX_US}")
    if tr["exchanges_outside"]:
        reasons.append(f"exchanges_outside = {tr['exchanges_outside']}: a completed exchange lies further from the track than "
                       f"half its delay plus offset_bound_total_us ({tr['offset_bound_total_us']:g} us)")
    if violations:
        reasons.append(f"causality_violations = {violations}: a delivered PDU was received more than the total offset bound "
                       f"({tr['offset_bound_total_us']:g} us) before it was sent; smallest margin {margin.min() / 1e3:g} us")
    if reasons:
        return None, reasons
    return _figures(tx, j, latency, rxpart, margin, tr, violations), []


# ---- the latency on the raw clocks (E9_SPEC.md, Addendum E) -------------------------------------------------------------
# CLOCK_MONOTONIC is steered by the time-synchronisation service, CLOCK_MONOTONIC_RAW is not. A probe file of format 2
# carries the raw stamps of every exchange, and each probe process samples the relation of its board's two clocks every
# 5 ms (clock_map_a.csv, clock_map_b.csv). The PDU stamps stay CLOCK_MONOTONIC: they are carried onto the raw clock of
# their board with that map, and the offset between the boards is tracked on the raw stamps (track() of raw_stamps()).
# Whole nanoseconds, doubled where a half occurs (2 m, 2 x_raw), stay integers; a difference against the first valid
# sample or the first anchor is formed in integers before anything is a float.

RAW_COLUMNS = ("t1r_ns", "t2r_ns", "t3r_ns", "t4r_ns")
WIDTH_MAX_NS = 5_000                     # two raw reads further apart were interrupted: no valid sample, no check point
MAP_GAP_MAX_MS = 50                      # a larger distance between two valid samples in the range the stamps use: not a result
KINK_BASE_NS = 4_000_000                 # E12.7: the slopes of the kink term are read over at least this
CHECK_MIN, CHECK_MIN_GATEWAY = 100, 20   # exchange points a board needs in that range: a harness run, the gateway run
ADJ_WINDOW_NS, ADJ_SPAN_MIN_NS = 1_000_000_000, 800_000_000  # E6: windows of 1 s; a window needs samples this far apart
ADJUSTED_PPM = 1                         # E6: a clock counts as adjusted when its window rates range over more than this
FORMAT_1 = ("the probe file is of format 1 (no raw stamps): refused for the latency, which is measured on the raw clocks "
            "(E9_SPEC.md, Addendum E)")


def raw_stamps(probe):
    """The exchanges of a probe file of format 2 under the names track() takes: the raw stamps in the place of the
    monotonic reads."""
    return {"seq": probe["seq"], **{c: probe[r] for c, r in zip(COLUMNS, RAW_COLUMNS)}}


def clock_map(cols):
    """The map of one board from the columns of its clock_map file: samples (its rows), samples_invalid and, of the
    valid samples (0 <= raw2 - raw1 <= WIDTH_MAX_NS) in the order of the file: a (the abscissa: the monotonic read), m2
    (twice m = mono - the mean of the two raw reads), h2 (twice the half width) and row (their row numbers). Valid
    samples whose monotonic reads do not ascend contradict the file: an error."""
    raw1, mono, raw2 = (np.asarray(cols[k], dtype=np.int64) for k in ("raw1_ns", "mono_ns", "raw2_ns"))
    row = np.flatnonzero((raw2 >= raw1) & (raw2 - raw1 <= WIDTH_MAX_NS))
    if np.any(np.diff(mono[row]) <= 0):
        raise ValueError("the valid samples are not in ascending order of their monotonic read")
    return {"samples": int(mono.size), "samples_invalid": int(mono.size - row.size), "a": mono[row],
            "m2": (2 * mono - raw1 - raw2)[row], "h2": (raw2 - raw1)[row], "row": row}


def to_raw(board, x):
    """The monotonic stamps `x` of a board on its raw clock, doubled, as (whole, part): 2 x_raw = whole - part, with
    whole = 2 x - 2 m(first valid sample), an integer, and part = 2 (m(x) - m(first valid sample)), m(x) by linear
    interpolation between the two valid samples around x. The caller has made sure that x lies inside the map."""
    a, m2 = board["a"], board["m2"]
    return 2 * np.asarray(x, dtype=np.int64) - int(m2[0]), np.interp(x - a[0], a - a[0], m2 - m2[0])


def map_figures(board, stamps, mono, mean_raw2, width):
    """The figures of a board's map (clock_map()) for the monotonic `stamps` that are carried onto its raw clock, and
    the independent certificate from the board's exchange points (`mono`: the monotonic read of each point,
    `mean_raw2`: twice the mean of its two raw reads, `width`: their distance).

    used range    from the last valid sample at or before the earliest stamp to the first valid sample at or after the
                  latest one. A stamp before the first or after the last valid sample cannot be carried over: an error
    gap_max_ms    the largest distance in abscissa between two consecutive valid samples of the used range
    holdout_us    the largest |m_k - L_k| over the samples of the used range whose neighbours in the file, k - 1 and
                  k + 1, are both valid (they may lie outside the range); L_k is the straight line between those two,
                  at k. None when no sample takes part
    kink_us       E12.1: the hold-out covers a change of rate only where the samples are evenly spaced. The valid
                  samples in the order of the file bound intervals j (from valid sample j to j + 1) of length g_j;
                  for every interval of the used range |slope after - slope before| x g_j / 4 is the most a single
                  change of rate inside it can put the straight line off. Each slope is read over a baseline of at
                  least KINK_BASE_NS (E12.7: a sampler that woke late takes the samples it owes microseconds
                  apart, and a slope between two of those is read noise): before, from the largest i with a_j - a_i
                  >= KINK_BASE_NS to j; after, from j + 1 to the smallest k with a_k - a_(j+1) >= KINK_BASE_NS.
                  The largest of these; 0 when the range is one sample; None when an interval of the range has no
                  such i or k in the file
    half_us       the largest half width of a sample of the used range
    bound_us      max(holdout_us, kink_us) + half_us; None when one of the two cannot be formed
    check_n       the points no wider than WIDTH_MAX_NS whose monotonic read lies in the used range, ends included;
                  check_max_us: the largest |value - m(abscissa)| among them, value = mono - mean of the two raw
                  reads; check_violations: those with |value - m(abscissa)| > bound + width / 2"""
    a, m2, h2, row = board["a"], board["m2"], board["h2"], board["row"]
    if not a.size:
        raise ValueError("has no valid sample")
    first, last = int(np.min(stamps)), int(np.max(stamps))
    if first < a[0]:
        raise ValueError(f"lies {(int(a[0]) - first) / 1e6:g} ms before the first valid sample")
    if last > a[-1]:
        raise ValueError(f"lies {(last - int(a[-1])) / 1e6:g} ms after the last valid sample")
    lo, hi = int(np.searchsorted(a, first, "right")) - 1, int(np.searchsorted(a, last, "left"))
    half_ns = float(h2[lo:hi + 1].max()) / 2
    k = np.arange(1, a.size - 1)
    k = k[(k >= lo) & (k <= hi) & (row[k - 1] == row[k] - 1) & (row[k + 1] == row[k] + 1)]  # both neighbours in the file valid
    line2 = (m2[k - 1] - m2[0]) + (m2[k + 1] - m2[k - 1]) * ((a[k] - a[k - 1]) / (a[k + 1] - a[k - 1]))
    holdout_ns = float(np.abs((m2[k] - m2[0]) - line2).max()) / 2 if k.size else None
    j = np.arange(lo, hi)               # the intervals of the used range: from valid sample j to j + 1
    i = np.searchsorted(a, a[j] - KINK_BASE_NS, "right") - 1     # the last sample at least the baseline before the interval
    k = np.searchsorted(a, a[j + 1] + KINK_BASE_NS, "left")      # the first one at least the baseline after it
    if not j.size:
        kink_ns = 0.0
    elif i.min() < 0 or k.max() > a.size - 1:
        kink_ns = None
    else:  # twice the two slopes, since m2 is twice m
        before2, after2 = (m2[j] - m2[i]) / (a[j] - a[i]), (m2[k] - m2[j + 1]) / (a[k] - a[j + 1])
        kink_ns = float((np.abs(after2 - before2) * (a[j + 1] - a[j])).max()) / 8
    bound_ns = None if None in (holdout_ns, kink_ns) else max(holdout_ns, kink_ns) + half_ns
    mono, mean_raw2, width = (np.asarray(v, dtype=np.int64) for v in (mono, mean_raw2, width))
    use = (width >= 0) & (width <= WIDTH_MAX_NS) & (mono >= a[lo]) & (mono <= a[hi])
    off_ns = np.abs((2 * mono[use] - mean_raw2[use] - int(m2[0])) - np.interp(mono[use] - a[0], a - a[0], m2 - m2[0])) / 2
    return {"gap_max_ms": (int(np.diff(a[lo:hi + 1]).max()) if hi > lo else 0) / 1e6,
            "holdout_us": None if holdout_ns is None else holdout_ns / 1e3,
            "kink_us": None if kink_ns is None else kink_ns / 1e3, "half_us": half_ns / 1e3,
            "bound_us": None if bound_ns is None else bound_ns / 1e3, "bound_ns": bound_ns, "check_n": int(off_ns.size),
            "check_max_us": float(off_ns.max()) / 1e3 if off_ns.size else None,
            "check_violations": 0 if bound_ns is None else int(np.count_nonzero(off_ns > bound_ns + width[use] / 2))}


def adjustment(board):
    """E6, what the map (clock_map()) says about the board's CLOCK_MONOTONIC against its raw clock. The valid samples
    are cut into windows of 1 s of abscissa from the first one; a window whose first and last sample are at least 0.8 s
    apart has the rate (m_last - m_first) / (abscissa_last - abscissa_first) in ppm, positive when CLOCK_MONOTONIC
    runs faster than the raw clock. adj_ppm_min, adj_ppm_max, adj_ppm_median over these rates (None without one);
    adj_step_ppm_max, the largest absolute difference between two rates that follow each other (0 with fewer than
    two); adj_offset_range_us, the largest minus the smallest m; adjusted, 1 when the rates range over more than
    ADJUSTED_PPM, else 0 (None without a rate): whether the correction of the clock CHANGED during the run, not
    whether there is one (E11 n: a clock that runs at a constant -1.8 ppm against its raw clock has adjusted = 0)."""
    a, m2 = board["a"], board["m2"]
    first = np.flatnonzero(np.r_[True, np.diff((a - a[0]) // ADJ_WINDOW_NS) != 0])
    last = np.r_[first[1:] - 1, a.size - 1]
    wide = a[last] - a[first] >= ADJ_SPAN_MIN_NS
    rate = (m2[last] - m2[first])[wide] / 2 / (a[last] - a[first])[wide] * 1e6
    low, high, median = (float(f(rate)) for f in (np.min, np.max, np.median)) if rate.size else (None, None, None)
    return {"adj_ppm_min": low, "adj_ppm_max": high, "adj_ppm_median": median,
            "adj_step_ppm_max": float(np.abs(np.diff(rate)).max()) if rate.size > 1 else 0.0,
            "adj_offset_range_us": int(m2.max() - m2.min()) / 2e3, "adjusted": None if low is None else int(high - low > ADJUSTED_PPM)}


def analyse(tx, rx, probe, maps, check_min=CHECK_MIN, per_pdu=None, record=None):
    """(figures, []) of one sender / receiver pair on the raw clocks (E9_SPEC.md, Addendum E), or (None, reasons) when
    the run is not a result for E9. `probe`: the columns of a probe file of format 2; `maps`: the columns of
    clock_map_a.csv and clock_map_b.csv under 'a' and 'b'; `check_min`: the exchange points each board needs in the
    range its stamps use (CHECK_MIN_GATEWAY for the gateway's files).

    The offset between the boards is the track of the FINAL ruling on the raw stamps (track(raw_stamps(probe))); its
    time axis is board A's raw clock. A PDU stamp x of a board is carried onto that board's raw clock, x_raw = x -
    m(x). Carried over are, on board A, release_ns and send_done_ns of every delivered PDU and the smallest release_ns
    of the sender's file; on board B, rx_done_ns and deliver_ns of every delivered PDU and the largest deliver_ns of
    all rows with result ok. Per delivered PDU: latency = deliver_raw - theta(release_raw) - release_raw; receive part
    = deliver_raw - theta(send_done_raw) - send_done_raw; causality margin = rx_done_raw - theta(send_done_raw) -
    send_done_raw. bound_total_us = offset_bound_total_us + the map bound of board A + that of board B.

    Not a result: a probe file of format 1; what analyse_mono() names for the probe, the join and the track, here on
    the raw stamps (fewer than four anchors, a gap above GAP_MAX_MS, the coverage rule with the first release and the
    last delivery carried onto the raw clocks, no certified bound, an exchange outside offset_bound_total_us); a stamp
    outside its map; a map with a gap above MAP_GAP_MAX_MS in the range its stamps use, in which no sample of that
    range can be tested against its neighbours, or in which an interval of that range has no sample KINK_BASE_NS
    before or after it (no kink term); an exchange point further from the map than the map's bound plus half
    its width; fewer than `check_min` such points on a board; bound_total_us above BOUND_MAX_US; a delivered PDU whose
    causality margin is below minus bound_total_us. Each limit itself passes. `per_pdu`, a dict, receives the three
    per-PDU quantities in ns (for the tests). `record`, a dict, receives what the maps say as far as it can be
    computed, 'clock' (adjustment()) and 'map' (the map figures) per board, also when the run is not a result: for
    summary.json, never for a key (E11 j)."""
    if RAW_COLUMNS[0] not in probe:
        return None, [FORMAT_1]
    board, broken = {}, []
    for x in "ab":
        try:
            board[x] = clock_map(maps[x])
        except ValueError as e:
            broken.append(f"clock_map_{x}.csv: {e}")
    if record is not None:
        record["clock"] = {x: adjustment(b) for x, b in board.items() if b["a"].size}
    if probe["seq"].size < 2:
        return None, [f"{probe['seq'].size} completed exchange(s) in the probe file: fewer than two"]
    try:
        tr = track(raw_stamps(probe))
    except ValueError as e:
        return None, [f"the probe file contradicts itself: {e}"]
    j, i, repeated = _join(tx, rx)
    if repeated:
        return None, ["the sender's rows have a stream and seq more than once: the receiver's rows cannot be joined"]
    if not j.size:
        return None, ["no delivered PDU of the receiver's file is in the sender's file"]
    release, sent, arrived, delivered = tx["release_ns"][j], tx["send_done_ns"][j], rx["rx_done_ns"][i], rx["deliver_ns"][i]
    if unsent := int(np.count_nonzero(sent == 0)):
        return None, [f"{unsent} delivered PDU(s) whose row in the sender's file has no send_done_ns"]
    if tr["anchors"] < 4:
        return None, [f"{tr['anchors']} anchor(s) in the probe file: fewer than four"]
    first_release, last_delivery = tx["release_ns"].min(), rx["deliver_ns"][rx["result"] == "ok"].max()
    stamps = {"a": np.r_[release, sent, first_release], "b": np.r_[arrived, delivered, last_delivery]}
    # the exchange points of each board as (monotonic read, twice the mean of its two raw reads, width): before a send
    # (points 1 and 3) the other raw read lies one width before the stamp, after a receive (2 and 4) one width after it
    t, r, w = ({p: np.asarray(probe[f"{c}{p}{end}"], dtype=np.int64) for p in "1234"} for c, end in (("t", "_ns"), ("t", "r_ns"), ("w", "_ns")))
    points = {"a": ((t["1"], 2 * r["1"] - w["1"], w["1"]), (t["4"], 2 * r["4"] + w["4"], w["4"])),
              "b": ((t["2"], 2 * r["2"] + w["2"], w["2"]), (t["3"], 2 * r["3"] - w["3"], w["3"]))}
    fig = {}
    for x in board:
        try:
            fig[x] = map_figures(board[x], stamps[x], *(np.concatenate(c) for c in zip(*points[x])))
        except ValueError as e:
            broken.append(f"a stamp of board {x.upper()} {e} of clock_map_{x}.csv: it cannot be carried onto the raw clock"
                          if str(e).startswith("lies ") else f"clock_map_{x}.csv: {e}")
    of_map = {x: {"samples": board[x]["samples"], "samples_invalid": board[x]["samples_invalid"],
                  **{k: v for k, v in f.items() if k != "bound_ns"}} for x, f in fig.items()}
    if record is not None:
        record["map"] = of_map
    if broken:
        return None, broken

    def across(b, a):  # a stamp on board B's raw clock, less theta at a stamp on board A's raw clock, less that stamp: ns
        at = ((a[0] - tr["origin2"]) - a[1]) / 2
        return ((b[0] - a[0] - tr["ref2"]) - (b[1] - a[1])) / 2 - np.interp(at, tr["x"], tr["y"])

    a_release, a_sent = to_raw(board["a"], release), to_raw(board["a"], sent)
    b_arrived, b_delivered = to_raw(board["b"], arrived), to_raw(board["b"], delivered)
    latency, rxpart, margin = across(b_delivered, a_release), across(b_delivered, a_sent), across(b_arrived, a_sent)
    if per_pdu is not None:
        per_pdu.update(latency_ns=latency, rxpart_ns=rxpart, margin_ns=margin)
    bounds = [fig[x]["bound_ns"] for x in "ab"]
    total_ns = tr["total_ns"] + sum(bounds) if tr["total_ns"] is not None and None not in bounds else None
    violations = int(np.count_nonzero(margin < -total_ns)) if total_ns is not None else 0
    reasons = []
    if tr["probe_gap_max_ms"] is not None and tr["probe_gap_max_ms"] > GAP_MAX_MS:
        reasons.append(f"probe_gap_max_ms = {tr['probe_gap_max_ms']:g} exceeds {GAP_MAX_MS}: the probe has a gap of more than 1 s")
    whole, part = to_raw(board["a"], np.array([first_release]))   # coverage: 2 x_raw = whole - part against twice the anchor's time
    if (tr["second_anchor_a2"] - int(whole[0])) + part[0] > 0:
        reasons.append("fewer than two anchors lie at or before the first release")
    whole, part = to_raw(board["b"], np.array([last_delivery]))
    if (tr["before_last_anchor_b2"] - int(whole[0])) + part[0] < 0:
        reasons.append("fewer than two anchors lie at or after the last delivery")
    if tr["total_ns"] is None:
        reasons.append("no certified bound: between the second and the second-to-last anchor the completed exchanges leave "
                       f"more than {CERT_GAP_NS // 1_000_000} ms")
    for x, f in fig.items():
        if f["gap_max_ms"] > MAP_GAP_MAX_MS:
            reasons.append(f"map_{x}.gap_max_ms = {f['gap_max_ms']:g} exceeds {MAP_GAP_MAX_MS}: clock_map_{x}.csv has a gap "
                           "between two valid samples in the range the stamps use")
        if f["holdout_us"] is None:
            reasons.append(f"clock_map_{x}.csv: no sample in the range the stamps use has a valid sample on either side in "
                           "the file: the map cannot be tested against itself")
        if f["kink_us"] is None:
            reasons.append(f"clock_map_{x}.csv: an interval of the range the stamps use has no valid sample at least "
                           f"{KINK_BASE_NS // 1_000_000} ms before it or after it in the file: its kink term cannot be formed")
        if f["check_violations"]:
            reasons.append(f"map_{x}.check_violations = {f['check_violations']}: an exchange point of board {x.upper()} reads the "
                           f"relation of its two clocks further from the map than map_{x}.bound_us ({f['bound_us']:g} us) plus half "
                           f"its width; the largest distance is {f['check_max_us']:g} us")
        if f["check_n"] < check_min:
            reasons.append(f"map_{x}.check_n = {f['check_n']}: fewer than {check_min} exchange points of board {x.upper()} in the "
                           "range the stamps use")
    if total_ns is not None and total_ns > BOUND_MAX_US * 1000:
        reasons.append(f"bound_total_us = {total_ns / 1e3:g} exceeds {BOUND_MAX_US} (offset_bound_total_us "
                       f"{tr['offset_bound_total_us']:g} + map_a.bound_us {fig['a']['bound_us']:g} + map_b.bound_us "
                       f"{fig['b']['bound_us']:g})")
    if tr["exchanges_outside"]:
        reasons.append(f"exchanges_outside = {tr['exchanges_outside']}: a completed exchange lies further from the track than "
                       f"half its delay plus offset_bound_total_us ({tr['offset_bound_total_us']:g} us)")
    if violations:
        reasons.append(f"causality_violations = {violations}: a delivered PDU was received more than the total bound "
                       f"({total_ns / 1e3:g} us) before it was sent; smallest margin {margin.min() / 1e3:g} us")
    if reasons:
        return None, reasons
    widths = np.concatenate(list(w.values()))
    mono = analyse_mono(tx, rx, probe)[0]   # diagnostic: what the format-1 definitions make of the monotonic columns
    try:
        mono_total = track(probe)["offset_bound_total_us"]
    except ValueError:
        mono_total = None
    figures = _figures(tx, j, latency, rxpart, margin, tr, violations)
    return {**figures, "bound_total_us": total_ns / 1e3, "probe_format": 2,
            "probe_width_p50_ns": float(np.quantile(widths, 0.5)), "probe_width_max_ns": int(widths.max()),
            "map": of_map, "clock": {x: adjustment(board[x]) for x in "ab"},
            "mono": {"verdict": int(mono is not None), "offset_bound_total_us": mono_total,
                     "latency_p50_diff_us": (mono["latency_ms"]["p50"] - figures["latency_ms"]["p50"]) * 1e3 if mono else None}}, []


def background(path):
    """The driver's record of the unrelated flow beside a periodic run (DATA_SCHEMA.md, background_traffic.txt):
    'key=value' lines, the last one 'verdict=PASS' or 'verdict=FAIL: <reasons>'. Returns the two rates in Mbit/s, the two
    byte counts, the verdict word and its whole line. A record without its verdict line or one of the four figures was
    cut and is an error. The verdict is the driver's; it is taken, not recomputed."""
    lines = dict(ln.split("=", 1) for ln in Path(path).read_text(errors="replace").splitlines() if "=" in ln)
    if "verdict" not in lines:
        raise ValueError("no verdict line")
    try:
        return {"rate_offered_mbit_s": int(lines["rate_offered_bit_s"]) / 1e6, "rate_achieved_mbit_s": int(lines["rate_achieved_bit_s"]) / 1e6,
                "bytes_sent": int(lines["bytes_sent"]), "bytes_received": int(lines["bytes_received"]),
                "verdict": lines["verdict"].split(":")[0].strip(), "verdict_line": lines["verdict"].strip()}
    except (KeyError, ValueError) as e:
        raise ValueError(f"line missing or no whole number: {e}") from e


# ---- the two tests of the method (E9_SPEC.md, 'Testing strategy' 1 and 2; a probetest directory) -----------------------

def same_host(probe):
    """Client and server of the probe on one board, where the true offset is zero: the number of exchanges, the anchors
    the largest delta / 2 among ALL of them (ruled 2026-11-25: only a run's offset_bound_us leaves the first and the
    last anchor out), and theta_beyond_half_delay, the exchanges with |theta| > delta / 2. The estimator promises
    that there is none."""
    tr = track(probe)
    return {"exchanges": tr["probes_completed"], "anchors": tr["anchors"],
            "offset_bound_us": float(tr["delay_ns"][tr["anchor"]].max()) / 2e3,
            "theta_beyond_half_delay": int(np.count_nonzero(np.abs(tr["theta_ns"]) > tr["delay_ns"] / 2))}


def two_directions(ab, ba):
    """Two probes at the same time, `ab` with its client on board A and `ba` with its client on board B, so that
    theta_AB + theta_BA is zero for a perfect measurement. Compared are the anchors of the region of each track (the
    second to the second-to-last one; E9_SPEC.md, E11 m: the end segments of a track are not certified and take no
    part): each is brought to the other board's clock with its own theta, and when that instant lies in the region
    of the other track (ends included), its theta plus the other track's theta(t) there is one sum. A track with
    fewer than four anchors has no region. Returns the number of anchors compared, the largest |theta_AB + theta_BA|
    and the limit it must stay within, the sum of the two total bounds."""
    a, b = track(ab), track(ba)
    sums = [np.empty(0)]
    for mine, other in ((a, b), (b, a)) if min(a["anchors"], b["anchors"]) >= 4 else ():
        # the anchor's instant on the other clock, counted from the other track's first anchor; the large parts in integers
        at = ((mine["origin2"] + mine["ref2"] - other["origin2"]) / 2 + mine["x"] + mine["y"])[1:-1]
        inside = (at >= other["x"][1]) & (at <= other["x"][-2])
        sums.append((mine["ref2"] + other["ref2"]) / 2 + mine["y"][1:-1][inside] + np.interp(at[inside], other["x"], other["y"]))
    both = np.concatenate(sums)
    return {"anchors_compared": int(both.size), "theta_sum_max_us": float(np.abs(both).max()) / 1e3 if both.size else None,
            # the sum of the two total bounds; none when a track has no certified bound (fewer than four anchors, a hole)
            "limit_us": None if None in (a["offset_bound_total_us"], b["offset_bound_total_us"])
            else a["offset_bound_total_us"] + b["offset_bound_total_us"]}
