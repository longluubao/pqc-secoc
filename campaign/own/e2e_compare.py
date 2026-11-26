"""Independent second reading of an E9 run directory (end-to-end latency across the two boards), compared key by key
with the toolkit. Written from E9_SPEC.md ('Interface details', the rulings of 2026-11-24 and 25, Addendum E), without
the toolkit's code and without the harness checker's.

PROBE FORMAT 2 (Addendum E, 2026-11-25): the latency is measured on the raw clocks. A clock_probe.csv without
'# format=2' (format 1: no raw stamps) is REFUSED for latency: the run is not a result and must have no e2e key.
  raw track  the exchange, anchor, region, bound, T(2 s), outside, gap and coverage rules below, applied to the raw
             stamps t1r..t4r; the time axis is board A's raw clock (E3)
  map        clock_map_a.csv / clock_map_b.csv, samples raw1, mono, raw2: valid when 0 <= raw2 - raw1 <= 5,000 ns;
             abscissa mono, m = mono - (raw1 + raw2) / 2, half-width (raw2 - raw1) / 2. A CLOCK_MONOTONIC stamp x of
             that board is carried to x - m(x), m(x) on the straight line between the two valid samples around x; a
             stamp before the first or after the last valid sample cannot be carried: not a result (E4)
  used range from the last valid sample at or before the earliest carried stamp to the first one at or after the
             latest. gap_max_ms: largest step of abscissa in it (above 50: not a result). holdout_us: largest
             |m_k - line through k-1 and k+1| over its samples; kink_us (E12.1): over its intervals between valid
             samples the largest |slope behind the interval - slope before it| x length / 4, each slope read over
             at least 4 ms, to the nearest valid sample that far from the interval's end (E12.7; an interval of the
             range without such a sample on either side: not a result); half_us: its largest half-width;
             bound_us = max(holdout_us, kink_us) + half_us
  identity   E12.2, not a result: a map whose role line is not that of its file name, whose host is not host_a /
             host_b of clock_probe.csv or whose commit is not the probe file's; a clock or clock_raw line other than
             CLOCK_MONOTONIC / CLOCK_MONOTONIC_RAW in any of the three files; interval_ms other than 5 in a map (the
             probe file's interval_ms is the exchange interval, which E2 does not fix: not judged)
  check      every exchange point of the board no wider than 5,000 ns is an own reading of m (monotonic read minus the
             mean of its two raw reads; the raw stamp is the second read at points 1 and 3, the first at 2 and 4):
             check_n = those inside the used range, check_max_us = largest |reading - m|, check_violations = those
             off by more than bound_us + width / 2. A violation, or fewer than 100 points (gateway run: 20), or
             samples_dropped other than 0: not a result
  latency    release, send_done carried with map a, arrival, delivery with map b; latency, receive part and causality
             margin as below with theta(t) of the raw track. bound_total_us = offset_bound_total_us + the two map
             bounds; above 100: not a result; a causality violation is a margin below minus bound_total_us (E5)
  clock_<x>  per board, from all its valid samples: windows of 1 s of abscissa from the first sample; a window whose
             first and last sample are at least 0.8 s apart has the rate change of m / change of abscissa (ppm);
             adj_ppm_min / max / median, adj_step_ppm_max (neighbours in the list of windows that have a rate),
             adj_offset_range_us, adjusted = 1 when max - min exceeds 1 ppm (E6)
  new keys   bound_total_us, probe_format, probe_width_p50_ns, probe_width_max_ns, map_<x>.*, clock_<x>.*, and the
             diagnostic mono.offset_bound_total_us, mono.verdict, mono.latency_p50_diff_us: the format-1 reading of
             the monotonic columns with the stamps as they are (E10)
  readings   fixed by E11: (a) a sample takes part in the hold-out when the rows next to it in the file are both
             valid, inside the used range or not; (b) the used range includes its two ends, for samples and check
             points; (c) carried stamps: board A release and send_done of every joined delivered PDU and the smallest
             release of the sender's file, board B arrival and delivery of every joined PDU and the largest delivery
             of the ok rows; (d) 100 check points in a harness run, 20 in the gateway run, whatever its length;
             (e) limits are 'not above'; (f) a probe-test file of format 2 is read on its raw stamps, one of format 1
             on its monotonic columns; (j) a run that is not a result has no key under .e2e. at all.
             E11 k and o: map_<x>.samples = rows of the file; not a result: a footer 'samples' other than the row
             count, a map file without a samples_dropped line, valid samples whose monotonic reads do not increase,
             a board without a carried stamp or without a valid sample, a used range in which no sample has two
             valid neighbours, a 'format=' line that disagrees with the columns; a probe-test pair of one file of
             each format is invalid; a stamp or a check point exactly on a sample takes that sample's m;
             adj_step_ppm_max is taken between neighbours in the list of the windows that have a rate; E6 is over
             all valid samples of the file. Own: mono.verdict = the rules of the earlier rulings on the monotonic
             columns with the stamps as they are
The rules below are those of the earlier rulings; under format 2 they apply to the raw stamps and the carried stamps.

usage: python3 -I e2e_compare.py <run_dir> <analysis_dir> <key_prefix>      (python3 -I e2e_compare.py --self-test)
Standard library only. The run directory holds exactly one clock_probe.csv; the files beside it say which kind it is:
  harness   periodic_tx*.csv (release_ns, send_done_ns) and periodic_rx*.csv (rx_done_ns, deliver_ns);
            keys <prefix>.periodic.<configuration>.e2e.<name>
  gateway   app_tx.csv (submit_ns, send_done_ns) and app_rx.csv (verify_done_ns, deliver_ns); submit_ns stands for the
            release and verify_done_ns for the arrival; keys <prefix>.functional.e2e.<name>
Rules, from the specification:
  exchange  2 theta = (t2 - t1) - (t4 - t3), clock B minus clock A; delta = (t4 - t1) - (t3 - t2); 2 tau = t1 + t4;
            exchanges are ordered by tau
  anchors   windows of 5 s of clock A from the first tau; in each window the exchange with the smallest delta, the
            earliest on a tie
  theta(t)  the straight line between the two neighbouring anchors by tau; outside them the first / last anchor's value
  bound     b = the largest delta / 2 of the anchors of the region (second to second-to-last anchor); the first and
            the last anchor only delimit
  per PDU   every ok row of the receiver whose stream and seq are in the sender's file (a second ok row of a job
            counts twice): latency = deliver_ns - theta(release) - release; receive part = deliver_ns -
            theta(send_done_ns) - send_done_ns; causality margin = arrival - theta(send_done_ns) - send_done_ns
  keys      n, latency mean / p50 / p90 / p99 / p99.9 / max, receive part p50 / p99 / max (type 7; every percentile is
            in numbers.csv, the line printed here names those with fewer than ten samples above them, which the
            toolkit holds back from numbers.tex), offset_bound_us, anchors, probes_completed, probe_delay_min_us and
            probe_delay_p50_us and probe_gap_max_ms over all completed exchanges (gap = largest step of tau),
            drift_ppm (least-squares slope of the anchors' theta over tau, only with two anchors),
            causality_min_us, causality_violations
  invalid   probe_gap_max_ms above 1000; fewer than four anchors; the second anchor's tau after the smallest release;
            the second-to-last anchor's (t2 + t3) / 2 before the largest deliver_ns of the ok rows (two anchors on
            each side of the PDUs: the end segments of the track are not used); no T(G), or
            offset_bound_total_us above 100 (all strict); an exchange outside; a causality violation; an ok row whose sender row has send_done_ns = 0; exchanges_completed missing or not
            the number of rows; a row with t4 before t1, t3 before t2 or a negative delta; a harness receiver that
            declares rx_done_ns not recorded. Own addition: no joined PDU, or fewer than two exchanges.
            An invalid run must have NO e2e key in numbers.csv; a valid one must have every key computed here.
  track check (final ruling of 2026-11-25; the rate between the clocks is not constant, board B follows NTP)
            region: from the second to the second-to-last anchor, by tau. For every completed exchange j of the
            region cert_j = |track(tau_j) - theta_j| + delta_j / 2: there the track is within cert_j of the true
            offset. T(G), G = 2,000 ms: the smallest T such that the exchanges with cert_j <= T, together with the
            two ends of the region, leave no distance in tau above G (exactly G passes; a region no longer than G
            gives 0). offset_cert_us = T(G); offset_bound_total_us = max(offset_bound_us, offset_cert_us);
            exchanges_outside = exchanges of the region
            with |track(tau) - theta| > delta / 2 + the total bound; causality_violations = margins below minus
            the total bound. All in exact rational arithmetic.
  background  a harness run with background_traffic.txt (cell i): the verdict is recomputed by the rule of
            DATA_SCHEMA.md (FAIL: achieved below 95 % of offered; nothing received or more received than sent; the
            flow began after the first release or ended before the last send_done_ns) and the record is checked
            against bg_source.txt and bg_sink.txt. A verdict of the record other than PASS, an own verdict FAIL
            or a marker BG_INVALID or E9_INVALID (beside the files or one directory above the periodic files)
            makes the run invalid for E9: no e2e key. A verdict other than the file's or a record that does not
            fit the two ends' files fails this check. The toolkit's keys
            <prefix>.periodic.<configuration>.bg.{rate_offered_mbit_s, rate_achieved_mbit_s, bytes_sent,
            bytes_received, verdict} are compared with the record (the verdict although it is a text key).
  streams   the keys above are over all streams of the file together. A sender file with more than one stream also
            has stream<k>.n and stream<k>.latency_p50_ms / _p99_ms / _p99_9_ms / _max_ms per stream index k (ruling
            of 2026-11-25), compared like every other key; a stream without a delivered PDU has n = 0 and no
            latency key. With '# stream_profiles=' (profile both) the text keys stream<k>.profile are compared with
            the k-th entry of that header line, which must be the same in the sender's and the receiver's file.
  probetest a run directory with a directory probetest (the two tests of the method, no PDU): keys
            <prefix>.probetest.zero.<host_a>.{exchanges, anchors, offset_bound_us, theta_beyond_half_delay.k} per
            zero_<host>.csv (client and server on one board: exchanges with |theta| > delta / 2, over all exchanges)
            and pair.{anchors_compared, theta_sum_max_us, limit_us} from pair_ab.csv and pair_ba.csv: a REGION
            anchor of either track (second to second-to-last) is compared when its instant on the other board's
            clock, (t2 + t3) / 2, lies inside the other track's region (ends included; E11 m: the end segments take
            no part); the sum is its theta plus the other track's theta at that instant; the limit is the sum of
            the two TOTAL bounds. The check also fails when an
            ANCHOR of a same-host file has |theta| > delta / 2 or a sum is above the limit.
Arithmetic: whole nanoseconds as integers and exact fractions, one division per value, so each own value is the
correctly rounded exact one. Tolerances: counts exactly; drift_ppm to nine digits; clock_<x>.adj_*_ppm to 1e-6 ppm;
every time key of a format-2 run to 0.1 ns or nine digits (a carried stamp is near 1.6e14 ns, where one step of a
float64 is 0.03 ns: an implementation that holds a carried stamp in a float differs from the exact value by that
much); the probe-test keys to 0.001 ns (the toolkit matched them to 3e-8 ns on the dry runs of 2026-11-24).
Not judged here: the rules of the periodic or functional run itself (periodic_compare.py, functional_compare.py), the
toolkit's invalid_runs list, a gateway run with a replaced process (app_tx2.csv), several transmitter files.
Exit 0 only if the run is valid by these rules, at least 12 keys were compared and nothing differs. Without a
numbers.csv in the analysis directory the own figures are printed and the check fails.
"""
import csv
import io
import math
import os
import re
import sys
from bisect import bisect_left, bisect_right
from contextlib import redirect_stdout
from fractions import Fraction
from pathlib import Path
from statistics import median

WINDOW2 = 2 * 5_000_000_000      # 5 s, in the doubled nanoseconds of 2 tau
GAP2 = 2 * 2_000_000_000         # G = 2,000 ms, likewise
MAP_WIDTH = 5_000                # ns: a map sample or an exchange point wider than this was interrupted between its reads
MAP_GAP = 50_000_000             # ns: the largest distance between two valid samples of the used range of a map
KINK_BASE = 4_000_000            # ns: the slopes of the kink term are read over at least this much (E12.7)
AGREED = []                      # the full names of the keys that were compared with a toolkit value and are equal (Addendum F4)
PERCENTILES = (("latency_p50_ms", "lat", 500), ("latency_p90_ms", "lat", 900), ("latency_p99_ms", "lat", 990),
               ("latency_p99_9_ms", "lat", 999), ("rxpart_p50_ms", "part", 500), ("rxpart_p99_ms", "part", 990))


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


def track(probes):
    """(the exchanges in the order of tau, their anchors); an exchange is (2 tau, 2 theta, delta, t2 + t3, seq)."""
    ex = sorted(((p["t1_ns"] + p["t4_ns"], (p["t2_ns"] - p["t1_ns"]) - (p["t4_ns"] - p["t3_ns"]),
                  (p["t4_ns"] - p["t1_ns"]) - (p["t3_ns"] - p["t2_ns"]), p["t2_ns"] + p["t3_ns"], p["seq"]) for p in probes),
                key=lambda e: e[0])
    best = {}
    for e in ex:
        w = (e[0] - ex[0][0]) // WINDOW2
        if w not in best or e[2] < best[w][2]:      # strictly smaller: the earliest one stays on a tie
            best[w] = e
    return ex, [best[w] for w in sorted(best)]


def subtractor(anchors):
    """A function (value, t) -> value - theta(t) in ns, for whole numbers value and t (a time on clock A)."""
    tau2, theta2 = [a[0] for a in anchors], [a[1] for a in anchors]

    def minus(value, t):
        x = 2 * t
        if x <= tau2[0] or x >= tau2[-1]:
            return (2 * value - theta2[0 if x <= tau2[0] else -1]) / 2
        k = bisect_right(tau2, x) - 1
        d = tau2[k + 1] - tau2[k]
        return (2 * value * d - theta2[k] * d - (theta2[k + 1] - theta2[k]) * (x - tau2[k])) / (2 * d)
    return minus


def pct(x, per_mille):
    """(percentile of type 7 of the sorted values x: linear between the order statistics around (n - 1) p; the number
    of samples above it)."""
    i, rest = divmod((len(x) - 1) * per_mille, 1000)
    q = x[i] + rest / 1000 * (x[min(i + 1, len(x) - 1)] - x[i])
    return q, len(x) - bisect_right(x, q)


def probe_faults(meta, probes):
    """Reasons why the probe file itself is invalid."""
    why = []
    if meta.get("exchanges_completed") != str(len(probes)):
        why.append(f"exchanges_completed={meta.get('exchanges_completed')} in the footer, {len(probes)} rows")
    bad = sum(p["t4_ns"] < p["t1_ns"] or p["t3_ns"] < p["t2_ns"] or p["t4_ns"] - p["t1_ns"] < p["t3_ns"] - p["t2_ns"] for p in probes)
    return why + ([f"{bad} exchange(s) with t4 before t1, t3 before t2 or a negative delta"] if bad else [])


def clock_track(probes):
    """The offset track of a probe file and what certifies it: the exchanges ex and the anchors (as track() gives them),
    b2 = the doubled bound of the anchors of the region (of all anchors when there are fewer than four and no region),
    region = [(delta, doubled cert)] of the exchanges from the second to the second-to-last anchor, cert2 = the doubled
    T(G), total2 = the doubled total bound. cert2 and total2 are None with fewer than four anchors or when no T exists."""
    ex, anchors = track(probes)
    tau2 = [a[0] for a in anchors]
    slope = [Fraction(b[1] - a[1], b[0] - a[0]) for a, b in zip(anchors, anchors[1:])]
    out = {"ex": ex, "anchors": anchors, "b2": max(a[2] for a in (anchors[1:-1] if len(anchors) >= 4 else anchors)), "region": [],
           "cert2": None, "total2": None}
    if len(anchors) < 4:
        return out
    lo, hi = tau2[1], tau2[-2]
    points = []         # (2 tau, delta, 2 cert) in the order of tau
    for e in ex:
        if lo <= e[0] <= hi:
            i = min(bisect_right(tau2, e[0]) - 1, len(slope) - 1)
            points.append((e[0], e[2], abs(anchors[i][1] + slope[i] * (e[0] - tau2[i]) - e[1]) + e[2]))
    out["region"] = [(delta, cert) for _, delta, cert in points]

    def covered(limit):     # do the exchanges certified to `limit`, with the two ends of the region, leave no distance above G?
        last = lo
        for x, _, cert in points:
            if cert <= limit:
                if x - last > GAP2:
                    return False
                last = x
        return hi - last <= GAP2
    certs = sorted({cert for _, _, cert in points})
    if hi - lo <= GAP2:
        out["cert2"] = Fraction(0)          # the two ends alone leave no such distance
    elif covered(certs[-1]):
        a, b = 0, len(certs) - 1            # the smallest certified distance that still covers the region
        while a < b:
            mid = (a + b) // 2
            a, b = (a, mid) if covered(certs[mid]) else (mid + 1, b)
        out["cert2"] = certs[a]
    if out["cert2"] is not None:
        out["total2"] = max(out["b2"], out["cert2"])
    return out


def own_keys(sender, receiver, probes, release="release_ns", arrival="rx_done_ns", to_a=None, to_b=None, maps2=0):
    """({key behind '.e2e.': own value}, the reasons why the run is invalid for E9, notes for the printed lines).
    Format 2: `probes` holds the raw stamps (raw_view), to_a and to_b carry a CLOCK_MONOTONIC stamp of board A or B onto
    the raw clock of that board (None for a stamp outside the map: such a PDU takes no part and is counted in the
    notes), and maps2, the doubled sum of the two map bounds in ns, is added to the bound that judges causality."""
    ct = clock_track(probes)
    ex, anchors, b2 = ct["ex"], ct["anchors"], ct["b2"]
    judge2 = b2 if ct["total2"] is None else ct["total2"]       # without a total bound the run is invalid whatever these counts say
    minus = subtractor(anchors)
    to_a, to_b = to_a or (lambda x: x), to_b or (lambda x: x)
    sent = {(r["stream"], r["seq"]): r for r in sender}
    ok = [r for r in receiver if r["result"] == "ok"]
    found = [(sent[r["stream"], r["seq"]], r) for r in ok if (r["stream"], r["seq"]) in sent]
    carried = [(s, to_a(s[release]), to_a(s["send_done_ns"]), to_b(r[arrival]), to_b(r["deliver_ns"])) for s, r in found]
    joined = [c for c in carried if None not in c]              # (sender row, release, send_done, arrival, delivery)
    lat = [(s["stream"], float(minus(dlv - rel, rel))) for s, rel, _, _, dlv in joined]
    t = {"lat": sorted(v for _, v in lat), "part": sorted(float(minus(dlv - snd, snd)) for _, _, snd, _, dlv in joined)}
    streams = {name: sorted(v for st, v in lat if st == name) for name in dict.fromkeys(r["stream"] for r in sender)}
    margin = [float(minus(arr - snd, snd)) for _, _, snd, arr, _ in joined]
    first, last = to_a(min(r[release] for r in sender)) if sender else None, to_b(max(r["deliver_ns"] for r in ok)) if ok else None
    steps = [b[0] - a[0] for a, b in zip(ex, ex[1:])]
    delays = sorted(e[2] for e in ex)
    n, sx, sy = len(anchors), sum(a[0] for a in anchors), sum(a[1] for a in anchors)
    den = n * sum(a[0] * a[0] for a in anchors) - sx * sx
    outside = sum(cert - delta > delta + judge2 for delta, cert in ct["region"])      # |track - theta| > delta / 2 + total, doubled
    k = {"n": len(joined), "latency_mean_ms": math.fsum(t["lat"]) / len(joined) / 1e6 if joined else None,
         **{name: pct(t[which], pm)[0] / 1e6 if joined else None for name, which, pm in PERCENTILES},
         "latency_max_ms": t["lat"][-1] / 1e6 if joined else None, "rxpart_max_ms": t["part"][-1] / 1e6 if joined else None,
         "offset_bound_us": b2 / 2000, "offset_cert_us": None if ct["cert2"] is None else float(ct["cert2"] / 2000),
         "offset_bound_total_us": None if ct["total2"] is None else float(ct["total2"] / 2000),
         "exchanges_outside": outside, "anchors": n, "probes_completed": len(ex),
         "probe_delay_min_us": delays[0] / 1000, "probe_delay_p50_us": pct(delays, 500)[0] / 1000,
         "probe_gap_max_ms": max(steps) / 2e6 if steps else None,
         "drift_ppm": (n * sum(a[0] * a[1] for a in anchors) - sx * sy) * 1_000_000 / den if den else None,
         "causality_min_us": min(margin) / 1000 if margin else None,
         "causality_violations": sum(2 * m < -(judge2 + maps2) for m in margin)}
    if len(streams) > 1:
        for name, x in streams.items():     # a stream without a delivered PDU has n = 0 and no latency key
            k.update({f"stream{name}.n": len(x), f"stream{name}.latency_max_ms": x[-1] / 1e6 if x else None,
                      **{f"stream{name}.latency_{label}_ms": pct(x, pm)[0] / 1e6 if x else None for label, pm in (("p50", 500), ("p99", 990), ("p99_9", 999))}})
    why = []
    if not steps or k["probe_gap_max_ms"] > 1000:
        why.append(f"probe_gap_max_ms = {k['probe_gap_max_ms']}: above 1000, or fewer than two exchanges")
    if n < 4:
        why.append(f"{n} anchors, fewer than four")
    if first is not None and n > 1 and anchors[1][0] > 2 * first:
        why.append("fewer than two anchors at or before the first release")
    if last is not None and n > 1 and anchors[-2][3] < 2 * last:
        why.append("fewer than two anchors at or after the last delivery")
    if n >= 4 and ct["cert2"] is None:
        why.append("no T(2 s): the exchanges of the region leave a distance above 2,000 ms")
    elif n >= 4 and k["offset_bound_total_us"] > 100:
        why.append(f"offset_bound_total_us = {k['offset_bound_total_us']}, above 100")
    if outside:
        why.append(f"exchanges_outside = {outside}")
    if k["causality_violations"]:
        why.append(f"causality_violations = {k['causality_violations']}")
    if any(s["send_done_ns"] == 0 for s, _ in found):
        why.append(f"{sum(s['send_done_ns'] == 0 for s, _ in found)} ok row(s) whose sender row has send_done_ns = 0")
    if not joined:
        why.append("no joined PDU")
    notes = {"ok rows without a sender row": len(ok) - len(found), "ok rows that repeat a job": len(found) - len({id(s) for s, _ in found}),
             "anchor seq": [a[4] for a in anchors], "region": len(ct["region"]), "total2": ct["total2"], "not carried": len(found) - len(joined),
             "per stream": {name: (len(x), pct(x, 500)[0] / 1e6, pct(x, 990)[0] / 1e6, x[-1] / 1e6) for name, x in streams.items() if x},
             "held back": [name for name, which, pm in PERCENTILES if joined and pct(t[which], pm)[1] < 10]}
    return k, why, notes


def raw_view(probes):
    """The exchanges of a format-2 probe file with their raw stamps in the place of the monotonic reads (E3)."""
    return [{"seq": p["seq"], "t1_ns": p["t1r_ns"], "t2_ns": p["t2r_ns"], "t3_ns": p["t3r_ns"], "t4_ns": p["t4r_ns"]} for p in probes]


def clock_map(rows):
    """The valid samples of a clock_map file in the order of the file, each (mono, 2 m, raw2 - raw1, held) with
    m = mono - (raw1 + raw2) / 2. A sample is valid when 0 <= raw2 - raw1 <= 5,000 ns; held: the rows next to it in the
    file are both valid, so it takes part in the hold-out (E11 a)."""
    ok = [0 <= s["raw2_ns"] - s["raw1_ns"] <= MAP_WIDTH for s in rows]
    return [(s["mono_ns"], 2 * s["mono_ns"] - s["raw1_ns"] - s["raw2_ns"], s["raw2_ns"] - s["raw1_ns"], 0 < i < len(rows) - 1 and ok[i - 1] and ok[i + 1])
            for i, s in enumerate(rows) if ok[i]]


def map_reader(valid):
    """(m2, to_raw) for the valid samples of a board: m2(x) = the doubled m at the abscissa x on the straight line between
    the two samples around x; to_raw(x) = x - m(x), the stamp x on the raw clock. Both exact; None before the first and
    after the last sample, and everywhere when the monotonic reads of the samples do not increase."""
    xs = [v[0] for v in valid]
    rising = all(p < q for p, q in zip(xs, xs[1:]))

    def m2(x):
        if not rising or not xs or x < xs[0] or x > xs[-1]:
            return None
        i = bisect_right(xs, x) - 1
        return valid[i][1] if xs[i] == x else valid[i][1] + Fraction(valid[i + 1][1] - valid[i][1], xs[i + 1] - xs[i]) * (x - xs[i])

    def to_raw(x):
        m = m2(x)
        return None if m is None else x - Fraction(m) / 2
    return m2, to_raw


def map_keys(rows, footer, stamps, points, least):
    """E4 for one board: ({key behind 'map_<x>.': own value}, the reasons why the run is not a result, the doubled map
    bound in ns or None). rows, footer: its clock_map file; stamps: the CLOCK_MONOTONIC stamps of this board that are
    carried onto its raw clock; points: (monotonic read, doubled own reading of m, width) of its exchange points; least:
    the number of check points a run needs."""
    valid = clock_map(rows)
    xs = [v[0] for v in valid]
    k = {"samples": len(rows), "samples_invalid": len(rows) - len(valid),
         **dict.fromkeys(("gap_max_ms", "holdout_us", "kink_us", "half_us", "bound_us", "check_n", "check_max_us", "check_violations"))}
    why = [f"samples_dropped={footer.get('samples_dropped')}"] if footer.get("samples_dropped") != "0" else []
    if footer.get("samples") != str(len(rows)):
        why.append(f"samples={footer.get('samples')} in the footer, {len(rows)} rows")
    if any(p >= q for p, q in zip(xs, xs[1:])):
        return k, why + ["the monotonic reads of the valid samples do not increase"], None
    if not stamps or not valid or min(stamps) < xs[0] or max(stamps) > xs[-1]:
        return k, why + ["a stamp before the first or after the last valid sample (or no stamp, or no sample)"], None
    lo, hi = bisect_right(xs, min(stamps)) - 1, bisect_left(xs, max(stamps))       # the used range, both ends included
    if not any(valid[i][3] for i in range(lo, hi + 1)):                            # E11 o: no hold-out can be formed
        return k, why + ["no sample of the used range has two valid neighbours"], None
    # a held sample has valid rows on both sides in the file: they are its neighbours here, inside the range or not
    hold2 = max(abs(valid[i][1] - valid[i - 1][1] - Fraction(valid[i + 1][1] - valid[i - 1][1], xs[i + 1] - xs[i - 1]) * (xs[i] - xs[i - 1]))
                for i in range(lo, hi + 1) if valid[i][3])
    if hi > lo and (xs[lo] - xs[0] < KINK_BASE or xs[-1] - xs[hi] < KINK_BASE):    # E12.7: no slope before the first or behind the last interval
        return k, why + ["an interval of the used range has no sample 4 ms before it or behind it in the file"], None

    # E12.1, E12.7, doubled: one rate change inside interval j (samples j and j + 1, length g) puts the line across it off by
    # up to |slope behind it - slope before it| x g / 4; each slope is read over at least 4 ms, from sample j back to the
    # nearest sample that far before it (i) and from sample j + 1 on to the nearest one that far behind it (n). The largest
    # term is kept as top / base in whole numbers (a fraction per interval costs seconds at 200,000 samples)
    top, base = 0, 1
    for j in range(lo, hi):
        i, n = bisect_right(xs, xs[j] - KINK_BASE) - 1, bisect_left(xs, xs[j + 1] + KINK_BASE)
        b, a = xs[j] - xs[i], xs[n] - xs[j + 1]
        num, den = abs((valid[n][1] - valid[j + 1][1]) * b - (valid[j][1] - valid[i][1]) * a) * (xs[j + 1] - xs[j]), 4 * a * b
        if num * base > top * den:
            top, base = num, den
    kink2 = Fraction(top, base)
    width = max(valid[i][2] for i in range(lo, hi + 1))
    bound2 = max(hold2, kink2) + width                                              # doubled: the larger of hold-out and kink term, + half-width
    m2 = map_reader(valid)[0]
    off = [(abs(v - m2(x)), w) for x, v, w in points if 0 <= w <= MAP_WIDTH and xs[lo] <= x <= xs[hi]]
    gap = max((xs[i + 1] - xs[i] for i in range(lo, hi)), default=0)
    k.update(gap_max_ms=gap / 1e6, holdout_us=float(hold2 / 2000), kink_us=float(kink2 / 2000), half_us=width / 2000, bound_us=float(bound2 / 2000), check_n=len(off),
             check_max_us=float(max(d for d, _ in off) / 2000) if off else None, check_violations=sum(d > bound2 + w for d, w in off))
    if gap > MAP_GAP:
        why.append(f"gap_max_ms = {k['gap_max_ms']}, above 50")
    if k["check_violations"]:
        why.append(f"check_violations = {k['check_violations']}")
    if len(off) < least:
        why.append(f"check_n = {len(off)}, fewer than {least}")
    return k, why, bound2


def adjustment(valid):
    """E6 for one board: {key behind 'clock_<x>.': own value} from its valid samples. Windows of 1 s of abscissa from the
    first sample; a window whose first and last sample are at least 0.8 s apart has the rate change of m / change of
    abscissa, in ppm (positive: CLOCK_MONOTONIC runs faster than the raw clock)."""
    k = dict.fromkeys(("adj_ppm_min", "adj_ppm_max", "adj_ppm_median", "adj_step_ppm_max", "adj_offset_range_us", "adjusted"))
    if not valid:
        return k
    windows = {}
    for x, m, *_ in valid:
        windows.setdefault((x - valid[0][0]) // 1_000_000_000, []).append((x, m))
    rates = [Fraction(w[-1][1] - w[0][1], 2 * (w[-1][0] - w[0][0])) * 10**6 for _, w in sorted(windows.items()) if w[-1][0] - w[0][0] >= 800_000_000]
    k.update(adj_offset_range_us=(max(v[1] for v in valid) - min(v[1] for v in valid)) / 2000, adjusted=0)
    if rates:
        k.update(adj_ppm_min=float(min(rates)), adj_ppm_max=float(max(rates)), adj_ppm_median=float(median(rates)),
                 adj_step_ppm_max=float(max((abs(q - p) for p, q in zip(rates, rates[1:])), default=Fraction(0))),
                 adjusted=int(max(rates) - min(rates) > 1))
    return k


def own_keys2(sender, receiver, probes, maps, release="release_ns", arrival="rx_done_ns", least=100):
    """Probe format 2 (Addendum E): ({key behind '.e2e.': own value}, the reasons why the run is not a result, notes).
    probes: the rows of clock_probe.csv with the monotonic reads, the raw stamps and the widths; maps: {'a': (footer,
    rows of clock_map_a.csv), 'b': ...}; least: check points a board needs (100 in a harness run, 20 in the gateway run)."""
    by = {(r["stream"], r["seq"]): r for r in sender}
    ok = [r for r in receiver if r["result"] == "ok"]
    mine = [(by[r["stream"], r["seq"]], r) for r in ok if (r["stream"], r["seq"]) in by]
    # every CLOCK_MONOTONIC stamp that enters a figure or a rule: those of the delivered PDUs, the first release, the last delivery
    stamps = {"a": [s[c] for s, _ in mine for c in (release, "send_done_ns")] + ([min(r[release] for r in sender)] if sender else []),
              "b": [r[c] for _, r in mine for c in (arrival, "deliver_ns")] + ([max(r["deliver_ns"] for r in ok)] if ok else [])}
    # the own reading of each exchange point: monotonic read, doubled (monotonic - mean of its two raw reads), width. The raw
    # stamp is the second read before a send (points 1 and 3) and the first read after a receive (points 2 and 4).
    points = {"a": [(p["t1_ns"], 2 * (p["t1_ns"] - p["t1r_ns"]) + p["w1_ns"], p["w1_ns"]) for p in probes]
              + [(p["t4_ns"], 2 * (p["t4_ns"] - p["t4r_ns"]) - p["w4_ns"], p["w4_ns"]) for p in probes],
              "b": [(p["t2_ns"], 2 * (p["t2_ns"] - p["t2r_ns"]) - p["w2_ns"], p["w2_ns"]) for p in probes]
              + [(p["t3_ns"], 2 * (p["t3_ns"] - p["t3r_ns"]) + p["w3_ns"], p["w3_ns"]) for p in probes]}
    extra, why, to, maps2 = {}, [], {}, 0
    for x in "ab":
        footer, rows = maps[x]
        k, reasons, bound2 = map_keys(rows, footer, stamps[x], points[x], least)
        valid = clock_map(rows)
        extra.update({f"map_{x}.{name}": v for name, v in k.items()})
        extra.update({f"clock_{x}.{name}": v for name, v in adjustment(valid).items()})
        why += [f"map of board {x}: {r}" for r in reasons]
        to[x], maps2 = map_reader(valid)[1], None if maps2 is None or bound2 is None else maps2 + bound2
    k, reasons, notes = own_keys(sender, receiver, raw_view(probes), release, arrival, to["a"], to["b"], maps2 or 0)
    total = None if notes["total2"] is None or maps2 is None else float((notes["total2"] + maps2) / 2000)
    widths = sorted(p[f"w{i}_ns"] for p in probes for i in "1234")
    # diagnostic: the format-1 definitions on the monotonic columns and the stamps as they are
    mono, mono_why, _ = own_keys(sender, receiver, probes, release, arrival)
    verdict = int(not mono_why and not probe_faults({"exchanges_completed": str(len(probes))}, probes))
    k.update(bound_total_us=total, probe_format=2, probe_width_p50_ns=float(pct(widths, 500)[0]), probe_width_max_ns=widths[-1], **extra)
    k.update({"mono.offset_bound_total_us": mono["offset_bound_total_us"], "mono.verdict": verdict,
              "mono.latency_p50_diff_us": (mono["latency_p50_ms"] - k["latency_p50_ms"]) * 1000
              if verdict and mono["latency_p50_ms"] is not None and k["latency_p50_ms"] is not None else None})
    if total is not None and total > 100:
        reasons.append(f"bound_total_us = {total}, above 100")
    return k, reasons + why, notes


def identity(meta, maps):
    """E12.2, the reasons why the three probe files do not belong together or are not what E2 specifies. meta: the
    header of clock_probe.csv; maps: {'a': (header and footer of clock_map_a.csv, its rows), 'b': ...}."""
    why = []
    for x, (m, _) in maps.items():
        want = {"role": x, "host": meta.get(f"host_{x}"), "commit": meta.get("commit"), "clock": "CLOCK_MONOTONIC", "clock_raw": "CLOCK_MONOTONIC_RAW", "interval_ms": "5"}
        why += [f"clock_map_{x}.csv: {name}={m.get(name)}, not {v}" for name, v in want.items() if v is None or m.get(name) != v]
    return why + [f"clock_probe.csv: {name}={meta.get(name)}, not {v}" for name, v in (("clock", "CLOCK_MONOTONIC"), ("clock_raw", "CLOCK_MONOTONIC_RAW")) if meta.get(name) != v]


def format_fault(meta, probes):
    """Why the 'format=' header line of a probe file disagrees with its columns (E11 o: not a result), or None."""
    fmt, raw = meta.get("format", "1"), all(f"{c}_ns" in probes[0] for c in ("t1r", "t2r", "t3r", "t4r", "w1", "w2", "w3", "w4"))
    return None if (fmt == "2") == raw else f"the header says format {fmt}, the columns are {'those' if raw else 'not those'} of format 2"


def refused(meta, probes):
    """Why a probe file is not read for latency: its header disagrees with its columns, or its format is not 2
    (Addendum E: no raw stamps); None for a file of format 2."""
    fmt, fault = meta.get("format", "1"), format_fault(meta, probes)
    if fault:
        return f"clock_probe.csv: {fault}"
    return None if fmt == "2" else f"clock_probe.csv is of format {fmt}: it has no raw stamps and is refused for latency (Addendum E)"


def pairs(path):
    """{key: value} of a file of key=value lines."""
    return dict(line.split("=", 1) for line in Path(path).read_text(errors="replace").splitlines() if "=" in line)


def background(bg, source, sink, first_release, last_send):
    """(the reasons for FAIL by the rule of DATA_SCHEMA.md, what in the record does not fit its own values or the two
    ends' files) of a background_traffic.txt; all arguments as text dicts, the two instants in ns of clock A."""
    n = {k: int(bg[k]) for k in ("bytes_sent", "bytes_received", "rate_offered_bit_s", "rate_achieved_bit_s", "source_duration_ns",
                                 "sink_duration_ns", "source_first_byte_ns", "source_last_byte_ns", "sink_first_byte_ns", "sink_last_byte_ns")}
    fail = []
    if n["source_duration_ns"] <= 0 or n["bytes_sent"] * 8 * 10**9 * 100 < 95 * n["rate_offered_bit_s"] * n["source_duration_ns"]:
        fail.append("achieved below 95 % of offered")
    if n["bytes_received"] == 0 or n["bytes_received"] > n["bytes_sent"]:
        fail.append("nothing received or more received than sent")
    if n["source_first_byte_ns"] > first_release:
        fail.append("the flow began after the first release")
    if n["source_last_byte_ns"] < last_send:
        fail.append("the flow ended before the last send_done_ns")
    faults = []
    if n["source_duration_ns"] > 0 and abs(n["rate_achieved_bit_s"] - n["bytes_sent"] * 8 * 10**9 / n["source_duration_ns"]) > 1:
        faults.append("rate_achieved_bit_s is not bytes_sent x 8 / source duration")
    for end, own in (("source", source), ("sink", sink)):
        if n[f"{end}_duration_ns"] != n[f"{end}_last_byte_ns"] - n[f"{end}_first_byte_ns"]:
            faults.append(f"{end}_duration_ns is not last byte - first byte")
        mine = (bg["bytes_sent" if end == "source" else "bytes_received"], bg[f"{end}_first_byte_ns"], bg[f"{end}_last_byte_ns"])
        if mine != (own.get("bytes"), own.get("first_byte_ns"), own.get("last_byte_ns")):
            faults.append(f"bytes, first or last byte of the {end} are not those of its own file")
    return fail, faults


def close(key, a, b, ns=0.001):
    """Counts exactly; drift_ppm to nine digits; the adjustment rates to 1e-6 ppm; times to `ns` nanoseconds in the unit
    of the key (_ms, _us, _ns); each or nine digits relative."""
    if isinstance(a, int):
        return float(b) == a
    if key == "drift_ppm":
        return math.isclose(a, float(b), rel_tol=1e-9, abs_tol=1e-12)
    if "_ppm" in key:
        return math.isclose(a, float(b), rel_tol=1e-9, abs_tol=1e-6)
    return math.isclose(a, float(b), rel_tol=1e-9, abs_tol=ns / (1e6 if key.endswith("_ms") else 1e3 if key.endswith("_us") else 1))


def compare(head, own, theirs, ns=0.001):
    """Prints each difference; returns their number. A key the toolkit lacks is a difference; an own None says the
    toolkit must not have the key."""
    bad = 0
    for key, a in own.items():
        b = theirs.get(key)
        if a is None and b is None:
            continue
        if a is None or b is None or not close(key, a, b, ns):
            bad += 1
            print(f"DIFF {head}{key}: own {a}, toolkit {b}")
        else:
            AGREED.append(head + key)
    return bad


def self_test():
    assert pct(list(range(100)), 900) == (89.1, 10) and pct(list(range(91)), 900) == (81, 9) and pct([5] * 30, 500) == (5, 0)
    assert pct(list(range(20)), 500) == (9.5, 10) and pct([7], 999) == (7, 0)
    # Known answers: clock B = clock A + THETA0 + 100 ppm of the time since T0 (whole ns on a grid of 10,000 ns), so that
    # the base case is the ruling's "constant drift of 100 ppm"; from step_at on the clock runs 100 ppm faster still.
    T0, THETA0 = 120_000_000_000_000, -19_958_353_450_209

    def clock(step_at=None, ppm=100):
        def read_b(t):
            assert (t - T0) % 10_000 == 0 or (ppm == 0 and step_at is None)
            return t + THETA0 + (t - T0) * ppm // 1_000_000 + (max(0, t - step_at) // 10_000 if step_at else 0)
        return read_b

    b = clock()

    def exchange(i, there=50_000, back=None, interval=100_000_000):
        back, t1 = there if back is None else back, T0 + i * interval
        return {"seq": i, "t1_ns": t1, "t2_ns": b(t1 + there), "t3_ns": b(t1 + there + 50_000), "t4_ns": t1 + there + 50_000 + back}

    def probe_run(best=(0, 2, 50, 100, 150, 200), n=220, slow=lambda i: i % 10 == 9, asym=37, interval=100_000_000):
        """Exchanges: 40 us each way for those in `best` (the anchors of their windows), 150 us for the slow ones, one of
        50 us there and 450 us back, 50 us each way for the rest."""
        return [exchange(i, 40_000, None, interval) if i in best else exchange(i, 50_000, 450_000, interval) if i == asym
                else exchange(i, 150_000, None, interval) if slow(i) else exchange(i, 50_000, None, interval) for i in range(n)]

    def pdu(j, release, latency, wire=100_000, stream="0"):
        send = release + 1_500_000
        return ({"stream": stream, "seq": j, "release_ns": release, "send_done_ns": send},
                {"stream": stream, "seq": j, "result": "ok", "rx_done_ns": b(send + wire), "deliver_ns": b(release + latency)})

    def pdu_run(first=7_000_000_000):    # 30 PDUs 100 ms apart with latencies of 2.00 to 3.45 ms
        made = [pdu(j, T0 + first + j * 100_000_000, 2_000_000 + 50_000 * j) for j in range(30)]
        return [m[0] for m in made], [m[1] for m in made]

    # 22 s of exchanges; the anchors are at 0, 5, 10, 15 and 20 s (0 and 2 tie); the PDUs lie between the second and the third
    probes = probe_run()
    ex, anchors = track(list(reversed(probes)))
    assert [a[4] for a in anchors] == [0, 50, 100, 150, 200] and all(a[2] == 79_995 for a in anchors)          # the earliest on a tie
    for tau2, theta2, delta, _, seq in ex:      # every estimate within delta / 2 of the truth; the asymmetric one is far off
        error2 = theta2 - (2 * THETA0 + (tau2 - 2 * T0) * 100 / 1_000_000)
        assert abs(error2) <= delta and error2 == (-400_040 if seq == 37 else 0) and (seq != 37 or delta == 499_995)
    tx, rx = pdu_run()
    pdus = list(zip(tx, rx))
    rx = rx + [{"stream": "0", "seq": 3, "result": "auth_fail", "rx_done_ns": 1, "deliver_ns": 0}]     # not ok: no sample
    k, why, notes = own_keys(tx, rx, probes)
    # KNOWN ANSWER, constant drift of 100 ppm: valid. theta(t) is exact between anchors on the true line, so each value is the
    # true interval times (1 + 100 ppm); the exchanges of 50 us each way certify the track every 0.1 s to their own delta / 2.
    assert why == [] and k["n"] == 30 and k["anchors"] == 5 and k["probes_completed"] == 220 and notes["anchor seq"] == [0, 50, 100, 150, 200]
    assert math.isclose(k["latency_mean_ms"], 2.7252725, rel_tol=1e-13) and k["latency_p50_ms"] == 2.7252725 and k["latency_max_ms"] == 3.450345
    for name, ns in (("latency_p90_ms", 3_305_330.5), ("latency_p99_ms", 3_435_843.55), ("latency_p99_9_ms", 3_448_894.855), ("rxpart_p99_ms", 1_935_693.55)):
        assert math.isclose(k[name], ns / 1e6, rel_tol=1e-13)
    assert notes["held back"] == ["latency_p90_ms", "latency_p99_ms", "latency_p99_9_ms", "rxpart_p99_ms"]     # fewer than ten above
    assert k["rxpart_p50_ms"] == 1.2251225 and k["rxpart_max_ms"] == 1.950195
    assert k["causality_min_us"] == 100.01 and k["causality_violations"] == 0 and k["offset_bound_us"] == 39.9975
    assert math.isclose(k["drift_ppm"], 100, rel_tol=1e-13) and k["probe_delay_min_us"] == 79.995 and k["probe_delay_p50_us"] == 99.995
    assert k["probe_gap_max_ms"] == 100.2
    assert k["offset_cert_us"] == 49.9975 and k["offset_bound_total_us"] == 49.9975 and k["exchanges_outside"] == 0 and "stream0.n" not in k
    assert "offset_interp_us" not in k
    other = pdu(0, T0 + 8_000_000_000, 9_000_000, stream="1")            # a second stream that uses seq 0 again: joined on stream and seq
    k, why, _ = own_keys(tx + [other[0]], [other[1]] + rx, probes)
    assert why == [] and k["n"] == 31 and k["latency_max_ms"] == 9.0009 and k["rxpart_max_ms"] == 7.50075
    assert _["per stream"]["1"] == (1, 9.0009, 9.0009, 9.0009) and _["per stream"]["0"][0] == 30 and _["per stream"]["0"][3] == 3.450345
    assert k["stream1.n"] == 1 and k["stream1.latency_p99_9_ms"] == 9.0009 and k["stream0.n"] == 30 and k["stream0.latency_p50_ms"] == 2.7252725
    assert k["stream0.latency_max_ms"] == 3.450345 and math.isclose(k["stream0.latency_p99_ms"], 3.43584355, rel_tol=1e-13)
    k, why, _ = own_keys(tx + [other[0]], rx, probes)                    # the second stream of the sender's file delivers nothing
    assert why == [] and k["n"] == 30 and k["stream1.n"] == 0 and k["stream1.latency_p50_ms"] is None and k["stream0.n"] == 30
    k, why, notes = own_keys(tx, rx + [rx[4]], probes)                   # a second ok row of a job counts twice
    assert why == [] and k["n"] == 31 and notes["ok rows that repeat a job"] == 1
    # the gateway's columns: submit_ns for the release, verify_done_ns (400 us after the send here) for the arrival
    gw_tx = [{"stream": s["stream"], "seq": s["seq"], "submit_ns": s["release_ns"], "send_done_ns": s["send_done_ns"]} for s in tx]
    gw_rx = [{**r, "rx_done_ns": 0, "verify_done_ns": b(s["send_done_ns"] + 400_000)} for s, r in pdus]
    k, why, _ = own_keys(gw_tx, gw_rx, probes, release="submit_ns", arrival="verify_done_ns")
    assert why == [] and k["latency_p50_ms"] == 2.7252725 and k["rxpart_max_ms"] == 1.950195 and k["causality_min_us"] == 400.04
    # Coverage (amendment 1a): two anchors at or before the first release, two at or after the last delivery
    few = "fewer than two anchors at or "
    inside = pdu(99, T0 + 3_000_000_000, 2_000_000)                      # between the first and the second anchor: the end segment is not used
    assert own_keys(tx + [inside[0]], rx + [inside[1]], probes)[1] == [few + "before the first release"]
    third = pdu(98, T0 + 12_000_000_000, 2_000_000)                      # between the third and the fourth anchor: still two anchors behind it
    assert own_keys(tx + [third[0]], rx + [third[1]], probes)[1] == []
    late = pdu(98, T0 + 17_000_000_000, 2_000_000)                       # behind the fourth of five anchors
    assert own_keys(tx + [late[0]], rx + [late[1]], probes)[1] == [few + "after the last delivery"]
    assert own_keys(tx, rx + [late[1]], probes)[1] == [few + "after the last delivery"]              # an ok row, joined or not
    assert own_keys(tx, rx, probes[:150])[1] == ["3 anchors, fewer than four", few + "after the last delivery"]
    beyond = pdu(97, T0 + 21_000_000_000, 2_000_000)                     # behind the last anchor the offset is held: 100 ppm of 1.001935 s too much
    assert subtractor(anchors)(beyond[1]["deliver_ns"] - beyond[0]["release_ns"], beyond[0]["release_ns"]) == 2_100_193.5
    # Causality against the TOTAL bound (amendment 3b), here 49.9975 us while the anchors' bound is 39.9975 us
    for wire, margin, count in ((-300_000, -300.03, 1), (-50_000, -50.005, 1), (-40_000, -40.004, 0)):
        odd = pdu(97, T0 + 10_500_000_000, 2_000_000, wire=wire)
        k, why, _ = own_keys(tx + [odd[0]], rx + [odd[1]], probes)
        assert k["causality_min_us"] == margin and k["causality_violations"] == count and why == [f"causality_violations = {count}"] * count
    # the asymmetric exchange as the only one of its window: it is an anchor, the bound says so, and every latency is within the bound
    k, why, _ = own_keys(tx, rx, [exchange(i, 40_000) for i in (0, 100, 150, 200)] + [exchange(50, 50_000, 450_000)])
    assert k["anchors"] == 5 and k["offset_bound_us"] == 249.9975 and k["offset_cert_us"] is None and any("no T(2 s)" in w for w in why)
    assert 1000 < abs(k["latency_max_ms"] * 1e6 - 3_450_345) <= 249_997.5       # wrong by much, and by no more than the bound
    k, why, _ = own_keys(tx, rx, [exchange(i, 40_000) for i in (0, 13, 50, 100)] + [exchange(30, 50_000, 450_000)])
    assert k["anchors"] == 3 and k["offset_bound_us"] == 39.9975                 # with a better exchange in the window it is not used
    # "exceeds" is strict: a total bound of exactly 100 us and a probe gap of exactly 1,000 ms pass, 1 ns more of bound does not
    k, why, _ = own_keys(tx, rx, [exchange(i, 100_000, 100_005) for i in range(0, 220, 10)])
    assert k["offset_bound_us"] == k["offset_cert_us"] == k["offset_bound_total_us"] == 100.0 and k["probe_gap_max_ms"] == 1000.0 and why == []
    # the last window holds one exchange of 400 us each way: it is the last anchor whatever its delay, it only delimits and
    # enters no figure; the same exchange as the anchor of a window inside the region sets the bound
    k, why, notes = own_keys(tx, rx, probe_run(n=250) + [exchange(250, 400_000)])
    assert notes["anchor seq"] == [0, 50, 100, 150, 200, 250] and k["offset_bound_us"] == 39.9975 and k["offset_bound_total_us"] == 49.9975 and why == []
    k = own_keys(tx, rx, [exchange(i, 400_000) if 100 <= i < 150 else e for i, e in enumerate(probe_run(n=250))])[0]
    assert k["offset_bound_us"] == 399.9975
    assert own_keys(tx, rx, [exchange(i, 100_000, 100_007) for i in range(0, 220, 10)])[1] == ["offset_bound_total_us = 100.001, above 100"]
    # G is strict too: good exchanges exactly 2,000 ms apart certify the track to their 40 us; 2,100 ms apart they do not, and
    # the exchanges of 150 us each way between them are needed
    k, why, _ = own_keys(tx, rx, probe_run(best=range(0, 220, 20), slow=lambda i: True, asym=None))
    assert why == [] and k["offset_cert_us"] == 39.9975 and k["offset_bound_total_us"] == 39.9975
    k, why, _ = own_keys(tx, rx, probe_run(best=range(0, 220, 21), slow=lambda i: True, asym=None))
    assert k["offset_cert_us"] == 149.9975 and why == ["offset_bound_total_us = 149.9975, above 100"]
    # a gap of 1.4 s in the exchanges; no ok row; a sender row without send_done_ns; a single anchor has no drift
    assert any("probe_gap_max_ms" in w for w in own_keys(tx, rx, [p for p in probes if not 70 <= p["seq"] <= 82])[1])
    assert own_keys(tx, [], probes)[1] == ["no joined PDU"]
    assert any("send_done_ns = 0" in w for w in own_keys([{**tx[0], "send_done_ns": 0}] + tx[1:], rx, probes)[1])
    assert own_keys(tx, rx, probes[:20])[0]["drift_ppm"] is None
    # An offset that is 300 us off and comes back, which the anchors do not see. For one second: the exchanges of that second
    # contradict the track. For three seconds: the certified bound itself rises to 350 us. In the first segment, which is
    # not used, it is not counted (amendment 3a).
    def bumped(lo, hi):
        return [{**e, "t2_ns": e["t2_ns"] + 300_000, "t3_ns": e["t3_ns"] + 300_000} if lo <= e["seq"] <= hi else e for e in probes]
    k, why, _ = own_keys(tx, rx, bumped(80, 89))
    assert k["offset_cert_us"] == 49.9975 and k["exchanges_outside"] == 10 and why == ["exchanges_outside = 10"]
    k, why, _ = own_keys(tx, rx, bumped(60, 89))
    assert k["offset_cert_us"] == 349.9975 and k["exchanges_outside"] == 0 and why == ["offset_bound_total_us = 349.9975, above 100"]
    k, why, _ = own_keys(tx, rx, bumped(20, 29))
    assert k["exchanges_outside"] == 0 and why == []
    # KNOWN ANSWER, a 100 ppm step in the middle (7.5 s) of the 5 s segment from 5 s to 10 s: the line is 125 us off there; the
    # exchanges 1 s before and after the step are the best that leave no more than 2 s: T(2 s) is about 125 us, not a result
    b = clock(step_at=T0 + 7_500_050_000)
    k, why, _ = own_keys(*pdu_run(), probe_run())
    assert 124.9984 < k["offset_cert_us"] < 124.9985 and k["offset_bound_total_us"] == k["offset_cert_us"] and k["exchanges_outside"] == 0
    assert why == [f"offset_bound_total_us = {k['offset_cert_us']}, above 100"] and k["offset_bound_us"] == 39.9975
    # KNOWN ANSWER, a 100 ppm step at 15 s in a 9.9 s segment (10.0 s to 19.9 s) between two segments of 0.1 s: above 200 us, not a result
    b = clock(step_at=T0 + 15_000_050_000)
    k, why, notes = own_keys(*pdu_run(first=11_000_000_000), probe_run(best=(0, 99, 100, 199, 200, 250), n=300))
    assert notes["anchor seq"] == [0, 99, 100, 199, 200, 250] and 240 < k["offset_cert_us"] < 255 and why == [f"offset_bound_total_us = {k['offset_cert_us']}, above 100"]
    # The same step in the FIRST segment (at 2.3 s), PDUs released there: the line is 124.2 us off at the step, the region
    # behind the second anchor certifies 50 us. Not a result by the coverage rule alone.
    b = clock(step_at=T0 + 2_300_000_000)
    edge_tx, edge_rx = pdu_run(first=1_000_000_000)
    k, why, _ = own_keys(edge_tx, edge_rx, probe_run())
    assert why == [few + "before the first release"] and k["offset_bound_total_us"] == 49.995
    at_step = subtractor(track(probe_run())[1])(edge_rx[13]["deliver_ns"] - edge_tx[13]["release_ns"], edge_tx[13]["release_ns"])
    assert edge_tx[13]["release_ns"] == T0 + 2_300_000_000 and 124_199 < 2_650_530 - at_step < 124_200
    # KNOWN ANSWER, two anchors 101 ms and 2 us apart, constant offset (exchanges every 101 ms): valid; the 2 us show in T only
    b = clock(ppm=0)
    close_run = probe_run(best=(5, 99, 150, 200, 250), n=290, interval=101_000_000)
    close_run[100] = exchange(100, 42_000, 38_000, 101_000_000)          # as good as an anchor, and its estimate reads 2 us high
    k, why, notes = own_keys(*pdu_run(first=11_000_000_000), close_run)
    assert notes["anchor seq"] == [5, 99, 100, 150, 200, 250] and why == [] and 51.27 < k["offset_cert_us"] < 51.29 and k["offset_bound_us"] == 40.0
    # The probe's own tests. Same host: clock B is clock A, so theta = (there - back) / 2 and never beyond delta / 2 ...
    def same_host(i, lie=0):
        t1, there = T0 + i * 100_000_000, 40_000 + 10_000 * (i % 2)
        return {"seq": i, "t1_ns": t1, "t2_ns": t1 + there + lie, "t3_ns": t1 + there + 20_000 + lie, "t4_ns": t1 + there + 20_000 + 40_000}
    k, failed = probetest_keys({"iris": [same_host(i) for i in range(60)]}, None, None)
    assert failed == [] and k == {"zero.iris.exchanges": 60, "zero.iris.anchors": 2, "zero.iris.offset_bound_us": 40.0, "zero.iris.theta_beyond_half_delay.k": 0}
    k, failed = probetest_keys({"iris": [same_host(i, 500_000 if i == 3 else 0) for i in range(60)]}, None, None)     # ... unless a clock reading is wrong
    assert failed == [] and k["zero.iris.theta_beyond_half_delay.k"] == 1                                                # not an anchor: counted only
    assert probetest_keys({"iris": [same_host(i, 500_000 if i == 0 else 0) for i in range(60)]}, None, None)[1] != []    # an anchor: the test fails
    # two directions, a pure offset: the second probe has its client on B, 50 ms later; each track certifies 50 us

    def back_probe(i, lie=0):
        ta, way = T0 + i * 100_000_000 + 50_000_000, 40_000 if i % 50 == 0 else 150_000 if i % 10 == 9 else 50_000
        return {"seq": i, "t1_ns": b(ta), "t2_ns": ta + way + lie, "t3_ns": ta + way + 50_000 + lie, "t4_ns": b(ta + 2 * way + 50_000)}
    ab = probe_run(best=(0, 50, 100, 150, 200), asym=None)
    k, failed = probetest_keys({}, ab, [back_probe(i) for i in range(220)])
    # region anchors only (seq 50, 100, 150 of each track) at instants inside the other track's region: the first track's
    # anchor 50 lies 50 ms before the second track's region, the second track's anchor 150 50 ms behind the first's
    assert failed == [] and k == {"pair.anchors_compared": 4, "pair.theta_sum_max_us": 0.0, "pair.limit_us": 100.0}
    k, failed = probetest_keys({}, ab, [back_probe(i, 3_000) for i in range(220)])      # board A's clock read 3 us too far by the second probe
    assert failed == [] and k["pair.theta_sum_max_us"] == 3.0 and k["pair.limit_us"] == 100.0
    assert probetest_keys({}, ab, [back_probe(i, 300_000) for i in range(220)])[1] != []                               # above the limit
    assert probetest_keys({}, ab[:120], [back_probe(i) for i in range(220)])[0]["pair.limit_us"] is None               # three anchors: no total bound
    good = {"exchanges_completed": "220"}
    assert probe_faults(good, probes) == [] and len(probe_faults({}, probes)) == 1 and len(probe_faults({"exchanges_completed": "219"}, probes)) == 1
    assert len(probe_faults(good, probes[:219] + [{**probes[219], "t4_ns": probes[219]["t1_ns"] - 1}])) == 1
    assert close("n", 30, "30") and not close("n", 30, "31") and close("latency_p50_ms", 2.7250545, "2.7250545000004")   # 0.0004 ns
    assert not close("latency_p50_ms", 2.7250545, "2.72505451") and close("offset_bound_us", 49.9995, "49.9995004")      # 0.01 ns
    assert not close("offset_bound_us", 49.9995, "49.99951") and close("drift_ppm", 20.0, "20.00000001") and not close("drift_ppm", 20.0, "20.000001")
    # background flow: 50 Mbit/s offered, 6,250,000 bytes in 1 s, from before the first release to after the last send
    bg = {"rate_offered_bit_s": "50000000", "rate_achieved_bit_s": "50000000", "bytes_sent": "6250000", "bytes_received": "6250000",
          "source_duration_ns": "1000000000", "sink_duration_ns": "999000000", "source_first_byte_ns": "100", "source_last_byte_ns": "1000000100",
          "sink_first_byte_ns": "7", "sink_last_byte_ns": "999000007"}
    src, snk = {"bytes": "6250000", "first_byte_ns": "100", "last_byte_ns": "1000000100"}, {"bytes": "6250000", "first_byte_ns": "7", "last_byte_ns": "999000007"}
    assert background(bg, src, snk, 100, 1_000_000_100) == ([], [])                     # the limits themselves pass
    assert background(bg, src, snk, 99, 1_000_000_101)[0] == ["the flow began after the first release", "the flow ended before the last send_done_ns"]
    assert background({**bg, "bytes_sent": "5937500", "rate_achieved_bit_s": "47500000"}, {**src, "bytes": "5937500"}, snk, 100, 200)[0] == [
        "nothing received or more received than sent"]                                  # exactly 95 % is not below it
    assert background({**bg, "bytes_sent": "5937499"}, src, snk, 100, 200)[0][0] == "achieved below 95 % of offered"
    assert background({**bg, "bytes_received": "0"}, src, snk, 100, 200)[0] == ["nothing received or more received than sent"]
    assert len(background({**bg, "rate_achieved_bit_s": "49000000", "sink_duration_ns": "5"}, src, {**snk, "bytes": "1"}, 100, 200)[1]) == 3
    self_test_format2(T0, THETA0)
    print("self-test ok")


def self_test_format2(TA0, THETA0):
    """The known answers of Addendum E, E7 (numbers 1 to 8), on a synthetic run of 32 s. Raw clocks: board B's is 25 ppm
    slower than board A's. CLOCK_MONOTONIC: board A's = raw + CA; board B's = raw + CB, and when it is steered it gains
    1 ns in every 200 ns of its own reading (+5,000 ppm) for 10 s from the instant 10 s. Every read triple (raw,
    monotonic, raw) is 120 ns wide with the monotonic read in its middle."""
    TB0, CA, CB = TA0 + THETA0, 7_000_000_123, -3_000_000_456
    R1 = TB0 + 10_000_000_000 - 250_000              # board B's raw clock at the instant 10 s

    def raw_b(x):                                     # board B's raw clock x ns of board A's raw clock after TA0
        assert x % 40_000 == 0
        return TB0 + x - x // 40_000

    def foot(rows, dropped=0):
        return {"samples": str(len(rows)), "samples_dropped": str(dropped)}

    X9 = 15_002_400_000                               # known answer 9: the instant at which PDU 10 is delivered

    def run2(steered, gap=0):
        """With gap (ns; known answer 9, E12.1) board B's CLOCK_MONOTONIC gains 6,900 ns per ms of its own reading from
        the instant X9 on, and its map is 5 ms apart except for one gap of that length with X9 in its middle."""
        R9 = raw_b(X9)

        def mono_b(r):
            if gap:
                return r + CB if r <= R9 else R9 + CB + (r - R9) * 10_000 // 9_931
            return r + CB + (min(max(r - R1, 0), 9_950_000_000) // 199 if steered else 0)
        probes = []
        for i in range(320):                          # an exchange every 100 ms: 40 us each way, 40 us at the far end
            x = i * 100_000_000
            t1r, t2r, t3r, t4r = TA0 + x, raw_b(x + 40_000), raw_b(x + 80_000), TA0 + x + 120_000
            probes.append({"seq": i, "t1_ns": t1r - 60 + CA, "t2_ns": mono_b(t2r + 60), "t3_ns": mono_b(t3r - 60), "t4_ns": t4r + 60 + CA,
                           "t1r_ns": t1r, "t2r_ns": t2r, "t3r_ns": t3r, "t4r_ns": t4r, "w1_ns": 120, "w2_ns": 120, "w3_ns": 120, "w4_ns": 120})
        rows_a = [{"raw1_ns": TA0 + j * 5_000_000 - 60, "mono_ns": TA0 + j * 5_000_000 + CA, "raw2_ns": TA0 + j * 5_000_000 + 60} for j in range(6501)]
        rows_b = [{"raw1_ns": r - 60, "mono_ns": mono_b(r), "raw2_ns": r + 60} for r in (R1 + j * 4_975_000 for j in range(-2010, 4524))]
        if gap:                                       # samples by their abscissa a; m = CB up to the change, then 69 ns more per 10,000 ns of a
            grid = [R9 + CB - gap // 2 - i * 5_000_000 for i in range(3200, -1, -1)] + [R9 + CB + gap // 2 + i * 5_000_000 for i in range(3400)]
            rows_b = [{"raw1_ns": a - m - 60, "mono_ns": a, "raw2_ns": a - m + 60} for a in grid for m in [CB + max(a - R9 - CB, 0) * 69 // 10_000]]
        tx, rx = [], []
        for j in range(30):                           # a PDU every 400 ms from 11 s on; true latency 2.00 ms + 40 us x j
            x, latency = 11_000_000_000 + j * 400_000_000, 2_000_000 + 40_000 * j
            tx.append({"stream": "0", "seq": j, "release_ns": TA0 + x + CA, "send_done_ns": TA0 + x + 1_480_000 + CA})
            rx.append({"stream": "0", "seq": j, "result": "ok", "rx_done_ns": mono_b(raw_b(x + 1_600_000)), "deliver_ns": mono_b(raw_b(x + latency))})
        return tx, rx, probes, {"a": (foot(rows_a), rows_a), "b": (foot(rows_b), rows_b)}

    # 2. Steady clocks. On board B's raw clock a true latency L counts L x (1 - 25 ppm): 1,999,950 + 39,999 j ns.
    tx, rx, probes, maps = run2(False)
    k, why, notes = own_keys2(tx, rx, probes, maps)
    assert why == [] and k["n"] == 30 and k["anchors"] == 7 and k["probes_completed"] == 320 and notes["not carried"] == 0
    assert k["latency_p50_ms"] == 2.5799355 and k["latency_max_ms"] == 3.159921 and math.isclose(k["latency_mean_ms"], 2.5799355, rel_tol=1e-13)
    assert k["rxpart_max_ms"] == 1.679958 and k["causality_min_us"] == 119.997 and k["causality_violations"] == 0
    assert k["offset_bound_us"] == k["offset_cert_us"] == k["offset_bound_total_us"] == 40.0005 and math.isclose(k["drift_ppm"], -25, rel_tol=1e-12)
    assert k["bound_total_us"] == 40.1205 and k["probe_format"] == 2 and k["probe_width_p50_ns"] == 120.0 and k["probe_width_max_ns"] == 120
    for x, gap in (("a", 5.0), ("b", 4.975)):         # the map hold-out is 0: the bound is the 60 ns of half a triple
        assert {n: k[f"map_{x}.{n}"] for n in ("samples_invalid", "gap_max_ms", "holdout_us", "half_us", "bound_us", "check_max_us", "check_violations")} == {
            "samples_invalid": 0, "gap_max_ms": gap, "holdout_us": 0.0, "half_us": 0.06, "bound_us": 0.06, "check_max_us": 0.0, "check_violations": 0}
        assert {n: k[f"clock_{x}.{n}"] for n in ("adj_ppm_min", "adj_ppm_max", "adj_ppm_median", "adj_step_ppm_max", "adj_offset_range_us", "adjusted")} == {
            "adj_ppm_min": 0.0, "adj_ppm_max": 0.0, "adj_ppm_median": 0.0, "adj_step_ppm_max": 0.0, "adj_offset_range_us": 0.0, "adjusted": 0}       # 8.
    assert k["map_a.samples"] == 6501 and k["map_a.check_n"] == 233 and k["map_b.samples"] == 6534 and 228 <= k["map_b.check_n"] <= 236
    # the format-1 reading of the monotonic columns gives the same latencies here (the two constants cancel) and is valid
    assert k["mono.verdict"] == 1 and k["mono.latency_p50_diff_us"] == 0.0 and k["mono.offset_bound_total_us"] == 40.1205
    steady = k
    # 1. Board B's CLOCK_MONOTONIC steered by +5,000 ppm for 10 s: a result; every latency recovered (here to within 1 ns,
    # the rounding of the steered clock to whole ns); both map bounds below 20 us; by its monotonic columns not a result
    tx1, rx1, probes1, maps1 = run2(True)
    k, why, _ = own_keys2(tx1, rx1, probes1, maps1)
    assert why == [] and k["n"] == 30 and all(abs(k[n] - steady[n]) < 1e-6 for n in ("latency_p50_ms", "latency_max_ms", "latency_mean_ms", "rxpart_max_ms"))
    assert abs(k["causality_min_us"] - 119.997) < 1e-3 and k["offset_bound_total_us"] == 40.0005
    kink = 25 * 199 / 399                             # us: 5,000 ppm over one sample step, seen from the line through its two neighbours
    assert math.isclose(k["map_b.holdout_us"], kink, rel_tol=1e-12) and math.isclose(k["map_b.bound_us"], kink + 0.06, rel_tol=1e-12) and k["map_a.bound_us"] == 0.06
    assert k["map_b.bound_us"] < 20 and math.isclose(k["bound_total_us"], 40.0005 + 0.06 + kink + 0.06, rel_tol=1e-12) and k["bound_total_us"] < 100
    assert k["map_b.check_max_us"] < 1e-3 and k["map_b.check_violations"] == 0 and k["map_b.gap_max_ms"] == 5.0
    assert k["mono.verdict"] == 0 and k["mono.latency_p50_diff_us"] is None and k["mono.offset_bound_total_us"] > 100
    # E12.1 on even spacing: the kink term is 5,000 ppm x 5 ms / 4, below the hold-out, so the bound is the hold-out's
    assert k["map_b.kink_us"] == 6.25 and k["map_a.kink_us"] == 0.0 and steady["map_a.kink_us"] == steady["map_b.kink_us"] == 0.0
    # 9. (E12.1) a map 5 ms apart except for one gap of 30 ms, in the middle of which board B's CLOCK_MONOTONIC starts to gain
    # 6,900 ppm of its own reading: the line across the gap is 6,900 ppm x 30 ms / 4 = 51.75 us off at the change. PDU 10
    # is delivered at that instant: its latency reads 51.75 us short (the mean of 30 by 1.725 us), within the total bound
    k9, why9, _ = own_keys2(*run2(False, 30_000_000))
    assert why9 == [] and k9["map_b.kink_us"] == 51.75 and math.isclose(k9["map_b.holdout_us"], 103.5 / 7, rel_tol=1e-12) and k9["map_b.gap_max_ms"] == 30.0
    assert k9["map_b.bound_us"] == 51.81 and k9["map_a.kink_us"] == 0.0 and math.isclose(k9["bound_total_us"], 40.0005 + 0.06 + 51.81, rel_tol=1e-12)
    assert abs(k9["latency_mean_ms"] - (steady["latency_mean_ms"] - 0.001725)) < 2e-6 and all(abs(k9[n] - steady[n]) < 2e-6 for n in ("latency_p50_ms", "latency_max_ms"))
    assert 51.75 < k9["bound_total_us"] < 100 and k9["map_b.check_violations"] == 0
    k9, why9, _ = own_keys2(*run2(False, 49_000_000))   # a gap of 49 ms: 84.525 us, and with the offset bound of 40 us not a result
    assert k9["map_b.kink_us"] == 84.525 and k9["map_b.gap_max_ms"] == 49.0 and len(why9) == 1 and why9[0].startswith("bound_total_us = 124.6")
    # 10. (E12.7) steady clocks, read noise of 150 ns that changes sign from sample to sample, and one wake-up 12 ms late whose
    # two owed samples follow 2 us apart (samples 3000 to 3002 of board A). The slopes are read over at least 4 ms: the
    # interval of 17 ms before the late sample has 60 ppm x 17 ms / 4 = 0.255 us (a slope across the 2 us would give 637 us),
    # every sample lies 300 ns off the line through its neighbours, and the run is a result
    def noisy(j):
        r, n = TA0 + j * 5_000_000 + {3000: 12_000_000, 3001: 7_002_000, 3002: 2_004_000}.get(j, 0), 150 if j % 2 == 0 else -150
        return {"raw1_ns": r - n - 60, "mono_ns": r + CA, "raw2_ns": r - n + 60}
    rows10 = [noisy(j) for j in range(6501)]
    k10, why10, _ = own_keys2(tx, rx, probes, {**maps, "a": (foot(rows10), rows10)})
    assert why10 == [] and k10["map_a.kink_us"] == 0.255 and k10["map_a.holdout_us"] == 0.3 and k10["map_a.gap_max_ms"] == 17.0
    assert k10["map_a.bound_us"] == 0.36 and k10["bound_total_us"] == 40.4205 and k10["map_a.check_violations"] == 0 and k10["n"] == 30
    # 8. what the maps say about each clock: board A not adjusted, board B at +5,000 ppm, 50 ms worked off
    assert k["clock_a.adjusted"] == 0 and k["clock_a.adj_ppm_max"] == 0.0 and k["clock_b.adjusted"] == 1 and k["clock_b.adj_ppm_max"] == 5000.0
    assert k["clock_b.adj_ppm_min"] == 0.0 and k["clock_b.adj_ppm_median"] == 0.0 and k["clock_b.adj_offset_range_us"] == 50000.0
    assert 0 < k["clock_b.adj_step_ppm_max"] <= 5000.0
    # 3. a gap of 60 ms between valid samples inside the used range; a stamp 1 ms before the first valid sample
    rows_a = maps["a"][1]
    holed = [r for j, r in enumerate(rows_a) if not 3001 <= j <= 3011]
    k, why, _ = own_keys2(tx, rx, probes, {**maps, "a": (foot(holed), holed)})
    assert k["map_a.gap_max_ms"] == 60.0 and why == ["map of board a: gap_max_ms = 60.0, above 50"]
    late = [{"raw1_ns": TA0 + 11_001_000_000 - 60, "mono_ns": TA0 + 11_001_000_000 + CA, "raw2_ns": TA0 + 11_001_000_000 + 60}] + rows_a[2201:]
    k, why, notes = own_keys2(tx, rx, probes, {**maps, "a": (foot(late), late)})
    assert any("stamp before the first" in w for w in why) and k["n"] == 29 and notes["not carried"] == 1 and k["map_a.bound_us"] is None and k["bound_total_us"] is None
    early = rows_a[:4000]                             # ... and a stamp behind the last valid sample
    assert any("after the last valid sample" in w for w in own_keys2(tx, rx, probes, {**maps, "a": (foot(early), early)})[1])
    # 4. a sample 6,000 ns wide is not valid and is not used (its monotonic value here is nonsense): still a result
    rows_b = list(maps["b"][1])
    rows_b[3000] = {"raw1_ns": rows_b[3000]["raw1_ns"], "mono_ns": rows_b[3000]["mono_ns"] + 1_000_000, "raw2_ns": rows_b[3000]["raw1_ns"] + 6_000}
    k, why, _ = own_keys2(tx, rx, probes, {**maps, "b": (foot(rows_b), rows_b)})
    assert why == [] and k["map_b.samples_invalid"] == 1 and k["map_b.gap_max_ms"] == 9.95 and k["map_b.holdout_us"] == 0.0 and k["latency_p50_ms"] == 2.5799355
    rows_b[3000]["raw2_ns"] = rows_b[3000]["raw1_ns"] + 5_000                    # exactly 5,000 ns wide is valid: now the nonsense is used
    assert own_keys2(tx, rx, probes, {**maps, "b": (foot(rows_b), rows_b)})[0]["map_b.samples_invalid"] == 0
    # E11 a, b, e, o and E12.1 on seven samples 5 ms apart with m = 0, 0, 0, 1 us, 0, 0, 0: a sample takes part in the
    # hold-out when the rows next to it in the file are both valid, also when they lie outside the used range; every
    # interval of the range needs an interval on each side; limits are "not above"
    def tiny(stamps, wide=(), order=range(7)):
        rows = [{"raw1_ns": j * 5_000_000 - m, "mono_ns": j * 5_000_000, "raw2_ns": j * 5_000_000 - m + (6_000 if j in wide else 0)} for j, m in enumerate((0, 0, 0, 1_000, 0, 0, 0))]
        return map_keys([rows[j] for j in order], foot(rows), stamps, [], 0)
    span = [5_000_000, 25_000_000]                    # the used range: samples 1 to 5
    k, why, _ = tiny(span)                            # each of its four intervals: slopes 200 ppm apart x 5 ms / 4 = 0.25 us
    assert why == [] and k["holdout_us"] == 1.0 and k["kink_us"] == 0.25 and k["bound_us"] == 1.0
    assert tiny([15_000_000, 17_000_000])[0]["holdout_us"] == 1.0                                                        # range = samples 3 and 4
    k, why, _ = tiny(span, wide={2})                  # sample 3 has an invalid neighbour: samples 4 and 5 take part; an interval of 10 ms
    assert why == [] and k["holdout_us"] == 0.5 and k["kink_us"] == 0.5 and k["gap_max_ms"] == 10.0 and k["samples_invalid"] == 1
    assert tiny(span, order=(0, 2, 1, 3, 4, 5, 6))[1] == ["the monotonic reads of the valid samples do not increase"]
    assert tiny(span, wide={2, 4})[1] == ["no sample of the used range has two valid neighbours"]                        # E11 o
    assert tiny([1_000_000, 25_000_000])[1] == ["an interval of the used range has no sample 4 ms before it or behind it in the file"]   # E12.7
    five = [{"raw1_ns": x, "mono_ns": x, "raw2_ns": x} for x in (-50_000_000, 0, 50_000_000, 100_000_000, 150_000_000)]
    assert map_keys(five, foot(five), [1, 2], [], 0)[1] == []                                                            # a gap of exactly 50 ms passes
    assert map_keys(five[:2] + [{**five[2], "mono_ns": 50_000_001}] + five[3:], foot(five), [1, 2], [], 0)[1] == ["gap_max_ms = 50.000001, above 50"]
    assert map_keys(five[1:3], foot(five[1:3]), [1, 2], [], 0)[1] == ["no sample of the used range has two valid neighbours"]
    # E12.2: the three probe files belong together and are what E2 specifies; each departure is one reason
    head = {"commit": "c0ffee", "host_a": "iris", "host_b": "pi", "clock": "CLOCK_MONOTONIC", "clock_raw": "CLOCK_MONOTONIC_RAW", "interval_ms": "101"}
    ident = {x: ({"role": x, "host": h, "commit": "c0ffee", "clock": "CLOCK_MONOTONIC", "clock_raw": "CLOCK_MONOTONIC_RAW", "interval_ms": "5"}, []) for x, h in (("a", "iris"), ("b", "pi"))}
    assert identity(head, ident) == []
    for name, value, x in (("role", "a", "b"), ("host", "iris", "b"), ("commit", "decaf", "a"), ("clock", "CLOCK_REALTIME", "a"), ("clock_raw", "CLOCK_MONOTONIC", "a"), ("interval_ms", "10", "b")):
        assert identity(head, {**ident, x: ({**ident[x][0], name: value}, [])}) == [f"clock_map_{x}.csv: {name}={value}, not {ident[x][0][name]}"]
    assert identity({**head, "clock_raw": "X"}, ident) == ["clock_probe.csv: clock_raw=X, not CLOCK_MONOTONIC_RAW"]
    assert len(identity({n: v for n, v in head.items() if n != "commit"}, ident)) == 2 and len(identity(head, {**ident, "b": ({}, [])})) == 6
    # 5. one exchange point whose own reading is 50 us off the map: one violation, not a result
    spoilt = [{**e, "t2_ns": e["t2_ns"] + 50_000} if e["seq"] == 150 else e for e in probes]
    k, why, _ = own_keys2(tx, rx, spoilt, maps)
    assert k["map_b.check_violations"] == 1 and k["map_b.check_max_us"] == 50.0 and why == ["map of board b: check_violations = 1"]
    # 6. samples_dropped=3 in a footer; a footer that does not count the rows; too few check points (the gateway run needs 20)
    assert own_keys2(tx, rx, probes, {**maps, "a": (foot(rows_a, 3), rows_a)})[1] == ["map of board a: samples_dropped=3"]
    assert own_keys2(tx, rx, probes, {**maps, "b": ({"samples": "5", "samples_dropped": "0"}, maps["b"][1])})[1] == ["map of board b: samples=5 in the footer, 6534 rows"]
    assert own_keys2(tx, rx, probes, maps, least=234)[1] == ["map of board a: check_n = 233, fewer than 234"] and own_keys2(tx, rx, probes, maps, least=20)[1] == []
    # 7. a format-1 file is refused for latency, by name
    old = raw_view(probes)                            # rows with the four columns of format 1 only
    assert refused({"format": "2"}, probes) is None and "format 1" in refused({"format": "1"}, old) and "refused for latency" in refused({}, old)
    # E11 o: a format line that disagrees with the columns is not a result either way
    assert refused({"format": "2"}, old) == "clock_probe.csv: the header says format 2, the columns are not those of format 2"
    assert refused({}, probes) == "clock_probe.csv: the header says format 1, the columns are those of format 2" and format_fault({}, old) is None
    # causality against bound_total_us (40.1205 us here): a margin of -40.1 us is no violation, -40.2 us is one
    for wire, count in ((1_439_960, 0), (1_439_800, 1)):
        back = [{**r, "rx_done_ns": TB0 + (11_000_000_000 + wire) - (11_000_000_000 + wire) // 40_000 + CB} if r["seq"] == 0 else r for r in rx]
        k, why, _ = own_keys2(tx, back, probes, maps)
        assert k["causality_violations"] == count and why == [f"causality_violations = {count}"] * count
    # the comparison and its negative controls: a changed value, a key the toolkit lacks, and the tolerances by unit
    same = {name: repr(v) for name, v in steady.items() if v is not None}
    with redirect_stdout(io.StringIO()) as out:
        counts = [compare("h.", steady, same, 0.1), compare("h.", steady, {**same, "bound_total_us": "40.1207"}, 0.1),
                  compare("h.", steady, {n: v for n, v in same.items() if n != "map_b.check_n"}, 0.1), compare("h.", steady, {**same, "mono.verdict": "0"}, 0.1)]
    assert counts == [0, 1, 1, 1] and "DIFF h.bound_total_us: own 40.1205, toolkit 40.1207" in out.getvalue() and "DIFF h.map_b.check_n" in out.getvalue()
    assert close("map_b.bound_us", 12.5287, "12.52870005", 0.1) and not close("map_b.bound_us", 12.5287, "12.5289", 0.1)          # 0.05 ns, 0.2 ns
    assert close("clock_b.adj_ppm_max", 5000.0, "5000.0000005") and not close("clock_b.adj_ppm_max", 5000.0, "5000.01")
    assert close("probe_width_p50_ns", 120.0, "120.05", 0.1) and not close("probe_width_p50_ns", 120.0, "120.5", 0.1) and close("map_a.check_n", 233, "233")


def probetest_keys(zero, ab, ba):
    """({key behind '.probetest.': own value}, the tests that fail) of the probe's two tests. zero: {host_a: rows of its
    zero_<host>.csv}; ab, ba: the rows of pair_ab.csv and pair_ba.csv, or None."""
    k, failed = {}, []
    for host, probes in zero.items():           # client and server on one board: the true offset is 0
        ex, anchors = track(probes)
        k.update({f"zero.{host}.exchanges": len(ex), f"zero.{host}.anchors": len(anchors), f"zero.{host}.offset_bound_us": max(a[2] for a in anchors) / 2000,
                  f"zero.{host}.theta_beyond_half_delay.k": sum(abs(e[1]) > e[2] for e in ex)})
        if any(abs(a[1]) > a[2] for a in anchors):
            failed.append(f"same host {host}: an anchor with |theta| above delta / 2")
    if ab and ba:                               # two directions at once: at one instant the two offsets cancel
        ta, tb = clock_track(ab), clock_track(ba)
        a, b = ta["anchors"], tb["anchors"]
        sums = []                               # doubled |theta + theta of the other track|
        for mine, other in ((a[1:-1], b[1:-1]), (b[1:-1], a[1:-1])):     # the regions: the end segments take no part (E11 m)
            tau2 = [o[0] for o in other]
            for e in mine:                      # the anchor's instant on the other board's clock is tau + theta = (t2 + t3) / 2
                if tau2 and tau2[0] <= e[3] <= tau2[-1]:
                    i = min(max(bisect_right(tau2, e[3]) - 1, 0), len(other) - 2)
                    sums.append(abs(e[1] + (other[i][1] + Fraction(other[i + 1][1] - other[i][1], tau2[i + 1] - tau2[i]) * (e[3] - tau2[i])
                                            if len(other) > 1 else other[0][1])))
        limit2 = None if ta["total2"] is None or tb["total2"] is None else ta["total2"] + tb["total2"]     # the two total bounds
        k.update({"pair.anchors_compared": len(sums), "pair.theta_sum_max_us": float(max(sums) / 2000) if sums else None,
                  "pair.limit_us": None if limit2 is None else float(limit2 / 2000)})
        if not sums or limit2 is None or max(sums) > limit2:
            failed.append("two directions: no anchor to compare, no total bound of a track, or a sum above the limit")
    return k, failed


def toolkit_rows(analysis_dir):
    numbers = Path(analysis_dir) / "numbers.csv"
    return list(csv.DictReader(numbers.open(newline=""))) if numbers.exists() else None


def record_compared(analysis_dir, keys):
    """Addendum F4: <analysis_dir>/own_compared_keys.txt, the keys that this call compared with a toolkit value and found
    equal, one per line, sorted. Under e9_compare.py (OWN_COMPARED_KEYS=add) the readers of one call add to one file;
    a direct call writes its own set. A call that does not end in agreement leaves no key of its own."""
    path = Path(analysis_dir) / "own_compared_keys.txt"
    if path.parent.is_dir():
        old = path.read_text().split() if os.environ.get("OWN_COMPARED_KEYS") == "add" and path.exists() else []
        path.write_text("".join(k + "\n" for k in sorted({*old, *keys})))


def finish(ok, analysis_dir):
    record_compared(analysis_dir, AGREED if ok else [])
    print("OWN-CHECK AGREES" if ok else "OWN-CHECK DISAGREES")
    sys.exit(0 if ok else 1)


def probetest_main(d, analysis_dir, prefix):
    zero, failed = {}, []
    def rows_of(path):          # format 2 on its raw stamps, format 1 on its monotonic columns (E11 f)
        meta, probes = read(path) if path.exists() else ({}, [])
        if probes and format_fault(meta, probes):
            failed.append(f"{path.name}: {format_fault(meta, probes)}")
            return meta, []
        return meta, raw_view(probes) if meta.get("format") == "2" else probes

    files = {p.name: rows_of(p) for p in sorted([*d.glob("zero_*.csv"), d / "pair_ab.csv", d / "pair_ba.csv"])}
    for name, (meta, probes) in files.items():
        failed += [f"{name}: {w}" for w in (probe_faults(meta, probes) if probes else ["no completed exchange, no file, or not read"])]
        if name.startswith("zero_") and probes:
            zero[meta.get("host_a")] = probes
    (meta_ab, ab), (meta_ba, ba) = files["pair_ab.csv"], files["pair_ba.csv"]
    if ab and ba and meta_ab.get("format", "1") != meta_ba.get("format", "1"):      # E11 o: one file of each format
        failed.append("pair_ab.csv and pair_ba.csv are of different formats: the pair is invalid")
        ab = None
    own, wrong = probetest_keys(zero, ab, ba)
    failed += wrong
    rows = toolkit_rows(analysis_dir)
    theirs = {r["key"][len(prefix) + 11:]: r["value"] for r in rows or [] if r["key"].startswith(prefix + ".probetest.") and r["unit"] != "text"}
    for host in zero:
        print(f"same host {host}: exchanges {own[f'zero.{host}.exchanges']}, anchors {own[f'zero.{host}.anchors']}, bound {own[f'zero.{host}.offset_bound_us']:.3f} us, "
              f"exchanges with |theta| above delta / 2: {own[f'zero.{host}.theta_beyond_half_delay.k']}")
    if "pair.limit_us" in own:
        print(f"two directions: anchors compared {own['pair.anchors_compared']}, largest |theta_AB + theta_BA| {own['pair.theta_sum_max_us']} us, limit {own['pair.limit_us']} us")
    for w in failed:
        print(f"DIFF probetest, the test fails by the own rules: {w}")
    bad = compare(f"{prefix}.probetest.", own, theirs) + len(failed) + (rows is None)
    for key in sorted(set(theirs) - set(own)):
        print(f"NOT COMPARED {prefix}.probetest.{key}: toolkit {theirs[key]} (a key this reader does not recompute)")
    print(f"keys compared {len(own)}, differences {bad}" + ("" if rows is not None else f"; no numbers.csv in {analysis_dir}"))
    finish(not bad and len(own) >= 7, analysis_dir)


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    self_test()
    AGREED.clear()              # the self-test compares too
    run_dir, analysis_dir, prefix = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    record_compared(analysis_dir, [])    # a direct call starts the file; under e9_compare.py this changes nothing
    for marker in ("DRY_RUN", "PILOT", "EXCLUDED"):
        if (run_dir / marker).exists():
            print(f"marker {marker}: nothing in this directory is a result")
    if (run_dir / "probetest").is_dir():
        return probetest_main(run_dir / "probetest", analysis_dir, prefix)
    found = sorted(run_dir.rglob("clock_probe.csv"))
    if len(found) != 1:
        raise SystemExit(f"{run_dir}: need exactly one clock_probe.csv, found {len(found)}")
    d = found[0].parent
    harness = sorted(d.glob("periodic_tx*.csv"))
    # shortcut: one sender file per run directory, as in every E9 cell; partitions or a replaced gateway process need a join per file
    if len(harness) == 1:
        sender, release, arrival, places = harness[0], "release_ns", "rx_done_ns", (d, d.parent)
        receiver, pattern = sender.with_name(sender.name.replace("periodic_tx", "periodic_rx", 1)), r"\.periodic\.(.+?)\.e2e\.(.+)"
    elif not harness and (d / "app_tx.csv").exists() and not (d / "app_tx2.csv").exists() and not (d / "app_rx2.csv").exists():
        sender, receiver, release, arrival, places = d / "app_tx.csv", d / "app_rx.csv", "submit_ns", "verify_done_ns", (d,)
        pattern = r"\.functional\.(?:(.+?)\.)?e2e\.(.+)"
    else:
        raise SystemExit(f"{d}: need one periodic_tx*.csv, or app_tx.csv of a single process, beside clock_probe.csv")
    probe_meta, probes = read(found[0])
    if not probes or not receiver.exists():
        raise SystemExit(f"{d}: no completed exchange in clock_probe.csv, or no {receiver.name}")
    rx_meta, rx_rows = read(receiver)
    tx_meta, tx_rows = read(sender)
    refusal = refused(probe_meta, probes)
    if refusal:                 # format 1: nothing is read for latency (its clock statistics are clock_rate.py's part)
        own, why, notes = {}, [refusal], None
    else:
        files = {x: d / f"clock_map_{x}.csv" for x in "ab"}
        maps = {x: read(f) if f.exists() else ({}, []) for x, f in files.items()}
        own, why, notes = own_keys2(tx_rows, rx_rows, probes, maps, release, arrival, 100 if harness else 20)
        why = probe_faults(probe_meta, raw_view(probes)) + identity(probe_meta, maps) + [f"no {f.name}" for f in files.values() if not f.exists()] + why
    if arrival == "rx_done_ns" and "rx_done_ns" in rx_meta.get("not_recorded", ""):
        why.append("the receiver declares rx_done_ns not recorded")
    why += [f"marker {name}" for name in ("BG_INVALID", "E9_INVALID") if any((q / name).exists() for q in places)]
    rows = toolkit_rows(analysis_dir)
    theirs, texts, heads = {}, {}, set()
    for r in rows or []:
        m = re.fullmatch(re.escape(prefix) + pattern, r["key"])
        if m:
            heads.add(r["key"][:-len(m[2])])
            (texts if r["unit"] == "text" else theirs)[m[2]] = r["value"]
    head = "|".join(sorted(heads)) or f"{prefix}.{'periodic.<configuration>' if release == 'release_ns' else 'functional'}.e2e."
    show = {k: "n/a" if v is None else v if isinstance(v, int) else f"{v:.6f}" for k, v in own.items()}
    if own:
        print(f"probe format {show['probe_format']}, widths ns p50 {show['probe_width_p50_ns']}, max {show['probe_width_max_ns']}; bound: offset {show['offset_bound_total_us']} "
              f"+ map a {show['map_a.bound_us']} + map b {show['map_b.bound_us']} = {show['bound_total_us']} us (limit 100); stamps outside their map: {notes['not carried']} PDU(s)")
        for x in "ab":
            print(f"board {x}: map samples {show[f'map_{x}.samples']}, invalid {show[f'map_{x}.samples_invalid']}, largest gap {show[f'map_{x}.gap_max_ms']} ms, hold-out "
                  f"{show[f'map_{x}.holdout_us']} us, kink term {show[f'map_{x}.kink_us']} us, half-width {show[f'map_{x}.half_us']} us, check points {show[f'map_{x}.check_n']}, largest off {show[f'map_{x}.check_max_us']} us, "
                  f"violations {show[f'map_{x}.check_violations']}; CLOCK_MONOTONIC against raw ppm min {show[f'clock_{x}.adj_ppm_min']}, max {show[f'clock_{x}.adj_ppm_max']}, median "
                  f"{show[f'clock_{x}.adj_ppm_median']}, largest step {show[f'clock_{x}.adj_step_ppm_max']}, offset range {show[f'clock_{x}.adj_offset_range_us']} us, adjusted {show[f'clock_{x}.adjusted']}")
        print(f"by the monotonic columns (format-1 reading, diagnostic only): verdict {show['mono.verdict']}, total bound {show['mono.offset_bound_total_us']} us, "
              f"median latency minus the one above {show['mono.latency_p50_diff_us']} us")
    own and print(f"{sender.name} + {receiver.name} + clock_probe.csv: joined PDUs {show['n']}; latency ms mean {show['latency_mean_ms']}, p50 "
          f"{show['latency_p50_ms']}, p90 {show['latency_p90_ms']}, p99 {show['latency_p99_ms']}, p99.9 {show['latency_p99_9_ms']}, max {show['latency_max_ms']}; "
          f"receive part ms p50 {show['rxpart_p50_ms']}, p99 {show['rxpart_p99_ms']}, max {show['rxpart_max_ms']}; fewer than ten samples above "
          f"(not in numbers.tex): {', '.join(notes['held back']) or 'none'}")
    own and print(f"clock probe {probe_meta.get('host_a')} -> {probe_meta.get('host_b')}: exchanges sent {probe_meta.get('exchanges_sent')}, completed {show['probes_completed']}, "
          f"anchors {show['anchors']}, offset bound {show['offset_bound_us']} us, certified every 2 s to {show['offset_cert_us']} us, total "
          f"{show['offset_bound_total_us']} us, exchanges outside {show['exchanges_outside']} of {notes['region']} in the region, delay us min {show['probe_delay_min_us']}, p50 {show['probe_delay_p50_us']}, "
          f"largest gap {show['probe_gap_max_ms']} ms, drift {show['drift_ppm']} ppm; causality margin ({arrival}) min {show['causality_min_us']} us, "
          f"violations {show['causality_violations']}; ok rows without a sender row {notes['ok rows without a sender row']}, repeating a job {notes['ok rows that repeat a job']}")
    if own and len(notes["per stream"]) > 1:
        print("latency per stream: " + "; ".join(
            f"stream {name}: n {n}, p50 {p50:.6f}, p99 {p99:.6f}, max {top:.6f} ms" for name, (n, p50, p99, top) in notes["per stream"].items()))
    bad = compared = 0
    record = next((q / "background_traffic.txt" for q in places if (q / "background_traffic.txt").exists()), None)
    if record:
        bg = pairs(record)
        fail, faults = background(bg, pairs(d / "bg_source.txt"), pairs(d / "bg_sink.txt"), min(r[release] for r in tx_rows), max(r["send_done_ns"] for r in tx_rows))
        mine, file = "FAIL" if fail else "PASS", bg.get("verdict", "none").partition(":")[0]
        print(f"background flow: offered {bg['rate_offered_bit_s']} bit/s, achieved {bg['rate_achieved_bit_s']}, sent {bg['bytes_sent']} bytes, received "
              f"{bg['bytes_received']}; own verdict {mine}{': ' + '; '.join(fail) if fail else ''}; verdict of the file {bg.get('verdict')}")
        for what in faults + ([f"verdict: own {mine}, file {file}"] if mine != file else []):
            print(f"DIFF background_traffic.txt, {what}")
        bad += len(faults) + (mine != file)
        why += [f"background flow: verdict {v}" for v in dict.fromkeys((file, mine)) if v != "PASS"]
        kit = {m[2]: (m[1], r["value"]) for r in rows or [] if (m := re.fullmatch("(" + re.escape(prefix) + r"\.periodic\..+?\.bg\.)(.+)", r["key"]))}
        bg_head = next((h for h, _ in kit.values()), f"{prefix}.periodic.<configuration>.bg.")
        bad += compare(bg_head, {"rate_offered_mbit_s": int(bg["rate_offered_bit_s"]) / 1e6, "rate_achieved_mbit_s": int(bg["rate_achieved_bit_s"]) / 1e6,
                                 "bytes_sent": int(bg["bytes_sent"]), "bytes_received": int(bg["bytes_received"])}, {k: v for k, (_, v) in kit.items()})
        if kit.get("verdict", ("", None))[1] != file:
            bad += 1
            print(f"DIFF {bg_head}verdict: own {file} (the file's; recomputed {mine}), toolkit {kit.get('verdict', ('', None))[1]}")
        else:
            AGREED.append(bg_head + "verdict")
    if rows is None:
        bad += 1
        print(f"DIFF {head}*: no numbers.csv in {analysis_dir}: the toolkit wrote none")
    if why:
        print("INVALID for E9 by the own rules: " + "; ".join(why))
        print(f"DIFF {head}*: own INVALID, toolkit has {len(theirs)} e2e keys" if theirs else "the toolkit has no e2e key either: consistent, nothing compared")
        bad += bool(theirs)
    elif rows is not None:
        bad, compared = bad + compare(head, own, theirs, 0.1), sum(v is not None for v in own.values())
        if len(heads) > 1:
            bad += 1
            print(f"DIFF {head}: own one configuration, toolkit {len(heads)} with e2e keys")
    if "stream_profiles" in tx_meta and not why and rows is not None:
        # profile=both: which stream is the signature stream and which the MAC stream; text keys, compared all the same
        named = dict(enumerate(tx_meta["stream_profiles"].split(",")))
        for name in dict.fromkeys(r["stream"] for r in tx_rows):
            mine, kit = named.get(int(name)), texts.pop(f"stream{name}.profile", None)
            compared += 1
            if mine != kit or rx_meta.get("stream_profiles") != tx_meta["stream_profiles"]:
                bad += 1
                print(f"DIFF {head}stream{name}.profile: own {mine} (sender's stream_profiles={tx_meta['stream_profiles']}, receiver's "
                      f"{rx_meta.get('stream_profiles')}), toolkit {kit}")
            else:
                AGREED.append(f"{head}stream{name}.profile")
    for key in sorted(set(theirs) - set(own)) + sorted(texts):
        print(f"NOT COMPARED {head}{key}: toolkit {theirs.get(key, texts.get(key))} (a key this reader does not recompute)")
    print(f"keys compared {compared}, differences {bad}")
    finish(not why and not bad and compared >= 12, analysis_dir)


if __name__ == "__main__":
    main()
