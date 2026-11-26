#!/usr/bin/env python3
"""Checks on the files of bench_clock_probe (E9): clock_probe.csv and the two clock maps. Each prints
its figures, then one line that starts with PASS or FAIL; the exit status is 0 only for PASS.

  check_clock_probe.py --zero FILE             client and server on ONE board (true offset 0):
                                               every exchange, so every anchor, must give |theta| <= delta/2
  check_clock_probe.py --pair FILE_AB FILE_BA  two probes at the same time, A to B and B to A: at every
                                               anchor the two tracks sum to zero within the two total bounds
  check_clock_probe.py --run FILE TX RX [MAP_A MAP_B]
                                               the rules of an E9 run: FILE with periodic_tx.csv and
                                               periodic_rx.csv, or with the gateway's app_tx.csv and app_rx.csv;
                                               the maps are clock_map_a.csv and clock_map_b.csv beside FILE
  check_clock_probe.py --files FILE MAP_A MAP_B  the three files of one probe as files: format 2, footers, widths
  check_clock_probe.py --form FILE...          one line per probe or map file as check_csv.py writes them:
                                               '<path>: ok' or what is wrong with its form
  check_clock_probe.py --selftest              synthetic files with known answers

The probe (format 2) reads RAW, MONOTONIC, RAW at each of its four stamp points. The stamps of the
PDUs are CLOCK_MONOTONIC, which a time-synchronisation service steers; CLOCK_MONOTONIC_RAW is not
steered. So (E9_SPEC.md, Addendum E, and the FINAL ruling on the clock track, which holds on the raw
values):
- The offset between the boards is tracked on the raw stamps: tau = (t1r + t4r) / 2 on board A's raw
  clock, theta = ((t2r - t1r) - (t4r - t3r)) / 2 (board B minus board A), delta = (t4r - t1r) -
  (t3r - t2r). Anchors: windows of 5 s from the first tau, in each the exchange with the smallest
  delta (the earliest on a tie). theta(t): the straight line between the neighbouring anchors.
  Region: second anchor to second-to-last one (fewer than four anchors: not a result); offset_bound:
  the largest delta / 2 of the region's anchors; cert_j = |theta(tau_j) - theta_j| + delta_j / 2;
  offset_cert: the smallest T such that the exchanges with cert_j <= T, with the two ends of the
  region, are nowhere more than 2,000 ms apart; offset_bound_total: the larger of the two;
  exchanges_outside: exchanges of the region farther from the line than their own delta / 2 plus
  that total (none allowed).
- A stamp x of board X is carried onto X's raw clock by X's map, clock_map_<x>.csv, samples (raw1,
  mono, raw2) every 5 ms: a sample is valid when 0 <= raw2 - raw1 <= 5,000 ns; its abscissa is mono,
  its value m = mono - (raw1 + raw2) / 2, its half-width (raw2 - raw1) / 2; x_raw = x - m(x), m(x)
  on the straight line between the two valid samples around x. A stamp outside the valid samples
  cannot be carried over. Used range: from the last valid sample at or before the earliest stamp
  carried over to the first at or after the latest. In it: no two valid samples more than 50 ms
  apart; hold-out = the largest distance of a sample from the line through its two neighbours in
  the file (both valid; at least one sample of the range must have them); kink = the largest
  |slope behind - slope before| x length / 4 over the intervals between two valid samples of the
  range, which is what one rate change inside an interval can do to the straight line across it
  (E12.1). The slope before is read from the interval's first sample back to the nearest valid
  sample at least 4 ms before it, the slope behind from its second sample on to the nearest one at
  least 4 ms behind it (E12.7: two samples microseconds apart, as a late sampler leaves them, give
  no rate); an interval of the range without such a sample in the file: not a result. map_bound =
  the larger of the two + the largest half-width. The exchange points check the map from another thread: a point with a width of at
  most 5,000 ns reads mono - (mean of its two raw reads) at its monotonic read, and must lie
  within map_bound plus half its width of the map (at least 100 such points per board, 20 in a
  gateway run). samples_dropped must be 0. The three files are those of one probe pair (E12.2):
  a map says the role it is read as, the host of that end and the commit of the probe file, and
  the clocks and the sampling interval of 5 ms.
- latency = deliver_raw - theta(release_raw) - release_raw; causality margin = arrival_raw -
  theta(send_done_raw) - send_done_raw; bound in total = offset_bound_total + map_bound of board A +
  map_bound of board B, at most 100 us; no margin below minus that bound. The run lies inside the
  region: first release at or after the second anchor, last delivery at or before the second-to-last.
A file of probe format 1 has no raw stamps: --run refuses it for latency. The line above the verdict
says what the definitions of format 1 make of the monotonic columns of the same run (a diagnostic,
never the verdict). "Exceeds" is strict. Integers and rationals until the figures are printed.
"""
import bisect
import os
import sys
import tempfile
from fractions import Fraction

WINDOW_NS = 5_000_000_000
GAP_LIMIT_NS = 1_000_000_000
BOUND_LIMIT_NS = 100_000
CERT_GAP_NS = 2_000_000_000
WIDTH_LIMIT_NS = 5_000              # three reads farther apart were interrupted between them
MAP_GAP_LIMIT_NS = 50_000_000
KINK_BASE_NS = 4_000_000            # the slopes of the kink term are read over at least this much (E12.7)
CHECK_POINTS_MIN = {False: 100, True: 20}       # harness files, gateway files
LATE_NS = 1_000_000                 # a map sample this far behind its deadline is counted (reported, not judged)
COLUMNS = {1: 'seq,t1_ns,t2_ns,t3_ns,t4_ns',
           2: 'seq,t1_ns,t2_ns,t3_ns,t4_ns,t1r_ns,t2r_ns,t3r_ns,t4r_ns,w1_ns,w2_ns,w3_ns,w4_ns'}
MAP_COLUMNS = 'raw1_ns,mono_ns,raw2_ns'
RUN_FIGURES = ('offset_bound_us', 'offset_cert_us', 'offset_bound_total_us', 'map_bound_a_us', 'map_bound_b_us',
               'bound_total_us', 'exchanges_outside')


class Invalid(Exception):
    """a file of the probe is not usable"""


class OutOfMap(Exception):
    """a stamp lies before the first or after the last valid sample of its board's map"""


def read_csv(path):
    """comment keys (the first value of a repeated key), the column names and the rows as dicts"""
    keys, cols, rows = {}, None, []
    with open(path, encoding='ascii') as f:
        for line in f:
            line = line.strip()
            if line.startswith('#'):
                k, _, v = line[1:].strip().partition('=')
                keys.setdefault(k, v)
            elif line and cols is None:
                cols = line.split(',')
            elif line:
                rows.append(dict(zip(cols, line.split(','))))
    return keys, cols or [], rows


class Probe:
    """A clock_probe.csv. fmt 1 or 2; mono = (seq, t1, t2, t3, t4) on CLOCK_MONOTONIC; format 2 also has raw, the
    same with the raw stamps, and widths (w1, w2, w3, w4). ex: the stamps an offset track of this file is built on."""

    def __init__(self, path):
        keys, cols, rows = read_csv(path)
        line = ','.join(cols)
        self.fmt = next((fmt for fmt, columns in COLUMNS.items() if columns == line), None)
        if self.fmt is None:
            raise Invalid(f'{path}: the column line is that of no probe format (1 or 2)')
        if keys.get('format', '1') != str(self.fmt):
            raise Invalid(f"{path}: the header says format {keys.get('format', '1')}, the columns are those of format {self.fmt}")
        if not keys.get('exchanges_completed', '').isdigit():
            raise Invalid(f'{path}: no exchanges_completed line (the client did not end normally)')
        vals = [tuple(int(r[c]) for c in cols) for r in rows]
        if int(keys['exchanges_completed']) != len(vals):
            raise Invalid(f"{path}: exchanges_completed={keys['exchanges_completed']} but {len(vals)} rows")
        if not vals:
            raise Invalid(f'{path}: no completed exchange')
        self.keys = keys
        self.mono = [v[:5] for v in vals]
        self.raw = [(v[0],) + v[5:9] for v in vals] if self.fmt == 2 else None
        self.widths = [v[9:13] for v in vals] if self.fmt == 2 else None
        self.ex = self.raw or self.mono
        for seq, t1, t2, t3, t4 in self.ex:
            if t4 < t1 or t3 < t2 or (t4 - t1) - (t3 - t2) < 0:
                raise Invalid(f'{path}: exchange {seq} has t4 before t1, t3 before t2 or a negative delta')
        if self.widths and min(min(w) for w in self.widths) < 0:
            raise Invalid(f'{path}: a width is negative (the second raw read before the first)')

    def points(self, board):
        """The exchange points of a board as readings of its map: (monotonic read, 2 x (mono - mean of the two raw
        reads), width). Board a took points 1 and 4, board b points 2 and 3; the other raw read of a point is its
        stamp minus the width before a send (1, 3) and plus the width after a receive (2, 4)."""
        pairs = ((1, 1), (4, -1)) if board == 'a' else ((2, -1), (3, 1))
        return [(m[i], 2 * m[i] - 2 * r[i] + sign * w[i - 1], w[i - 1])
                for m, r, w in zip(self.mono, self.raw, self.widths) for i, sign in pairs]


def read_probe(path):
    return Probe(path)


class ClockMap:
    """One board's clock map. Valid samples only: ab their monotonic reads, m2 = 2 x (mono - (raw1 + raw2) / 2),
    w their widths, idx their places in the file."""

    def __init__(self, path):
        keys, cols, rows = {}, None, []
        with open(path, encoding='ascii') as f:
            for line in f:
                if line.startswith('#'):
                    k, _, v = line[1:].strip().partition('=')
                    keys.setdefault(k, v)
                elif cols is None:
                    cols = line.strip()
                    if cols != MAP_COLUMNS:
                        break
                elif line.strip():
                    a, b, c = line.split(',')
                    rows.append((int(a), int(b), int(c)))
        if cols != MAP_COLUMNS:
            raise Invalid(f'{path}: the column line is not {MAP_COLUMNS}')
        if not keys.get('samples', '').isdigit() or not keys.get('samples_dropped', '').isdigit():
            raise Invalid(f'{path}: no samples / samples_dropped lines (the probe did not end normally)')
        if int(keys['samples']) != len(rows):
            raise Invalid(f"{path}: samples={keys['samples']} but {len(rows)} rows")
        self.keys, self.rows, self.dropped = keys, rows, int(keys['samples_dropped'])
        self.ab, self.m2, self.w, self.idx = [], [], [], []
        for i, (raw1, mono, raw2) in enumerate(rows):
            if 0 <= raw2 - raw1 <= WIDTH_LIMIT_NS:
                if self.ab and mono <= self.ab[-1]:
                    raise Invalid(f'{path}: the monotonic reads of the samples do not rise (sample {i})')
                self.ab.append(mono)
                self.m2.append(2 * mono - raw1 - raw2)
                self.w.append(raw2 - raw1)
                self.idx.append(i)
        self.invalid = len(rows) - len(self.ab)
        step = int(keys['interval_ms']) * 1_000_000 if keys.get('interval_ms', '').isdigit() else 5_000_000
        # how far each sample lies behind its deadline: the deadlines are one interval apart, and where they lie is
        # read from where most samples lie (the first sample may itself have been late)
        behind = sorted(row[1] - rows[0][1] - i * step for i, row in enumerate(rows))
        usual = median(behind) if behind else 0     # once: a campaign's map has 200,000 samples
        self.late = sum(1 for x in behind if x - usual > LATE_NS)

    def m(self, x):
        """mono - raw at the monotonic time x of this board, in ns"""
        if not self.ab or x < self.ab[0] or x > self.ab[-1]:
            raise OutOfMap()
        i = bisect.bisect_right(self.ab, x) - 1
        if i == len(self.ab) - 1:
            return Fraction(self.m2[i], 2)
        return Fraction(self.m2[i], 2) + Fraction((self.m2[i + 1] - self.m2[i]) * (x - self.ab[i]), 2 * (self.ab[i + 1] - self.ab[i]))

    def to_raw(self, x):
        return x - self.m(x)

    def judge(self, first, last, points):
        """The figures of the used range for the stamps from `first` to `last` (both inside the map); points: the
        exchange points of this board (Probe.points)."""
        lo, hi = bisect.bisect_right(self.ab, first) - 1, bisect.bisect_left(self.ab, last)
        self.span = (self.ab[lo], self.ab[hi])
        self.gap = max((b - a for a, b in zip(self.ab[lo:hi], self.ab[lo + 1:hi + 1])), default=0)
        num, den = 0, 1         # the hold-out as num / den, largest so far
        self.held = 0           # samples of the range that have a hold-out
        for k in range(max(lo, 1), min(hi, len(self.ab) - 2) + 1):
            if self.idx[k - 1] == self.idx[k] - 1 and self.idx[k + 1] == self.idx[k] + 1:    # its neighbours in the file, both valid
                self.held += 1
                d = self.ab[k + 1] - self.ab[k - 1]
                n = abs((self.m2[k] - self.m2[k - 1]) * d - (self.m2[k + 1] - self.m2[k - 1]) * (self.ab[k] - self.ab[k - 1]))
                if n * den > num * 2 * d:       # |m_k - L_k| = n / (2 d)
                    num, den = n, 2 * d
        self.holdout = Fraction(num, den)
        # E12.1, E12.7: interval j lies between the valid samples j and j + 1. One rate change inside it puts the straight
        # line across it off by at most |slope behind - slope before| g_j / 4 (slopes of m, g: length). The slope before
        # is read from sample j back to i, the nearest valid sample at least KINK_BASE_NS before it, the slope behind
        # from sample j + 1 on to k, the nearest at least that far behind it; without such an i or k in the file the
        # interval cannot be judged.
        self.edge = False
        num, den = 0, 1
        for j in range(lo, hi):
            i = bisect.bisect_right(self.ab, self.ab[j] - KINK_BASE_NS) - 1
            k = bisect.bisect_left(self.ab, self.ab[j + 1] + KINK_BASE_NS)
            if i < 0 or k >= len(self.ab):
                self.edge = True
                continue
            before, after = self.ab[j] - self.ab[i], self.ab[k] - self.ab[j + 1]
            n = abs((self.m2[k] - self.m2[j + 1]) * before - (self.m2[j] - self.m2[i]) * after) * (self.ab[j + 1] - self.ab[j])
            if n * den > num * 8 * before * after:      # kink_j = n / (8 before after), the slopes being halves of m2's
                num, den = n, 8 * before * after
        self.kink = Fraction(num, den)
        self.half = Fraction(max(self.w[lo:hi + 1]), 2)
        self.bound = max(self.holdout, self.kink) + self.half
        self.check_n, self.check_max, self.violations = 0, Fraction(0), 0
        for ab, value2, width in points:
            if width <= WIDTH_LIMIT_NS and self.span[0] <= ab <= self.span[1]:
                off = abs(Fraction(value2, 2) - self.m(ab))
                self.check_n += 1
                self.check_max = max(self.check_max, off)
                self.violations += off > self.bound + Fraction(width, 2)


class Track:
    """The offset track of one probe file. Doubled values stay integer: tau2 = t1 + t4 = 2 tau and
    th2 = (t2 - t1) - (t4 - t3) = 2 theta; an entry is (tau2, th2, delta, t2 + t3).
    bound, cert, total and outside are None where the file does not give them (why says the reason)."""

    def __init__(self, exchanges):
        self.ex = sorted(((t1 + t4, (t2 - t1) - (t4 - t3), (t4 - t1) - (t3 - t2), t2 + t3)
                          for _, t1, t2, t3, t4 in exchanges), key=lambda e: e[0])
        best = {}
        for e in self.ex:       # in the order of tau, so a tie keeps the earliest
            w = (e[0] - self.ex[0][0]) // (2 * WINDOW_NS)
            if w not in best or e[2] < best[w][2]:
                best[w] = e
        self.anchors = [best[w] for w in sorted(best)]
        self.tau2 = [a[0] for a in self.anchors]
        self.bound_all = Fraction(max(a[2] for a in self.anchors), 2)    # over every anchor: the same-host test has no region
        self.gap = Fraction(max((b[0] - a[0] for a, b in zip(self.ex, self.ex[1:])), default=0), 2)
        self.bound = self.cert = self.total = self.outside = None
        self.why = f'{len(self.anchors)} anchors: fewer than four, the track has no region'
        if len(self.anchors) >= 4:
            self.lo, self.hi = self.anchors[1][0], self.anchors[-2][0]
            self.bound = Fraction(max(a[2] for a in self.anchors[1:-1]), 2)
            inside = [e for e in self.ex if self.lo <= e[0] <= self.hi]
            dist = [abs(Fraction(e[1], 2) - self.theta(Fraction(e[0], 2))) for e in inside]
            self.cert = self._certified([(e[0], d + Fraction(e[2], 2)) for e, d in zip(inside, dist)])
            self.why = 'no bound can be certified: more than 2 s of the region without an exchange'
            if self.cert is not None:
                self.total = max(self.bound, self.cert)
                self.outside = sum(1 for e, d in zip(inside, dist) if d > Fraction(e[2], 2) + self.total)

    def _certified(self, points):
        """The smallest T such that the points (2 tau, cert) with cert <= T, together with the two ends of the
        region, are nowhere more than CERT_GAP_NS apart; None when even all of them leave such a distance."""
        def covered(limit):
            last = self.lo
            for tau2, cert in points:           # in the order of tau
                if cert <= limit:
                    if tau2 - last > 2 * CERT_GAP_NS:
                        return False
                    last = tau2
            return self.hi - last <= 2 * CERT_GAP_NS
        if self.hi - self.lo <= 2 * CERT_GAP_NS:
            return Fraction(0)                  # the two ends are close enough by themselves
        levels = sorted({cert for _, cert in points})
        if not covered(levels[-1]):
            return None
        low, high = 0, len(levels) - 1
        while low < high:                       # covered() only gets easier as the limit grows
            mid = (low + high) // 2
            low, high = (low, mid) if covered(levels[mid]) else (mid + 1, high)
        return levels[low]

    def theta(self, t):
        """clock B minus clock A, in ns, at the time t of clock A"""
        i = bisect.bisect_right(self.tau2, 2 * t)
        if i == 0 or i == len(self.anchors):
            return Fraction(self.anchors[max(i - 1, 0)][1], 2)
        lo, hi = self.anchors[i - 1], self.anchors[i]
        return Fraction(lo[1], 2) + Fraction(hi[1] - lo[1], 2) * (2 * t - lo[0]) / (hi[0] - lo[0])

    def summary(self):
        delays = sorted(e[2] for e in self.ex)
        window = lambda e: (e[0] - self.ex[0][0]) // (2 * WINDOW_NS)
        in_last = sum(1 for e in self.ex if window(e) == window(self.ex[-1]))
        return (f'exchanges completed {len(self.ex)}, anchors {len(self.anchors)} ({in_last} exchanges in the last window), '
                f'delay min {delays[0] / 1e3:.1f} us, median {us(median(delays))} us, '
                f'largest gap {float(self.gap) / 1e6:.1f} ms')

    def figures(self):
        """the tokens of the verdict line of a run"""
        show = lambda v: 'none' if v is None else us(v)
        return (f'offset_bound_us={show(self.bound)} offset_cert_us={show(self.cert)} offset_bound_total_us={show(self.total)} '
                f"exchanges_outside={'none' if self.outside is None else self.outside}")


def us(ns):
    return f'{float(ns) / 1e3:.1f}'


def median(values):
    """the median of type 7: with an even count the mean of the two middle values"""
    v = sorted(values)
    return v[len(v) // 2] if len(v) % 2 else Fraction(v[len(v) // 2 - 1] + v[len(v) // 2], 2)


def spread(values):
    """median, 99th percentile and largest of a list of widths, as text"""
    v = sorted(values)
    return f'{float(median(v)):.0f} / {v[min(len(v) - 1, len(v) * 99 // 100)]} / {v[-1]}'       # whole nanoseconds


def verdict(reasons, figures, out=print):
    out(('FAIL ' if reasons else 'PASS ') + figures + ''.join(f'; {r}' for r in reasons))
    return 1 if reasons else 0


def check_zero(path, out=print):
    probe = read_probe(path)        # format 2: on the raw stamps; format 1: on its monotonic ones
    keys, tr = probe.keys, Track(probe.ex)
    bad_anchors = sum(1 for a in tr.anchors if abs(a[1]) > a[2])       # |2 theta| > delta
    bad_all = sum(1 for e in tr.ex if abs(e[1]) > e[2])
    out(f"same-host test, probe format {probe.fmt}: {path} (host_a={keys.get('host_a')} host_b={keys.get('host_b')})")
    out('  ' + tr.summary())
    out(f'  largest |theta| of an anchor {us(Fraction(max(abs(a[1]) for a in tr.anchors), 2))} us, of any exchange '
        f'{us(Fraction(max(abs(e[1]) for e in tr.ex), 2))} us')
    out(f'  |theta| > delta/2: {bad_anchors} of {len(tr.anchors)} anchors, {bad_all} of {len(tr.ex)} exchanges')
    reasons = []
    if keys.get('host_a') != keys.get('host_b'):
        reasons.append('host_a and host_b differ: not a same-host file')
    if bad_all:
        reasons.append(f'{bad_all} exchanges ({bad_anchors} anchors) with |theta| > delta/2 at a true offset of zero')
    return verdict(reasons, f'offset_bound_us={us(tr.bound_all)}', out)


def check_pair(path_ab, path_ba, out=print):
    pab, pba = read_probe(path_ab), read_probe(path_ba)
    kab, kba, ab, ba = pab.keys, pba.keys, Track(pab.ex), Track(pba.ex)
    out(f'two-direction test, probe formats {pab.fmt} and {pba.fmt}: {path_ab} and {path_ba}')
    out('  A to B: ' + ab.summary() + ', ' + ab.figures())
    out('  B to A: ' + ba.summary() + ', ' + ba.figures())
    reasons = [f'{name}: {tr.why}' for name, tr in (('A to B', ab), ('B to A', ba)) if tr.total is None]
    if pab.fmt != pba.fmt:
        reasons.append('the two files are of different probe formats')
    if (kab.get('host_a'), kab.get('host_b')) != (kba.get('host_b'), kba.get('host_a')):
        reasons.append('the two files are not the two directions of one pair of hosts')
    if any(tr.total is None for tr in (ab, ba)):
        return verdict(reasons, 'offset_bound_us=none', out)
    limit = ab.total + ba.total
    worst, n, bad = Fraction(0), 0, 0
    for one, other in ((ab, ba), (ba, ab)):
        for tau2, th2, _, _ in one.anchors[1:-1]:   # the anchors of its region, where the other file's region covers them
            t_other = Fraction(tau2 + th2, 2)       # the anchor's instant on the other board's clock
            if not other.lo <= 2 * t_other <= other.hi:
                continue
            n += 1
            s = abs(Fraction(th2, 2) + other.theta(t_other))
            worst = max(worst, s)
            bad += s > limit
    out(f'  anchors compared {n}, largest |theta_AB + theta_BA| {us(worst)} us, limit: the two total bounds added, {us(limit)} us')
    if n == 0:
        reasons.append('the two files do not overlap in time')
    if bad:
        reasons.append(f'{bad} anchors with |theta_AB + theta_BA| above the two total bounds added')
    return verdict(reasons, f'offset_bound_us={us(limit)}', out)


def judge_pdus(tr, pdus, first_release, last_deliver, bound):
    """What a track says about the PDUs measured on its two clocks. pdus: (release, send_done, arrival, deliver),
    the first two on clock A, the others on clock B; bound: what a causality margin is held against.
    Returns the reasons, the latencies in rising order, the smallest margin, the two leads."""
    reasons = []
    lead_in = Fraction(2 * first_release - tr.anchors[1][0], 2)         # both on clock A
    lead_out = Fraction(tr.anchors[-2][3], 2) - last_deliver            # both on clock B
    if lead_in < 0:
        reasons.append('fewer than two anchors before the first release')
    if lead_out < 0:
        reasons.append('fewer than two anchors after the last delivery')
    latency = sorted(deliver - tr.theta(release) - release for release, _, _, deliver in pdus)
    margin = [arrival - tr.theta(done) - done for _, done, arrival, _ in pdus]
    violations = sum(1 for m in margin if m < -bound)
    if violations:
        reasons.append(f'{violations} causality violations')
    return reasons, latency, min(margin), violations, lead_in, lead_out


def format1_view(probe, pdus, first_release, last_deliver, common):
    """What the definitions of probe format 1 make of the same run: the FINAL ruling on the monotonic columns and
    on the PDU stamps as they are. Returns (it is a result by them, the text of the diagnostic line, median latency)."""
    tr = Track(probe.mono)
    reasons, middle = list(common), None
    if tr.gap > GAP_LIMIT_NS:
        reasons.append(f'probe gap {float(tr.gap) / 1e6:.1f} ms exceeds 1000 ms')
    if tr.total is None:
        reasons.append(tr.why)
    else:
        if tr.total > BOUND_LIMIT_NS:
            reasons.append(f'total bound {us(tr.total)} us exceeds 100 us')
        if tr.outside:
            reasons.append(f'{tr.outside} exchanges outside the track')
        if pdus:
            more, latency, _, _, _, _ = judge_pdus(tr, pdus, first_release, last_deliver, tr.total)
            reasons += more
            middle = median(latency)
    return not reasons, ('FAIL ' if reasons else 'PASS ') + tr.figures() + ''.join(f'; {r}' for r in reasons), middle


def check_run(path, tx_path, rx_path, map_a_path=None, map_b_path=None, out=print):
    probe = read_probe(path)
    _, tx_cols, tx_rows = read_csv(tx_path)
    rx_keys, _, rx_rows = read_csv(rx_path)
    gateway = 'submit_ns' in tx_cols        # app_tx.csv / app_rx.csv: submit_ns for the release, verify_done_ns for the arrival
    release, arrival = ('submit_ns', 'verify_done_ns') if gateway else ('release_ns', 'rx_done_ns')
    sent = {(r['stream'], r['seq']): r for r in tx_rows}
    ok = [r for r in rx_rows if r['result'] == 'ok' and (r['stream'], r['seq']) in sent]
    common = []         # reasons that do not depend on which clock the latency is taken on
    if not gateway and 'rx_done_ns' in rx_keys.get('not_recorded', ''):
        common.append('rx_done_ns is not recorded: causality cannot be judged')
    if not ok:
        common.append('no delivered PDU that the sender file knows')
    pdus = [(int(s[release]), int(s['send_done_ns']), int(r[arrival]), int(r['deliver_ns']))
            for r in ok for s in (sent[(r['stream'], r['seq'])],)]
    unsent = sum(1 for p in pdus if p[1] == 0)
    if unsent:
        common.append(f'{unsent} delivered PDUs whose sender row has send_done_ns = 0')
    pdus = [p for p in pdus if p[1] != 0]
    first_release = min((int(r[release]) for r in tx_rows), default=0)
    last_deliver = max((int(r['deliver_ns']) for r in rx_rows if r['result'] == 'ok'), default=0)   # every delivery, joined or not
    out(f"E9 run check ({'gateway files' if gateway else 'harness files'}, probe format {probe.fmt}): {path}")
    old_ok, old_line, old_median = format1_view(probe, pdus, first_release, last_deliver, common)
    figures = dict.fromkeys(RUN_FIGURES, 'none')

    def end(reasons, middle=None):
        note = ''
        if old_ok and middle is not None:
            note = f'; median latency by them minus the median here {us(old_median - middle)} us'
        out(f'  definitions of format 1 on the monotonic columns (diagnostic, not the verdict): {old_line}{note}')
        return verdict(reasons, ' '.join(f'{k}={v}' for k, v in figures.items()), out)

    if probe.fmt != 2:
        return end(common + ['the probe file has format 1 (CLOCK_MONOTONIC stamps only, no raw stamps): refused for latency, '
                             'which is taken on the raw clocks of format 2'])
    tr = Track(probe.raw)
    reasons = list(common)
    out('  ' + tr.summary() + ' (limit 1000)')
    if tr.gap > GAP_LIMIT_NS:
        reasons.append(f'probe gap {float(tr.gap) / 1e6:.1f} ms exceeds 1000 ms')
    if tr.total is None:
        reasons.append(tr.why)
    else:
        figures.update(offset_bound_us=us(tr.bound), offset_cert_us=us(tr.cert), offset_bound_total_us=us(tr.total),
                       exchanges_outside=tr.outside)
        out(f'  raw track, region from the second to the second-to-last anchor: largest delta/2 of its anchors {us(tr.bound)} us; '
            f'certified at instants no more than 2 s apart to within {us(tr.cert)} us; offset bound in total {us(tr.total)} us')
        out(f'  exchanges of the region outside the track by more than their own delta/2 plus that bound: {tr.outside}')
        if tr.outside:
            reasons.append(f'{tr.outside} exchanges outside the track')
    out('  widths of the exchange points in ns, median / 99th percentile / largest: A ' + spread([w for p in probe.widths for w in (p[0], p[3])])
        + ', B ' + spread([w for p in probe.widths for w in (p[1], p[2])]))
    for key, want in (('clock', 'CLOCK_MONOTONIC'), ('clock_raw', 'CLOCK_MONOTONIC_RAW')):
        if probe.keys.get(key) != want:
            reasons.append(f"the probe file's header says {key}={probe.keys.get(key, 'none')}, not {want}")
    here = os.path.dirname(os.path.abspath(path))
    maps = {}
    for board, given in (('a', map_a_path), ('b', map_b_path)):
        name = f'map of board {board.upper()}'
        try:
            mp = ClockMap(given or os.path.join(here, f'clock_map_{board}.csv'))
        except (Invalid, OSError, ValueError) as e:
            reasons.append(f'{name}: {e}')
            continue
        # what the file says by itself is printed whatever becomes of the run
        out(f"  {name} ({mp.keys.get('host', '?')}): samples {len(mp.rows)}, not valid {mp.invalid}, dropped {mp.dropped}; widths in ns "
            f"{spread([r[2] - r[0] for r in mp.rows]) if mp.rows else 'none'}; more than 1 ms behind their deadline {mp.late}")
        # E12.2: the three files are those of one probe pair, with the clocks and the sampling interval of E2
        for key, want, whose in (('role', board, ''), ('host', probe.keys.get(f'host_{board}', 'none'), f" (the probe file's host_{board})"),
                                 ('commit', probe.keys.get('commit', 'none'), " (the probe file's)"), ('clock', 'CLOCK_MONOTONIC', ''),
                                 ('clock_raw', 'CLOCK_MONOTONIC_RAW', ''), ('interval_ms', '5', '')):
            if mp.keys.get(key) != want:
                reasons.append(f"{name}: its header says {key}={mp.keys.get(key, 'none')}, not {want}{whose}")
        if mp.dropped:
            reasons.append(f'{name}: samples_dropped={mp.dropped}')
        if mp.ab:
            maps[board] = mp
        else:
            reasons.append(f'{name}: no valid sample')
    if len(maps) < 2 or tr.total is None or not pdus:
        return end(reasons)
    # every stamp onto the raw clock of its board; the ranges of the two maps that this uses
    try:
        a = maps['a'].to_raw
        on_a = [(a(rel), a(done)) for rel, done, _, _ in pdus]
        first_raw = a(first_release)
    except OutOfMap:
        return end(reasons + ['a stamp of board A lies outside its map (before its first or after its last valid sample)'])
    try:
        b = maps['b'].to_raw
        on_b = [(b(arr), b(dlv)) for _, _, arr, dlv in pdus]
        last_raw = b(last_deliver)
    except OutOfMap:
        return end(reasons + ['a stamp of board B lies outside its map (before its first or after its last valid sample)'])
    maps['a'].judge(first_release, max(p[1] for p in pdus), probe.points('a'))
    maps['b'].judge(min(p[2] for p in pdus), last_deliver, probe.points('b'))
    for board, mp in maps.items():
        name = f'map of board {board.upper()}'
        out(f'  {name}, range used {(mp.span[1] - mp.span[0]) / 1e9:.2f} s: largest gap {mp.gap / 1e6:.1f} ms (limit 50); hold-out '
            f"{us(mp.holdout) if mp.held else 'none'} us, kink {us(mp.kink)} us, the larger + half-width {us(mp.half)} us = bound "
            f'{us(mp.bound)} us; check points {mp.check_n}, farthest {us(mp.check_max)} us, violations {mp.violations}')
        figures[f'map_bound_{board}_us'] = us(mp.bound)
        if mp.gap > MAP_GAP_LIMIT_NS:
            reasons.append(f'{name}: {mp.gap / 1e6:.1f} ms between two valid samples exceeds 50 ms')
        if not mp.held:
            reasons.append(f'{name}: no sample of the used range has two valid neighbours (no hold-out)')
        if mp.edge:
            reasons.append(f'{name}: an interval of the used range has no sample 4 ms before it or behind it in the file '
                           '(the kink term cannot be formed)')
        if mp.violations:
            reasons.append(f'{name}: {mp.violations} exchange points off the map by more than its bound (map_check)')
        if mp.check_n < CHECK_POINTS_MIN[gateway]:
            reasons.append(f'{name}: {mp.check_n} exchange points check it, fewer than {CHECK_POINTS_MIN[gateway]}')
    total = tr.total + maps['a'].bound + maps['b'].bound
    figures['bound_total_us'] = us(total)
    out(f'  bound in total: offset {us(tr.total)} + map A {us(maps["a"].bound)} + map B {us(maps["b"].bound)} = {us(total)} us (limit 100)')
    if total > BOUND_LIMIT_NS:
        reasons.append(f'bound in total {us(total)} us exceeds 100 us')
    more, latency, margin, violations, lead_in, lead_out = judge_pdus(
        tr, [(ra[0], ra[1], rb[0], rb[1]) for ra, rb in zip(on_a, on_b)], first_raw, last_raw, total)
    reasons += more
    out(f'  second anchor {float(lead_in) / 1e9:.2f} s before the first release, second-to-last anchor '
        f'{float(lead_out) / 1e9:.2f} s after the last delivery')
    out(f'  delivered PDUs joined {len(pdus)}; causality ({arrival} - theta - send_done_ns, on the raw clocks): smallest margin '
        f'{us(margin)} us, violations (margin below minus the bound in total) {violations}')
    if reasons:
        return end(reasons)     # not a result: no latency figure
    out(f'  latency deliver - theta - {release}, on the raw clocks: min {float(latency[0]) / 1e6:.3f} ms, median '
        f'{float(median(latency)) / 1e6:.3f} ms, max {float(latency[-1]) / 1e6:.3f} ms')
    return end(reasons, median(latency))


def check_form(*paths, out=print):
    """One line per file of the probe in the form of check_csv.py: '<path>: ok', or what is wrong with its form (the
    column line, the footers, the counts, monotonic reads of a map that do not rise)."""
    bad = 0
    for path in paths:
        try:
            with open(path, encoding='ascii') as f:
                first = next((line.strip() for line in f if line.strip() and not line.startswith('#')), '')
            if first == MAP_COLUMNS:
                ClockMap(path)
            else:
                Probe(path)
            out(f'{path}: ok')
        except (Invalid, OSError, ValueError) as e:
            bad += 1
            out(str(e) if str(e).startswith(f'{path}: ') else f'{path}: {e}')
    return 1 if bad else 0


def check_files(path, map_a_path, map_b_path, out=print):
    """The three files one probe pair writes, as files: what a same-host run of the two programs must produce."""
    probe = read_probe(path)
    reasons = []
    out(f'probe files: {path} (format {probe.fmt}, {len(probe.ex)} exchanges)')
    if probe.fmt != 2:
        reasons.append('the probe file is not of format 2')
    for key in ('format', 'clock', 'clock_raw', 'host_a', 'host_b', 'interval_ms', 'port', 'cpu_a', 'cpu_b', 'commit'):
        if not probe.keys.get(key):
            reasons.append(f'the probe file has no {key} line')
    span = probe.mono[-1][4] - probe.mono[0][1]
    if probe.fmt == 2:
        widths = [w for p in probe.widths for w in p]
        out(f'  widths of the exchange points in ns, median / 99th percentile / largest: {spread(widths)}')
        if median(widths) > WIDTH_LIMIT_NS:
            reasons.append('the median width of the exchange points is above 5,000 ns')
    for role, mpath in (('a', map_a_path), ('b', map_b_path)):
        try:
            mp = ClockMap(mpath)
        except (Invalid, OSError, ValueError) as e:
            reasons.append(f'map {role}: {e}')
            continue
        out(f"  map {role}: samples {len(mp.rows)}, not valid {mp.invalid}, dropped {mp.dropped}, more than 1 ms late {mp.late}; "
            f'widths in ns {spread([r[2] - r[0] for r in mp.rows]) if mp.rows else "none"}')
        for key in ('tool', 'commit', 'host', 'clock', 'clock_raw', 'cpu'):
            if not mp.keys.get(key):
                reasons.append(f'map {role} has no {key} line')
        if mp.keys.get('role') != role or mp.keys.get('interval_ms') != '5':
            reasons.append(f"map {role}: role={mp.keys.get('role')} interval_ms={mp.keys.get('interval_ms')}, expected {role} and 5")
        if mp.dropped:
            reasons.append(f'map {role}: samples_dropped={mp.dropped}')
        if len(mp.rows) < span // 5_000_000 * 8 // 10:
            reasons.append(f'map {role}: {len(mp.rows)} samples for {span / 1e9:.1f} s of exchanges, fewer than 8 in 10 of one per 5 ms')
        elif mp.invalid * 10 > len(mp.rows):
            reasons.append(f'map {role}: more than one sample in ten is not valid')
        elif mp.ab[0] > probe.mono[0][1 if role == 'a' else 2] or mp.ab[-1] < probe.mono[-1][4 if role == 'a' else 3]:
            reasons.append(f'map {role} does not cover the exchanges (it must begin before the first and end after the last)')
    out(('FAIL' if reasons else 'PASS') + ''.join(f'; {r}' for r in reasons))
    return 1 if reasons else 0


def selftest():
    """Clock B = clock A + 20 s + 30 ppm; 80 us to the server (now and then 3 ms), 30 us back, 15 us in it."""
    a0, off, ppm = 119_899_302_191_756, 20_000_000_000_000, 30
    lcg = [12345]

    def rnd(n):
        lcg[0] = (lcg[0] * 6364136223846793005 + 1442695040888963407) % 2 ** 64
        return (lcg[0] >> 33) % n

    def clock_b(a, shift=off, drift=ppm, step=None):
        """clock B at the instant a of clock A; step = (instant, ppm): its rate changes by that much from then on"""
        bend = max(0, a - step[0]) * step[1] // 1_000_000 if step else 0
        return a + shift + (a - a0) * drift // 1_000_000 + bend

    def exchanges(first, count, shift=off, drift=ppm, skip=(), slow=0, step=None, anchors=None, glitch=None, interval=100_000_000):
        """anchors: the exchanges that have the shortest path, {index: (us there, us back)}, one per window of 5 s;
        every other exchange then takes 80 us there and 30 us back, without the random part.
        glitch = (exchange, ns): the server's two stamps of that one exchange are off by that much."""
        rows = []
        for k in range(count):
            if k in skip:
                continue
            t1 = a0 + (first + k) * interval
            if anchors is not None:
                there_us, back_us = anchors.get(k, (80, 30))
                there = t1 + there_us * 1000
                back = there + 15_000
                home = back + back_us * 1000
            else:
                there = t1 + 80_000 + rnd(20_000) + slow + (3_000_000 if rnd(7) == 0 else 0)
                back = there + 15_000 + rnd(5_000)
                home = back + 30_000 + rnd(10_000)
            off_by = glitch[1] if glitch and glitch[0] == k else 0
            rows.append((first + k, t1, clock_b(there, shift, drift, step) + off_by, clock_b(back, shift, drift, step) + off_by, home))
        return rows

    def write(name, cols, rows, head=('tool=selftest',), foot=()):
        with open(name, 'w', encoding='ascii') as f:
            f.write(''.join(f'# {h}\n' for h in head) + cols + '\n')
            f.write(''.join(','.join(str(v) for v in r) + '\n' for r in rows) + ''.join(f'# {x}\n' for x in foot))
        return name

    def probe(name, rows, host_b='b', host_a='a', fmt=2):
        """rows (seq, t1, t2, t3, t4) as a probe file. Format 2: the raw stamps are these values and each board's
        CLOCK_MONOTONIC equals its raw clock (widths 0), so the maps of such a file read 0 everywhere."""
        body = [r + r[1:] + (0, 0, 0, 0) for r in rows] if fmt == 2 else rows
        more = ('format=2', 'clock_raw=CLOCK_MONOTONIC_RAW') if fmt == 2 else ()
        return write(name, COLUMNS[fmt], body, ('tool=bench_clock_probe', 'commit=0123456789ab', 'clock=CLOCK_MONOTONIC') + more
                     + (f'host_a={host_a}', f'host_b={host_b}'),
                     (f'exchanges_sent={len(rows)}', f'exchanges_completed={len(rows)}'))

    def write_map(name, role, rows, dropped=0, over=()):
        """over: header lines put before the usual ones (the first line of a key is the one that is read)"""
        return write(name, MAP_COLUMNS, rows, tuple(over) + ('tool=bench_clock_probe', 'commit=0123456789ab', f'host={role}', f'role={role}',
                                                            'clock=CLOCK_MONOTONIC', 'clock_raw=CLOCK_MONOTONIC_RAW', 'interval_ms=5', 'cpu=1'),
                     (f'samples={len(rows)}', f'samples_dropped={dropped}'))

    quiet = lambda *_: None
    # the estimator against the known clock: every anchor within its own delta/2, the track within b
    rows = exchanges(0, 600)
    tr = Track(rows)
    assert len(tr.anchors) == 12, len(tr.anchors)
    for tau2, th2, delta, _ in tr.anchors:
        assert abs(th2 - 2 * (clock_b(tau2 // 2) - tau2 // 2)) <= delta + 2
    for a in range(a0 - 10 ** 9, a0 + 62 * 10 ** 9, 137_000_001):
        slack = 30 * 7_000 if not tr.tau2[0] <= 2 * a <= tr.tau2[-1] else 2      # outside the anchors the drift (up to 7 s of it) is not followed
        assert abs(tr.theta(a) - (clock_b(a) - a)) <= tr.bound_all + slack, a
    assert Fraction(55_000) < tr.bound < Fraction(80_000), tr.bound      # half of 110 to 140 us; the asymmetry is inside it
    assert tr.bound <= tr.total < Fraction(100_000) and tr.outside == 0, (tr.total, tr.outside)
    # T(2 s) by its definition, the slow way: every level tried in turn
    inside = [e for e in tr.ex if tr.lo <= e[0] <= tr.hi]
    certs = [abs(Fraction(e[1], 2) - tr.theta(Fraction(e[0], 2))) + Fraction(e[2], 2) for e in inside]
    for level in sorted(set(certs)):
        marks = [tr.lo] + [e[0] for e, cert in zip(inside, certs) if cert <= level] + [tr.hi]
        if all(b - a <= 2 * CERT_GAP_NS for a, b in zip(marks, marks[1:])):
            assert level == tr.cert, (level, tr.cert)
            break
    assert Track(exchanges(0, 140)).total is None       # 14 s: three anchors, no region
    blind = Track(exchanges(0, 600, skip=range(200, 225)))     # 2.5 s of the region without an exchange: nothing certifies it
    assert blind.cert is None and blind.total is None and 'more than 2 s' in blind.why, blind.why

    with tempfile.TemporaryDirectory() as d:
        p = lambda n: os.path.join(d, n)
        # same host: offset zero passes; a server clock 200 us off, or a file of two hosts, fails
        assert check_zero(probe(p('zero.csv'), exchanges(0, 300, 0, 0), 'a'), quiet) == 0
        assert check_zero(probe(p('zero_off.csv'), exchanges(0, 300, 200_000, 0), 'a'), quiet) == 1
        assert check_zero(probe(p('zero_hosts.csv'), exchanges(0, 300, 0, 0)), quiet) == 1
        # two directions: B to A sees the opposite clock; a 300 us error in one direction fails
        def reverse(err=0, first=3):
            out = []
            for seq, t1, t2, t3, t4 in exchanges(first, 600, 0, 0):     # instants on clock A, then put on the other clock
                out.append((seq, clock_b(t1), t2 + err, t3 + err, clock_b(t4)))
            return out
        ab = probe(p('ab.csv'), rows)
        assert check_pair(ab, probe(p('ba.csv'), reverse(), 'a', 'b'), quiet) == 0
        assert check_pair(ab, probe(p('ba_err.csv'), reverse(300_000), 'a', 'b'), quiet) == 1
        assert check_pair(probe(p('ab1.csv'), rows, fmt=1), probe(p('ba1.csv'), reverse(), 'a', 'b', fmt=1), quiet) == 0   # format 1: its own stamps
        assert check_pair(ab, probe(p('ba1.csv'), reverse(), 'a', 'b', fmt=1), quiet) == 1                                # one of each: no
        assert check_zero(probe(p('zero1.csv'), exchanges(0, 300, 0, 0), 'a', fmt=1), quiet) == 0
        for name, other, reason in (('ba_hosts.csv', probe(p('ba_hosts.csv'), reverse(), 'a', 'c'), 'not the two directions of one pair of hosts'),
                                    ('ba_later.csv', probe(p('ba_later.csv'), reverse(first=3000), 'a', 'b'), 'do not overlap in time'),
                                    ('ba_short.csv', probe(p('ba_short.csv'), reverse()[:140], 'a', 'b'), 'fewer than four')):
            lines = []
            assert check_pair(ab, other, lines.append) == 1 and lines[-1].count(';') == 1 and reason in lines[-1], lines[-1]
        # the two clocks of each board agree in these files: maps that read 0, over everything a case below stamps
        both = [(t, t, t) for t in range(a0 - 6 * 10 ** 9, a0 + 82 * 10 ** 9, 5_000_000)]
        map_a = write_map(p('map_a.csv'), 'a', both)
        map_b = write_map(p('map_b.csv'), 'b', [(t + off, t + off, t + off) for t, _, _ in both])
        def check(probe_file, files, out=quiet):
            return check_run(probe_file, *files, map_a, map_b, out=out)
        # a run: releases from 12 s to 48 s of a probe that runs 60 s (two anchors on each side)
        def run(first=120, n=3600, early=0, tx_cols='stream,seq,release_ns,start_ns,auth_done_ns,send_done_ns', undone=(),
                clock=clock_b):
            tx, rx = [], []
            for k in range(n):
                rel = a0 + first * 100_000_000 + k * 10_000_000
                done = rel + 1_500_000
                arrive = clock(done + 110_000) - (early if k == 7 else 0)
                tx.append((0, k, rel, rel + 1000, rel + 1_400_000, 0 if k in undone else done))
                rx.append((0, k, 0 if 'submit' in tx_cols else arrive, arrive + 400_000, arrive + 401_000, 'ok'))
            k = len(os.listdir(d))      # a pair of files of its own for every call
            return (write(p(f'tx{k}.csv'), tx_cols, tx),
                    write(p(f'rx{k}.csv'), 'stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result', rx))
        good = probe(p('probe.csv'), rows)
        lines = []
        assert check(good, run(), lines.append) == 0, lines
        # 1.5 ms + 0.11 ms + 0.401 ms: offset and drift are removed, the asymmetry of the probe's path stays within b
        latency = next(line for line in lines if 'latency' in line)
        assert abs(float(latency.split('median ')[1].split(' ms')[0]) - 2.011) < 0.07, latency
        assert 'exchanges_outside=0' in lines[-1] and 'offset_cert_us=' in lines[-1] and 'offset_bound_total_us=' in lines[-1], lines[-1]
        assert check(good, run(early=100_000)) == 0     # 10 us after the send: inside the bound
        for bad, files in ((good, run(early=300_000)),                   # received 190 us before it was sent
                           (good, run(undone=(5,))),                     # delivered but never sent
                           (good, run(first=60, n=4200)),                # released at 6 s: one anchor before it for certain, not two
                           (good, run(n=5600)),                          # delivered up to 68 s: no anchor behind it
                           (probe(p('gap.csv'), exchanges(0, 600, skip=range(200, 211))), run()),   # 1.1 s without an exchange
                           (probe(p('slow.csv'), exchanges(0, 600, slow=150_000)), run())):         # bound above 100 us
            lines = []
            assert check(bad, files, lines.append) == 1, lines
            assert lines[-1].startswith('FAIL') and lines[-1].count(';') == 1, lines[-1]      # exactly the one reason
        assert check(probe(p('gap09.csv'), exchanges(0, 600, skip=range(200, 208))), run()) == 0   # 0.9 s
        # a limit is "not above" (E11 e): every exchange with delta/2 = 100 us exactly makes a bound in total of 100.0 us
        lines = []
        assert check(probe(p('hundred.csv'), exchanges(0, 600, drift=0, anchors={k: (150, 50) for k in range(600)})),
                     run(clock=lambda a: clock_b(a, off, 0)), lines.append) == 0 and ' bound_total_us=100.0 ' in lines[-1], lines[-1]
        # no delivered PDU of the receiver's file is in the sender's
        lines = []
        assert check(good, (run()[0], write(p('rx_other.csv'), 'stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result',
                                            [(0, 10 ** 6, t, t, t, 'ok') for t in (clock_b(a0 + 2 * 10 ** 10),)])), lines.append) == 1
        assert lines[-1].split('; ')[1:] == ['no delivered PDU that the sender file knows'], lines[-1]
        # The rate between the clocks changes (NTP on a board): the known answers of the FINAL ruling. Path without
        # the random part: an anchor has delta/2 = 47.5 us, any other exchange 55 us and lies 2.5 us off the anchors.
        five = {k: (70, 25) for k in range(25, 600, 50)}        # anchors 2.5, 7.5, ... s: 5 s apart
        def certified(name, rows, files):
            lines = []
            status = check(probe(p(name), rows), files, lines.append)
            figures = dict(tok.split('=') for tok in lines[-1].split(';')[0].split()[1:])
            return status, float(figures['offset_cert_us']), lines[-1]
        # a constant drift of 100 ppm is a straight line: valid, certified to within the exchanges' own 57.5 us
        status, cert, last = certified('drift100.csv', exchanges(0, 600, drift=100, anchors=five), run(clock=lambda a: clock_b(a, off, 100)))
        assert status == 0 and cert == 57.5, last
        # a step of 100 ppm in the middle of a segment of 5 s: the line is 125 us off there, and T(2 s) is about that
        step = (a0 + 15_000_000_000, 100)
        status, cert, last = certified('step100.csv', exchanges(0, 600, drift=0, step=step, anchors=five),
                                       run(clock=lambda a: clock_b(a, off, 0, step)))
        assert status == 1 and 120 < cert < 140 and 'exceeds 100 us' in last, last
        # the same step in a segment of 9.8 s between two short ones: more than 200 us
        wide = {k: (70, 25) for k in (49, 51, 149, 151, 249, 251, 349, 351, 449, 451, 549, 551)}
        step = (a0 + 10_000_000_000, 100)
        status, cert, last = certified('step_wide.csv', exchanges(0, 600, drift=0, step=step, anchors=wide),
                                       run(clock=lambda a: clock_b(a, off, 0, step)))
        assert status == 1 and cert > 200 and 'exceeds 100 us' in last, last
        # two anchors one interval of 101 ms and 2 us apart, nothing wrong with the clocks: valid (slopes are not used)
        close = {49: (70, 25), 50: (72, 23), **{k: (70, 25) for k in (124, 174, 223, 273, 322, 372, 421, 471, 520, 570)}}
        rows101 = exchanges(0, 594, drift=0, anchors=close, interval=101_000_000)
        assert [round((x - a0 * 2) / 2 / 101e6) for x in Track(rows101).tau2] == sorted(close), 'the anchors are not where the test wants them'
        status, cert, last = certified('close.csv', rows101, run(clock=lambda a: clock_b(a, off, 0)))
        assert status == 0 and cert < 60, last
        # a step of 30 ppm bends the line by 37.5 us: certified to within 80 us, valid
        step = (a0 + 15_000_000_000, 30)
        status, cert, last = certified('step30.csv', exchanges(0, 600, drift=0, step=step, anchors=five),
                                       run(clock=lambda a: clock_b(a, off, 0, step)))
        assert status == 0 and 70 < cert < 90, last
        # A step of 79 ppm in the middle of the first segment, with PDUs released there: the line is 98.75 us off,
        # which no other rule sees (the first segment is not part of the region); coverage is the one reason.
        step = (a0 + 5_000_000_000, 79)
        lines = []
        assert check(probe(p('step_first.csv'), exchanges(0, 600, drift=0, step=step, anchors=five)),
                     run(first=50, n=4300, clock=lambda a: clock_b(a, off, 0, step)), lines.append) == 1, lines
        assert lines[-1].split('; ')[1:] == ['fewer than two anchors before the first release'], lines[-1]
        # A single slow exchange alone in the last window, or alone in the first, is an anchor whatever its delay; it
        # only delimits, and no figure differs from the same file with a fast exchange in its place.
        for name, count, slow_one, skip in (('last', 552, 551, (550,)), ('first', 540, 0, range(1, 51))):
            pair = [Track(exchanges(0, count, drift=0, anchors={**five, slow_one: there_back}, skip=skip))
                    for there_back in ((800, 800), (70, 25))]
            assert len(pair[0].anchors) == len(pair[1].anchors) >= 4 and pair[0].tau2[1:-1] == pair[1].tau2[1:-1], name
            assert pair[0].anchors[0 if name == 'first' else -1][2] == 1_600_000, name     # the slow one is that anchor
            assert pair[0].figures() == pair[1].figures() and pair[0].total == pair[1].total and pair[0].total is not None, name
            assert (pair[0].bound, pair[0].cert, pair[0].outside) == (pair[1].bound, pair[1].cert, pair[1].outside), name
        # one exchange whose server stamps are 500 us off contradicts the bound, whatever the others certify
        lines = []
        assert check(probe(p('glitch.csv'), exchanges(0, 600, anchors=five, glitch=(333, 500_000))), run(), lines.append) == 1, lines
        assert lines[-1].endswith('exchanges_outside=1; 1 exchanges outside the track'), lines[-1]
        # a probe of 14 s has three anchors: no region, not a result
        lines = []
        assert check(probe(p('short.csv'), exchanges(0, 140)), run(first=60, n=500), lines.append) == 1, lines
        assert 'fewer than four' in lines[-1] and 'offset_bound_total_us=none' in lines[-1], lines[-1]
        # gateway files: submit_ns and verify_done_ns stand in; harness files without rx_done_ns cannot be judged
        gw = run(tx_cols='stream,seq,submit_ns,start_ns,auth_done_ns,send_done_ns')
        assert check(good, gw) == 0
        lines = []
        assert check(good, (run()[0], write(p('rx_nr.csv'), 'stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result',
                                            [(0, 0, 0, clock_b(a0 + 10 ** 10), clock_b(a0 + 10 ** 10), 'ok')],
                                            ('not_recorded=rx_done_ns',))), lines.append) == 1
        assert 'rx_done_ns is not recorded' in lines[-1], lines[-1]
        # files that are not usable: wrong count, missing footer, a reply stamped before its request
        for name, body, foot, head in (('nofoot.csv', rows, (), ()), ('count.csv', rows, ('exchanges_completed=599',), ()),
                                       ('order.csv', [(0, 10, 30, 20, 40)], ('exchanges_completed=1',), ()),
                                       ('negdelta.csv', [(0, 10, 20, 60, 40)], ('exchanges_completed=1',), ()),
                                       ('empty.csv', [], ('exchanges_completed=0',), ()),
                                       ('format.csv', rows, ('exchanges_completed=600',), ('format=2',))):     # says 2, has the columns of 1
            try:
                read_probe(write(p(name), COLUMNS[1], body, head, foot))
                raise AssertionError(name)
            except Invalid:
                pass
        # map files that are not usable, in the one-line form: the footer's count is not the rows, no samples_dropped
        # line though there are samples, another column line
        three = [(t, t + 200, t + 400) for t in (10 ** 9, 10 ** 9 + 5_000_000, 10 ** 9 + 10_000_000)]
        for name, cols, foot, fault in (('m_count.csv', MAP_COLUMNS, ('samples=4', 'samples_dropped=0'), 'samples=4 but 3 rows'),
                                        ('m_nodrop.csv', MAP_COLUMNS, ('samples=3',), 'no samples / samples_dropped lines'),
                                        ('m_cols.csv', 'raw1_ns,mono_ns', ('samples=3', 'samples_dropped=0'), 'the column line is')):
            lines = []
            assert check_form(write(p(name), cols, three if cols == MAP_COLUMNS else [r[:2] for r in three], foot=foot),
                              out=lines.append) == 1 and fault in lines[0], lines
        assert check_form(write(p('m_ok.csv'), MAP_COLUMNS, three, foot=('samples=3', 'samples_dropped=0')), out=quiet) == 0
        for name, cols, body, fault in (('m_cols.csv', None, None, 'the column line is not'),      # given as a map, it is refused as one
                                        ('p_width.csv', COLUMNS[2], [(0, 10, 20, 30, 40, 10, 20, 30, 40, 0, -1, 0, 0)], 'a width is negative')):
            try:
                if cols:
                    read_probe(write(p(name), cols, body, ('format=2',), ('exchanges_completed=1',)))
                else:
                    ClockMap(p(name))
                raise AssertionError(name)
            except Invalid as e:
                assert fault in str(e), e
        # ---- Addendum E: boards whose CLOCK_MONOTONIC is not their raw clock (known answers of E7) ----
        T0 = 10 ** 12

        def world(seconds=60, steer=None, pdus=3000, rate_b=25, paths=((70_000, 25_000), (80_000, 30_000))):
            """True time t in ns. Board A: raw = t + 5 s, CLOCK_MONOTONIC = raw + 7 s. Board B: its raw clock runs rate_b
            ppm slower than A's, its CLOCK_MONOTONIC = raw + 3 s + steering; steer = (from ns, to ns, ppm) after T0. An
            exchange every 101 ms (paths: ns there and back of the one in 50 that is the anchor of its window, and of the
            others; 15 us in the server), a map sample every 5 ms on both boards, a PDU every 10 ms from 12 s on whose true
            latency is 2.011 ms (1.5 ms to send_done, 0.11 ms to the arrival, 0.401 ms to the delivery)."""
            raw_a = lambda t: t + 5 * 10 ** 9
            mono_a = lambda t: raw_a(t) + 7 * 10 ** 9
            raw_b = lambda t: t + 11 * 10 ** 9 - (t - T0) * rate_b // 1_000_000

            def mono_b(t):
                steered = 0
                if steer:   # CLOCK_MONOTONIC gains steer[2] ns against the raw clock per 1,000,000 ns of its own reading
                    span = max(0, min(raw_b(t), raw_b(T0 + steer[1])) - raw_b(T0 + steer[0]))
                    steered = span * steer[2] // (1_000_000 - steer[2])
                return raw_b(t) + 3 * 10 ** 9 + steered

            def point(raw, mono, t, before, width=300):
                """the three reads next to an event at t: (monotonic read, raw stamp of the exchange, width)"""
                first = t - 50 - width if before else t + 50
                r1, mid, r2 = raw(first), mono(first + width // 2), raw(first + width)
                return mid, (r2 if before else r1), r2 - r1
            ex = []
            for k in range(seconds * 1000 // 101):
                t = T0 + k * 101_000_000
                there, back = paths[0] if k % 50 == 25 else paths[1]
                pts = (point(raw_a, mono_a, t, True), point(raw_b, mono_b, t + there, False),
                       point(raw_b, mono_b, t + there + 15_000, True), point(raw_a, mono_a, t + there + 15_000 + back, False))
                ex.append((k,) + tuple(q[0] for q in pts) + tuple(q[1] for q in pts) + tuple(q[2] for q in pts))
            times = range(T0 - 2 * 10 ** 9, T0 + (seconds + 2) * 10 ** 9, 5_000_000)
            tx, rx = [], []
            for i in range(pdus):
                rel = T0 + 12 * 10 ** 9 + i * 10_000_000
                arrive = rel + 1_500_000 + 110_000
                tx.append((0, i, mono_a(rel), mono_a(rel + 1000), mono_a(rel + 1_400_000), mono_a(rel + 1_500_000)))
                rx.append((0, i, mono_b(arrive), mono_b(arrive + 400_000), mono_b(arrive + 401_000), 'ok'))
            return {'ex': ex, 'a': [(raw_a(t), mono_a(t + 200), raw_a(t + 400)) for t in times],
                    'b': [(raw_b(t), mono_b(t + 200), raw_b(t + 400)) for t in times], 'tx': tx, 'rx': rx,
                    'raw_b': raw_b, 'mono_b': mono_b}

        def put(tag, w, dropped=(0, 0), fmt=2, judge=check_run, over_probe=(), over_a=(), over_b=(), release='release_ns'):
            """the five files of a world in a directory of their own, judged with the maps found beside the probe file;
            over_*: header lines put before the usual ones of that file; release='submit_ns': the gateway's files"""
            os.mkdir(p(tag))
            q = lambda n: os.path.join(p(tag), n)
            head = tuple(over_probe) + ('tool=bench_clock_probe', 'commit=0123456789ab', 'host_a=a', 'host_b=b', 'clock=CLOCK_MONOTONIC',
                                        'interval_ms=101', 'port=50105', 'cpu_a=1', 'cpu_b=1')
            if fmt == 2:
                head += ('format=2', 'clock_raw=CLOCK_MONOTONIC_RAW')
            write(q('clock_probe.csv'), COLUMNS[fmt], w['ex'] if fmt == 2 else [r[:5] for r in w['ex']], head,
                  (f"exchanges_sent={len(w['ex'])}", f"exchanges_completed={len(w['ex'])}"))
            write_map(q('clock_map_a.csv'), 'a', w['a'], dropped[0], over_a)
            write_map(q('clock_map_b.csv'), 'b', w['b'], dropped[1], over_b)
            write(q('tx.csv'), f'stream,seq,{release},start_ns,auth_done_ns,send_done_ns', w['tx'])
            write(q('rx.csv'), 'stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result', w['rx'])
            lines = []
            if judge is check_files:
                return check_files(q('clock_probe.csv'), q('clock_map_a.csv'), q('clock_map_b.csv'), out=lines.append), lines
            status = check_run(q('clock_probe.csv'), q('tx.csv'), q('rx.csv'), out=lines.append)
            return status, dict(tok.split('=') for tok in lines[-1].split(';')[0].split()[1:]), lines

        def latencies_ms(lines):
            line = next(x for x in lines if 'latency deliver' in x)
            return [float(line.split(key)[1].split(' ms')[0]) for key in ('min ', 'median ', 'max ')]

        # 1. Board B's CLOCK_MONOTONIC steered by +5,000 ppm for 10 s in the middle: a result on the raw clocks, every
        #    latency within the bound of the true one, both map bounds below 20 us; by the old definitions not a result.
        status, fig, lines = put('steered', world(steer=(25 * 10 ** 9, 35 * 10 ** 9, 5000)))
        assert status == 0, lines
        bound_ms = float(fig['bound_total_us']) / 1000
        low, _, high = latencies_ms(lines)
        assert 2.011 - bound_ms <= low and high <= 2.011 + bound_ms, (low, high, bound_ms)
        # the steps lie at a sample: the hold-out sees rate change x 5 ms / 2 = 12.5 us there, the kink term half of it
        assert fig['map_bound_a_us'] == '0.2' and fig['map_bound_b_us'] == '12.7', fig
        assert any('map of board B' in x and 'hold-out 12.5 us, kink 6.3 us' in x for x in lines), lines
        assert float(fig['bound_total_us']) == round(sum(float(fig[k]) for k in ('offset_bound_total_us', 'map_bound_a_us', 'map_bound_b_us')), 1) \
            or abs(float(fig['bound_total_us']) - sum(float(fig[k]) for k in ('offset_bound_total_us', 'map_bound_a_us', 'map_bound_b_us'))) < 0.2, fig
        assert 'not the verdict): FAIL' in lines[-2], lines[-2]
        # 2. Steady clocks: the old definitions agree, to within the bound, and a map's hold-out is 0
        steady = world()
        status, fig, lines = put('steady', steady)
        assert status == 0 and 'not the verdict): PASS' in lines[-2], lines
        assert abs(float(lines[-2].split('median here ')[1].split(' us')[0])) <= float(fig['bound_total_us']), lines[-2]
        assert sum('hold-out 0.0 us' in x for x in lines) == 2, lines
        assert check_form(*(os.path.join(p('steady'), n) for n in ('clock_probe.csv', 'clock_map_a.csv', 'clock_map_b.csv')), out=quiet) == 0
        assert put('steady_files', steady, judge=check_files)[0] == 0
        # 3. 60 ms without a valid sample inside the used range; a stamp 1 ms before the first valid sample
        cut = dict(steady, b=steady['b'][:5000] + steady['b'][5011:])
        status, fig, lines = put('gap', cut)
        assert status == 1 and 'map of board B: 60.0 ms between two valid samples exceeds 50 ms' in lines[-1], lines[-1]
        # not a result: no latency figure, but what the maps say is still printed
        assert not any('latency deliver' in x for x in lines) and sum(x.startswith('  map of board') for x in lines) == 4, lines
        late = dict(steady, a=[x for x in steady['a'] if x[1] >= steady['tx'][0][2] + 1_000_000])
        status, fig, lines = put('late_map', late)
        assert status == 1 and 'a stamp of board A lies outside its map' in lines[-1], lines[-1]
        # 4. one sample 6,000 ns wide: not valid, not used, the run stays a result
        wide_one = dict(steady, a=[(r1, m, r1 + 6000) if i == 6000 else (r1, m, r2) for i, (r1, m, r2) in enumerate(steady['a'])])
        status, fig, lines = put('wide_sample', wide_one)
        assert status == 0 and any('map of board A' in x and 'not valid 1,' in x for x in lines), lines
        # a board without a single valid sample
        status, fig, lines = put('no_valid', dict(steady, b=[(r1, m, r1 + 6000) for r1, m, _ in steady['b']]))
        assert status == 1 and 'map of board B: no valid sample' in lines[-1] and any('not valid 12800,' in x for x in lines), lines[-1]
        # 5. one exchange point whose own reading is 50 us off the map: one violation
        off_point = dict(steady, ex=[(r[0], r[1] + 50_000) + r[2:] if r[0] == 300 else r for r in steady['ex']])
        status, fig, lines = put('off_point', off_point)
        assert status == 1 and 'map of board A: 1 exchange points off the map' in lines[-1], lines[-1]
        # 6. samples that found the memory full
        status, fig, lines = put('dropped', steady, dropped=(0, 3))
        assert status == 1 and 'map of board B: samples_dropped=3' in lines[-1], lines[-1]
        assert put('dropped_files', steady, dropped=(3, 0), judge=check_files)[0] == 1
        # a map whose monotonic reads do not rise, and one whose footer does not count its rows: not a result, and
        # said in the one-line form too
        twisted = list(steady['a'])
        twisted[7000], twisted[7001] = twisted[7001], twisted[7000]
        status, fig, lines = put('twisted', dict(steady, a=twisted))
        assert status == 1 and 'do not rise' in lines[-1], lines[-1]
        lines = []
        assert check_form(os.path.join(p('twisted'), 'clock_map_a.csv'), os.path.join(p('twisted'), 'clock_map_b.csv'), p('none.csv'),
                          out=lines.append) == 1
        assert 'do not rise' in lines[0] and lines[1].endswith('clock_map_b.csv: ok') and lines[2].startswith(p('none.csv') + ': '), lines
        # 7. a file of format 1 has no raw stamps: refused for latency, by name
        status, fig, lines = put('format1', steady, fmt=1)
        assert status == 1 and 'format 1' in lines[-1] and fig['bound_total_us'] == 'none', lines[-1]
        assert 'not the verdict): PASS' in lines[-2], lines[-2]        # what those files gave before this change
        # a map file without its footer, and no map file at all
        os.mkdir(p('nomap'))
        status, fig, lines = put('nofoot_map', dict(steady, a=steady['a']))
        with open(os.path.join(p('nofoot_map'), 'clock_map_a.csv'), 'w', encoding='ascii') as f:
            f.write(MAP_COLUMNS + '\n1,2,3\n')
        lines = []
        assert check_run(os.path.join(p('nofoot_map'), 'clock_probe.csv'), os.path.join(p('nofoot_map'), 'tx.csv'),
                         os.path.join(p('nofoot_map'), 'rx.csv'), out=lines.append) == 1 and 'map of board A:' in lines[-1], lines[-1]
        os.remove(os.path.join(p('nofoot_map'), 'clock_map_a.csv'))
        lines = []
        assert check_run(os.path.join(p('nofoot_map'), 'clock_probe.csv'), os.path.join(p('nofoot_map'), 'tx.csv'),
                         os.path.join(p('nofoot_map'), 'rx.csv'), out=lines.append) == 1 and 'map of board A:' in lines[-1], lines[-1]
        # ---- E12 and E11 o, e: a shorter world for the cases that turn on one rule (probe 40 s, PDUs from 12 s to 24 s) ----
        small = world(seconds=40, pdus=1200)
        first_a, last_b = small['tx'][0][2], small['rx'][-1][4]         # the first release and the last delivery, as stamped

        def only(tag, w, reason, **how):
            """the run is not a result, for this one reason"""
            status, fig, lines = put(tag, w, **how)
            assert status == 1 and len(lines[-1].split('; ')) == 2 and reason in lines[-1], lines[-1]
            return lines
        assert put('small', small)[0] == 0
        # 9. (E12.1) Board B's map is evenly spaced at 5 ms of the board's own CLOCK_MONOTONIC except for one gap, and the
        #    clock gains 6,900 ppm from the middle of that gap on. The straight line across the gap is off by rate change
        #    x gap / 4 at the change; the hold-out of the samples next to the gap sees less than that.
        def kinked(tag, gap):
            change = 30 * 10 ** 9 + 200 + gap // 2      # after T0; the last sample before the gap is read at T0 + 30 s + 200
            w = world(steer=(change, 10 ** 12, 6900), rate_b=0, paths=((50_000, 20_000), (55_000, 25_000)))
            raw, mono = w['raw_b'], w['mono_b']
            # 5 ms of the steered clock are 4,965,500 ns: the samples behind the gap lie on that grid
            reads = [T0 + change + (gap // 2 + n * 5_000_000) * 9931 // 10_000 for n in range(6500)]
            w['b'] = ([x for x in w['b'] if x[1] <= mono(T0 + 30 * 10 ** 9 + 200)]
                      + [(raw(u - 200), mono(u), raw(u + 200)) for u in reads if u < T0 + 62 * 10 ** 9])
            status, fig, lines = put(tag, w)
            mp = ClockMap(os.path.join(p(tag), 'clock_map_b.csv'))
            mp.judge(w['rx'][0][2], w['rx'][-1][4], [])
            return status, fig, lines, mp, abs(mp.to_raw(mono(T0 + change)) - raw(T0 + change))     # a stamp at the change, carried over
        status, fig, lines, mp, error = kinked('kink30', 30_000_000)
        assert mp.kink == 51_750 and error == 51_750 and mp.holdout < mp.kink and mp.bound == 51_750 + 200, (mp.kink, error, mp.holdout, mp.bound)
        assert status == 0 and 38 < float(fig['offset_bound_total_us']) < 46 and fig['map_bound_b_us'] in ('51.9', '52.0'), lines[-1]
        assert any('map of board B' in x and 'kink 51.8 us' in x for x in lines), lines
        bound_ms = float(fig['bound_total_us']) / 1000
        low, _, high = latencies_ms(lines)     # a delivery stamped 3 ms before the change is 41 us off: more than the hold-out, inside the bound
        assert 2.011 - bound_ms <= low < 2.011 - 0.035 and high <= 2.011 + bound_ms, (low, high, bound_ms)
        status, fig, lines, mp, error = kinked('kink49', 49_000_000)
        assert mp.kink == 84_525 and error == 84_525 and status == 1, (mp.kink, error, lines[-1])
        assert len(lines[-1].split('; ')) == 2 and 'bound in total' in lines[-1] and 'exceeds 100 us' in lines[-1], lines[-1]
        # 10. (E12.7) Steady clocks, read noise of up to 150 ns per sample, and one wake-up of board A's sampler 12 ms late,
        #     the two samples it owes following 2 us apart (their noise the worst case: +150, -150, +150 ns). A slope
        #     between two such samples is 15 %; read over 4 ms or more, the kink term stays below 1 us.
        noisy = [(r1, m + rnd(301) - 150, r2) for r1, m, r2 in small['a']]
        r1, m, r2 = small['a'][4000]
        for n, noise in enumerate((150, -150, 150)):
            late = 12_000_000 + n * 2_000
            noisy[4000 + n] = (r1 + late, m + late + noise, r2 + late)
        status, fig, lines = put('late_wake', dict(small, a=noisy))
        kink = float(next(x for x in lines if 'map of board A, range' in x).split('kink ')[1].split(' us')[0])
        assert status == 0 and 0 < kink < 1 and float(fig['map_bound_a_us']) < 1, lines
        # (E12.7) "at least 4 ms": a sample exactly 4,000,000 ns before the interval, and one exactly 4,000,000 ns behind it,
        # are the ones the slopes are read to. m in ns at 0, 1, 5, 10, 14, 15, 20 ms; the interval from 5 to 10 ms.
        base = 10 ** 9
        exact = [(base + ms * 10 ** 6 - v, base + ms * 10 ** 6, base + ms * 10 ** 6 - v)
                 for ms, v in ((0, 0), (1, 1000), (5, 1000), (10, 1000), (14, 3000), (15, 1000), (20, 1000))]
        mp = ClockMap(write_map(p('exact4.csv'), 'a', exact))
        mp.judge(base + 5 * 10 ** 6, base + 10 * 10 ** 6, [])
        assert mp.kink == 625 and not mp.edge, mp.kink      # |2000 ns / 4 ms - 0| x 5 ms / 4; to 0 ms and 15 ms it would be 250
        # (E12.7) the used range begins at the first valid sample of the file, or ends at its last: no sample 4 ms before
        # its first interval, or behind its last one
        only('edge', dict(small, a=[x for x in small['a'] if x[1] >= first_a - 5_000_000]),     # the sample 5 ms before the first release is the first
             'map of board A: an interval of the used range has no sample 4 ms before it or behind it in the file')
        only('edge_end', dict(small, a=[x for x in small['a'] if x[1] <= small['tx'][-1][5] + 5_000_000]),
             'map of board A: an interval of the used range has no sample 4 ms before it or behind it in the file')
        # (E11 o) every second sample of board A not valid: 10 ms between valid ones, and none has two valid neighbours
        only('no_holdout', dict(small, a=[(r1, m, r1 + 6000) if i % 2 else (r1, m, r2) for i, (r1, m, r2) in enumerate(small['a'])]),
             'map of board A: no sample of the used range has two valid neighbours')
        # (E12.2) the three files are not those of one probe pair: eight header lines, eight reasons
        status, fig, lines = put('identity', small, over_probe=('clock=CLOCK_TAI', 'clock_raw=CLOCK_REALTIME'),
                                 over_a=('role=b', 'commit=ba9876543210', 'clock_raw=CLOCK_MONOTONIC'),
                                 over_b=('host=c', 'interval_ms=10', 'clock=CLOCK_BOOTTIME'))
        assert status == 1 and lines[-1].split('; ')[1:] == [
            "the probe file's header says clock=CLOCK_TAI, not CLOCK_MONOTONIC",
            "the probe file's header says clock_raw=CLOCK_REALTIME, not CLOCK_MONOTONIC_RAW",
            "map of board A: its header says role=b, not a",
            "map of board A: its header says commit=ba9876543210, not 0123456789ab (the probe file's)",
            "map of board A: its header says clock_raw=CLOCK_MONOTONIC, not CLOCK_MONOTONIC_RAW",
            "map of board B: its header says host=c, not b (the probe file's host_b)",
            "map of board B: its header says clock=CLOCK_BOOTTIME, not CLOCK_MONOTONIC",
            "map of board B: its header says interval_ms=10, not 5"], lines[-1]
        # (E11 e) "not above": a sample exactly 5,000 ns wide is valid; exactly 50 ms between two valid samples pass
        status, fig, lines = put('width5000', dict(small, a=[(r1, m, r1 + 5000) if i == 4000 else (r1, m, r2) for i, (r1, m, r2) in enumerate(small['a'])]))
        assert status == 0 and any('map of board A' in x and 'not valid 0,' in x for x in lines), lines
        status, fig, lines = put('gap50', dict(small, a=small['a'][:4000] + small['a'][4009:]))     # board A: 50,000,000 ns to the digit
        assert status == 0 and any('map of board A' in x and 'largest gap 50.0 ms' in x for x in lines), lines
        # (E4) an exchange point wider than 5,000 ns checks nothing: its reading, 50 us off the map, is not a violation
        status, fig, lines = put('wide_point', dict(small, ex=[(r[0], r[1] + 50_000) + r[2:9] + (6000,) + r[10:] if r[0] == 150 else r
                                                               for r in small['ex']]))
        assert status == 0, lines[-1]
        # (E4) a stamp of board B behind the last valid sample of its map
        only('short_map', dict(small, b=[x for x in small['b'] if x[1] <= last_b - 1_000_000]), 'a stamp of board B lies outside its map')
        # (E4, E11 d) PDUs over 4 s: 80 exchange points check each map, fewer than the 100 of a harness run, enough for a gateway run
        few = world(seconds=40, pdus=400)
        status, fig, lines = put('few', few)
        assert status == 1 and lines[-1].split('; ')[1:] == [f'map of board {x}: 80 exchange points check it, fewer than 100' for x in 'AB'], lines[-1]
        assert put('few_gateway', few, release='submit_ns')[0] == 0
    assert median([4, 1, 3]) == 3 and median([4, 1, 3, 2]) == Fraction(5, 2) and median([7]) == 7
    print('check_clock_probe selftest: ok')
    return 0


def main(argv):
    modes = {'--zero': (check_zero, (1,)), '--pair': (check_pair, (2,)), '--run': (check_run, (3, 5)), '--files': (check_files, (3,))}
    if argv[1:] == ['--selftest']:
        return selftest()
    if argv[1:2] == ['--form']:
        return check_form(*argv[2:])
    if len(argv) < 2 or argv[1] not in modes or len(argv) - 2 not in modes[argv[1]][1]:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        return modes[argv[1]][0](*argv[2:])
    except (Invalid, OSError, KeyError, ValueError) as e:
        figures = ' '.join(f'{k}=none' for k in RUN_FIGURES) if argv[1] == '--run' else 'offset_bound_us=none'
        print(f'FAIL {figures}; {e}')
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
