"""sign_attrib.csv (seq, wall_ns, cpu_ns[, shake_calls]): wall time and thread processor time of every
signing call (experiment E1a), optionally with the number of SHAKE-256 initialisations inside it."""
import math

import numpy as np
from scipy import stats as sps

from analysis import stats

THRESHOLDS_MS = (5, 10, 15, 20)   # wall-time thresholds of the tail attribution
OFF_OVER_US = (100, 1000, 5000)   # thresholds for the per-call time off the processor
CPU_SUM_TOLERANCE = 0.01          # the cpu_ns of all rows must add up to the footer's cpu_s within this fraction
WALL_SLACK_NS = 2000              # wall_ns may be below cpu_ns by this much (resolution of the two clocks)
FLOOR_MARGIN_US = 100             # a call is above the floor when its off exceeds the median off by more than this
NOT_OFF_CPU = "includes the per-call clock-read floor; not a time off the processor"  # why off_total_s is no manuscript number


def _positive(meta, key):
    v = meta[key]
    if not (v.isascii() and v.isdigit()) or int(v) == 0:
        raise ValueError(f"header {key}={v!r} is not a positive integer")
    return int(v)


def rounds_of(meta, cols):
    """Rounds of the rejection loop per call, (shake_calls - shake_calls_min) / shake_calls_step + 1
    as a float array, or None for a file without the fourth column. The header must fit the columns:
    four columns need shake_calls_min and shake_calls_step; three columns need shake_counted=off (or
    no such line, as in files written before the switch existed)."""
    if "shake_calls" not in cols:
        if meta.get("shake_counted", "off") != "off":
            raise ValueError(f"three columns, but the header says shake_counted={meta['shake_counted']}")
        return None
    if "shake_calls_min" not in meta or "shake_calls_step" not in meta:
        raise ValueError("four columns need the header lines shake_calls_min and shake_calls_step")
    return (cols["shake_calls"] - _positive(meta, "shake_calls_min")) / _positive(meta, "shake_calls_step") + 1


def consistency(meta, cols):
    """Reasons why the rows contradict the file itself; any of them makes the file invalid:
    - the cpu_ns of all rows, warm-up included, do not add up to the footer's cpu_s within 1%
      (CPU_SUM_TOLERANCE; skipped for a file without that footer line);
    - a row has wall_ns < cpu_ns - WALL_SLACK_NS;
    - a shake_calls value is not shake_calls_min plus a whole multiple of shake_calls_step.
    A header that does not fit the columns, or a seq that is not contiguous from 0, is a malformed
    file and raises ValueError."""
    seq, wall, cpu = cols["seq"], cols["wall_ns"], cols["cpu_ns"]
    if not np.array_equal(np.sort(seq), np.arange(seq.size)):
        raise ValueError("seq is not contiguous from 0")
    rounds = rounds_of(meta, cols)
    reasons = []
    try:
        footer = float(meta["cpu_s"])
    except (KeyError, ValueError):
        footer = None
    total = float(cpu.sum()) / 1e9
    if footer is not None and abs(total - footer) > CPU_SUM_TOLERANCE * footer:
        reasons.append(f"sum of cpu_ns over all rows is {total:.6f} s, the footer's cpu_s is {footer:.6f} s: more than "
                       f"{CPU_SUM_TOLERANCE:.0%} apart")
    short = np.flatnonzero(wall < cpu - WALL_SLACK_NS)
    if short.size:
        reasons.append(f"{short.size} row(s) with wall_ns < cpu_ns - {WALL_SLACK_NS} (first: seq {int(seq[short[0]])})")
    if rounds is not None:
        off = np.flatnonzero((rounds < 1) | (rounds != np.floor(rounds)))
        if off.size:
            reasons.append(f"{off.size} row(s) with shake_calls off the progression {meta['shake_calls_min']} + k x "
                           f"{meta['shake_calls_step']} (first: seq {int(seq[off[0]])})")
    return reasons


def rounds_threshold(intercept_us, slope_us, t_us):
    """Smallest whole number of rounds r >= 1 for which the line intercept + slope x r is above t
    (strict; a call has at least one round). None for a line that does not rise."""
    if not slope_us > 0:
        return None
    r = max(1, math.floor((t_us - intercept_us) / slope_us) + 1)
    while r > 1 and intercept_us + slope_us * (r - 1) > t_us:  # the division is only a first guess: the line decides
        r -= 1
    while not intercept_us + slope_us * r > t_us:
        r += 1
    return r


def analyse(meta, cols, warmup, thresholds_ms=THRESHOLDS_MS, block_len=None, n_boot=None, rng=None):
    """Over the calls with seq >= warmup, times in microseconds. 'Above' is strict everywhere.

    'wall_us' and 'cpu_us': the median (type 7) and the mean of the wall time and of the processor
    time of a call. In a file with shake_calls both include the counting. With block_len, n_boot
    and rng each median gets 'p50_ci95', the interval the signing median of crypto_ops has: the
    moving-block bootstrap percentile interval over the calls in acquisition order (wall time
    first, then processor time, from the same generator), when at least two blocks fit; 'bootstrap'
    then names the method and its parameters.

    off = wall_ns - cpu_ns of a call: by the schema the time the pinned thread did not run during it
    (how interrupt time is counted depends on the kernel, see the run record). 'off_total_s' is the
    sum of off over the calls, small negative values included; 'off_max_us' the largest; 'off_over'
    counts the calls with off above each of OFF_OVER_US. Every call carries a floor of a few
    microseconds that is not time off the processor: the two inner clock reads lie inside the wall
    interval and outside the processor-time interval. 'off_min_us' and 'off_median_us' show its
    size, and off_total_s contains it n times, so off_total_s is not a time off the processor.
    'off_above_floor': the calls whose off is more than FLOOR_MARGIN_US above the floor (the median
    off), k of them, and 'seconds', the sum over them of off minus the floor.

    'wall_over', per wall-time threshold t: k = calls with wall time above t; cpu_also_over = those
    of them whose processor time is above t as well; max_off_us = the largest off among the k calls;
    rounds_min = the fewest rounds among them (None without the fourth column or with k = 0);
    rounds_min_or_more = the calls of the whole sample with at least rounds_min rounds (when it
    equals k, "wall time above t" and "at least rounds_min rounds" are the same set of calls).

    'cpu_over', per threshold t, whatever the wall time: k = calls with processor time above t;
    rounds_min and rounds_min_or_more as in 'wall_over', for those k calls; rounds_threshold = the
    smallest whole number of rounds for which the fitted line (below) is above t, see
    rounds_threshold(); and the calls of the whole sample in the four cells of processor time above
    t or not against rounds >= rounds_threshold or not: both, cpu_only, rounds_only, neither
    (k = both + cpu_only). Calls with exactly rounds_threshold rounds, or one fewer, fall on either
    side of t by where the line crosses it within that round; beyond that one-round ambiguity:
    cpu_only_below_crossing = processor time above t with fewer than rounds_threshold - 1 rounds,
    rounds_only_above_crossing = processor time not above t with more than rounds_threshold rounds.
    'share' = k / n with 'share_cp95', its exact two-sided Clopper-Pearson 95% interval (independent
    calls assumed). 'rounds_at_least': k = calls with at least rounds_threshold rounds, share = k / n
    with share_cp95, and share_geometric = (1 - one_share)^(rounds_threshold - 1), the share of calls
    with at least that many rounds under a geometric law with the measured one-round share, and
    share_geometric_ci95, the same formula at the two ends of the exact 95% interval of the
    one-round share (the larger one-round share gives the lower bound; rounds_threshold is taken as
    given, so the uncertainty of the fitted line is not in it); both None when no call has one
    round. The threshold and everything that needs it are None without a line or with a line that
    does not rise.

    'rounds' (files with shake_calls): mean, max, one_share = share of the calls with one round
    (one_share_cp95: its exact two-sided Clopper-Pearson 95% interval, independent calls assumed),
    geometric_mean = 1 / one_share, the mean of a geometric law with that one-round share;
    'per_round': for every number of rounds that occurs its n, share, mean processor time and
    geometric_share = one_share x (1 - one_share)^(rounds - 1); 'fit': the ordinary least-squares
    line of processor time on rounds (slope cpu_per_round_us, intercept cpu_intercept_us, r2), and of
    its residuals the sd with divisor n - 2, the type-7 percentiles p0.1 and p99.9, minimum and
    maximum. No fit when every call has the same number of rounds. A file with the fourth column is
    an instrumented run: its times include the counting.
    """
    order = np.argsort(cols["seq"], kind="stable")
    keep = order[cols["seq"][order] >= warmup]
    wall, cpu = cols["wall_ns"][keep] / 1e3, cols["cpu_ns"][keep] / 1e3
    if wall.size == 0:
        raise ValueError(f"no calls left after dropping seq < {warmup}")
    all_rounds = rounds_of(meta, cols)
    rounds = None if all_rounds is None else all_rounds[keep]
    off = wall - cpu
    floor = float(np.median(off))
    above = off[off > floor + FLOOR_MARGIN_US]
    out = {"n_total": int(cols["seq"].size), "n_warmup_dropped": int(cols["seq"].size - wall.size), "n": int(wall.size),
           "wall_us": {"p50": float(np.median(wall)), "mean": float(wall.mean())},
           "cpu_us": {"p50": float(np.median(cpu)), "mean": float(cpu.mean())},
           # the measured upper percentiles of the processor time (type 7), to set beside what line and law imply
           "cpu_tail_us": dict(zip(("p99", "p99.9"), np.quantile(cpu, [0.99, 0.999]).tolist())),
           "off_total_s": float(off.sum()) / 1e6, "off_min_us": float(off.min()), "off_median_us": floor,
           "off_max_us": float(off.max()),
           "off_above_floor": {"k": int(above.size), "seconds": float((above - floor).sum()) / 1e6},
           "off_over": [{"threshold_us": u, "k": int(np.count_nonzero(off > u))} for u in OFF_OVER_US], "wall_over": [],
           "cpu_over": [], "rounds": None}
    if block_len and wall.size >= 2 * block_len:  # the same condition and call as for the crypto_ops series
        for name, x in (("wall_us", wall), ("cpu_us", cpu)):
            out[name]["p50_ci95"] = stats.block_bootstrap_quantile_ci(x, [0.5], block_len, n_boot, 0.95, rng)[0].tolist()
        out["bootstrap"] = {"method": "moving-block bootstrap, percentile interval", "block_len": block_len, "n_boot": n_boot}
    n, fit = int(wall.size), None
    ones = None if rounds is None else int(np.count_nonzero(rounds == 1))  # the count itself, for the exact interval
    one, one_ci = (None, None) if rounds is None else (ones / n, stats.clopper_pearson_interval(ones, n))
    if rounds is not None and rounds.min() != rounds.max():
        line = sps.linregress(rounds, cpu)
        resid = cpu - (line.intercept + line.slope * rounds)
        low, high = np.quantile(resid, [0.001, 0.999])
        fit = {"cpu_per_round_us": float(line.slope), "cpu_intercept_us": float(line.intercept), "r2": float(line.rvalue ** 2),
               "resid_us": {"n": int(resid.size), "sd": math.sqrt(float((resid ** 2).sum()) / (resid.size - 2)),
                            "p0.1": float(low), "p99.9": float(high), "min": float(resid.min()), "max": float(resid.max())}}
    for t in thresholds_ms:
        over = wall > 1e3 * t
        k = int(np.count_nonzero(over))
        fewest = int(rounds[over].min()) if k and rounds is not None else None
        out["wall_over"].append({"threshold_ms": t, "k": k, "cpu_also_over": int(np.count_nonzero(over & (cpu > 1e3 * t))),
                                 "max_off_us": float(off[over].max()) if k else None, "rounds_min": fewest,
                                 "rounds_min_or_more": None if fewest is None else int(np.count_nonzero(rounds >= fewest))})
        over = cpu > 1e3 * t
        k = int(np.count_nonzero(over))
        fewest = int(rounds[over].min()) if k and rounds is not None else None
        at = rounds_threshold(fit["cpu_intercept_us"], fit["cpu_per_round_us"], 1e3 * t) if fit else None
        cells, at_least = dict.fromkeys(("both", "cpu_only", "rounds_only", "neither", "cpu_only_below_crossing",
                                         "rounds_only_above_crossing")), None
        if at is not None:
            many = rounds >= at
            cells = {name: int(np.count_nonzero(c)) for name, c in zip(cells, (
                over & many, over & ~many, ~over & many, ~over & ~many, over & (rounds < at - 1), ~over & (rounds > at)))}
            m = int(np.count_nonzero(many))
            at_least = {"k": m, "share": m / n, "share_cp95": list(stats.clopper_pearson_interval(m, n)),
                        "share_geometric": (1 - one) ** (at - 1) if one else None,
                        "share_geometric_ci95": [(1 - p) ** (at - 1) for p in reversed(one_ci)] if one else None}
        out["cpu_over"].append({"threshold_ms": t, "k": k, "share": k / n, "share_cp95": list(stats.clopper_pearson_interval(k, n)),
                                "rounds_min": fewest,
                                "rounds_min_or_more": None if fewest is None else int(np.count_nonzero(rounds >= fewest)),
                                "rounds_threshold": at, **cells, "rounds_at_least": at_least})
    if rounds is not None:
        law = None
        if fit and one and one < 1:
            # line and law together: the smallest number of rounds r with 1 - (1 - one)^r >= q under the geometric law,
            # and the processor time the line gives for r rounds
            law = {}
            for name, q in (("p50", 0.5), ("p99", 0.99), ("p99.9", 0.999)):
                r = max(1, math.ceil(math.log(1 - q) / math.log(1 - one) - 1e-12))
                law[name] = {"rounds": r, "cpu_us": fit["cpu_intercept_us"] + fit["cpu_per_round_us"] * r}
        out["rounds"] = {
            "mean": float(rounds.mean()), "one_share": one, "one_share_cp95": list(one_ci), "max": int(rounds.max()),
            "geometric_mean": 1 / one if one else None,
            "fit": fit, "law": law,
            "per_round": [{"rounds": int(r), "n": int(np.count_nonzero(rounds == r)), "share": float(np.mean(rounds == r)),
                           "geometric_share": one * (1 - one) ** (int(r) - 1), "mean_cpu_us": float(cpu[rounds == r].mean())}
                          for r in np.unique(rounds)]}
    return out
