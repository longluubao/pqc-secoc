"""cyclictest_<policy>_cpu<N>.txt: scheduling-latency histogram written by scripts/run_cyclictest.sh.

The file is '# key=value' lines with the run conditions, cyclictest's histogram in 1 us buckets
('<latency_us> <count>', one measuring thread), its '# Total / Min / Avg / Max Latencies /
Histogram Overflows' lines, and more '# key=value' lines written after the run.
"""
import math
import re

import numpy as np

from analysis import csvio

NAME = "cyclictest*.txt"
PERCENTILES = (99, 99.9, 99.99)
LATE_US = (100, 1000)  # wake-ups later than these are counted
_SUMMARY = re.compile(r"# (Total|Min Latencies|Avg Latencies|Max Latencies|Histogram Overflows): (\d+)")
_BUCKET = re.compile(r"(\d+) (\d+)")
_HEADER = ("policy", "cpu", "interval_us", "duration_s")


def read(path):
    """Returns (meta, counts, summary): the '# key=value' lines, the histogram as an array indexed by
    latency in us, and cyclictest's own summary numbers. A line that is neither is an error."""
    meta, counts, summary = {}, [], {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(map(str.strip, f), 1):
            if not line:
                continue
            if line.startswith("#"):
                if m := _SUMMARY.fullmatch(line):
                    summary[m[1]] = int(m[2])
                elif m := csvio._META.match(line):
                    meta[m[1]] = m[2].strip()
                continue
            m = _BUCKET.fullmatch(line)
            if not m or int(m[1]) != len(counts):
                raise csvio.CsvError(f"{path}:{lineno}: expected the histogram row '{len(counts):06d} <count>' "
                                     f"(one thread, buckets in order), got {line!r}")
            counts.append(int(m[2]))
    return meta, np.array(counts, dtype=np.int64), summary


def analyse(meta, counts, summary, env=None):
    """Scheduling-latency statistics of one cyclictest run, in microseconds.

    samples = Total + Histogram Overflows. In the rt-tests source a latency at or above the histogram
    size goes to the overflow counter only and into no bucket; '# Total:' is the sum of the printed
    buckets (checked here) and so excludes the overflows; the Min / Avg / Max lines include the
    overflowed samples. min, avg and max are therefore cyclictest's own lines (avg is an integer
    there); mean is the histogram mean when nothing overflowed.

    Percentiles are read from the histogram: the smallest latency L with at least that share of all
    samples at or below L, the overflows counting as values above the last bucket. That is the
    inverse empirical distribution on 1 us buckets, not the interpolating type-7 estimator used for
    the raw-sample tables. A percentile that lies among the overflows is None: all that is known is
    that it is above the last bucket (histogram_us - 1), which the table prints as '> <last bucket>'
    and for which there is no number to give a macro.

    'late_over': the number of wake-ups later than each of LATE_US microseconds (strictly above),
    overflows included.

    'validity': invalid (not to be analysed) when the summary lines or the end-of-run lines are
    missing (the run was cut short), the CPU frequency changed, get_throttled shows an active bit or
    changed (in the file or the run's env file), or the scheduling class that was read back from the
    running threads is not the policy asked for. The load condition is the '# load=' line; a file
    without one is labelled cpu<N>.
    """
    missing = [k for k in _HEADER if k not in meta]
    if missing:
        raise ValueError(f"missing header key(s) {missing}: not a file written by run_cyclictest.sh")
    cpu, policy = meta["cpu"], meta["policy"]
    out = {"policy": policy, "cpu": int(cpu), "priority": int(meta["priority"]) if meta.get("priority", "").isdigit() else None,
           "load": meta.get("load") or f"cpu{cpu}", "load_from_header": "load" in meta,
           "interval_us": float(meta["interval_us"]), "duration_s": float(meta["duration_s"]), "host": meta.get("host"),
           "histogram_us": int(counts.size)}
    reasons, warnings = [], []
    lacking = [k for k in ("Total", "Min Latencies", "Avg Latencies", "Max Latencies", "Histogram Overflows") if k not in summary]
    lacking += [k for k in ("freq_khz_end", "throttled_end") if k not in meta]
    if lacking:
        reasons.append(f"incomplete ({', '.join(lacking)} missing): the run was cut short")
    start, end = meta.get("freq_khz_start"), meta.get("freq_khz_end")
    if start is not None and end is not None and start != end:
        reasons.append(f"CPU frequency changed during the run ({start} -> {end} kHz)")
    states = []
    for where, readings in (("file", [meta[k] for k in ("throttled_start", "throttled_end") if k in meta]),
                            (f"env file of {env['host']}" if env else "", [t for _, t in env["throttled"]] if env else [])):
        state, why, warn = csvio.throttling(readings, where)
        states.append(state)
        reasons += why
        warnings += warn
    seen = meta.get("threads_observed_class_rtprio_cpu")
    if seen is not None:
        threads = [t.strip() for t in seen.split(";")]
        if policy == "fifo" and f"FF {meta.get('priority')} {cpu}" not in threads:
            reasons.append(f"no thread ran as SCHED_FIFO priority {meta.get('priority')} on cpu {cpu} (observed: {seen})")
        if policy == "other" and (f"TS - {cpu}" not in threads or any(t.startswith(("FF", "RR")) for t in threads)):
            reasons.append(f"threads did not all run as SCHED_OTHER on cpu {cpu} (observed: {seen})")
    out["validity"] = {"valid": not reasons, "reasons": reasons, "warnings": warnings, "freq_khz_start": start,
                       "freq_khz_end": end, "throttled_start": meta.get("throttled_start"),
                       "throttled_end": meta.get("throttled_end"),
                       "throttled": True if True in states else False if False in states else None}
    if lacking:
        return out
    if int(counts.sum()) != summary["Total"]:
        raise ValueError(f"the histogram sums to {int(counts.sum())} but '# Total:' says {summary['Total']}")
    overflows, n = summary["Histogram Overflows"], summary["Total"] + summary["Histogram Overflows"]
    filled = np.flatnonzero(counts)
    if filled.size and (summary["Min Latencies"] != filled[0] or (overflows == 0 and summary["Max Latencies"] != filled[-1])):
        raise ValueError(f"cyclictest's min/max lines ({summary['Min Latencies']}, {summary['Max Latencies']}) disagree "
                         f"with the histogram ({int(filled[0])}, {int(filled[-1])})")
    if overflows and summary["Max Latencies"] < counts.size:
        raise ValueError(f"{overflows} overflow(s) but Max Latencies is {summary['Max Latencies']}, inside the histogram "
                         f"of {counts.size} buckets")
    cumulative = np.cumsum(counts)
    out.update(samples=n, overflows=overflows, min_us=summary["Min Latencies"], avg_us=summary["Avg Latencies"],
               max_us=summary["Max Latencies"],
               mean_us=float(counts @ np.arange(counts.size)) / n if n and not overflows else None)
    for p in PERCENTILES:
        i = int(np.searchsorted(cumulative, math.ceil(p / 100 * n - 1e-9)))  # first bucket with enough samples at or below
        out[f"p{p:g}_us"] = i if n and i < counts.size else None
    # wake-ups later than t (strictly above), overflows included: an overflow is at or above the histogram size, so it
    # is later than every t inside the histogram; against a t beyond the histogram it cannot be placed (None)
    out["late_over"] = [{"threshold_us": t, "k": int(counts[t + 1:].sum()) + overflows if t < counts.size else
                         0 if not overflows else None} for t in LATE_US]
    return out
