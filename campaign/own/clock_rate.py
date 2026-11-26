"""Independent second reading of what the probe files of E9 say about the two clocks themselves (keys clock.*),
compared key by key with the toolkit. Written from Addendum C of E9_SPEC.md alone; it shares no code with the toolkit
or with e2e_compare.py. No PDU and no latency is read.

usage: python3 -I -B clock_rate.py <inputs.tsv> <runs_root> [<toolkit_out_dir> <prefix>]
       python3 -I -B clock_rate.py --file <clock_probe.csv>
       python3 -I -B clock_rate.py --selftest
--file reads ONE probe file (pair_ab.csv and pair_ba.csv of a probe test have the same columns), without a checksum,
and prints one line of key=value pairs: exchanges, anchors, segments, rate_ppm_min, rate_ppm_max, rate_ppm_median,
rate_step_ppm_max, offset_range_ms, span_s, impossible_rows (plain decimals; the rate keys are absent without a
segment). Exit status 0 when the file has at least two segments, so that a step exists, and 1 otherwise (also for a
file without a row). It is the steadiness check of a probe-only run: the caller compares rate_step_ppm_max with 5.
In a file whose client ran on board B (pair_ba.csv) the rates have the opposite sign; the step is an absolute value.
<inputs.tsv>: lines 'cell <tab> run directory <tab> file inside it <tab> sha256' ('#' lines are comments); every file
is read from <runs_root>/<run directory>/<file> and its SHA-256 is checked first (a mismatch stops the reader).
Without the last two arguments the own values are printed. With them every key <prefix>.<cell>.<stat> and
<prefix>.all.<stat> of <toolkit_out_dir>/numbers.csv is compared with the own value, in both directions (a key that
only one side has is a difference; rows of unit text are not compared); the last line is OWN-CHECK AGREES or
OWN-CHECK DISAGREES: <n> difference(s), exit status 0 or 1. Standard library only; nothing is written but <toolkit_out_dir>/own_compared_keys.txt (Addendum F4).

Definitions (Addendum C, 1 to 4), in whole nanoseconds and exact fractions until the one final division:
  exchange   2 theta = (t2 - t1) - (t4 - t3), board B's clock minus board A's; delta = (t4 - t1) - (t3 - t2);
             2 tau = t1 + t4; exchanges in the order of tau
  anchors    windows of 5 s counted from the first exchange; the anchor of a window is its exchange with the smallest
             delta, the earlier one on a tie. ALL anchors are used, the first and the last included.
  segment    two consecutive anchors whose tau differ by at least 2.0 s; rate = change of theta / change of tau, ppm
  per file   segments; rate_ppm_min, rate_ppm_max, rate_ppm_median over its segments; rate_step_ppm_max = the largest
             |difference| between the rates of two consecutive segments; offset_range_ms = largest minus smallest
             theta of its anchors; span_s = tau of the last anchor minus tau of the first
  overall    files; rate_ppm_min, rate_ppm_max over all segments; rate_abs_max_ppm and the same in percent,
             rate_abs_max_pct; rate_step_ppm_max; offset_range_ms_max; files_steady = files whose rate_step_ppm_max
             is at most 5 ppm, files_adjusted = the others; rate_ppm_steady_min, rate_ppm_steady_max = smallest and
             largest median rate among the steady files
Readings where the addendum leaves a choice:
  1. "consecutive segments" are neighbours in the list of the file's segments in time order, also when a pair of
     anchors closer than 2 s (no segment) lies between them;
  2. the median of an even number of rates is the mean of the two middle ones;
  3. a file with fewer than two segments has rate_step_ppm_max = 0; a file without a segment has no rate key and its
     median takes no part in rate_ppm_steady_*; an overall value with nothing to take it from has no key;
  4. every row of a file is used as it stands (a file is not judged here; the count of impossible rows is printed).
Tolerance of the comparison (raw values, not the rounded ones): the values are quotients of differences of integer
time stamps. This reader forms them exactly; an implementation in floating point that works in microseconds or
seconds loses at most about 0.004 ns on an offset near 2e13 ns, which is below 1e-8 ppm on a rate over 2 s or more.
Allowed: 1e-6 ppm on rates and steps (a millionth of the 1 ppm the keys are rounded to), 1e-10 on the percentage,
1e-7 ms on offsets, 1e-9 s on spans, or nine digits relative; counts must be equal.
"""
import csv
import hashlib
import math
import os
import sys
from fractions import Fraction
from pathlib import Path
from statistics import median

WINDOW2 = 2 * 5_000_000_000          # 5 s in the doubled nanoseconds of 2 tau
SEGMENT2 = 2 * 2_000_000_000         # 2.0 s likewise
STEADY_PPM = 5
TOLERANCE = {"rate_abs_max_pct": 1e-10, "offset_range_ms": 1e-7, "offset_range_ms_max": 1e-7, "span_s": 1e-9}     # the others: 1e-6 ppm


def record_compared(analysis_dir, keys):
    """Addendum F4: <analysis_dir>/own_compared_keys.txt, the keys that this call compared with a toolkit value and found
    equal, one per line, sorted. Under e9_compare.py (OWN_COMPARED_KEYS=add) the readers of one call add to one file;
    a direct call writes its own set. A call that does not end in agreement leaves no key of its own."""
    path = Path(analysis_dir) / "own_compared_keys.txt"
    if path.parent.is_dir():
        old = path.read_text().split() if os.environ.get("OWN_COMPARED_KEYS") == "add" and path.exists() else []
        path.write_text("".join(k + "\n" for k in sorted({*old, *keys})))


def parse(text):
    """[(t1, t2, t3, t4)] of the rows of a clock_probe.csv; '#' lines and the column line are skipped."""
    rows = []
    for line in text.splitlines():
        cells = line.split(",")
        if line and not line.startswith("#") and cells[0].isdigit():
            rows.append(tuple(int(c) for c in cells[1:5]))
    return rows


def anchors_of(rows):
    """The anchors of a probe file as (2 tau, 2 theta, delta, position in the file), in the order of tau."""
    ex = sorted(((t1 + t4, (t2 - t1) - (t4 - t3), (t4 - t1) - (t3 - t2), i) for i, (t1, t2, t3, t4) in enumerate(rows)), key=lambda e: e[0])
    best = {}
    for e in ex:
        w = (e[0] - ex[0][0]) // WINDOW2
        if w not in best or e[2] < best[w][2]:        # strictly smaller: on a tie the earlier one stays
            best[w] = e
    return [best[w] for w in sorted(best)]


def file_stats(rows):
    """{stat: exact value} of one probe file; None where the file has nothing to take the value from."""
    a = anchors_of(rows)
    rates = [Fraction(y[1] - x[1], y[0] - x[0]) * 10**6 for x, y in zip(a, a[1:]) if y[0] - x[0] >= SEGMENT2]      # ppm
    steps = [abs(q - p) for p, q in zip(rates, rates[1:])]
    return {"segments": len(rates), "rate_ppm_min": min(rates, default=None), "rate_ppm_max": max(rates, default=None),
            "rate_ppm_median": median(rates) if rates else None, "rate_step_ppm_max": max(steps, default=Fraction(0)),
            "offset_range_ms": Fraction(max(x[1] for x in a) - min(x[1] for x in a), 2 * 10**6),
            "span_s": Fraction(a[-1][0] - a[0][0], 2 * 10**9)}


def impossible(rows):
    """Rows with t4 before t1, t3 before t2 or a negative delta (printed, not judged)."""
    return sum(t4 < t1 or t3 < t2 or (t4 - t1) - (t3 - t2) < 0 for t1, t2, t3, t4 in rows)


def one_line(rows):
    """(the statistics of one probe file as key=value pairs on one line, the exit status: 0 with at least two segments)."""
    if not rows:
        return "exchanges=0 anchors=0 segments=0", 1
    s = file_stats(rows)
    pairs = [f"exchanges={len(rows)}", f"anchors={len(anchors_of(rows))}", f"segments={s['segments']}"]
    pairs += [f"{k}={float(s[k]):.6f}" for k in ("rate_ppm_min", "rate_ppm_max", "rate_ppm_median", "rate_step_ppm_max", "offset_range_ms", "span_s")
              if s[k] is not None]
    return " ".join(pairs + [f"impossible_rows={impossible(rows)}"]), 0 if s["segments"] >= 2 else 1


def overall(files):
    """{stat: exact value} over the per-file results `files` (a list of file_stats)."""
    lows, highs = [f["rate_ppm_min"] for f in files if f["segments"]], [f["rate_ppm_max"] for f in files if f["segments"]]
    steady = [f for f in files if f["rate_step_ppm_max"] <= STEADY_PPM]
    medians = [f["rate_ppm_median"] for f in steady if f["segments"]]
    largest = max((abs(v) for v in lows + highs), default=None)
    return {"files": len(files), "rate_ppm_min": min(lows, default=None), "rate_ppm_max": max(highs, default=None),
            "rate_abs_max_ppm": largest, "rate_abs_max_pct": None if largest is None else largest / 10**4,
            "rate_step_ppm_max": max((f["rate_step_ppm_max"] for f in files), default=None),
            "offset_range_ms_max": max((f["offset_range_ms"] for f in files), default=None),
            "files_steady": len(steady), "files_adjusted": len(files) - len(steady),
            "rate_ppm_steady_min": min(medians, default=None), "rate_ppm_steady_max": max(medians, default=None)}


def keys(prefix, per_cell):
    """{key: own value as int or float} of the cells {cell: file_stats} and of the overall figures; no key for a None."""
    out = {}
    for cell, stats in {**per_cell, "all": overall(list(per_cell.values()))}.items():
        out.update({f"{prefix}.{cell}.{name}": v if isinstance(v, int) else float(v) for name, v in stats.items() if v is not None})
    return out


def differences(own, theirs):
    """['DIFF <key>: own <v>, toolkit <v>'] for every key that only one side has or whose values differ beyond the tolerance."""
    out = []
    for key in sorted(set(own) | set(theirs)):
        a, b = own.get(key), theirs.get(key)
        if a is not None and b is not None:
            same = float(b) == a if isinstance(a, int) else math.isclose(a, float(b), rel_tol=1e-9, abs_tol=TOLERANCE.get(key.rsplit(".", 1)[1], 1e-6))
        if a is None or b is None or not same:
            out.append(f"DIFF {key}: own {a}, toolkit {b}")
    return out


def selftest(report=True):
    T0, THETA0 = 120_000_000_000_000, -19_958_353_450_209

    def probe(offset_at, best=(0, 50, 100, 150, 200), n=250):
        """n exchanges 100 ms apart. Clock B reads t + THETA0 + offset_at(t - T0) at the instant t of clock A. The exchanges
        in `best` take no time at all (delta 0: they are the anchors, and their theta is the true offset); the others take
        40 us each way and 40 us at the far end."""
        rows = []
        for i in range(n):
            t1, way = T0 + i * 100_000_000, 0 if i in best else 40_000
            rows.append((t1, t1 + way + THETA0 + offset_at(i * 100_000_000 + way), t1 + 2 * way + THETA0 + offset_at(i * 100_000_000 + 2 * way), t1 + 3 * way))
        return rows

    def exact(stats):
        return {k: v if v is None or isinstance(v, int) else float(v) for k, v in stats.items()}

    def drift(ppm):
        return lambda x: x * ppm // 1_000_000

    def change(before, after, at):      # the rate changes from `before` to `after` ppm at the instant `at` (ns after T0)
        return lambda x: x * before // 1_000_000 if x <= at else at * before // 1_000_000 + (x - at) * after // 1_000_000

    # KNOWN ANSWERS of Addendum C, 7. Anchors at 0, 5, 10, 15 and 20 s: four segments of 5 s.
    constant = file_stats(probe(lambda x: 0))
    assert exact(constant) == {"segments": 4, "rate_ppm_min": 0.0, "rate_ppm_max": 0.0, "rate_ppm_median": 0.0, "rate_step_ppm_max": 0.0,
                               "offset_range_ms": 0.0, "span_s": 20.0}
    steady = file_stats(probe(drift(25)))
    assert exact(steady) == {"segments": 4, "rate_ppm_min": 25.0, "rate_ppm_max": 25.0, "rate_ppm_median": 25.0, "rate_step_ppm_max": 0.0,
                             "offset_range_ms": 0.5, "span_s": 20.0}                # 25 ppm of 20 s = 0.5 ms
    # -25 ppm until the anchor at 10 s, +500 ppm from there: rates -25, -25, 500, 500; the offsets of the anchors are
    # 0, -125, -250, +2,250, +4,750 us from the first, so the range is 4,750 + 250 = 5,000 us
    adjusted = file_stats(probe(change(-25, 500, 10_000_000_000)))
    assert exact(adjusted) == {"segments": 4, "rate_ppm_min": -25.0, "rate_ppm_max": 500.0, "rate_ppm_median": 237.5, "rate_step_ppm_max": 525.0,
                               "offset_range_ms": 5.0, "span_s": 20.0}
    # anchors closer than 2 s form no segment: anchors at 0, 9.9, 10.0, 15 and 20 s give three segments; the rate changes
    # from 25 to 100 ppm between the two close anchors, and the step is taken between the segments on either side of them
    gap = file_stats(probe(change(25, 100, 9_950_000_000), best=(0, 99, 100, 150, 200)))
    assert exact(gap) == {"segments": 3, "rate_ppm_min": 25.0, "rate_ppm_max": 100.0, "rate_ppm_median": 100.0, "rate_step_ppm_max": 75.0,
                          "offset_range_ms": 1.25375, "span_s": 20.0}               # 248.75 us at 9.95 s, then 100 ppm of 10.05 s
    assert file_stats(probe(drift(25), best=(0, 80, 100, 150, 200)))["segments"] == 4      # exactly 2.0 s apart is a segment
    assert file_stats(probe(drift(25), best=(0, 81, 100, 150, 200)))["segments"] == 3      # 1.9 s is none
    # windows and ties: of two exchanges without delay in one window the earlier one is the anchor; the order of the rows is free
    assert [a[3] for a in anchors_of(probe(drift(25), best=(0, 20, 50, 100, 150, 200)))] == [0, 50, 100, 150, 200]
    assert exact(file_stats(list(reversed(probe(drift(25)))))) == exact(steady)
    # few anchors: one segment has no step; a file of one window has no segment and no rate
    assert exact(file_stats(probe(drift(25), n=100))) == {"segments": 1, "rate_ppm_min": 25.0, "rate_ppm_max": 25.0, "rate_ppm_median": 25.0,
                                                          "rate_step_ppm_max": 0.0, "offset_range_ms": 0.125, "span_s": 5.0}
    lone = file_stats(probe(drift(25), n=40))
    assert lone["segments"] == 0 and lone["rate_ppm_median"] is None and lone["rate_step_ppm_max"] == 0 and lone["span_s"] == 0
    # overall: a step of exactly 5 ppm is steady, 6 ppm is not
    five, six = file_stats(probe(change(25, 30, 10_000_000_000))), file_stats(probe(change(25, 31, 10_000_000_000)))
    assert five["rate_step_ppm_max"] == 5 and six["rate_step_ppm_max"] == 6
    cells = {"s1.a": constant, "s1.b": steady, "s1.c": adjusted, "s1.d": gap, "s1.e": five, "s1.f": six}
    assert exact(overall(list(cells.values()))) == {
        "files": 6, "rate_ppm_min": -25.0, "rate_ppm_max": 500.0, "rate_abs_max_ppm": 500.0, "rate_abs_max_pct": 0.05, "rate_step_ppm_max": 525.0,
        "offset_range_ms_max": 5.0, "files_steady": 3, "files_adjusted": 3, "rate_ppm_steady_min": 0.0, "rate_ppm_steady_max": 27.5}
    assert exact(overall([adjusted]))["rate_ppm_steady_min"] is None and overall([lone])["rate_ppm_min"] is None
    # the file format: comment lines before and behind the rows, the column line
    text = "# tool=bench_clock_probe\nseq,t1_ns,t2_ns,t3_ns,t4_ns\n0,10,5,6,20\n2,30,25,27,41\n# exchanges_sent=3\n# exchanges_completed=2\n"
    assert parse(text) == [(10, 5, 6, 20), (30, 25, 27, 41)]
    # the comparison, with its negative controls: a changed value, a key that only one side has
    own = keys("clock.x", cells)
    assert own["clock.x.s1.c.rate_ppm_max"] == 500.0 and own["clock.x.all.files_adjusted"] == 3 and len(own) == 6 * 7 + 11
    same = {k: repr(v) for k, v in own.items()}
    assert differences(own, same) == [] and differences(own, {**same, "clock.x.s1.c.rate_ppm_max": "500.0000001"}) == []     # within 1e-6 ppm
    assert differences(own, {**same, "clock.x.s1.c.rate_ppm_max": "501"}) == ["DIFF clock.x.s1.c.rate_ppm_max: own 500.0, toolkit 501"]
    assert differences(own, {**same, "clock.x.s1.c.rate_ppm_max": "500.00001"}) != [] and differences(own, {**same, "clock.x.all.files": "7"}) != []
    assert len(differences(own, {k: v for k, v in same.items() if k != "clock.x.all.span_s" and k != "clock.x.s1.a.span_s"})) == 1
    assert differences(own, {**same, "clock.x.s1.z.segments": "4"}) == ["DIFF clock.x.s1.z.segments: own None, toolkit 4"]
    assert differences(own, {**same, "clock.x.s1.a.offset_range_ms": "0.0000002"}) != [] and differences(own, {**same, "clock.x.s1.a.span_s": "20.0000001"}) != []
    # the mode for one file: one line, plain decimals, status 0 only with at least two segments
    assert one_line(probe(change(-25, 500, 10_000_000_000))) == (
        "exchanges=250 anchors=5 segments=4 rate_ppm_min=-25.000000 rate_ppm_max=500.000000 rate_ppm_median=237.500000 "
        "rate_step_ppm_max=525.000000 offset_range_ms=5.000000 span_s=20.000000 impossible_rows=0", 0)
    assert one_line(probe(drift(25), n=150))[1] == 0 and "segments=2 " in one_line(probe(drift(25), n=150))[0]
    assert one_line(probe(drift(25), n=100)) == ("exchanges=100 anchors=2 segments=1 rate_ppm_min=25.000000 rate_ppm_max=25.000000 rate_ppm_median=25.000000 "
                                                 "rate_step_ppm_max=0.000000 offset_range_ms=0.125000 span_s=5.000000 impossible_rows=0", 1)
    assert one_line(probe(drift(25), n=40)) == ("exchanges=40 anchors=1 segments=0 rate_step_ppm_max=0.000000 offset_range_ms=0.000000 span_s=0.000000 "
                                                "impossible_rows=0", 1)
    assert one_line([]) == ("exchanges=0 anchors=0 segments=0", 1) and one_line([(10, 5, 4, 9)])[0].endswith("impossible_rows=1")
    if report:
        print("self-test ok")


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    if len(argv) == 3 and argv[1] == "--file":
        selftest(report=False)          # a reader that fails its own test gives no verdict: it stops with a traceback and status 1
        line, status = one_line(parse(Path(argv[2]).read_text()))
        print(line)
        return status
    if len(argv) not in (3, 5):
        sys.stderr.write(__doc__)
        return 2
    selftest()
    per_cell, wrong = {}, []
    print("cell | exchanges | anchors | segments | rate ppm min / max / median | largest step ppm | offset range ms | span s | by 5 ppm")
    for line in Path(argv[1]).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cell, run, inside, sha = line.split("\t")
        data = (Path(argv[2]) / run / inside).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha.strip():
            wrong.append(f"{cell}: {run}/{inside}")
            continue
        rows = parse(data.decode("ascii"))
        s = per_cell[cell] = file_stats(rows)
        odd = impossible(rows)
        rate = " / ".join("none" if s[k] is None else f"{float(s[k]):.3f}" for k in ("rate_ppm_min", "rate_ppm_max", "rate_ppm_median"))
        print(f"{cell} | {len(rows)} | {len(anchors_of(rows))} | {s['segments']} | {rate} | {float(s['rate_step_ppm_max']):.3f} | "
              f"{float(s['offset_range_ms']):.4f} | {float(s['span_s']):.3f} | {'steady' if s['rate_step_ppm_max'] <= STEADY_PPM else 'adjusted'}"
              + (f" | {odd} impossible row(s)" if odd else ""))
    if wrong:
        print("SHA-256 is not the one of the inputs file: " + "; ".join(wrong))
        return 1
    print("overall: " + ", ".join(f"{k} {v if isinstance(v, int) else 'none' if v is None else format(float(v), '.6g')}" for k, v in overall(list(per_cell.values())).items()))
    if len(argv) == 3:
        return 0
    prefix, theirs = argv[4], {}
    record_compared(argv[3], [])    # a direct call starts the file
    with open(Path(argv[3]) / "numbers.csv", newline="") as f:
        theirs = {r["key"]: r["value"] for r in csv.DictReader(f) if r["key"].startswith(prefix + ".") and r["unit"] != "text"}
    own = keys(prefix, per_cell)
    found = differences(own, theirs)
    record_compared(argv[3], set(own) & set(theirs) if not found and own else [])
    print("\n".join(found + [f"keys compared {len(set(own) | set(theirs))}, differences {len(found)}"]))
    print("OWN-CHECK AGREES" if not found and own else f"OWN-CHECK DISAGREES: {len(found)} difference(s)")
    return 0 if not found and own else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
