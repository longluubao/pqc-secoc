r"""What the clock probe files say about the two boards' clocks themselves (E9_SPEC.md, Addendum C; keys clock.*).

    python3 -I <toolkit>/analysis/clock_rate.py <inputs.tsv> --runs-root <dir> --out <out_dir> --key-prefix clock.e9p1

<inputs.tsv>: comment lines (#), then one line per probe file with four fields separated by tabs: the cell (the part
of the key: s1.a), the run directory under --runs-root, the file inside it, the file's sha256. A file whose sha256 is
not the listed one is refused; after any refusal nothing is written. The output directory gets numbers.tex,
numbers.csv, number_keys.md and suppressed_keys.txt, which analysis.merge_numbers takes like any other.

No PDU and no latency enters, and nothing here says whether a run is a result for E9. Per file:

    anchors          those of the latency keys (e2e.anchors): windows of 5 s from the first exchange, in each the
                     exchange with the smallest delay, the earlier one on a tie. All anchors are used, the first and
                     the last included
    segment          two neighbouring anchors whose tau differ by at least 2.0 s (exactly 2.0 s is a segment); its
                     rate is (theta_2 - theta_1) / (tau_2 - tau_1) in ppm, positive when board B's clock runs faster
                     than board A's
    rate_ppm_min, rate_ppm_max, rate_ppm_median   over the file's segments (an even number: the mean of the two middle)
    rate_step_ppm_max   the largest absolute difference between the rates of two segments that follow each other in
                     the file's list of segments, also across a pair of anchors too close to form one; 0 with fewer
                     than two segments
    offset_range_ms  the largest minus the smallest theta over the anchors
    span_s           tau of the last anchor minus tau of the first

Over the files: files; the smallest and the largest segment rate of any file; rate_abs_max_ppm, the larger of their
absolute values, and the same as a percentage; the largest rate step and offset range; files_steady, the files whose
rate_step_ppm_max is at most STEADY_PPM, and files_adjusted, the others; the smallest and the largest median rate
among the steady files.

A file without a segment has no rate key and enters no rate over the files; its rate step is 0, so it counts as steady
(E9_SPEC.md, Addendum C, "Readings fixed on 2026-11-25", (a) to (d)). A row that contradicts itself (t4 before t1, t3
before t2, a negative delay) stops the command: such an exchange was not measured.
Each anchor's theta is known to within its delta / 2, so a rate over 5 s is known to within about 20 ppm (a text
statement of the addendum, not a key). The footer of a probe file is not judged here: the sha256 says which file it is.
"""
import argparse
import hashlib
import sys
from pathlib import Path

if __package__ in (None, ""):  # run by path under python3 -I, which keeps the script directory off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis import csvio, e2e, make_numbers, toolkit_commit  # noqa: E402

import numpy as np  # noqa: E402  (after analysis: under python3 -I the package adds the user site that holds numpy)

MIN_SEGMENT_NS = 2_000_000_000  # anchors closer than this form no segment
STEADY_PPM = 5                  # a file is steady when its largest rate step is at most this
ALL = "all"                     # the key part of the figures over all files
PCT = "rate_abs_max_pct"        # the one key whose value is a percentage, not a proportion: unit '%', not 'percent'

SEGMENT = ("over a segment, two neighbouring anchors of the clock probe (in every 5 s the exchange with the smallest "
           "delay) whose tau differ by at least 2 s, the rate between the two boards' CLOCK_MONOTONIC is (theta_2 - "
           "theta_1) / (tau_2 - tau_1), positive when board B's clock runs faster than board A's")
LIMITS = ("; a statement about the clocks during these runs only: it says not which of the two clocks was adjusted, and "
          "nothing about a latency or about a duration measured in another experiment")
STEP = ("largest absolute difference between the rates of two segments that follow each other (the size of an abrupt "
        "change of rate)")


def file_stats(cols):
    """The statistics of one probe file (the columns of its clock_probe.csv), and rate_ppm, the rate of every segment
    in the order of time. With fewer than two segments the rate step is 0; without a segment the three rates are None."""
    _, tau2, theta2, _, anchor = e2e.anchors(cols)
    tau2, theta2 = tau2[anchor], theta2[anchor]        # twice tau and twice theta, whole ns: their ratio is the rate
    gap2 = np.diff(tau2)
    rate = np.diff(theta2)[gap2 >= 2 * MIN_SEGMENT_NS] / gap2[gap2 >= 2 * MIN_SEGMENT_NS] * 1e6
    low, high, median = (float(f(rate)) for f in (np.min, np.max, np.median)) if rate.size else (None, None, None)
    return {"anchors": int(anchor.size), "segments": int(rate.size), "rate_ppm": rate,
            "rate_ppm_min": low, "rate_ppm_max": high, "rate_ppm_median": median,
            "rate_step_ppm_max": float(np.abs(np.diff(rate)).max()) if rate.size > 1 else 0.0,
            "offset_range_ms": int(theta2.max() - theta2.min()) / 2e6, "span_s": int(tau2[-1] - tau2[0]) / 2e9}


def overall(files):
    """The figures over all files, from the file_stats() of each. rate_abs_max_pct is the percentage itself (ppm /
    10,000), not a proportion. A file without a segment enters no rate; a rate that no file gives is None."""
    with_rate = [f for f in files if f["segments"]]
    low = min((f["rate_ppm_min"] for f in with_rate), default=None)
    high = max((f["rate_ppm_max"] for f in with_rate), default=None)
    largest = None if low is None else max(abs(low), abs(high))
    steady = [f for f in files if f["rate_step_ppm_max"] <= STEADY_PPM]
    medians = [f["rate_ppm_median"] for f in steady if f["segments"]]
    return {"files": len(files), "segments": sum(f["segments"] for f in files), "rate_ppm_min": low, "rate_ppm_max": high,
            "rate_abs_max_ppm": largest, "rate_abs_max_pct": None if largest is None else largest / 1e4,
            "rate_step_ppm_max": max(f["rate_step_ppm_max"] for f in files),
            "offset_range_ms_max": max(f["offset_range_ms"] for f in files),
            "files_steady": len(steady), "files_adjusted": len(files) - len(steady),
            "rate_ppm_steady_min": min(medians, default=None), "rate_ppm_steady_max": max(medians, default=None)}


def read_inputs(path):
    """The lines of the list of inputs as (cell, run directory, file, sha256). A line without its four fields, a cell
    that is no key part, the cell 'all' (the key part of the figures over all files) and a cell named twice are errors."""
    out = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = [f.strip() for f in line.split("\t")]
        if len(fields) != 4 or not all(fields):
            raise ValueError(f"{path}:{n}: a line needs four fields separated by tabs (cell, run directory, file, sha256)")
        cell = fields[0]
        if cell == ALL or not all(make_numbers.SEGMENT.fullmatch(part) for part in cell.split(".")):
            raise ValueError(f"{path}:{n}: the cell {cell!r} cannot be a key part ('{ALL}' is taken by the figures over "
                             "all files; the parts between dots are made of A-Z a-z 0-9 _ -)")
        if cell in [c for c, *_ in out]:
            raise ValueError(f"{path}:{n}: the cell {cell!r} is listed more than once")
        out.append(tuple(fields))
    if not out:
        raise ValueError(f"{path}: no probe file is listed")
    return out


def collect(inputs, runs_root, prefix, listed):
    """The number items of the files in `inputs` (read_inputs; `listed`: the name of that list): a file is read only
    when its sha256 is the listed one."""
    items, stats = [], []

    def add(base, source, filt, name, value, unit, n, how, signed=False, decimals=None):
        if value is not None:
            key = f"{prefix}.{base}.{name}"
            items.append({"key": key, "value": value, "unit": unit, "n": n, "source_file": source, "experiment": "clock_rate",
                          "filter": filt, "how": how + LIMITS, "signed": signed, "group": key, "raw": make_numbers.raw(value),
                          "suppressed": None, "decimals": decimals})

    for cell, run, file, sha in inputs:
        p = Path(runs_root) / run / file
        found = hashlib.sha256(p.read_bytes()).hexdigest()
        if found != sha.lower():
            raise ValueError(f"{p}: sha256 {found} is not the listed {sha}: not the file the list names")
        try:
            s = file_stats(csvio.read_csv(p, "clock_probe")[1])
        except ValueError as e:
            raise ValueError(f"{p}: {e}") from e
        stats.append(s)
        source, filt, n = f"{run}/{file}", f"cell={cell}, sha256={sha.lower()}", s["segments"]
        add(cell, source, filt, "segments", n, "count", s["anchors"], "segments of the file: " + SEGMENT)
        for name, what in (("min", "smallest"), ("max", "largest"), ("median", "median")):
            add(cell, source, filt, f"rate_ppm_{name}", s[f"rate_ppm_{name}"], "ppm", n,
                f"{what} rate of the file's segments: " + SEGMENT, signed=True, decimals=0)
        add(cell, source, filt, "rate_step_ppm_max", s["rate_step_ppm_max"], "ppm", n, STEP + " in the file: " + SEGMENT, decimals=0)
        add(cell, source, filt, "offset_range_ms", s["offset_range_ms"], "ms", s["anchors"], "largest minus smallest offset "
            "theta (board B's clock minus board A's) over the anchors of the file's clock probe", decimals=1)
        add(cell, source, filt, "span_s", s["span_s"], "s", s["anchors"], "time from the first to the last anchor of the "
            "file's clock probe (tau of the last one minus tau of the first)", decimals=0)

    o, source, files = overall(stats), listed, len(stats)
    filt, n = f"all {files} listed probe files", o["segments"]
    add(ALL, source, filt, "files", files, "count", files, "probe files (clock_probe.csv, one per run) the figures are taken over")
    for name, what in (("min", "smallest"), ("max", "largest")):
        add(ALL, source, filt, f"rate_ppm_{name}", o[f"rate_ppm_{name}"], "ppm", n, f"{what} segment rate of any file: " + SEGMENT,
            signed=True, decimals=0)
    add(ALL, source, filt, "rate_abs_max_ppm", o["rate_abs_max_ppm"], "ppm", n, "largest absolute segment rate of any file "
        "(the larger of |rate_ppm_min| and |rate_ppm_max|): " + SEGMENT, decimals=0)
    if o["rate_abs_max_pct"] is not None:  # formatted by the percent rule, which takes a proportion; see below
        add(ALL, source, filt, PCT, o["rate_abs_max_pct"] / 100, "percent", n, "rate_abs_max_ppm as a percentage (the value is the "
            "percentage itself, not a proportion): " + SEGMENT)
    add(ALL, source, filt, "rate_step_ppm_max", o["rate_step_ppm_max"], "ppm", n, STEP + " in any file: " + SEGMENT, decimals=0)
    add(ALL, source, filt, "offset_range_ms_max", o["offset_range_ms_max"], "ms", files, "largest offset range of a file: "
        "largest minus smallest offset theta (board B's clock minus board A's) over the anchors of its clock probe", decimals=1)
    steady = f"a file is steady when its {STEP} is at most {STEADY_PPM} ppm"
    add(ALL, source, filt, "files_steady", o["files_steady"], "count", files, "steady files: " + steady)
    add(ALL, source, filt, "files_adjusted", o["files_adjusted"], "count", files, "files that are not steady: " + steady)
    for name, what in (("min", "smallest"), ("max", "largest")):
        add(ALL, source, filt, f"rate_ppm_steady_{name}", o[f"rate_ppm_steady_{name}"], "ppm", o["files_steady"],
            f"{what} median segment rate among the steady files ({steady}): " + SEGMENT, signed=True, decimals=0)
    make_numbers.format_items(items)
    for item in items:  # Addendum C: this key's value is "the same as a percentage"; its printed form stays what it was
        if item["key"] == f"{prefix}.{ALL}.{PCT}":
            item.update(value=o["rate_abs_max_pct"], raw=make_numbers.raw(o["rate_abs_max_pct"]), unit="%")
    return items


def main(argv=None):
    ap = argparse.ArgumentParser(description="Clock-rate keys from clock probe files (E9_SPEC.md, Addendum C).")
    ap.add_argument("inputs", type=Path, help="list of the probe files: cell, run directory, file inside it, sha256 (tabs)")
    ap.add_argument("--runs-root", type=Path, required=True, help="directory that holds the run directories of the list")
    ap.add_argument("--out", type=Path, required=True, help="output directory")
    ap.add_argument("--key-prefix", required=True, help="put in front of every key: clock.e9p1")
    a = ap.parse_args(argv)
    try:
        prefix = make_numbers.check_prefix(a.key_prefix)
        inputs = read_inputs(a.inputs)
        items = collect(inputs, a.runs_root, prefix, a.inputs.name)
    except (OSError, ValueError) as e:
        sys.exit(f"error: {e}")
    a.out.mkdir(parents=True, exist_ok=True)
    make_numbers.write(a.out / "numbers.tex", items, {
        "run_dir": f"clock rates of the {len(inputs)} probe files listed in {a.inputs.name}", "seed": None,
        "toolkit_commit": toolkit_commit(), "key_prefix": prefix, "not_a_result": None, "markers": [],
        "title": f"the clock rates of the probe files listed in {a.inputs.name}"})
    print(f"{len(inputs)} probe files -> {a.out}: {len(items)} keys in numbers.tex")


if __name__ == "__main__":
    main()
