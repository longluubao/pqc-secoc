"""Fork-counter witness of a measurement run: lists the 5 s intervals in which more processes were created than a limit
and says whether each lies at a step boundary of the driver or inside a measured step.

usage: python3 witness_report.py <witness file> [limit per interval, default 3]
Lines of the witness file: '<local time> <processes counter of /proc/stat>'.
Step boundaries are read from gates_*.txt next to the witness file (the driver starts processes there: snapshots,
environment capture, the measured process). A flagged interval within 6 s of a boundary, before the first
boundary or after the last one is "at a boundary"; any other flagged interval is "INSIDE A STEP" and is the
signature of foreign activity (a log-in, a started command).
A step whose gates line says load= something other than none or idle (the loaded cells of E0) runs the driver's own
temperature watcher, which starts a few processes every two seconds on the other cores. Inside such a step the limit
is therefore the step's own level: median of its intervals + limit + 2 x their median absolute deviation; the report
prints that level per loaded step.
Exit 0: no interval inside a step above the limit and no sampling gap; 1: otherwise; 2: file unusable.
"""
import glob
import os
import re
import sys
from datetime import datetime, timedelta


def main():
    path, limit = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3
    rows = []
    for line in open(path):
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            rows.append((datetime.fromisoformat(parts[0]), int(parts[1])))
    if len(rows) < 2:
        print("witness file has fewer than two samples"); return 2
    slack = timedelta(seconds=6)    # the driver's bursts lie within a few seconds of the time it writes into the gates file
    steps = []                  # (start, end) of every step that has both gates lines
    bounds, loaded = [], []     # loaded: (start, end, step name) of steps that run the driver's own watcher
    for g in glob.glob(os.path.join(os.path.dirname(os.path.abspath(path)), "gates_*.txt")):
        text = open(g).read()
        for m in re.finditer(r"time=(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", text):
            bounds.append(datetime.fromisoformat(m[1]))
        start = {}
        for m in re.finditer(r"step=(\S+) phase=(start|end) load=(\S+) time=(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", text):
            if m[2] == "start":
                start[m[1]] = datetime.fromisoformat(m[4])
            elif m[1] in start:
                t0 = start.pop(m[1])
                steps.append((t0, datetime.fromisoformat(m[4])))
                if m[3] not in ("none", "idle"):
                    loaded.append((t0, datetime.fromisoformat(m[4]), m[1]))
    bounds.sort()

    def at_boundary(a, b):
        if not bounds:
            return None
        if b <= bounds[0] + slack or a >= bounds[-1] - slack:
            return True
        if any(a - slack <= t <= b + slack for t in bounds):
            return True
        if steps and not any(t0 <= a and b <= t1 for t0, t1 in steps):
            return "between"    # after a step's end and before the next start: the driver's cooling wait, nothing is measured
        return False

    total = rows[-1][1] - rows[0][1]
    secs = (rows[-1][0] - rows[0][0]).total_seconds()
    level = {}                  # interval start -> limit that applies there (loaded steps only)
    notes = []
    for t0, t1, name in loaded:
        inside_step = [(a[0], b[1] - a[1]) for a, b in zip(rows, rows[1:]) if a[0] >= t0 + slack and b[0] <= t1 - slack]
        if len(inside_step) >= 5:
            vals = sorted(v for _, v in inside_step)
            med = vals[len(vals) // 2]
            mad = sorted(abs(v - med) for v in vals)[len(vals) // 2]
            lim = med + limit + 2 * mad
            for t, _ in inside_step:
                level[t] = lim
            notes.append(f"  loaded step {name}: the driver's own watcher creates a median of {med} processes per interval "
                         f"(deviation {mad}); limit inside this step: {lim}")
    flagged = [(a[0], b[0], b[1] - a[1]) for a, b in zip(rows, rows[1:]) if b[1] - a[1] > level.get(a[0], limit)]
    gaps = [(a[0], b[0]) for a, b in zip(rows, rows[1:]) if (b[0] - a[0]).total_seconds() > 12]
    inside = [f for f in flagged if at_boundary(f[0], f[1]) is False]
    unknown = [f for f in flagged if at_boundary(f[0], f[1]) is None]
    quiet = [b[1] - a[1] for a, b in zip(rows, rows[1:]) if b[1] - a[1] <= level.get(a[0], limit)]
    between = [f for f in flagged if at_boundary(f[0], f[1]) == "between"]
    print(f"{len(rows)} samples from {rows[0][0].time()} to {rows[-1][0].time()}: {total} processes created in {secs:.0f} s; "
          f"intervals above {limit}: {len(flagged)} ({len(flagged) - len(inside) - len(unknown) - len(between)} at step boundaries, "
          + (f"{len(between)} between steps, " if between else "") + f"{len(inside)} INSIDE A STEP, "
          f"{len(unknown)} unclassified: no gates file); sampling gaps over 12 s: {len(gaps)}; "
          f"in the other {len(quiet)} intervals: {sum(quiet)} processes in all, at most {max(quiet) if quiet else 0} per interval")
    for n in notes:
        print(n)
    for a, b, d in flagged:
        where = {True: "at a step boundary", False: "INSIDE A STEP", None: "unclassified",
                 "between": "between two steps: the driver waits for the board to cool, nothing is measured"}[at_boundary(a, b)]
        print(f"  {a.time()} to {b.time()}: {d} processes created ({where})")
    for a, b in gaps:
        print(f"  no sample between {a.time()} and {b.time()}")
    return 1 if inside or unknown or gaps else 0


if __name__ == "__main__":
    sys.exit(main())
