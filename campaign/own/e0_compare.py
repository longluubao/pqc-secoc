"""Independent second reading of an E0 run directory (cyclictest histograms), compared with the toolkit's numbers.csv.

usage: python3 e0_compare.py <run_dir> <analysis_dir> <key_prefix>
Reads cyclictest/cyclictest_<policy>_cpu<N>_<load>.txt itself: the 1 us histogram rows '<latency_us> <count>' and
cyclictest's '# Total / Min Latencies / Avg Latencies / Max Latencies / Histogram Overflows' lines.
Own numbers: samples = Total + Overflows; min and max from cyclictest's lines, cross-checked with the first and
last filled bucket; mean of the histogram (only without overflows); p99, p99.9, p99.99 = smallest latency L with
at least that share of all samples at or below L; counts of wake-ups later than 100 us and 1,000 us.
Compared with every toolkit key <prefix>.cyclictest.<...>.<policy>-<load>.<stat> that exists.
Exit 0 only if at least one key per file was compared and none disagrees.
"""
import csv
import glob
import math
import os
import re
import sys
from pathlib import Path


def read(path):
    meta, counts, summ = {}, [], {}
    for line in open(path, errors="replace"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = re.fullmatch(r"# (Total|Min Latencies|Avg Latencies|Max Latencies|Histogram Overflows): (\d+)", line)
            if m:
                summ[m[1]] = int(m[2])
            elif "=" in line:
                k, v = line[1:].strip().split("=", 1)
                meta[k.strip()] = v.strip()
            continue
        m = re.fullmatch(r"(\d+) (\d+)", line)
        if not m or int(m[1]) != len(counts):
            raise SystemExit(f"{path}: unexpected line {line!r}")
        counts.append(int(m[2]))
    return meta, counts, summ


def record_compared(analysis_dir, keys):
    """Addendum F4: <analysis_dir>/own_compared_keys.txt, the keys that this call compared with a toolkit value and found
    equal, one per line, sorted. Under e9_compare.py (OWN_COMPARED_KEYS=add) the readers of one call add to one file;
    a direct call writes its own set. A call that does not end in agreement leaves no key of its own."""
    path = Path(analysis_dir) / "own_compared_keys.txt"
    if path.parent.is_dir():
        old = path.read_text().split() if os.environ.get("OWN_COMPARED_KEYS") == "add" and path.exists() else []
        path.write_text("".join(k + "\n" for k in sorted({*old, *keys})))


def main():
    run, ana, prefix = sys.argv[1:4]
    record_compared(ana, [])    # a direct call starts the file
    agreed, tk = [], {}
    with open(os.path.join(ana, "numbers.csv"), newline="") as fh:
        for r in csv.DictReader(fh):
            tk[r["key"]] = r["value"]
    files = sorted(glob.glob(os.path.join(run, "cyclictest", "cyclictest_*.txt")))
    if not files:
        print("no cyclictest files"); return 2
    total_compared, bad, empty = 0, [], []
    for f in files:
        meta, counts, summ = read(f)
        policy, load = meta.get("policy"), meta.get("load")
        need = ("Total", "Min Latencies", "Avg Latencies", "Max Latencies", "Histogram Overflows")
        if any(k not in summ for k in need):
            print(f"{os.path.basename(f)}: INCOMPLETE (summary lines missing): {sorted(summ)}"); bad.append(f); continue
        over, n = summ["Histogram Overflows"], summ["Total"] + summ["Histogram Overflows"]
        if sum(counts) != summ["Total"]:
            bad.append(f"{f}: histogram sum {sum(counts)} != Total {summ['Total']}")
        filled = [i for i, c in enumerate(counts) if c]
        if filled and (filled[0] != summ["Min Latencies"] or (over == 0 and filled[-1] != summ["Max Latencies"])):
            bad.append(f"{f}: min/max lines disagree with the histogram")
        own = {"samples": n, "overflows": over, "min_us": summ["Min Latencies"], "avg_us": summ["Avg Latencies"],
               "max_us": summ["Max Latencies"]}
        if n and not over:
            own["mean_us"] = sum(i * c for i, c in enumerate(counts)) / n
        cum, acc = [], 0
        for c in counts:
            acc += c; cum.append(acc)
        for name, p in (("p99_us", .99), ("p99_9_us", .999), ("p99_99_us", .9999)):
            want = math.ceil(p * n - 1e-9)
            own[name] = next((i for i, a in enumerate(cum) if a >= want), None)
        late100 = sum(counts[101:]) + over
        late1000 = sum(counts[1001:]) + over
        own["late_over_100us.k"] = late100      # strictly later than 100 us; overflows counted
        own["late_over_1ms.k"] = late1000
        pat = re.compile(re.escape(prefix) + r"\.cyclictest\..*" + re.escape(f"{policy}-{load}") + r"\.([a-z0-9_.]+)$")
        compared = 0
        for key, val in tk.items():
            m = pat.match(key)
            if not m or m[1] not in own or own[m[1]] is None:
                continue
            compared += 1
            if not math.isclose(float(own[m[1]]), float(val), rel_tol=1e-9, abs_tol=1e-12):
                bad.append(f"{key}: own {own[m[1]]!r} toolkit {val!r}")
            else:
                agreed.append(key)
        total_compared += compared
        if not compared:
            empty.append(os.path.basename(f))
        print(f"{policy:5s} {load:12s} n={n:7d} min={own['min_us']:4d} avg={own['avg_us']:4d} p99={own['p99_us']} p99.9={own['p99_9_us']} "
              f"p99.99={own['p99_99_us']} max={own['max_us']:6d} us  overflows(>= {len(counts)} us)={over}  later than 100 us: {late100}  "
              f"later than 1 ms: {late1000}  throttled {meta.get('throttled_start')} -> {meta.get('throttled_end')}  "
              f"temp {meta.get('temp_start')} -> {meta.get('temp_end')}  class {meta.get('threads_observed_class_rtprio_cpu')}  keys compared: {compared}")
    for b in bad:
        print("DISAGREE:", b)
    for e in empty:
        print("NO TOOLKIT KEY MATCHED:", e)
    ok = total_compared and not bad and not empty
    print(f"compared {total_compared} keys with the toolkit, {len(bad)} disagreements")
    record_compared(ana, agreed if ok else [])
    print("OWN-CHECK AGREES" if ok else "OWN-CHECK FAILS")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
