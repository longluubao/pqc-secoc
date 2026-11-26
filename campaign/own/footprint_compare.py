"""Independent second reading of the footprint files of a run directory (E8, E8v), compared key by key with the toolkit.

usage: python3 -I -B footprint_compare.py <run_dir> <analysis_dir> <key_prefix>     (python3 -I -B footprint_compare.py --self-test)
Reads the raw files at the top of <run_dir> itself, standard library only:
  perf_<op>_<calls>.csv   `perf stat -x,` of one run of the benchmark tool with <calls> calls: count, unit, event, time the
                          counter ran, share of the run in which it ran, ...      -> the counts of instructions:u and cycles:u
  rss_samples.txt         one line per sample: time, host, then 'Name: value kB' fields of /proc/<pid>/status
  size_<label>.txt        per build ('== <build>/' line; a file without such a line holds one build and its keys have no
                          build part): unstripped_bytes=, stripped_bytes=, then the table of `size -A` (section, size, addr)
Own rules, written from the definitions of number_keys.md and from CAMPAIGN.md (E8, E8v), E9_SPEC.md (Rulings of
2026-11-24, item 2 'Instructions per verification') and RESULTS.md (E8), not from the toolkit's code:
  per call    only the operations mldsa_sign and mldsa_verify_only, from exactly two runs of different length:
              (count of the longer run - count of the shorter) / (calls of the longer - calls of the shorter), the calls
              being those of the file names, so that the start-up of the tool cancels; instructions per cycle is the
              ratio of the two differences, NOT perf's own 'insn per cycle' column (that one includes the start-up).
              Another operation gets no key: a verify run of bench_crypto_ops also signs in every iteration. Its own
              difference is printed for the record.
  count       a count is taken only when perf counted during 100 % of the run (otherwise perf prints an estimate).
  VmHWM       the largest VmHWM value among the lines of a host, and the number of those lines.
  sections    .text, .rodata, .data, .bss by their exact name (.data.rel.ro is not .data).
Compared: EVERY key <key_prefix>.footprint.* of numbers.csv must be reproduced, and every own key must be there; counts
exactly, the per-call figures and the ratio to nine significant digits.
A directory with the marker FUNCTIONAL (E8, part 2: the gateway run whose processes were sampled) also holds the files
of a functional run: functional_compare.py is run on it first, as before, and both must agree (one reader per row of
accepted_runs.tsv). Exit 0 only then; the last line is the verdict.
"""
import csv
import math
import os
import re
import subprocess
import sys
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
PER_CALL = ("mldsa_sign", "mldsa_verify_only")
EVENTS = {"instructions": "instructions:u", "cycles": "cycles:u"}
SECTIONS = {".text": "text_bytes", ".rodata": "rodata_bytes", ".data": "data_bytes", ".bss": "bss_bytes"}
FILE_SIZES = ("unstripped_bytes", "stripped_bytes")


def perf_name(name):
    """(operation, calls) of a file name perf_<op>_<calls>.csv: the calls are the last number, the operation may hold '_'."""
    m = re.fullmatch(r"perf_(.+)_(\d+)\.csv", name)
    return (m[1], int(m[2])) if m else None


def perf_counts(text):
    """{'instructions': count, 'cycles': count} of one `perf stat -x,` file, by the name of the event."""
    found = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cells = line.split(",")
        if len(cells) < 5 or not cells[0].isdigit():
            raise SystemExit(f"perf stat line without a count or without the share of the run: {line!r}")
        if cells[2] in found:
            raise SystemExit(f"perf stat file with the event {cells[2]} twice")
        if float(cells[4]) != 100:
            raise SystemExit(f"perf counted during {cells[4]} % of the run: the value is an estimate, not a count: {line!r}")
        found[cells[2]] = int(cells[0])
    if not set(EVENTS.values()) <= set(found):
        raise SystemExit(f"perf stat file without {' and '.join(EVENTS.values())}: it has {sorted(found)}")
    return {name: found[event] for name, event in EVENTS.items()}


def per_call(runs):
    """{key part: value} of the runs {calls: perf_counts()} of one operation: the whole-run counts and, from exactly two
    runs, the per-call differences."""
    if len(runs) != 2:
        raise SystemExit(f"{len(runs)} run length(s) {sorted(runs)}: the per-call figure is defined for exactly two")
    (n1, short), (n2, long) = sorted(runs.items())
    grown = {name: long[name] - short[name] for name in EVENTS}
    k = {f"n{n}.{name}": c[name] for n, c in runs.items() for name in EVENTS}
    k["instructions_per_call"] = grown["instructions"] / (n2 - n1)
    k["cycles_per_call"] = grown["cycles"] / (n2 - n1)
    k["instructions_per_cycle"] = grown["instructions"] / grown["cycles"]
    return k


def rss(text):
    """{host: [VmHWM in kB of each sample line of the host]}."""
    hosts = {}
    for line in text.splitlines():
        t = line.split()
        if not t:
            continue
        # shortcut: a sample line without VmHWM (the process had gone) stops the reader, no rule says whether it counts; decide when a run has one
        if "VmHWM:" not in t or t[t.index("VmHWM:") + 1:t.index("VmHWM:") + 3][1:] != ["kB"]:
            raise SystemExit(f"rss sample line without 'VmHWM: <n> kB': {line!r}")
        hosts.setdefault(t[1], []).append(int(t[t.index("VmHWM:") + 1]))
    return hosts


def sizes(text):
    """{build (None for a file without '== <build>/' lines): {key part: bytes}}."""
    builds, build = {}, None

    def put(name, value):
        if name in builds.setdefault(build, {}):
            raise SystemExit(f"size file: {name} twice in build {build}")
        builds[build][name] = int(value)

    for line in text.splitlines():
        t = line.split()
        if len(t) == 2 and t[0] == "==":
            build = t[1].rstrip("/")
        elif len(t) == 1 and t[0].partition("=")[0] in FILE_SIZES:
            put(*t[0].split("="))
        elif len(t) == 3 and t[0] in SECTIONS:
            put(SECTIONS[t[0]], t[1])
    return builds


def own_keys(run_dir):
    """({key behind '<prefix>.footprint.': value}, the lines to print) of one run directory."""
    k, lines, ops = {}, [], {}
    for p in sorted(run_dir.glob("perf_*.csv")):
        if not perf_name(p.name):
            raise SystemExit(f"{p.name}: no number of calls in the file name")
        op, calls = perf_name(p.name)
        ops.setdefault(op, {})[calls] = perf_counts(p.read_text())
    for op, runs in ops.items():
        if op not in PER_CALL:
            d = per_call(runs) if len(runs) == 2 else {}
            lines.append(f"perf {op}: runs of {sorted(runs)} calls, NO key by the own rule (not {' or '.join(PER_CALL)}); "
                         f"own difference per iteration: {d.get('instructions_per_call', 'n/a')} instructions, {d.get('cycles_per_call', 'n/a')} cycles")
            continue
        d = per_call(runs)
        k.update({f"perf.{op}.{name}": v for name, v in d.items()})
        lines.append(f"perf {op}: runs of {sorted(runs)} calls; per call {d['instructions_per_call']} instructions, "
                     f"{d['cycles_per_call']} cycles, {d['instructions_per_cycle']} instructions per cycle")
    samples = run_dir / "rss_samples.txt"
    for host, values in (rss(samples.read_text()) if samples.exists() else {}).items():
        k[f"rss.{host}.samples"], k[f"rss.{host}.vmhwm_max_kb"] = len(values), max(values)
        lines.append(f"rss {host}: {len(values)} samples, largest VmHWM {max(values)} kB")
    for p in sorted(run_dir.glob("size_*.txt")):
        label = p.stem[len("size_"):]
        for build, fields in sizes(p.read_text()).items():
            head = f"size.{label}." + ("" if build is None else build + ".")
            k.update({head + name: v for name, v in fields.items()})
            lines.append(f"size {label} {build or '(one build)'}: stripped {fields.get('stripped_bytes', 'n/a')} bytes, .text {fields.get('text_bytes', 'n/a')}")
    return k, lines


def same(a, b):
    """Own value a against the toolkit's text b: a count exactly, another value to nine significant digits. A text that
    is no number is a difference, not a stop."""
    try:
        return Fraction(b) == a if isinstance(a, int) else math.isclose(a, float(b), rel_tol=1e-9, abs_tol=1e-12)
    except (ValueError, ZeroDivisionError):
        return False


def record_compared(analysis_dir, keys, add=False):
    """Addendum F4: <analysis_dir>/own_compared_keys.txt, the keys that this call compared with a toolkit value and found
    equal, one per line, sorted. Under e9_compare.py (OWN_COMPARED_KEYS=add) the readers of one call add to one file;
    a direct call writes its own set. A call that does not end in agreement leaves no key of its own.
    add: beside the keys that functional_compare.py wrote in this call."""
    path = Path(analysis_dir) / "own_compared_keys.txt"
    if path.parent.is_dir():
        old = path.read_text().split() if (add or os.environ.get("OWN_COMPARED_KEYS") == "add") and path.exists() else []
        path.write_text("".join(k + "\n" for k in sorted({*old, *keys})))


def stops(f, *args):
    try:
        f(*args)
    except SystemExit:
        return True
    return False


def self_test():
    assert perf_name("perf_mldsa_verify_only_10000.csv") == ("mldsa_verify_only", 10000)
    assert perf_name("perf_mldsa_verify_1000.csv") == ("mldsa_verify", 1000) and perf_name("perf_mldsa_sign.csv") is None
    text = "# started on Mon Nov 23 17:58:17 2026\n\n1300,,instructions:u,5000,100.00,1.86,insn per cycle\n700,,cycles:u,5000,100.00,,\n"
    assert perf_counts(text) == {"instructions": 1300, "cycles": 700}
    assert perf_counts("700,,cycles:u,5,100.00,,\n9,,branches:u,5,100.00,,\n1300,,instructions:u,5,100.00,,\n") == {"instructions": 1300, "cycles": 700}
    assert stops(perf_counts, "<not counted>,,instructions:u,0,0.00,,\n700,,cycles:u,5,100.00,,\n")
    assert stops(perf_counts, text.replace("100.00,1.86", "50.00,1.86"))            # a scaled estimate is not a count
    assert stops(perf_counts, text + "700,,cycles:u,5000,100.00,,\n") and stops(perf_counts, "1300,,instructions:u\n")    # an event twice; a short line
    assert stops(perf_counts, "1300,,instructions,5,100.00,,\n700,,cycles,5,100.00,,\n")      # not the user-space events
    # known answer: 100 instructions and 40 cycles per call, 300 of each at start-up; 10 and 30 calls
    runs = {30: {"instructions": 3300, "cycles": 1500}, 10: {"instructions": 1300, "cycles": 700}}
    d = per_call(runs)
    assert d["instructions_per_call"] == 100 and d["cycles_per_call"] == 40 and d["instructions_per_cycle"] == 2.5
    assert d["instructions_per_cycle"] != 1300 / 700 and d["instructions_per_cycle"] != 3300 / 1500      # not a whole-run ratio
    assert d["n10.instructions"] == 1300 and d["n30.cycles"] == 1500 and len(d) == 7
    assert stops(per_call, {10: runs[10]}) and stops(per_call, {**runs, 20: runs[10]})
    lines = ("18:04:48 a VmSize: 99999 kB VmHWM: 5 kB VmRSS: 5 kB VmData: 1 kB \n18:04:49 b VmSize: 8316 kB VmHWM: 6024 kB VmRSS: 6000 kB \n"
             "18:05:17 a VmSize: 99999 kB VmHWM: 9 kB VmRSS: 4 kB \n\n18:05:45 a VmSize: 99999 kB VmHWM: 7 kB VmRSS: 7 kB \n")
    assert rss(lines) == {"a": [5, 9, 7], "b": [6024]} and max(rss(lines)["a"]) == 9      # the largest, not the first or the last
    assert stops(rss, "18:04:48 a VmSize: 99999 kB\n") and stops(rss, "18:04:48 a VmHWM: 5 MB x\n") and stops(rss, "18:04:48 a VmHWM: 5\n")
    table = ("unstripped_bytes=900\nstripped_bytes=800\n/dev/shm/SecOC.s  :\nsection                 size     addr\n.text  300  24128\n"
             ".rodata 20 5\n.data.rel.ro  552  457312\n.data  7  9\n.bss  1000  11\n.comment  31  0\nTotal  1910\n\n\n")
    one = {"unstripped_bytes": 900, "stripped_bytes": 800, "text_bytes": 300, "rodata_bytes": 20, "data_bytes": 7, "bss_bytes": 1000}
    assert sizes(table) == {None: one}
    two = sizes("== build-rx/\n" + table + "== build-tx/\n" + table.replace(".text  300", ".text  301"))
    assert two == {"build-rx": one, "build-tx": {**one, "text_bytes": 301}}
    assert stops(sizes, table + table)                                              # two tables under one build
    assert same(21, "21") and same(21, "21.0") and not same(21, "21.0000001") and same(2 ** 60 + 1, str(2 ** 60 + 1)) and not same(2 ** 60 + 1, str(2 ** 60))
    assert same(2487591.928, "2487591.928") and same(1 / 3, "0.3333333333") and not same(1 / 3, "0.33333334")
    assert not same(21, "") and not same(0.5, "n/a") and not same(3, "1/0")                # no number: a difference, not a stop
    print("self-test ok")


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) != 4:
        sys.stderr.write(__doc__)
        sys.exit(2)
    run_dir, analysis_dir, prefix = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    self_test()
    record_compared(analysis_dir, [])    # a direct call starts the file
    path = analysis_dir / "own_compared_keys.txt"
    before = path.read_text() if path.exists() else None      # empty, or what a caller with OWN_COMPARED_KEYS=add had collected
    ok = False
    try:
        ok = judge(run_dir, analysis_dir, prefix)
    finally:      # a call that does not end in agreement, also one that ends in an exception, leaves no key of its own
        if not ok and before is not None:
            path.write_text(before)
    print("OWN-CHECK AGREES" if ok else "OWN-CHECK DISAGREES")
    sys.exit(0 if ok else 1)


def judge(run_dir, analysis_dir, prefix):
    """Prints the comparison; True when everything agrees. The keys are written only then (the functional reader has put
    its own into the file before; main() takes them out again when this returns False or ends in an exception)."""
    # read first: a file that stops this reader must not leave the keys of the functional reader behind
    own, lines = own_keys(run_dir)
    own = {f"{prefix}.footprint.{k}": v for k, v in own.items()}
    with open(analysis_dir / "numbers.csv", newline="") as f:
        kit = {r["key"]: r["value"] for r in csv.DictReader(f) if r["key"].startswith(prefix + ".footprint.") and r["unit"] != "text"}
    functional = True
    if (run_dir / "FUNCTIONAL").exists():
        p = subprocess.run([sys.executable, "-I", "-B", str(HERE / "functional_compare.py")] + sys.argv[1:], capture_output=True, text=True,
                           env={**os.environ, "OWN_COMPARED_KEYS": "add"})
        print("== functional_compare.py (exit %d)" % p.returncode)
        print((p.stdout + p.stderr).rstrip())
        functional = p.returncode == 0
    bad, agreed = 0, []
    for key in sorted(set(own) | set(kit)):
        a, b = own.get(key), kit.get(key)
        if a is not None and b is not None and same(a, b):
            agreed.append(key)
        else:
            bad += 1
            print(f"DIFF {key}: own {a}, toolkit {b}")
    print("\n".join(lines))
    print(f"footprint: keys compared {len(set(own) | set(kit))}, differences {bad}")
    ok = bad == 0 and bool(kit) and functional
    if ok:
        record_compared(analysis_dir, agreed, add=True)
    return ok


if __name__ == "__main__":
    main()
