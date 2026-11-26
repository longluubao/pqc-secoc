r"""One numbers.tex for the manuscript from the analysis directories of several runs.

    python3 -m analysis.merge_numbers <analysis dir> [...] --out numbers_all.tex [--allow-marked]
    python3 -I <toolkit>/analysis/merge_numbers.py <analysis dir> [...] --out numbers_all.tex [--allow-marked]

Each input is a directory written by analysis.make_tables or analysis.sessions (or the numbers.tex in
it), generated with its own --key-prefix (per session and host: e1.s1.iris, e1.s2.iris). The output:

- <out>: a header naming every run (directory, key prefix, toolkit commit, number of keys), the macros
  once, then every key definition. \measundefined is only provided, so a manuscript that defines it
  before the \input (a PENDING marker while runs are missing) keeps its own; without that an unknown
  key is a hard error. \meas and \measraw are provided and then redefined, so a fallback definition
  made before the \input does not clash and is replaced.
- <out with .csv>: the audit rows of all inputs.
- <out>.suppressed.txt: the keys that are in the .csv only, with the reason (the percentile rule).

Errors (exit code 1, nothing written): a key with different values in two inputs, both named (the
same value twice is accepted); an input whose .tex and .csv disagree beyond its suppressed keys; an
input from a DRY_RUN, PILOT or EXCLUDED run, unless --allow-marked is given, and then the header says
so in capitals and the values stay wrapped in \notaresult; an input without suppressed_keys.txt (written
before the percentile rule). The merge sees what the analysis recorded, not the run directory: a run
that was marked or relabelled after it was analysed must be analysed again before it is merged.
"""
import argparse
import csv
import io
import re
import sys
from pathlib import Path

if __package__ in (None, ""):  # run by path under python3 -I, which keeps the script directory off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis import csvio, make_numbers  # noqa: E402

DEFINITION = re.compile(r"\\expandafter\\def\\csname meas@([^\\]+)\\endcsname")
RUN_LINE = re.compile(r"% run (?P<run>.*), seed .*, toolkit (?P<toolkit>.*), key prefix '(?P<prefix>.*)'$")
MARKED = re.compile(r"% (" + "|".join(csvio.MARKERS) + r") directory: NOT A RESULT")


def read(tex_path):
    """One numbers.tex with the numbers.csv next to it, as a dict: 'lines' (definition lines by
    key), 'rows' (CSV rows by key), 'held_back' (keys that are in the CSV only, with the reason),
    'marker' (DRY_RUN, PILOT or EXCLUDED when the run is not a result, else None), 'prefix' and
    'toolkit' from its header. The CSV may list more keys than the .tex file defines, but only
    those that the suppressed_keys.txt of the same directory names."""
    tex_path = Path(tex_path)
    text = tex_path.read_text(encoding="utf-8")
    lines = {}
    for line in text.splitlines():
        m = DEFINITION.match(line)
        if m:
            if m[1] in lines:
                raise ValueError(f"{tex_path}: key {m[1]!r} is defined twice")
            lines[m[1]] = line
    with open(tex_path.with_suffix(".csv"), newline="", encoding="utf-8") as f:
        table = list(csv.DictReader(f))
    if not table or list(table[0]) != make_numbers.CSV_HEADER:
        raise ValueError(f"{tex_path.with_suffix('.csv')}: not a numbers.csv written by this toolkit")
    rows = {r["key"]: r for r in table}
    listed = tex_path.with_name(make_numbers.SUPPRESSED_FILE)
    if not listed.is_file():  # written before the percentile rule: its .tex may define keys that the rule holds back
        raise ValueError(f"{tex_path.parent} has no {make_numbers.SUPPRESSED_FILE}: it was written by an older toolkit; "
                         "run make_tables on the run directory again")
    held_back = dict(ln.split("\t", 1) for ln in listed.read_text(encoding="utf-8").splitlines()
                     if ln and not ln.startswith("#"))
    if set(rows) - set(held_back) != set(lines) or not set(held_back) <= set(rows) or len(rows) != len(table):
        odd = sorted((set(rows) - set(held_back)) ^ set(lines))[:3] or sorted(set(held_back) - set(rows))[:3]
        raise ValueError(f"{tex_path} and its .csv do not list the same keys (for example {odd}; keys named in "
                         f"{make_numbers.SUPPRESSED_FILE} may be in the .csv only)")
    head = text.split("\\", 1)[0].splitlines()  # the comment lines above the first macro
    run = next((m for m in map(RUN_LINE.match, head) if m), None)
    marker = next((m[1] for m in map(MARKED.match, head) if m), "marked" if make_numbers.NOT_A_RESULT in text else None)
    return {"lines": lines, "rows": rows, "held_back": held_back, "marker": marker,
            "prefix": run["prefix"] if run else "?", "toolkit": run["toolkit"] if run else "?"}


def merge(tex_paths, allow_marked=False):
    """(tex text, csv text, number of defined keys, suppressed text) of the union of the inputs."""
    lines, rows, origin, held_back, runs, marked = {}, {}, {}, {}, [], []
    for path in map(Path, tex_paths):
        new = read(path)
        where = path.parent
        if new["marker"]:
            if not allow_marked:
                raise ValueError(f"{where} comes from a {new['marker']} run: its values are not results; pass "
                                 "--allow-marked to merge it anyway (the output is then marked)")
            marked.append(f"{where.name} ({new['marker']})")
        for key, row in new["rows"].items():
            if key in rows and (rows[key]["value"], rows[key]["formatted"]) != (row["value"], row["formatted"]):
                raise ValueError(f"key {key!r} has different values in {origin[key]} ({rows[key]['value']}) and {where} "
                                 f"({row['value']}): give each run its own --key-prefix (make_tables or make_numbers)")
            origin.setdefault(key, where)
            rows.setdefault(key, row)
        for key, line in new["lines"].items():
            lines.setdefault(key, line)
        held_back.update(new["held_back"])
        runs.append(f"%   {where.name}: key prefix '{new['prefix']}', toolkit {new['toolkit']}, {len(new['lines'])} keys"
                    + (f", {len(new['held_back'])} more held back" if new["held_back"] else "")
                    + (f", NOT A RESULT ({new['marker']})" if new["marker"] else ""))
    keys = sorted(lines)
    tex = (f"% numbers.tex: merged by analysis.merge_numbers from {len(tex_paths)} run(s), do not edit. {len(keys)} keys.\n"
           + (f"% CONTAINS VALUES THAT ARE NOT RESULTS (--allow-marked): {', '.join(marked)}\n" if marked else "")
           + (f"% {len(held_back)} more keys are in the .csv only: the .suppressed.txt file next to this one says why\n"
              if held_back else "")
           + "% runs:\n" + "\n".join(runs) + "\n" + make_numbers.MERGED_PREAMBLE
           + (make_numbers.NOT_A_RESULT if marked else "") + "\n".join(lines[k] for k in keys) + "\n")
    out = io.StringIO()
    w = csv.DictWriter(out, make_numbers.CSV_HEADER, lineterminator="\n")
    w.writeheader()
    w.writerows(rows[k] for k in sorted(rows))
    return tex, out.getvalue(), len(keys), make_numbers.SUPPRESSED_HEAD + "".join(f"{k}\t{held_back[k]}\n" for k in sorted(held_back))


def main(argv=None):
    ap = argparse.ArgumentParser(description="One numbers.tex from several analysis directories; a key with two values is an error.")
    ap.add_argument("inputs", nargs="+", type=Path, help="directories written by analysis.make_tables or analysis.sessions "
                    "(or their numbers.tex files)")
    ap.add_argument("--out", type=Path, required=True, help="path of the merged .tex file; the .csv goes next to it and the "
                    "held-back keys into <out>.suppressed.txt")
    ap.add_argument("--allow-marked", action="store_true", help="accept inputs from DRY_RUN, PILOT or EXCLUDED runs; the "
                    "header then says so and their values stay marked")
    a = ap.parse_args(argv)
    inputs = [p / "numbers.tex" if p.is_dir() else p for p in a.inputs]
    try:
        tex, table, n, held_back = merge(inputs, a.allow_marked)
    except (OSError, ValueError) as e:
        sys.exit(f"error: {e}")
    suppressed = Path(str(a.out) + ".suppressed.txt")
    a.out.write_text(tex, encoding="utf-8")
    a.out.with_suffix(".csv").write_text(table, encoding="utf-8")
    suppressed.write_text(held_back, encoding="utf-8")
    print(f"{n} keys from {len(inputs)} run(s) -> {a.out} and {a.out.with_suffix('.csv')}; held-back keys in {suppressed}")


if __name__ == "__main__":
    main()
