r"""Sessions of one experiment side by side: a table with one row per session and statistic, and the
range over the sessions as number keys. Sessions are never pooled.

    python3 -m analysis.sessions --out <dir> <analysis dir of session 1> <analysis dir of session 2> [...]
    python3 -I <toolkit>/analysis/sessions.py --out <dir> <analysis dir> <analysis dir> [...]

Each input is a directory written by analysis.make_tables with its own --key-prefix; the prefixes
must differ in exactly one part, the session (e1.s1.iris, e1.s2.iris, e1.s3.iris). For the
statistics the manuscript quotes (QUOTED: median, mean, p99, p99.9, p99.99, maximum, exceed_5ms.p,
exceed_10ms.p, exceed_20ms.k, tail_ratio_per_ms, and the bounds of E9, of the anchors, of the offset in total and the
total bound of Addendum E, which stand beside every latency across the two boards) the output has the keys

    <prefix with the session part replaced by 'all'>.<statistic>.min_over_sessions / .max_over_sessions

(e1.all.iris.crypto_ops.sign_p8.mldsa_sign.p99_us.max_over_sessions), written as numbers.tex,
numbers.csv, number_keys.md and suppressed_keys.txt, to be merged with the sessions' own files by
analysis.merge_numbers. There is no mean over sessions and no pooled estimate. A statistic that one
session lacks gets no range. An 'n' (the number of values of a file and operation) that differs
between the sessions is an error, except the n of E9's e2e keys: the PDUs delivered are an outcome
of a session, not a count that its design fixes. Each board is its own set of sessions: one command per board. The numbers are rebuilt from each session's summary.json, so the
percentile rule of this toolkit version applies whatever version wrote the session's files.
"""
import argparse
import json
import re
import sys
from pathlib import Path

if __package__ in (None, ""):  # run by path under python3 -I, which keeps the script directory off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis import csvio, make_numbers, tables, toolkit_commit  # noqa: E402
from analysis.tables import DASH  # noqa: E402

ALL = "all"
# the statistics the manuscript quotes, as the last parts of a key
QUOTED = re.compile(r"(?:^|[._])(?:(?:p50|mean|p99|p99_9|p99_99|max)_(?:us|ms)|exceed_(?:5|10)ms\.p|exceed_20ms\.k"
                    r"|tail_ratio_per_ms|e2e\.offset_bound_us|e2e\.offset_bound_total_us|e2e\.bound_total_us)$")
BANNER = {"DRY_RUN": "DRY RUN: not a result", "PILOT": "PILOT: not a result", "EXCLUDED": "EXCLUDED RUN: not a result"}


def load(out_dir):
    """One analysed session: (key prefix, summary, items by key without the prefix)."""
    summary = json.loads((Path(out_dir) / "summary.json").read_text(encoding="utf-8"))
    prefix = summary.get("key_prefix") or ""
    if not prefix:
        raise ValueError(f"{out_dir} has no key prefix: analyse each session with its own --key-prefix (e1.s1.iris)")
    items = make_numbers.collect(summary["results"], {"seed": summary.get("seed"), **summary.get("params", {})}, prefix)
    return prefix, summary, {i["key"][len(prefix) + 1:]: i for i in items}


def all_prefix(prefixes):
    """The key prefix of the ranges: the sessions' prefixes with the one part in which they differ
    replaced by ALL. Prefixes that are equal, or differ in length or in more than one part, are an error."""
    parts = [p.split(".") for p in prefixes]
    twice = sorted({p for p in prefixes if prefixes.count(p) > 1})
    if twice:
        raise ValueError(f"two sessions have the same key prefix {twice[0]!r}")
    differ = [i for i in range(len(parts[0])) if len({p[i] for p in parts if len(p) > i}) > 1]
    if len({len(p) for p in parts}) > 1 or len(differ) != 1:
        raise ValueError(f"the key prefixes {prefixes} must differ in exactly one part, the session")
    return ".".join(ALL if i == differ[0] else part for i, part in enumerate(parts[0]))


def plain(value, unit, decimals=None):
    """A table cell: the value without LaTeX, with at least `decimals` decimals (those that tell the smallest and the
    largest session value of the statistic apart: the table tells apart what the range keys tell apart)."""
    if unit in ("count", "id"):
        return str(value)
    scale, mark = (100, "%") if unit == "percent" else (1, "")
    cell = tables.pct(value, 4) if mark else tables.num(value, 2)
    if decimals is not None and decimals > len(cell.rstrip("%").partition(".")[2]):
        cell = tables.rounded(scale * value, decimals) + mark
    return cell


def range_decimals(ends, unit, signed, shown, fixed):
    """(decimals both ends of a range are printed with, decimals that tell the ends apart for the table cells).

    `ends` are the smallest and the largest session value, `shown` the decimals each session prints its own value
    with (None: scientific notation), `fixed` the decimals a statistic prescribes (whole-microsecond cyclictest
    values: 0), None where it prescribes none.

    A range is its own statistic: its decimals show one significant digit of the distance between its two ends, and
    nothing else. Two tail ratios of 2.26295 and 2.26353 are 2.2629 and 2.2635; medians of 423.925 and 424.537 us are
    423.9 and 424.5 although one session prints three decimals; maxima of 17.83 and 19.29 ms are 18 and 19 although
    the unit prints two. One more decimal only where that digit would print the two ends alike, which takes two ties
    that round to the same digit (11.5 and 12.5): a range tells its ends apart whenever they differ. And one floor:
    where that digit would print a non-zero end as zero, both ends get the decimals that show one significant digit
    of the smaller non-zero end (0.07 to 5.00 ms; 0.0004% to 0.3000%); an end that is exactly zero prints as zero.
    Counts stay whole; a p-value or an identifier keeps the rule of its unit (None).
    Ends that are equal have no distance and print as the sessions do; equal means equal to the twelve significant
    digits a value is taken to have (make_numbers._distance). For a proportion the decimals and the distance are those
    of the percentage. (A cap of three decimals beyond the leading digit of the distance, built first, cannot bind any
    more: the rule gives exactly that leading digit.)"""
    apart = make_numbers.shared_decimals(ends, unit, signed)
    scale = 100 if unit == "percent" else 1
    gap = make_numbers._distance(scale * ends[0], scale * ends[1])
    if not gap:
        decimals = max(fixed) if None not in fixed else None if None in shown else max(shown)
    elif apart is None:
        decimals = None
    else:
        decimals = 0 if unit in make_numbers.INTEGER_UNITS else max(0, -make_numbers._exponent(gap))
        if make_numbers.fmt(ends[0], unit, signed, decimals) == make_numbers.fmt(ends[1], unit, signed, decimals):
            decimals += 1  # both ends are ties that round to one digit (11.5 and 12.5 are both 12): a range tells its ends apart
        if any(v and not re.search("[1-9]", make_numbers.fmt(v, unit, signed, decimals)) for v in ends):
            # the one floor: a non-zero end must not print as zero; both ends then show one significant digit of the
            # smaller non-zero end (0.07 to 5.00 ms)
            decimals = -make_numbers._exponent(min(abs(scale * v) for v in ends if v))
    # the table cells keep their own rule: at least two decimals, and those that tell the ends apart for every unit
    if apart is not None and gap and unit not in ("percent", "us", "ms", *make_numbers.INTEGER_UNITS):
        apart = max(apart, -make_numbers._exponent(gap))
    return decimals, apart


def combine(out_dirs):
    """(range items, table rows, meta) for the sessions in `out_dirs`."""
    if len(out_dirs) < 2:
        raise ValueError("a range over sessions needs at least two analysed sessions")
    loaded = [load(d) for d in out_dirs]
    prefixes = [prefix for prefix, _, _ in loaded]
    base = all_prefix(prefixes)
    warmups = {prefix: s.get("params", {}).get("warmup") for prefix, s, _ in loaded}
    if len(set(warmups.values())) > 1:
        raise ValueError(f"warmup differs between the sessions ({warmups}): their statistics are not comparable")
    counts = {}  # a caption states one n per file and operation for all sessions
    for prefix, _, items in loaded:
        for k, i in items.items():
            # E9: the PDUs delivered, of a run or of one of its streams, are an outcome, not a design count
            if k.rsplit(".", 1)[-1] == "n" and not re.search(r"\.e2e\.(stream[^.]+\.)?n$", k):
                counts.setdefault(k, {})[prefix] = i["value"]
    for k, by in counts.items():
        if len(set(by.values())) > 1:
            raise ValueError(f"{k} differs between the sessions: " + ", ".join(f"{p} {v}" for p, v in by.items())
                             + "; the sessions of one experiment must have the same number of values")
    stats = list(dict.fromkeys(k for _, _, items in loaded for k in items if QUOTED.search(k)))
    ranges, rows, printed = [], [], []
    for stat in sorted(stats):
        have = [(prefix, items[stat]) for prefix, _, items in loaded if stat in items]
        first = have[0][1]
        held_back = next((f"in session {prefix}: {i['suppressed']}" for prefix, i in have if i["suppressed"]), None)
        ends = [f(i["value"] for _, i in have) for f in (min, max)]
        decimals, apart = range_decimals(ends, first["unit"], first["signed"], [i.get("shown_decimals") for _, i in have],
                                         [i.get("decimals") for _, i in have])
        rows += [[stat, first["unit"], prefix, plain(i["value"], i["unit"], apart), make_numbers._n(i),
                  "no" if i["suppressed"] else "yes"] for prefix, i in have]
        if len(have) < len(loaded):  # never a range over fewer sessions than were given
            missing = ", ".join(p for p in prefixes if p not in [q for q, _ in have])
            rows.append([stat, first["unit"], f"no range: not in {missing}", DASH, len(have), "no"])
            continue
        whose = f"{len(have)} sessions' values ({', '.join(prefixes)}; no pooling)"
        for end, pick, word in (("min", min, "smallest"), ("max", max, "largest")):
            value = pick(i["value"] for _, i in have)
            ranges.append({"key": f"{base}.{stat}.{end}_over_sessions", "value": value, "unit": first["unit"], "n": len(have),
                           "source_file": ", ".join(str(Path(d).name) for d in out_dirs), "experiment": first["experiment"],
                           "filter": first["filter"], "signed": first["signed"], "group": f"{base}.{stat}",
                           "how": f"{word} of the {whose} of: {first['how']}",
                           "raw": make_numbers.raw(value), "suppressed": held_back, "decimals": decimals})
            rows.append([stat, first["unit"], f"{end} over sessions", plain(value, first["unit"], apart), len(have),
                         "no" if held_back else "yes"])
        printed.append((*ranges[-2:], whose, first["how"]))
    make_numbers.format_items(ranges)
    # the third key of a statistic prints its range as one piece of text: both ends as their own keys print them, with
    # an en dash, or the one value when the ends are exactly equal (two keys cannot print 'a' in place of 'a--a')
    for low, high, whose, what in printed:
        same = not make_numbers._distance(low["value"], high["value"])  # no distance: the predicate of range_decimals
        text, plain_text = (low[k] if same else f"{low[k]}--{high[k]}" for k in ("formatted", "raw"))
        key = low["group"] + ".range_over_sessions"
        ranges.append({**low, "key": key, "group": key, "value": text, "formatted": text, "raw": plain_text, "unit": "text",
                       "signed": False, "decimals": None,
                       "how": (f"the one value all {whose.replace(chr(39) + ' values', ' have')} of: {what}" if same else
                               f"smallest to largest of the {whose}, printed as one range, of: {what}")})
    found = [m for _, s, _ in loaded for m in (s.get("markers") or [])]
    marker = next((name for name in csvio.MARKERS for _, s, _ in loaded if s.get("not_a_result") == name), None)
    meta = {"run_dir": "sessions " + ", ".join(prefixes), "seed": None, "toolkit_commit": toolkit_commit(), "key_prefix": base,
            "not_a_result": marker, "markers": found,  # the next two word number_keys.md for several sessions
            "title": "the ranges over the sessions " + ", ".join(prefixes), "scope": "these sessions"}
    return sorted(ranges, key=lambda i: i["key"]), rows, meta


def main(argv=None):
    ap = argparse.ArgumentParser(description="Sessions side by side: a table and min / max / range keys over sessions; no pooling.")
    ap.add_argument("sessions", nargs="+", type=Path, help="directories written by analysis.make_tables, one per session")
    ap.add_argument("--out", type=Path, required=True, help="output directory")
    a = ap.parse_args(argv)
    try:
        ranges, rows, meta = combine(a.sessions)
    except (OSError, ValueError, KeyError) as e:
        sys.exit(f"error: {e}")
    a.out.mkdir(parents=True, exist_ok=True)
    tables.write(a.out, "sessions", ["statistic", "unit", "session", "value", "n", "in numbers.tex"], rows,
                 "one row per session and statistic, then the smallest and the largest session value; sessions are never "
                 "pooled and no mean over sessions is formed; n: the values behind a session's statistic, or the number of "
                 "sessions for a range; in numbers.tex: 'no' for a percentile with fewer than 10 samples above it in some "
                 "session, and for a statistic that a session lacks", BANNER.get(meta["not_a_result"]))
    make_numbers.write(a.out / "numbers.tex", ranges, meta)
    print(f"{len(a.sessions)} sessions -> {a.out}: sessions.md, sessions.tex and {len(make_numbers.defined(ranges))} range keys "
          f"in numbers.tex ({len(ranges) - len(make_numbers.defined(ranges))} more held back)")


if __name__ == "__main__":
    main()
