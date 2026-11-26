r"""summary.json -> numbers.tex and numbers.csv: one LaTeX macro per reported scalar.

    python3 -m analysis.make_numbers <analysis_out_dir> [--out numbers.tex]
    python3 -I <toolkit>/analysis/make_numbers.py <analysis_out_dir>

make_tables writes both files itself; run this alone to rebuild them from an existing summary.json.
In the manuscript: \input{numbers.tex}, then \meas{<key>} for the formatted value and
\measraw{<key>} for the plain one. An unknown key is a LaTeX error, never an empty string. A value that is missing
or undefined in the run gets no macro. Key scheme and formatting rules: README.md.
"""
import argparse
import csv
import io
import json
import math
import re
import sys
from fractions import Fraction
from pathlib import Path, PurePosixPath

if __package__ in (None, ""):  # run by path under python3 -I, which keeps the script directory off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis import csvio, footprint, functional, handshake, hsneg, overhead, sign_attrib, tables, throughput, toolkit_commit  # noqa: E402

SEGMENT = re.compile(r"[A-Za-z0-9_-]+")  # a key is segments joined by dots; nothing else may enter a \csname
INTEGER_UNITS = ("count", "bytes")
STATS = {"mean": "mean", "sd": "sd", "min": "min", "max": "max", "p50": "p50", "p90": "p90", "p95": "p95",
         "p99": "p99", "p99.9": "p99_9", "p99.99": "p99_99"}
P_FLOOR = 1e-300
MIN_ABOVE = 10  # a percentile is a manuscript number only when at least this many samples lie above it


def scarce(stat, n):
    """Why the percentile `stat` ('p50', 'p99.99') of n values is not a manuscript number, or None when
    it is one. Rule: n(1 - p) >= MIN_ABOVE samples must lie above it (for a percentile below the median,
    mirrored: n p samples below it); with fewer the value depends on the percentile definition
    (nearest rank against the interpolating type 7). The product is taken
    exactly: 100000 x (1 - 0.9999) is 10, where floating point gives 9.999999999998899. A statistic
    that is not a percentile (mean, sd, min, max) always passes."""
    if not (stat[:1] == "p" and stat[1:2].isdigit()):
        return None
    p = Fraction(stat[1:]) / 100
    beyond, side = (n * (1 - p), "above") if 2 * p >= 1 else (n * p, "below")  # a low percentile: the samples below it
    if beyond >= MIN_ABOVE:
        return None
    return (f"{stat} of {n} values: {float(beyond):g} samples lie {side} it, fewer than {MIN_ABOVE}; the value depends on the "
            "percentile definition")

# ---- formatting ----------------------------------------------------------------------------------


def _exponent(v):
    """floor(log10(v)) of a positive v, immune to rounding noise in the last bits (100 * 0.9 is
    90.00000000000001, and its complement must still count as 10, not 9.99...)."""
    return math.floor(math.log10(float(f"{v:.12g}")))


def _distance(a, b):
    """|a - b| of two values taken as exact to 12 significant digits, rounded at the twelfth significant digit of the
    larger one: 423.926 - 423.925 is 0.001, not the 0.00099999999998 of floating point, which would count as a
    distance below 0.001 and cost a decimal too many whenever a bound is exactly 1, 10 or 100 ns away."""
    a, b = float(f"{a:.12g}"), float(f"{b:.12g}")
    big = max(abs(a), abs(b))
    return round(abs(a - b), 11 - _exponent(big)) if big else 0.0


def _decimals(value, unit, signed, scientific=True):
    """Decimal places of the fixed-point form under the rule of `unit` (percent: of the percentage),
    or None where the rule uses scientific notation (never None with scientific=False)."""
    v = abs(value)
    if unit in INTEGER_UNITS:
        return 0
    if unit == "percent":
        x = float(f"{100 * v:.12g}")
        if 0 < x < 0.01 and scientific:
            return None
        if x > 100:  # above one: one significant digit of the excess, so that only an exact one prints as 100%
            return max(0, -_exponent(x - 100))
        m = x if signed else min(x, 100 - x)  # a probability near 1 is as precise as its complement
        d = 0 if m == 0 else max(0, 1 - _exponent(m))
        if x != 100 and float(tables.rounded(x, d)) == 100:  # a signed value just below one: its distance to 100% shows too
            d = -_exponent(100 - x)
        return d
    if unit == "p":
        return None if v < 1e-3 and scientific else max(0, 1 - _exponent(v))
    base, sig = {"us": (0, 2), "ms": (2, 2)}.get(unit, (0, 3))
    return base if v == 0 else max(base, sig - 1 - _exponent(v))


def shared_decimals(values, unit, signed=False):
    """Decimals for an estimate (the first value) and its confidence bounds, so that all of them are
    printed alike: the largest number any member needs under its own rule, in fixed notation. A
    proportion (unit percent) and a time (us, ms) get in addition the decimals that show one
    significant digit of the smallest distance between the estimate and a bound that differs from
    it, so that a narrow interval is not printed as its estimate: 2.65% [2.62%, 2.68%], not 2.7%
    [2.6%, 2.7%]; 1,456.0 [1,455.8, 1,456.2] us, not 1,456 [1,456, 1,456]. A distance that vanishes
    at 12 significant digits is rounding noise and counts as none (see _distance). None for the units
    p and id: each member is printed on its own."""
    if unit in ("p", "id"):
        return None
    d = max(_decimals(v, unit, signed, scientific=False) for v in values)
    if unit in ("percent", "us", "ms"):
        scale = 100 if unit == "percent" else 1
        gaps = [g for g in (_distance(scale * v, scale * values[0]) for v in values[1:]) if g]
        if gaps:
            d = max(d, -_exponent(min(gaps)))
    return d


def fmt_together(values, unit, signed=False):
    """An estimate (first) and its bounds formatted with shared_decimals()."""
    d = shared_decimals(values, unit, signed)
    return [fmt(v, unit, signed, d) for v in values]


def _used(value, unit, signed, decimals):
    """The decimals fmt() prints a finite value with (None: scientific notation, or a word)."""
    if unit == "text":
        return None
    if unit == "percent" and value in (0, 1):  # none of n and n of n are exact: 0% and 100%, whatever the group's decimals
        return 0
    return _decimals(value, unit, signed) if decimals is None else decimals


def fmt(value, unit, signed=False, decimals=None):
    r"""TeX markup of `value`, usable in text and in math mode.

    us: integer with {,} thousands separators.  ms: two decimals.  Both show at least two
    significant digits, so 0.44 us is "0.44", not "0".  Every unit is rounded by tables.rounded(): in
    decimal arithmetic, half to even, so that a time rounds the same way in its two units and a table
    cell the same way as its key.
    percent (value is a fraction): percentage with two significant digits, counted on the smaller of
    p and 1 - p so that 0.99617 is "99.62\%", not "100\%"; scientific below 0.01% for a value that
    stands alone (never with `decimals`, so never for an estimate with bounds); an exact zero is
    "0\%" and an exact one "100\%" whatever the decimals (none of 999,000 has no fifth decimal),
    and nothing else prints as 100%: above one the decimals show one significant digit of the
    excess ("100.04\%", "104\%"); ends in \%.
    p: two significant digits, scientific below 0.001, "<10^{-300}" at or below 1e-300 (also for 0).
    count, bytes: integer with separators.  id: the integer as it is (a seed).  text: a word of a
    fixed vocabulary that the reader has checked (PASS, FAIL), or text composed from formatted numbers
    (a range over sessions), printed as it is.  Any other unit: three significant digits.
    `decimals` overrides the number of decimals (see shared_decimals: an estimate and its bounds are
    printed with the same number). `signed` always prints the sign; a value that rounds to zero has none.
    """
    if unit == "text":
        return value
    if not math.isfinite(value):
        raise ValueError(f"cannot format the non-finite value {value!r}")
    if unit == "id":
        return str(int(value))
    if unit == "p" and value <= P_FLOOR:
        return rf"\ensuremath{{<10^{{{round(math.log10(P_FLOOR))}}}}}"
    x = 100 * value if unit == "percent" else value
    sign = "-" if x < 0 else "+" if signed and x > 0 else ""
    d = _used(value, unit, signed, decimals)
    if d is None:
        mantissa, exponent = f"{abs(x):.1e}".split("e")
        body = rf"\ensuremath{{{sign}{mantissa}\times10^{{{int(exponent)}}}}}"
    else:
        # the one rounding of the toolkit, shared with the tables: 87.5 us is "88" and, as 0.0875 ms, "0.088"
        whole, _, frac = tables.rounded(abs(x), d).partition(".")
        if not (int(whole) or frac.strip("0")):
            sign = ""  # rounded to zero: no "-0"
        body = (rf"\ensuremath{{{sign}}}" if sign else "") + f"{int(whole):,}".replace(",", "{,}") + ("." + frac if frac else "")
    return body + (r"\%" if unit == "percent" else "")


# ---- keys ----------------------------------------------------------------------------------------


def _g(x):
    """A number inside a key segment: 10.0 -> '10', 2.5 -> '2p5'."""
    return f"{x:g}".replace(".", "p")


def _duration(us):
    ns = round(us * 1e3)
    return next((f"{ns // m}{unit}" for unit, m in (("ms", 10**6), ("us", 10**3)) if ns % m == 0), f"{ns}ns")


def file_label(source):
    """The <label> of a file named <kind>_<label>.csv, else ''."""
    name = PurePosixPath(source).name
    kind = csvio.kind_of(name)
    m = re.fullmatch(re.escape(kind) + r"[._-](.+)\.csv", name) if kind in csvio.KINDS else None
    return m[1] if m else ""


def label(kind, source):
    """Run-specific key part for experiments whose files carry no configuration header: the name of
    the file's directory without the leading words it shares with `kind`, then the file's own label,
    joined by '-'. Empty for the canonical layout (crypto/crypto_ops.csv, attack/attack.csv);
    'mac' for attack_mac/attack.csv; '1e6' for crypto_1e6/crypto_ops.csv."""
    words, kind_words = [w for w in re.split("[_-]", PurePosixPath(source).parent.name) if w], kind.split("_")
    shared = 0
    while shared < min(len(words), len(kind_words)) and words[shared] == kind_words[shared]:
        shared += 1
    return "-".join(part for part in ("_".join(words[shared:]), file_label(source)) if part)


def paired_label(source, mode, launch=None):
    """Key label of a paired-overhead file. A noise-floor (mode aa) file always has 'aa' in it, so it
    can never take the keys of the comparison. One launch of a set is keyed by the set's label
    (that of a plain overhead_paired.csv in its directory) and its launch number, whatever the file
    is called: the set itself then owns the plain keys for its pooled result."""
    if launch is not None:
        source = f"{PurePosixPath(source).parent}/overhead_paired.csv"
    lab = label("overhead_paired", source)
    if mode == "aa" and "aa" not in re.split("[-_]", lab):
        lab = "-".join(part for part in (lab, "aa") if part)
    return lab if launch is None else "-".join(part for part in (lab, f"L{launch:02d}") if part)


def config_id(r):
    """Key part of a periodic configuration, from its file header: p<period>[-d<deadline>]-s<streams>-
    c<cores>-<profile>-<scheduler>[-<mainfunction>][-mf<period>][-<phase>][-part<partition>]; the
    deadline appears only when it differs from the period, the last four only when the file has the
    optional header key."""
    deadline = f"-d{_duration(r['deadline_us'])}" if r["deadline_us"] != r["period_us"] else ""
    optional = (r.get("mainfunction"), None if r.get("mf_period_us") is None else f"mf{_duration(r['mf_period_us'])}",
                r.get("phase"), None if r.get("partition") is None else f"part{r['partition']}")
    return (f"p{_duration(r['period_us'])}{deadline}-s{r['streams']}-c{r['cores']}-{r['profile']}-{r['scheduler']}"
            + "".join(f"-{part}" for part in optional if part))


def off_cpu_s(header):
    """wall_s - cpu_s of a harness file's footer lines, or None when the file does not have both."""
    try:
        return float(header["wall_s"]) - float(header["cpu_s"])
    except (KeyError, TypeError, ValueError):
        return None


def ladder_id(t):
    """Key part of a throughput ladder, from its file header: <profile>-c<cores>[-<mainfunction>]
    [-mf<period>]; cores is the header's cores times the partitions, the last two appear only when
    the files have the optional header key."""
    optional = (t.get("mainfunction"), None if t.get("mf_period_us") is None else f"mf{_duration(t['mf_period_us'])}")
    return f"{t['profile']}-c{t['cores']}" + "".join(f"-{part}" for part in optional if part)


def handshake_label(f):
    """Key label of a handshake file: one file per host, keyed by the host its '# host=' line names,
    whatever the file is called (baolong's files say raspberrypi); a file without that line is keyed
    by its own label."""
    source = f["source"]
    if f.get("host"):
        source = f"{PurePosixPath(source).parent}/handshake_{f['host']}.csv"
    return label("handshake", source)


HSNEG_RECORD = {  # the counts of a negative test's record line that become keys
    "repetitions": "repetitions asked for", "repetitions_done": "complete repetitions found",
    "attacked": "handshakes the proxy edited, messages it injected, or probes sent", "runs": "runs of the test (a batch has several)",
    "runs_passed": "runs that passed", "pdus_sent": "PDUs sent during the test", "pdus_delivered": "PDUs delivered during the test",
    "pdus_rejected": "PDUs rejected during the test", "pdus_given_up": "PDUs given up without a confirmation during the test",
    "installs_tx": "key installations on the initiator's side", "installs_rx": "key installations on the responder's side"}


def _dotted(*parts):
    return ".".join(p for p in parts if p)


# ---- summary.json -> items -----------------------------------------------------------------------


HINTS = {  # what to do about a duplicate key, per experiment
    "periodic": "the configuration id comes from the Tx file header; name a repeated configuration "
                "periodic_tx_<label>.csv and periodic_rx_<label>.csv to give it its own keys",
    "throughput": "the ladder id comes from the file header (profile, cores, main function) and a run directory can "
                  "hold one ladder per id; either two directories hold the same ladder, or the files of one ladder "
                  "disagree in a header key such as commit",
}
DEFAULT_HINT = "two files of one experiment need different directory names or file labels"


def collect(results, run=None, key_prefix=""):
    """Every scalar of a make_tables 'results' dict as an item (key, value, formatted, raw, unit, n,
    source_file, experiment, filter, how), sorted by key, plus the run parameters in `run` (seed,
    warm-up, ...) under 'run.<name>'. `n` is the sample size behind that statistic. Values that are
    None get no item. `key_prefix` (for example 's1.iris') is put in front of every key, so that the
    numbers of several runs can be loaded together. An invalid or duplicate key raises ValueError.

    `raw` is the plain number as text, or None for a p-value at or below 1e-300: an underflowed p
    has no plain form (0 would be a lie), only the formatted "<10^{-300}".
    """
    items = {}
    root = f"{key_prefix}." if key_prefix else ""

    def emitter(prefix, source, experiment, filt):
        def add(name, value, unit, how, n, of=None, signed=False, why=None, decimals=None):
            """`of` names the estimate (same prefix) whose confidence bound this is: they share decimals.
            `why` (see scarce()) keeps the key out of numbers.tex; it stays in numbers.csv. `decimals`
            fixes the number of decimals instead of the unit's rule (0 for values that are whole numbers
            by construction)."""
            if value is None:
                return
            key = f"{root}{prefix}.{name}"
            bad = [seg for seg in key.split(".") if not SEGMENT.fullmatch(seg)]
            if bad:
                raise ValueError(f"{source}: number key {key!r} has the part(s) {bad} outside [A-Za-z0-9_-]; rename the "
                                 "directory, file label or stream so that the key is a valid LaTeX name")
            if key in items:
                raise ValueError(f"duplicate number key {key!r} from {items[key]['source_file']} and {source}: "
                                 f"{HINTS.get(experiment.removesuffix('_rx'), DEFAULT_HINT)} (README.md, 'Keys')")
            items[key] = {"key": key, "value": value, "unit": unit, "n": n, "source_file": source,
                          "experiment": experiment, "filter": filt, "how": how, "signed": signed,
                          "group": f"{root}{prefix}.{of}" if of else key,
                          "raw": None if unit == "p" and value <= P_FLOOR else raw(value), "suppressed": why,
                          "decimals": decimals}
        return add

    def time(add, name, us, how, n, of=None, signed=False, why=None):  # every time gets a _us and a _ms key
        for unit, per in (("us", 1), ("ms", 1000)):
            add(f"{name}_{unit}", None if us is None else us / per, unit, how, n, f"{of}_{unit}" if of else None, signed, why)

    def described(add, prefix, d, what):
        if d is None:  # a time the file has no timestamps for ('# not_recorded='): no keys
            return
        add(prefix + "n", d["n"], "count", f"number of values of {what}", d["n"])
        for stat, name in STATS.items():
            time(add, prefix + name, d.get(stat), f"{stat} of {what}" + (", type-7 percentile" if stat[0] == "p" else ""),
                 d["n"], why=scarce(stat, d["n"]))

    def interval(add, name, pair, unit, how, n, of, signed=False, decimals=None, why=None):  # the bounds of the estimate named `of`
        for side, v in zip(("lo", "hi"), pair):
            add(f"{name}_{side}", v, unit, f"{how}, {'lower' if side == 'lo' else 'upper'} bound", n, of, signed, why, decimals)

    def time_interval(add, name, pair_us, how, n, of, signed=False, why=None):
        for side, v in zip(("lo", "hi"), pair_us):
            time(add, f"{name}_{side}", v, f"{how}, {'lower' if side == 'lo' else 'upper'} bound", n, of, signed, why)

    def header(base, f, experiment):  # numeric '# key=value' lines of a harness file
        add = emitter(f"{base}.header" if base else "header", f["source"], experiment, "file header")
        for k, v in (f.get("header") or {}).items():
            try:
                number, unit = int(v), "id" if k == "seed" else "count"
            except ValueError:
                try:
                    number, unit = float(v), "1"
                except ValueError:
                    continue  # text (tool, commit, host, mode, ...): not a number
            if math.isfinite(number):
                add(k, number, unit, f"'# {k}=' line of the file", None)

    add = emitter("run", "summary.json", "run", "analysis parameter")
    for name, how in (("warmup", "samples with seq below this are dropped in the single-node series (crypto_ops, sign_attrib, "
                       "overhead_paired and overhead_unpaired files); nothing is dropped in the periodic, throughput, attack, "
                       "handshake, negative-test, functional and cyclictest analyses, where this parameter does not apply"),
                      ("block_len", "moving-block bootstrap block length"),
                      ("n_boot", "bootstrap replicates"), ("trim", "throughput samples dropped at each end of a rate step"),
                      ("sim_draws", "queue model: random-offset draws"), ("sim_jobs", "queue model: jobs per run")):
        add(name, (run or {}).get(name), "count", how, None)
    add("seed", (run or {}).get("seed"), "id", "seed of the bootstrap and the queue model", None)

    def checks(base, f, experiment):  # derived from the header: the share of one core the run had, and the time off it
        share = (f.get("validity") or {}).get("cpu_share")
        emitter(base, f["source"], experiment, "file header")("cpu_share", share, "1", "cpu_s / wall_s", None)
        emitter(f"{base}.header" if base else "header", f["source"], experiment, "file header")(
            "off_cpu_s", off_cpu_s(f.get("header")), "s", "wall_s - cpu_s of the file footer: the time the process was "
            "not on a processor, over the whole file (every operation, warm-up included)", None)

    for f in results["crypto_ops"]:
        base = _dotted("crypto_ops", label("crypto_ops", f["source"]))
        header(base, f, "crypto_ops")
        checks(base, f, "crypto_ops")
        for o in f["ops"]:
            t, n = o["time_us"], o["time_us"]["n"]
            add = emitter(f"{base}.{o['op']}", f["source"], "crypto_ops", f"op={o['op']}, seq>={f['warmup']}")
            add("n_total", o["n_total"], "count", "samples in the file", o["n_total"])
            add("n_dropped", o["n_warmup_dropped"], "count", "warm-up samples dropped", o["n_total"])
            described(add, "", t, "post-warm-up time")
            add("cv", t.get("cv"), "1", "sd / mean", n)
            add("lag1", t.get("lag1"), "1", "lag-1 autocorrelation", n)
            if b := o.get("bootstrap"):
                for q in ("p50", "p99"):
                    time_interval(add, f"{q}_ci95", b[f"{q}_ci95_us"], f"moving-block bootstrap 95% CI of {q} "
                                  f"(block {b['block_len']}, {b['n_boot']} replicates)", n, q, why=scarce(q, n))
            if e := o.get("excess_over_10ms"):
                add("excess_over_10ms_calls", e["calls"], "count", "calls above 10 ms", n)
                add("excess_over_10ms_s", e["seconds"], "s", "time beyond 10 ms in the calls above 10 ms: sum of (t - 10 ms) "
                    "over them", n)
            if e := o.get("tail_expected"):
                add("tail_expected_above_max", e["expected_count"], "1", "expected count above the largest value of this "
                    f"series under the fitted decay of {e['fit_source']}, for the calls of this series", e["calls"])
            if first := (o.get("tail") or {}).get("from_1ms"):
                how = f"sensitivity: the tail fit started at 1 ms ({first['bins']} bins up to {first['to_ms']} ms)"
                add("tail_ratio_from1ms", first["ratio_per_ms"], "1", how + ", ratio per ms", first["bins"])
                add("tail_dispersion_from1ms", first["dispersion"], "1", how + ", Pearson chi-square / (bins - 2)", first["bins"])
            if fit := (o.get("tail") or {}).get("fit"):
                add("tail_above_fit_end", fit["above_fit_end"], "count", f"samples above {fit['to_ms']} ms, the upper end "
                    "of the tail fit", n)
                how = (f"1-ms bins from {fit['from_ms']} ms (the first whole millisecond above the median) to {fit['to_ms']} "
                       "ms (the last with at least 100 samples above it)")
                add("tail_ratio_per_ms", fit["ratio_per_ms"], "1", "factor by which the count of samples falls per "
                    "millisecond: Poisson regression of the counts in the " + how, fit["bins"])
                for side, v in zip(("lo", "hi"), fit["ratio_ci95"]):
                    add(f"tail_ratio_{side}", v, "1", f"95% interval of that factor, {'lower' if side == 'lo' else 'upper'} "
                        "bound: Wald on the log ratio, Student-t, standard error scaled by sqrt(max(1, dispersion))",
                        fit["bins"], "tail_ratio_per_ms")
                add("tail_fit_from_ms", fit["from_ms"], "count", "first threshold of the fit range, in ms", fit["bins"])
                add("tail_fit_to_ms", fit["to_ms"], "count", "last threshold of the fit range, in ms", fit["bins"])
                add("tail_fit_bins", fit["bins"], "count", "1-ms bins the fit uses", fit["bins"])
                add("tail_dispersion", fit["dispersion"], "1", "Pearson chi-square / (bins - 2) of that fit; far above 1: "
                    "the counts do not fall by a constant factor over the range", fit["bins"])
            for e in o.get("exceedance", []):
                at = f"exceed_{_g(e['threshold_ms'])}ms"
                add(f"{at}.k", e["k"], "count", f"samples above {e['threshold_ms']:g} ms", e["n"])
                add(f"{at}.p", e["p"], "percent", f"P(t > {e['threshold_ms']:g} ms) = k / n", e["n"])
                interval(add, f"{at}.cp95", e["cp95"], "percent", "exact two-sided Clopper-Pearson 95% interval, "
                         "independent samples assumed", e["n"], f"{at}.p")
                interval(add, f"{at}.wilson95", e["wilson95"], "percent", "Wilson 95% interval", e["n"], f"{at}.p")
                if "adjacent_pairs" in e:  # how the calls above the threshold lie in the series, and two attempts
                    d = f"{e['threshold_ms']:g} ms"
                    add(f"{at}.adjacent_pairs.k", e["adjacent_pairs"], "count", f"pairs of consecutive calls (in the order of seq) "
                        f"that are both above {d}", e["n"] - 1)
                    add(f"{at}.adjacent_pairs_if_independent", e["adjacent_pairs_if_independent"], "1", "number of such pairs "
                        f"expected if the calls were independent: (n - 1) x (k / n)^2, with k the calls above {d}; to set "
                        "beside adjacent_pairs.k", e["n"] - 1)
                    add(f"{at}.p_squared_estimate", e["p_squared"], "percent", f"(k / n)^2, the square of the share above {d}: "
                        "an estimate of the share of signatures above it if two independent signing attempts ran side by "
                        "side and the first to finish were taken; it assumes that the two attempts are independent and "
                        "each has the measured share, and that running two does not slow either; not a measurement", e["n"])

    def paired(base, source, ops, warmup, floor, scope):
        """Within-launch results of one paired file, or of the pooled pairs of a launch set."""
        # in mode aa the csm_ns column holds a second standalone call: the same pair measured twice
        b = "second standalone call (noise floor, mode=aa)" if floor else "csm"
        for o in ops:
            n = o["n_pairs"]
            add = emitter(f"{base}.{o['op']}", source, "overhead_paired",
                          f"op={o['op']}, seq>={warmup}, {scope}" + (", mode=aa" if floor else ""))
            add("n_pairs", n, "count", "pairs after warm-up", n)
            add("n_dropped", o["n_warmup_dropped"], "count", "warm-up pairs dropped", n + o["n_warmup_dropped"])
            few = scarce("p50", n)  # a median is the 50th percentile: the rule of scarce() applies
            time(add, "median_standalone", o["median_standalone_us"], "median standalone time", n, why=few)
            time(add, "median_csm", o["median_csm_us"], f"median time of the csm_ns column: {b}", n, why=few)
            time(add, "median_diff", o["median_diff_us"], f"median of paired differences {b} - standalone", n, signed=True,
                 why=few)
            add("median_ratio_diff", o["median_ratio"] - 1, "percent", f"median of paired ratios {b} / standalone, minus 1",
                n, signed=True, why=few)
            hl = o["hl_paired"]
            how = f"paired Hodges-Lehmann estimate (median of Walsh averages) of {b} - standalone"
            time(add, "hl", hl["estimate_us"], how, n, signed=True)
            time_interval(add, "hl_ci95", hl["ci95_us"], how + ", 95% CI within launch (optimistic)", n, "hl", signed=True)
            add("wilcoxon_p", o["wilcoxon_p"], "p", "Wilcoxon signed-rank test, two-sided", n)
            t = o["tost_paired_log"]
            if t["margin"] is not None:  # an A/A file is not judged against the margin
                add("tost_margin", t["margin"], "percent", "pre-registered relative equivalence margin (equivalence_margin.txt)", n)
                add("tost_p", t["p"], "p", f"TOST on paired log-ratios against +/-{t['margin']:g}, within launch (optimistic)", n)
            how = f"geometric mean of the paired ratios {b} / standalone, minus 1"
            add("gm_ratio_diff", t["gm_ratio"] - 1, "percent", how, n, signed=True)
            interval(add, "gm_ratio_diff_ci90", [v - 1 for v in t["gm_ratio_ci"]], "percent",
                     how + ", 90% CI within launch (optimistic)", n, "gm_ratio_diff", signed=True)
            add("cliffs_delta", o["cliffs_delta"], "1", f"Cliff's delta, P({b} > standalone) - P({b} < standalone)", n,
                signed=True)
            e = o["order_effect"]
            add("order_n_ab", e["n_AB"], "count", "pairs with order AB (the standalone_ns column measured first)", n)
            add("order_n_ba", e["n_BA"], "count", "pairs with order BA (the csm_ns column measured first)", n)
            time(add, "order_median_diff_ab", e.get("median_diff_AB_us"), "median paired difference, AB pairs", e["n_AB"],
                 signed=True, why=scarce("p50", e["n_AB"]))
            time(add, "order_median_diff_ba", e.get("median_diff_BA_us"), "median paired difference, BA pairs", e["n_BA"],
                 signed=True, why=scarce("p50", e["n_BA"]))
            if hl := e.get("hl_shift_BA_minus_AB"):
                how = "two-sample Hodges-Lehmann shift of the paired differences, BA - AB"
                time(add, "order_hl", hl["estimate_us"], how, n, signed=True)
                time_interval(add, "order_hl_ci95", hl["ci95_us"], how + ", 95% CI", n, "order_hl", signed=True)
            add("order_p", e.get("mann_whitney_p"), "p", "Mann-Whitney test of AB against BA differences, two-sided", n)

    for f in results["overhead_paired"]:
        base = _dotted("overhead_paired", paired_label(f["source"], f.get("mode"), f.get("launch")))
        header(base, f, "overhead_paired")
        checks(base, f, "overhead_paired")
        scope = "one file" if f.get("launch") is None else f"launch {f['launch']}"
        paired(base, f["source"], f["ops"], f["warmup"], f.get("mode") == "aa", scope)

    for t in results.get("overhead_launch_sets", []):
        floor = t["mode"] == "aa"
        # the set takes the keys a single file in that directory would take: <dir>/overhead_paired.csv
        base = _dotted("overhead_paired", paired_label(f"{t['source']}/overhead_paired.csv", t["mode"]))
        paired(base, t["source"], t["pooled"], t["warmup"], floor, f"{t['n_launches']} launches pooled")
        b = "second standalone call (noise floor, mode=aa)" if floor else "csm"
        for a in t["across_launch"]:
            n = a["n_launches"]
            add = emitter(f"{base}.{a['op']}.across_launch", t["source"], "overhead_paired",
                          f"op={a['op']}, one value per launch" + (", mode=aa" if floor else ""))
            add("n_launches", n, "count", "valid launches in the set", n)
            add("n_invalid_launches", t["n_invalid_launches"], "count", "launches left out as invalid", n + t["n_invalid_launches"])
            h, how = a["hl_us"], f"per-launch paired Hodges-Lehmann estimates of {b} - standalone"
            time(add, "hl_mean", h["mean"], f"mean of the {how}", n, signed=True)
            time(add, "hl_sd", h["sd"], f"standard deviation of the {how}", n)
            time(add, "hl_min", h["min"], f"smallest of the {how}", n, signed=True)
            time(add, "hl_max", h["max"], f"largest of the {how}", n, signed=True)
            time_interval(add, "hl_t95", h["t95"], f"Student-t 95% interval of the mean of the {how}", n, "hl_mean", signed=True)
            time_interval(add, "hl_t90", h["t90"], f"Student-t 90% interval of the mean of the {how}", n, "hl_mean", signed=True)
            g, how = a["gm_ratio"], f"per-launch geometric-mean ratios {b} / standalone"
            add("gm_ratio_diff", g["mean"] - 1, "percent", f"geometric mean over launches of the {how}, minus 1", n, signed=True)
            add("gm_ratio_diff_min", g["min"] - 1, "percent", f"smallest of the {how}, minus 1", n, signed=True)
            add("gm_ratio_diff_max", g["max"] - 1, "percent", f"largest of the {how}, minus 1", n, signed=True)
            add("gm_ratio_log_sd", g["log_sd"], "1", f"standard deviation of the logarithms of the {how}", n)
            for level in ("t95", "t90"):
                if None not in g[level]:
                    interval(add, f"gm_ratio_diff_{level}", [v - 1 for v in g[level]], "percent",
                             f"Student-t {level[1:]}% interval (on the log scale) of that geometric mean, minus 1", n,
                             "gm_ratio_diff", signed=True)
            if a["tost"]:
                add("tost_margin", a["tost"]["margin"], "percent", "pre-registered relative equivalence margin", n)
                add("tost_p", a["tost"]["p"], "p", f"TOST on the launch-level log-ratios against +/-{a['tost']['margin']:g}", n)

    for f in results["overhead_unpaired"]:
        for o in f["ops"]:
            n = o["n_standalone"] + o["n_csm"]
            add = emitter(_dotted("overhead_unpaired", label("overhead_unpaired", f["source"]), o["op"]), f["source"],
                          "overhead_unpaired", f"op={o['op']}, seq>={o['warmup']}")
            add("n_standalone", o["n_standalone"], "count", "standalone samples after warm-up", o["n_standalone"])
            add("n_csm", o["n_csm"], "count", "Csm-integrated samples after warm-up", o["n_csm"])
            time(add, "median_standalone", o["median_standalone_us"], "median standalone time", o["n_standalone"],
                 why=scarce("p50", o["n_standalone"]))
            time(add, "median_csm", o["median_csm_us"], "median Csm-integrated time", o["n_csm"], why=scarce("p50", o["n_csm"]))
            seq = "; " + overhead.SEQUENTIAL
            add("median_rel_diff", o["median_rel_diff"], "percent", "median csm / median standalone, minus 1" + seq, n, signed=True,
                why=scarce("p50", min(o["n_standalone"], o["n_csm"])))
            add("mann_whitney_p", o["mann_whitney_p"], "p", "Mann-Whitney test, two-sided" + seq, n)
            hl = o["hl_shift"]
            how = "two-sample Hodges-Lehmann shift csm - standalone"
            time(add, "hl", hl["estimate_us"], how + seq, n, signed=True)
            time_interval(add, "hl_ci95", hl["ci95_us"], how + ", 95% CI" + seq, n, "hl", signed=True)
            add("cliffs_delta", o["cliffs_delta"], "1", "Cliff's delta, P(csm > standalone) - P(csm < standalone)" + seq, n, signed=True)
            for t in o["tost_log_post_hoc"]:
                m, late = f"tost_m{_g(100 * t['margin'])}pct", "; " + overhead.POST_HOC + seq
                add(f"{m}_p", t["p"], "p", "post hoc TOST (two one-sided Welch t-tests, the larger p) on log-times against "
                    f"+/-{t['margin']:g}" + late, n)
                how = "ratio of geometric means csm / standalone, minus 1"
                add(f"{m}_gm_ratio_diff", t["gm_ratio"] - 1, "percent", how + late, n, signed=True)
                interval(add, f"{m}_gm_ratio_diff_ci90", [v - 1 for v in t["gm_ratio_ci"]], "percent", how + ", 90% CI" + late, n,
                         f"{m}_gm_ratio_diff", signed=True)
            if boot := o.get("bootstrap"):  # the secondary analysis of the archived samples: dependence within a phase
                for arm, word in (("standalone", "standalone"), ("csm", "Csm-integrated")):
                    add(f"lag1_{arm}", o[f"lag1_{arm}"], "1", f"lag-1 autocorrelation of the {word} phase, its samples in the "
                        "order of seq after warm-up; " + overhead.WITHIN + seq, o[f"n_{arm}"], signed=True)
                interval(add, "median_rel_diff_bb90", boot["median_rel_diff_ci90"], "percent", "moving-block bootstrap 90% "
                         "interval (percentile method) of median csm / median standalone, minus 1: blocks of "
                         f"{boot['block_len']} consecutive samples resampled within each phase, {boot['n_boot']} resamples; "
                         + overhead.WITHIN + seq, n, "median_rel_diff", signed=True,
                         why=scarce("p50", min(o["n_standalone"], o["n_csm"])))

    for r in results["periodic"]:
        cid, n = config_id(r), r["jobs"]
        base = _dotted("periodic", file_label(r["source"]), cid)
        add = emitter(base, r["source"], "periodic", f"config={cid}")
        time(add, "period", r["period_us"], "period_ns of the file header", None)
        time(add, "deadline", r["deadline_us"], "deadline_ns of the file header", None)
        for name in ("streams", "cores", "payload_bytes"):
            add(name, r[name], "bytes" if name == "payload_bytes" else "count", f"{name} of the file header", None)
        time(add, "mf_period", r.get("mf_period_us"), "mf_period_us of the file header (main-function period)", None)
        add("partition", r.get("partition"), "id", "partition of the file header (index of the gateway process)", None)
        for name, how in (("jobs", "released jobs"), ("unfinished", "jobs with send_done_ns = 0"),
                          ("not_started", "jobs with start_ns = 0"), ("misses", "deadline misses"),
                          ("longest_miss_run", "longest run of consecutive misses, worst stream")):
            add(name, r[name], "count", how, n)
        for k, v in r["max_misses_in_window"].items():
            add(f"max_misses_in_{k}", v, "count", f"most misses in any {k} consecutive jobs, worst stream", n)
        for k in csvio.TRANSPORT_COUNTS:  # a count that was not given (-1 or no line) has no key
            add(k, (r.get("transport") or {}).get(k), "count", csvio.TRANSPORT_WHAT[k] + " (TCP_INFO at the end minus at the first "
                "release)", None)
        add("miss_ratio", r["miss_ratio"], "percent", "misses / jobs", n)
        interval(add, "miss_cp95", r["miss_cp95"], "percent", "exact two-sided Clopper-Pearson 95% interval of the miss "
                 "ratio; exact for independent jobs, too narrow when misses come in bursts", n, "miss_ratio")
        interval(add, "miss_wilson95", r["miss_wilson95"], "percent", "Wilson 95% interval of the miss ratio", n, "miss_ratio")
        for q, what in (("response", "send_done - release, finished jobs"), ("queueing", "start - release, started jobs"),
                        ("auth", "auth_done - start"), ("service", "send_done - start, finished jobs")):
            described(add, f"{q}_", r[f"{q}_us"], what)
        add("auth_utilisation", r.get("auth_utilisation"), "percent", "measured utilisation of the sender process by the "
            "authentication: the time covered by the intervals from start_ns to auth_done_ns of the jobs of all streams of "
            "the file, divided by the time from the first release_ns to the last send_done_ns of the file; covered time, not "
            "the sum of the lengths, because the jobs of the streams of one cycle start together and are authenticated one "
            "after the other", (r.get("auth_us") or {}).get("n"))
        if m := r.get("model"):
            how = f"queue model, service times from {m['service_source']}"
            add("model_utilisation", m["utilisation"], "percent", "streams x mean service / (cores x period)", m["jobs_per_run"])
            add("model_measured_offsets", m["measured_offsets"]["mean"], "percent", how + ", measured release offsets",
                m["measured_offsets"]["jobs_per_run"])
            for stat in ("mean", "min", "max"):
                add(f"model_random_{stat}", m["random_offsets"][stat], "percent",
                    f"{how}, {stat} over {m['random_offsets']['draws']} random-offset draws", m["jobs_per_run"])
            add("model_synchronous", m["synchronous"]["mean"], "percent", how + ", synchronous release", m["jobs_per_run"])
        for ps in r["per_stream"]:
            add_s = emitter(f"{base}.s{ps['stream']}", r["source"], "periodic", f"config={cid}, stream={ps['stream']}")
            add_s("jobs", ps["jobs"], "count", "released jobs", ps["jobs"])
            add_s("misses", ps["misses"], "count", "deadline misses", ps["jobs"])
            add_s("longest_miss_run", ps["longest_miss_run"], "count", "longest run of consecutive misses", ps["jobs"])
            for k, v in ps["max_misses_in_window"].items():
                add_s(f"max_misses_in_{k}", v, "count", f"most misses in any {k} consecutive jobs", ps["jobs"])
        if x := r.get("rx"):
            add = emitter(base, x["source"], "periodic_rx", f"config={cid}")
            for name, field, how in (("rx_delivered", "delivered", "Tx jobs with an ok Rx row"),
                                     ("rx_lost", "lost", "Tx jobs with no Rx row"),
                                     ("rx_duplicates", "duplicates", "Rx rows beyond the first per job"),
                                     ("rx_out_of_order", "out_of_order", "Rx rows overtaken by a later seq"),
                                     ("rx_not_in_tx", "rx_not_in_tx", "Rx rows of jobs the sender never logged")):
                add(name, x[field], "count", how, x["tx_jobs"])
            add("rx_rows", x["rx_rows"], "count", "rows of the Rx file", x["rx_rows"])
            add("rx_delivery_ratio", x["delivery_ratio"], "percent", "delivered / Tx jobs", x["tx_jobs"])
            for res, c in x["by_result"].items():
                add(f"rx_result_{res}", c, "count", f"Rx rows with result {res}", x["rx_rows"])
            described(add, "rx_verify_", x["verify_us"], "verify_done - rx_done, ok rows")
            described(add, "rx_deliver_", x["deliver_us"], "deliver - rx_done, ok rows")
            for cls, d in x["reject_us"].items():
                described(add, f"rx_reject_{cls}_", d, f"verify_done - rx_done (reject decision), {cls} rows")
            if lat := x["latency"]:
                add = emitter(base, x["source"], "periodic_rx", f"config={cid}, clock={lat['clock_source']}")
                described(add, "latency_", lat["one_way_us"], "rx_done on the Tx clock - send_done, first ok arrival")
                described(add, "end_to_end_", lat["end_to_end_us"], "deliver on the Tx clock - release, first ok arrival")
                time(add, "clock_rtt_max", lat["clock_rtt_max_us"], "largest probe round trip (twice the offset uncertainty)",
                     lat["clock_samples"])
                time(add, "clock_rtt_median", lat["clock_rtt_median_us"], "median probe round trip", lat["clock_samples"],
                     why=scarce("p50", lat["clock_samples"]))
                add("clock_probes", lat["clock_samples"], "count", "rows of clock_offset.csv", lat["clock_samples"])
                add("clock_outside_span", lat["outside_clock_span"], "count",
                    "delivered jobs received before the first or after the last probe", lat["one_way_us"]["n"])
            for ps in x["per_stream"]:
                add_s = emitter(f"{base}.s{ps['stream']}", x["source"], "periodic_rx", f"config={cid}, stream={ps['stream']}")
                add_s("rx_delivered", ps["delivered"], "count", "Tx jobs with an ok Rx row", ps["tx_jobs"])
                add_s("rx_lost", ps["lost"], "count", "Tx jobs with no Rx row", ps["tx_jobs"])
                for res, c in ps["by_result"].items():
                    add_s(f"rx_result_{res}", c, "count", f"Rx rows with result {res}", sum(ps["by_result"].values()))

    def e2e_keys(base, e, where, release, reception, received, profiles=None):
        """E9, end-to-end latency across the two boards on their raw clocks (E9_SPEC.md, Addendum E; key names: E10):
        the keys under <base>.e2e. `release` and `reception` are the columns that stand for the release and the
        reception (the harness: release_ns and rx_done_ns; the gateway binaries: submit_ns and verify_done_ns)."""
        n = e["n"]
        add = emitter(base + ".e2e", e["source"], "e2e", where + ", clock probe")
        theta = ("every time stamp is first carried from CLOCK_MONOTONIC onto the raw clock of its board (CLOCK_MONOTONIC_RAW, "
                 "not steered by the time-synchronisation service) with that board's clock map; theta(t) is the offset of the "
                 "receiving board's raw clock against the sending board's at the time t of the sending board's raw clock, "
                 "interpolated between the anchors of clock_probe.csv (in every 5 s the two-way exchange with the smallest "
                 "delay); bound_total_us says how well the measurement certifies the result")
        add("n", n, "count", "delivered PDUs: rows of the receiver's file with result ok, joined with the sender's rows on "
            "stream and seq", n)
        for group, name, what in (("latency_ms", "latency", "end-to-end latency, release on the sending board to delivery to "
                                   f"the application on the receiving board: deliver_ns - theta({release}) - {release}; "),
                                  ("rxpart_ms", "rxpart", "transfer and receive part: deliver_ns - theta(send_done_ns) - "
                                   "send_done_ns; ")):
            for stat, v in e[group].items():
                add(f"{name}_{STATS[stat]}_ms", v, "ms", f"{stat} of the " + what + theta
                    + (", type-7 percentile" if stat[0] == "p" else ""), n, why=scarce(stat, n))
        probes = e["probes_completed"]
        add("offset_bound_us", e["offset_bound_us"], "us", "bound of the offset measurement at the anchors: the largest "
            "delta / 2 among the anchors from the second to the second-to-last one (the first and the last anchor only "
            "delimit), delta = (t4 - t1) - (t3 - t2) being the round-trip delay of an exchange on its raw stamps; the true offset "
            "lies within theta +- delta / 2 whatever the asymmetry of the two directions; between the anchors see "
            "offset_cert_us", e["anchors"], decimals=1)
        add("offset_cert_us", e["offset_cert_us"], "us", "certified bound of the offset track between the anchors: every "
            "completed exchange between the second and the second-to-last anchor certifies the track within |track - theta| "
            "+ delta / 2 at its instant (the true offset lies within delta / 2 of its theta); this is the smallest T such "
            "that the exchanges certifying within T, with the two ends of that region, are nowhere more than 2,000 ms apart",
            probes, decimals=1)
        add("offset_bound_total_us", e["offset_bound_total_us"], "us", "the larger of offset_bound_us and offset_cert_us: at "
            "instants no more than 2 s apart the probe certifies the estimate of the offset between the two raw clocks to "
            "within this; it is not a bound for every instant; one of the three terms of bound_total_us", probes, decimals=1)
        add("exchanges_outside", e["exchanges_outside"], "count", "completed exchanges between the second and the "
            "second-to-last anchor whose own offset is further from the track than half their delay plus "
            "offset_bound_total_us; a run with one is not a result, so this is 0", probes)
        add("anchors", e["anchors"], "count", "anchors of the offset track: windows of 5 s of the sending board's clock from "
            "the first exchange, in each the exchange with the smallest delay (the earliest on a tie)", probes)
        add("probes_completed", probes, "count", "completed exchanges: rows of clock_probe.csv", probes)
        add("probe_delay_min_us", e["probe_delay_min_us"], "us", "smallest round-trip delay delta of all completed exchanges", probes)
        add("probe_delay_p50_us", e["probe_delay_p50_us"], "us", "median round-trip delay delta of all completed exchanges, "
            "type-7 percentile", probes, why=scarce("p50", probes))
        add("probe_gap_max_ms", e["probe_gap_max_ms"], "ms", "largest time between two consecutive completed exchanges, by "
            "their time tau = (t1 + t4) / 2 on the sending board's clock", probes)
        add("drift_ppm", e["drift_ppm"], "1", "slope of the anchors' offset theta over their time tau, least squares, in "
            "parts per million; positive: the receiving board's clock runs faster; informational", e["anchors"], signed=True)
        add("causality_min_us", e["causality_min_us"], "us", f"smallest causality margin of a delivered PDU: {reception} - "
            f"theta(send_done_ns) - send_done_ns, {received} after the send; " + theta, n, signed=True)
        add("causality_violations", e["causality_violations"], "count", "delivered PDUs whose causality margin is below "
            "minus bound_total_us; a run with one is not a result, so this is 0", n)
        add("bound_total_us", e["bound_total_us"], "us", "offset_bound_total_us + map_a.bound_us + map_b.bound_us: at instants "
            "no more than 2 s apart the measurement certifies the latencies to within this (the offset between the raw "
            "clocks; the two map terms bound the conversion of the time stamps in every interval between two samples of "
            "the map); it is not a bound for every instant", probes, decimals=1)
        add("probe_format", e["probe_format"], "count", "format of the probe file: 2, with the raw stamps of every exchange",
            probes)
        add("probe_width_p50_ns", e["probe_width_p50_ns"], "ns", "median width of the stamp points of all exchanges (four per "
            "exchange): the distance between the two raw reads around the monotonic read of a point, type-7 percentile",
            4 * probes, why=scarce("p50", 4 * probes), decimals=0)
        add("probe_width_max_ns", e["probe_width_max_ns"], "ns", "largest width of a stamp point of all exchanges", 4 * probes,
            decimals=0)
        used = "the range of the map that the time stamps of the run use (from the last valid sample at or before the " \
               "earliest one to the first valid sample at or after the latest one)"
        for x in "ab":
            which = f"board {x.upper()}, the {'sending' if x == 'a' else 'receiving'} one"
            source = "/".join(e["source"].split("/")[:-1] + [f"clock_map_{x}.csv"])
            m, c = e["map"][x], e["clock"][x]
            add = emitter(f"{base}.e2e.map_{x}", source, "e2e", f"{where}, clock map of {which}")
            add("samples", m["samples"], "count", f"samples of the clock map of {which}: rows of clock_map_{x}.csv, one "
                "reading RAW, MONOTONIC, RAW of the board's two clocks every 5 ms", m["samples"])
            add("samples_invalid", m["samples_invalid"], "count", "samples that are not valid: their two raw reads lie more "
                "than 5,000 ns apart (interrupted between the reads) or the wrong way round; they are not used", m["samples"])
            add("gap_max_ms", m["gap_max_ms"], "ms", "largest distance between two consecutive valid samples in " + used
                + "; above 50 ms a run is not a result", m["samples"])
            add("holdout_us", m["holdout_us"], "us", "hold-out bound of the map: the largest distance of a valid sample from "
                "the straight line through its two neighbours in the file (both valid), over the samples in " + used
                + "; m = monotonic read - mean of the two raw reads", m["samples"], decimals=1)
            add("kink_us", m["kink_us"], "us", "kink term of the map: for every interval between two consecutive valid samples "
                "in " + used + ", |slope of m after the interval - slope before it| x the interval's length / 4, the most a "
                "single change of rate inside that interval can put the straight line off; each slope read over the nearest "
                "samples at least 4 ms away; the largest of these (the hold-out covers such a change only where the samples "
                "are evenly spaced)", m["samples"], decimals=1)
            add("half_us", m["half_us"], "us", "largest half width of a valid sample (half the distance of its two raw reads) "
                "in " + used, m["samples"], decimals=1)
            add("bound_us", m["bound_us"], "us", f"bound of the map of {which}: the larger of holdout_us and kink_us, plus "
                "half_us; one of the three terms of bound_total_us", m["samples"], decimals=1)
            add("check_n", m["check_n"], "count", "check points of the map: the stamp points of the exchanges on this board "
                "(each reads the same relation of the two clocks, in another thread at another instant) that are no wider "
                "than 5,000 ns and lie in " + used, m["check_n"])
            add("check_max_us", m["check_max_us"], "us", "largest distance of a check point from the map: |its monotonic read - "
                "the mean of its two raw reads - m(its monotonic read)|", m["check_n"], decimals=1)
            add("check_violations", m["check_violations"], "count", "check points further from the map than bound_us plus half "
                "their width; a run with one is not a result, so this is 0", m["check_n"])
            add = emitter(f"{base}.e2e.clock_{x}", source, "e2e", f"{where}, clocks of {which}")
            rate = (f"rate of CLOCK_MONOTONIC against the raw clock on {which}, over windows of 1 s of the map's valid samples "
                    "(a window needs samples at least 0.8 s apart): (m_last - m_first) / (monotonic_last - monotonic_first), "
                    "positive when CLOCK_MONOTONIC runs faster; these keys say which board's clock was steered")
            for name, what in (("min", "smallest"), ("max", "largest"), ("median", "median")):
                add(f"adj_ppm_{name}", c[f"adj_ppm_{name}"], "ppm", f"{what} " + rate, m["samples"], signed=True, decimals=2)
            add("adj_step_ppm_max", c["adj_step_ppm_max"], "ppm", "largest absolute difference between the rates of two "
                "windows that follow each other; " + rate, m["samples"], decimals=2)
            add("adj_offset_range_us", c["adj_offset_range_us"], "us", "largest minus smallest m = monotonic read - mean of the "
                f"two raw reads over the valid samples of the map of {which}: what CLOCK_MONOTONIC moved against the raw "
                "clock during the run", m["samples"])
            add("adjusted", c["adjusted"], "count", f"1 when the correction of CLOCK_MONOTONIC on {which} changed by more "
                "than 1 ppm during the run (adj_ppm_max - adj_ppm_min above 1), else 0; it says not whether a correction "
                "exists: a clock at a constant -1.8 ppm against its raw clock has 0 here and adj_ppm_median -1.8", m["samples"])
        add = emitter(f"{base}.e2e.mono", e["source"], "e2e", where + ", clock probe, monotonic columns")
        diagnostic = ("diagnostic of Addendum E, never printed in a document as a result: what the earlier definitions (the "
                      "FINAL ruling on the monotonic columns of the probe file, no maps) make of the same run")
        add("verdict", e["mono"]["verdict"], "count", "1 when the earlier definitions on the monotonic columns would call "
            "the run a result, else 0", probes, why=diagnostic)
        add("offset_bound_total_us", e["mono"]["offset_bound_total_us"], "us", "offset_bound_total_us of the track on the "
            "monotonic columns", probes, why=diagnostic, decimals=1)
        add("latency_p50_diff_us", e["mono"]["latency_p50_diff_us"], "us", "median latency by the monotonic columns minus "
            "latency_p50 of this run; present only when mono.verdict is 1", n, signed=True, why=diagnostic)
        for ps in e.get("per_stream", []):  # a file with more than one stream: each stream beside the figures over all
            k = ps["stream"]
            add = emitter(f"{base}.e2e.stream{k}", e["source"], "e2e", f"{where}, stream={k}, clock probe")
            add("n", ps["n"], "count", f"delivered PDUs of stream {k}: rows of the receiver's file with result ok and this "
                "stream, joined with the sender's rows on stream and seq", ps["n"])
            for stat, v in (ps["latency_ms"] or {}).items():
                add(f"latency_{STATS[stat]}_ms", v, "ms", f"{stat} of the end-to-end latency of the PDUs of stream {k}: "
                    f"deliver_ns - theta({release}) - {release}; " + theta + (", type-7 percentile" if stat[0] == "p" else ""),
                    ps["n"], why=scarce(stat, ps["n"]))
            if profiles and k.isdigit() and int(k) < len(profiles):
                add("profile", profiles[int(k)], "text", f"the variant of stream {k}: its entry in the '# stream_profiles=' line "
                    "of the sender's file, which says profile=both", None)

    for r in results["periodic"]:
        if bg := r.get("bg"):  # the unrelated flow on the link during the run (E9, cell i): the driver's record
            cid = config_id(r)
            add = emitter(_dotted("periodic", file_label(r["source"]), cid) + ".bg", bg["source"], "periodic",
                          f"config={cid}, unrelated flow")
            flow = "of the unrelated TCP flow that ran on the link during the run (the driver's record)"
            add("rate_offered_mbit_s", bg["rate_offered_mbit_s"], "Mbit/s", "rate_offered_bit_s / 1e6: the rate asked " + flow, None)
            add("rate_achieved_mbit_s", bg["rate_achieved_mbit_s"], "Mbit/s", "rate_achieved_bit_s / 1e6: bytes sent times 8 over "
                "the source's duration, " + flow, None)
            add("bytes_sent", bg["bytes_sent"], "bytes", "bytes the source sent, " + flow, None)
            add("bytes_received", bg["bytes_received"], "bytes", "bytes the sink received, " + flow, None)
            add("verdict", bg["verdict"], "text", "the driver's verdict on the flow, PASS or FAIL (FAIL: achieved below 95% of "
                "offered, nothing received or more than sent, or the flow did not cover the PDUs); taken from the record, not "
                "recomputed; with FAIL the e2e keys of the run are not a result", None)
        if e := r.get("e2e"):
            cid = config_id(r)
            e2e_keys(_dotted("periodic", file_label(r["source"]), cid), e, f"config={cid}", "release_ns", "rx_done_ns", "reception",
                     r.get("stream_profiles"))
    for t in results.get("functional", []):  # cell g: the gateway binaries, which record no reception time
        if e := t.get("e2e"):
            e2e_keys(_dotted("functional", "" if t["source"] == "." else PurePosixPath(t["source"]).name), e,
                     f"profile={t['profile']}, gateway binaries", "submit_ns", "verify_done_ns",
                     "verification (the gateway records no reception time)")

    for c in results.get("periodic_cells", []):
        if c["missing_partitions"]:
            continue  # a partition is not on file or invalid: nothing was combined
        cid = config_id({**c, "partition": None}) + f"-parts{c['partitions']}"  # streams and cores are the sums
        n, what = c["jobs"], f"added over the {c['partitions']} partitions (independent processes) of the cell"
        cores = f"cores of the cell, {what}"
        if c["cores"] < c["partitions"]:  # E9_SPEC.md, H4: sender processes pinned to one core are not independent of each other
            what = f"added over the {c['partitions']} sender processes of the cell, which share a core"
            cores = (f"distinct cores of the cell's {c['partitions']} sender processes (the distinct values of the cpu_affinity "
                     "line of their files): the processes share a core")
        add = emitter(_dotted("periodic", c["label"], cid), c["source"], "periodic", f"cell={cid}")
        for name in ("partitions", "streams", "cores"):
            add(name, c[name], "count", cores if name == "cores" else f"{name} of the cell" + ("" if name == "partitions" else ", " + what), None)
        add("jobs", n, "count", "released jobs, " + what, n)
        add("auth_utilisation", c.get("auth_utilisation"), "percent", "measured utilisation of the shared core by the "
            "authentication: the time covered by the union of the intervals from start_ns to auth_done_ns of the jobs of all "
            "sender processes of the cell, which are pinned to one core, divided by the time from the smallest release_ns to "
            "the largest send_done_ns over all its files; the union over the processes, not a sum of their shares; only "
            "when every process recorded the end of the authentication and finished a job", n)
        add("misses", c["misses"], "count", "deadline misses, " + what, n)
        add("miss_ratio", c["miss_ratio"], "percent", "misses / jobs, " + what, n)
        interval(add, "miss_cp95", c["miss_cp95"], "percent", "exact two-sided Clopper-Pearson 95% interval of that miss "
                 "ratio; exact for independent jobs, too narrow when misses come in bursts", n, "miss_ratio")
        if q := c.get("no_retrans"):  # the sensitivity figure: beside the one over all partitions, never instead of it
            how = ("sensitivity, over the partitions whose transmitter reports no retransmitted segment in the measured window "
                   "(never instead of the figure over all partitions): ")
            add = emitter(_dotted("periodic", c["label"], cid) + ".no_retrans", c["source"], "periodic", f"cell={cid}")
            add("partitions", q["partitions"], "count", how + "partitions that remain", None)
            add("left_out_retransmitted", q["left_out_retransmitted"], "count", "partitions left out: a retransmitted segment in "
                "the measured window", None)
            add("left_out_unknown", q["left_out_unknown"], "count", "partitions left out: the count was not given, which is not "
                "zero", None)
            add("streams", q["streams"], "count", how + "streams", None)
            add("jobs", q["jobs"], "count", how + "released jobs", q["jobs"])
            add("misses", q["misses"], "count", how + "deadline misses", q["jobs"])
            add("miss_ratio", q["miss_ratio"], "percent", how + "misses / jobs", q["jobs"])
            interval(add, "miss_cp95", q["miss_cp95"] or (None, None), "percent", how + "exact two-sided Clopper-Pearson 95% "
                     "interval of that miss ratio", q["jobs"], "miss_ratio")

    CLAMPED = ("loss_ratio", "tx_drop_ratio", "tx_cpu_util", "rx_cpu_util")  # proportions: throughput._across clamps their interval to [0, 1]
    across = (("delivered_pps", "PDU/s", "delivered PDU/s (rx host)", False),
              ("loss_ratio", "percent", "loss ratio (share of the offered PDUs " + throughput.NOT_DELIVERED + ")", False),
              ("tx_drop_ratio", "percent", "share of the offered PDUs dropped at release, to read beside the loss ratio: "
               + throughput.DROPPED, False),
              ("tx_cpu_util", "percent", "CPU utilisation of the tx host", False),
              ("rx_cpu_util", "percent", "CPU utilisation of the rx host", False),
              ("tx_proc_cpu_share", "percent", "tx host's " + throughput.PROC_CPU, False),
              ("rx_proc_cpu_share", "percent", "rx host's " + throughput.PROC_CPU, False),
              ("wire_mbit_s", "Mbit/s", "wire rate of the tx host", False),
              ("sendq_mean_bytes", "bytes", "mean send-queue depth", False),
              ("sendq_max_bytes", "bytes", "largest send-queue depth", False),
              ("sendq_slope_bytes_per_s", "bytes/s", "send-queue slope", True),
              ("sendq_growth_bytes", "bytes", "growth of the send queue over the window (its fitted slope times the length of "
               "the window; with several partitions added over their connections)", True))
    for t in results["throughput"]:
        lid = ladder_id(t)
        sat = t["saturation"]
        add = emitter(f"throughput.{lid}", t["source"], "throughput", f"ladder={lid}")
        add("saturation_pps", sat["saturation_pps"], "PDU/s", "highest offered rate such that it and every lower step are "
            "sustained: " + sat["criterion"], len(sat["steps"]))
        add("non_monotone_steps", len(sat["non_monotone"]), "count", "sustained steps above the first step that is not "
            "sustained or not judged; they do not count for the saturation point", len(sat["steps"]))
        add("loss_max", sat["loss_max"], "percent", "largest loss ratio (share of the offered PDUs not delivered inside the "
            "window) at which a repetition still sustains its rate", None)
        add("cores", t["cores"], "count", "cores of the file header, added over the partitions", None)
        add("partitions", t["partitions"], "count", "gateway processes (file pairs) per rate step", None)
        quiet = sat["no_retrans"] if sat["no_retrans"]["files_known"] else None  # no second line when no file gives the count
        if quiet:  # the sensitivity line: beside the figures over all repetitions, never instead of them
            add = emitter(f"throughput.{lid}.no_retrans", t["source"], "throughput", f"ladder={lid}, repetitions without a "
                          "retransmitted segment")
            add("saturation_pps", quiet["saturation_pps"], "PDU/s", "sensitivity: the saturation point over "
                + quiet["criterion"], len(quiet["steps"]))
            add("reps_left_out", quiet["reps_left_out"], "count", "repetitions the sensitivity line leaves out", None)
            add("files_with_retrans", quiet["files_with_retrans"], "count", "transmitter files with a retransmitted segment in "
                "the measured window", None)
            add("files_unknown", quiet["files_unknown"], "count", "transmitter files that do not give the count (or are "
                "missing)", None)
            add = emitter(f"throughput.{lid}", t["source"], "throughput", f"ladder={lid}")

        def step_key(offered, rep):
            return f"throughput.{lid}.r{_g(offered)}" + ("" if rep is None else f".rep{rep}")

        for st in sat["steps"]:
            where = f"ladder={lid}, offered={st['offered_pps']:g} PDU/s"
            add = emitter(step_key(st["offered_pps"], None), t["source"], "throughput", where + ", one value per repetition")
            add("n_reps", st["n_reps"], "count", "repetitions of the rate step", st["n_reps"])
            add("judged_reps", st["judged_reps"], "count", "repetitions with both hosts' files, so that they can be judged",
                st["n_reps"])
            add("sustained_reps", st["sustained_reps"], "count", "repetitions that sustained the rate: " + sat["criterion"],
                st["n_reps"])
            for q_step in (quiet["steps"] if quiet else ()):  # the same delivery figures without a retransmitted segment
                if q_step["offered_pps"] == st["offered_pps"]:
                    how = "sensitivity, over the repetitions without a retransmitted segment (never instead of the figure over all): "
                    add_q = emitter(step_key(st["offered_pps"], None) + ".no_retrans", t["source"], "throughput",
                                    where + ", repetitions without a retransmitted segment")
                    add_q("n_reps", q_step["n_reps"], "count", how + "repetitions of the rate step", q_step["n_reps"])
                    add_q("judged_reps", q_step["judged_reps"], "count", how + "repetitions that can be judged", q_step["n_reps"])
                    add_q("sustained_reps", q_step["sustained_reps"], "count", how + "repetitions that sustained the rate",
                          q_step["n_reps"])
                    for q, unit, what, sign in across[:2]:  # delivered PDU/s and loss ratio
                        if a := q_step["across"][q]:
                            add_q(f"{q}_mean", a["mean"], unit, how + f"mean of the {what}", a["n"], signed=sign)
                            interval(add_q, f"{q}_t95", a["t95"], unit, how + "Student-t 95% interval of that mean"
                                     + (", bounds clamped to the range of a proportion" if q in CLAMPED else ""), a["n"], f"{q}_mean", sign)
                            for end, word in (("min", "smallest"), ("max", "largest")):
                                add_q(f"{q}_{end}", a[end], unit, how + f"{word} repetition value of the {what}", a["n"], f"{q}_mean", sign)
            for q, unit, what, sign in across:
                if a := st["across"][q]:
                    why = throughput.CPU_NOT_QUOTED if q.endswith("cpu_util") else None  # in numbers.csv, no macro
                    add(f"{q}_mean", a["mean"], unit, f"mean over the repetitions of the {what}", a["n"], signed=sign, why=why)
                    interval(add, f"{q}_t95", a["t95"], unit, "Student-t 95% interval of that mean over the repetitions"
                             + (", bounds clamped to the range of a proportion" if q in CLAMPED else ""), a["n"],
                             f"{q}_mean", sign, why=why)
                    for end, word in (("min", "smallest"), ("max", "largest")):
                        add(f"{q}_{end}", a[end], unit, f"{word} repetition value of the {what}", a["n"], f"{q}_mean", sign, why)
            if pooled := st["pooled_loss"]:
                n, how = pooled["offered_pdus"], f"secondary: added over the {pooled['reps']} judged repetition(s) of the step"
                add("offered_pdus_pooled", n, "count", "PDUs offered, " + how, n)
                add("lost_pdus_pooled", pooled["lost_pdus"], "count", "PDUs not delivered inside the window, " + how, n)
                add("loss_pooled", pooled["loss_ratio"], "percent", "PDUs not delivered inside the window / offered PDUs, " + how, n)
                interval(add, "loss_pooled_cp95", pooled["loss_cp95"], "percent", "exact two-sided Clopper-Pearson 95% interval "
                         "of the pooled proportion; " + how + ", ignores the variation between repetitions", n, "loss_pooled")
            for r in st["reps"]:
                n = r["offered_pdus"]
                add = emitter(step_key(st["offered_pps"], r["rep"]), " + ".join(r["files"]) or t["source"], "throughput",
                              where + ("" if r["rep"] is None else f", repetition {r['rep']}"))
                add("offered_pdus", n, "count", "PDUs the generator released in the steady-state window (sent + dropped at "
                    "release, tx host)", n)
                add("lost_pdus", r["lost_pdus"], "count", "offered PDUs " + throughput.NOT_DELIVERED + " (offered - delivered, "
                    "same samples on both hosts)", n)
                add("dropped_pdus", r["dropped_pdus"], "count", throughput.DROPPED, n)
                add("loss_ratio", r["loss_ratio"], "percent", "share of the offered PDUs " + throughput.NOT_DELIVERED
                    + "; an end-to-end figure, not PDUs lost by the stack or by the network", n)
                interval(add, "loss_cp95", r["loss_cp95"] or (None, None), "percent",
                         "exact two-sided Clopper-Pearson 95% interval of the loss ratio", n, "loss_ratio")
        for r in t["rows"]:
            n = r["intervals"]
            add = emitter(f"{step_key(r['offered_pps'], r['rep'])}.{r['role']}", r["file"], "throughput",
                          f"ladder={lid}, offered={r['offered_pps']:g} PDU/s, host={r['host']}"
                          + ("" if r["rep"] is None else f", repetition {r['rep']}"))
            add("intervals", n, "count", "one-second intervals in the steady-state window", n)
            add("window_s", r["window_s"], "s", "length of the steady-state window", n)
            add("pps_mean", r["pps_mean"], "PDU/s", "mean of the per-second PDU rates, steady-state window", n)
            interval(add, "pps_t95", r["pps_ci95"], "PDU/s", "Student-t 95% CI of that mean", n, "pps_mean")
            add("cpu_util", r["cpu_util"], "percent", "busy / total jiffies of the pinned cores", n, why=throughput.CPU_NOT_QUOTED)
            add("proc_cpu_share", r["proc_cpu_share"], "percent", throughput.PROC_CPU, n)
            add("wire_mbit_s", r["wire_mbit_s"], "Mbit/s", "interface bytes in the host's data direction", n)
            add("tx_mbit_s", r["tx_mbit_s"], "Mbit/s", "interface bytes sent by this host", n)
            add("rx_mbit_s", r["rx_mbit_s"], "Mbit/s", "interface bytes received by this host", n)
            add("wire_bytes_per_pdu", r["wire_bytes_per_pdu"], "bytes/PDU", "interface bytes / PDUs", n)
            add("sendq_mean_bytes", r["sendq_mean_bytes"], "bytes", "mean send-queue depth", n + 1)
            add("sendq_max_bytes", r["sendq_max_bytes"], "bytes", "largest send-queue depth", n + 1)
            add("sendq_slope_bytes_per_s", r["sendq_slope_bytes_per_s"], "bytes/s", "least-squares slope of the send-queue depth",
                n + 1, signed=True)
            if r["role"] == "tx":
                add("sendq_growth_bytes", r.get("sendq_growth_bytes"), "bytes", "growth of the send queue over the "
                    "steady-state window: the least-squares slope of its depth times the length of the window (with several "
                    "partitions: each connection's, added)", n + 1, signed=True)
            add("sendq_slope_lo95_onesided_bytes_per_s", r["sendq_slope_lower95"], "bytes/s",
                "one-sided 95% lower bound of that slope (none for a queue whose depth never changes, none for a sum of "
                "partitions)", n + 1, "sendq_slope_bytes_per_s", True)
            if r["role"] == "tx":  # what the queue verdict compares; a receiver's send queue is not judged
                add("sendq_growth_lo95_bytes", r["sendq_growth_lower95_bytes"], "bytes", "that lower bound times the length "
                    "of the window: the growth of the send queue over the window that the fit supports (0 for a queue whose "
                    "depth never changes; for several partitions the largest of their bounds); the queue counts as growing "
                    "when this is at least queued_bytes_per_pdu", n + 1, signed=True)
                add("queued_bytes_per_pdu", r["queued_bytes_per_pdu"], "bytes/PDU", throughput.QUEUED_PDU, n)
            add("cpu_one_tick_clamps.k", r["cpu_one_tick_clamps"], "count", "sample steps of the file(s) in which the busy "
                "jiffies grew by one tick more than the total jiffies; such a step counts as fully busy (rounding of the "
                "kernel's idle and iowait ticks); reported, not judged", r["cpu_steps"])
            add("drops", r["drops"], "count", "the sampler's drops column on this host: releases the generator dropped at a full "
                "queue (tx host), PDUs the receiver rejected (rx host)", n)
            add("drop_ratio", r["drop_ratio"], "percent", "drops / (done + drops) on this host alone", n)
            for k in csvio.TRANSPORT_COUNTS:  # of the tx host; a count that was not given has no key
                add(k, r[k], "count", csvio.TRANSPORT_WHAT[k] + " (TCP_INFO at the end minus at the first release)", None)
            add("partitions", r["partitions"], "count", "partitions (gateway processes) added up in this row", None)

    for f in results["attack"]:
        for v in f["vectors"]:
            n = v["n"]
            base = _dotted("attack", label("attack", f["source"]), v["vector"])
            add = emitter(base, f["source"], "attack", f"vector={v['vector']}")
            add("n", n, "count", "injected PDUs", n)
            add("delivered", v["delivered"], "count", "PDUs that reached the application", n)
            add("rejected", v["rejected"], "count", "PDUs with reject_stage != none", n)
            add("rejection_rate", v["rejection_rate"], "percent", "rejected / n", n)
            interval(add, "rejection_wilson95", v["rejection_wilson95"], "percent", "Wilson 95% interval", n, "rejection_rate")
            interval(add, "rejection_cp95", v["rejection_cp95"], "percent", "exact two-sided Clopper-Pearson 95% interval", n,
                     "rejection_rate")
            add("false_rejections", v.get("false_rejections"), "count", "benign PDUs not delivered", n)
            if "false_rejections" in v:
                add("false_rejection_rate", v["false_rejection_rate"], "percent", "false rejections / n", n)
                interval(add, "false_rejection_cp95", v["false_rejection_cp95"], "percent",
                         "exact two-sided Clopper-Pearson 95% interval of the false-rejection rate", n, "false_rejection_rate")
                add("false_rejection_cp95_onesided_hi", v["false_rejection_upper95"], "percent",
                    "one-sided 95% Clopper-Pearson upper bound of the false-rejection rate", n, "false_rejection_rate")
            described(add, "detect_", v["detect_us"], "detect_ns, rejected PDUs")
            for st in v["stages"]:
                add_s = emitter(f"{base}.{st['stage']}", f["source"], "attack", f"vector={v['vector']}, reject_stage={st['stage']}")
                add_s("count", st["count"], "count", "PDUs rejected at this stage", n)
                add_s("rate", st["rate"], "percent", "count / n", n)
                interval(add_s, "cp95", st["cp95"], "percent", "exact two-sided Clopper-Pearson 95% interval", n, "rate")
                described(add_s, "detect_", st["detect_us"], "detect_ns at this stage")

    for f in results.get("sign_attrib", []):  # keys: crypto_attrib[.<directory label>].<file name without .csv>.<quantity>
        source = PurePosixPath(f["source"])
        base = _dotted("crypto_attrib", label("crypto_attrib", str(source.with_name("x.csv"))), source.stem)
        header(base, f, "sign_attrib")
        checks(base, f, "sign_attrib")
        n, note = f["n"], " (instrumented run: the times include the counting)" if f["counted"] else ""
        add = emitter(base, f["source"], "sign_attrib", f"seq>={f['warmup']}")
        add("n_total", f["n_total"], "count", "calls in the file", f["n_total"])
        add("n_dropped", f["n_warmup_dropped"], "count", "warm-up calls dropped", f["n_total"])
        add("n", n, "count", "calls after the warm-up", n)
        for stat, v in (f.get("cpu_tail_us") or {}).items():  # measured, beside what line and law imply (below)
            time(add, f"cpu_{STATS[stat]}", v, f"{stat} of the processor time of a signing call, type-7 percentile" + note, n,
                 why=scarce(stat, n))
        for which, what in (("wall", "wall time"), ("cpu", "processor time")):  # no percentile above the median here
            time(add, f"{which}_p50", f[f"{which}_us"]["p50"], f"median {what} of a signing call, type-7 percentile" + note, n,
                 why=scarce("p50", n))
            if b := f.get("bootstrap"):  # the interval the signing median of crypto_ops has
                time_interval(add, f"{which}_p50_ci95", f[f"{which}_us"]["p50_ci95"], f"moving-block bootstrap 95% CI of the "
                              f"median {what} (block {b['block_len']}, {b['n_boot']} replicates)" + note, n, f"{which}_p50",
                              why=scarce("p50", n))
            time(add, f"{which}_mean", f[f"{which}_us"]["mean"], f"mean {what} of a signing call" + note, n)
        add("off_total_s", f["off_total_s"], "s", "sum over the calls of wall_ns - cpu_ns", n, why=sign_attrib.NOT_OFF_CPU)
        add("off_above_floor.k", f["off_above_floor"]["k"], "count", "calls whose wall_ns - cpu_ns is more than "
            f"{sign_attrib.FLOOR_MARGIN_US} us above the floor (the median)", n)
        add("off_above_floor_s", f["off_above_floor"]["seconds"], "s", "sum over those calls of wall_ns - cpu_ns minus the "
            "floor (the median): time off the processor above the per-call clock-read floor", n)
        time(add, "off_min", f["off_min_us"], "smallest wall_ns - cpu_ns of a call", n)
        time(add, "off_median", f["off_median_us"], "median wall_ns - cpu_ns of a call: the per-call floor of the two clock "
             "reads inside the wall interval", n, why=scarce("p50", n))
        time(add, "off_max", f["off_max_us"], "largest wall_ns - cpu_ns of a call", n)
        for o in f["off_over"]:
            add(f"off_over_{_duration(o['threshold_us'])}.k", o["k"], "count",
                f"calls with wall_ns - cpu_ns above {_duration(o['threshold_us'])}", n)
        for w in f["wall_over"]:
            t = _g(w["threshold_ms"])
            add(f"wall_over_{t}ms.k", w["k"], "count", f"calls with wall time above {t} ms", n)
            add(f"wall_over_{t}ms.cpu_also_over", w["cpu_also_over"], "count", f"calls with wall time and processor time both "
                f"above {t} ms", n)
            time(add, f"wall_over_{t}ms.max_off", w["max_off_us"], "largest wall_ns - cpu_ns among the calls with wall time "
                 f"above {t} ms", w["k"])
            add(f"wall_over_{t}ms.rounds_min", w["rounds_min"], "count", f"fewest rounds among the calls with wall time above "
                f"{t} ms", w["k"])
            add(f"wall_over_{t}ms.calls_with_rounds_min_or_more", w["rounds_min_or_more"], "count", "calls of the whole sample "
                f"with at least as many rounds as the fewest-round call above {t} ms", n)
        for c in f["cpu_over"]:  # by processor time, whatever the wall time
            t = _g(c["threshold_ms"])
            add(f"cpu_over_{t}ms.k", c["k"], "count", f"calls with processor time above {t} ms" + note, n)
            add(f"cpu_over_{t}ms.share", c["share"], "percent", f"share of the calls with processor time above {t} ms: "
                f"cpu_over_{t}ms.k / n" + note, n)
            interval(add, f"cpu_over_{t}ms.share_cp95", c["share_cp95"], "percent", "exact two-sided Clopper-Pearson 95% "
                     "interval, independent calls assumed", n, f"cpu_over_{t}ms.share")
            add(f"cpu_over_{t}ms.rounds_min", c["rounds_min"], "count", "fewest rounds among the calls with processor time "
                f"above {t} ms" + note, c["k"])
            add(f"cpu_over_{t}ms.calls_with_rounds_min_or_more", c["rounds_min_or_more"], "count", "calls of the whole sample "
                f"with at least as many rounds as the fewest-round call with processor time above {t} ms" + note, n)
            add(f"rounds_threshold_{t}ms", c["rounds_threshold"], "count", "smallest whole number of rounds for which the "
                f"least-squares line of processor time on rounds is above {t} ms" + note, n)
            for cell, cpu, rounds in (("both", "above", "at least"), ("cpu_only", "above", "fewer than"),
                                      ("rounds_only", "not above", "at least"), ("neither", "not above", "fewer than")):
                add(f"cpu_vs_rounds_{t}ms.{cell}", c[cell], "count", f"calls with processor time {cpu} {t} ms and {rounds} "
                    f"rounds_threshold_{t}ms rounds" + note, n)
            add(f"cpu_vs_rounds_{t}ms.cpu_only_below_crossing", c["cpu_only_below_crossing"], "count", "calls with processor "
                f"time above {t} ms and fewer than rounds_threshold_{t}ms - 1 rounds" + note, n)
            add(f"cpu_vs_rounds_{t}ms.rounds_only_above_crossing", c["rounds_only_above_crossing"], "count", "calls with "
                f"processor time not above {t} ms and more than rounds_threshold_{t}ms rounds" + note, n)
            if a := c["rounds_at_least"]:
                at = f"rounds_at_least_threshold_{t}ms"
                add(f"{at}.k", a["k"], "count", f"calls with at least rounds_threshold_{t}ms rounds" + note, n)
                add(f"{at}.share", a["share"], "percent", f"share of the calls with at least rounds_threshold_{t}ms rounds: "
                    "k / n" + note, n)
                interval(add, f"{at}.share_cp95", a["share_cp95"], "percent", "exact two-sided Clopper-Pearson 95% interval, "
                         "independent calls assumed", n, f"{at}.share")
                add(f"{at}.share_geometric", a["share_geometric"], "percent", f"(1 - rounds_one_share)^(rounds_threshold_{t}ms "
                    f"- 1): the share of calls with at least rounds_threshold_{t}ms rounds under a geometric law with the "
                    "measured one-round share" + note, n)
                if a["share_geometric"] is not None and c["rounds_threshold"] > f["rounds"]["max"]:
                    add(f"{at}.share_geometric_extrapolation", a["share_geometric"], "percent", f"the same value as {at}."
                        f"share_geometric, under the name of what it is here: no call of the run has rounds_threshold_{t}ms "
                        "rounds (the most is rounds_max), so the geometric law is extended beyond the data; an "
                        "extrapolation, not a measured share" + note, n)
                interval(add, f"{at}.share_geometric", a["share_geometric_ci95"] or (None, None), "percent", "from the exact "
                         "interval of the one-round share; the rounds threshold is taken as given" + note, n,
                         f"{at}.share_geometric")
        if r := f["rounds"]:
            # the text sets these next to values of the standard: two decimals for the two means, at least one for
            # the share and its bounds (the general rules would print 19.57% as 20%)
            add("rounds_mean", r["mean"], "1", "mean number of rounds per call", n, decimals=2)
            d = max(1, shared_decimals([r["one_share"], *r["one_share_cp95"]], "percent"))
            add("rounds_one_share", r["one_share"], "percent", "share of the calls with one round", n, decimals=d)
            interval(add, "rounds_one_share_cp95", r["one_share_cp95"], "percent", "exact two-sided Clopper-Pearson 95% "
                     "interval, independent calls assumed", n, "rounds_one_share", decimals=d)
            add("rounds_max", r["max"], "count", "largest number of rounds of a call", n)
            add("rounds_mean_geometric", r["geometric_mean"], "1", "1 / rounds_one_share: the mean of a geometric law with "
                "the measured one-round share", n, decimals=2)
            for stat, m in (r.get("law") or {}).items():  # what the line and the law imply together: model figures
                add(f"line_and_law.{STATS[stat]}_rounds", m["rounds"], "count", f"{stat} of the number of rounds under a "
                    "geometric law with the measured one-round share: the smallest r with 1 - (1 - rounds_one_share)^r at or "
                    f"above {float(stat[1:]) / 100:g}", n)
                time(add, f"line_and_law.{STATS[stat]}_cpu", m["cpu_us"], f"{stat} of the processor time implied by line and "
                     f"law: the least-squares line of processor time on rounds at line_and_law.{STATS[stat]}_rounds rounds; "
                     f"a model figure to set beside the measured cpu_{STATS[stat]}, not a measurement" + note, n)
                measured = f["cpu_us"]["p50"] if stat == "p50" else (f.get("cpu_tail_us") or {}).get(stat)
                if measured:  # how far line and law are from the percentile measured in the same run
                    add(f"line_and_law.{STATS[stat]}_cpu_rel_diff", m["cpu_us"] / measured - 1, "percent",
                        f"line_and_law.{STATS[stat]}_cpu divided by the measured cpu_{STATS[stat]} of the same run, minus 1: "
                        "the processor time that the least-squares line and the geometric law imply against the type-7 "
                        "percentile of the measured processor times" + note, n, signed=True, why=scarce(stat, n))
            if fit := r["fit"]:
                line = "the least-squares line of processor time on rounds" + note
                time(add, "cpu_per_round", fit["cpu_per_round_us"], "slope of " + line, n)
                time(add, "cpu_intercept", fit["cpu_intercept_us"], "intercept of " + line, n, signed=True)
                add("r2", fit["r2"], "1", "r squared of " + line, n)
                d = fit["resid_us"]
                for stat, name, what in (("sd", "sd", "sd (divisor n - 2)"), ("p0.1", "p0_1", "p0.1, type-7 percentile,"),
                                         ("p99.9", "p99_9", "p99.9, type-7 percentile,"), ("min", "min", "smallest"),
                                         ("max", "max", "largest")):
                    time(add, f"resid_{name}", d[stat], f"{what} of the residuals of " + line, d["n"],
                         signed=stat != "sd", why=scarce(stat, d["n"]))

    for t in results.get("probetest", []):  # E9: the two tests of the probe's method, quoted as the check of the estimator
        base = _dotted("probetest", "" if t["source"] in (".", "probetest") else label("probetest", t["source"] + "/x.csv"))
        for z in t["zero"]:
            add = emitter(f"{base}.zero.{z['host']}", z["source"], "probetest", f"same-host test, host={z['host']}")
            n = z["exchanges"]
            add("exchanges", n, "count", "completed exchanges of the same-host test: client and server of the clock probe on "
                "this one board, where the true offset is zero", n)
            add("anchors", z["anchors"], "count", "anchors of the offset track (in every 5 s the exchange with the smallest delay)", n)
            add("offset_bound_us", z["offset_bound_us"], "us", "bound of the offset measurement in the same-host test: the "
                "largest delta / 2 among all its anchors (a run's e2e.offset_bound_us leaves the first and the last one out)",
                z["anchors"], decimals=1)
            add("theta_beyond_half_delay.k", z["theta_beyond_half_delay"], "count", "exchanges of the same-host test whose "
                "offset theta is further from the true offset, zero, than delta / 2; the estimator promises none", n)
        if p := t["pair"]:
            add = emitter(f"{base}.pair", p["source"], "probetest", "two-direction test")
            add("anchors_compared", p["anchors_compared"], "count", "anchors compared in the two-direction test (one probe "
                "from board A to B and one from B to A at the same time): the anchors of each track from the second to the "
                "second-to-last one whose instant, brought to the other board's clock, lies between the second and the "
                "second-to-last anchor of the other track", p["anchors_compared"])
            add("theta_sum_max_us", p["theta_sum_max_us"], "us", "largest |theta_AB + theta_BA| over the anchors compared: an "
                "anchor's offset plus the other track's offset at the same instant, zero for a perfect measurement",
                p["anchors_compared"])
            add("limit_us", p["limit_us"], "us", "what theta_sum_max_us must stay within: the sum of the two total bounds of "
                "the two-direction test (for each track the larger of the largest delta / 2 among its anchors from the second to the "
                "second-to-last one and its certified bound); none when a track has fewer than four anchors", p["anchors_compared"],
                decimals=1)

    for f in results.get("footprint", []):  # E8, standard tools: counts only
        if f["what"] == "size":
            for b in f["builds"]:
                add = emitter(_dotted("footprint.size", f["label"], b["build"]), f["source"], "footprint",
                              f"build={b['build']}" if b["build"] else "the file's one build")
                add("unstripped_bytes", b["unstripped_bytes"], "bytes", "size of the binary file before strip (the file's "
                    "unstripped_bytes line)", None)
                add("stripped_bytes", b["stripped_bytes"], "bytes", "size of the stripped binary file (the file's "
                    "stripped_bytes line)", None)
                for section, name in footprint.SECTIONS.items():
                    add(name, b[name], "bytes", f"size of the section {section} of the stripped binary (`size -A`)", None)
        elif f["what"] == "perf":
            (short, long), where = f["runs"], f"op={f['op']}"
            add = emitter(f"footprint.perf.{f['op']}", f["source"], "footprint", where)
            pair = (f"of the run of {long['calls']:,} calls less that of the run of {short['calls']:,}, over the "
                    f"{long['calls'] - short['calls']:,} calls between them (the numbers of calls are those of the file names; "
                    "what the tool does before and after its calls cancels); " + footprint.ONE_PAIR)
            add("instructions_per_call", f["instructions_per_call"], "1", "instructions of one call: the instructions:u count "
                + pair, None)
            add("cycles_per_call", f["cycles_per_call"], "1", "processor cycles of one call: the cycles:u count " + pair, None)
            add("instructions_per_cycle", f["instructions_per_cycle"], "1", "instructions per cycle of those calls: the ratio "
                "of the two differences; " + footprint.ONE_PAIR, None)
            for run in f["runs"]:
                add = emitter(f"footprint.perf.{f['op']}.n{run['calls']}", f["source"], "footprint", f"{where}, calls={run['calls']}")
                for event, name in footprint.EVENTS.items():
                    add(name, run[name], "count", f"perf stat count of {event} over the whole run of the tool with "
                        f"{run['calls']:,} calls, start-up included", None)
        else:
            for host, h in f["hosts"].items():
                add = emitter(f"footprint.rss.{host}", f["source"], "footprint", f"host={host}")
                add("vmhwm_max_kb", h["vmhwm_max_kb"], "count", "largest VmHWM (peak resident set of the process, in kB as "
                    "/proc/<pid>/status gives it) among the samples of this host", h["samples"])
                add("samples", h["samples"], "count", "sample lines of this host in the file", h["samples"])

    for c in results.get("capture", []):  # the driver's summary of a packet capture (calibration run): counts and ratios
        add = emitter(_dotted("capture", *c["source"].split("/")[:-1], c["host"]), c["source"], "capture", f"host={c['host']}")
        frames, pdus = c["frames_with_payload"], c["jobs_confirmed"]
        what = ("in the packet capture taken on the sending board during the run; frames on the wire only when segmentation "
                "offload is off there (offload_<host>.txt beside the file)")
        add("frames_with_payload", frames, "count", "frames with TCP payload sent by the board " + what
            + "; the file's captured_frames_with_payload line", frames)
        add("tcp_payload_bytes", c["tcp_payload_bytes"], "bytes", "TCP payload bytes of those frames; the file's "
            "tcp_payload_bytes line", frames)
        add("frame_bytes", c["frame_bytes"], "bytes", "bytes of those frames with their headers; the file's "
            "frame_bytes_as_captured line", frames)
        add("jobs_confirmed", pdus, "count", "Secured I-PDUs the sender confirmed in the run; the file's jobs_confirmed line", pdus)
        add("frames_per_pdu", c["frames_per_pdu"], "1", "frames_with_payload / jobs_confirmed: frames with TCP payload per "
            "Secured I-PDU, " + what + "; the capture also holds the few frames of the session set-up, which are not taken "
            "off", pdus)
        add("frame_bytes_per_frame", c["frame_bytes_per_frame"], "bytes", "frame_bytes / frames_with_payload: mean size of a "
            "frame with payload, headers included", frames)
        add("tcp_payload_bytes_per_frame", c["tcp_payload_bytes_per_frame"], "bytes", "tcp_payload_bytes / "
            "frames_with_payload: mean TCP payload of a frame with payload", frames)

    for c in results.get("cyclictest", []):
        add = emitter(_dotted("cyclictest", label("cyclictest", c["source"]), f"{c['policy']}-{c['load']}"), c["source"],
                      "cyclictest", f"policy={c['policy']}, load={c['load']}, cpu={c['cpu']}")
        n = c["samples"]
        add("samples", n, "count", "wake-ups measured (histogram total plus overflows)", n)
        add("overflows", c["overflows"], "count", f"latencies at or above the histogram size of {c['histogram_us']} us", n)
        add("duration_s", c["duration_s"], "s", "requested duration", None)
        add("cpu", c["cpu"], "id", "the CPU cyclictest was pinned to", None)
        add("priority", c["priority"], "count", "real-time priority asked for (0 under SCHED_OTHER)", None)
        time(add, "histogram", c["histogram_us"], "histogram size: latencies at or above it are overflows", None)
        time(add, "interval", c["interval_us"], "wake-up period", None)
        def whole_us(name, us, how, why=None):  # a latency read from the 1 us histogram: a whole number of microseconds
            add(f"{name}_us", us, "us", how, n, why=why, decimals=0)
            add(f"{name}_ms", None if us is None else us / 1000, "ms", how, n, why=why)

        for name, how in (("min", "cyclictest's Min Latencies line"), ("avg", "cyclictest's Avg Latencies line (an integer)"),
                          ("max", "cyclictest's Max Latencies line")):
            whole_us(name, c[f"{name}_us"], how)
        time(add, "mean", c["mean_us"], "mean of the 1 us histogram", n)
        for q in ("99", "99.9", "99.99"):
            whole_us("p" + q.replace(".", "_"), c[f"p{q}_us"], f"{q}th percentile read from the 1 us histogram", scarce("p" + q, n))
        for late in c["late_over"]:
            add(f"late_over_{_duration(late['threshold_us'])}.k", late["k"], "count",
                f"wake-ups later than {_duration(late['threshold_us'])} (strictly above), overflows included", n)

    for f in results["handshake"]:
        header(_dotted("handshake", handshake_label(f)), f, "handshake")
        for r in f["roles"]:
            add = emitter(_dotted("handshake", handshake_label(f), r["role"]), f["source"], "handshake",
                          f"role={r['role']}")
            add("n", r["n"], "count", "handshakes attempted", r["n"])
            add("ok", r["ok"], "count", "handshakes with result ok", r["n"])
            add("failed", r["n"] - r["ok"], "count", "handshakes with any other result", r["n"])
            for result, c in r["results"].items():
                add(f"result_{result}", c, "count", f"handshakes with result {result}", r["n"])
            described(add, "total_", r["total_us"], "total_ns, successful handshakes (per role; includes main-function "
                      "scheduling, and for the responder the initiator's computation and two network legs)")
            described(add, "compute_", r["compute_us"], "sum of the stage columns, successful handshakes")
            for phase, d in r["phases_us"].items():
                described(add, f"{phase}_", d, f"{phase}_ns, successful handshakes")
            for k in ("bytes_tx", "bytes_rx"):
                for stat, v in (r[k] or {}).items():
                    add(f"{k}_{stat}", v, "bytes", f"{stat} of {k}, successful handshakes", r["ok"],
                        why=scarce("p50", r["ok"]) if stat == "median" else None)

    # the own computation of a handshake spread over the PDUs of a session (handshake.SESSION_PDUS, an assumption): per
    # role, and both roles of one directory added when it holds exactly one of each
    per, sides = f"{handshake.SESSION_PDUS:,} PDUs", {}
    amortised = (f"divided by {handshake.SESSION_PDUS:,}: the amortised cost per PDU when one handshake serves a session of {per}; "
                 "the session length is an assumption of this key, not a measurement")
    for f in results["handshake"]:
        for r in f["roles"]:
            if r["compute_us"].get("mean") is None:
                continue
            add = emitter(_dotted("handshake", handshake_label(f), r["role"]), f["source"], "handshake", f"role={r['role']}")
            time(add, "compute_mean_per_pdu_session1000", r["compute_us"]["mean"] / handshake.SESSION_PDUS, "mean own "
                 f"computation of a handshake of this role (compute_mean, the sum of its stage columns), {amortised}", r["compute_us"]["n"])
            sides.setdefault(PurePosixPath(f["source"]).parent.as_posix(), []).append((f["source"], r))
    for d, found in sides.items():
        if sorted(r["role"] for _, r in found) == ["initiator", "responder"]:
            add = emitter(_dotted("handshake", label("handshake", f"{d}/handshake.csv"), "both_roles"),
                          " + ".join(dict.fromkeys(source for source, _ in found)), "handshake", "both roles")
            time(add, "compute_mean_per_pdu_session1000", sum(r["compute_us"]["mean"] for _, r in found) / handshake.SESSION_PDUS,
                 "mean own computation of a handshake, both roles added (the initiator's compute_mean plus the "
                 f"responder's), {amortised}", min(r["compute_us"]["n"] for _, r in found))

    for t in results.get("functional", []):
        # a functional run of the gateway binaries: counts only, keyed by its directory when the run directory holds several
        base = _dotted("functional", "" if t["source"] == "." else PurePosixPath(t["source"]).name)
        add = emitter(base, t["source"], "functional", f"profile={t['profile']}")
        sent, decided = t["sent"], t["delivered"] + sum(t["rejected"].values())
        add("streams", t["streams"], "count", "streams of the functional run: those the transmitter's header names and those of its rows", None)
        add("sent", sent, "count", "PDUs the transmitting gateway sent: rows of app_tx*.csv, all parts (a row is written "
            "when the transmission is confirmed)", sent)
        add("delivered", t["delivered"], "count", "PDUs delivered to the receiving application: rows of app_rx*.csv with result "
            "ok, all parts", sent)
        add("delivered_in_order", t["delivered_in_order"], "count", functional.IN_ORDER, sent)
        add("lost", sent - t["delivered_in_order"], "count", "PDUs lost: sent - delivered_in_order, the PDUs the transmitting "
            "gateway sent that are not among the delivered ones met in the order they were sent (a PDU the receiver "
            "rejected has no delivered row, so it is among these)", sent)
        add("delivered_byte_exact", t["delivered_byte_exact"], "count", functional.BYTE_EXACT, sent)
        add("rejected", sum(t["rejected"].values()), "count", "PDUs the receiver rejected: " + functional.REJECTED_NOTE, decided)
        for result, k in t["rejected"].items():
            add(f"rejected_{result}", k, "count", f"rows of app_rx*.csv with result {result}; " + functional.REJECTED_NOTE, decided)
        for st in t["per_stream"]:
            add_s = emitter(f"{base}.s{st['stream']}", t["source"], "functional", f"profile={t['profile']}, stream={st['stream']}")
            for k, how in (("sent", "PDUs sent on this stream"), ("delivered", "PDUs of this stream delivered"),
                           ("delivered_in_order", functional.IN_ORDER), ("delivered_byte_exact", functional.BYTE_EXACT)):
                add_s(k, st[k], "count", how, st["sent"])
            add_s("lost", st["sent"] - st["delivered_in_order"], "count", "PDUs of this stream lost: sent - delivered_in_order",
                  st["sent"])
        for role, side in t["handshakes"].items():
            add_r = emitter(f"{base}.{role}", t["source"], "functional", f"role={role}")
            add_r("n", side["n"], "count", f"rows the {role}'s handshake application logged in the functional run, all its "
                  "handshake files: attempts that ended and messages discarded without ending one; counted, never timed", side["n"])
            for result, c in side["results"].items():
                add_r(f"result_{result}", c, "count", f"handshake rows of the {role} with result {result}", side["n"])
        for side, name in (("tx", "transmitting"), ("rx", "receiving")):
            add_c = emitter(f"{base}.{side}", t["source"], "functional", f"side={side}")
            c = t["connections"][side]
            add_c("parts", t[f"{side}_parts"], "count", f"processes of the {name} gateway in the run: one app_{side} file each", None)
            add_c("tcp_connections", c["n"], "count", f"TCP connections of the {name} gateway: the '# tcp_nodelay=' lines of its "
                  f"app_{side} files", c["n"])
            add_c("tcp_nodelay_1", c["nodelay_1"], "count", "of those connections, the ones that read back tcp_nodelay=1 (all "
                  "of them: a run with another read-back is invalid)", c["n"])

    for t in results.get("hsneg", []):
        # a negative handshake test: what each side logged, counted here from its handshake files, and the oracle's
        # record line; no time of any kind
        lab, r = hsneg.label(t["record"], PurePosixPath(t["source"]).name), t["record"]
        files = f"{t['source']} ({len(t['files'])} handshake file(s))"
        for role, side in t["sides"].items():
            add = emitter(_dotted("hsneg", lab, role), files, "hsneg", f"role={role}")
            add("n", side["n"], "count", f"handshake rows the {role} logged in the negative test, over all its handshake files "
                "(a gateway writes a row for an attempt that ended and for a message discarded without ending one)", side["n"])
            for result, c in side["results"].items():
                add(f"result_{result}", c, "count", f"handshake rows of the {role} with result {result}", side["n"])
        if r:
            add = emitter(_dotted("hsneg", lab), t["record_file"], "hsneg", f"test={r['test']}, variant={r['variant']}")
            add("verdict", r["verdict"], "text", "the oracle's verdict on the test, PASS or FAIL, from its record line", None)
            for k, how in HSNEG_RECORD.items():
                add(k, r[k], "count", how + " (the oracle's record line)", None)

    format_items(items.values())
    return [items[k] for k in sorted(items)]


def format_items(items):
    """Sets 'formatted' on every item. Items of one 'group' (an estimate and all its bounds) are
    printed with the same number of decimals, see shared_decimals(). 'shown_decimals' records the
    number used (None: scientific notation), for the ranges over sessions."""
    groups = {}
    for item in items:
        groups.setdefault(item["group"], []).append(item)
    for group, members in groups.items():
        members.sort(key=lambda m: m["key"] != group)  # the estimate first: the bounds are measured from it
        first = members[0]
        d = shared_decimals([m["value"] for m in members], first["unit"], first["signed"]) if len(members) > 1 else None
        for m in members:
            used = d if m.get("decimals") is None else m["decimals"]
            m["formatted"] = fmt(m["value"], m["unit"], m["signed"], used)  # first: it refuses a non-finite value
            m["shown_decimals"] = _used(m["value"], m["unit"], m["signed"], used)


# ---- output --------------------------------------------------------------------------------------

PREAMBLE = r"""\newcommand{\measundefined}[1]{\PackageError{numbers}{Undefined number key '\detokenize{#1}'}%
  {The key is not in numbers.tex. numbers.csv lists every key of this run.}\textbf{??}}
\newcommand{\meas}[1]{\ifcsname meas@\detokenize{#1}\endcsname\csname meas@\detokenize{#1}\endcsname\else\measundefined{#1}\fi}
\newcommand{\measraw}[1]{\ifcsname measraw@\detokenize{#1}\endcsname\csname measraw@\detokenize{#1}\endcsname\else\measundefined{#1}\fi}
"""
# The merged file of a whole campaign is \input by a manuscript that may define things first: its own \measundefined
# (a PENDING marker while runs are missing; without it a missing key stays a hard error) and a fallback \meas.
# So \measundefined is only provided, and \meas / \measraw are provided and then redefined: no clash, and ours win.
MERGED_PREAMBLE = PREAMBLE.replace(r"\newcommand{\measundefined}", r"\providecommand{\measundefined}") \
    .replace(r"\newcommand{\meas}[1]", r"\providecommand{\meas}[1]{}\renewcommand{\meas}[1]") \
    .replace(r"\newcommand{\measraw}[1]", r"\providecommand{\measraw}[1]{}\renewcommand{\measraw}[1]")
# every value of a DRY_RUN or PILOT directory is wrapped in this: bold, red if a colour package is loaded, tagged
NOT_A_RESULT = (r"\DeclareRobustCommand{\notaresult}[2][DRY]{\textbf{\ifdefined\textcolor\textcolor{red}{[#1] #2}"
                r"\else[#1] #2\fi}}" + "\n")
# \notaresult{...} prints [DRY]; \notaresult[PILOT]{...} prints [PILOT]; \notaresult[EXCL]{...} prints [EXCL]
TAGS = {"DRY_RUN": "", "PILOT": "[PILOT]", "EXCLUDED": "[EXCL]"}


def raw(value):
    """The unformatted value as text: integers and words as they are, floats in their shortest exact form."""
    return str(value) if isinstance(value, (int, str)) else repr(float(value))


def _n(item):
    return "-" if item["n"] is None else item["n"]  # a run parameter has no sample size


def shown(item, meta):
    r"""What \meas prints for the item: its formatted value, wrapped in \notaresult for a marked run."""
    marker = meta.get("not_a_result")
    return rf"\notaresult{TAGS[marker]}{{{item['formatted']}}}" if marker else item["formatted"]


def definition(item, meta):
    r"""The numbers.tex line of one item. \measraw is not defined for an underflowed p-value (it has
    no plain form) nor in a DRY_RUN / PILOT run (a plain number could be printed unmarked)."""
    line = rf"\expandafter\def\csname meas@{item['key']}\endcsname{{{shown(item, meta)}}}"
    if item["raw"] is not None and not meta.get("not_a_result"):
        line += rf"\expandafter\def\csname measraw@{item['key']}\endcsname{{{item['raw']}}}"
    return (line + f"% {item['source_file']} | {item['experiment']} | {item['filter']} | n={_n(item)} | "
            f"toolkit {meta.get('toolkit_commit', 'unknown')}")


def defined(items):
    """The items numbers.tex defines: all but the percentiles the rule of scarce() holds back."""
    return [i for i in items if not i.get("suppressed")]


def render_tex(items, meta):
    marker = meta.get("not_a_result")
    held_back, items = len(items) - len(defined(items)), defined(items)
    head = (f"% numbers.tex: generated by analysis.make_numbers, do not edit. {len(items)} keys.\n"
            f"% run {meta.get('run_dir')}, seed {meta.get('seed')}, toolkit {meta.get('toolkit_commit', 'unknown')}"
            f", key prefix '{meta.get('key_prefix') or ''}'\n"
            + (f"% {held_back} more keys are in numbers.csv only: {SUPPRESSED_FILE} says why\n" if held_back else "")
            + (f"% {marker} directory: NOT A RESULT. Every value is wrapped in \\notaresult, \\measraw is not defined.\n"
               if marker else "")
            + "".join(f"% {m['name']}: {line}\n" for m in meta.get("markers") or [] for line in m["text"].splitlines())
            + "% each line: \\meas{key} value, \\measraw{key} value, then source | experiment | filter | n | toolkit\n")
    return head + PREAMBLE + (NOT_A_RESULT if marker else "") + "\n".join(definition(i, meta) for i in items) + "\n"


CSV_HEADER = ["key", "value", "formatted", "unit", "n", "source_file", "how"]
SUPPRESSED_FILE = "suppressed_keys.txt"
SUPPRESSED_HEAD = ("# keys of numbers.csv that numbers.tex does not define, with the reason (key <tab> reason).\n"
                   f"# Rule: a percentile p of n values is a manuscript number only if n(1 - p) >= {MIN_ABOVE} samples lie above it;\n"
                   "# an interval of such a percentile goes with it. A few other keys are kept for the record only; their\n"
                   "# reason says why.\n")


def short_reason(reason):
    """A suppression reason without the sample counts, for the list of keys: the percentile rule in
    general terms, any other reason as it is."""
    for side in ("above", "below"):
        if f"samples lie {side} it" in reason:
            return f"fewer than {MIN_ABOVE} samples {side} it"
    return reason


def render_suppressed(items):
    return SUPPRESSED_HEAD + "".join(f"{i['key']}\t{i['suppressed']}\n" for i in items if i.get("suppressed"))


def render_csv(items, meta):
    """The audit table. `value` is the stored number; for an underflowed p-value it reads <1e-300."""
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(CSV_HEADER)
    w.writerows([i["key"], i["raw"] if i["raw"] is not None else f"<{P_FLOOR:g}", shown(i, meta), i["unit"], _n(i),
                 i["source_file"], i["how"]] for i in items)
    return out.getvalue()


KEYS_FILE = "number_keys.md"
KEYS_NOTE = """A percentile is a manuscript number only when at least 10 samples lie above it, n(1 - p) >= 10.
A percentile that fails this, and its interval, is in numbers.csv but not in numbers.tex; it is
marked below and listed with the reason in suppressed_keys.txt. Citing it is a LaTeX error.

A key exists only when the run has the value. No key is made for a statistic that is undefined
for the data (a p-value when every difference is zero), a handshake result that did not occur, a
stage a role does not use or a binary does not record, a percentile among the cyclictest overflows,
a miss window longer than the run, or latency without a clock relation. Key parts that come from
names (directory and file label, host, configuration id, rate, repetition, stream, vector, launch
number, key prefix) follow the files of the run that is analysed: another run has other names in
those places.

A run analysed with a key prefix (experiment, session, host) has it at the front of every key, so
the sessions of an experiment have keys of their own. The smallest and the largest value over the
sessions are further keys, `<prefix with the session part replaced by all>.<key>.min_over_sessions`
and `.max_over_sessions`, written by analysis.sessions; analysis.merge_numbers joins the files of
all runs into the one numbers.tex of the manuscript.

Units: `us` and `ms` microseconds and milliseconds (every time has both); `percent` a proportion,
printed as a percentage with its sign; `p` a p-value; `count`, `bytes`, `s`, `PDU/s`, `Mbit/s`,
`bytes/PDU`, `bytes/s` as named; `1` a dimensionless number; `id` an identifier printed as it is;
`text` a word (the verdict of a negative handshake test, PASS or FAIL) or a range over sessions
printed as one piece (both ends with an en dash, or the one value when they are exactly equal).
"""


def render_keys(items, meta):
    r"""number_keys.md: every key of the run with what it means (how it is computed, then the rows it
    is computed from), its unit and its source file, in the order of numbers.csv and without any
    value, so that \meas{key} can be written into a manuscript before the data exist."""
    def cell(text):
        return str(text).replace("|", "\\|")

    marker = meta.get("not_a_result")
    return (f"# Number keys of {meta.get('title') or 'run ' + str(meta.get('run_dir'))}\n\n"
            f"{len(items)} keys ({len(items) - len(defined(items))} of them marked 'not in numbers.tex'), generated by "
            f"analysis.make_numbers (toolkit {meta.get('toolkit_commit', 'unknown')}), key "
            f"prefix '{meta.get('key_prefix') or ''}'. After `\\input{{numbers.tex}}`, `\\meas{{key}}` prints the formatted "
            "value and `\\measraw{key}` the plain number. The values are in numbers.csv.\n\n"
            + (f"{marker} directory: the keys below are real, the values of {meta.get('scope', 'this run')} are not "
               "results.\n\n" if marker else "")
            + KEYS_NOTE + "\n| key | meaning | unit | source file |\n|---|---|---|---|\n"
            + "".join(f"| `{i['key']}` | {cell(i['how'])} ({cell(i['filter'])})"
                      + (f" (not in numbers.tex: {cell(short_reason(i['suppressed']))})" if i.get("suppressed") else "")
                      + f" | {i['unit']} | {cell(i['source_file'])} |\n" for i in items))


def write(tex_path, items, meta):
    """Write numbers.tex at tex_path, the audit CSV next to it (same name, .csv), and in the same
    directory the list of keys without values (number_keys.md) and the keys that the .tex file does
    not define (suppressed_keys.txt, written also when it lists none)."""
    tex_path = Path(tex_path)
    tex_path.write_text(render_tex(items, meta), encoding="utf-8")
    tex_path.with_suffix(".csv").write_text(render_csv(items, meta), encoding="utf-8")
    tex_path.with_name(KEYS_FILE).write_text(render_keys(items, meta), encoding="utf-8")
    tex_path.with_name(SUPPRESSED_FILE).write_text(render_suppressed(items), encoding="utf-8")


def check_prefix(key_prefix):
    bad = [seg for seg in key_prefix.split(".") if not SEGMENT.fullmatch(seg)] if key_prefix else []
    if bad:
        raise ValueError(f"key prefix {key_prefix!r}: the part(s) {bad} are not made of A-Z a-z 0-9 _ -")
    return key_prefix


def main(argv=None):
    ap = argparse.ArgumentParser(description="Rebuild numbers.tex and numbers.csv from <analysis_out_dir>/summary.json.")
    ap.add_argument("out_dir", type=Path, help="directory written by analysis.make_tables")
    ap.add_argument("--out", type=Path, help="path of the .tex file (default: <out_dir>/numbers.tex); the CSV goes next to it")
    ap.add_argument("--key-prefix", help="put <prefix>. in front of every key (default: the prefix stored in summary.json)")
    a = ap.parse_args(argv)
    try:
        summary = json.loads((a.out_dir / "summary.json").read_text(encoding="utf-8"))
        if a.key_prefix is not None:
            summary["key_prefix"] = a.key_prefix
        # all keys are checked before anything is written
        items = collect(summary["results"], {"seed": summary.get("seed"), **summary.get("params", {})},
                        check_prefix(summary.get("key_prefix") or ""))
        computed, now = summary.get("toolkit_commit", "unknown"), toolkit_commit()
        if now != computed:  # the numbers were computed by one version of the toolkit and are formatted by another
            summary["toolkit_commit"] = f"{computed}, formatted by {now}"
    except (OSError, ValueError, KeyError) as e:
        sys.exit(f"error: {e}")
    tex = a.out or a.out_dir / "numbers.tex"
    write(tex, items, summary)
    print(f"{len(defined(items))} keys -> {tex}; {len(items)} in {tex.with_suffix('.csv')} and {tex.with_name(KEYS_FILE)}; "
          f"{len(items) - len(defined(items))} held back, see {tex.with_name(SUPPRESSED_FILE)}")


if __name__ == "__main__":
    main()
