"""Turn one run directory of raw measurement CSVs into tables, figures and summary.json.

    python3 -m analysis.make_tables <run_dir> [--out <dir>]                  # from the toolkit root
    python3 -I <toolkit>/analysis/make_tables.py <run_dir> --out <dir>       # isolated mode

CSV files are found recursively by name (<kind>.csv or <kind>_<label>.csv; see csvio.kind_of) and
their headers are validated. Output: tables/*.md, tables/*.tex, figures/*.pdf (if matplotlib is
installed), summary.json, which holds every number next to the path and SHA-256 of its source, and
numbers.tex / numbers.csv (one LaTeX macro per scalar, see make_numbers.py). README.md has the details.
"""
import argparse
import hashlib
import json
import math
import os
import platform
import re
import sys
import zlib
from pathlib import Path

if __package__ in (None, ""):  # run by path under python3 -I, which keeps the script directory off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis import (attack, crypto_ops, csvio, cyclictest, e2e, footprint, functional, handshake, hsneg, make_numbers, overhead, periodic,  # noqa: E402
                      sign_attrib, simulate, tables, throughput, toolkit_commit)
from analysis import figures as figs  # noqa: E402  (imports matplotlib only inside make_all)
from analysis.tables import DASH, ci, num, pct, sig  # noqa: E402

import numpy as np  # noqa: E402  (after the package import, which makes numpy importable under -I)
import scipy  # noqa: E402

SEED = 20261122
LEGACY_MARGINS = (0.01, 0.02)  # post hoc: the legacy data had been seen before any margin was chosen
KINDS = ("crypto_ops", "sign_attrib", "overhead_paired", "overhead_launch_sets", "overhead_unpaired", "periodic", "periodic_cells",
         "throughput", "attack",
         "handshake", "hsneg", "functional", "cyclictest", "footprint", "probetest")
CHECKED = ("crypto_ops", "overhead_paired", "sign_attrib")  # files of the single-node harnesses carry self-checks
PART = re.compile(r"(?:^|[._-])p\d+$")  # partition suffix of a file label: periodic_tx_p0.csv
CELL = ("period_us", "deadline_us", "cores", "profile", "scheduler", "payload_bytes", "commit", "host", "mainfunction",
        "mf_period_us", "phase", "partitions")  # what the partitions of one periodic cell have in common
REP = re.compile(r"(?:^|[._-])rep0*(\d+)(?:$|[._-])")  # repetition number in a file label: throughput_tx_400pps_rep2_p0.csv
TRAFFIC_LOG = ("traffic log of the load generator in an attack, throughput, calibration or negative-test directory, "
               "not a periodic experiment")
NEGATIVE_INVALID = "another handshake file of this negative test is invalid"
# a functional run of the gateway binaries: a directory with the marker FUNCTIONAL (DATA_SCHEMA.md, 'Functional runs')
JOINED = "joined by the driver from the parts of a functional run, which are read themselves"
NOT_TIMED = "in a FUNCTIONAL directory: nothing there is a timing result, so this file is not analysed"
FUNCTIONAL_INVALID = "its functional run is incomplete or invalid"
MAP_HEADER = ",".join(name for name, _ in csvio.SCHEMAS["clock_map"])
# E12.2: the header lines a probe file of format 2 and a clock map must carry as they are (E9_SPEC.md, E2)
PROBE_LINES = (("clock", "CLOCK_MONOTONIC"), ("clock_raw", "CLOCK_MONOTONIC_RAW"))
MAP_LINES = (*PROBE_LINES, ("interval_ms", "5"))
MAP_NOT_USED = "clock_map file not used: no clock_probe file of format 2 was analysed beside it"
NO_FUNCTIONAL_RUN = ("FUNCTIONAL directory without app_tx*.csv and app_rx*.csv: no functional run is recorded here (a run "
                     "that was cut off before the gateways wrote anything, or a build or link step)")
SETUP_HANDSHAKE = ("session set-up handshake of another experiment (in an attack, throughput or calibration directory, beside a "
                   "periodic file, or its header says pdu_stream other than none), not a handshake experiment")
EXIT_INVALID = 3  # make_tables wrote its output, but left at least one file unanalysed as invalid
SAMPLER = re.compile(r"throughput_(tx|rx)(.*)\.csv")  # a sampler file of the networked harness: throughput_<role>[_<label>].csv


def transport_lines(p, kind, meta):
    """(meta, note): `meta` with the tcp_ and jobs lines the file itself lacks, read from the header and footer (never
    the rows) of the generator's traffic log beside it, and a note for the reasons when no usable log was found.

    A sampler file throughput_<role><label>.csv of a ladder step need not carry these lines (jobs_started and
    jobs_confirmed are in the log's footer only, and so is stopped_early): they are those of periodic_<role><label>.csv
    in the same directory, which must be from the same host, repetition and partition.
    An attack file takes tcp_nodelay from periodic_tx.csv and periodic_rx.csv beside it: 1 only when both say 1.
    Lines of the file itself win. This fails closed: without a usable log the lines stay missing, and
    csvio.transport() then makes the file invalid."""
    if kind == "throughput" and (m := SAMPLER.fullmatch(p.name)):
        logs, same = [p.with_name(f"periodic_{m[1]}{m[2]}.csv")], ("host", "rep", "partition")
    elif kind == "attack":
        logs, same = [p.with_name("periodic_tx.csv"), p.with_name("periodic_rx.csv")], ()
    else:
        return meta, None
    wanted = ("tcp_nodelay",) if kind == "attack" else None  # an attack file is no transmitter file: only this line
    if wanted and all(k in meta for k in wanted):
        return meta, None  # a sampler file is always read with its log: the window counts may be in the log only
    read = {}
    for log in logs:
        if not log.is_file():
            return meta, f"no traffic log {log.name} beside the file"
        other = csvio.read_meta(log)
        differ = [f"its {k}={other[k]} differs from {meta[k]}" for k in same if k in meta and k in other and other[k] != meta[k]]
        if differ:
            return meta, f"the traffic log {log.name} beside the file is not used: " + ", ".join(differ)
        if "tcp_nodelay" not in other and "tcp_nodelay" not in meta:
            return meta, f"the traffic log {log.name} beside the file has no tcp_nodelay line"
        for k, v in other.items():
            if (k.startswith("tcp_") or k in (*csvio.JOBS, "tx_confirmations_failed", "stopped_early")) and \
                    (wanted is None or k in wanted) and \
                    (k not in read or (k == "tcp_nodelay" and read[k] == "1")):
                read[k], read["from:" + k] = v, log.name  # for an attack file: the end that does not say 1 is the one shown
    taken = {k: v for k, v in read.items() if not k.startswith("from:") and k not in meta}
    if not taken:
        return meta, None
    return {**meta, **taken, csvio.TRANSPORT_FROM: {k: read["from:" + k] for k in taken}}, None
GATED = (*CHECKED, "periodic_tx", "throughput", "handshake")  # not analysed when invalid (periodic_rx: with its Tx file)
NO_ATTACK_LOG = "no traffic log periodic_tx.csv beside the file: whether every started job was confirmed is not recorded"


def failed(checks, reasons):
    """`checks` made invalid by further `reasons`; a file without harness lines gets a validity record for them."""
    return {"warnings": [], "throttled": None, **(checks or {}), "valid": False,
            "reasons": [*(checks or {}).get("reasons", []), *reasons]}
BANNER = {"DRY_RUN": "DRY RUN: not a result", "PILOT": "PILOT: not a result", "EXCLUDED": "EXCLUDED RUN: not a result"}


def launch_id(meta, path):
    """Launch number of a paired file that is one launch of a set: its '# launch=' line, else a file
    label ending in L<n> or launch<n> (overhead_paired_L07.csv). None for any other file."""
    text = meta.get("launch")
    if text is None:
        m = re.search(r"(?:^|[._-])(?:L|launch)0*(\d+)$", make_numbers.file_label(Path(path).name))
        return int(m[1]) if m else None
    if not (text.isascii() and text.isdigit()):
        raise ValueError(f"header launch={text!r} is not a non-negative integer")
    return int(text)


def _clean(o):
    """JSON-ready copy: numpy scalars and arrays to Python, non-finite floats to null."""
    if isinstance(o, dict):
        return {str(k): _clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_clean(v) for v in o]
    if isinstance(o, np.ndarray):
        return _clean(o.tolist())
    if isinstance(o, np.generic):
        o = o.item()
    if isinstance(o, float) and not math.isfinite(o):
        return None
    return o


def run(run_dir, out, *, seed=SEED, warmup=1000, block_len=100, n_boot=2000, thresholds_ms=(5.0, 10.0, 15.0, 20.0),
        trim=0, sim_draws=20, sim_jobs=200_000, figures=True, key_prefix=""):
    """Analyse run_dir, write everything under out, and return the summary dict."""
    run_dir, out = Path(run_dir).resolve(), Path(out).resolve()
    key_prefix = make_numbers.check_prefix(key_prefix)
    paths, skipped = csvio.discover(run_dir)
    cyclic = sorted(run_dir.rglob(cyclictest.NAME))
    # a directory with the marker FUNCTIONAL is a functional run of the gateway binaries: its own files are counted
    # (below, after the timing files), and nothing else in it is analysed, because nothing there is a timing result
    functional_runs = {m.parent: functional.parts(m.parent) for m in sorted(run_dir.rglob(functional.MARKER)) if m.is_file()}
    # footprint figures taken with standard tools (E8): counted, never timed. A file of such a name without the shape
    # is no footprint file (its reader gives None) and stays what it was: not read, a CSV file listed as not recognised
    sizes = {p: b for p in sorted(run_dir.rglob(footprint.SIZE)) if (b := footprint.sizes(p))}
    perfs = {p: c for p in sorted(run_dir.rglob(footprint.PERF)) if footprint.PERF_NAME.fullmatch(p.name) and (c := footprint.perf(p))}
    rsses = {p: h for p in sorted(run_dir.rglob(footprint.RSS)) if (h := footprint.rss(p))}
    captures = {p: c for p in sorted(run_dir.rglob(footprint.CAPTURE)) if (c := footprint.capture(p))}
    # the two tests of the probe's method (E9): a directory named probetest with zero_<host>.csv, pair_ab.csv, pair_ba.csv
    def is_map(p):  # a clock map (Addendum E) by its header row, whatever its name: the probe test's maps are not read
        with open(p, encoding="utf-8-sig", errors="replace") as f:
            return next((s for s in map(str.strip, f) if s and not s.startswith("#")), "") == MAP_HEADER

    probetests = {d: sorted(p for p in d.glob("*.csv") if re.fullmatch(r"zero_.+\.csv|pair_(ab|ba)\.csv", p.name) and not is_map(p))
                  for d in sorted({run_dir, *run_dir.rglob("probetest")}) if d.is_dir() and d.name == "probetest"}
    probetests = {d: files for d, files in probetests.items() if files}
    if not paths and not cyclic and not functional_runs and not (sizes or perfs or rsses or captures) and not probetests:
        raise ValueError(f"no recognised CSV or cyclictest files under {run_dir}")
    skipped = [e for e in skipped if run_dir / e["path"] not in {p for files in probetests.values() for p in files}]
    skipped = [e for e in skipped if run_dir / e["path"] not in perfs]
    kinds = {p: csvio.kind_of(p) for p in paths}
    joined_files = {p for _, files in functional_runs.values() for p in files}
    gateway_files = joined_files | {p for by_stem, _ in functional_runs.values() for files in by_stem.values() for p in files}
    skipped = [e for e in skipped if run_dir / e["path"] not in gateway_files]  # no longer 'not recognised' there
    skipped += [{"path": p.relative_to(run_dir).as_posix(), "reason": JOINED, "header_matches_schema": kinds.get(p)}
                for p in sorted(joined_files)]
    # ... except the clock probe beside the gateway files (E9, cell g): with it the run gets its end-to-end latency
    gateway_probes = {}  # functional directory -> its clock_probe file
    for p in paths:
        if kinds[p] == "clock_probe" and p.parent in functional_runs and gateway_probes.setdefault(p.parent, p) != p:
            raise ValueError(f"{p.parent}: more than one clock_probe file ({gateway_probes[p.parent].name}, {p.name})")
    skipped += [{"path": p.relative_to(run_dir).as_posix(), "reason": NOT_TIMED, "header_matches_schema": kinds[p]}
                for p in paths if p.parent in functional_runs and p not in gateway_files
                and kinds[p] not in ("clock_probe", "clock_map")]  # the probe's files are read with the run (below)
    paths = [p for p in paths if p.parent not in functional_runs]
    # the load generator's own periodic_tx / periodic_rx log beside an attack run, a throughput run or the bytes-per-PDU
    # calibration is not a periodic experiment: it is listed and its rows are never read (run_dir is resolved, so this
    # also holds when that directory is analysed)
    def inside(p, *words):
        """The outermost directory, from the run directory down to the file's own, whose name starts with one of `words`."""
        dirs = [d for d in (p.parent, *p.parent.parents) if run_dir in (d, *d.parents)]
        return next((d for d in reversed(dirs) if re.split("[_-]", d.name)[0] in words), None)

    # the handshake files of a negative handshake test (hstest/, or hstest/r001/ ... for a batch): counted per side and
    # result, never timed, and neither a handshake experiment nor a set-up handshake
    negative = {}
    for p in paths:
        if kinds[p] == "handshake" and inside(p, "hstest"):
            negative.setdefault(inside(p, "hstest"), []).append(p)
    in_test = {p for files in negative.values() for p in files}
    logs = {p: TRAFFIC_LOG for p in paths if kinds[p] in ("periodic_tx", "periodic_rx")
            and (re.split("[_-]", p.parent.name)[0] in ("attack", "throughput", "calibration") or inside(p, "hstest"))}
    # likewise the handshake before a ladder step, a calibration ladder or an attack run, in that directory or in a
    # subdirectory of it (throughput/handshake_100pps_rep1/handshake_tx.csv): session set-up, not a handshake experiment.
    # So is the one handshake before a periodic run (a periodic file beside it) and any handshake file whose header
    # says that a PDU stream ran beside the handshakes; a file without the pdu_stream line does not say so
    def setup_handshake(p):
        return bool(inside(p, "attack", "throughput", "calibration")
                    or any(q.parent == p.parent and kinds[q] in ("periodic_tx", "periodic_rx") for q in paths)
                    or csvio.read_meta(p).get("pdu_stream", "none") != "none")

    logs.update({p: SETUP_HANDSHAKE for p in paths if kinds[p] == "handshake" and p not in in_test and setup_handshake(p)})
    skipped += [{"path": p.relative_to(run_dir).as_posix(), "reason": logs[p], "header_matches_schema": kinds[p]}
                for p in paths if p in logs]
    paths = [p for p in paths if p not in logs and p not in in_test]
    found = csvio.markers(run_dir)  # DRY_RUN, PILOT or EXCLUDED in, above or below the run directory: nothing here is a result
    marked = found[0] if found else None
    marker = marked[0] if marked else None
    # read before any data: the margin must exist before overhead_paired is looked at
    # ... unless every paired file is an A/A noise-floor file: the campaign measures that block in a run directory of
    # its own, before the margin is written into the directory of the A/B block
    compared = [p for p in paths if kinds[p] == "overhead_paired" and csvio.read_meta(p).get("mode") != "aa"]
    margin = overhead.read_margin(run_dir, marker) if compared else None
    margin_file = run_dir / overhead.MARGIN_FILE
    margin_info = None if margin is None else {
        "file": overhead.MARGIN_FILE, "value": margin, "sha256": hashlib.sha256(margin_file.read_bytes()).hexdigest(),
        # the comment lines say where the margin comes from (the A/A block it was derived from)
        "comments": [s.strip().lstrip("#").strip() for s in margin_file.read_text().splitlines() if s.strip().startswith("#")]}

    def rel(p):
        return p.relative_to(run_dir).as_posix()

    def src(p):
        return {"source": rel(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}

    def rng(p):  # one stream per file, so adding a file never changes another file's numbers
        return np.random.default_rng([seed, zlib.crc32(rel(p).encode())])

    def at(p, fn, *args, **kw):  # analysis errors name the offending file
        try:
            return fn(*args, **kw)
        except csvio.CsvError:
            raise
        except ValueError as e:
            raise ValueError(f"{p}: {e}") from e

    envs = {}  # host -> get_throttled readings of env_<host>.txt; they judge every timing file of that host
    for e in sorted(run_dir.glob("env_*.txt")):
        env = {**csvio.read_env(e), "file": rel(e)}
        envs[env["host"]] = env

    def receiver_goes_with(p, reasons, pair=()):
        """The receiver's file of an invalid periodic sender `p` is invalid with it (one rule, one list, both
        directions): listed once, with its own reasons and, when the sender fails by itself (`reasons` beyond the
        ones in `pair`, which the receiver gave it), with one that names the sender's file."""
        rx_p = p.with_name(p.name.replace("periodic_tx", "periodic_rx", 1))
        if kinds.get(rx_p) != "periodic_rx":
            return
        rx_meta, own = csvio.read_meta(rx_p), [r for r in reasons if r not in pair]
        rx_checks = csvio.validity(rx_meta, "periodic_rx", envs.get(rx_meta.get("host")))
        invalid.append({**src(rx_p), "experiment": "periodic_rx", "mode": None, **failed(rx_checks, [
            f"the sender's file of this pair, {p.name}, is invalid ({own[0]}): the pair is invalid as a pair"] if own else [])})
        bad_rx.add(rx_p)

    res = {k: [] for k in KINDS}
    fig = {"sign": [], "response": [], "tail": [], "attrib": []}
    configs, tput, invalid, launches, bad_rx = [], {}, [], {}, set()
    for p in paths:
        if kinds[p] in ("periodic_rx", "clock_offset", "clock_probe", "clock_map"):
            continue  # read together with their periodic_tx file below
        try:
            kind, meta, cols = csvio.load(p)
        except csvio.CsvError as e:
            # a harness run killed while writing leaves a cut row and no trailer: that is an invalid run to report,
            # not a reason to lose every other table; a malformed row in a finished file stays a hard error
            meta = csvio.read_meta(p)
            checks = csvio.validity(meta, kinds[p], envs.get(meta.get("host"))) if kinds[p] in GATED else None
            if not checks or checks["valid"]:
                raise
            reasons = checks["reasons"] + [f"unreadable row: {str(e).replace(str(p), p.name)}"]
            invalid.append({**src(p), "experiment": kinds[p], "mode": meta.get("mode"), **checks, "reasons": reasons})
            if kinds[p] == "periodic_tx":
                receiver_goes_with(p, reasons)
            continue
        meta, no_log = transport_lines(p, kind, meta)
        joined_attack = kind == "attack" and "tool" in meta  # the join script's file, with either oracle
        checks = at(p, csvio.validity, meta, kind, envs.get(meta.get("host"))) if kind in GATED or joined_attack else None
        pair = []  # what the other end of a periodic pair adds to the sender's reasons
        if kind == "periodic_tx":
            # a pair, the transmitter's and the receiver's file of one run, is one connection with one configuration:
            # when the receiver's end does not read tcp_nodelay=1 the pair is invalid as a pair. A harness sender's file
            # without a receiver's file must carry the read-back of the receiving end itself
            rx_p = p.with_name(p.name.replace("periodic_tx", "periodic_rx", 1))
            rx_meta = csvio.read_meta(rx_p) if kinds.get(rx_p) == "periodic_rx" else None
            if rx_meta is None:
                if "tool" in meta and meta.get("tcp_nodelay_rx") != "1":
                    said = "no tcp_nodelay_rx line" if "tcp_nodelay_rx" not in meta else f"tcp_nodelay_rx={meta['tcp_nodelay_rx']}"
                    pair = [f"no receiver's file {rx_p.name} beside it and {said}: the receiving end of the connection was "
                            "not read back as 1"]
            elif "tool" in rx_meta and (rx_fails := [r for r in csvio.transport(rx_meta, "periodic_rx") if "tcp_nodelay" in r]):
                pair = [f"the receiver's file of this pair, {rx_p.name}, does not read tcp_nodelay=1 ({rx_fails[0]}): "
                        "a pair is one connection and is invalid as a pair"]
            if pair:
                checks = failed(checks, pair)
        if joined_attack:  # fail closed: the generator's traffic log must say that every started job was confirmed
            log = p.with_name("periodic_tx.csv")
            if unconfirmed := csvio.jobs(csvio.read_meta(log), log.name) if log.is_file() else [NO_ATTACK_LOG]:
                checks = failed(checks, unconfirmed)
            # ... and the receiver's log is one of the two files of the join (harness as oracle): one that lost rows or
            # does not hold the rows it counts spoils it; a generator's log that was stopped early means a run cut short
            if spoiled := [r for q in (log, p.with_name("periodic_rx.csv")) if q.is_file()
                           for r in csvio.footer(csvio.read_meta(q), rows=csvio.data_rows(q), log=q.name)]:
                checks = failed(checks, spoiled)
        # why a line is missing: the note goes to the first of these reasons that the file has
        start = next((s for s in ("no tcp_nodelay line", "jobs_started / jobs_confirmed missing")
                      if checks and no_log and any(r.startswith(s) for r in checks["reasons"])), None)
        if start:
            checks["reasons"] = [r + "; " + no_log if r.startswith(start) else r for r in checks["reasons"]]
        broken = at(p, sign_attrib.consistency, meta, cols) if kind == "sign_attrib" else \
            at(p, throughput.consistency, cols) if kind == "throughput" else \
            periodic.consistency(meta, cols) if kind == "periodic_tx" else None
        if kind in csvio.NETWORKED:  # the files that carry such lines; a single-node or legacy file is not read for them
            broken = [*(broken or []), *csvio.footer(meta, kind, next(iter(cols.values())).size)]
        if broken:
            # rows that contradict the file itself make it invalid like a failed self-check
            checks = failed(checks, broken)
        if kind == "throughput" and not broken and (clamps := throughput.one_tick_clamps(cols)):
            # reported, not judged: a file without harness lines gets a validity line for it
            checks = {"valid": True, "reasons": [], "warnings": [], "throttled": None, **(checks or {})}
            checks["warnings"] = [*checks["warnings"], f"{clamps} of {cols['t_ns'].size - 1} sample steps with busy one tick "
                                  "above total, counted as fully busy"]
        if checks and not checks["valid"]:
            invalid.append({**src(p), "experiment": kind, "mode": meta.get("mode"), **checks})
            if kind == "periodic_tx":
                receiver_goes_with(p, checks["reasons"], pair)
            continue  # reported, never analysed: no tables, no number keys
        own = {**src(p), "validity": checks, "header": meta} if kind in CHECKED else None
        if kind == "crypto_ops":
            ops = at(p, crypto_ops.analyse, cols, warmup=warmup, block_len=block_len, n_boot=n_boot,
                     thresholds_ms=thresholds_ms, rng=rng(p))
            res[kind].append({**own, "warmup": warmup, "ops": ops})
            fig["sign"] += [(f"{rel(p)}: {o['op']}", crypto_ops.samples(cols, o["op"], warmup) / 1e3)
                            for o in ops if "exceedance" in o]
            fig["tail"] += [(f"{rel(p)}: {o['op']}", crypto_ops.samples(cols, o["op"], warmup) / 1e3, o["tail"]["fit"])
                            for o in ops if "tail" in o]
        elif kind == "sign_attrib":
            r = at(p, sign_attrib.analyse, meta, cols, warmup, block_len=block_len, n_boot=n_boot, rng=rng(p))
            res[kind].append({**own, "warmup": warmup, "counted": "shake_calls" in cols, **r})
            if r["rounds"] and r["rounds"]["fit"]:
                keep = cols["seq"] >= warmup
                fig["attrib"].append((rel(p), sign_attrib.rounds_of(meta, cols)[keep], cols["cpu_ns"][keep] / 1e3, r["rounds"]["fit"]))
        elif kind == "overhead_paired":
            floor, launch = meta.get("mode") == "aa", at(p, launch_id, meta, p)
            block = {**own, "mode": meta.get("mode"), "launch": launch, "warmup": warmup, "margin": None if floor else margin,
                     "margin_source": None if floor else overhead.MARGIN_FILE,
                     "ops": at(p, overhead.analyse_paired, cols, margin, warmup, floor)}
            res[kind].append(block)
            if launch is not None:  # one launch of a set: the set is analysed below, with the launch as the unit
                launches.setdefault((p.parent, meta.get("mode")), []).append((launch, meta, cols, block))
        elif kind == "overhead_unpaired":
            res[kind].append({**src(p), "ops": at(p, overhead.analyse_unpaired, cols, warmup, LEGACY_MARGINS, block_len, n_boot,
                                                  rng(p))})
        elif kind == "periodic_tx":
            configs.append({"p": p, "cols": cols, "res": {**src(p), "validity": checks, **at(p, periodic.analyse_tx, meta, cols),
                                                         "transport": at(p, csvio.transport_counts, meta)}})
        elif kind == "throughput":
            cfg = at(p, throughput.config, meta)  # files of one directory with the same header form one ladder
            if "rep" not in cfg and (m := REP.search(make_numbers.file_label(p.name))):
                cfg["rep"] = int(m[1])  # the header's '# rep=' line wins over the file name, as for launches
            # the partitions (gateway processes) and the repetitions of a ladder belong together
            ladder = (p.parent, *(v for k, v in cfg.items() if k not in ("partition", "rep")))
            cfg["transport"] = at(p, csvio.transport_counts, meta)  # the window counts of this file's connection
            tput.setdefault(ladder, []).append((p, cfg, cols, checks))
        elif kind == "attack":
            res[kind].append({**src(p), "legacy": "legacy" in meta, "oracle": meta.get("oracle"),
                              "vectors": at(p, attack.analyse, cols, meta.get("oracle") != attack.UNTIMED_ORACLE)})
        elif kind == "handshake":
            res[kind].append({**src(p), "validity": checks, "host": meta.get("host"),
                              "header": {k: meta[k] for k in handshake.HEADER if k in meta},
                              "roles": at(p, handshake.analyse, cols)})

    # the fitted decay of the longest series of an op, applied to every signing series of the run: how many calls
    # above each series' largest value does it predict among that series' calls
    fits = {}  # op -> (n, file, fit)
    for f in res["crypto_ops"]:
        for o in f["ops"]:
            fit = (o.get("tail") or {}).get("fit")
            if fit and o["time_us"]["n"] > fits.get(o["op"], (0,))[0]:
                fits[o["op"]] = (o["time_us"]["n"], f["source"], fit)
    for f in res["crypto_ops"]:
        for o in f["ops"]:
            if "exceedance" in o and o["op"] in fits:
                _, source, fit = fits[o["op"]]
                top, calls = o["time_us"]["max"] / 1e3, o["time_us"]["n"]
                o["tail_expected"] = {"fit_source": source, "above_ms": top, "calls": calls,
                                      "expected_count": crypto_ops.tail_expected(fit, top, calls)}

    for (d, mode), members in launches.items():
        members.sort(key=lambda m: m[0])
        ids = [m[0] for m in members]
        if len(set(ids)) != len(ids):
            raise ValueError(f"{d}: launch number {next(i for i in ids if ids.count(i) > 1)} appears in more than one "
                             f"{mode or ''} file of the set")
        for key in ("commit", "host", "msg_bytes"):
            values = sorted({str(m[1].get(key)) for m in members})
            if len(values) > 1:
                raise ValueError(f"{d}: the launches of one set must share '{key}', found {values}")
        floor = mode == "aa"
        own = make_numbers.paired_label(f"{rel(d)}/overhead_paired.csv" if d != run_dir else "overhead_paired.csv", mode)
        for f in res["overhead_paired"]:  # a file without a launch number that would take the keys of the pooled set
            if f["launch"] is None and (run_dir / f["source"]).parent == d and \
                    make_numbers.paired_label(f["source"], f["mode"]) == own:
                raise ValueError(f"{run_dir / f['source']}: this file has no launch number but sits beside the launches of "
                                 "a set, whose pooled result has the same number keys; give it a '# launch=' line, a file "
                                 "label, or its own directory")
        pooled = {k: np.concatenate([m[2][k] for m in members]) for k in members[0][2]}
        res["overhead_launch_sets"].append({
            "source": rel(d) if d != run_dir else ".", "mode": mode, "warmup": warmup, "margin": None if floor else margin,
            "files": [m[3]["source"] for m in members], "n_launches": len(members),
            "n_invalid_launches": sum(1 for f in invalid if f["experiment"] == "overhead_paired" and f["mode"] == mode
                                      and (run_dir / f["source"]).parent == d),
            "pooled": at(d, overhead.analyse_paired, pooled, margin, warmup, floor),
            "across_launch": overhead.across_launches([(m[0], m[3]["ops"]) for m in members], margin, floor)})

    for p in cyclic:
        meta, counts, lines = cyclictest.read(p)
        r = at(p, cyclictest.analyse, meta, counts, lines, envs.get(meta.get("host")))
        if r["validity"]["valid"]:
            res["cyclictest"].append({**src(p), **r})
        else:
            invalid.append({**src(p), "experiment": "cyclictest", "mode": None, **r["validity"]})

    probe_read = {}  # probe file -> (its columns or None, the reasons the file itself gives, its comment lines)

    def probe_of(probe_p):
        """(columns, reasons, comment lines) of a clock probe's file. Its own count of its rows is judged as in every
        file (exchanges_completed must be the number of rows), and a file without that line is invalid. A file that
        cannot be read and has no footer is what a killed probe leaves (a cut row, or nothing at all): a reason, and no
        columns; in a file that has its footer an unreadable row stays an error."""
        if probe_p not in probe_read:
            meta = csvio.read_meta(probe_p)
            reasons = [] if "exchanges_completed" in meta else ["no exchanges_completed line: the probe did not write its footer"]
            try:
                cols = csvio.read_csv(probe_p, "clock_probe")[1]
                reasons += csvio.footer(meta, "clock_probe", cols["seq"].size)
                fmt = "2" if e2e.RAW_COLUMNS[0] in cols else "1"   # format 2 carries the raw stamps (Addendum E)
                if meta.get("format", "1") != fmt:
                    reasons.append(f"the header says format={meta.get('format')}, but the columns are those of format {fmt}")
            except csvio.CsvError as e:
                if not reasons:
                    raise
                cols, reasons = None, [*reasons, f"unreadable row: {str(e).replace(str(probe_p), probe_p.name)}"]
            probe_read[probe_p] = (cols, reasons, meta)
        return probe_read[probe_p]

    maps_read, maps_used = {}, set()  # probe file -> (the two maps or None, the reasons their files give); map files read

    def maps_of(probe_p):
        """(the columns of clock_map_a.csv and clock_map_b.csv beside a probe file of format 2, under 'a' and 'b', or
        None; the reasons these files give). A file that is missing, that did not get its footer (samples,
        samples_dropped), whose count of its samples is not the number of its rows or that lost samples is a reason;
        an unreadable row is one in a file without footer and an error in one that has it, as for the probe file.
        The three files must be those of one run (E12.2): each map's role that of its file name, its host the probe
        file's host_a or host_b, one commit in all three, and the clock lines as E2 has them (PROBE_LINES, MAP_LINES);
        a line that is missing is not what it must be."""
        if probe_p not in maps_read:
            maps, reasons, of_probe, commits = {}, [], probe_of(probe_p)[2], {}
            reasons += [f"{probe_p.name}: {key}={of_probe.get(key)}, not {must}" for key, must in PROBE_LINES if of_probe.get(key) != must]
            for x in "ab":
                p = probe_p.with_name(f"clock_map_{x}.csv")
                if not p.is_file():
                    reasons.append(f"{p.name} is missing beside the probe file of format 2")
                    continue
                maps_used.add(p)
                meta = csvio.read_meta(p)
                commits[p.name] = meta.get("commit")
                own = [] if "samples" in meta else ["no samples line: the probe did not write its footer"]
                if meta.get("role") != x:
                    own.append(f"role={meta.get('role')}, but the file name says role {x}")
                if meta.get("host") != of_probe.get(f"host_{x}"):
                    own.append(f"host={meta.get('host')}, but {probe_p.name} says host_{x}={of_probe.get(f'host_{x}')}")
                own += [f"{key}={meta.get(key)}, not {must}" for key, must in MAP_LINES if meta.get(key) != must]
                try:
                    maps[x] = csvio.read_csv(p, "clock_map")[1]
                    own += csvio.footer(meta, "clock_map", maps[x]["mono_ns"].size)
                except csvio.CsvError as e:
                    if not own:
                        raise
                    own.append(f"unreadable row: {str(e).replace(str(p), p.name)}")
                if "samples" in meta and meta.get("samples_dropped") != "0":
                    own.append("no samples_dropped line" if "samples_dropped" not in meta else
                               f"samples_dropped={meta['samples_dropped']}: the probe lost samples of the map")
                reasons += [f"{p.name}: {why}" for why in own]
            if len(commits) == 2 and len({of_probe.get("commit"), *commits.values()}) > 1:
                reasons.append("the commit lines of the three probe files differ: " + ", ".join(
                    f"{name} {commit}" for name, commit in ((probe_p.name, of_probe.get("commit")), *commits.items())))
            maps_read[probe_p] = (None if reasons else maps, reasons)
        return maps_read[probe_p]

    def probed_with(probe_p):
        """(exchanges, maps, the reasons the files give) of a probe file. The maps are read for a file of format 2
        only; when they cannot be used there are no exchanges to analyse either."""
        exchanges, reasons, _ = probe_of(probe_p)
        if exchanges is None or e2e.RAW_COLUMNS[0] not in exchanges:
            return exchanges, None, reasons
        maps, more = maps_of(probe_p)
        return (None if maps is None else exchanges), maps, reasons + more

    run_wide = {}  # directory of periodic files -> (the unrelated flow's figures or None, reasons against the e2e keys)

    def beside(d):
        """What the driver wrote about the run of the periodic files in `d`, there or one directory above (the run
        directory), never outside the directory being analysed: the record of the unrelated flow (cell i) and the
        markers that make the run no result for E9."""
        if d not in run_wide:
            flow, reasons = None, []
            for q in (q for q in (d, d.parent) if run_dir in (q, *q.parents)):
                if flow is None and not reasons and (q / e2e.BG_NAME).is_file():
                    try:
                        flow = {**src(q / e2e.BG_NAME), **e2e.background(q / e2e.BG_NAME)}
                        reasons += [f"{e2e.BG_NAME}: verdict={flow['verdict_line']}"] if flow["verdict"] != "PASS" else []
                    except ValueError as e:
                        reasons.append(f"{e2e.BG_NAME}: {e}")
                for name in e2e.MARKERS:
                    if (q / name).is_file():
                        text = (q / name).read_text(errors="replace").strip()
                        reasons.append(f"marker {name} in the run directory: {text.splitlines()[0] if text else '(empty)'}")
            run_wide[d] = (flow, reasons)
        return run_wide[d]

    for d, files in probetests.items():  # counted against what the estimator promises; nothing here is a latency
        read, test = {}, {"source": rel(d) if d != run_dir else ".", "zero": [], "pair": None}
        for p in files:
            cols, reasons, meta = probe_of(p)
            reasons = list(reasons)
            if cols is not None and cols["seq"].size < 2:
                reasons.append(f"{cols['seq'].size} completed exchange(s) in the probe file: fewer than two")
            raw = cols is not None and e2e.RAW_COLUMNS[0] in cols  # format 2: the test is made on the raw stamps
            cols = e2e.raw_stamps(cols) if raw else cols
            try:
                if cols is not None and not reasons:
                    e2e.track(cols)
            except ValueError as e:
                reasons.append(f"the probe file contradicts itself: {e}")
            if p.name.startswith("zero_") and meta.get("host_a") != meta.get("host_b"):
                reasons.append(f"host_a={meta.get('host_a')} and host_b={meta.get('host_b')}: not a same-host test")
            if reasons:
                invalid.append({**src(p), "experiment": "probetest", "mode": None, **failed(None, reasons)})
            else:
                read[p.name] = (p, {**meta, "raw": raw}, cols)
        for name, (p, meta, cols) in read.items():
            if name.startswith("zero_"):
                test["zero"].append({**src(p), "host": meta.get("host_a") or p.stem.removeprefix("zero_"), **e2e.same_host(cols)})
        if "pair_ab.csv" in read and "pair_ba.csv" in read:
            (pa, ma, ca), (pb, mb, cb) = read["pair_ab.csv"], read["pair_ba.csv"]
            if (ma.get("host_a"), ma.get("host_b")) != (mb.get("host_b"), mb.get("host_a")):
                invalid.append({**src(pb), "experiment": "probetest", "mode": None, **failed(None, [
                    f"pair_ab.csv runs from {ma.get('host_a')} to {ma.get('host_b')}, pair_ba.csv from {mb.get('host_a')} to "
                    f"{mb.get('host_b')}: not the two directions of one pair"])})
            elif ma["raw"] != mb["raw"]:
                invalid.append({**src(pb), "experiment": "probetest", "mode": None, **failed(None, [
                    "pair_ab.csv and pair_ba.csv are of different probe formats: one has raw stamps, the other has none"])})
            else:
                test["pair"] = {"source": f"{rel(pa)} + {rel(pb)}", **e2e.two_directions(ca, cb)}
        if test["zero"] or test["pair"]:
            res["probetest"].append(test)

    for p, builds in sizes.items():
        res["footprint"].append({"what": "size", **src(p), "label": p.stem.removeprefix("size_"), "builds": builds})
    runs_of = {}  # (directory, operation) -> number of calls -> perf file
    for p in perfs:
        op, calls = footprint.PERF_NAME.fullmatch(p.name).groups()
        runs_of.setdefault((p.parent, op), {})[int(calls)] = p
    for (_, op), runs in runs_of.items():
        if op in footprint.PER_CALL and len(runs) == 2:
            res["footprint"].append({"what": "perf", "op": op, "source": " + ".join(rel(runs[n]) for n in sorted(runs)),
                                     "runs": [{"calls": n, **perfs[runs[n]]} for n in sorted(runs)],
                                     **at(runs[min(runs)], footprint.per_call, {n: perfs[p] for n, p in runs.items()})})
        else:
            skipped += [{"path": rel(p), "reason": footprint.NOT_PER_CALL, "header_matches_schema": None} for p in runs.values()]
    for p, hosts in rsses.items():
        res["footprint"].append({"what": "rss", **src(p), "hosts": hosts})
    if captures:  # counts of a packet capture (calibration run): keys only
        res["capture"] = [{**src(p), "host": p.stem.removeprefix("capture_"), **c} for p, c in captures.items()]

    rx_left = {p for p in paths if kinds[p] == "periodic_rx"} - bad_rx
    clocks = {}  # directory -> its clock_offset file; it serves the periodic_rx files of that directory
    for p in paths:
        if kinds[p] == "clock_offset" and clocks.setdefault(p.parent, p) != p:
            raise ValueError(f"{p.parent}: more than one clock_offset file ({clocks[p.parent].name}, {p.name})")
    clock_used = set()
    # E9: the clock probe of a directory serves its sender / receiver pairs; the run is a result for E9 as a whole or not
    probes, probed = {}, {}  # directory -> its clock_probe file; probe file -> [(periodic result, figures, reasons)]
    records = {}             # probe file -> what its maps say, per pair
    for p in paths:
        if kinds[p] == "clock_probe" and probes.setdefault(p.parent, p) != p:
            raise ValueError(f"{p.parent}: more than one clock_probe file ({probes[p.parent].name}, {p.name})")
    def cell_of(r):
        """What the files of one periodic cell have in common: directory, file label without the partition, header."""
        return (Path(r["source"]).parent.as_posix(), PART.sub("", make_numbers.file_label(r["source"])), tuple(r.get(k) for k in CELL))

    cols_of = {c["res"]["source"]: c["cols"] for c in configs}  # the rows of every sender file, for a cell's own figure
    pinned = {}  # cell -> where its processes say they were pinned
    for c in configs:
        if c["res"].get("partition") is not None and c["res"].get("cpu_affinity"):
            pinned.setdefault(cell_of(c["res"]), []).append(c["res"]["cpu_affinity"])

    def shares_a_core(r):
        """A sender process of a cell in which fewer cores than processes were used (two of them say the same cpu_affinity)."""
        at_cores = pinned.get(cell_of(r), []) if r.get("partition") is not None else []
        return len(set(at_cores)) < len(at_cores)

    for c in configs:
        p, r = c["p"], c["res"]
        if shares_a_core(r):  # between start_ns and auth_done_ns another process of the cell may have held the core
            r["auth_utilisation"] = None
        if beside(p.parent)[0]:
            r["bg"] = beside(p.parent)[0]
        rx_p = p.with_name(p.name.replace("periodic_tx", "periodic_rx", 1))
        rx_meta, rx_cols = csvio.load(rx_p)[1:] if rx_p in rx_left else (None, None)
        rx_checks = at(rx_p, csvio.validity, rx_meta, "periodic_rx", envs.get(rx_meta.get("host"))) if rx_meta is not None else None
        if rx_meta is not None and (spoiled := csvio.footer(rx_meta, "periodic_rx", next(iter(rx_cols.values())).size)):
            rx_checks = failed(rx_checks, spoiled)
        rx_left.discard(rx_p)
        if rx_checks and not rx_checks["valid"]:  # the receiver file is out; the sender side stands on its own
            invalid.append({**src(rx_p), "experiment": "periodic_rx", "mode": None, **rx_checks})
        elif rx_meta is not None:
            clock_p = clocks.get(rx_p.parent)
            clock = csvio.load(clock_p)[2] if clock_p else None
            r["rx"] = {**src(rx_p), "validity": rx_checks, **at(rx_p, periodic.analyse_rx, c["cols"], rx_cols, clock, rx_meta)}
            if clock_p:
                clock_used.add(clock_p)
            if r["rx"]["latency"]:
                r["rx"]["latency"].update(clock_source=rel(clock_p), clock_sha256=src(clock_p)["sha256"])
            if probe_p := probes.get(rx_p.parent):
                exchanges, maps, _ = probed_with(probe_p)
                record = {}  # what the maps say, kept in summary.json also when the run is not a result (E11 j)
                across = (None, []) if exchanges is None else \
                    (None, [f"rx_done_ns is declared not recorded in {rx_p.name}: the causality rule cannot be judged"]) \
                    if r["rx"]["not_recorded"] else at(probe_p, e2e.analyse, c["cols"], rx_cols, exchanges, maps, record=record)
                probed.setdefault(probe_p, []).append((r, *across))
                if record:
                    records.setdefault(probe_p, []).append({"pair": r["source"], **record})
        # service times for the model: an uncontended (single-stream) run of the same setup if there is one
        same = ("profile", "scheduler", "payload_bytes", "host", "mainfunction", "mf_period_us")
        alone = [o for o in configs if o["res"]["streams"] == 1 and all(o["res"].get(k) == r.get(k) for k in same)]
        ref = max(alone, key=lambda o: o["res"]["period_us"], default=c)
        service = periodic.service_ns(ref["cols"])
        # the model draws one service time for every stream, and gives a process a core of its own: not for a file with
        # both variants, and not for a process that shares its core with another process of its cell (E9_SPEC.md, H4)
        if sim_draws and service.size and r["profile"] != "both" and not shares_a_core(r):
            period = round(r["period_us"] * 1e3)
            r["model"] = {**simulate.model(service, period, r["streams"], r["cores"], deadline=r["deadline_us"] * 1e3,
                                           rng=rng(p), draws=sim_draws, jobs=sim_jobs,
                                           measured_offsets=periodic.release_offsets_ns(c["cols"], period),
                                           measured_jobs=r["jobs"]),
                          "service_source": ref["res"]["source"],
                          "service_note": "send_done_ns - start_ns of a single-stream run" if alone else
                          "send_done_ns - start_ns of this run; may already include contention between streams"}
        fig["response"].append((r["source"], periodic.response_ns(c["cols"]) / 1e3, r["deadline_us"]))
        res["periodic"].append(r)
    for probe_p, pairs in probed.items():
        several = len(pairs) > 1  # a reason of one pair names it when the directory has more than one
        reasons = probed_with(probe_p)[2] + beside(probe_p.parent)[1] + list(dict.fromkeys(
            why + (f" ({Path(r['source']).name})" if several else "") for r, _, whys in pairs for why in whys))
        if reasons:  # listed, no e2e key; the pair's own periodic keys stand
            invalid.append({**src(probe_p), "experiment": "e2e", "mode": None, **failed(None, reasons),
                            **({"record": records[probe_p]} if probe_p in records else {})})
        else:
            for r, figures, _ in pairs:
                r["e2e"] = {**src(probe_p), **figures}
    skipped += [{"path": rel(p), "reason": "clock_probe file not used: no analysed periodic_rx file in its directory",
                 "header_matches_schema": "clock_probe"} for p in sorted(set(probes.values()) - set(probed))]
    cells = {}  # (directory, file label without the partition, common header) -> partition -> result
    for r in res["periodic"]:
        if r.get("partition") is not None:
            cells.setdefault(cell_of(r), {}).setdefault(r["partition"], r)
    for (d, label, _), members in cells.items():
        first = members[min(members)]
        expected = range(first.get("partitions") or max(members) + 1)
        if max(members) not in expected:
            raise ValueError(f"{run_dir / members[max(members)]['source']}: partition {max(members)} in a cell of "
                             f"partitions={len(expected)}")
        if len(expected) > 1:  # one process is not a cell of partitions (the harness writes partition=0 in every file)
            missing = [i for i in expected if i not in members]  # not on file, or invalid and so not analysed
            # one core, and every process recorded the end of the authentication and finished a job: the intervals of
            # a part of the processes would understate the core
            one_core = not missing and len({members[i].get("cpu_affinity") for i in expected}) == 1 and first.get("cpu_affinity") \
                and all(not members[i]["not_recorded"] and members[i]["jobs"] > members[i]["unfinished"] for i in expected)
            res["periodic_cells"].append({
                # all processes pinned to one core: the measured utilisation of that core by the authentication (below)
                **({"auth_utilisation": periodic.shared_utilisation([cols_of[members[i]["source"]] for i in expected])}
                   if one_core else {}),
                "source": d, "label": label, "files": [members[i]["source"] for i in sorted(members)],
                "expected_partitions": len(expected), "missing_partitions": missing,
                **{k: first.get(k) for k in CELL if k not in ("cores", "partitions")},
                **({} if missing else periodic.combine([members[i] for i in expected]))})
    skipped += [{"path": rel(p), "reason": "periodic_rx file without a matching periodic_tx file",
                 "header_matches_schema": "periodic_rx"} for p in sorted(rx_left)]
    skipped += [{"path": rel(p), "reason": "clock_offset file not used: no analysed periodic_rx file in its directory",
                 "header_matches_schema": "clock_offset"} for p in sorted(set(clocks.values()) - clock_used)]

    for (d, *_), files in tput.items():
        res["throughput"].append({"source": rel(d) if d != run_dir else ".",
                                  **{k: v for k, v in files[0][1].items() if k not in ("partition", "rep")},
                                  "files": [{**src(p), "validity": checks} for p, _, _, checks in files],
                                  **throughput.analyse([(rel(p), cfg, cols) for p, cfg, cols, _ in files], trim)})

    for d, (by_stem, _) in functional_runs.items():
        files, marker_file = [p for stem in functional.STEMS for p in by_stem[stem]], d / functional.MARKER
        reasons = functional.missing(by_stem)
        if reasons is None:
            reasons = [NO_FUNCTIONAL_RUN]
        elif not reasons:
            try:
                res["functional"].append({"source": rel(d), "files": [src(p) for p in files], **functional.analyse(by_stem)})
            except csvio.CsvError as e:  # these files have no trailer: a cut row is all a killed process leaves
                reasons = [f"cannot be read: {str(e).replace(str(d) + '/', '')}"]
            except functional.Invalid as e:
                reasons = e.reasons
        probe_p = gateway_probes.get(d)
        if reasons:
            invalid.append({**src(marker_file), "experiment": "functional", "mode": None, **failed(None, reasons)})
            skipped += [{"path": rel(p), "reason": FUNCTIONAL_INVALID, "header_matches_schema": None} for p in files]
            skipped += [{"path": rel(probe_p), "reason": FUNCTIONAL_INVALID, "header_matches_schema": "clock_probe"}] if probe_p else []
        elif probe_p:  # E9, cell g: the latency across the boards from the gateways' own time stamps
            exchanges, maps, whys = probed_with(probe_p)
            record = {}
            figures, more = (None, []) if exchanges is None else at(
                probe_p, e2e.analyse, *functional.e2e_columns(by_stem), exchanges, maps, e2e.CHECK_MIN_GATEWAY, record=record)
            if whys := whys + beside(d)[1] + more:  # listed, no e2e key; the counts of the run stand
                invalid.append({**src(probe_p), "experiment": "e2e", "mode": None, **failed(None, whys),
                                **({"record": [record]} if record else {})})
            else:
                res["functional"][-1]["e2e"] = {**src(probe_p), **figures}

    skipped += [{"path": rel(p), "reason": MAP_NOT_USED, "header_matches_schema": "clock_map"}
                for p in paths if kinds[p] == "clock_map" and p not in maps_used]

    for root, files in sorted(negative.items()):
        sides, checked, bad = {}, [], False
        for p in files:
            meta, cols = csvio.load(p)[1:]
            checks = at(p, csvio.validity, meta, "handshake", envs.get(meta.get("host")))
            log = p.with_name("periodic_tx.csv")  # the harness's traffic log, when the harness was the transmitting end
            unconfirmed = csvio.jobs(csvio.read_meta(log), log.name) if log.is_file() else []
            unconfirmed += csvio.footer(meta, "handshake", next(iter(cols.values())).size)
            if unconfirmed:
                checks = failed(checks, unconfirmed)
            if checks and not checks["valid"]:
                invalid.append({**src(p), "experiment": "handshake", "mode": None, **checks})
                bad = True
                continue
            checked.append({**src(p), "validity": checks})
            for role, c in handshake.counts(cols).items():
                side = sides.setdefault(role, {"n": 0, "results": {}})
                side["n"] += c["n"]
                for result, k in c["results"].items():
                    side["results"][result] = side["results"].get(result, 0) + k
        if bad:  # the counts of the files that are left are not the test
            skipped += [{"path": f["source"], "reason": NEGATIVE_INVALID, "header_matches_schema": "handshake"} for f in checked]
            continue
        record_p = root.parent / "hsneg.txt"  # the oracle's record, beside the hstest directory
        record_p = record_p if root != run_dir and record_p.is_file() else None
        record = hsneg.read(record_p) if record_p else None
        differ = hsneg.disagreement(record, sides, rel(root)) if record else []
        if differ:
            invalid.append({**src(record_p), "experiment": "hsneg", "mode": None, "valid": False, "reasons": differ,
                            "warnings": [], "throttled": None})
            continue
        res["hsneg"].append({"source": rel(root), "files": checked, "record_file": rel(record_p) if record_p else None,
                             "record": record, "sides": sides})

    res = _clean(res)
    params = {"warmup": warmup, "block_len": block_len, "n_boot": n_boot, "thresholds_ms": list(thresholds_ms),
              "trim": trim, "sim_draws": sim_draws, "sim_jobs": sim_jobs, "legacy_margins": list(LEGACY_MARGINS)}
    # every key is checked before anything is written
    numbers = make_numbers.collect(res, {"seed": seed, **params}, key_prefix)

    (out / "tables").mkdir(parents=True, exist_ok=True)
    written, written_csv = _write_tables(out / "tables", res, warmup, invalid, BANNER.get(marker), margin_info)

    fig_status = {"status": "disabled", "written": []}
    if figures:
        try:
            import matplotlib  # noqa: F401
        except ImportError:
            fig_status["status"] = "skipped: matplotlib is not installed"
        else:
            try:
                (out / "figures").mkdir(exist_ok=True)
                fig_status = {"status": "ok",
                              "written": figs.make_all(out / "figures", fig, res, thresholds_ms, BANNER.get(marker))}
            except Exception as e:  # figures are optional; a plotting error must not cost the tables
                fig_status["status"] = f"failed: {type(e).__name__}: {e}"
    for name in figs.NAMES:  # like the tables: a figure not drawn in this run is not left over from an earlier one
        if name not in fig_status["written"]:
            (out / "figures" / name).unlink(missing_ok=True)

    summary = _clean({
        "tool": "analysis.make_tables", "toolkit_commit": toolkit_commit(),
        "run_dir": run_dir.name, "seed": seed,  # name only: output is machine-independent
        "not_a_result": marker,  # the marker that labels the output (DRY_RUN, then PILOT, then EXCLUDED), else null
        "not_a_result_marker": os.path.relpath(marked[1], run_dir) if marked else None,
        "markers": [{"name": name, "path": os.path.relpath(path, run_dir),  # every marker found, with what it says
                     "text": path.read_text(encoding="utf-8", errors="replace").strip()} for name, path in found],
        "key_prefix": key_prefix, "params": params, "equivalence_margin": margin_info,
        "env": [{"file": e["file"], "host": e["host"], "throttled": [f"{label}: {text}" for label, text in e["throttled"]]}
                for e in envs.values()],
        "versions": {"python": platform.python_version(), "numpy": np.__version__, "scipy": scipy.__version__},
        "units": "keys ending in _us are microseconds; ratios and probabilities are fractions, not percent",
        "results": res, "invalid_runs": invalid, "skipped_csv": skipped, "tables": written, "tables_csv": written_csv,
        "figures": fig_status,
        "numbers": {"keys": len(make_numbers.defined(numbers)),  # defined in numbers.tex; numbers.csv has the held-back ones too
                    "suppressed": len(numbers) - len(make_numbers.defined(numbers)),
                    "files": ["numbers.tex", "numbers.csv", make_numbers.KEYS_FILE, make_numbers.SUPPRESSED_FILE]}})
    (out / "summary.json").write_text(json.dumps(summary, indent=1, allow_nan=False) + "\n", encoding="utf-8")
    make_numbers.write(out / "numbers.tex", numbers, summary)
    return summary


def _write_tables(out, res, warmup, invalid, banner=None, margin=None):
    """Write every table the results allow; returns the names of the .md / .tex tables and the file
    names of the tables that are written as CSV."""
    written, written_csv = [], []

    def table(name, headers, rows, note=""):
        if rows:
            tables.write(out, name, headers, rows, note, banner)
            written.append(name)
        else:  # a table this run does not have must not survive from an earlier run into the same directory
            for ext in ("md", "tex"):
                (out / f"{name}.{ext}").unlink(missing_ok=True)

    def f5(v):
        return tables.rounded(v, 5)

    def signed(v):
        return DASH if v is None else tables.rounded(v, 2, sign=True)

    def times_row(source, quantity, d, why):  # describe() of a time, or why there is none
        cols = ("mean", "p50", "p90", "p95", "p99", "p99.9", "max")
        return [source, quantity, d["n"], *(num(d.get(c)) for c in cols)] if d else [source, quantity, why, *[DASH] * len(cols)]

    def checks_row(source, experiment, v):
        def cell(k):
            return DASH if v.get(k) is None else v[k]

        status = "valid" if v["valid"] else "INVALID, not analysed: " + "; ".join(v["reasons"])
        return [source, experiment, status, cell("signature_mismatches"), cell("failed_calls"), cell("mlockall"),
                DASH if v.get("cpu_share") is None else tables.rounded(v["cpu_share"], 4), cell("freq_khz_start"), cell("freq_khz_end"),
                {None: "unknown", True: "yes", False: "no"}[v["throttled"]], "; ".join(v["warnings"]) or DASH]

    table("validity",
          ["file", "experiment", "status", "signature mismatches", "failed calls", "mlockall", "cpu_s/wall_s",
           "freq start (kHz)", "freq end (kHz)", "throttled", "warnings"],
          [checks_row(source, kind, v) for source, kind, v in (
              *((f["source"], kind, f["validity"]) for kind in (*CHECKED, "cyclictest") for f in res[kind]),
              *((f["source"], kind, f["validity"]) for r in res["periodic"]
                for kind, f in (("periodic_tx", r), ("periodic_rx", r.get("rx") or {"source": None, "validity": None}))),
              *((f["source"], "throughput", f["validity"]) for t in res["throughput"] for f in t["files"]),
              *((f["source"], "handshake", f["validity"]) for f in res["handshake"]),
              *((f["source"], "handshake", f["validity"]) for t in res["hsneg"] for f in t["files"])) if v]
          + [checks_row(f["source"], f["experiment"], f) for f in invalid],
          "self-checks of the timing files: a non-zero counter, a missing trailer, mlockall not ok, a frequency change, "
          "cpu_s/wall_s below " + f"{csvio.CPU_SHARE_MIN}" + " (single-node files only; a networked gateway process is idle "
          "between PDUs) or active or changed get_throttled bits (file or env_<host>.txt) "
          "make a file invalid; throttled: any bit seen, unknown = no numeric reading; a dash means the file does not say; "
          "sign_attrib files are also invalid when the cpu_ns of all rows differ from the footer's cpu_s by more than 1% "
          "(the footer also covers set-up, the probe calls of a counting run and the clock reads, so a counting run of "
          "only a few thousand calls fails the 1% rule by construction), when a row has wall_ns < cpu_ns - 2000, or when a "
          "count is off the progression; a throughput file is also invalid when, from one sample to the next, the busy "
          "jiffies go backwards or grow by 2 or more ticks more than the total jiffies (one tick more is rounding of the "
          "kernel's idle and iowait ticks: the step counts as fully busy and is counted in the warnings column); a "
          "periodic sender's file is also invalid when the job counts of its footer are not those of its rows; a "
          "networked file is invalid when the count of its rows that it carries (rows; pdus in an attack file) is not the number of "
          "its rows, or with rows_lost other than 0, stopped_early other than 0 or contradicting_pdus other than 0 (a "
          "line a file does not have is not judged); stopped_early of the traffic log beside a ladder file judges that "
          "file, and an attack file is judged by these lines and the row count of the traffic logs beside it (a ladder "
          "never reads the rows of a log, so rows a log lost do not touch a ladder file); a "
          "networked harness file is also invalid when tcp_nodelay does not read 1 (its own line, or that of the traffic "
          "log beside a ladder or attack file; a periodic pair as a pair), and a transmitter file when its connection was "
          "made again inside the window (tcp_connections_at_first_release differs from tcp_connections_at_end) or a "
          "started job was not confirmed (jobs_started differs from jobs_confirmed), or when it does not say; an attack "
          "file, and the handshake files of a negative test that have one, are judged by these two lines of the traffic "
          "log periodic_tx.csv beside them; the receiver's file of a periodic pair is invalid with its sender's file, and "
          "a harness sender's file without a receiver's file needs the line tcp_nodelay_rx=1; "
          "retransmissions and releases dropped at a full queue never make a file invalid")

    warm = f"times in µs; samples with seq < {warmup} dropped"
    ops = [(f["source"], o, o["time_us"]) for f in res["crypto_ops"] for o in f["ops"]]
    cols = ("mean", "sd", "min", "p50", "p90", "p95", "p99", "p99.9", "p99.99", "max")
    table("crypto_ops", ["file", "op", "n", "mean (µs)", *cols[1:], "CV", "lag-1"],
          [[s, o["op"], t["n"], *(num(t.get(c)) for c in cols), sig(t.get("cv")), sig(t.get("lag1"))] for s, o, t in ops],
          warm + "; percentiles are type 7 (linear interpolation)")
    table("crypto_ops_ci", ["file", "op", "n", "p50 (µs)", "p50 95% CI", "p99 (µs)", "p99 95% CI", "block", "replicates"],
          [[s, o["op"], t["n"], num(t["p50"]), ci(o["bootstrap"]["p50_ci95_us"]), num(t["p99"]),
            ci(o["bootstrap"]["p99_ci95_us"]), o["bootstrap"]["block_len"], o["bootstrap"]["n_boot"]]
           for s, o, t in ops if "bootstrap" in o], warm + "; moving-block bootstrap percentile intervals")
    table("exceedance", ["file", "op", "threshold (ms)", "k", "n", "P(t > d)", "Clopper-Pearson 95%"],
          [[s, o["op"], f"{e['threshold_ms']:g}", e["k"], e["n"], pct(e["p"]), ci(e["cp95"], pct)]
           for s, o, _ in ops for e in o.get("exceedance", [])],
          warm + "; exact two-sided interval for independent samples (Wilson is in summary.json)")

    table("sign_excess",
          ["file", "op", "n", "wall_s", "cpu_s", "wall - cpu (s)", "calls above 10 ms", "time beyond 10 ms in them (s)"],
          [[f["source"], o["op"], o["time_us"]["n"], (f.get("header") or {}).get("wall_s", DASH),
            (f.get("header") or {}).get("cpu_s", DASH), num(make_numbers.off_cpu_s(f.get("header")), 3),
            o["excess_over_10ms"]["calls"], num(o["excess_over_10ms"]["seconds"], 6)]
           for f in res["crypto_ops"] for o in f["ops"] if "excess_over_10ms" in o],
          "wall_s and cpu_s are the footer lines of the whole file (every operation in it, warm-up included); wall - cpu "
          "is the time the process was not on a processor in that whole file; the last two columns are the calls above "
          f"10 ms after the warm-up (seq >= {warmup}) and the sum of (t - 10 ms) over them")

    # tail shape of the long signing series: the counts as CSV (25 rows per series), the fit as a table
    tails = [(s, o, o["tail"]) for s, o, _ in ops if "tail" in o]
    expected = [(s, o, o["tail_expected"]) for s, o, _ in ops if "tail_expected" in o]
    counts_csv = out / "sign_tail_counts.csv"
    if tails:
        lines = ([f"# {banner}"] if banner else []) + ["file,op,n,threshold_ms,count_above,in_fit"]
        for s, o, t in tails:
            fit = t["fit"] or {"from_ms": 1, "to_ms": 0}
            lines += [f"{s},{o['op']},{o['time_us']['n']},{k},{c},{int(fit['from_ms'] <= k <= fit['to_ms'])}"
                      for k, c in zip(t["thresholds_ms"], t["counts_above"])]
        counts_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written_csv.append(counts_csv.name)
    else:
        counts_csv.unlink(missing_ok=True)
    def fit_cells(t):  # the columns of a series with its own tail output
        if not (f := t["fit"]):
            return [DASH, DASH, DASH, t["fit_note"], DASH, DASH]
        return [f["from_ms"], f["to_ms"], f["bins"], num(f["ratio_per_ms"], 4), ci(f["ratio_ci95"], lambda v: num(v, 4)),
                num(f["dispersion"])]

    def from_1ms(t):
        return [num(t["from_1ms"]["ratio_per_ms"], 4), num(t["from_1ms"]["dispersion"])] if t["from_1ms"] else [DASH, DASH]

    def expected_cells(s, o):  # which fit is applied, and what it predicts above the series' largest value
        e = o.get("tail_expected")
        return [DASH, DASH] if not e else ["own" if e["fit_source"] == s else e["fit_source"], sig(e["expected_count"], 5)]

    table("sign_tail_fit",
          ["file", "op", "n", "largest value (ms)", "fit from (ms)", "fit to (ms)", "1-ms bins", "ratio per ms", "95% interval",
           "dispersion", "ratio from 1 ms", "dispersion from 1 ms", "samples above fit end", "fit used",
           "expected count above the largest value"],
          [[s, o["op"], o["time_us"]["n"], num(t["max_ms"], 3), *fit_cells(t), *from_1ms(t),
            t["fit"]["above_fit_end"] if t["fit"] else DASH, *expected_cells(s, o)] for s, o, t in tails]
          + [[s, o["op"], o["time_us"]["n"], num(e["above_ms"], 3), *[DASH] * 9, *expected_cells(s, o)]
             for s, o, e in expected if "tail" not in o],
          warm + f"; series of at least {crypto_ops.TAIL_MIN_N} values get the counts above 1 .. 25 ms "
          "(sign_tail_counts.csv) and a fit; fit range: from the first whole millisecond above the series' median to the "
          f"last whole millisecond with at least {crypto_ops.TAIL_MIN_COUNT} samples above it; ratio per ms: the factor by "
          "which the count falls from one millisecond to the next; " + crypto_ops.TAIL_METHOD + "; a dispersion far above "
          "1 means the counts do not fall by a constant factor over the range; ratio and dispersion from 1 ms: the same "
          "fit started at 1 ms, as a sensitivity figure; last column: expected count above x ms under the fitted decay, "
          "for n calls, with x the largest value and n the number of calls of the row's series, and the fit named in "
          "'fit used' (own, or the longest series of the same operation in the run); beyond the fit end it continues "
          "the fitted decay; the fit-range rule was set on pilot data only, so the campaign sessions are untouched by it")

    # wall time against processor time of every signing call
    attrib = res["sign_attrib"]
    instrumented = "; a file with shake_calls is an instrumented run: its times include the counting"
    table("sign_attrib",
          ["file", "n", "median off (µs)", "largest off (µs)", "calls above the floor", "their off above the floor (s)",
           "calls with off > 100 µs", "> 1 ms", "> 5 ms", "rounds mean",
           "1 / one-round share", "one-round share", "rounds max", "cpu per round (µs)", "intercept (µs)", "r²",
           "residual sd (µs)"],
          [[f["source"], f["n"], num(f["off_median_us"]), num(f["off_max_us"]), f["off_above_floor"]["k"],
            num(f["off_above_floor"]["seconds"], 6), *(o["k"] for o in f["off_over"]),
            *([num(r["mean"], 4), num(r["geometric_mean"], 4), pct(r["one_share"], 4), r["max"],
               *([num(fit["cpu_per_round_us"]), num(fit["cpu_intercept_us"]), f5(fit["r2"]), num(fit["resid_us"]["sd"])]
                 if (fit := r["fit"]) else [DASH] * 4)] if (r := f["rounds"]) else [DASH] * 8)] for f in attrib],
          f"calls with seq >= {warmup}; off = wall_ns - cpu_ns of a call (by the schema the time the pinned thread did not "
          "run; how interrupt time is counted depends on the kernel, see the run record); every call carries a floor, "
          "shown by the median off (the two clock reads inside the wall interval: time on the processor), so the plain "
          "sum of off is not a time off the processor and is kept in summary.json and numbers.csv only; above the floor: "
          f"the calls whose off is more than {sign_attrib.FLOOR_MARGIN_US} µs above the median, and the sum of their off "
          "minus the median; rounds = (shake_calls - shake_calls_min) / shake_calls_step + 1; 1 / one-round share: the mean of a "
          "geometric law with the measured one-round share, next to the measured mean; line: ordinary least squares of "
          "processor time on rounds, residual sd with divisor n - 2" + instrumented)
    table("sign_attrib_tail",
          ["file", "wall time above (ms)", "calls", "of them with processor time above it too", "largest off among them (µs)",
           "fewest rounds among them", "calls of the sample with at least that many rounds"],
          [[f["source"], f"{w['threshold_ms']:g}", w["k"], w["cpu_also_over"], num(w["max_off_us"]),
            *(DASH if w[c] is None else w[c] for c in ("rounds_min", "rounds_min_or_more"))]
           for f in attrib for w in f["wall_over"]],
          f"calls with seq >= {warmup}; 'above' is strict; off = wall_ns - cpu_ns of a call; when the last column equals "
          "the number of calls above the threshold, 'wall time above it' and 'at least that many rounds' are the same "
          "set of calls")
    table("sign_attrib_two_by_two",
          ["file", "processor time above (ms)", "calls", "fewest rounds among them", "calls of the sample with at least that many rounds",
           "rounds threshold of the line", "both", "processor time only", "rounds only", "neither",
           "processor time only, below the crossing round", "rounds only, above the crossing round"],
          [[f["source"], f"{c['threshold_ms']:g}", c["k"],
            *(DASH if c[x] is None else c[x] for x in ("rounds_min", "rounds_min_or_more", "rounds_threshold", "both", "cpu_only",
                                                       "rounds_only", "neither", "cpu_only_below_crossing",
                                                       "rounds_only_above_crossing"))]
           for f in attrib if f["rounds"] for c in f["cpu_over"]],
          f"calls with seq >= {warmup}; 'above' is strict; the calls are taken by processor time, whatever their wall time; "
          "rounds threshold of the line: the smallest whole number of rounds for which the least-squares line of processor "
          "time on rounds is above the threshold; the four counts cover the whole sample: processor time above the threshold "
          "and at least that many rounds (both), processor time above it with fewer rounds (processor time only), at least "
          "that many rounds with processor time not above it (rounds only), neither; calls with exactly the rounds threshold, "
          "or one round fewer, fall on either side by where the line crosses the threshold within that round; the last two "
          "columns count the calls beyond that: processor time above the threshold with fewer rounds than the rounds "
          "threshold minus one, and processor time not above it with more rounds than the rounds threshold; no rounds "
          "threshold and no counts against it without a line or with a line that does not rise" + instrumented)
    table("sign_attrib_shares",
          ["file", "threshold (ms)", "n", "calls with processor time above it", "share", "Clopper-Pearson 95%",
           "rounds threshold of the line", "calls with at least that many rounds", "share", "Clopper-Pearson 95%",
           "share under a geometric law", "its bounds"],
          [[f["source"], f"{c['threshold_ms']:g}", f["n"], c["k"], pct(c["share"]), ci(c["share_cp95"], pct),
            *([c["rounds_threshold"], a["k"], pct(a["share"]), ci(a["share_cp95"], pct), pct(a["share_geometric"]),
               ci(a["share_geometric_ci95"], pct)] if (a := c["rounds_at_least"]) else [DASH] * 6)]
           for f in attrib for c in f["cpu_over"]],
          f"calls with seq >= {warmup}; 'above' is strict; exact two-sided intervals, independent calls assumed; rounds "
          "threshold of the line: the smallest whole number of rounds for which the least-squares line of processor time on "
          "rounds is above the threshold; share under a geometric law: (1 - one-round share)^(rounds threshold - 1), with "
          "the measured one-round share; its bounds: the same formula at the two ends of the exact 95% interval of the "
          "one-round share, the rounds threshold taken as given" + instrumented)
    table("sign_attrib_rounds",
          ["file", "rounds", "n", "share", "share under a geometric law", "mean processor time (µs)"],
          [[f["source"], p["rounds"], p["n"], pct(p["share"], 4), pct(p["geometric_share"], 4), num(p["mean_cpu_us"])]
           for f in attrib if f["rounds"] for p in f["rounds"]["per_round"]],
          f"calls with seq >= {warmup}, by number of rounds; geometric law: one-round share x (1 - one-round share)^"
          "(rounds - 1), with the measured one-round share" + instrumented)

    # within-launch results: single paired files, and the pooled pairs of a launch set
    within = [(f["source"], f["mode"], f["ops"]) for f in res["overhead_paired"] if f["launch"] is None]
    within += [(f"{t['source']} ({t['n_launches']} launches pooled)", t["mode"], t["pooled"]) for t in res["overhead_launch_sets"]]
    paired = [(s, m, o, o["tost_paired_log"]) for s, m, ops in within if m != "aa" for o in ops]
    optimistic = ("within launch, optimistic: the pairs are treated as independent, which leaves out the difference "
                  "between process launches (see overhead_across_launch for the headline)")
    table("overhead_paired",
          ["file", "mode", "op", "pairs", "dropped", "median standalone (µs)", "median csm (µs)", "median diff (µs)",
           "median ratio", "HL paired (µs)", "HL 95% CI", "Wilcoxon p", "margin", "TOST p", "GM ratio",
           "GM ratio 90% CI", "equivalent", "Cliff's δ"],
          [[s, m or DASH, o["op"], o["n_pairs"], o["n_warmup_dropped"], num(o["median_standalone_us"]), num(o["median_csm_us"]),
            signed(o["median_diff_us"]), f5(o["median_ratio"]), signed(o["hl_paired"]["estimate_us"]),
            ci(o["hl_paired"]["ci95_us"], signed), sig(o["wilcoxon_p"]), f"±{pct(t['margin'])}", sig(t["p"]),
            f5(t["gm_ratio"]), ci(t["gm_ratio_ci"], f5), "yes" if t["equivalent"] else "no", tables.rounded(o["cliffs_delta"], 4, sign=True)]
           for s, m, o, t in paired],
          optimistic + "; differences are csm - standalone; TOST on paired log-ratios tests the geometric mean of "
          "csm/standalone against the margin read from equivalence_margin.txt")
    table("overhead_noise_floor",
          ["file", "op", "pairs", "dropped", "median standalone (µs)", "median standalone, second call (µs)",
           "median diff (µs)", "HL paired (µs)", "HL 95% CI", "Wilcoxon p", "GM ratio", "GM ratio 90% CI", "Cliff's δ"],
          [[s, o["op"], o["n_pairs"], o["n_warmup_dropped"], num(o["median_standalone_us"]), num(o["median_csm_us"]),
            signed(o["median_diff_us"]), signed(o["hl_paired"]["estimate_us"]), ci(o["hl_paired"]["ci95_us"], signed),
            sig(o["wilcoxon_p"]), f5(o["tost_paired_log"]["gm_ratio"]), ci(o["tost_paired_log"]["gm_ratio_ci"], f5),
            tables.rounded(o["cliffs_delta"], 4, sign=True)] for s, m, ops in within if m == "aa" for o in ops],
          "A/A runs (mode aa): both columns are the standalone call, so the difference second - first is the noise floor "
          "of the paired comparison; it is not judged against the equivalence margin; " + optimistic)
    table("overhead_order",
          ["file", "op", "n AB", "n BA", "median diff AB (µs)", "median diff BA (µs)", "HL shift BA–AB (µs)",
           "95% CI", "Mann-Whitney p"],
          [[s, o["op"], e["n_AB"], e["n_BA"], signed(e.get("median_diff_AB_us")), signed(e.get("median_diff_BA_us")),
            signed(h.get("estimate_us")), ci(h.get("ci95_us"), signed), sig(e.get("mann_whitney_p"))]
           for s, _, ops in within for o in ops for e in [o["order_effect"]] for h in [e.get("hl_shift_BA_minus_AB", {})]],
          "order-effect check: paired differences (second column - standalone) of AB pairs against BA pairs")
    table("overhead_launches",
          ["file", "mode", "launch", "op", "pairs", "HL paired (µs)", "HL 95% CI", "GM ratio", "GM ratio 90% CI"],
          [[f["source"], f["mode"] or DASH, f["launch"], o["op"], o["n_pairs"], signed(o["hl_paired"]["estimate_us"]),
            ci(o["hl_paired"]["ci95_us"], signed), f5(o["tost_paired_log"]["gm_ratio"]), ci(o["tost_paired_log"]["gm_ratio_ci"], f5)]
           for f in res["overhead_paired"] if f["launch"] is not None for o in f["ops"]],
          "one row per process launch; the intervals are within that launch")
    table("overhead_across_launch",
          ["directory", "mode", "op", "launches", "invalid launches", "HL mean (µs)", "SD", "min", "max", "95% t-interval",
           "90% t-interval", "GM ratio", "GM ratio 90% t-interval", "margin", "TOST p", "verdict"],
          [[t["source"], t["mode"] or DASH, a["op"], a["n_launches"], t["n_invalid_launches"], signed(h["mean"]), num(h["sd"]),
            signed(h["min"]), signed(h["max"]), ci(h["t95"], signed), ci(h["t90"], signed), f5(g["mean"]), ci(g["t90"], f5),
            f"±{pct(a['tost']['margin'])}" if a["tost"] else DASH, sig(a["tost"]["p"]) if a["tost"] else DASH, a["verdict"]]
           for t in res["overhead_launch_sets"] for a in t["across_launch"] for h, g in [(a["hl_us"], a["gm_ratio"])]],
          "HEADLINE: the process launch is the unit of replication; one paired Hodges-Lehmann estimate and one "
          "geometric-mean ratio per launch, Student-t intervals over launches, TOST on the launch-level log-ratios with "
          "n = number of launches; no verdict below " + f"{overhead.MIN_LAUNCHES}" + " launches or for A/A sets"
          + ("; margin file " + margin["file"] + ((": " + " / ".join(margin["comments"])) if margin["comments"] else "")
             if margin else ""))
    table("overhead_unpaired",
          ["file", "op", "n standalone", "n csm", "median standalone (µs)", "median csm (µs)", "rel. median diff",
           "Mann-Whitney p", "HL shift (µs)", "HL 95% CI", "Cliff's δ", "TOST p (post hoc)", "lag-1 standalone", "lag-1 csm",
           "block-bootstrap 90% of the rel. median diff"],
          [[f["source"], o["op"], o["n_standalone"], o["n_csm"], num(o["median_standalone_us"]), num(o["median_csm_us"]),
            tables.rounded(100 * o["median_rel_diff"], 3, sign=True) + "%", sig(o["mann_whitney_p"]), signed(o["hl_shift"]["estimate_us"]),
            ci(o["hl_shift"]["ci95_us"], signed), tables.rounded(o["cliffs_delta"], 4, sign=True),
            "; ".join(f"±{pct(t['margin'])}: {sig(t['p'])}" for t in o["tost_log_post_hoc"]),
            *(sig(o[f"lag1_{arm}"]) for arm in ("standalone", "csm")),
            ci([100 * v for v in o["bootstrap"]["median_rel_diff_ci90"]], lambda v: tables.rounded(v, 3, sign=True) + "%")]
           for f in res["overhead_unpaired"] for o in f["ops"]],
          "legacy unpaired samples; " + overhead.SEQUENTIAL + "; shift is csm - standalone; TOST on log-times "
          "(geometric-mean ratio): " + overhead.POST_HOC + "; lag-1: autocorrelation of each phase in the order of seq; "
          "block bootstrap: moving blocks resampled within each phase, percentile interval of median csm / median "
          "standalone - 1; lag-1 and the bootstrap: " + overhead.WITHIN)

    def model_cells(m):
        if not m:
            return [DASH] * 5
        r = m["random_offsets"]
        return [pct(m["utilisation"]), pct(m["measured_offsets"]["mean"]), pct(r["mean"]),
                ci([r["min"], r["max"]], pct), pct(m["synchronous"]["mean"])]

    per = res["periodic"]
    table("periodic",
          ["file", "period (ms)", "deadline (ms)", "streams", "cores", "profile", "scheduler", "main function",
           "MF period (µs)", "phase", "partition", "jobs", "unfinished", "misses",
           "miss ratio", "Clopper-Pearson 95%", "longest run", "max misses in 10", "in 100", "in 1000", "model utilisation",
           "model as-measured offsets", "model random offsets", "model [min, max]", "model synchronous",
           "retransmitted segments", "duplicate SACKs", "retransmission time-outs"],
          [[r["source"], f"{r['period_us'] / 1e3:g}", f"{r['deadline_us'] / 1e3:g}", r["streams"], r["cores"],
            r["profile"], r["scheduler"], *(r.get(k, DASH) for k in periodic.ID_KEYS),
            r["jobs"], r["unfinished"], r["misses"], pct(r["miss_ratio"]),
            ci(r["miss_cp95"], pct), r["longest_miss_run"],
            *(DASH if r["max_misses_in_window"][w] is None else r["max_misses_in_window"][w] for w in ("10", "100", "1000")),
            *model_cells(r.get("model")),
            *(DASH if (v := (r.get("transport") or {}).get(k)) is None else v for k in csvio.TRANSPORT_COUNTS)]
           for r in per],
          "miss: job unfinished or send_done - release > deadline, over all released jobs; interval: exact for "
          "independent jobs, too narrow when misses come in bursts (Wilson is in summary.json); "
          "model: global non-preemptive FIFO, service times resampled from a measured sample (source in summary.json); "
          "as-measured case simulates the measured number of jobs, the other cases --sim-jobs; the last three columns "
          "are the counts of the transmitter's connection in the measured window (TCP_INFO at the end minus at the first "
          "release; a dash: not given, which is not zero); they never make a file invalid")
    # what the note may say of the cells' processes: what their files say (cores < partitions as in make_numbers)
    at = {r["source"]: r.get("cpu_affinity") for r in res["periodic"]}
    layouts = {"shared" if c["cores"] < c["partitions"] else "own" if all(at[f] for f in c["files"]) else None
               for c in res["periodic_cells"] if not c["missing_partitions"]}
    table("periodic_combined",
          ["directory", "label", "period (ms)", "partitions", "streams", "cores", "profile", "scheduler", "jobs", "misses",
           "miss ratio", "Clopper-Pearson 95%", "files", "partitions without a retransmission", "left out: retransmission",
           "left out: count not given", "jobs, without", "misses, without", "miss ratio, without", "Clopper-Pearson 95%, without"],
          [[c["source"], c["label"] or DASH, f"{c['period_us'] / 1e3:g}", c["expected_partitions"],
            *((c["streams"], c["cores"], c["profile"], c["scheduler"], c["jobs"], c["misses"], pct(c["miss_ratio"]),
               ci(c["miss_cp95"], pct)) if not c["missing_partitions"] else
              (DASH, DASH, c["profile"], c["scheduler"], DASH, DASH, DASH,
               "partition " + ", ".join(map(str, c["missing_partitions"])) + " missing or invalid: not combined")),
            ", ".join(c["files"]),
            *((q["partitions"], q["left_out_retransmitted"], q["left_out_unknown"], *(DASH if q[k] is None else q[k] for k in ("jobs", "misses")),
               pct(q["miss_ratio"]), ci(q["miss_cp95"], pct)) if (q := c.get("no_retrans")) else [DASH] * 7)]
           for c in res["periodic_cells"]],
          "a cell measured as several partitions: " + {
              "own": "independent gateway processes side by side, each with its own streams, queue and core; releases and "
                     "misses are added over them (streams and cores are the sums)",
              "shared": "sender processes side by side that share a core, each with its own streams and queue; releases and "
                        "misses are added over them; streams are the sum, the cores column is the number of distinct cores",
          }.get(layouts.pop() if len(layouts) == 1 else None,  # true of any cell: no affinity line, or cells of both kinds
                "sender processes side by side, each with its own streams and queue; releases and misses are added over "
                "them; streams are the sum; the cores column is the number of distinct cores when every file of the cell "
                "records where its process was pinned (cpu_affinity), else the sum of the cores the files name") +
          "; interval: exact for independent jobs, too narrow when misses come in bursts; the partitions' own rows are "
          "in the periodic table; the last seven columns are the sensitivity figure: the same combination over the "
          "partitions whose transmitter reports no retransmitted segment in the measured window (a count that was not "
          "given is not zero and leaves the partition out), beside the figure over all partitions, never instead of it; "
          "dashes: no file of the cell gives the count")
    stat = ("mean", "p50", "p90", "p95", "p99", "p99.9", "max")
    table("periodic_times", ["file", "quantity", "n", "mean (µs)", *stat[1:]],
          [times_row(r["source"], q, r[f"{q}_us"], periodic.NOT_RECORDED)
           for r in per for q in ("response", "queueing", "auth", "service")],
          "response = send_done - release, queueing = start - release, auth = auth_done - start, service = send_done - "
          "start; each over the jobs that reached the stage (n), so unfinished jobs are not in the percentiles; not "
          "recorded: the file's '# not_recorded=' line names a timestamp the quantity needs")
    table("periodic_rx",
          ["file", "tx jobs", "delivered", "delivery ratio", "not delivered", "duplicates", "out of order", "not in tx", "results"],
          [[x["source"], x["tx_jobs"], x["delivered"], pct(x["delivery_ratio"], 6), x["lost"], x["duplicates"],
            x["out_of_order"], x["rx_not_in_tx"], ", ".join(f"{k}: {v}" for k, v in x["by_result"].items())]
           for x in (r["rx"] for r in per if "rx" in r)])
    rx_times = []
    for x in (r["rx"] for r in per if "rx" in r):
        lat = x["latency"] or {}
        for q, d, why in (("verification", x["verify_us"], periodic.NOT_RECORDED),
                          ("delivery", x["deliver_us"], periodic.NOT_RECORDED),
                          *((f"reject decision ({k})", d, "") for k, d in x["reject_us"].items() if d["n"]),
                          ("one-way latency", lat.get("one_way_us"), x["latency_note"]),
                          ("end-to-end", lat.get("end_to_end_us"), x["latency_note"])):
            rx_times.append(times_row(x["source"], q, d, why))
    table("periodic_rx_times", ["file", "quantity", "n", "mean (µs)", *stat[1:]], rx_times,
          "over ok rows: verification = verify_done - rx_done, delivery = deliver - rx_done; reject decision = "
          "verify_done - rx_done per failure class; with a clock_offset.csv (" + periodic.CLOCK_CONVENTION + "), per "
          "delivered job: one-way latency = rx_done - send_done, end-to-end = deliver - release, each uncertain by "
          "half the probe round trip")
    table("periodic_rx_streams", ["file", "stream", "tx jobs", "delivered", "not delivered", *periodic.RESULTS[:3]],
          [[x["source"], ps["stream"], ps["tx_jobs"], ps["delivered"], ps["lost"], *ps["by_result"].values()]
           for x in (r["rx"] for r in per if "rx" in r) for ps in x["per_stream"]],
          "delivered: Tx jobs with an ok Rx row; not delivered: Tx jobs with no Rx row; then Rx rows per result (framing_fail "
          "rows name no stream and are counted per configuration only)")

    def of_e2e(e, group, stat, places=3):  # a percentile with fewer than ten samples above it is not printed
        return DASH if make_numbers.scarce(stat, e["n"]) else num(e[group][stat], places)

    table("e2e", ["file", "configuration", "n", "latency median (ms)", "p99 (ms)", "p99.9 (ms)", "max (ms)",
                  "receive part median (ms)", "certified to within (µs)"],
          [[source, cell, e["n"], *(of_e2e(e, "latency_ms", q) for q in ("p50", "p99", "p99.9", "max")),
            of_e2e(e, "rxpart_ms", "p50"), num(e["bound_total_us"], 1)]
           for source, cell, e in (*((r["source"], make_numbers.config_id(r), r.get("e2e")) for r in per),
                                   *((t["source"], f"gateway binaries, {t['profile']}", t.get("e2e")) for t in res["functional"])) if e],
          "end-to-end latency across the two boards (E9): per delivered PDU, deliver_ns - theta(release_ns) - release_ns, "
          "from the release on the sending board to the delivery to the application on the receiving board; receive part: "
          "deliver_ns - theta(send_done_ns) - send_done_ns, transfer and receive path; for the gateway binaries (a "
          "functional run with the probe file beside it) the release is submit_ns; every time stamp is first carried "
          "from CLOCK_MONOTONIC onto the raw clock of its board (CLOCK_MONOTONIC_RAW, which the time-synchronisation service "
          "does not steer) with the map that the probe sampled on that board every 5 ms (clock_map_a.csv, clock_map_b.csv); "
          "theta(t): the offset between the two boards' raw clocks, measured during the run by a two-way exchange "
          "(clock_probe.csv, format 2) and interpolated between the exchange with the smallest delay of every 5 s (the "
          "anchors); certified to within: bound_total_us, the sum of offset_bound_total_us (the larger of the largest half "
          "delay among the anchors, the first and the last one apart, and the certified bound of the line between them: "
          "the smallest figure met by exchanges no more than 2 s apart) and the bounds of the two maps (the larger of the "
          "hold-out of every sample against its neighbours and the kink term of every interval, plus the largest half "
          "width); at instants no more than 2 s apart the measurement "
          "certifies the estimate to within it, which is not a bound for every instant; percentiles of "
          f"type 7, a dash where fewer than ten PDUs lie above one; a run with a probe file of format 1, a probe gap above "
          f"{e2e.GAP_MAX_MS} ms, fewer than two anchors before the first release or after the last delivery, no certified "
          f"bound, a time stamp outside its map, a map gap above {e2e.MAP_GAP_MAX_MS} ms, an exchange point off the map, a "
          f"total bound above {e2e.BOUND_MAX_US} µs, an exchange outside the offset bound, or a PDU received before it was "
          "sent by more than the total bound is not in this table (validity table)")

    def rep(r):
        return DASH if r["rep"] is None else r["rep"]

    def loss(v):
        return pct(v, 5)

    yes_no = {None: DASH, True: "yes", False: "no"}
    # a ladder is named as in its number keys: <profile>-c<cores>[-<mainfunction>][-mf<period>]
    ladders = [(t, [t["source"], make_numbers.ladder_id(t)]) for t in res["throughput"]]
    steps = [(t, [*lead, f"{s['offered_pps']:g}"], s) for t, lead in ladders for s in t["saturation"]["steps"]]
    window = "; ".join(sorted({f"steady-state window: first and last {t['trim']} samples of each file dropped (--trim {t['trim']})"
                               if t["trim"] else "steady-state window: every sample of each file (--trim 0)" for t, _ in ladders}))
    dips = ["; non-monotone: " + " ".join(lead) + ": " + ", ".join(f"{r:g}" for r in sat["non_monotone"])
            + f" PDU/s sustained above {sat['range_ended_at']:g} PDU/s, the first step that is not (not counted)"
            for t, lead in ladders if (sat := t["saturation"])["non_monotone"]]
    table("throughput",
          ["directory", "ladder", "offered (PDU/s)", "host", "partition", "rep", "role", "intervals", "PDU/s",
           "95% CI", "CPU", "process CPU", "wire Mbit/s", "wire bytes/PDU", "sendq mean (B)", "sendq max (B)", "drops", "drop ratio",
           "retransmitted segments", "duplicate SACKs", "retransmission time-outs"],
          [[*lead, f"{r['offered_pps']:g}", r["host"],
            f"sum of {r['partitions']}" if r["partitions"] > 1 else DASH if r["partition"] is None else r["partition"],
            rep(r), r["role"], r["intervals"], num(r["pps_mean"]), ci(r["pps_ci95"]),
            pct(r["cpu_util"]), pct(r["proc_cpu_share"]), num(r["wire_mbit_s"], 3), DASH if part else num(r["wire_bytes_per_pdu"], 1),
            num(r["sendq_mean_bytes"], 0), r["sendq_max_bytes"], r["drops"], pct(r["drop_ratio"]),
            *(DASH if r[k] is None else r[k] for k in csvio.TRANSPORT_COUNTS)]
           for t, lead in ladders for part, rows in ((False, t["rows"]), (True, t["parts"])) for r in rows],
          window + "; one row per repetition and host; the last three columns are the counts of the transmitter's "
          "connection in the measured window (TCP_INFO at the end minus at the first release; a dash: not given, which "
          "is not zero; none for a receiver); they never make a file invalid; process CPU: " + throughput.PROC_CPU
          + " (a dash: the file has no proc_cpu_ns column); CPU: busy / total jiffies of the sampler, from the kernel's "
          "tick-based accounting, which misses work that starts on a timer: shown for the record, not a utilisation to "
          "quote and no manuscript number; drops: the sampler's column, on the tx host the releases the generator dropped "
          "at a full queue, on the rx host the PDUs the receiver rejected; drop ratio = drops / (done + drops) on that "
          "host alone; sum of N: "
          "the N partitions (gateway processes) of the step added up, PDU/s interval by interval, CPU over their "
          "cores, wire rate from the host's interface counters (not added), followed by one row per partition (no "
          "bytes per PDU there: the interface counters are the host's, not one partition's)")
    table("throughput_reps",
          ["directory", "ladder", "offered (PDU/s)", "rep", "delivered (PDU/s)", "offered PDUs", "not delivered",
           "dropped at release", "loss ratio", "Clopper-Pearson 95%", "queue growth bound (B)", "one queued PDU (B)",
           "send queue growing", "sustained"],
          [[*lead, rep(r), num(r["delivered_pps"]),
            *(DASH if r[k] is None else r[k] for k in ("offered_pdus", "lost_pdus", "dropped_pdus")),
            loss(r["loss_ratio"]), ci(r["loss_cp95"], loss), num(r["sendq_growth_lower95_bytes"], 1),
            num(r["queued_bytes_per_pdu"], 1), yes_no[r["sendq_growing"]],
            {None: r["note"], True: "yes", False: "no"}[r["sustained"]]] for _, lead, s in steps for r in s["reps"]],
          window + "; one row per repetition of a rate step; offered PDUs = PDUs the generator released (sent + dropped "
          "at release on the tx host); not delivered = offered - delivered, over the same samples on both hosts: PDUs "
          + throughput.NOT_DELIVERED + "; it is an end-to-end count, not PDUs lost by the stack or by the network; "
          "dropped at release: " + throughput.DROPPED + "; loss ratio = not delivered / offered; interval: "
          "exact two-sided Clopper-Pearson, exact for independent PDUs and too narrow when they come in bursts; "
          "queue growth bound: the one-sided 95% lower bound of the slope of the tx host's send queue times the length of "
          "the window (0 for a queue whose depth never changes; for several partitions the largest of their bounds); one "
          "queued PDU: " + throughput.QUEUED_PDU + "; " + throughput.GROWING + " (a dash: no size, so not judged); "
          "sustained: send queue not growing and loss ratio at most "
          + "/".join(sorted({f"{t['saturation']['loss_max']:g}" for t, _ in ladders})))
    quantities = (("delivered_pps", "delivered (PDU/s)", num), ("loss_ratio", "loss ratio", loss),
                  ("tx_drop_ratio", "dropped at release, share of the offered PDUs (tx host)", loss),
                  ("tx_cpu_util", "CPU of the tx host", pct), ("rx_cpu_util", "CPU of the rx host", pct),
                  ("tx_proc_cpu_share", "process CPU of the tx host", pct), ("rx_proc_cpu_share", "process CPU of the rx host", pct),
                  ("wire_mbit_s", "wire rate of the tx host (Mbit/s)", lambda v: num(v, 3)),
                  ("sendq_mean_bytes", "send queue mean (bytes)", lambda v: num(v, 0)),
                  ("sendq_max_bytes", "send queue maximum (bytes)", lambda v: num(v, 0)),
                  ("sendq_slope_bytes_per_s", "send queue slope (bytes/s)", lambda v: num(v, 1)))
    table("throughput_steps",
          ["directory", "ladder", "offered (PDU/s)", "quantity", "reps", "mean", "95% t-interval", "min", "max"],
          [[*lead, label, a["n"], f(a["mean"]), ci(a["t95"], f), f(a["min"]), f(a["max"])]
           for _, lead, s in steps for key, label, f in quantities if (a := s["across"][key])],
          "the repetition is the unit: one value per repetition of the rate step, then their mean, the Student-t 95% "
          "interval of that mean (none for a single repetition; for the loss ratio and the CPU utilisations, which are "
          "proportions, its bounds are clamped to [0, 1]), the smallest and the largest; samples of different "
          "repetitions are never pooled; loss ratio: the share of the offered PDUs " + throughput.NOT_DELIVERED
          + "; dropped at release: what the transmitter alone dropped, " + throughput.DROPPED
          + "; the CPU rows come from the kernel's tick-based accounting, which misses work "
          "that starts on a timer: shown for the record, no manuscript numbers; process CPU: " + throughput.PROC_CPU
          + " (not a proportion: its interval is not clamped)")
    table("throughput_saturation",
          ["directory", "ladder", "offered (PDU/s)", "reps", "delivered mean (PDU/s)", "largest loss ratio",
           "largest share dropped at release", "send queue growing", "sustained in", "verdict", "saturation point (PDU/s)",
           "secondary: pooled loss ratio", "secondary: exact 95% of the pooled counts"],
          [[*lead, s["n_reps"], num(s["delivered_pps"]), loss((s["across"]["loss_ratio"] or {}).get("max")),
            loss((s["across"]["tx_drop_ratio"] or {}).get("max")),
            yes_no[s["sendq_growing"]], f"{s['sustained_reps']} of {s['n_reps']}",
            {None: "not judged", True: "sustained", False: "not sustained"}[s["sustained"]]
            + (", above the sustained range" if s["offered_pps"] in t["saturation"]["non_monotone"] else ""),
            sig(t["saturation"]["saturation_pps"], 6), loss((s["pooled_loss"] or {}).get("loss_ratio")),
            ci((s["pooled_loss"] or {}).get("loss_cp95"), loss)] for t, lead, s in steps],
          window + "; sustained: " + "; ".join(sorted({t["saturation"]["criterion"] for t, _ in ladders}))
          + "; loss ratio: the share of the offered PDUs " + throughput.NOT_DELIVERED + " (an end-to-end figure, not PDUs "
          "lost by the stack or by the network); share dropped at release: beside it, " + throughput.DROPPED
          + "; the bound and the size of every repetition are in throughput_reps; a step "
          "is not sustained as soon as one repetition is not; send queue growing: in any repetition; a step that is "
          "not sustained or not judged ends the sustained range" + "".join(dips) + "; secondary columns: the PDUs "
          "not delivered and offered of the step's repetitions added up, with the exact Clopper-Pearson interval of that proportion; "
          "it ignores the variation between repetitions, the per-repetition intervals (throughput_reps) are the "
          "primary statement"
          + "".join(f"; {' '.join(lead)}: no transmitter file gives tcp_total_retrans_in_window, so no sensitivity line over "
                    "the repetitions without a retransmission can be formed" for t, lead in ladders
                    if not t["saturation"]["no_retrans"]["files_known"]))
    known = [(t, lead) for t, lead in ladders if t["saturation"]["no_retrans"]["files_known"]]
    verdict = {None: "not judged", True: "sustained", False: "not sustained"}
    table("throughput_no_retrans",
          ["directory", "ladder", "offered (PDU/s)", "reps", "without a retransmission", "left out: retransmission",
           "left out: count not given", "delivered mean (PDU/s), all", "without", "largest loss ratio, all", "without",
           "verdict, all", "without", "saturation point (PDU/s), all", "without"],
          [[*lead, f"{s['offered_pps']:g}", s["n_reps"], q["n_reps"], sum(w == "retransmitted" for w in q["left_out"].values()),
            sum(w == "unknown" for w in q["left_out"].values()), num(s["delivered_pps"]), num(q["delivered_pps"]),
            loss((s["across"]["loss_ratio"] or {}).get("max")), loss((q["across"]["loss_ratio"] or {}).get("max")),
            verdict[s["sustained"]], verdict[q["sustained"]], sig(t["saturation"]["saturation_pps"], 6),
            sig(t["saturation"]["no_retrans"]["saturation_pps"], 6)]
           for t, lead in known for s, q in zip(t["saturation"]["steps"], t["saturation"]["no_retrans"]["steps"])],
          "sensitivity line: every figure once over all valid repetitions and once over "
          + throughput.NO_RETRANS + "; the second figure stands beside the first, never instead of them: a retransmission does "
          "not make a file invalid; "
          + "; ".join(f"{' '.join(lead)}: {(q := t['saturation']['no_retrans'])['reps_left_out']} repetition(s) left out, "
                      f"{q['files_with_retrans']} transmitter file(s) with a retransmitted segment, {q['files_unknown']} without "
                      "the count" for t, lead in known))

    def detect(d, cols):  # detection-time cells; None: the oracle of the file records no decision time
        return [periodic.NOT_RECORDED, *[DASH] * (len(cols) - 1)] if d is None else [num(d.get(c)) for c in cols]

    table("attack",
          ["file", "vector", "n", "delivered", "rejected", "rejection rate", "Clopper-Pearson 95%", "framing", "freshness",
           "auth", "detect mean (µs)", "p50", "p95", "false rejection 95% upper bound"],
          [[f["source"], v["vector"], v["n"], v["delivered"], v["rejected"], pct(v["rejection_rate"], 6),
            ci(v["rejection_cp95"], lambda x: pct(x, 5)), *(v["by_stage"][s] for s in ("framing", "freshness", "auth")),
            *detect(v["detect_us"], ("mean", "p50", "p95")), pct(v.get("false_rejection_upper95"))]
           for f in res["attack"] for v in f["vectors"]],
          "interval: exact two-sided Clopper-Pearson (Wilson is in summary.json); upper bound: one-sided 95% "
          "Clopper-Pearson on the benign false-rejection rate; detect: reception complete to reject decision; not "
          f"recorded: the file says '# oracle={attack.UNTIMED_ORACLE}', whose detect_ns is 0 by construction")
    table("attack_stages",
          ["file", "vector", "reject stage", "count", "n", "rate", "Clopper-Pearson 95%", "detect mean (µs)", "p50", "p95",
           "p99", "max"],
          [[f["source"], v["vector"], st["stage"], st["count"], v["n"], pct(st["rate"], 6), ci(st["cp95"], lambda x: pct(x, 5)),
            *detect(st["detect_us"], ("mean", "p50", "p95", "p99", "max"))]
           for f in res["attack"] for v in f["vectors"] for st in v["stages"]],
          "PDUs of each vector rejected at each stage, exact two-sided 95% interval of that proportion, time to detect "
          f"(not recorded for a file with '# oracle={attack.UNTIMED_ORACLE}')")

    table("footprint", ["file", "build, operation or host", "quantity", "value"],
          [row for f in res["footprint"] for row in (
              [[f["source"], b["build"] or DASH, f"{what} (bytes)", b[k]] for b in f["builds"]
               for k, what in ((footprint.BYTES[0], "binary file, not stripped"), (footprint.BYTES[1], "binary file, stripped"),
                               *((name, sec) for sec, name in footprint.SECTIONS.items()))] if f["what"] == "size" else
              [[f["source"], f["op"], what, num(f[k], d)] for k, what, d in (
                  ("instructions_per_call", "instructions per call", 0), ("cycles_per_call", "cycles per call", 0),
                  ("instructions_per_cycle", "instructions per cycle", 2))] if f["what"] == "perf" else
              [[f["source"], host, what, h[k]] for host, h in f["hosts"].items()
               for k, what in (("vmhwm_max_kb", "largest VmHWM (kB)"), ("samples", "samples"))])],
          "footprint figures taken with standard tools, counts only: the size of the binary file before and after strip "
          "and the sections of the stripped binary (`size -A`), one row set per build of a file; per call of "
          + ", ".join(footprint.PER_CALL) + ": the perf stat count of the longer run less that of the shorter, over the "
          "calls between them (" + footprint.ONE_PAIR + "; the numbers of calls are those of the file names); largest "
          "VmHWM: the peak resident set among the samples of a host's process, and the number of its samples")

    table("cyclictest",
          ["file", "policy", "load", "cpu", "duration (s)", "samples", "min (µs)", "avg", "max", "p99", "p99.9", "p99.99",
           "overflows", "later than 100 µs", "later than 1 ms"],
          [[c["source"], c["policy"], c["load"], c["cpu"], f"{c['duration_s']:g}", c["samples"], c["min_us"], c["avg_us"],
            c["max_us"], *(f"> {c['histogram_us'] - 1}" if c[f"p{q:g}_us"] is None else c[f"p{q:g}_us"]
                           for q in cyclictest.PERCENTILES), c["overflows"],
            *(DASH if late["k"] is None else late["k"] for late in c["late_over"])]
           for c in res["cyclictest"]],
          "scheduling latency of a 1 ms periodic wake-up; min, avg, max are cyclictest's own lines and include the "
          "overflowed samples; percentiles are read from its 1 µs histogram, the overflows counted as values above the "
          "last bucket ('> N': the percentile lies among them); later than: wake-ups strictly above 100 µs / 1 ms, "
          "overflows included (a dash: overflows that cannot be placed against a threshold beyond the histogram); load is "
          "the file's '# load=' line, or cpu<N> when the file has none")

    roles = [(f, r) for f in res["handshake"] for r in f["roles"]]
    stat = ("mean", "p50", "p95", "p99", "max")
    table("handshake",
          ["file", "role", "main function", "MF period (µs)", "t_min (ms)", "n", "results", "total mean (µs)", *stat[1:],
           "compute mean (µs)", "compute p50", "compute max", "bytes tx (median)", "bytes rx (median)"],
          [[f["source"], r["role"], *(f["header"].get(k, DASH) for k in handshake.HEADER), r["n"],
            ", ".join(f"{k}: {v}" for k, v in r["results"].items()), *(num(r["total_us"].get(c)) for c in stat),
            *(num(r["compute_us"].get(c)) for c in ("mean", "p50", "max")),
            *(num(r[b]["median"], 0) if r[b] else DASH for b in ("bytes_tx", "bytes_rx"))] for f, r in roles],
          "times over successful handshakes; total: initiator = start of ML-KEM key generation to keys installed (after "
          "M3 is handed to SoAd, M4 not included), responder = M1 completely received to keys installed after M3, so "
          "the responder's total includes the initiator's computation and two network legs; both totals include "
          "main-function scheduling and are not crypto time; compute = sum of the role's stage columns per handshake; "
          "bytes include the 8-byte SoAd PDU header of each message; t_min: minimum handshake interval in force")
    def logged(results):
        return ", ".join(f"{k}: {v}" for k, v in (results or {}).items()) or DASH

    table("functional",
          ["directory", "profile", "streams", "tx parts", "rx parts", "sent", "delivered", "in order", "byte-exact",
           *functional.REJECTED, "initiator handshake rows", "responder handshake rows", "tx TCP connections", "rx TCP connections"],
          [[t["source"], t["profile"] or DASH, t["streams"], t["tx_parts"], t["rx_parts"], t["sent"], t["delivered"],
            t["delivered_in_order"], "not judged" if t["delivered_byte_exact"] is None else t["delivered_byte_exact"],
            *t["rejected"].values(), *(logged(t["handshakes"].get(role, {}).get("results")) for role in hsneg.SIDES),
            *(t["connections"][side]["n"] for side in ("tx", "rx"))] for t in res["functional"]],
          "functional runs of the gateway binaries (directories with the marker FUNCTIONAL): counts only, no time is read "
          "from these files; parts of a replaced gateway process (app_rx2.csv ...) are added, the driver's joined *_all.csv "
          "are not read; sent: rows of app_tx*.csv, written when a transmission is confirmed; delivered: rows of "
          "app_rx*.csv with result ok; in order: " + functional.IN_ORDER + "; byte-exact: " + functional.BYTE_EXACT
          + " (not judged: another payload length); then " + functional.REJECTED_NOTE + "; handshake rows: attempts that "
          "ended and messages discarded without ending one, per result, counted and never timed; TCP connections: the "
          "'# tcp_nodelay=' lines of each side's app files, one per connection; every one reads 1, since a run with "
          "another read-back, or with a file without a line although its process carried PDUs, is invalid")
    table("functional_streams", ["directory", "stream", "sent", "delivered", "in order", "byte-exact"],
          [[t["source"], st["stream"], st["sent"], st["delivered"], st["delivered_in_order"],
            "not judged" if st["delivered_byte_exact"] is None else st["delivered_byte_exact"]]
           for t in res["functional"] for st in t["per_stream"]],
          "one row per stream of a functional run; the columns as in the table functional")
    table("hsneg",
          ["directory", "test", "variant", "verdict", "repetitions asked", "done", "attacked", "runs", "passed",
           "initiator logged", "responder logged", "expected of the initiator", "expected of the responder", "PDUs sent",
           "delivered", "rejected", "given up", "installs tx", "installs rx", "tcp_nodelay tx", "tcp_nodelay rx", "files"],
          [[t["source"], *((t["record"] or {}).get(k, DASH) for k in ("test", "variant", "verdict", "repetitions",
                                                                       "repetitions_done", "attacked", "runs", "runs_passed")),
            *(logged(t["sides"].get(role, {}).get("results")) for role in hsneg.SIDES),
            *(logged(t["record"][k]) if t["record"] else DASH for k in ("expected_tx", "expected_rx")),
            *((t["record"] or {}).get(k, DASH) for k in ("pdus_sent", "pdus_delivered", "pdus_rejected", "pdus_given_up",
                                                          "installs_tx", "installs_rx", "tcp_nodelay_tx", "tcp_nodelay_rx")),
            len(t["files"])] for t in res["hsneg"]],
          "negative handshake tests: one row per test directory; logged: the attempts in the handshake files of each side, "
          "counted here per result class and added over the files of the test (a batch has one pair per run); everything "
          "else is the oracle's record line in hsneg.txt beside the directory (a dash: no record line, which is the format "
          "before 2026-11-23 10:41); the record's seen counts are compared with the counts here and a difference makes "
          "the test invalid; expected: the first handshake plus the complete repetitions; no time is taken from these files")
    table("handshake_phases", ["file", "role", "phase", "mean (µs)", *stat[1:]],
          [[f["source"], r["role"], ph, *(num(t[c]) for c in stat)] for f, r in roles for ph, t in r["phases_us"].items()],
          "stage columns over successful handshakes; hash = all transcript hashes, mac = key-confirmation HMAC "
          "generate and verify; a stage the role does not use is omitted")
    return written, written_csv


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--out", type=Path, help="output directory (default: ./analysis_out/<run_dir name>)")
    ap.add_argument("--seed", type=int, default=SEED, help="RNG seed for bootstrap and simulation (recorded in summary.json)")
    ap.add_argument("--warmup", type=int, default=1000,
                    help="drop seq < WARMUP in crypto_ops, overhead_paired and the legacy timing files")
    ap.add_argument("--block-len", type=int, default=100, help="moving-block bootstrap block length")
    ap.add_argument("--n-boot", type=int, default=2000, help="bootstrap replicates")
    ap.add_argument("--thresholds-ms", default="5,10,15,20", help="exceedance thresholds for signing ops")
    ap.add_argument("--trim", type=int, default=0, help="throughput: samples dropped at each end of a file (default 0: the "
                    "harness starts sampling after the ramp, so every sample is steady state)")
    ap.add_argument("--sim-draws", type=int, default=20, help="queue model: random-offset draws (0 disables the model)")
    ap.add_argument("--sim-jobs", type=int, default=200_000, help="queue model: jobs per run")
    ap.add_argument("--no-figures", action="store_true")
    ap.add_argument("--key-prefix", default="", help="put <prefix>. in front of every number key, for example s1.iris, so "
                    "that the numbers of several runs can be merged (analysis.merge_numbers)")
    a = ap.parse_args(argv)
    if not a.run_dir.is_dir():
        ap.error(f"{a.run_dir} is not a directory")
    out = a.out or Path("analysis_out") / a.run_dir.resolve().name
    if a.out is None and out.resolve().is_relative_to(a.run_dir.resolve()):
        ap.error("the default output directory would be inside the run directory; pass --out")
    try:
        s = run(a.run_dir, out, seed=a.seed, warmup=a.warmup, block_len=a.block_len, n_boot=a.n_boot,
                thresholds_ms=tuple(float(v) for v in a.thresholds_ms.split(",")), trim=a.trim,
                sim_draws=a.sim_draws, sim_jobs=a.sim_jobs, figures=not a.no_figures, key_prefix=a.key_prefix)
    except (OSError, ValueError) as e:
        sys.exit(f"error: {e}")
    print(f"{len(s['tables'])} tables -> {Path(out).resolve() / 'tables'}; summary.json written; "
          f"{s['numbers']['keys']} keys in numbers.tex ({s['numbers']['suppressed']} more held back: suppressed_keys.txt); "
          f"figures: {s['figures']['status']}; "
          f"{len(s['skipped_csv'])} CSV file(s) not analysed (see summary.json)"
          + (f"; {s['not_a_result']} directory: NOT A RESULT, every number is marked" if s["not_a_result"] else ""))
    if s["invalid_runs"]:
        for f in s["invalid_runs"]:
            print(f"INVALID, not analysed: {f['source']}: {'; '.join(f['reasons'])}", file=sys.stderr)
        sys.exit(EXIT_INVALID)


if __name__ == "__main__":
    main()
