"""Strict CSV reading for the run-directory schemas (DATA_SCHEMA.md) and the three legacy files.

Lines starting with '#' and blank lines are ignored ('# key=value' comments are returned as
metadata). The header must match the schema exactly and any malformed row raises CsvError with
file and line number; nothing is skipped silently.
"""
import re
from pathlib import Path

import numpy as np


class CsvError(ValueError):
    pass


INT, SINT, FLOAT, STR = "non-negative integer", "integer", "non-negative number", "non-empty label"


def _enum(*values):
    return frozenset(values)


SCHEMAS = {
    "crypto_ops": (("op", _enum("mldsa_keygen", "mldsa_sign", "mldsa_verify", "mlkem_keygen", "mlkem_encaps",
                                "mlkem_decaps", "hkdf", "hmac_gen", "hmac_verify")), ("seq", INT), ("ns", INT)),
    "overhead_paired": (("seq", INT), ("order", _enum("AB", "BA")), ("op", _enum("sign", "verify")),
                        ("standalone_ns", INT), ("csm_ns", INT)),
    "periodic_tx": (("stream", STR), ("seq", INT), ("release_ns", INT), ("start_ns", INT),
                    ("auth_done_ns", INT), ("send_done_ns", INT)),
    "periodic_rx": (("stream", STR), ("seq", SINT), ("rx_done_ns", INT), ("verify_done_ns", INT), ("deliver_ns", INT),
                    ("result", _enum("ok", "freshness_fail", "auth_fail", "framing_fail"))),
    "throughput": (("t_ns", INT), ("host", STR), ("offered_pps", FLOAT), ("pdus_done", INT),
                   ("cpu_busy_jiffies", INT), ("cpu_total_jiffies", INT), ("if_tx_bytes", INT), ("if_tx_packets", INT),
                   ("if_rx_bytes", INT), ("if_rx_packets", INT), ("sendq_bytes", INT), ("drops", INT)),
    "attack": (("vector", _enum("benign", "replay", "bitflip", "auth_tamper", "freshness_rollback", "session_replay")), ("iter", INT),
               ("delivered", _enum("0", "1")), ("reject_stage", _enum("none", "framing", "freshness", "auth")),
               ("detect_ns", INT)),
    "handshake": (("seq", INT), ("role", _enum("initiator", "responder")),
                  ("result", _enum("ok", "bad_ver", "bad_len", "unknown_id", "sig_fail", "mac_fail", "timeout", "state")),
                  ("total_ns", INT), ("bytes_tx", INT), ("bytes_rx", INT), ("keygen_ns", INT), ("encaps_ns", INT),
                  ("decaps_ns", INT), ("sign_ns", INT), ("verify_ns", INT), ("kdf_ns", INT), ("hash_ns", INT), ("mac_ns", INT)),
    "clock_offset": (("t_ns", INT), ("offset_ns", SINT), ("rtt_ns", INT), ("method", STR)),
    # E9_SPEC.md: one completed two-way exchange per row, t1 and t4 on the client's clock, t2 and t3 on the server's
    "clock_probe": (("seq", INT), ("t1_ns", INT), ("t2_ns", INT), ("t3_ns", INT), ("t4_ns", INT)),
    # E9_SPEC.md, Addendum E: the relation of a board's two clocks, one RAW, MONOTONIC, RAW reading per row
    "clock_map": (("raw1_ns", INT), ("mono_ns", INT), ("raw2_ns", INT)),
    "sign_attrib": (("seq", INT), ("wall_ns", INT), ("cpu_ns", INT)),
    # legacy dataset run_FINAL_20260525_230303
    "phase_compare": (("phase", STR), ("seq", INT), ("ns_delta", INT)),
    "tx_perf_10k": (("seq", INT), ("phase", _enum("keygen", "sign", "verify")), ("ns_delta", INT), ("wallclock_ns", INT)),
    "attack_raw": (("vector", STR), ("iter", INT), ("detected", _enum("0", "1")), ("duration_ns", INT), ("reason", STR)),
}
# columns a file of the kind may carry after the fixed ones: the rounds counter of a counting run;
# the cumulative processor time of the harness process in the sampler files written since 2026-11-23; the raw stamps
# and the widths of the four stamp points of a probe file of format 2 (Addendum E)
OPTIONAL_COLUMNS = {"sign_attrib": (("shake_calls", INT),), "throughput": (("proc_cpu_ns", INT),),
                    "clock_probe": tuple((f"{c}{p}{end}", INT) for c, end in (("t", "r_ns"), ("w", "_ns")) for p in "1234")}
LEGACY_NAMES = {"phase_compare.csv": "phase_compare", "tx_perf_10k.csv": "tx_perf_10k", "attack_raw.csv": "attack_raw"}
KINDS = ("crypto_ops", "overhead_paired", "periodic_tx", "periodic_rx", "throughput", "attack", "handshake", "sign_attrib",
         "clock_offset", "clock_probe", "clock_map")
_META = re.compile(r"#\s*([A-Za-z_][\w.]*)\s*=\s*(.*)$")


def _note(meta, key, value):
    """Record one '# key=value' line. A later line of a key replaces an earlier one, except tcp_nodelay: a process
    writes one such line per TCP connection it had, and the value kept is 1 only while every line reads 1 (the first
    line that does not read 1 stays), so that the gate of transport() fails closed for a file with several
    connections."""
    if key != "tcp_nodelay" or meta.get(key, "1") == "1":
        meta[key] = value


def all_values(path, key):
    """Every value a file gives for '# key=', in the order of its lines (one tcp_nodelay line per TCP connection)."""
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        return [m[2].strip() for m in map(_META.match, map(str.strip, f)) if m and m[1] == key]


def read_csv(path, kind, spec=None):
    """Read one file of schema `kind` (its columns in `spec` when the kind is not one of SCHEMAS). Returns
    (meta, cols): meta is the dict of '# key=value' comment lines, cols maps column name to a numpy array (int64,
    float or str)."""
    spec = spec or SCHEMAS[kind]
    names = [name for name, _ in spec]
    meta, cols, header_seen = {}, [[] for _ in spec], False
    with open(path, encoding="utf-8-sig", newline="") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                m = _META.match(line)
                if m:
                    _note(meta, m[1], m[2].strip())
                continue
            fields = line.split(",")
            if not header_seen:
                extra = OPTIONAL_COLUMNS.get(kind, ())
                if extra and fields == names + [name for name, _ in extra]:
                    spec, names, cols = (*spec, *extra), fields, cols + [[] for _ in extra]
                elif fields != names:
                    raise CsvError(f"{path}:{lineno}: header {line!r} is not the {kind} header {','.join(names)!r}"
                                   + (f" (optionally followed by {','.join(name for name, _ in extra)})" if extra else ""))
                header_seen = True
                continue
            if len(fields) != len(spec):
                raise CsvError(f"{path}:{lineno}: {len(fields)} fields, expected {len(spec)}: {line!r}")
            for col, (name, typ), v in zip(cols, spec, fields):
                if typ is INT:
                    if not (v.isascii() and v.isdigit()):
                        raise CsvError(f"{path}:{lineno}: column {name}: {v!r} is not a {typ}")
                    col.append(int(v))
                elif typ is SINT:
                    digits = v[1:] if v[:1] in ("-", "+") else v
                    if not (digits.isascii() and digits.isdigit()):
                        raise CsvError(f"{path}:{lineno}: column {name}: {v!r} is not an {typ}")
                    col.append(int(v))
                elif typ is FLOAT:
                    try:
                        x = float(v)
                    except ValueError:
                        x = -1.0
                    if not 0 <= x < float("inf"):
                        raise CsvError(f"{path}:{lineno}: column {name}: {v!r} is not a {typ}")
                    col.append(x)
                elif typ is STR:
                    if not v:
                        raise CsvError(f"{path}:{lineno}: column {name}: empty value")
                    col.append(v)
                else:
                    if v not in typ:
                        raise CsvError(f"{path}:{lineno}: column {name}: {v!r} is not one of {sorted(typ)}")
                    col.append(v)
    if not header_seen:
        raise CsvError(f"{path}: no header row, expected {','.join(names)!r}")
    dtypes = {INT: np.int64, SINT: np.int64, FLOAT: float}
    return meta, {name: np.array(col, dtype=dtypes.get(typ, str)) for col, (name, typ) in zip(cols, spec)}


def read_meta(path):
    """Only the '# key=value' comment lines of a file, for when its rows cannot be read."""
    meta = {}
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        for m in filter(None, map(_META.match, map(str.strip, f))):
            _note(meta, m[1], m[2].strip())
    return meta


def kind_of(path):
    """Schema kind from the file name: a legacy name exactly, otherwise '<kind>.csv' or
    '<kind><sep><label>.csv' with sep one of '_', '-', '.'. None if the name is not recognised."""
    name = Path(path).name
    if name in LEGACY_NAMES:
        return LEGACY_NAMES[name]
    return next((k for k in KINDS if re.fullmatch(re.escape(k) + r"([._-].+)?\.csv", name)), None)


def discover(run_dir):
    """All *.csv files below run_dir, split into (recognised paths, skipped entries). A skipped entry
    says which schema its header matches, if any, so a misnamed data file is visible."""
    known, skipped = [], []
    headers = {",".join(n for n, _ in spec): kind for kind, spec in SCHEMAS.items()}
    for p in sorted(Path(run_dir).rglob("*.csv")):
        if kind_of(p):
            known.append(p)
            continue
        with open(p, encoding="utf-8-sig", errors="replace") as f:
            first = next((s for s in map(str.strip, f) if s and not s.startswith("#")), "")
        skipped.append({"path": p.relative_to(run_dir).as_posix(), "reason": "file name not recognised",
                        "header_matches_schema": headers.get(first)})
    return known, skipped


_COUNTERS = ("signature_mismatches", "failed_calls")
_TRAILER = ("freq_khz_end", "wall_s", "cpu_s")  # written when a harness run ends; paired files add the counters
CPU_SHARE_MIN = 0.97  # cpu_s / wall_s of a pinned single-thread run; below this the core was shared
SINGLE_THREAD = ("crypto_ops", "overhead_paired", "sign_attrib")  # busy from start to end: the CPU-share rule applies
# kinds whose real harness files are known to carry the mlockall line and the trailer, so that their absence means
# an unfinished run; handshake joins when a real file shows its lines
WITH_TRAILER = (*SINGLE_THREAD, "periodic_tx", "periodic_rx", "throughput")
NETWORKED = ("periodic_tx", "periodic_rx", "throughput", "handshake", "attack")  # written over a TCP connection: transport()
TRANSPORT_FROM = "transport_read_from"  # set by the caller: {line: the traffic log beside the file it was read from}
JOBS = ("jobs_started", "jobs_confirmed")  # footer of a transmitter's traffic log; a file in which they differ is invalid
# a file of this name in a run directory: nothing there is a result. EXCLUDED is written by the measurement
# drivers when one of their validity gates fails (its text is the reason).
MARKERS = ("DRY_RUN", "PILOT", "EXCLUDED")


def markers(run_dir):
    """Every marker file that concerns run_dir, as (name, path): in MARKERS order, and for each name
    the nearest directory first. A marker covers its own directory and everything below it; and if
    run_dir is a collection that holds a marked run anywhere below, the whole analysis is marked,
    because its numbers would mix with the rest."""
    run_dir = Path(run_dir).resolve()
    found = []
    for name in MARKERS:
        found += [(name, d / name) for d in (run_dir, *run_dir.parents) if (d / name).is_file()]
        found += [(name, p) for p in sorted(run_dir.rglob(name), key=lambda p: (len(p.parts), p))
                  if p.parent != run_dir and p.is_file()]
    return found


def marker(run_dir):
    """(name, path) of the marker that labels the analysis of run_dir, else None: the first of
    markers(), so DRY_RUN wins over PILOT and PILOT over EXCLUDED."""
    found = markers(run_dir)
    return found[0] if found else None


def read_env(path):
    """env_<host>.txt as capture_env.sh writes it: blocks opened by '===== <label> <date> ====='
    (label 'before' or 'after') with one 'key=value' per line. Returns the host name and the
    get_throttled reading of every block in file order, as (label, text) pairs."""
    host, readings, label = None, [], None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in map(str.strip, f):
            m = re.fullmatch(r"=====\s*(\S+).*=====", line)
            if m:
                label = m[1]
            elif line.startswith("hostname="):
                host = host or line.partition("=")[2]
            elif line.startswith("throttled="):
                readings.append((label, line.partition("=")[2]))
    return {"host": host or Path(path).stem.removeprefix("env_"), "throttled": readings}


def throttling(readings, where):
    """Judges `vcgencmd get_throttled` readings taken in time order (texts such as 'throttled=0x50000').

    Returns (state, reasons, warnings). Invalid: a currently-active bit (0-3: under-voltage, frequency
    capped, throttled, soft temperature limit) in any reading, or readings that differ (something
    happened between them). Warning: the same sticky bits (16-19, 'has occurred since boot') before
    and after. state is True if any bit was seen; False if at least two readings exist and all are
    0; None otherwise: a single reading cannot show that nothing happened during the run, and a
    reading that is not a number ('unavailable') is unknown, not zero.
    """
    values = []
    for text in readings:
        try:
            values.append(int(text.rpartition("=")[2], 0))
        except ValueError:
            pass
    if not values:
        return None, [], []
    shown, reasons, warnings = " -> ".join(f"{v:#x}" for v in values), [], []
    if any(v & 0xF for v in values):
        reasons.append(f"throttling active ({where}: get_throttled {shown})")
    elif len(set(values)) > 1:
        reasons.append(f"get_throttled changed during the run ({where}: {shown})")
    elif values[0] and len(values) > 1:
        warnings.append(f"throttling had occurred before the run ({where}: get_throttled {shown}, sticky bits only)")
    return (True if any(values) else False if len(values) > 1 else None), reasons, warnings


def _same_counts(meta, keys, event, differ, log=None):
    """Reasons unless the two count lines `keys` are both in `meta`, are counts and agree. `event` is what a missing
    or unreadable pair leaves open, `differ(a, b, shown)` the reason for a difference, `log` the traffic log the lines
    were read from when they are not the file's own."""
    a, b = (meta.get(k) for k in keys)
    shown = ", ".join(f"{k}={meta.get(k)}" for k in keys) + (f" (read from {log})" if log else "")
    if a is None or b is None:
        return [f"{' / '.join(keys)} missing{f' in {log}' if log else ''}: whether {event} is not recorded"]
    if not all(v.isascii() and v.isdigit() for v in (a, b)):
        return [f"{shown}: not counts, so whether {event} is not known"]
    return [differ(int(a), int(b), shown)] if int(a) != int(b) else []


def jobs(meta, log=None):
    """Reasons from the footer lines jobs_started and jobs_confirmed (DATA_SCHEMA.md, 'Jobs given up'): a file in
    which they differ is invalid, and so is one that does not say. A started job that was not confirmed either had a
    failed confirmation (the footer's tx_confirmations_failed) or was given up without one; in both cases its row
    received the next PDU. The reason states the two counts and, when the footer gives a count of failed
    confirmations that fits, how the difference divides."""
    def differ(a, b, shown):
        if a < b:
            return f"{shown} differ: more jobs confirmed than started"
        failed = meta.get("tx_confirmations_failed", "")
        split = failed.isascii() and failed.isdigit() and int(failed) <= a - b
        return f"{a - b} job(s) started and not confirmed ({shown})" + (
            f", of which {failed} with a failed confirmation (tx_confirmations_failed) and {a - b - int(failed)} given up "
            "without one" if split else "")

    return _same_counts(meta, JOBS, "every started job was confirmed", differ, log)


# the line in which a file counts its own rows: 'rows'; in a joined attack file 'pdus', in a clock probe's file the exchanges
ROW_COUNT = {"attack": "pdus", "clock_probe": "exchanges_completed", "clock_map": "samples"}
NOT_ZERO = (("rows_lost", "rows of the log were lost"), ("stopped_early", "the run was stopped before its end"),
            ("contradicting_pdus", "the join script counted PDUs that contradict"))


def data_rows(path):
    """Number of data rows of a CSV file counted as lines (comment lines, empty lines and the column line left out):
    for a log whose rows are counted and not read."""
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        return max(0, sum(1 for ln in map(str.strip, f) if ln and not ln.startswith("#")) - 1)


def footer(meta, kind=None, rows=None, log=None):
    """Reasons from the counts a harness writes about a file (CAMPAIGN.md, 'Invalid files'): the file's count of its
    own rows (ROW_COUNT) is not the number of rows it has (`rows`; None: not counted, and then not judged), or one of
    NOT_ZERO is not 0. A line the file does not have is not judged: files written before these lines existed, and the
    gateway's logs, carry none. Anything but 0 is a reason, also a value that is no count. `log` names the traffic log
    the lines were read from when they judge the file beside it; a line that transport_lines() took from a log names
    its log itself."""
    out, came, key = [], meta.get(TRANSPORT_FROM, {}), ROW_COUNT.get(kind, "rows")
    v = meta.get(key)
    if rows is not None and v is not None and not (v.isascii() and v.isdigit() and int(v) == rows):
        out.append(f"{key}={v} in {log}, but that log has {rows} rows" if log else f"{key}={v}, but the file has {rows} rows")
    for key, what in NOT_ZERO:
        v, source = meta.get(key, "0"), log or came.get(key)
        if v != "0":
            out.append(f"{key}={v}" + (f" (read from {source})" if source else "") + ": "
                       + (what if v.isascii() and v.isdigit() else "not a count, so the file does not say 0"))
    return out


def transport(meta, kind):
    """Reasons why a networked harness file is invalid by its transport lines (DATA_SCHEMA.md,
    'Transport keys of the networked harness files'):
    - tcp_nodelay, the value read back with getsockopt, is not exactly 1, or the line is missing:
      with Nagle's algorithm on, several PDUs share a segment and wait for it;
    - in a transmitter file (periodic_tx, or the throughput file of the tx host),
      tcp_connections_at_first_release and tcp_connections_at_end differ: the connection was made
      again inside the measured window;
    - in a transmitter file, jobs_started and jobs_confirmed differ ('Jobs given up'; the schema
      reads the difference as jobs given up without a confirmation, whose row then received the
      next PDU; the reason states the two counts and no cause).
    Missing lines of a transmitter file, or values that are no counts, leave that unknown, and
    unknown is not 'the same'.
    Retransmissions never make a file invalid; their counts are reported. Releases dropped at a full
    queue (jobs_dropped_at_release) are no reason either."""
    read_from = meta.get(TRANSPORT_FROM) or {}

    def source(*keys):  # the traffic log these lines were read from, when the file itself did not carry them
        return " and ".join(dict.fromkeys(read_from[k] for k in keys if k in read_from)) or None

    src, reasons = (f" (read from {source('tcp_nodelay')})" if source("tcp_nodelay") else ""), []
    nodelay = meta.get("tcp_nodelay")
    if nodelay is None:
        reasons.append("no tcp_nodelay line: whether Nagle's algorithm was off on this connection is not recorded")
    elif nodelay == "0":
        reasons.append(f"tcp_nodelay=0{src}: Nagle's algorithm was not switched off on this connection")
    elif nodelay != "1":  # -1: the option could not be read back (for an attack file: an end has no read-back)
        reasons.append(f"tcp_nodelay={nodelay}{src}: not a read-back of 1, so whether Nagle's algorithm was off on this "
                       "connection is not known")
    if kind == "periodic_tx" or (kind == "throughput" and meta.get("host") is not None and meta.get("host") == meta.get("tx_host")):
        keys = ("tcp_connections_at_first_release", "tcp_connections_at_end")
        reasons += _same_counts(meta, keys, "the connection was established again inside the measured window",
                                lambda a, b, shown: f"the TCP connection was established again inside the measured window ({shown})",
                                source(*keys))
        reasons += jobs(meta, source(*JOBS))
    return reasons


# the counts of a transmitter's connection in the measured window (TCP_INFO at the end minus at the first release)
TRANSPORT_COUNTS = ("tcp_total_retrans_in_window", "tcp_dsack_dups_in_window", "tcp_total_rto_in_window")
TRANSPORT_WHAT = {
    "tcp_total_retrans_in_window": "retransmitted segments of the transmitter's connection in the measured window",
    "tcp_dsack_dups_in_window": "duplicate-SACK reports the transmitter received in the measured window (the peer already had "
                                "the segment)",
    "tcp_total_rto_in_window": "retransmission time-outs of the transmitter's connection in the measured window"}


def transport_counts(meta):
    """{key: count or None} for TRANSPORT_COUNTS. None when the line is missing or reads -1 ('the
    kernel or the board's header did not give the field'): unknown, which is never 0. Any other
    value that is no count is an error. The counts are reported; they never make a file invalid."""
    out = {}
    for k in TRANSPORT_COUNTS:
        v = meta.get(k)
        if v is not None and v != "-1" and not (v.isascii() and v.isdigit()):
            raise ValueError(f"header {k}={v!r} is neither a count nor -1")
        out[k] = None if v in (None, "-1") else int(v)
    return out


def validity(meta, kind, env=None):
    """Self-checks of a timing file, from the '# key=value' lines the harness wrote above and below
    its rows and from the run's env_<host>.txt (`env`: the read_env() result for this file's host,
    or None if the run has no such file). Returns None for a file that carries no such lines and has
    no env file (a legacy or hand-made file: nothing to check).

    Invalid, so the file must not be analysed:
    - signature_mismatches or failed_calls is not 0;
    - a harness-written file (it has '# tool=') of a kind in WITH_TRAILER lacks part of its trailer
      (freq_khz_end, wall_s, cpu_s, for overhead_paired also the two counters: the run did not
      finish, and absent counters are not zero) or its mlockall line;
    - mlockall is not 'ok';
    - the CPU frequency differs between start and end (the governor is fixed, so a change means
      throttling);
    - for the single-node kinds (SINGLE_THREAD) cpu_s / wall_s is below CPU_SHARE_MIN (the core was
      shared with something else); a networked gateway process waits between PDUs, so its share is
      reported but not judged;
    - get_throttled, in the file's own throttled_start / throttled_end lines or in the env file,
      shows an active bit or changes (see throttling());
    - a harness-written file of a kind in NETWORKED fails transport(): tcp_nodelay is not 1, a
      transmitter's connection was established again, or a transmitter's started job was not
      confirmed.
    Warning only: sticky throttling bits that were already set before the run.
    A reading that is not a number ('unavailable') is unknown and stays None.
    """
    own = _COUNTERS + _TRAILER + ("freq_khz_start", "mlockall", "throttled_start", "throttled_end")
    if "tool" not in meta and not any(k in meta for k in own) and env is None:
        return None
    out, reasons, warnings = {}, [], []
    for k in _COUNTERS:
        v = meta.get(k)
        if v is not None and not (v.isascii() and v.isdigit()):
            raise ValueError(f"header {k}={v!r} is not a non-negative integer")
        out[k] = None if v is None else int(v)
        if out[k]:
            reasons.append(f"{k}={out[k]}")
    if "tool" in meta and kind in WITH_TRAILER:
        missing = [k for k in (*_TRAILER, *(_COUNTERS if kind == "overhead_paired" else ())) if k not in meta]
        if missing:
            reasons.append(f"trailer missing ({', '.join(missing)}): the run did not finish")
        if "mlockall" not in meta:
            reasons.append("mlockall line missing")
    if "tool" in meta and kind in NETWORKED:
        reasons += transport(meta, kind)
    out["mlockall"] = meta.get("mlockall")
    if out["mlockall"] not in (None, "ok"):
        reasons.append(f"mlockall={out['mlockall']}")
    for k in ("freq_khz_start", "freq_khz_end"):
        v = meta.get(k, "")
        out[k] = int(v) if v.isascii() and v.isdigit() else None
    if None not in (out["freq_khz_start"], out["freq_khz_end"]) and out["freq_khz_start"] != out["freq_khz_end"]:
        reasons.append(f"CPU frequency changed during the run ({out['freq_khz_start']} -> {out['freq_khz_end']} kHz)")
    try:
        out["cpu_share"] = float(meta["cpu_s"]) / float(meta["wall_s"])
    except (KeyError, ValueError, ZeroDivisionError):
        out["cpu_share"] = None
    if kind in SINGLE_THREAD and out["cpu_share"] is not None and out["cpu_share"] < CPU_SHARE_MIN:
        reasons.append(f"cpu_s/wall_s = {out['cpu_share']:.3f}, below {CPU_SHARE_MIN}: the core was shared")
    out["throttled_start"], out["throttled_end"] = meta.get("throttled_start"), meta.get("throttled_end")
    states = []
    for where, readings in (("file", [t for t in (out["throttled_start"], out["throttled_end"]) if t is not None]),
                            (f"env file of {env['host']}" if env else "", [t for _, t in env["throttled"]] if env else [])):
        state, why, warn = throttling(readings, where)
        states.append(state)
        reasons += why
        warnings += warn
    out["env_throttled"] = [f"{label}: {text}" for label, text in env["throttled"]] if env else None
    out["throttled"] = True if True in states else False if False in states else None
    return {"valid": not reasons, "reasons": reasons, "warnings": warnings, **out}


_LEGACY_VECTOR = {"BENIGN": "benign", "REPLAY": "replay", "BIT_FLIP": "bitflip", "SIG_TAMPER": "auth_tamper",
                  "FRESHNESS_ROLLBACK": "freshness_rollback"}
_LEGACY_STAGE = {"OK": "none", "SIG_INVALID": "auth", "FRESH_REPLAY": "freshness", "FRESH_ROLLBACK": "freshness"}
_LEGACY_ARM = {"A_Standalone": "standalone", "B_CsmIntegrated": "csm"}


def _translate(path, column, values, table):
    unknown = sorted(set(values.tolist()) - set(table))
    if unknown:
        raise CsvError(f"{path}: column {column}: unknown legacy value(s) {unknown}")
    return np.array([table[v] for v in values.tolist()], dtype=str)


def load(path):
    """Read a recognised file and return (kind, meta, cols) in current-schema terms. Legacy files are
    converted: tx_perf_10k -> crypto_ops columns (op, seq, ns); attack_raw -> attack columns
    (delivered = 1 - detected, reject_stage from reason, detect_ns = duration_ns);
    phase_compare -> kind 'overhead_unpaired' with columns (op, arm, seq, ns)."""
    raw = kind_of(path)
    if raw is None:
        raise CsvError(f"{path}: file name not recognised")
    meta, c = read_csv(path, raw)
    if raw == "tx_perf_10k":
        return "crypto_ops", meta | {"legacy": raw}, {"op": c["phase"], "seq": c["seq"], "ns": c["ns_delta"]}
    if raw == "attack_raw":
        return "attack", meta | {"legacy": raw}, {
            "vector": _translate(path, "vector", c["vector"], _LEGACY_VECTOR), "iter": c["iter"],
            "delivered": np.where(c["detected"] == "1", "0", "1"),
            "reject_stage": _translate(path, "reason", c["reason"], _LEGACY_STAGE), "detect_ns": c["duration_ns"]}
    if raw == "phase_compare":
        parts = {p: re.fullmatch(r"(A_Standalone|B_CsmIntegrated)_(\w+)", p) for p in set(c["phase"].tolist())}
        bad = sorted(p for p, m in parts.items() if not m)
        if bad:
            raise CsvError(f"{path}: column phase: unknown legacy value(s) {bad}")
        return "overhead_unpaired", meta | {"legacy": raw}, {
            "op": _translate(path, "phase", c["phase"], {p: m[2].lower() for p, m in parts.items()}),
            "arm": _translate(path, "phase", c["phase"], {p: _LEGACY_ARM[m[1]] for p, m in parts.items()}),
            "seq": c["seq"], "ns": c["ns_delta"]}
    return raw, meta, c
