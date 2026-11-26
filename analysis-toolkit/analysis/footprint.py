"""Footprint figures taken with standard tools (CAMPAIGN.md, E8): counts only, no statistics, nothing timed.

    size_<label>.txt    'unstripped_bytes=N' and 'stripped_bytes=N', then the table of `size -A` of the stripped binary
                        (rows 'section size addr' up to 'Total'); one such block, or several, each under '== <build>/'
    perf_<op>_<n>.csv   `perf stat -x,` of <n> calls of one operation: '<count>,,<event>,<run time>,<share of the time
                        the counter ran>,...' for the events instructions:u and cycles:u
    rss_samples.txt     '<time> <host> VmSize: N kB VmHWM: N kB VmRSS: N kB VmData: N kB', one line per host and sample

A file of such a name without this shape (no unstripped_bytes line, neither event, no VmHWM field) is no footprint file:
the reader returns None and the file is left alone. A file that has the shape and contradicts itself is an error."""
import re
from pathlib import Path

SIZE, PERF, RSS = "size_*.txt", "perf_*.csv", "rss_samples.txt"
CAPTURE = "capture_*.txt"  # the driver's summary of the sending board's packet capture in a calibration run
CAPTURE_LINES = {"captured_frames_with_payload": "frames_with_payload", "tcp_payload_bytes": "tcp_payload_bytes",
                 "frame_bytes_as_captured": "frame_bytes", "jobs_confirmed": "jobs_confirmed"}  # line -> name here
PERF_NAME = re.compile(r"perf_(.+)_(\d+)\.csv")  # operation, number of calls
SECTIONS = {".text": "text_bytes", ".rodata": "rodata_bytes", ".data": "data_bytes", ".bss": "bss_bytes"}
BYTES = ("unstripped_bytes", "stripped_bytes")
EVENTS = {"instructions:u": "instructions", "cycles:u": "cycles"}
# the operations whose runs differ in the number of calls only: mldsa_verify of the primitive benchmark also signs in
# every iteration; mldsa_verify_only is the tool that signs once and then only verifies (E9_SPEC.md, rulings of 2026-11-24)
PER_CALL = ("mldsa_sign", "mldsa_verify_only")
NOT_PER_CALL = ("perf stat run that is not turned into a per-call figure: only " + " and ".join(PER_CALL) + " are, from "
                "exactly two runs of different length in one directory (a verify run of the tool also signs in every iteration)")
ONE_PAIR = "one pair of runs, user space only, no interval"


def sizes(path):
    """[{build, unstripped_bytes, stripped_bytes, text_bytes, rodata_bytes, data_bytes, bss_bytes}], one per block of the
    file; build is None for a block without a '== <build>/' line. The rows of a block must add up to its Total."""
    text = Path(path).read_text(errors="replace")
    if "unstripped_bytes=" not in text:
        return None
    builds, b = [], None
    for line in map(str.strip, text.splitlines()):
        if m := re.fullmatch(r"== (.+?)/?", line):
            builds.append(b := {"build": m[1], "rows": 0})
        elif m := re.fullmatch(r"(\w+)=(\d+)", line):
            if b is None or m[1] in b:  # a file without '==' lines, or its next block
                builds.append(b := {"build": None, "rows": 0})
            b[m[1]] = int(m[2])
        elif b and (m := re.fullmatch(r"(\S+)\s+(\d+)\s+\d+", line)):
            b["rows"] += int(m[2])
            if m[1] in SECTIONS:
                b[SECTIONS[m[1]]] = int(m[2])
        elif b and (m := re.fullmatch(r"Total\s+(\d+)", line)):
            if int(m[1]) != b["rows"]:
                raise ValueError(f"{path}: build {b['build']}: the rows add up to {b['rows']} bytes, Total says {m[1]}")
            b["total"] = True
    for b in builds:
        missing = [k for k in (*BYTES, *SECTIONS.values()) if k not in b]
        if missing or "total" not in b:
            raise ValueError(f"{path}: build {b['build']}: {', '.join(missing) + ' missing' if missing else 'no Total line'}")
    return [{k: b[k] for k in ("build", *BYTES, *SECTIONS.values())} for b in builds]


def perf(path):
    """{instructions, cycles} of one perf stat file. A value that is no whole number ('<not counted>'), or a counter
    that did not run for all of the time (its count is then an estimate), is an error."""
    counts = {}
    for f in (line.strip().split(",") for line in Path(path).read_text(errors="replace").splitlines()):
        if len(f) > 4 and f[2] in EVENTS:
            if not f[0].isdigit() or f[4] != "100.00":
                raise ValueError(f"{path}: {f[2]} is no whole count of the whole run (value {f[0]!r}, counter running "
                                 f"{f[4]!r}% of the time)")
            counts[EVENTS[f[2]]] = int(f[0])
    if counts and len(counts) < len(EVENTS):
        raise ValueError(f"{path}: has {', '.join(counts)} only; a per-call figure needs both {' and '.join(EVENTS)}")
    return counts or None


def per_call(runs):
    """`runs`: {number of calls: {instructions, cycles}} of two runs of one operation. Per call: the difference of the
    counts over the difference of the calls, so that what the tool does before and after its calls cancels; and
    instructions per cycle as the ratio of the two differences. ONE_PAIR: there is nothing to form an interval from."""
    (n1, a), (n2, b) = sorted(runs.items())
    d = {k: (b[k] - a[k]) / (n2 - n1) for k in EVENTS.values()}
    if min(d.values()) <= 0:
        raise ValueError(f"the run of {n2} calls does not count more instructions and cycles than the run of {n1}")
    return {"instructions_per_call": d["instructions"], "cycles_per_call": d["cycles"],
            "instructions_per_cycle": d["instructions"] / d["cycles"]}


def rss(path):
    """{host: {samples, vmhwm_max_kb}}: the number of sample lines of each host and the largest VmHWM among them. A
    line without a host and a VmHWM in kB is an error: a sample that could not be read is not passed over."""
    lines = [ln.strip() for ln in Path(path).read_text(errors="replace").splitlines() if ln.strip()]
    if not any("VmHWM:" in ln for ln in lines):
        return None
    hosts = {}
    for ln in lines:
        m = re.fullmatch(r"\S+ (\S+) .*?\bVmHWM:\s+(\d+) kB\b.*", ln)
        if not m:
            raise ValueError(f"{path}: a sample line without a host and a VmHWM in kB: {ln!r}")
        h = hosts.setdefault(m[1], {"samples": 0, "vmhwm_max_kb": 0})
        h["samples"], h["vmhwm_max_kb"] = h["samples"] + 1, max(h["vmhwm_max_kb"], int(m[2]))
    return hosts


def capture(path):
    """The counts of a capture_<host>.txt and three plain ratios of them: the frames with TCP payload in the capture,
    their TCP payload bytes and frame bytes, the PDUs the sender confirmed ('# jobs_confirmed='); frames_per_pdu =
    frames / PDUs, frame_bytes_per_frame and tcp_payload_bytes_per_frame = bytes / frames. Nothing is taken off: the
    capture also holds the frames of the session set-up. None for a file with none of the four lines (no capture
    file); a file that has some and lacks one, or in which one is no positive whole number, is damaged: an error."""
    found = dict(m.groups() for ln in Path(path).read_text(errors="replace").splitlines()
                 if (m := re.fullmatch(r"#?\s*(\w+)=(\S+)", ln.strip())))
    if not any(line in found for line in CAPTURE_LINES):
        return None
    bad = [line for line in CAPTURE_LINES if not (found.get(line, "").isascii() and found.get(line, "").isdigit() and int(found[line]))]
    if bad:
        raise ValueError(f"{path}: a capture file needs these lines as positive whole numbers: {', '.join(bad)}")
    c = {name: int(found[line]) for line, name in CAPTURE_LINES.items()}
    return {**c, "frames_per_pdu": c["frames_with_payload"] / c["jobs_confirmed"],
            "frame_bytes_per_frame": c["frame_bytes"] / c["frames_with_payload"],
            "tcp_payload_bytes_per_frame": c["tcp_payload_bytes"] / c["frames_with_payload"]}
