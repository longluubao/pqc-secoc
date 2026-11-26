"""hsneg.txt: the oracle's record of a negative handshake test (DATA_SCHEMA.md, 'Record of a negative handshake test').

The file has lines for a reader, then exactly one line that starts with 'test=', then PASS or REJECT as its last
line. The counts of the two ends' handshake files are taken by the toolkit itself (handshake.counts) and compared with
the record's seen_tx / seen_rx; the record gives what the files cannot: which test it was, what was asked and attacked,
and the oracle's verdict."""
from analysis import csvio

FIELDS = ("test", "variant", "repetitions", "attacked", "verdict", "expected_tx", "seen_tx", "expected_rx", "seen_rx",
          "repetitions_done", "runs", "runs_passed", "pdus_sent", "pdus_delivered", "pdus_rejected", "pdus_given_up",
          "installs_tx", "installs_rx", "tcp_nodelay_tx", "tcp_nodelay_rx")
VARIANTS = ("none", "drop", "sig", "mac", "key", "flip")
LISTS = ("expected_tx", "seen_tx", "expected_rx", "seen_rx")
LAST = {"PASS": "PASS", "FAIL": "REJECT"}  # the file's last line for each verdict
RESULTS = ("ok", "bad_ver", "bad_len", "unknown_id", "sig_fail", "mac_fail", "timeout", "state")  # the schema's order
assert set(RESULTS) == dict(csvio.SCHEMAS["handshake"])["result"]
SIDES = {"initiator": "tx", "responder": "rx"}  # the record calls the initiator tx and the responder rx


def _count(text):
    return int(text) if text.isascii() and text.isdigit() else None


def _list(text):
    """'ok:1,sig_fail:3' -> {'ok': 1, 'sig_fail': 3}; 'none' -> {}; None unless the classes are result classes of the
    schema, in its order, each once and with a count above 0 (the record lists only classes that occur)."""
    if text == "none":
        return {}
    parts = [p.partition(":") for p in text.split(",")]
    out = {k: _count(v) for k, _, v in parts}
    if len(out) != len(parts) or list(out) != [r for r in RESULTS if r in out] or not all(out.values()):
        return None
    return out


def read(path):
    """The record as a dict (counts as int, the four lists as {result: count}), or None for a file without a 'test='
    line (the format before 2026-11-23 10:41). A record that is not in the agreed format raises ValueError."""
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [s.strip() for s in f if s.strip()]
    records = [s for s in lines if s.startswith("test=")]
    if not records:
        return None

    def bad(what):
        return ValueError(f"{path}: {what}")

    if len(records) != 1:
        raise bad(f"{len(records)} lines start with 'test='; the record is exactly one line")
    pairs = [field.partition("=") for field in records[0].split(" ")]
    if tuple(k for k, _, _ in pairs) != FIELDS:
        raise bad(f"{[k for k, _, _ in pairs]} are not the fields of the record in their order ({' '.join(FIELDS)})")
    r = {}
    for k, _, text in pairs:
        if k == "variant":
            value, what = (text if text in VARIANTS else None), f"one of {', '.join(VARIANTS)}"
        elif k == "verdict":
            value, what = (text if text in LAST else None), "PASS or FAIL"
        elif k in LISTS:
            value, what = _list(text), "a list result:count of result classes that occur, in the schema's order, or none"
        elif k.startswith("tcp_nodelay"):
            value, what = (int(text) if text in ("1", "0", "-1") else None), "1, 0 or -1"
        elif k == "test":
            value, what = _count(text), "a test number from 1 to 12"
            value = value if value is not None and 1 <= value <= 12 else None
        else:
            value, what = _count(text), "a count"
        if value is None:
            raise bad(f"{k}={text!r} is not {what}")
        r[k] = value
    if lines[-1] != LAST[r["verdict"]]:
        raise bad(f"verdict={r['verdict']} but the last line is {lines[-1]!r} (PASS goes with PASS, FAIL with REJECT)")
    return r


def label(record, directory):
    """Key part of a negative test: t<test>[-<variant>] from its record; without a record the directory's name, since
    nothing else says which test it was."""
    if record is None:
        return directory
    return f"t{record['test']}" + ("" if record["variant"] == "none" else f"-{record['variant']}")


def disagreement(record, sides, where):
    """Reasons why the record's seen_tx / seen_rx are not the counts `sides` ({role: {'n', 'results'}}) found in the
    handshake files: the oracle read the same files, so a difference means the record is of other files."""
    def shown(results):
        return ", ".join(f"{k}: {v}" for k, v in results.items()) or "none"

    out = []
    for role, side in SIDES.items():
        results = sides.get(role, {}).get("results", {})
        found = {r: results[r] for r in RESULTS if results.get(r)}  # the record lists only the classes that occur
        if record[f"seen_{side}"] != found:
            out.append(f"seen_{side}={shown(record[f'seen_{side}'])} in the record, but the {role}'s handshake files below "
                       f"{where} have {shown(found)}")
    return out
