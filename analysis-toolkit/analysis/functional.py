"""Functional runs of the gateway binaries (DATA_SCHEMA.md, 'Functional runs of the gateway binaries' and 'Contract of
the gateway's application logs'): a directory with the marker FUNCTIONAL holds the gateways' own records of one run.
Counts only, never a time:

    app_tx*.csv        stream,seq,submit_ns,start_ns,auth_done_ns,send_done_ns   one row per PDU whose transmission was confirmed
    app_rx*.csv        stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result    one row per outcome at the receiver
    rx_payload*.csv    stream,seq,payload_hex                                    one row per delivered PDU, in the order of the ok rows
    handshake_tx*.csv, handshake_rx*.csv                                         the handshake.csv columns; one row per attempt that
                                                                                 ended or message discarded without ending one

A replaced gateway process continues in a numbered part (app_rx2.csv); the parts are read in numeric order and added. The
driver's joined copies (*_all.csv) hold the same rows again and are not read. A process writes one '# tcp_nodelay=' line
per TCP connection it had, behind the column line. The receiver takes the stream of a delivered row from the PDU ID and
its sequence number from the last four bytes of the delivered payload, which is why order and payload are judged
against the transmitter's rows. None of the time columns is read."""
import re

import numpy as np

from analysis import csvio, handshake

MARKER = "FUNCTIONAL"
STEMS = ("app_tx", "app_rx", "rx_payload", "handshake_tx", "handshake_rx")
SCHEMAS = {"app_tx": (("stream", csvio.STR), ("seq", csvio.INT), ("submit_ns", csvio.INT), ("start_ns", csvio.INT),
                      ("auth_done_ns", csvio.INT), ("send_done_ns", csvio.INT)),
           "app_rx": csvio.SCHEMAS["periodic_rx"],
           "rx_payload": (("stream", csvio.STR), ("seq", csvio.INT), ("payload_hex", csvio.STR)),
           "handshake_tx": csvio.SCHEMAS["handshake"], "handshake_rx": csvio.SCHEMAS["handshake"]}
REJECTED = ("freshness_fail", "auth_fail", "framing_fail")  # every result of app_rx but ok
MISSING = {"app_tx": "the transmitting side's record", "app_rx": "the receiving side's record", "rx_payload": "the delivered payloads"}
PAYLOAD_LEN = 8  # the one payload length the contract defines the bytes for (pattern())
SIDE = {"app_tx": "tx", "handshake_tx": "tx", "app_rx": "rx", "rx_payload": "rx", "handshake_rx": "rx"}  # the process a file is of
IN_ORDER = ("delivered PDUs met in the order they were sent: per stream, each delivered sequence number is looked for in "
            "the transmitter's rows (all its parts, one after the other) after the last one found; a PDU that arrives "
            "late, twice, or was never sent is not counted")
BYTE_EXACT = ("delivered PDUs, among those in order, whose payload in rx_payload*.csv has the pattern of a PDU that the "
              "transmitter sent on that stream (byte 0 the stream index, bytes 1 to 3 zero, bytes 4 to 7 the sequence "
              "number, big-endian; defined for 8-byte payloads only); the receiver decodes the sequence number from those "
              "last four bytes, so this does not test the sequence number independently of the payload")
REJECTED_NOTE = ("the rows of app_rx*.csv with another result than ok: what the streams of the run's variant saw (a PDU of a "
                 "row that is not a stream of the variant writes no row at all); auth_fail means that the verification "
                 "failed or could not be done, not only a wrong authenticator")


class Invalid(ValueError):
    """The files of a functional run are not the record of one run; `reasons` says why."""

    def __init__(self, reasons):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


def parts(directory):
    """({stem: its files in `directory` in numeric order of their part}, [the driver's joined *_all.csv files])."""
    found, joined = {stem: [] for stem in STEMS}, []
    for p in sorted(directory.iterdir()):
        m = re.fullmatch(rf"({'|'.join(STEMS)})(\d*|_all)\.csv", p.name)
        if m and m[2] == "_all":
            joined.append(p)
        elif m:
            found[m[1]].append((int(m[2] or 1), p))  # app_rx.csv is the first part, app_rx2.csv the second
    return {stem: [p for _, p in sorted(numbered)] for stem, numbered in found.items()}, joined


def missing(found):
    """Reasons why the files in `found` are not a whole run; None when neither side wrote anything (no run at all)."""
    if not found["app_tx"] and not found["app_rx"]:
        return None
    return [f"no {stem}*.csv: {what} {'are' if stem == 'rx_payload' else 'is'} missing, the run is incomplete"
            for stem, what in MISSING.items() if not found[stem]]


def in_order(sent, delivered):
    """For each of the `delivered` sequence numbers of a stream, whether it is met in the `sent` sequence after the
    last one that was met (each sent PDU serves once). A restarted transmitter counts from 0 again, and its rows follow
    those of the first in `sent`, so its PDUs are in order without a rule of their own."""
    out, start = [], 0
    for q in delivered:
        try:
            start = sent.index(q, start) + 1
            out.append(True)
        except ValueError:
            out.append(False)
    return out


def pattern(stream, seq, payload_len):
    """The payload, in lower-case hex, of PDU `seq` of `stream` (the contract: byte 0 the stream index, bytes 1 to 3
    zero, bytes 4 to 7 the sequence number, 32 bit, big-endian). None where the contract defines none: another payload
    length, a stream that is no index of one byte, a sequence number that is no 32-bit number."""
    if payload_len != PAYLOAD_LEN or not (stream.isascii() and stream.isdigit() and int(stream) < 256) or not 0 <= seq < 2 ** 32:
        return None
    return f"{int(stream):02x}000000{seq:08x}"


def part_number(p):
    """app_rx.csv is the first part of its process's files, app_rx2.csv the second."""
    return int(re.search(r"(\d*)\.csv$", p.name)[1] or 1)


def unread_connections(found, carried):
    """Reasons from the '# tcp_nodelay=' lines of every file of the run: each line is one TCP connection of the file's
    process and must read 1; a file without any line is a reason when its process carried PDUs (`carried`: the
    (side, part) pairs whose app file has rows), because then a connection existed and was not read back."""
    reasons = []
    for stem in STEMS:
        for p in found[stem]:
            values = csvio.all_values(p, "tcp_nodelay")
            reasons += [f"{p.name}: TCP connection {k} of {len(values)} reads tcp_nodelay={v}, not 1"
                        for k, v in enumerate(values, 1) if v != "1"]
            if not values and (SIDE[stem], part_number(p)) in carried:
                reasons.append(f"{p.name}: no tcp_nodelay line although its process carried PDUs: no connection was read back")
    return reasons


def e2e_columns(found):
    """(sender's rows, receiver's rows) of a run, all parts one after the other, under the names the e2e analysis takes
    (E9_SPEC.md, cell g): the release is submit_ns, and the place of the reception takes verify_done_ns, because the
    gateway records no rx_done_ns. These are the only time columns of a functional run that are ever read."""
    def rows(stem, names):
        cols = [csvio.read_csv(p, stem, SCHEMAS[stem])[1] for p in found[stem]]
        return {name: np.concatenate([c[column] for c in cols]) for name, column in names.items()}
    return (rows("app_tx", {"stream": "stream", "seq": "seq", "release_ns": "submit_ns", "send_done_ns": "send_done_ns"}),
            rows("app_rx", {"stream": "stream", "seq": "seq", "rx_done_ns": "verify_done_ns", "deliver_ns": "deliver_ns",
                            "result": "result"}))


def analyse(found):
    """The counts of one run from its files (`found` as parts() gives them; missing() has found nothing missing).
    Raises csvio.CsvError for a file that cannot be read and Invalid when a connection did not read back tcp_nodelay=1
    (unread_connections) or rx_payload does not list the delivered rows.

    sent: rows of app_tx (a row is a confirmed PDU), per stream.
    delivered: rows of app_rx with result ok, per stream.  rejected: the other rows, per result class (REJECTED_NOTE).
    delivered_in_order: IN_ORDER.  delivered_byte_exact: BYTE_EXACT; None when the payload length is not PAYLOAD_LEN.
    handshakes: rows per role and result over all handshake files (handshake.counts; nothing is timed).
    connections: per side, the '# tcp_nodelay=' lines of its app files (one per TCP connection) and how many read 1."""
    read = {stem: [csvio.read_csv(p, stem, SCHEMAS[stem]) for p in found[stem]] for stem in STEMS}
    carried = {(SIDE[stem], part_number(p)) for stem in ("app_tx", "app_rx")
               for p, (_, c) in zip(found[stem], read[stem]) if c["seq"].size}
    if reasons := unread_connections(found, carried):
        raise Invalid(reasons)
    head = read["app_tx"][0][0]
    sent = {}
    for _, c in read["app_tx"]:
        for s, q in zip(c["stream"].tolist(), c["seq"].tolist()):
            sent.setdefault(s, []).append(q)
    if head.get("streams", "").isdigit():  # a stream the header names has its (zero) counts also when nothing was sent
        for k in range(int(head["streams"])):
            sent.setdefault(str(k), [])
    delivered, rejected = [], dict.fromkeys(REJECTED, 0)
    for _, c in read["app_rx"]:
        for s, q, result in zip(c["stream"].tolist(), c["seq"].tolist(), c["result"].tolist()):
            if result == "ok":
                delivered.append((s, q))
            else:
                rejected[result] += 1
    listed = [row for _, c in read["rx_payload"] for row in zip(c["stream"].tolist(), c["seq"].tolist(), c["payload_hex"].tolist())]
    if len(listed) != len(delivered):
        raise Invalid([f"rx_payload*.csv has {len(listed)} rows, app_rx*.csv has {len(delivered)} delivered rows: the payload "
                       "file does not list the delivered PDUs"])
    for n, ((s, q, _), was) in enumerate(zip(listed, delivered), 1):
        if (s, q) != was:
            raise Invalid([f"rx_payload*.csv row {n} is stream {s} seq {q}, delivered row {n} of app_rx*.csv is stream {was[0]} "
                           f"seq {was[1]}: the payload file does not list the delivered PDUs in their order"])
    payload_len = int(head["payload_len"]) if head.get("payload_len", "").isdigit() else None
    judged = payload_len == PAYLOAD_LEN
    per_stream = []
    for s in sorted({*sent, *(s for s, _ in delivered)}, key=lambda s: (not s.isdigit(), int(s) if s.isdigit() else 0, s)):
        was_sent, got = sent.get(s, []), [(q, h) for d, q, h in listed if d == s]
        ordered = in_order(was_sent, [q for q, _ in got])
        exact = sum(ok and h == pattern(s, q, payload_len) for ok, (q, h) in zip(ordered, got)) if judged else None
        per_stream.append({"stream": s, "sent": len(was_sent), "delivered": len(got), "delivered_in_order": sum(ordered),
                           "delivered_byte_exact": exact})
    sides = {}
    for _, c in read["handshake_tx"] + read["handshake_rx"]:
        for role, tally in handshake.counts(c).items():
            side = sides.setdefault(role, {"n": 0, "results": {}})
            side["n"] += tally["n"]
            for result, k in tally["results"].items():
                side["results"][result] = side["results"].get(result, 0) + k
    connections = {}
    for side, stem in (("tx", "app_tx"), ("rx", "app_rx")):
        values = [v for p in found[stem] for v in csvio.all_values(p, "tcp_nodelay")]
        connections[side] = {"n": len(values), "nodelay_1": values.count("1")}
    return {"profile": head.get("profile"), "payload_len": payload_len, "streams": len(per_stream),
            "tx_parts": len(found["app_tx"]), "rx_parts": len(found["app_rx"]),
            **{k: sum(st[k] for st in per_stream) for k in ("sent", "delivered", "delivered_in_order")},
            "delivered_byte_exact": sum(st["delivered_byte_exact"] for st in per_stream) if judged else None,
            "rejected": rejected, "per_stream": per_stream, "handshakes": sides, "connections": connections}
