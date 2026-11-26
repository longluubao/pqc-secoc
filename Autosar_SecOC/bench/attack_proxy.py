#!/usr/bin/env python3
"""On-path attacker for the secured PDU stream: a TCP relay between transmitter and receiver.

    attack_proxy.py --listen PORT --connect HOST:PORT --log FILE --vector V[,V...] --every M
                    [--count N] [--seed S] [--layout ID:HDR:PAYLOAD:FRESHNESS ...]
    attack_proxy.py --selftest

The transmitter connects to --listen; the proxy connects on to the receiver. It holds no key and
parses only the SoAd PDU header (4-byte ID, 4-byte length, big endian) to find PDU boundaries.
Every M-th PDU of the incoming stream is attacked, the vectors taking turns:

    replay              forward the PDU, then send the same bytes again
    bitflip             flip one random bit of the Authentic I-PDU and forward that instead
    auth_tamper         flip one random bit of the authenticator and forward that instead
    freshness_rollback  put the freshness field of the previous PDU into this one and forward that
    session_replay      forward the PDU, then send a PDU recorded in an earlier session (--session-file,
                        written by --record in that run): the one with the smallest freshness value
                        above the PDU just forwarded, so that the freshness check lets it through

Where the fields are is configuration, per PDU header ID: --layout ID:HDR:PAYLOAD:FRESHNESS gives
the lengths of the Secured I-PDU header, the Authentic I-PDU and the transmitted freshness; the
authenticator is the rest (default 16:1:8:4, signature stream 0 with header ID 0x10: one length byte, 8 payload
bytes, the complete 32-bit freshness value). PDUs with another header ID are forwarded untouched
and logged as 'other', except the IDs of --pass-ids (default: the four handshake messages), which
are forwarded without a log row because the receiver's log has no row for them either. What the
receiver sends back (the handshake's M2 and M4) is relayed to the transmitter.

Handshake messages can be edited on the wire, in either direction:
    --hs ID:drop[@SEL]               do not forward the PDU with header ID
    --hs ID:flip:OFFSET:LEN[@SEL]    flip one random bit in bytes OFFSET..OFFSET+LEN-1 of its body
    --hs ID:replace:OFFSET:FILE[@SEL]  put the bytes of FILE at OFFSET of its body
    --hs ID:resign[@SEL]             M2 (0x31) or M3 (0x32) only: replace the signature by one that the
                                     program --forge makes over the same signed data ('R' || th2 or
                                     'I' || th3, computed from the messages as forwarded) with a key pair
                                     it creates for that call. No key of either gateway is involved.
    --hs-inject ID:FILE:to_receiver|to_transmitter:START_S:PERIOD_S:COUNT
                                     send the bytes of FILE as a PDU with header ID, COUNT times, every
                                     PERIOD_S seconds, starting START_S seconds after the first M4 has
                                     passed (a session is established)
    --hs-record PREFIX               write the body of the first PDU of each handshake header ID to
                                     PREFIX<id>.bin (30..33), for the replays of a later run
ID as 0x30..0x33 for M1..M4. SEL chooses the occurrences of that header ID: N (the N-th only,
default 1), N+ (the N-th and all later ones), N/S (the N-th and every S-th after it). Edits and
injections go to --hs-log (index,direction,header_id,occurrence,action,detail), not to the PDU log.

The log has one row per PDU sent to the receiver, in order: index,vector,iter,src_seq,detail.
src_seq is the big-endian number in the last four bytes of the Authentic I-PDU as the transmitter
sent it. Joined with the receiver's own log (join_attack.py) it gives attack.csv.

Limits: it sits on one of the two hosts, sees only TCP payload (no link-layer manipulation), and
does nothing about timing. It must never run during a timing experiment.
"""
import argparse
import hashlib
import random
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

VECTORS = ("replay", "bitflip", "auth_tamper", "freshness_rollback", "session_replay")
HEADER = struct.Struct(">II")
# PQC-SecOC-HS-v1 (PqcHs.h): M2 = ver || ID_B (32) || ct (1088) || sig_B (3309) || mac_B (32),
# M3 = ver || sig_A (3309) || mac_A (32). Needed by 'resign' only.
M1, M2, M3, M4 = 0x30, 0x31, 0x32, 0x33
HS_LABEL = b"PQC-SecOC-HS-v1"
SIG_SPAN = {M2: (1121, 4430), M3: (1, 3310)}


def split_pdus(buffer):
    """Complete PDUs (header ID, body) at the front of buffer, and the bytes left over."""
    pdus, pos = [], 0
    while len(buffer) - pos >= HEADER.size:
        header_id, length = HEADER.unpack_from(buffer, pos)
        if len(buffer) - pos - HEADER.size < length:
            break
        pdus.append((header_id, bytes(buffer[pos + HEADER.size:pos + HEADER.size + length])))
        pos += HEADER.size + length
    return pdus, buffer[pos:]


def fields(body, layout):
    """Byte ranges (payload, freshness, authenticator) of a Secured I-PDU body, or None if too short."""
    hdr, payload, fresh = layout
    if len(body) <= hdr + payload + fresh:
        return None
    return (hdr, hdr + payload), (hdr + payload, hdr + payload + fresh), (hdr + payload + fresh, len(body))


def flip_bit(body, span, rng):
    bit = rng.randrange(span[0] * 8, span[1] * 8)
    out = bytearray(body)
    out[bit // 8] ^= 1 << (bit % 8)
    return bytes(out), f"bit {bit % 8} of byte {bit // 8}"


def attack(vector, body, layout, rng, previous_freshness, old_session=()):
    """The bodies to send in place of `body`, as (vector label, body, detail) in sending order.
    An attack that cannot be built (no earlier freshness yet, no recorded PDU with a later freshness)
    leaves the PDU benign. old_session: (freshness, body) of an earlier session, sorted."""
    payload, fresh, auth = fields(body, layout)
    if vector == "session_replay":
        current = body[fresh[0]:fresh[1]]       # big endian: bytes compare as the numbers do
        later = next((old for value, old in old_session if value > current), None)
        if later is not None:
            return [("benign", body, ""),
                    ("session_replay", later, f"old-session PDU with freshness {later[fresh[0]:fresh[1]].hex()} after {current.hex()}")]
    if vector == "replay":
        return [("benign", body, ""), ("replay", body, "same bytes again")]
    if vector == "bitflip":
        changed, where = flip_bit(body, payload, rng)
        return [("bitflip", changed, where)]
    if vector == "auth_tamper":
        changed, where = flip_bit(body, auth, rng)
        return [("auth_tamper", changed, where)]
    if vector == "freshness_rollback" and previous_freshness not in (None, body[fresh[0]:fresh[1]]):
        changed = body[:fresh[0]] + previous_freshness + body[fresh[1]:]
        return [("freshness_rollback", changed, f"freshness {body[fresh[0]:fresh[1]].hex()} -> {previous_freshness.hex()}")]
    return [("benign", body, "")]


class Relay:
    """Decides, PDU by PDU, what goes to the receiver; keeps the log rows."""

    def __init__(self, vectors, every, count, seed, layouts, passes=(), session=b""):
        self.vectors, self.every, self.count, self.layouts = vectors, every, count, layouts
        self.passes = set(passes)       # header IDs that are not Secured I-PDUs: forwarded, no log row
        self.rng = random.Random(seed)
        self.seen = self.injected = self.passed = self.bytes_back = self.not_built = 0
        self.old_session = {}           # header ID -> [(freshness, body)] of an earlier session, sorted
        for header_id, body in split_pdus(session)[0]:
            spans = fields(body, layouts[header_id]) if header_id in layouts else None
            if spans:
                self.old_session.setdefault(header_id, []).append((body[spans[1][0]:spans[1][1]], body))
        for recorded in self.old_session.values():
            recorded.sort()
        self.iters = {}
        self.previous_freshness = {}
        self.rows = []

    def process(self, header_id, body):
        """Wire bytes to send for one incoming PDU."""
        if header_id in self.passes:
            self.passed += 1
            return HEADER.pack(header_id, len(body)) + body
        layout = self.layouts.get(header_id)
        spans = fields(body, layout) if layout else None
        if spans is None:
            out = [("other", body, "")]
            src_seq = -1
        else:
            payload, fresh, _ = spans
            src_seq = int.from_bytes(body[payload[1] - 4:payload[1]], "big") if payload[1] - payload[0] >= 4 else -1
            self.seen += 1
            due = self.every and self.seen % self.every == 0 and (self.count is None or self.injected < self.count)
            vector = self.vectors[self.injected % len(self.vectors)] if due else None
            out = attack(vector, body, layout, self.rng, self.previous_freshness.get(header_id),
                         self.old_session.get(header_id, ()))
            if any(label != "benign" for label, _, _ in out):
                self.injected += 1
            elif due:
                self.not_built += 1     # the same vector is tried again at the next PDU that is due
            self.previous_freshness[header_id] = body[fresh[0]:fresh[1]]
        wire = b""
        for label, data, detail in out:
            self.rows.append((len(self.rows), label, self.iters.get(label, 0), src_seq, detail))
            self.iters[label] = self.iters.get(label, 0) + 1
            wire += HEADER.pack(header_id, len(data)) + data
        return wire


def parse_selector(text):
    """Occurrences of a header ID as (first, step): 'N' the N-th only, 'N+' from the N-th on,
    'N/S' the N-th and every S-th after it; '' is '1'."""
    if text.endswith("+"):
        return int(text[:-1]), 1
    first, _, step = text.partition("/")
    return int(first or 1), int(step or 0)


def selected(selector, n):
    first, step = selector
    return n == first if step == 0 else n >= first and (n - first) % step == 0


class HsEdits:
    """Edits of handshake messages by header ID and occurrence. forge(signed data) -> signature made
    with a key pair created for that call."""

    def __init__(self, items, seed, forge=None, record=None):
        self.rng = random.Random(seed ^ 0x48530000)
        self.edits, self.seen, self.rows, self.last = [], {}, [], {}
        self.forge, self.record, self.lock = forge, record, threading.Lock()
        for item in items:
            spec, _, when = item.partition("@")
            parts = spec.split(":")
            edit = {"id": int(parts[0], 0), "action": parts[1], "when": parse_selector(when)}
            if edit["action"] == "flip":
                edit["span"] = (int(parts[2]), int(parts[2]) + int(parts[3]))
            elif edit["action"] == "replace":
                edit["off"], edit["file"] = int(parts[2]), parts[3]
                with open(parts[3], "rb") as f:
                    edit["data"] = f.read()
            elif edit["action"] == "resign":
                if edit["id"] not in SIG_SPAN or forge is None:
                    raise SystemExit(f"--hs {item}: resign is for 0x31 (M2) and 0x32 (M3) and needs --forge")
            elif edit["action"] != "drop":
                raise SystemExit(f"--hs {item}: the action is drop, flip, replace or resign")
            self.edits.append(edit)

    def resign(self, header_id, body):
        """sig_B is over 'R' || H(L || M1 || M2 up to the signature), sig_A over 'I' || H(L || M1 || M2),
        with M1 and M2 as this proxy forwarded them (what the verifying side hashes when the edit of
        this run is the signature alone)."""
        m1, m2, (lo, hi) = self.last.get(M1), self.last.get(M2), SIG_SPAN[header_id]
        if len(body) < hi or m1 is None or (header_id == M3 and m2 is None):
            return body, "short body or no M1/M2 seen before it: forwarded unchanged"
        if header_id == M2:
            signed = b"R" + hashlib.sha384(HS_LABEL + m1 + body[:lo]).digest()
        else:
            signed = b"I" + hashlib.sha384(HS_LABEL + m1 + m2).digest()
        signature = self.forge(signed)
        if len(signature) != hi - lo:
            return body, f"the signer returned {len(signature)} bytes: forwarded unchanged"
        return body[:lo] + signature + body[hi:], f"signature over {signed[:1].decode()} || hash by a throwaway key"

    def process(self, direction, header_id, body):
        """The body to forward for one PDU, or None to drop it."""
        with self.lock:     # called from both relay directions
            self.seen[header_id] = n = self.seen.get(header_id, 0) + 1
            if self.record and n == 1:
                with open(f"{self.record}{header_id:02x}.bin", "wb") as f:
                    f.write(body)
            for edit in self.edits:
                if body is None or edit["id"] != header_id or not selected(edit["when"], n):
                    continue
                if edit["action"] == "drop":
                    detail, body = f"{len(body)} bytes not forwarded", None
                elif edit["action"] == "flip":
                    if edit["span"][1] > len(body):
                        detail = f"span {edit['span']} outside the {len(body)}-byte body: forwarded unchanged"
                    else:
                        body, detail = flip_bit(body, edit["span"], self.rng)
                elif edit["action"] == "replace":
                    off, data = edit["off"], edit["data"]
                    if off + len(data) > len(body):
                        detail = f"{len(data)} bytes at {off} do not fit the {len(body)}-byte body: forwarded unchanged"
                    else:
                        body, detail = body[:off] + data + body[off + len(data):], f"bytes {off}..{off + len(data) - 1} from {edit['file']}"
                else:
                    body, detail = self.resign(header_id, body)
                self.rows.append((len(self.rows), direction, f"0x{header_id:02x}", n, edit["action"], detail))
            if body is not None and header_id in (M1, M2):
                self.last[header_id] = body
            return body


def parse_layouts(items):
    layouts = {}
    for item in items:
        header_id, hdr, payload, fresh = (int(x) for x in item.split(":"))
        layouts[header_id] = (hdr, payload, fresh)
    return layouts


def write_log(path, relay, args):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# tool=attack_proxy\n# vectors={','.join(relay.vectors)}\n# every={relay.every}\n"
                f"# count={relay.count}\n# seed={args.seed}\n# layouts={' '.join(args.layout)}\n"
                f"# pdus_in={relay.seen}\n# injected={relay.injected}\n# not_built={relay.not_built}\n"
                f"# passed_without_row={relay.passed}\n# pass_ids={args.pass_ids}\n# bytes_back={relay.bytes_back}\n")
        f.write("index,vector,iter,src_seq,detail\n")
        for row in relay.rows:
            f.write(",".join(str(x) for x in row) + "\n")


def serve(args):
    session = b""
    if args.session_file:
        with open(args.session_file, "rb") as f:
            session = f.read()
    relay = Relay(args.vector.split(","), args.every, args.count, args.seed, parse_layouts(args.layout),
                  [int(x, 0) for x in args.pass_ids.split(",") if x], session)
    if "session_replay" in relay.vectors and not relay.old_session:
        raise SystemExit("session_replay needs --session-file with PDUs of an earlier session (see --record)")

    def forge(signed):
        out = subprocess.run([args.forge, "sign", signed.hex()], capture_output=True, text=True, timeout=10, check=True)
        return bytes.fromhex(out.stdout.strip())

    hs = HsEdits(args.hs, args.seed, forge if args.forge else None, args.hs_record)
    injections = []
    for item in args.hs_inject:
        header_id, path, direction, start, period, count = item.split(":")
        if direction not in ("to_receiver", "to_transmitter"):
            raise SystemExit(f"--hs-inject {item}: the direction is to_receiver or to_transmitter")
        with open(path, "rb") as f:
            injections.append((int(header_id, 0), path, f.read(), direction, float(start), float(period), int(count)))
    host, port = args.connect.rsplit(":", 1)
    with socket.create_server((args.bind, args.listen)) as listener:
        print(f"proxy listening on port {args.listen}", flush=True)
        upstream, peer = listener.accept()
    print(f"transmitter connected from {peer[0]}:{peer[1]}", flush=True)     # which node the PDUs come from
    record = open(args.record, "wb") if args.record else None
    with upstream, socket.create_connection((host, int(port))) as downstream:
        downstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        targets = {"to_receiver": (downstream, threading.Lock()), "to_transmitter": (upstream, threading.Lock())}
        established = threading.Event()     # the first M4 has gone to the transmitter

        def send(direction, data):          # one PDU at a time per socket: an injection comes from another thread
            sock, lock = targets[direction]
            with lock:
                sock.sendall(data)

        def inject(header_id, path, data, direction, start, period, count):
            established.wait()
            time.sleep(start)
            for k in range(count):
                try:
                    send(direction, HEADER.pack(header_id, len(data)) + data)
                except OSError:
                    return                  # the run is over
                hs.rows.append((len(hs.rows), direction, f"0x{header_id:02x}", k + 1, "inject", f"{len(data)} bytes of {path}"))
                time.sleep(period)

        def back():     # what the receiver sends (the handshake's M2 and M4): to the transmitter
            pending = b""
            try:
                while True:
                    chunk = downstream.recv(65536)
                    if not chunk:
                        break
                    relay.bytes_back += len(chunk)
                    pdus, pending = split_pdus(pending + chunk)
                    for header_id, body in pdus:
                        body = hs.process("to_transmitter", header_id, body)
                        if body is not None:
                            send("to_transmitter", HEADER.pack(header_id, len(body)) + body)
                            if header_id == M4:
                                established.set()
            except OSError:
                pass

        returning = threading.Thread(target=back, daemon=True)
        returning.start()
        for injection in injections:
            threading.Thread(target=inject, args=injection, daemon=True).start()
        buffer = b""
        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                break
            pdus, buffer = split_pdus(buffer + chunk)
            for header_id, body in pdus:
                if header_id in relay.passes:
                    body = hs.process("to_receiver", header_id, body)
                elif record:
                    record.write(HEADER.pack(header_id, len(body)) + body)      # as the transmitter sent it
                if body is not None:
                    send("to_receiver", relay.process(header_id, body))
        downstream.shutdown(socket.SHUT_WR)     # the transmitter is done; the receiver may still answer
        returning.join(timeout=5)
    if record:
        record.close()
    if args.hs_log:
        with open(args.hs_log, "w", encoding="utf-8") as f:
            f.write(f"# tool=attack_proxy\n# hs={' '.join(args.hs)}\n# hs_inject={' '.join(args.hs_inject)}\n# seed={args.seed}\n")
            f.write("index,direction,header_id,occurrence,action,detail\n")
            for i, row in enumerate(hs.rows):       # index in the order written (edits and injections interleave)
                f.write(",".join(str(x) for x in (i,) + tuple(row[1:])) + "\n")
    write_log(args.log, relay, args)
    print(f"pdus_in={relay.seen} injected={relay.injected} not_built={relay.not_built} forwarded={len(relay.rows)} leftover_bytes={len(buffer)}")
    return 0 if not buffer else 1


def selftest():
    rng = random.Random(1)
    layout = (1, 8, 1)

    def pdu(seq, fresh):
        return bytes([8]) + bytes(4) + seq.to_bytes(4, "big") + bytes([fresh]) + bytes(range(256)) * 13

    def diff_bits(a, b):
        return [i for i in range(len(a) * 8) if (a[i // 8] ^ b[i // 8]) >> (i % 8) & 1]

    a, b = pdu(7, 3), pdu(8, 4)
    checks = []
    wire = b"".join(HEADER.pack(2, len(x)) + x for x in (a, b))
    for cut in (1, 7, 8, 9, 1448, len(wire)):       # any segmentation gives the same PDUs
        got, rest = [], b""
        for i in range(0, len(wire), cut):
            pdus, rest = split_pdus(rest + wire[i:i + cut])
            got += pdus
        checks.append(got == [(2, a), (2, b)] and rest == b"")
    out = attack("replay", a, layout, rng, None)
    checks.append([x[0] for x in out] == ["benign", "replay"] and out[0][1] == out[1][1] == a)
    out = attack("bitflip", a, layout, rng, None)
    bits = diff_bits(a, out[0][1])
    checks.append(len(bits) == 1 and 8 <= bits[0] < 72)                 # one bit, inside the payload
    out = attack("auth_tamper", a, layout, rng, None)
    bits = diff_bits(a, out[0][1])
    checks.append(len(bits) == 1 and bits[0] >= 80)                     # one bit, inside the authenticator
    out = attack("freshness_rollback", b, layout, rng, a[9:10])
    checks.append(out[0][0] == "freshness_rollback" and out[0][1][9] == 3 and out[0][1][:9] == b[:9] and out[0][1][10:] == b[10:])
    checks.append(attack("freshness_rollback", a, layout, rng, None)[0][0] == "benign")     # nothing earlier yet
    checks.append([parse_selector(x) for x in ("", "3", "2+", "2/2")] == [(1, 0), (3, 0), (2, 1), (2, 2)])
    checks.append([[n for n in range(1, 8) if selected(parse_selector(x), n)] for x in ("3", "2+", "2/2")]
                  == [[3], [2, 3, 4, 5, 6, 7], [2, 4, 6]])
    # an old-session PDU: the recorded one with the smallest freshness above the current one, after the benign PDU
    old = [(bytes([f]), pdu(100 + f, f)) for f in (2, 5, 9)]
    out = attack("session_replay", pdu(7, 3), layout, rng, None, old)
    checks.append([x[0] for x in out] == ["benign", "session_replay"] and out[0][1] == pdu(7, 3) and out[1][1] == pdu(105, 5))
    checks.append([x[0] for x in attack("session_replay", pdu(7, 9), layout, rng, None, old)] == ["benign"])    # nothing later recorded
    recorded = b"".join(HEADER.pack(2, len(body)) + body for _, body in reversed(old)) + HEADER.pack(0x30, 2) + b"M1"
    replaying = Relay(["session_replay"], 1, None, 1, {2: layout}, [0x30], recorded)
    replaying.process(2, pdu(0, 9))
    wire = replaying.process(2, pdu(1, 4))
    checks.append([f for f, _ in replaying.old_session[2]] == [b"\x02", b"\x05", b"\x09"] and replaying.not_built == 1
                  and split_pdus(wire)[0] == [(2, pdu(1, 4)), (2, pdu(105, 5))] and [r[1] for r in replaying.rows] == ["benign", "benign", "session_replay"])
    # replace, and a signature by another key over the data the verifier hashes
    signed_data = []
    with tempfile.NamedTemporaryFile() as other_ek:
        other_ek.write(bytes([0x77]) * 1184)
        other_ek.flush()
        edits = HsEdits([f"0x30:replace:33:{other_ek.name}@2+", "0x31:resign@2", "0x32:resign"], 3,
                        lambda signed: signed_data.append(signed) or bytes([0xAA]) * 3309)
    m1, m2, m3 = bytes([1]) * 1217, bytes([2]) * 4462, bytes([3]) * 3342
    first = [edits.process("to_receiver", M1, m1), edits.process("to_transmitter", M2, m2)]
    changed = edits.process("to_receiver", M3, m3)
    checks.append(first == [m1, m2] and changed == m3[:1] + bytes([0xAA]) * 3309 + m3[3310:]
                  and signed_data == [b"I" + hashlib.sha384(HS_LABEL + m1 + m2).digest()])
    m1_new = edits.process("to_receiver", M1, m1)       # second M1: the file's bytes in place of ek
    checks.append(m1_new == m1[:33] + bytes([0x77]) * 1184 and len(m1_new) == len(m1))
    m2_new = edits.process("to_transmitter", M2, m2)
    checks.append(m2_new == m2[:1121] + bytes([0xAA]) * 3309 + m2[4430:]
                  and signed_data[1] == b"R" + hashlib.sha384(HS_LABEL + m1_new + m2[:1121]).digest())
    checks.append([r[4] for r in edits.rows] == ["resign", "replace", "resign"] and [r[3] for r in edits.rows] == [1, 2, 2])
    hs = HsEdits(["0x32:drop@2", "0x31:flip:33:1088"], 3)                    # second M3 dropped, a bit of ct flipped in the first M2
    m2 = bytes(4462)
    flipped = hs.process("to_transmitter", 0x31, m2)
    checks.append(hs.process("to_receiver", 0x32, b"first") == b"first" and hs.process("to_receiver", 0x32, b"second") is None)
    checks.append(len(diff_bits(m2, flipped)) == 1 and 33 * 8 <= diff_bits(m2, flipped)[0] < (33 + 1088) * 8)
    checks.append(hs.process("to_transmitter", 0x31, m2) == m2 and [r[4] for r in hs.rows] == ["flip", "drop"])   # each edit once
    quiet = Relay(["replay"], 1, None, 1, {2: layout}, [0x30])              # a handshake message: same bytes, no row
    checks.append(quiet.process(0x30, b"M1") == HEADER.pack(0x30, 2) + b"M1" and quiet.rows == [] and quiet.passed == 1)
    relay = Relay(list(VECTORS), 2, None, 5, {2: layout})
    for seq in range(8):
        relay.process(2, pdu(seq, seq))
    relay.process(9, b"handshake bytes")                                 # unknown header ID: untouched
    labels = [r[1] for r in relay.rows]
    checks.append(labels == ["benign", "benign", "replay", "benign", "bitflip", "benign", "auth_tamper", "benign",
                             "freshness_rollback", "other"])
    checks.append([r[3] for r in relay.rows] == [0, 1, 1, 2, 3, 4, 5, 6, 7, -1] and [r[0] for r in relay.rows] == list(range(10)))
    print(f"selftest: {len(checks)} checks, {checks.count(False)} failed")
    return 0 if all(checks) else 1


def main():
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--bind", default="", help="address to listen on (default: every address of the host)")
    ap.add_argument("--connect", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--vector", required=True, help="comma-separated, from: " + ", ".join(VECTORS))
    ap.add_argument("--every", type=int, required=True)
    ap.add_argument("--count", type=int)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--layout", nargs="+", default=["16:1:8:4"])
    ap.add_argument("--hs", nargs="*", default=[], help="edits of handshake messages, see above")
    ap.add_argument("--hs-log", help="CSV of the handshake edits and injections that were made")
    ap.add_argument("--hs-inject", nargs="*", default=[], help="unsolicited handshake messages, see above")
    ap.add_argument("--hs-record", help="prefix of the files that take the first M1..M4 of this run")
    ap.add_argument("--forge", help="program that prints a signature: <program> sign <hex of the signed data>")
    ap.add_argument("--record", help="file that takes every Secured I-PDU as the transmitter sent it")
    ap.add_argument("--session-file", help="a --record file of an earlier session, for session_replay")
    ap.add_argument("--pass-ids", default="0x30,0x31,0x32,0x33",
                    help="header IDs forwarded without a log row: the handshake messages, which are no Secured I-PDUs")
    args = ap.parse_args()
    unknown = [v for v in args.vector.split(",") if v not in VECTORS]
    if unknown or args.every < 0:
        ap.error(f"unknown vector(s) {unknown}" if unknown else "--every must be 0 (no PDU is attacked) or more")
    return serve(args)


if __name__ == "__main__":
    sys.exit(main())
