#!/usr/bin/env python3
"""Side probes of the on-wire handshake tests 9 and 10 (SPEC.md "Negative tests"), standard library only.

    hs_side_probes.py udp HOST [--port 60500] [--payload FILE] [--count N] [--interval S]
        Send a control datagram in the format of the retired UDP key-exchange channel
        (0x51 0x43, version 1, type 1 = public key, peer 0, 16-bit little-endian length, payload)
        and wait for any answer; N times, S seconds apart.
    hs_side_probes.py tcp HOST PORT --bind ADDR --send FILE [--header-id 0x30] [--count N] [--interval S]
        Open a TCP connection from ADDR (an address that is not the configured peer), send FILE as
        one PDU and report what the other side did with the connection; N times, S seconds apart.
    hs_side_probes.py listeners [--port 60500]
        Is a UDP socket bound to the port on this host (reads `ss -lunH`)?
    hs_side_probes.py --selftest

Each prints one line of key=value pairs: for udp `count=` and `answers=` (datagrams that got any
reply), for tcp `count=`, `no_answer=` (refused, or closed by the other side without a byte),
`answered=` (bytes came back) and `still_open=` (not closed within 3 s). Exit status 0 means the
probe ran, whatever it found; `listeners` exits 1 when a listener exists.
"""
import argparse
import socket
import struct
import subprocess
import sys
import threading
import time

OLD_PORT = 60500        # SOAD_PQC_LOCAL_CONTROL_PORT of the as-found tree


def old_control_datagram(payload):
    return bytes([0x51, 0x43, 0x01, 0x01, 0x00]) + struct.pack("<H", len(payload)) + payload


def udp(host, port, payload, count=1, interval=0.0, wait=0.5):
    answers = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(wait)
        for k in range(count):
            s.sendto(old_control_datagram(payload), (host, port))
            try:
                s.recvfrom(4096)
                answers += 1
            except OSError:         # nothing came (time-out), or ICMP port unreachable: nothing is bound there
                pass
            if k + 1 < count:
                time.sleep(interval)
    return f"probe=udp to={host}:{port} sent_bytes={7 + len(payload)} count={count} answers={answers}"


def tcp(host, port, bind, data, header_id, count=1, interval=0.0):
    """One summary line over `count` connections, with the details of the last one."""
    tally = {"no_answer": 0, "answered": 0, "still_open": 0}
    line = ""
    for k in range(count):
        line = tcp_once(host, port, bind, data, header_id)
        if "received_bytes=0" not in line:
            tally["answered"] += 1
        elif "connect=ok" in line and "closed_by_peer_ms=-1" in line:
            tally["still_open"] += 1
        else:
            tally["no_answer"] += 1
        if k + 1 < count:
            time.sleep(interval)
    return f"{line} count={count} " + " ".join(f"{name}={n}" for name, n in tally.items())


def tcp_once(host, port, bind, data, header_id):
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=3, source_address=(bind, 0))
    except OSError as e:
        return f"probe=tcp from={bind} to={host}:{port} connect={type(e).__name__} sent_bytes=0 received_bytes=0 closed_by_peer_ms=-1"
    received, closed_ms, sent = 0, -1, 0
    with s:
        s.settimeout(3)
        try:
            s.sendall(struct.pack(">II", header_id, len(data)) + data)
            sent = 8 + len(data)
        except OSError:
            pass                    # reset before or while sending
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    closed_ms = round((time.monotonic() - t0) * 1000)
                    break
                received += len(chunk)
        except socket.timeout:
            pass                    # still open after 3 s: closed_by_peer_ms stays -1
        except OSError:
            closed_ms = round((time.monotonic() - t0) * 1000)
    return (f"probe=tcp from={bind} to={host}:{port} connect=ok sent_bytes={sent} received_bytes={received} "
            f"closed_by_peer_ms={closed_ms}")


def listeners(port, ss_output=None):
    if ss_output is None:
        ss_output = subprocess.run(["ss", "-lunH"], capture_output=True, text=True, check=True).stdout
    bound = [line for line in ss_output.splitlines() if any(f.endswith(f":{port}") for f in line.split()[3:5])]
    return f"probe=listeners port={port} udp_listeners={len(bound)}", len(bound)


def selftest():
    checks = [old_control_datagram(b"ab") == bytes([0x51, 0x43, 1, 1, 0, 2, 0]) + b"ab"]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:      # a bound port: the datagram arrives, no answer
        sink.bind(("127.0.0.1", 0))
        line = udp("127.0.0.1", sink.getsockname()[1], b"x" * 1184, count=3, wait=0.05)
        checks.append("sent_bytes=1191 count=3 answers=0" in line and sink.recvfrom(4096)[0][:7] == bytes([0x51, 0x43, 1, 1, 0, 0xA0, 0x04]))
    with socket.create_server(("127.0.0.1", 0)) as server:              # a server that closes at once, as a refusing SoAd does
        def refuse_all():
            try:
                while True:
                    server.accept()[0].close()
            except OSError:
                pass                # the listener was closed: the test is over
        threading.Thread(target=refuse_all, daemon=True).start()
        line = tcp("127.0.0.1", server.getsockname()[1], "127.0.0.1", b"M1", 0x30, count=3)
        checks.append("connect=ok" in line and "count=3 no_answer=3 answered=0 still_open=0" in line)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as never_listened:   # a port nobody listens on: bound, then closed
        never_listened.bind(("127.0.0.1", 0))
        free_port = never_listened.getsockname()[1]
    line = tcp("127.0.0.1", free_port, "127.0.0.1", b"M1", 0x30)
    checks.append("connect=ConnectionRefusedError" in line and "count=1 no_answer=1 answered=0 still_open=0" in line)
    with socket.create_server(("127.0.0.1", 0)) as server:              # a server that answers: must be counted as answered
        def answer_one():
            conn = server.accept()[0]
            conn.recv(64)
            conn.sendall(b"M2")
            conn.close()
        threading.Thread(target=answer_one, daemon=True).start()
        checks.append("no_answer=0 answered=1" in tcp("127.0.0.1", server.getsockname()[1], "127.0.0.1", b"M1", 0x30))
    ss = "UNCONN 0 0 0.0.0.0:60500 0.0.0.0:*\nUNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\nUNCONN 0 0 [::]:60500 [::]:*\n"
    checks.append(listeners(60500, ss) == ("probe=listeners port=60500 udp_listeners=2", 2) and listeners(60501, ss)[1] == 0)
    print(f"selftest: {len(checks)} checks, {checks.count(False)} failed")
    return 0 if all(checks) else 1


def main():
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="probe", required=True)
    p = sub.add_parser("udp")
    p.add_argument("host")
    p.add_argument("--port", type=int, default=OLD_PORT)
    p.add_argument("--payload", help="file with the payload (default: 1184 zero bytes, the size of an ML-KEM-768 key)")
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--interval", type=float, default=0.05)
    p.add_argument("--wait", type=float, default=0.5, help="seconds to wait for an answer to each datagram")
    p = sub.add_parser("tcp")
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("--bind", required=True)
    p.add_argument("--send", required=True)
    p.add_argument("--header-id", type=lambda x: int(x, 0), default=0x30)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--interval", type=float, default=0.05)
    p = sub.add_parser("listeners")
    p.add_argument("--port", type=int, default=OLD_PORT)
    args = ap.parse_args()
    if args.probe == "udp":
        payload = bytes(1184)
        if args.payload:
            with open(args.payload, "rb") as f:
                payload = f.read()
        print(udp(args.host, args.port, payload, args.count, args.interval, args.wait))
        return 0
    if args.probe == "tcp":
        with open(args.send, "rb") as f:
            print(tcp(args.host, args.port, args.bind, f.read(), args.header_id, args.count, args.interval))
        return 0
    line, count = listeners(args.port)
    print(line)
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
