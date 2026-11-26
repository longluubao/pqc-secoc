#!/usr/bin/env python3
"""Unrelated traffic beside a measured stream (E9, cell i): one unprotected TCP flow at a fixed mean rate.

  bg_traffic.py --sink   --bind A.B.C.D --port P [--peer A.B.C.D] [--cpu N] [--max-seconds S] --out FILE
  bg_traffic.py --source --connect A.B.C.D:P --mbit R [--cpu N] [--max-seconds S] [--seed N] --out FILE
  bg_traffic.py --report SOURCE_FILE SINK_FILE [PERIODIC_TX_CSV]
  bg_traffic.py --selftest

Source: zero bytes on one TCP connection with the kernel's default socket options. The harness
releases every 10 ms, the clock probe sends every 100 ms and a source with a tick of its own would
meet them at the same phase for a whole run. So the writes come at gaps drawn uniformly from 0.5 to
1.5 ms by a seeded generator, and each write brings the bytes sent up to rate x elapsed time (at most
256 KiB at once): the mean rate is the offered one, and what a full send buffer held back is made up.
Sink: accepts one connection (from --peer only) and reads it to its end.
Both end on SIGTERM or SIGINT, when the connection ends, or after --max-seconds (default 1800: a
flow that its driver forgot must not load the link for ever), and then write FILE: key=value lines,
times in ns of CLOCK_MONOTONIC of that board. The source also records how far it fell behind:
max_deficit_bytes, the most bytes it was behind its nominal count when it came to write (one gap's
worth, about 9 kB at 50 Mbit/s, when nothing holds it up), and send_timeouts, the writes that a full
send buffer held up for 0.5 s (recorded, not judged).
--report prints the two files as one (background_traffic.txt of DATA_SCHEMA.md) and a last line
verdict=PASS or verdict=FAIL: <reasons>: the achieved rate is below 95 % of the offered one, nothing
arrived, or (with the transmitter's periodic file, whose times are on the source's clock) the flow
began after the first release or ended before the last PDU was sent. Exit status 0 only for PASS.
Standard library only: it runs on the Pis.
"""
import argparse
import os
import random
import signal
import socket
import subprocess
import sys
import tempfile
import time

CHUNK = 256 * 1024
PATTERN = "writes at gaps uniform in 0.5 to 1.5 ms (seeded), each up to rate x elapsed time, at most 256 KiB"
stop = False


def on_signal(*_):
    global stop
    stop = True


def start(cpu):
    if cpu >= 0 and hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {cpu})
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)


def write_out(path, pairs):
    with open(path, "w", encoding="ascii") as f:
        f.write("".join(f"{k}={v}\n" for k, v in pairs))


def source(a):
    host, port = a.connect.rsplit(":", 1)
    start(a.cpu)
    rate = int(a.mbit * 1_000_000) // 8     # bytes per second
    rng = random.Random(a.seed)
    buf = memoryview(bytes(CHUNK))
    s = socket.create_connection((host, int(port)), timeout=5)
    s.settimeout(0.5)       # a full send buffer must not hide the signal that ends the run
    print("connected", flush=True)
    sent = writes = deficit = timeouts = 0
    ended = "signal"
    t0 = due_at = last = time.monotonic_ns()
    while not stop:
        now = time.monotonic_ns()
        if now - t0 >= a.max_seconds * 10 ** 9:
            ended = "limit"
            break
        if now < due_at:
            time.sleep((due_at - now) / 1e9)
            continue
        due_at = max(due_at, now - 5_000_000) + rng.randrange(500_000, 1_500_001)
        todo = rate * (now - t0) // 10 ** 9 - sent
        deficit = max(deficit, todo)        # how far behind the nominal byte count it is when it comes to write
        if todo > 0:
            try:
                n = s.send(buf[:min(todo, CHUNK)])
                sent += n
                writes += 1
                last = time.monotonic_ns()
            except socket.timeout:
                n = 0
                timeouts += 1
            except OSError:
                ended = "connection"
                break
    s.close()
    write_out(a.out, (("role", "source"), ("host", socket.gethostname()), ("cpu", a.cpu), ("rate_offered_bit_s", rate * 8),
                      ("pattern", PATTERN), ("seed", a.seed), ("bytes", sent), ("writes", writes), ("first_byte_ns", t0),
                      ("last_byte_ns", last), ("max_deficit_bytes", deficit), ("send_timeouts", timeouts), ("ended_by", ended)))
    print(f"bytes_sent={sent} seconds={(last - t0) / 1e9:.1f} ended_by={ended}", flush=True)
    return 0


def sink(a):
    start(a.cpu)
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((a.bind, a.port))
    ls.listen(1)
    ls.settimeout(0.5)
    print("listening", flush=True)
    t0 = time.monotonic_ns()
    expired = lambda: time.monotonic_ns() - t0 >= a.max_seconds * 10 ** 9
    conn, received, first, last, ended = None, 0, 0, 0, "signal"
    while conn is None and not stop and not expired():
        try:
            c, addr = ls.accept()
        except socket.timeout:
            continue
        if a.peer and addr[0] != a.peer:
            c.close()       # not the board this flow comes from
            continue
        conn = c
    buf = bytearray(CHUNK)
    while conn is not None and not stop:
        if expired():
            ended = "limit"
            break
        try:
            conn.settimeout(0.5)
            n = conn.recv_into(buf)
        except socket.timeout:
            continue
        except OSError:
            n = 0
        if n == 0:
            ended = "connection"
            break
        last = time.monotonic_ns()
        first = first or last
        received += n
    write_out(a.out, (("role", "sink"), ("host", socket.gethostname()), ("cpu", a.cpu), ("bytes", received),
                      ("first_byte_ns", first), ("last_byte_ns", last), ("ended_by", ended)))
    print(f"bytes_received={received} ended_by={ended}", flush=True)
    return 0


def read(path, role):
    with open(path, encoding="ascii") as f:
        d = dict(line.rstrip("\n").split("=", 1) for line in f if "=" in line)
    if d.get("role") != role:
        raise ValueError(f"{path} is not the file of a {role}")
    return d


def report(src_path, sink_path, tx_csv=None, out=print):
    try:
        src, snk = read(src_path, "source"), read(sink_path, "sink")
        sent, received, offered = int(src["bytes"]), int(snk["bytes"]), int(src["rate_offered_bit_s"])
        first, last = int(src["first_byte_ns"]), int(src["last_byte_ns"])
    except (OSError, ValueError, KeyError) as e:
        out(f"verdict=FAIL: {e}")
        return 1
    achieved = sent * 8 * 10 ** 9 // (last - first) if last > first else 0
    for k, v in (("rate_offered_bit_s", offered), ("rate_achieved_bit_s", achieved), ("pattern", src["pattern"]),
                 ("seed", src["seed"]), ("bytes_sent", sent), ("bytes_received", received), ("writes", src["writes"]),
                 ("max_deficit_bytes", src.get("max_deficit_bytes", "")), ("send_timeouts", src.get("send_timeouts", "")),
                 ("source_duration_ns", last - first),
                 ("sink_duration_ns", int(snk["last_byte_ns"]) - int(snk["first_byte_ns"])),
                 ("source_host", src["host"]), ("sink_host", snk["host"]), ("source_cpu", src["cpu"]),
                 ("sink_cpu", snk["cpu"]), ("source_first_byte_ns", first), ("source_last_byte_ns", last),
                 ("sink_first_byte_ns", snk["first_byte_ns"]), ("sink_last_byte_ns", snk["last_byte_ns"]),
                 ("source_ended_by", src["ended_by"]), ("sink_ended_by", snk["ended_by"])):
        out(f"{k}={v}")
    reasons = []
    if achieved * 100 < offered * 95:
        reasons.append(f"achieved rate {achieved} bit/s is below 95 % of the offered {offered} bit/s")
    if received == 0 or received > sent:
        reasons.append(f"{received} bytes received of {sent} sent")
    if tx_csv:      # release_ns and send_done_ns are on the source board's clock, as first and last
        try:
            with open(tx_csv, encoding="ascii") as f:
                rows = [line.split(",") for line in f if line[:1].isdigit()]
            releases = [int(r[2]) for r in rows]
            done = [int(r[5]) for r in rows]
            if not rows or first > min(releases):
                reasons.append("the flow began after the first release")
            if not rows or last < max(done):
                reasons.append("the flow ended before the last PDU was sent")
        except (OSError, ValueError, IndexError) as e:
            reasons.append(f"{tx_csv}: {e}")
    out("verdict=" + ("FAIL: " + "; ".join(reasons) if reasons else "PASS"))
    return 1 if reasons else 0


def selftest():
    """Source and sink as two processes on 127.0.0.1 at 8 Mbit/s for 2 s, then the report on their files."""
    me = [sys.executable, os.path.abspath(__file__)]
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with tempfile.TemporaryDirectory() as d:
        p = lambda n: os.path.join(d, n)
        snk = subprocess.Popen(me + ["--sink", "--bind", "127.0.0.1", "--port", str(port), "--peer", "127.0.0.1",
                                     "--out", p("sink.txt")], stdout=subprocess.PIPE, text=True)
        assert snk.stdout.readline().strip() == "listening"
        src = subprocess.Popen(me + ["--source", "--connect", f"127.0.0.1:{port}", "--mbit", "8", "--out", p("source.txt")],
                               stdout=subprocess.PIPE, text=True)
        assert src.stdout.readline().strip() == "connected"
        time.sleep(2)
        src.send_signal(signal.SIGTERM)
        assert src.wait(10) == 0 and snk.wait(10) == 0      # the sink ends by itself when the connection does
        a, b = read(p("source.txt"), "source"), read(p("sink.txt"), "sink")
        assert a["ended_by"] == "signal" and b["ended_by"] == "connection", (a, b)
        assert a["bytes"] == b["bytes"] and int(a["bytes"]) > 1_500_000, (a["bytes"], b["bytes"])
        gap_us = (int(a["last_byte_ns"]) - int(a["first_byte_ns"])) / 1000 / int(a["writes"])
        assert 700 < gap_us < 1500, gap_us      # about one write per millisecond, no fixed tick
        first, last = int(a["first_byte_ns"]), int(a["last_byte_ns"])

        def tx(name, release, done):
            with open(p(name), "w", encoding="ascii") as f:
                f.write(f"# x=1\nstream,seq,release_ns,start_ns,auth_done_ns,send_done_ns\n0,0,{release},0,0,{release + 5}\n0,1,{done - 9},0,0,{done}\n")
            return p(name)
        lines = []
        assert report(p("source.txt"), p("sink.txt"), tx("in.csv", first + 10, last - 10), lines.append) == 0, lines
        assert lines[-1] == "verdict=PASS" and f"bytes_sent={a['bytes']}" in lines and "rate_offered_bit_s=8000000" in lines
        deficit = next(int(line[18:]) for line in lines if line.startswith("max_deficit_bytes="))
        assert "send_timeouts=0" in lines and 500 < deficit < 200_000, lines     # at least half a millisecond's worth of 8 Mbit/s
        for name, release, done, why in (("early.csv", first - 10, last - 10, "began after the first release"),
                                         ("late.csv", first + 10, last + 10, "ended before the last PDU")):
            lines = []
            assert report(p("source.txt"), p("sink.txt"), tx(name, release, done), lines.append) == 1 and why in lines[-1], lines
        # half the offered rate, nothing received, a file that is missing
        write_out(p("slow.txt"), [(k, int(v) * 2 if k == "rate_offered_bit_s" else v) for k, v in a.items()])
        write_out(p("none.txt"), [(k, 0 if k == "bytes" else v) for k, v in b.items()])
        for s_file, k_file, why in (("slow.txt", "sink.txt", "below 95 %"), ("source.txt", "none.txt", "0 bytes received"),
                                    ("source.txt", "missing.txt", "No such file"), ("sink.txt", "sink.txt", "not the file of a source")):
            lines = []
            assert report(p(s_file), p(k_file), None, lines.append) == 1 and why in lines[-1], lines
        # a sink that nobody connects to ends at its limit and says so
        subprocess.run(me + ["--sink", "--bind", "127.0.0.1", "--port", str(port), "--max-seconds", "1", "--out", p("idle.txt")],
                       check=True, stdout=subprocess.DEVNULL, timeout=10)
        assert read(p("idle.txt"), "sink")["bytes"] == "0"
    print("bg_traffic selftest: ok")
    return 0


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    if argv[:1] == ["--report"] and len(argv) in (3, 4):
        return report(*argv[1:])
    ap = argparse.ArgumentParser(usage="bg_traffic.py --sink ... | --source ... | --report ... | --selftest (options: the head of this file)")
    role = ap.add_mutually_exclusive_group(required=True)
    role.add_argument("--sink", action="store_true")
    role.add_argument("--source", action="store_true")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int)
    ap.add_argument("--peer")
    ap.add_argument("--connect")
    ap.add_argument("--mbit", type=float)
    ap.add_argument("--cpu", type=int, default=-1)
    ap.add_argument("--max-seconds", type=int, default=1800)
    ap.add_argument("--seed", type=int, default=20261124)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if (a.sink and not a.port) or (a.source and not (a.connect and a.mbit and a.mbit > 0)):
        ap.error("--sink needs --port; --source needs --connect and --mbit")
    return sink(a) if a.sink else source(a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
