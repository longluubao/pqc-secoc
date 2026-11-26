"""Local socket test of attack_proxy.py's serving loop: fake receiver and transmitter on 127.0.0.1."""
import os, socket, struct, subprocess, sys, threading, time
PROXY, D = sys.argv[1], sys.argv[2]
H = struct.Struct(">II")
def frame(i, b): return H.pack(i, len(b)) + b
def read_frames(sock, n, timeout=6):
    sock.settimeout(timeout); buf, out = b"", []
    while len(out) < n:
        chunk = sock.recv(65536)
        if not chunk: break
        buf += chunk
        while len(buf) >= 8:
            i, l = H.unpack_from(buf)
            if len(buf) < 8 + l: break
            out.append((i, buf[8:8 + l])); buf = buf[8 + l:]
    return out
open(f"{D}/old_m3.bin", "wb").write(b"\x09" * 3342)
open(f"{D}/forge.sh", "w").write("#!/bin/sh\npython3 -c \"print('ab' * 3309)\"\n"); os.chmod(f"{D}/forge.sh", 0o755)
srv = socket.create_server(("127.0.0.1", 0)); rx_port = srv.getsockname()[1]
tmp = socket.socket(); tmp.bind(("127.0.0.1", 0)); px_port = tmp.getsockname()[1]; tmp.close()
def pdu(seq, fresh): return bytes([8]) + bytes(4) + seq.to_bytes(4, "big") + fresh.to_bytes(4, "big") + bytes(3309)
proxy = subprocess.Popen([sys.executable, "-I", PROXY, "--listen", str(px_port), "--connect", f"127.0.0.1:{rx_port}", "--log", f"{D}/proxy_log.csv",
                          "--vector", "replay", "--every", "0", "--hs", "0x31:resign@1", "0x32:flip:1:3309@2+", "--hs-log", f"{D}/hs.csv",
                          "--hs-inject", f"0x32:{D}/old_m3.bin:to_receiver:0.2:0.3:3", "--hs-record", f"{D}/rec_", "--forge", f"{D}/forge.sh",
                          "--record", f"{D}/session.bin"], stdout=subprocess.PIPE, text=True)
assert "listening" in proxy.stdout.readline()
tx = socket.create_connection(("127.0.0.1", px_port)); rx, _ = srv.accept()
m1, m2, m3, m4 = b"\x01" * 1217, b"\x02" * 4462, b"\x03" * 3342, b"\x04" * 33
tx.sendall(frame(0x30, m1)); assert read_frames(rx, 1) == [(0x30, m1)]
rx.sendall(frame(0x31, m2)); got = read_frames(tx, 1)
assert got[0][1][:1121] == m2[:1121] and got[0][1][1121:4430] == b"\xab" * 3309 and got[0][1][4430:] == m2[4430:], "resign of M2"
tx.sendall(frame(0x32, m3)); assert read_frames(rx, 1) == [(0x32, m3)], "first M3 untouched"
rx.sendall(frame(0x33, m4)); assert read_frames(tx, 1) == [(0x33, m4)]
# stream of PDUs while three old M3 are injected: every frame must arrive whole
def stream():
    for k in range(60):
        tx.sendall(frame(0x10, pdu(k, k + 1))); time.sleep(0.02)
t = threading.Thread(target=stream); t.start()
frames = read_frames(rx, 63); t.join()
ids = [i for i, _ in frames]
assert ids.count(0x10) == 60 and ids.count(0x32) == 3 and all(b == b"\x09" * 3342 for i, b in frames if i == 0x32), ids
assert [int.from_bytes(b[5:9], "big") for i, b in frames if i == 0x10] == list(range(60))
tx.sendall(frame(0x32, m3)); second = read_frames(rx, 1)[0][1]
assert second != m3 and len(second) == len(m3) and second[3310:] == m3[3310:], "second M3: one bit of sig_A flipped"
tx.shutdown(socket.SHUT_WR); rx.close(); print(proxy.stdout.read().strip()); assert proxy.wait(10) == 0
rows = [l.strip().split(",") for l in open(f"{D}/hs.csv") if not l.startswith("#")][1:]
assert sorted(r[4] for r in rows) == ["flip", "inject", "inject", "inject", "resign"] and [r[0] for r in rows] == [str(i) for i in range(5)], rows
assert [open(f"{D}/rec_{i}.bin", "rb").read() for i in ("30", "31", "32", "33")] == [m1, m2, m3, m4], "recorded as received"
assert open(f"{D}/session.bin", "rb").read() == b"".join(frame(0x10, pdu(k, k + 1)) for k in range(60))
# second run: the recorded session replayed into a new one
srv2 = socket.create_server(("127.0.0.1", 0)); tmp = socket.socket(); tmp.bind(("127.0.0.1", 0)); px2 = tmp.getsockname()[1]; tmp.close()
proxy = subprocess.Popen([sys.executable, "-I", PROXY, "--listen", str(px2), "--connect", f"127.0.0.1:{srv2.getsockname()[1]}", "--log", f"{D}/proxy_log2.csv",
                          "--vector", "session_replay", "--every", "2", "--layout", "16:1:8:4", "--session-file", f"{D}/session.bin"], stdout=subprocess.PIPE, text=True)
assert "listening" in proxy.stdout.readline()
tx = socket.create_connection(("127.0.0.1", px2)); rx, _ = srv2.accept()
for k in range(6):
    tx.sendall(frame(0x10, bytes([8]) + bytes(4) + (500 + k).to_bytes(4, "big") + (k + 1).to_bytes(4, "big") + b"\x55" * 3309))
frames = read_frames(rx, 9)
fresh = [(int.from_bytes(b[9:13], "big"), b[13] == 0x55) for _, b in frames]
assert fresh == [(1, True), (2, True), (3, False), (3, True), (4, True), (5, False), (5, True), (6, True), (7, False)], fresh
tx.shutdown(socket.SHUT_WR); rx.close(); print(proxy.stdout.read().strip()); assert proxy.wait(10) == 0
print("local proxy test: ok")
