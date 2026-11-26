#!/usr/bin/env python3
"""In-path relay for one TCP connection of SoAd PDUs, both directions, PDU by PDU.

Usage: relay_tamper.py <listen_port> <dst_host> <dst_port> <every> [<drop_header_id> [<nth>]]

  every > 0   in front of every <every>-th Secured I-PDU from the transmitter (PDU header IDs
              0x10..0x2F) a copy of that PDU with the last bit of its authenticator flipped is
              inserted. The receiver sees a tampered PDU with a new freshness value (auth_fail)
              and then the genuine one with the same value (still delivered). 0: nothing inserted.
  drop_header_id  the <nth> (default first) PDU with this header ID, from either side, is not
              forwarded; everything else is. 0x32 is the handshake message M3, 0x33 is M4.

Handshake messages (0x30..0x33) are otherwise passed unchanged in both directions and are neither
counted nor copied. Whole PDUs are inserted or left out, so the streams stay aligned.
For loopback runs: the receiver is built with another port (SECOC_PORT) and this relay listens on the
port the transmitter connects to. It ends when the transmitter closes the connection.
"""
import socket
import struct
import sys
import threading

stats = {"secured": 0, "tampered": 0, "dropped": 0, "seen": 0}
lock = threading.Lock()


def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def relay(src, dst, every, drop_id, drop_nth):
    """PDUs from src to dst until either side closes; every > 0 only for the transmitter's direction"""
    try:
        while True:
            header = read_exact(src, 8)
            if header is None:
                break
            payload = read_exact(src, struct.unpack(">I", header[4:])[0])
            if payload is None:
                break
            header_id = struct.unpack(">I", header[:4])[0]
            with lock:
                if drop_id is not None and header_id == drop_id:
                    stats["seen"] += 1
                    if stats["seen"] == drop_nth:
                        stats["dropped"] += 1
                        continue
                # Secured I-PDUs: signature streams 0x10.., MAC streams 0x20.. (SoAd_PduIds.h)
                if every > 0 and 0x10 <= header_id < 0x30:
                    stats["secured"] += 1
                    if stats["secured"] % every == 0:
                        dst.sendall(header + payload[:-1] + bytes([payload[-1] ^ 0x01]))
                        stats["tampered"] += 1
            dst.sendall(header + payload)
    except OSError:
        pass


def main():
    listen_port, dst_host, dst_port, every = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    drop_id = int(sys.argv[5], 0) if len(sys.argv) > 5 else None
    drop_nth = int(sys.argv[6]) if len(sys.argv) > 6 else 1
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", listen_port))
    server.listen(1)
    print("relay listening on %d" % listen_port, flush=True)
    src, _ = server.accept()
    dst = socket.create_connection((dst_host, dst_port), timeout=5)
    dst.settimeout(None)
    threading.Thread(target=relay, args=(dst, src, 0, drop_id, drop_nth), daemon=True).start()
    relay(src, dst, every, drop_id, drop_nth)
    dst.close()
    print("inserted %d tampered copies among %d Secured I-PDUs, dropped %d PDU(s) with header ID %s"
          % (stats["tampered"], stats["secured"], stats["dropped"], "none" if drop_id is None else hex(drop_id)), flush=True)


if __name__ == "__main__":
    main()
