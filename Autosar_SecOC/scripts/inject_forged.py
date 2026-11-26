#!/usr/bin/env python3
"""Send forged Secured I-PDUs to a PQC-SecOC receiver over one TCP connection, then close it.

Usage: inject_forged.py <host> <port> <count> [gap_seconds] [mldsa65|mac] [key_file]

Each PDU is well-formed up to the authenticator: SoAd PDU header (ID, length), SecOC header byte,
8 payload bytes, 32-bit freshness counter i (1..count), then
  mldsa65 (default): 3,309 random bytes where the ML-DSA-65 signature belongs (signature stream 0);
  mac: 16 bytes where the HMAC-SHA-256 tag belongs (MAC stream 0): random for odd i, and for even i
       the right tag of this PDU under a key the receiver does not have. With key_file every PDU
       carries the right tag under the first 32 bytes of that file (a static key that a gateway
       must not use: it reads no key file).
The receiver must reject every one of them (auth_fail), however many arrive in a row, and must still
deliver the genuine PDUs that follow.
"""
import hashlib
import hmac
import os
import socket
import struct
import sys
import time

# PDU header ID and SecOC Data ID of stream 0 of each variant (include/SoAd/SoAd_PduIds.h)
HEADER_ID = {"mldsa65": 0x10, "mac": 0x20}
DATA_ID = {"mldsa65": 2, "mac": 13}
PAYLOAD_LEN = 8
SIGNATURE_LEN = 3309
TAG_LEN = 16
OTHER_KEY = os.urandom(32)


def forged_pdu(counter, profile="mldsa65", key=None):
    payload = b"\xee" * PAYLOAD_LEN
    freshness = struct.pack(">I", counter)
    if profile == "mac" and (key is not None or counter % 2 == 0):
        # DataToAuthenticator = Data ID (16 bit, big endian) | Authentic I-PDU | complete freshness value
        data = struct.pack(">H", DATA_ID[profile]) + payload + freshness
        authenticator = hmac.new(key if key is not None else OTHER_KEY, data, hashlib.sha256).digest()[:TAG_LEN]
    else:
        authenticator = os.urandom(TAG_LEN if profile == "mac" else SIGNATURE_LEN)
    secured = bytes([PAYLOAD_LEN]) + payload + freshness + authenticator
    return struct.pack(">II", HEADER_ID[profile], len(secured)) + secured


def main():
    host, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    gap = float(sys.argv[4]) if len(sys.argv) > 4 else 0.05
    profile = sys.argv[5] if len(sys.argv) > 5 else "mldsa65"
    assert profile in HEADER_ID, profile
    key = None
    if len(sys.argv) > 6:
        with open(sys.argv[6], "rb") as f:
            key = f.read(32)
        assert profile == "mac" and len(key) == 32
    with socket.create_connection((host, port), timeout=5) as s:
        for i in range(count):
            s.sendall(forged_pdu(i + 1, profile, key))
            time.sleep(gap)
    print("sent %d forged %s PDUs to %s:%d" % (count, profile, host, port))


if __name__ == "__main__":
    main()
