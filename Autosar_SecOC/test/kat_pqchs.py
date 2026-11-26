#!/usr/bin/env python3
"""Known-answer check of one PQC-SecOC-HS-v1 run, standard library only.

Input: the file written by `pqchs_test <file>` (hex lines m1, m2, m3, m4, ss, prk, k_kc_r, k_kc_i,
k_auth_i2r, k_auth_r2i, sid_a, sid_b, signed_b, signed_a, sess_a, sess_b). The shared secret and the
two signatures are taken as opaque bytes; everything else of the key schedule is recomputed here from
the protocol definition and must match byte for byte:

    th2     = H(L || M1 || ver || ID_B || ct);   B signs 'R' || th2 (signed_b)
    PRK     = HKDF-Extract(salt = th2, IKM = ss)
    key     = HKDF-Expand(PRK, L || label || ID_A || ID_B, 32)   labels kc-r, kc-i, auth-i2r, auth-r2i
    mac_B   = HMAC(K_kc_r, H(L || M1 || M2 without mac_B))
    th3     = H(L || M1 || M2);                  A signs 'I' || th3 (signed_a)
    mac_A   = HMAC(K_kc_i, H(L || M1 || M2 || ver || sig_A))
    sess    = H(L || M1 || M2 || M3);  sid = first 4 bytes;  mac_ack = HMAC(K_kc_r, sess)

pqchs_test deletes the file when it starts and writes it only for a run without a failed check, so a
missing file, or one without all the lines above, means there is no run to check: exit status not 0.

H = SHA-384, HKDF and HMAC with SHA-256, L = "PQC-SecOC-HS-v1" (15 bytes, no terminator).
Usage: python3 kat_pqchs.py <file>      exit status 0 = all values match
"""
import hashlib
import hmac
import sys

L = b"PQC-SecOC-HS-v1"
LEN = {"m1": 1217, "m2": 4462, "m3": 3342, "m4": 33}


def H(*parts):
    return hashlib.sha384(b"".join(parts)).digest()


def hmac256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac256(prk, block + info + bytes([counter]))
        okm += block
        counter += 1
    return okm[:length]


def main(path):
    v = {}
    with open(path) as f:
        for line in f:
            name, _, value = line.strip().partition("=")
            if name:
                v[name] = bytes.fromhex(value)

    failures = []

    def check(name, got, expected):
        ok = got == expected
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            failures.append(name)

    for name, length in LEN.items():
        check(f"len({name}) = {length}", len(v[name]), length)
    assert len(L) == 15

    m1, m2, m3, m4 = v["m1"], v["m2"], v["m3"], v["m4"]
    ver, id_a, ek = m1[0:1], m1[1:33], m1[33:]
    id_b, ct, sig_b, mac_b = m2[1:33], m2[33:1121], m2[1121:4430], m2[4430:]
    sig_a, mac_a = m3[1:3310], m3[3310:]
    mac_ack = m4[1:]
    check("ver = 0x01 in M1..M4", (m1[0], m2[0], m3[0], m4[0]), (1, 1, 1, 1))
    check("field lengths", (len(ek), len(ct), len(sig_b), len(sig_a)), (1184, 1088, 3309, 3309))

    th2 = H(L, m1, ver, id_b, ct)
    check("message signed by B = 'R' || th2", v["signed_b"], b"R" + th2)
    prk = hmac256(th2, v["ss"])                       # HKDF-Extract(salt, IKM) = HMAC(salt, IKM)
    check("PRK", prk, v["prk"])

    keys = {}
    for label, name in ((b"kc-r", "k_kc_r"), (b"kc-i", "k_kc_i"), (b"auth-i2r", "k_auth_i2r"), (b"auth-r2i", "k_auth_r2i")):
        keys[name] = hkdf_expand(prk, L + label + id_a + id_b, 32)
        check(name, keys[name], v[name])

    check("mac_B", hmac256(keys["k_kc_r"], H(L, m1, m2[:4430])), mac_b)
    th3 = H(L, m1, m2)
    check("message signed by A = 'I' || th3", v["signed_a"], b"I" + th3)
    check("mac_A", hmac256(keys["k_kc_i"], H(L, m1, m2, m3[0:1], sig_a)), mac_a)
    sess = H(L, m1, m2, m3)
    check("mac_ack", hmac256(keys["k_kc_r"], sess), mac_ack)
    check("sess of A", sess, v["sess_a"])
    check("sess of B", sess, v["sess_b"])
    check("sid of A", sess[:4], v["sid_a"])
    check("sid of B", sess[:4], v["sid_b"])
    check("four distinct keys", len(set(keys.values())), 4)

    if failures:
        print(f"FAIL: {len(failures)} value(s) differ: {', '.join(failures)}")
        return 1
    print("PASS: every recomputed value matches")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
