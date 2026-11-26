"""handshake.csv: authenticated ML-KEM handshake, one row per attempt on each host."""
import numpy as np

from analysis import stats

PHASES = ("keygen", "encaps", "decaps", "sign", "verify", "kdf", "hash", "mac")
SESSION_PDUS = 1000  # the session length that the amortised cost per PDU assumes: one handshake per 1,000 PDUs
HEADER = ("mainfunction", "mf_period_us", "t_min_ms")  # recorded from the file's comment lines when present
TOTAL = {"initiator": "start of ML-KEM key generation to keys installed (after M3 is handed to SoAd; M4 not included)",
         "responder": "M1 completely received to keys installed after M3; includes the initiator's computation and two "
                      "network legs"}


def counts(cols):
    """{role: {'n': attempts, 'results': {result: count}}} with ok first and then the failures in the order they first
    occur; nothing is timed (all a negative test is read for)."""
    out = {}
    for role in dict.fromkeys(cols["role"].tolist()):
        results = cols["result"][cols["role"] == role].tolist()
        failures = [r for r in results if r != "ok"]
        out[role] = {"n": len(results), "results": {"ok": results.count("ok"), **{r: failures.count(r) for r in dict.fromkeys(failures)}}}
    return out


def analyse(cols):
    """Per role: attempts, successes (result == ok), counts per result, and over the successful
    handshakes describe() in microseconds of
    - total_ns, which means something different per role (TOTAL): the responder's total contains the
      initiator's computation and two network legs, and both totals contain main-function
      scheduling, so neither is crypto time;
    - compute: the sum of the stage columns of each handshake, the role's own crypto time;
    - every stage the role uses (a stage whose values are all 0 is unused and omitted): hash is all
      transcript hashes, mac is key-confirmation HMAC generate and verify;
    plus min / median / max of bytes_tx and bytes_rx (message bytes including the 8-byte SoAd PDU
    header of each message). Failed attempts are counted, not timed."""
    out = []
    for role, tally in counts(cols).items():
        ok = (cols["role"] == role) & (cols["result"] == "ok")
        r = {"role": role, "n": tally["n"], "ok": tally["results"]["ok"], "total_means": TOTAL[role],
             "failures": {label: c for label, c in tally["results"].items() if label != "ok"},
             "results": tally["results"],
             "total_us": stats.describe(cols["total_ns"][ok] / 1e3),
             "compute_us": stats.describe(sum(cols[f"{p}_ns"][ok] for p in PHASES) / 1e3),
             "phases_us": {p: stats.describe(cols[f"{p}_ns"][ok] / 1e3) for p in PHASES if cols[f"{p}_ns"][ok].any()}}
        for k in ("bytes_tx", "bytes_rx"):
            b = cols[k][ok]
            r[k] = {"min": int(b.min()), "median": float(np.median(b)), "max": int(b.max())} if b.size else None
        out.append(r)
    return out
