"""Independent second reading of the E1 sessions of one board side by side, compared with the toolkit's keys e1.all.<host>.*.

usage: python3 -I -B sessions_compare.py <sessions analysis dir> <session run dir> <session run dir> ...
       python3 -I -B sessions_compare.py --self-test
e.g.   sessions_compare.py analysis/E1_sessions_iris runs/E1_s1_iris_<t> runs/E1_s2_iris_<t> runs/E1_s3_iris_<t>
There is no key prefix: a key is taken by what follows its head, <head>.crypto_ops.<step>.<op>.<stat>.<which>_over_sessions.

The toolkit's keys are the smallest (min), the largest (max) and both ends (range, text 'a--b', or the one value when
the sessions have the same) of the sessions' values of <stat>; sessions are never pooled.
Own rules:
  session value  read here from <run dir>/crypto_ops/crypto_ops_<step>.csv by the rule of e1_compare.py: seq < 1000
                 dropped per operation, ns / 1000 = us; n, min, mean, max, the type-7 percentiles (e1_compare.type7)
                 and, for mldsa_sign, count and share of the times above 5, 10, 15 and 20 ms. No per-session key of
                 the toolkit is read.
  its judge      e1_compare.main() returns no values, so its code is made the judge of the ones computed here: they
                 are written to a numbers.csv in a temporary directory and e1_compare.main() is run on the session's
                 run directory against that file. It must return 0 and name every one of them as compared and equal.
  over sessions  min and max over the sessions that have the statistic. A key's n must be the number of those
                 sessions and its source_file their directory names; anything else is a difference.
  not compared   a toolkit key whose statistic e1_compare.py does not compute (the _ms twins of the _us keys,
                 tail_ratio_per_ms): counted or named, it does not change the exit code.
Counts are compared exactly, other values to nine digits. Exit 0 only if e1_compare.py agrees with the values of every
session, at least one key was compared and nothing differs.
"""
import contextlib
import csv
import io
import math
import re
import site
import sys
import tempfile
from pathlib import Path

if sys.flags.no_user_site:      # python3 -I hides the user site-packages, where numpy is installed on the measuring workstation
    site.addsitedir(site.getusersitepackages())
sys.dont_write_bytecode = True      # the import below must leave no __pycache__ in own/
sys.path.insert(0, str(Path(__file__).resolve().parent))      # python3 -I hides the script's directory as well
import e1_compare  # noqa: E402

KEY = re.compile(r"(crypto_ops\..+)\.(min|max|range)_over_sessions$")
COLUMNS = ("key", "value", "formatted", "unit", "n", "source_file", "how")
PERCENTILES = (("p50", .5), ("p90", .9), ("p95", .95), ("p99", .99), ("p99_9", .999), ("p99_99", .9999))


def session_values(run_dir):
    """{crypto_ops.<step>.<op>.<stat>: value} of one session; n and the exceedance counts are int."""
    own = {}
    for path in sorted(Path(run_dir).glob("crypto_ops/crypto_ops_*.csv")):
        ops = {}
        with open(path) as f:
            for line in f:
                if not line.startswith(("#", "op,")):
                    op, seq, ns = line.split(",")
                    if int(seq) >= 1000:
                        ops.setdefault(op, []).append(int(ns))
        for op, ns in ops.items():
            us = [v / 1000 for v in sorted(ns)]
            base = f"crypto_ops.{path.stem[len('crypto_ops_'):]}.{op}."
            own.update({base + "n": len(ns), base + "min_us": us[0], base + "max_us": us[-1],
                        base + "mean_us": sum(ns) / len(ns) / 1000})
            for name, p in PERCENTILES:
                own[f"{base}{name}_us"] = e1_compare.type7(us, p)
            if op == "mldsa_sign":
                for ms in (5, 10, 15, 20):
                    k = sum(v > ms * 1_000_000 for v in ns)
                    own.update({f"{base}exceed_{ms}ms.k": k, f"{base}exceed_{ms}ms.p": k / len(ns)})
    return own


def e1_reader_agrees(run_dir, own):
    """True if e1_compare.main(), run on the session's raw files, finds every value of `own` equal to its own."""
    with tempfile.TemporaryDirectory() as tmp:
        with open(Path(tmp) / "numbers.csv", "w", newline="") as f:
            rows = csv.writer(f)
            rows.writerow(COLUMNS)
            rows.writerows((f"s.{k}", repr(v), "", "", "", "", "") for k, v in own.items())
        argv, sys.argv = sys.argv, ["e1_compare.py", str(run_dir), tmp, "s"]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                status = e1_compare.main()
        except SystemExit as stop:      # should its main() come to end in sys.exit(), as that of the other readers does
            status = stop.code
        finally:
            sys.argv = argv
        return status == 0 and (Path(tmp) / "own_compared_keys.txt").read_text().split() == sorted(f"s.{k}" for k in own)


def same(a, b):
    """a own, b the toolkit's text: counts exactly, other values to nine digits (the expression of the other readers)."""
    try:
        return float(b) == a if isinstance(a, int) else math.isclose(a, float(b), rel_tol=1e-9, abs_tol=1e-12)
    except ValueError:
        return False


def compare(analysis_dir, sessions):
    """sessions: {run directory name: session_values()}. Prints each difference; returns (the keys that agree, the
    number of differences, the toolkit keys not recomputed here)."""
    agreed, bad, skipped = [], 0, []
    with open(Path(analysis_dir) / "numbers.csv", newline="") as f:
        for r in csv.DictReader(f):
            m = KEY.search(r["key"])
            have = {name: own[m[1]] for name, own in sessions.items() if m and m[1] in own}
            if not have:
                skipped.append(r["key"])
                continue
            lo, hi = min(have.values()), max(have.values())
            mine = {"min": [lo], "max": [hi], "range": [lo, hi]}[m[2]]
            theirs = r["value"].split("--") if m[2] == "range" else [r["value"]]
            if m[2] == "range" and (len(theirs) == 1) != (lo == hi):
                theirs = []      # the form is the one value exactly when all sessions have the same: 'a--a' is a difference
            elif m[2] == "range" and len(theirs) == 1:
                theirs *= 2      # the one value that all sessions have
            if (len(theirs) == len(mine) and all(same(a, b) for a, b in zip(mine, theirs))
                    and r["n"] == str(len(have)) and set(r["source_file"].split(", ")) == set(have)):
                agreed.append(r["key"])
            else:
                bad += 1
                print(f"DIFF {r['key']}: own {'--'.join(map(repr, mine))} of {len(have)} sessions ({', '.join(have)}), "
                      f"toolkit {r['value']} of n={r['n']} ({r['source_file']})")
    return agreed, bad, skipped


def self_test():
    def session(root, name, ns):      # 1000 warm-up rows of 99 ms, which no statistic may see, then the values
        (root / name / "crypto_ops").mkdir(parents=True)
        (root / name / "crypto_ops" / "crypto_ops_sign_p8.csv").write_text(
            "# msg_bytes=8\nop,seq,ns\n" + "".join(f"mldsa_sign,{i},{v}\n" for i, v in enumerate([99_000_000] * 1000 + ns)))
        return root / name

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        runs = [session(root, "s1", [1_000_000, 2_000_000, 3_000_000, 12_000_000]),
                session(root, "s2", [1_000_000, 2_000_000, 5_000_000, 30_000_000]),
                session(root, "s3", [1_000_000, 2_000_000, 3_000_000, 7_000_000])]
        own = {r.name: session_values(r) for r in runs}
        b = "crypto_ops.sign_p8.mldsa_sign."
        s1 = own["s1"]
        assert (s1[b + "n"], s1[b + "min_us"], s1[b + "p50_us"], s1[b + "mean_us"], s1[b + "max_us"]) == (4, 1000, 2500, 4500, 12000)
        assert (s1[b + "exceed_5ms.k"], s1[b + "exceed_10ms.p"], s1[b + "exceed_20ms.k"]) == (1, .25, 0)
        assert all(e1_reader_agrees(r, own[r.name]) for r in runs)
        assert not e1_reader_agrees(runs[0], {**s1, b + "max_us": 12000.001})       # a wrong session value is caught
        assert not e1_reader_agrees(runs[0], {**s1, b + "no_such_stat": 1.0})       # and one e1_compare.py does not compute

        def kit(rows, n="3", source="s1, s2, s3"):
            with open(root / "numbers.csv", "w", newline="") as f:
                out = csv.writer(f)
                out.writerow(COLUMNS)
                out.writerows((f"e1.all.x.{b}{k}_over_sessions", v, "", "", n, source, "") for k, v in rows.items())
            with contextlib.redirect_stdout(io.StringIO()):
                agreed, bad, skipped = compare(root, own)
            return len(agreed), bad, len(skipped)

        rows = {"max_us.max": "30000.0", "max_us.min": "7000.0", "max_us.range": "7000.0--30000.0",
                "p50_us.range": "2500.0--3500.0", "exceed_20ms.k.max": "1", "exceed_20ms.k.range": "0--1",
                "exceed_5ms.k.range": "1", "exceed_5ms.p.range": "0.25", "max_ms.max": "30.0"}
        assert kit(rows) == (8, 0, 1)                                               # max_ms: not recomputed, no difference
        assert kit({**rows, "max_us.max": "30000.001"}) == (7, 1, 1)                # one wrong end
        assert kit({**rows, "max_us.range": "7000.0--30000.001"}) == (7, 1, 1)
        assert kit({**rows, "exceed_20ms.k.range": "0"}) == (7, 1, 1)               # one value where the sessions differ
        assert kit({**rows, "exceed_5ms.k.range": "1--1"}) == (7, 1, 1)             # two pieces where the sessions have the same
        assert kit({**rows, "exceed_20ms.k.max": "1.0000000001"}) == (7, 1, 1)      # a count is compared exactly
        assert kit({**rows, "p50_us.range": "PASS"}) == (7, 1, 1)
        assert kit(rows, n="2") == (0, 8, 1) and kit(rows, source="s1, s2") == (0, 8, 1)       # another set of sessions
        del own["s3"]
        assert kit(rows) == (0, 8, 1)                                               # a session left out of the call
    print("self-test ok")


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    self_test()
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    analysis_dir, runs = sys.argv[1], [Path(r) for r in sys.argv[2:]]
    e1_compare.record_compared(analysis_dir, [])    # a direct call starts the file
    sessions, judged = {}, True
    for run in runs:
        sessions[run.name] = own = session_values(run)
        ok = e1_reader_agrees(run, own)
        judged = judged and ok
        print(f"{run.name}: {len(own)} values of the session computed here; e1_compare.py on the raw files "
              + ("finds every one of them equal to its own" if ok else "DOES NOT AGREE with them"))
    agreed, bad, skipped = compare(analysis_dir, sessions)
    other = [k for k in skipped if re.sub(r"_ms(\.\w+)$", r"_us\1", k) not in agreed]
    print(f"toolkit keys not recomputed here: {len(skipped) - len(other)} _ms twins of _us keys that agree" + "".join(f", {k}" for k in other))
    print(f"keys compared {len(agreed) + bad}, differences {bad}")
    ok = bool(judged and agreed and not bad)
    e1_compare.record_compared(analysis_dir, agreed if ok else [])
    print("OWN-CHECK AGREES" if ok else "OWN-CHECK DISAGREES")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
