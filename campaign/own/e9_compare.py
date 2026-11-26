#!/usr/bin/env python3
"""Own check of an E9 run directory: the reader of its layout AND the latency reader, both against the toolkit's keys.

usage: python3 -I e9_compare.py <run_dir> <analysis_dir> <key_prefix>      (python3 -I e9_compare.py --self-test)

A directory with the marker FUNCTIONAL holds gateway files (functional_compare.py), any other one the files of the
periodic mode (periodic_compare.py); e2e_compare.py reads the clock probe and the latency in both. The check passes
only if both readers pass. The last line is the verdict that campaign_post.sh and regen_all.sh print.
"""
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def readers(run_dir):
    first = "functional_compare.py" if (Path(run_dir) / "FUNCTIONAL").exists() else "periodic_compare.py"
    return [first, "e2e_compare.py"]


def main(argv):
    if argv[1:] == ["--self-test"]:
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            assert readers(d) == ["periodic_compare.py", "e2e_compare.py"]
            (Path(d) / "FUNCTIONAL").touch()
            assert readers(d) == ["functional_compare.py", "e2e_compare.py"]
        for r in ("periodic_compare.py", "functional_compare.py", "e2e_compare.py"):
            assert (HERE / r).exists(), r
        print("self-test ok")
        return 0
    if len(argv) != 4:
        sys.stderr.write(__doc__)
        return 2
    bad = []
    keys = Path(argv[2]) / "own_compared_keys.txt"      # Addendum F4: started here, each reader adds the keys it compared and found equal
    if keys.parent.is_dir():
        keys.write_text("")
    for r in readers(argv[1]):
        p = subprocess.run([sys.executable, "-I", str(HERE / r)] + argv[1:], capture_output=True, text=True,
                           env={**os.environ, "OWN_COMPARED_KEYS": "add"})
        out = (p.stdout + p.stderr).rstrip()
        print("== %s (exit %d)" % (r, p.returncode))
        print(out)
        if p.returncode != 0:
            bad.append(r)
    if bad and keys.parent.is_dir():
        keys.write_text("")                               # a call in which a reader disagrees leaves no key
    print("E9 OWN-CHECK %s" % ("DISAGREES: " + ", ".join(bad) if bad else "AGREES (layout reader and latency reader)"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
