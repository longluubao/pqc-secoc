#!/usr/bin/env python3
"""Gate F4 of E9_SPEC.md (Addendum F): no document prints a key that the own readers did not compare.

usage: python3 -I -B printed_keys_gate.py [--prefix e9.] <analysis dir | own_compared_keys.txt>... <file to scan>...
       python3 -I -B printed_keys_gate.py --self-test

Compared set: every own_compared_keys.txt that is named, or that lies in an analysis directory that is named (the files
which e9_compare.py and the other own readers write beside the toolkit's numbers.csv; a call that disagreed leaves an
empty one). Name the directories of ACCEPTED runs only: the file says that the keys were compared and found equal, not
that the run is a result, and a dry run or an older analysis directory (.prev) has one too. A numbers.csv beside such
a file gives the toolkit's keys, which are needed to judge a pattern. An own_checked_keys.txt beside it (first field of
each line a key) holds the keys that a reader checked against the sampling error and not to nine digits (bootstrap
ends): a printed key in it is not outside the set; such keys are counted and listed apart.
Files to scan: every other argument, any text. A printed key is every run of key characters (letters, digits, _ . -)
that begins with the prefix, in whatever form it stands: \\meas{key}, \\measpct{key}{2}, \\csname measraw@key\\endcsname,
{{v:key}} of a text template, a string of a script that fills one. Comments of a .tex file are left out; nothing else is, so
a key in a comment of a script or in running text counts as printed (the gate fails rather than overlook one).
A key with a place holder in it (#1 of a TeX macro, {name} of a Python f-string) or one that ends in a dot (a head to
which a script adds the rest) is a PATTERN: it passes only if the toolkit has keys that fit it and every one of them
was compared.
Exit 0 with the counts when every printed key is in the compared set, 1 with the list otherwise, 2 when the call names
no compared set or no file to scan.
"""
import csv
import re
import sys
from pathlib import Path

HOLDER = r"\{[^{}\n]*\}|#\d"       # a place holder inside a key: {name} of an f-string, #1 of a TeX macro


def printed(text, prefix, tex=False):
    """The keys and patterns with the prefix that a text prints, each once, in the order of their first appearance."""
    if tex:
        text = re.sub(r"(?<!\\)%.*", "", text)
    return list(dict.fromkeys(re.findall(r"(?<![A-Za-z0-9_.])" + re.escape(prefix) + r"(?:[A-Za-z0-9_.\-]|" + HOLDER + ")*", text)))


def check(found, compared, toolkit):
    """[(key or pattern, why)] for what is printed and not covered by the compared set."""
    bad = []
    for item in found:
        parts = re.split(HOLDER, item)
        if len(parts) == 1 and not item.endswith("."):
            if item not in compared:
                bad.append((item, "not in the compared set"))
            continue
        fit = re.compile(".+".join(map(re.escape, parts)) + (".+" if item.endswith(".") else ""))
        keys = sorted(k for k in toolkit if fit.fullmatch(k))
        left = [k for k in keys if k not in compared]
        if not keys:
            bad.append((item, "pattern: no toolkit key fits it (or no numbers.csv was given), so it cannot be judged"))
        elif left:
            bad.append((item, f"pattern: {len(left)} of the {len(keys)} toolkit keys that fit it were not compared, for example {left[0]}"))
    return bad


def self_test():
    compared = {"e9.s1.a.periodic.c.e2e.n", "e9.s1.a.periodic.c.e2e.latency_p50_ms", "e9.s1.a.periodic.c.jobs"}
    toolkit = compared | {"e9.s1.a.periodic.c.auth_p50_us"}
    tex = (r"\meas{e9.s1.a.periodic.c.e2e.n} of \measpct{e9.s1.a.periodic.c.auth_p50_us}{2} % \meas{e9.s1.a.periodic.c.commented_out}" "\n"
           r"\csname measraw@e9.s1.a.periodic.c.jobs\endcsname \newcommand{\mE}[1]{\meas{e9.s1.a.periodic.c.e2e.#1}} "
           r"\newcommand{\mP}[1]{\meas{e9.s1.a.periodic.c.#1}} \meas{e6.s1.x.jobs} \meas{pre9.s1.a.periodic.c.e2e.n}")
    found = printed(tex, "e9.", True)
    assert found == ["e9.s1.a.periodic.c.e2e.n", "e9.s1.a.periodic.c.auth_p50_us", "e9.s1.a.periodic.c.jobs", "e9.s1.a.periodic.c.e2e.#1", "e9.s1.a.periodic.c.#1"]
    # one key inside, one outside; one pattern whose keys were all compared, one that reaches a key that was not
    assert [item for item, _ in check(found, compared, toolkit)] == ["e9.s1.a.periodic.c.auth_p50_us", "e9.s1.a.periodic.c.#1"]
    assert "e9.s1.a.periodic.c.commented_out" in printed(tex, "e9.")                       # only a .tex file loses its comments
    assert printed("{{v:e9.s1.a.periodic.c.e2e.n}} and {{A:sec:results}}", "e9.") == ["e9.s1.a.periodic.c.e2e.n"]
    script = 'def E9(ses, stat):\n    return f"e9.{ses}.a.periodic.c.e2e.{stat}"\nHEAD = "e9.s1.a.periodic.c."\n'
    assert printed(script, "e9.") == ["e9.{ses}.a.periodic.c.e2e.{stat}", "e9.s1.a.periodic.c."]
    assert [item for item, _ in check(printed(script, "e9."), compared, toolkit)] == ["e9.s1.a.periodic.c."]
    assert check(["e9.{ses}.a.periodic.c.e2e.{stat}"], compared, set())[0][1].startswith("pattern: no toolkit key")
    assert check(["e9.s1.a.periodic.c.e2e.n"], compared, set()) == [] and check(["e9.s2.a.periodic.c.e2e.n"], compared, toolkit) != []
    print("self-test ok")
    return 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    self_test()
    prefix = "e9."
    if "--prefix" in argv[:-1]:
        i = argv.index("--prefix")
        prefix, argv = argv[i + 1], argv[:i] + argv[i + 2:]
    lists, scan = [], []
    for a in map(Path, argv):
        if a.is_dir():
            a = a / "own_compared_keys.txt"
            if not a.exists():
                sys.stderr.write(f"{a.parent}: no own_compared_keys.txt in this directory\n")
                return 2
        (lists if a.name == "own_compared_keys.txt" else scan).append(a)
    if not lists or not scan:
        sys.stderr.write(__doc__)
        return 2
    compared, checked, toolkit = set(), set(), set()
    for p in lists:
        compared |= set(p.read_text().split())
        if (p.parent / "own_checked_keys.txt").exists():
            checked |= {line.split("\t")[0] for line in (p.parent / "own_checked_keys.txt").read_text().splitlines() if line.strip()}
        if (p.parent / "numbers.csv").exists():
            with open(p.parent / "numbers.csv", newline="") as f:
                toolkit |= {r["key"] for r in csv.DictReader(f)}
    total = outside = within = 0
    for path in scan:
        found = printed(path.read_text(encoding="utf-8"), prefix, path.suffix == ".tex")
        bad = check(found, compared | checked, toolkit)
        only = [k for k in found if k in checked and k not in compared]
        total, outside, within = total + len(found), outside + len(bad), within + len(only)
        print(f"{path}: printed keys and patterns that begin with {prefix}: {len(found)}; outside the compared set: {len(bad)}"
              + (f"; checked against the sampling error only: {len(only)}" if only else ""))
        for item, why in bad:
            print(f"OUTSIDE {path}: {item}: {why}")
        for item in only:
            print(f"CHECKED {path}: {item}: agrees within the sampling error (own_checked_keys.txt), not to nine digits")
    print(f"compared set: {sum(k.startswith(prefix) for k in compared)} keys that begin with {prefix} from {len(lists)} file(s); "
          f"toolkit keys known: {sum(k.startswith(prefix) for k in toolkit)}; files scanned: {len(scan)}; printed: {total}; outside: {outside}" + (f"; checked against the sampling error only: {within}" if within else ""))
    print("GATE FAILS" if outside else "GATE PASSES")
    return 1 if outside else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
