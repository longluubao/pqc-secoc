"""Independent second reading of E2 (direct library call against the Csm path, paired, per process launch).

usage: python3 -I e2_own.py margin  <aa_run_dir> <margin_file_to_write>
       python3 -I e2_own.py compare <ab_or_aa_run_dir> <analysis_dir> <key_prefix>
       python3 -I e2_own.py --self-test
Raw files: <run_dir>/overhead/overhead_paired[_aa]_L<nn>.csv with the columns seq,order,op,standalone_ns,csm_ns
(in an A/A file the second column is a second direct call). Pairs with seq < 1000 are the warm-up and are dropped.
Per launch and operation: r = geometric mean of csm_ns / standalone_ns over the remaining pairs.
A launch file that is invalid by the file-level rules of DATA_SCHEMA.md (no bottom block; signature_mismatches or
failed_calls not 0; mlockall not ok; start and end frequency differ; cpu_s / wall_s below 0.97) is printed and left out
of every figure: n_launches counts the valid launches, n_invalid_launches the others.

margin  (rule of CAMPAIGN.md, fixed before the A/A block was run): noise floor = largest |r - 1| over all A/A
        launches and both operations; margin = max(0.01, noise floor), rounded UP to four decimals; written as
        one number to the margin file.
compare over the A/B launches, per operation, with the launch as the unit: geometric mean of the r, Student-t 95 %
        interval on the log scale, smallest and largest r, standard deviation of log r, and the two one-sided
        t-tests of mean(log r) against -log(1 + margin) and +log(1 + margin) (p = the larger one-sided p;
        equivalence if p < 0.05). Each value is compared with the toolkit key
        <prefix>.overhead_paired...<op>.across_launch.<name> in numbers.csv. Exit 0 only if every such key that
        exists agrees and at least five keys per operation were compared.
        Added 2026-11-25, compared as a count exactly or to nine significant digits (no absolute allowance), per
        operation: median_standalone_us and median_csm_us (median of each column, the launches pooled), and
        across_launch.hl_mean_us, .hl_t95_lo_us, .hl_t95_hi_us: per launch the paired Hodges-Lehmann estimate of
        csm_ns - standalone_ns, which is the median of the Walsh averages (d_i + d_j) / 2 over all i <= j (each
        difference with itself included); then the mean of the launches' estimates and its Student-t 95 % interval
        (sd with the divisor n - 1).
        A run directory without A/B files is the A/A block (overhead_paired_aa_L*.csv): the same quantities, without
        margin and test, against the keys <prefix>.overhead_paired.aa.<op>..., all of them by the strict rule.
        The order of the two calls in a pair (column order: AB = the standalone_ns column measured first), per launch
        (<prefix>.overhead_paired.L<nn>.<op>.order_*, in the A/A block ...aa-L<nn>...) and over the pairs of all valid
        launches (...overhead_paired.<op>.order_*, ...aa.<op>...), by the strict rule: order_n_ab, order_n_ba;
        order_median_diff_ab / _ba = median of csm_ns - standalone_ns over the pairs of that order; order_hl = the
        two-sample Hodges-Lehmann shift of those differences, BA - AB (median of all d_BA - d_AB), with its 95 %
        interval order_hl_ci95_lo / _hi; order_p = the two-sided Mann-Whitney test of the AB against the BA
        differences. Times in us and in ms. The two-sample statistics are those of archive_compare.py (its rules).
        cliffs_delta, per launch and over all valid launches: P(csm > standalone) - P(csm < standalone). The
        definition does not say over which pairs: over ALL cross pairs of the two columns, 2U / (m n) - 1 (the
        unpaired dominance), settled from the docstring of the toolkit's stats.mann_whitney.
"""
import csv
import glob
import math
import os
import re
import site
import sys
from pathlib import Path

if sys.flags.no_user_site:      # python3 -I hides the user site-packages, where numpy is installed on the measuring workstation
    site.addsitedir(site.getusersitepackages())
import numpy as np  # noqa: E402
from scipy import stats as sps  # noqa: E402
sys.dont_write_bytecode = True      # the import below must leave no __pycache__ in own/
sys.path.insert(0, str(Path(__file__).resolve().parent))      # python3 -I hides the script's directory as well
import archive_compare as two  # noqa: E402     (two-sample Hodges-Lehmann shift with its interval, Mann-Whitney test, median)

WARMUP = 1000
# DATA_SCHEMA.md: "CPU time over wall time clearly below 1" makes a pinned single-thread file invalid, without a number.
# 0.97 is the toolkit's documented threshold (validity table of its README), taken from there to settle that.
CPU_SHARE_MIN = 0.97


def record_compared(analysis_dir, keys):
    """Addendum F4: <analysis_dir>/own_compared_keys.txt, the keys that this call compared with a toolkit value and found
    equal, one per line, sorted. Under e9_compare.py (OWN_COMPARED_KEYS=add) the readers of one call add to one file;
    a direct call writes its own set. A call that does not end in agreement leaves no key of its own."""
    path = Path(analysis_dir) / "own_compared_keys.txt"
    if path.parent.is_dir():
        old = path.read_text().split() if os.environ.get("OWN_COMPARED_KEYS") == "add" and path.exists() else []
        path.write_text("".join(k + "\n" for k in sorted({*old, *keys})))


def launch_ratios(path):
    """{op: (geometric-mean ratio second / first column, pairs used)} of one launch file."""
    logs = {}
    with open(path, newline="") as f:
        rows = csv.DictReader(line for line in f if not line.startswith("#"))
        for row in rows:
            if int(row["seq"]) >= WARMUP:
                logs.setdefault(row["op"], []).append(math.log(int(row["csm_ns"]) / int(row["standalone_ns"])))
    return {op: (math.exp(sum(v) / len(v)), len(v)) for op, v in logs.items()}


def launch_pairs(path):
    """{op: (standalone_ns, csm_ns, AB)} of one launch file: two integer arrays and one that is True where the order of
    the pair is AB (the standalone_ns column measured first); the warm-up pairs left out."""
    cols = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(line for line in f if not line.startswith("#")):
            if int(row["seq"]) >= WARMUP:
                if row["order"] not in ("AB", "BA"):
                    raise SystemExit(f"{path}: order {row['order']!r} is neither AB nor BA")
                a, b, first = cols.setdefault(row["op"], ([], [], []))
                a.append(int(row["standalone_ns"]))
                b.append(int(row["csm_ns"]))
                first.append(row["order"] == "AB")
    return {op: (np.array(a, dtype=np.int64), np.array(b, dtype=np.int64), np.array(first, dtype=bool)) for op, (a, b, first) in cols.items()}


def order_numbers(d, ab):
    """{key part: value} of the order of the two calls: d = csm_ns - standalone_ns of each pair, ab = True where the pair's
    order is AB. Counts; the median difference of each order; the shift BA - AB (median of all d_BA - d_AB) with its
    95 % interval; the two-sided Mann-Whitney p of the two sets of differences. Times in us and in ms; a statistic that
    needs both orders is None (the toolkit must not have the key) when one order has no pair."""
    x, y = d[ab], d[~ab]
    k = {"order_n_ab": int(x.size), "order_n_ba": int(y.size)}
    both = x.size > 0 and y.size > 0
    shift = two.hodges_lehmann(x, y) if both else (None, None, None)
    k["order_p"] = two.mann_whitney(x, y)[1] if both else None
    for name, ns in (("order_median_diff_ab", two.median(x) if x.size else None), ("order_median_diff_ba", two.median(y) if y.size else None),
                     ("order_hl", shift[0]), ("order_hl_ci95_lo", shift[1]), ("order_hl_ci95_hi", shift[2])):
        k[name + "_us"], k[name + "_ms"] = (None, None) if ns is None else (ns / 1e3, ns / 1e6)
    return k


def header_faults(meta):
    """Reasons of DATA_SCHEMA.md why a launch file with these '# key=value' lines is no result; [] for a valid file."""
    if "wall_s" not in meta or "cpu_s" not in meta:
        return ["no bottom block (interrupted)"]
    why = [f"{name}={meta.get(name)}" for name in ("signature_mismatches", "failed_calls") if meta.get(name) != "0"]
    why += [f"mlockall={meta.get('mlockall')}"] if meta.get("mlockall") != "ok" else []
    if meta.get("freq_khz_start") is None or meta.get("freq_khz_start") != meta.get("freq_khz_end"):
        why.append(f"freq_khz_start={meta.get('freq_khz_start')}, freq_khz_end={meta.get('freq_khz_end')}")
    if float(meta["cpu_s"]) / float(meta["wall_s"]) < CPU_SHARE_MIN:
        why.append(f"cpu_s / wall_s = {float(meta['cpu_s']) / float(meta['wall_s']):.4f}, below {CPU_SHARE_MIN}")
    return why


def launch_files(run_dir, aa):
    """(the valid launch files of the block, the number of invalid ones); an invalid file is printed and left out."""
    pattern = "overhead_paired_aa_L*.csv" if aa else "overhead_paired_L[0-9]*.csv"
    files = sorted(glob.glob(os.path.join(run_dir, "overhead", pattern)))
    if not files:
        raise SystemExit(f"{run_dir}: no overhead/{pattern}")
    valid = []
    for p in files:
        with open(p) as f:
            meta = dict(line[1:].strip().partition("=")[::2] for line in f if line.startswith("#"))
        why = header_faults(meta)
        if why:
            print(f"{os.path.basename(p)}: INVALID launch by the own rules, left out of every figure: " + "; ".join(why))
        else:
            valid.append(p)
    if not valid:
        raise SystemExit(f"{run_dir}: no valid launch among the {len(files)} files overhead/{pattern}")
    return valid, len(files) - len(valid)


def ratios(files):
    out = {}
    for p in files:
        for op, (r, n) in launch_ratios(p).items():
            out.setdefault(op, []).append((os.path.basename(p), r, n))
    return out


def margin_from(per_op):
    floor = max(abs(r - 1) for rows in per_op.values() for _, r, _ in rows)
    return floor, max(0.01, math.ceil(floor * 1e4 - 1e-9) / 1e4)


def launch_level(values, margin=None):
    d = np.log(np.asarray(values, dtype=float))
    n, mean, sd = d.size, float(d.mean()), float(d.std(ddof=1))
    se = sd / math.sqrt(n)
    h95 = float(sps.t.ppf(0.975, n - 1)) * se
    out = {"n_launches": n, "gm_ratio_diff": math.exp(mean) - 1, "gm_ratio_diff_min": float(min(values)) - 1,
           "gm_ratio_diff_max": float(max(values)) - 1, "gm_ratio_log_sd": sd, "t95_lo": math.exp(mean - h95) - 1,
           "t95_hi": math.exp(mean + h95) - 1}
    if margin is not None:      # the A/A block has no margin and no test
        m = math.log1p(margin)
        out.update(tost_margin=margin, tost_p=float(max(sps.t.sf((mean + m) / se, n - 1), sps.t.cdf((mean - m) / se, n - 1))))
    return out


def hodges_lehmann(d):
    """Paired Hodges-Lehmann estimate of the differences d: the median of the Walsh averages (d_i + d_j) / 2 over all
    i <= j, each difference with itself included (n (n + 1) / 2 averages). Integer differences stay exact: the sums
    are integers, and the median of an even number of them is the mean of the two middle ones."""
    d = np.asarray(d)
    i, j = np.triu_indices(d.size)
    return float(np.median(d[i] + d[j])) / 2


def mean_t95(values):
    """(mean, lower, upper): the mean of the values and its Student-t 95 % interval, sd with the divisor n - 1."""
    x = np.asarray(values, dtype=float)
    mean = float(x.mean())
    h = float(sps.t.ppf(0.975, x.size - 1)) * float(x.std(ddof=1)) / math.sqrt(x.size)
    return mean, mean - h, mean + h


def strict(mine, theirs):
    """A count exactly, any other value to nine significant digits."""
    return theirs == mine if isinstance(mine, int) else math.isclose(mine, theirs, rel_tol=1e-9, abs_tol=0.0)


def agrees(mine, text):
    """The own value against the toolkit's text by the strict rule. The toolkit writes a p below 1e-300 as '<1e-300': that
    agrees with an own p below 1e-300 (the same statement; there is no digit to compare)."""
    if text.startswith("<"):
        return isinstance(mine, float) and mine < float(text[1:])
    return strict(mine, float(text))


def self_test():
    assert margin_from({"sign": [("a", 1.0004, 1), ("b", 0.9991, 1)]})[1] == 0.01       # a floor below 1 % gives the 1 % margin
    floor, m = margin_from({"sign": [("a", 1.01234, 1)], "verify": [("a", 0.999, 1)]})
    assert abs(floor - 0.01234) < 1e-12 and m == 0.0124                      # rounded up, never down
    assert margin_from({"sign": [("a", 1.0124, 1)]})[1] == 0.0124            # an exact four-decimal value stays
    r = launch_level([1.001, 0.999, 1.0005, 0.9995, 1.0], 0.01)
    assert r["n_launches"] == 5 and abs(r["gm_ratio_diff"]) < 1e-4 and r["tost_p"] < 0.001   # tight around 1: equivalent
    r = launch_level([1.02, 1.021, 1.019, 1.02, 1.0205], 0.01)
    assert r["tost_p"] > 0.99                                                # 2 % above with a 1 % margin: not equivalent
    r = launch_level([1.001, 0.999])
    assert r["n_launches"] == 2 and "tost_p" not in r and "tost_margin" not in r   # no margin: no test
    assert hodges_lehmann([1, 2, 4]) == 2.25         # Walsh averages 1 1.5 2 2.5 3 4; without the i = j terms it would be 2.5
    assert hodges_lehmann(np.array([-3, 5])) == 1 and hodges_lehmann([7]) == 7 and hodges_lehmann([0, 0, 1]) == 0.25
    mean, lo, hi = mean_t95([1, 2, 3, 4, 5])         # sd sqrt(2.5), table value t(0.975; 4) = 2.776445
    assert mean == 3 and math.isclose(hi - 3, 2.776445105 * math.sqrt(0.5), rel_tol=1e-8) and math.isclose(3 - lo, hi - 3)
    assert float(np.median(np.array([4, 1, 3, 2]))) == 2.5                   # the median of a column, even number of values
    # order of the calls, by hand: AB differences 1, 2, 3 and BA differences 4, 5, 7 ns: medians 2 and 5; the nine
    # differences BA - AB are 1 2 2 3 3 4 4 5 6, median 3; every BA difference lies above every AB one: U = 9 of 9,
    # z = (9 - 4.5 - 0.5) / sqrt(3 x 3 x 7 / 12), two-sided; 3 and 3 values give no interval (C < 1)
    o = order_numbers(np.array([4, 1, 5, 2, 7, 3]), np.array([False, True, False, True, False, True]))
    assert o["order_n_ab"] == 3 and o["order_n_ba"] == 3 and o["order_median_diff_ab_us"] == 0.002 and o["order_median_diff_ba_ms"] == 5e-6
    assert o["order_hl_us"] == 0.003 and o["order_hl_ci95_lo_us"] is None and math.isclose(o["order_p"], 2 * sps.norm.sf(4 / math.sqrt(5.25)), rel_tol=1e-12)
    assert two.mann_whitney(np.array([1, 2, 2, 3]), np.array([2, 4, 5, 6]))[2] == 0.75      # Cliff's delta over all 16 cross pairs: 13 above, 1 below, 2 equal
    assert two.hodges_lehmann(np.array([1, 2, 3]), np.array([4, 5, 7]), in_memory=0)[0] == 3.0       # the shift counted without forming the differences (the pooled set)
    o = order_numbers(np.array([4, 1, 5]), np.array([True, True, True]))     # one order only: counts and one median, nothing that needs both
    assert o["order_n_ba"] == 0 and o["order_median_diff_ab_us"] == 0.004 and o["order_p"] is None and o["order_hl_ms"] is None
    good = {"signature_mismatches": "0", "failed_calls": "0", "mlockall": "ok", "freq_khz_start": "1500000", "freq_khz_end": "1500000",
            "wall_s": "18.505", "cpu_s": "18.509"}
    assert header_faults(good) == [] and header_faults({k: v for k, v in good.items() if k not in ("wall_s", "cpu_s")}) == ["no bottom block (interrupted)"]
    for name, value in (("signature_mismatches", "1"), ("failed_calls", "2"), ("mlockall", "failed"), ("freq_khz_end", "600000"), ("cpu_s", "17.9")):
        assert len(header_faults({**good, name: value})) == 1, name                # 17.9 / 18.505 = 0.9673, below 0.97
    assert header_faults({**good, "cpu_s": "17.96"}) == []                         # 0.9705: not below
    assert strict(10, 10.0) and not strict(10, 10.000001) and strict(1.5, 1.5000000001) and not strict(1.5, 1.50000001)
    assert not strict(1.5e-7, 1.6e-7) and strict(0.0, 0.0)                   # no absolute allowance for a small value
    assert agrees(0.0, "<1e-300") and agrees(3e-310, "<1e-300") and not agrees(2e-300, "<1e-300") and not agrees(7, "<1e-300")
    assert agrees(1.5, "1.5000000001") and not agrees(1.5, "1.50000001") and agrees(10, "10")
    print("self-test ok")


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    self_test()
    mode, run_dir = sys.argv[1], sys.argv[2]
    if mode == "margin":
        per_op = ratios(launch_files(run_dir, True)[0])
        for op, rows in per_op.items():
            print(f"A/A {op}: " + " ".join(f"{r - 1:+.5f}" for _, r, _ in rows) + f"   (pairs per launch {rows[0][2]})")
        floor, margin = margin_from(per_op)
        launches = {len(rows) for rows in per_op.values()}
        if launches != {10}:
            raise SystemExit(f"expected 10 A/A launches per operation, found {sorted(launches)}")
        with open(sys.argv[3], "w") as f:
            f.write(f"# relative equivalence margin of E2, from the A/A block {os.path.basename(os.path.normpath(run_dir))}: "
                    f"noise floor {floor:.6f} (largest |r - 1| over 10 launches and both operations); rule: max(0.01, floor), four decimals rounded up\n"
                    f"{margin:.4f}\n")
        print(f"noise floor {floor:.6f}; margin {margin:.4f}; written to {sys.argv[3]}")
        return
    if mode != "compare":
        raise SystemExit("mode must be margin or compare")
    analysis_dir, prefix = sys.argv[3], sys.argv[4]
    record_compared(analysis_dir, [])    # a direct call starts the file
    aa = not glob.glob(os.path.join(run_dir, "overhead", "overhead_paired_L[0-9]*.csv"))   # no A/B file: the A/A block
    margin = None
    if not aa:
        margin = [float(s) for s in map(str.strip, open(os.path.join(run_dir, "equivalence_margin.txt"))) if s and not s.startswith("#")]
        (margin,) = margin
    files, invalid = launch_files(run_dir, aa)
    per_op = ratios(files)
    cols = {}      # {op: [(standalone_ns, csm_ns) of each launch]}
    for p in files:
        for op, ab in launch_pairs(p).items():
            cols.setdefault(op, []).append(ab)
    order = {}     # {key part behind '<prefix>.overhead_paired.': order_numbers()} per launch and over all valid launches
    for p in files:
        launch = ("aa-" if aa else "") + re.search(r"_(L\d+)\.csv$", p)[1]
        for op, (x, y, first) in launch_pairs(p).items():
            order[f"{launch}.{op}"] = {**order_numbers(y - x, first), "cliffs_delta": two.mann_whitney(x, y)[2]}
    for op, launches in cols.items():
        x, y, first = (np.concatenate(v) for v in zip(*launches))
        order[("aa." if aa else "") + op] = {**order_numbers(y - x, first), "cliffs_delta": two.mann_whitney(x, y)[2]}
    kit, name_of, agreed, tk = {}, {}, [], {}
    with open(os.path.join(analysis_dir, "numbers.csv"), newline="") as f:
        for r in csv.DictReader(f):
            tk[r["key"]] = r["value"]
            m = re.fullmatch(re.escape(prefix) + r"\.overhead_paired(?:\..+)?\.(sign|verify)\.across_launch\.(\w+)", r["key"])
            if m and r["unit"] != "text" and (".aa." in r["key"]) == aa:   # each block has its own keys: the A/A block's carry .aa.
                kit[(m[1], m[2])], name_of[(m[1], m[2])] = float(r["value"]), r["key"]
    bad = 0
    for op, rows in per_op.items():
        own = {**launch_level([r for _, r, _ in rows], margin), "n_invalid_launches": invalid}
        if aa:
            print(f"A/A {op}: {own['n_launches']} launches, second direct call against the first: {own['gm_ratio_diff'] * 100:+.4f} % "
                  f"[{own['t95_lo'] * 100:+.4f}, {own['t95_hi'] * 100:+.4f}] (95 %), launches from {own['gm_ratio_diff_min'] * 100:+.4f} to "
                  f"{own['gm_ratio_diff_max'] * 100:+.4f} %; the noise floor, not judged against a margin")
        else:
            print(f"{op}: {own['n_launches']} launches, Csm path against direct call: {own['gm_ratio_diff'] * 100:+.4f} % "
                  f"[{own['t95_lo'] * 100:+.4f}, {own['t95_hi'] * 100:+.4f}] (95 %), launches from {own['gm_ratio_diff_min'] * 100:+.4f} to "
                  f"{own['gm_ratio_diff_max'] * 100:+.4f} %, margin {margin * 100:.2f} %, TOST p = {own['tost_p']:.3g} -> "
                  f"{'equivalent within the margin' if own['tost_p'] < 0.05 else 'equivalence NOT shown'}")
        names = {"n_launches": "n_launches", "n_invalid_launches": "n_invalid_launches", "gm_ratio_diff": "gm_ratio_diff", "gm_ratio_diff_min": "gm_ratio_diff_min",
                 "gm_ratio_diff_max": "gm_ratio_diff_max", "gm_ratio_log_sd": "gm_ratio_log_sd", "tost_margin": "tost_margin",
                 "tost_p": "tost_p", "gm_ratio_diff_t95_lo": "t95_lo", "gm_ratio_diff_t95_hi": "t95_hi"}
        compared = 0
        for key, mine in names.items():
            if (op, key) not in kit or mine not in own:
                continue
            compared += 1
            theirs = kit[(op, key)]
            if aa:      # no key of the A/A block was compared before 2026-11-25: the strict rule for all of them
                same = strict(own[mine], theirs)
            else:
                same = any(math.isclose(theirs, own[mine] * k, rel_tol=1e-6, abs_tol=1e-12) for k in (1, 100))   # a share may be stored as a fraction or in percent
            if not same:
                bad += 1
                print(f"DIFF {op}.{key}: own {own[mine]!r}, toolkit {theirs!r}")
            else:
                agreed.append(name_of[(op, key)])
        a, b, _ = (np.concatenate(x) for x in zip(*cols[op]))          # the launches pooled
        hl = [hodges_lehmann(y - x) / 1e3 for x, y, _ in cols[op]]     # us, one estimate per launch
        mean, lo, hi = mean_t95(hl)
        new = {"median_standalone_us": float(np.median(a)) / 1e3, "median_csm_us": float(np.median(b)) / 1e3,
               "across_launch.hl_mean_us": mean, "across_launch.hl_t95_lo_us": lo, "across_launch.hl_t95_hi_us": hi}
        print(f"{op}: median {new['median_standalone_us']:.3f} us first column, {new['median_csm_us']:.3f} us second column over {a.size} pairs; "
              f"Hodges-Lehmann difference per launch, mean {mean:+.4f} us [{lo:+.4f}, {hi:+.4f}] (95 %, {len(hl)} launches)")
        head = f"{prefix}.overhead_paired{'.aa' if aa else ''}.{op}."
        extra = 0
        for key, mine in new.items():
            if head + key not in tk:
                print(f"NOT COMPARED {head}{key}: own {mine!r}, the toolkit has no such key")
            elif strict(mine, float(tk[head + key])):
                extra += 1
                agreed.append(head + key)
            else:
                extra += 1
                bad += 1
                print(f"DIFF {head}{key}: own {mine!r}, toolkit {tk[head + key]}")
        print(f"{op}: compared {compared + extra} keys with the toolkit")
        if compared < 5:
            bad += 1
            print(f"{op}: fewer than five toolkit keys found for the launch-level comparison")
    done = differ = 0      # the order of the two calls: every key of every launch and of the set, by the strict rule
    for where, own in sorted(order.items()):
        for key, mine in own.items():
            name = f"{prefix}.overhead_paired.{where}.{key}"
            if mine is None and name not in tk:
                continue
            done += 1
            if mine is not None and name in tk and agrees(mine, tk[name]):
                agreed.append(name)
            else:
                differ += 1
                print(f"DIFF {name}: own {mine!r}, toolkit {tk.get(name)}")
    for op in per_op:
        o = order[("aa." if aa else "") + op]
        print(f"{op}: order of the two calls over all valid launches: {o['order_n_ab']} pairs AB, {o['order_n_ba']} BA; median difference "
              f"{o['order_median_diff_ab_us']} and {o['order_median_diff_ba_us']} us; shift BA - AB {o['order_hl_us']} us "
              f"[{o['order_hl_ci95_lo_us']}, {o['order_hl_ci95_hi_us']}], Mann-Whitney p {o['order_p']:.6g}")
    print(f"order of the two calls and Cliff's delta: compared {done} keys of {len(order)} launches and sets with the toolkit, {differ} differences")
    bad += differ
    record_compared(analysis_dir, agreed if bad == 0 else [])
    print("OWN-CHECK AGREES" if bad == 0 else "OWN-CHECK DISAGREES")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
