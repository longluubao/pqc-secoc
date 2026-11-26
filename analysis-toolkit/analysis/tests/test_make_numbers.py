"""numbers.tex / numbers.csv: formatting rules, key scheme, and agreement of the two files."""
import copy
import csv
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from scipy import stats as sps

from analysis import make_numbers, make_tables, merge_numbers, stats
from analysis.make_numbers import fmt
from analysis.tests import synth

PARAMS = dict(warmup=10, block_len=5, n_boot=50, sim_draws=3, sim_jobs=400, trim=5)  # trim: the synthetic ladder files
PLUS, MINUS = r"\ensuremath{+}", r"\ensuremath{-}"
CONFIG = "periodic.p10ms-s2-c1-mldsa65-fifo"


# ---- formatting rules ----------------------------------------------------------------------------

@pytest.mark.parametrize("value,unit,want", [
    # microseconds: integers with {,}; never fewer than two significant digits
    (1527.42, "us", "1{,}527"), (431.81, "us", "432"), (17136.97, "us", "17{,}137"), (1234567.4, "us", "1{,}234{,}567"),
    (12.4, "us", "12"), (3.13, "us", "3.1"), (0.444, "us", "0.44"), (0.0712, "us", "0.071"), (9.96, "us", "10.0"), (0, "us", "0"),
    # milliseconds: two decimals; never fewer than two significant digits
    (1.52742, "ms", "1.53"), (17.13697, "ms", "17.14"), (0.43181, "ms", "0.43"), (1234.5, "ms", "1{,}234.50"),
    (0.0712, "ms", "0.071"), (0.00313, "ms", "0.0031"), (0, "ms", "0.00"),
    # ratios: percentages with two significant digits of min(p, 1 - p); scientific below 0.01%
    (0.0017, "percent", r"0.17\%"), (0.0257, "percent", r"2.6\%"), (0.125, "percent", r"12\%"), (0.75, "percent", r"75\%"),
    (0.1, "percent", r"10\%"), (0.9, "percent", r"90\%"), (0.3, "percent", r"30\%"), (0.7, "percent", r"70\%"),  # 100 * 0.9 is not 90
    (0.99, "percent", r"99.0\%"), (0.999, "percent", r"99.90\%"), (0.01, "percent", r"1.0\%"), (0.07, "percent", r"7.0\%"),
    (0.974, "percent", r"97.4\%"), (0.99617, "percent", r"99.62\%"), (0.999963, "percent", r"99.9963\%"),
    (0.000384, "percent", r"0.038\%"), (0.0001, "percent", r"0.010\%"),
    (0.0000999, "percent", r"\ensuremath{1.0\times10^{-2}}\%"), (2.3e-5, "percent", r"\ensuremath{2.3\times10^{-3}}\%"),
    (1e-9, "percent", r"\ensuremath{1.0\times10^{-7}}\%"), (0, "percent", r"0\%"), (1, "percent", r"100\%"),
    # a utilisation may exceed 1: one significant digit of the excess over 100%, so that only an exact one is 100%
    (1.2, "percent", r"120\%"), (3.456, "percent", r"346\%"), (1.04, "percent", r"104\%"), (1.0126, "percent", r"101\%"),
    (1.0004, "percent", r"100.04\%"), (1.003, "percent", r"100.3\%"), (1.006, "percent", r"100.6\%"),
    (1.000004, "percent", r"100.0004\%"),
    # p-values: two significant digits, scientific below 0.001, floor at 1e-300
    (0.636, "p", "0.64"), (0.191, "p", "0.19"), (0.0183, "p", "0.018"), (0.00398, "p", "0.0040"), (0.001, "p", "0.0010"),
    (1.0, "p", "1.0"), (0.000999, "p", r"\ensuremath{1.0\times10^{-3}}"), (1.42e-7, "p", r"\ensuremath{1.4\times10^{-7}}"),
    (9.96e-5, "p", r"\ensuremath{1.0\times10^{-4}}"), (1.08e-150, "p", r"\ensuremath{1.1\times10^{-150}}"),
    (2e-300, "p", r"\ensuremath{2.0\times10^{-300}}"), (1e-300, "p", r"\ensuremath{<10^{-300}}"),
    (5e-324, "p", r"\ensuremath{<10^{-300}}"), (0.0, "p", r"\ensuremath{<10^{-300}}"),
    # counts: integers with separators
    (17, "count", "17"), (10000, "count", "10{,}000"), (1234567, "count", "1{,}234{,}567"), (0, "count", "0"),
    (7000.0, "bytes", "7{,}000"), (95000.4, "bytes", "95{,}000"),
    # any other unit: three significant digits
    (2.72, "Mbit/s", "2.72"), (3400.0, "bytes/PDU", "3{,}400"), (149.97, "PDU/s", "150"), (0.06096, "1", "0.0610"),
    (0.699069, "1", "0.699"), (12345.6, "PDU/s", "12{,}346"),
])
def test_format_rules(value, unit, want):
    assert fmt(value, unit) == want


@pytest.mark.parametrize("value,unit,want", [
    (3.13, "us", PLUS + "3.1"), (-11.93, "us", MINUS + "12"), (0.444, "us", PLUS + "0.44"), (-1527.4, "us", MINUS + "1{,}527"),
    (0.00173, "percent", PLUS + r"0.17\%"), (-0.00139, "percent", MINUS + r"0.14\%"),
    (0.9, "percent", PLUS + r"90\%"),  # a signed percentage is a difference: no complement rule
    (-2.3e-5, "percent", r"\ensuremath{-2.3\times10^{-3}}\%"), (0.00386301, "1", PLUS + "0.00386"), (-0.043, "1", MINUS + "0.0430"),
    (0, "us", "0"), (-0.0, "us", "0"), (0.0, "percent", r"0\%"),  # zero carries no sign
])
def test_format_signed(value, unit, want):
    assert fmt(value, unit, signed=True) == want


def test_unsigned_units_still_show_a_minus_and_never_minus_zero():
    assert fmt(-0.9, "1") == MINUS + "0.900" and fmt(-3, "count") == MINUS + "3"
    assert fmt(-0.4, "count") == "0" and fmt(-0.4, "bytes") == "0"  # rounds to zero: "0", not "-0"


@pytest.mark.parametrize("values,unit,signed,want", [
    # an estimate and its bounds share the largest number of decimals any of them needs
    ([12.4, 9.6, 15.1], "us", False, ["12.4", "9.6", "15.1"]),  # 9.6 needs one decimal, so all three get one
    ([3.13, -11.93, 19.33], "us", True, [PLUS + "3.1", MINUS + "11.9", PLUS + "19.3"]),  # the legacy sign shift
    ([0.444, 0.296, 0.573], "us", True, [PLUS + "0.44", PLUS + "0.30", PLUS + "0.57"]),  # the legacy verify shift
    ([1527.42, 1509.99, 1541.97], "us", False, ["1{,}527", "1{,}510", "1{,}542"]),
    ([1.52742, 1.50999, 1.54197], "ms", False, ["1.53", "1.51", "1.54"]),
    # a time with a narrow interval: integers would print 1,456 [1,456, 1,456]; as for a proportion, the decimals show
    # one significant digit of the smallest distance between the estimate and a bound (0.19 us)
    ([1455.982, 1455.796, 1456.185], "us", False, ["1{,}456.0", "1{,}455.8", "1{,}456.2"]),
    ([1.455982, 1.455796, 1.456185], "ms", False, ["1.4560", "1.4558", "1.4562"]),
    ([17.278, 17.262, 17.296], "us", False, ["17.28", "17.26", "17.30"]),
    ([1.631, 1.593, 1.668], "us", True, [PLUS + "1.63", PLUS + "1.59", PLUS + "1.67"]),
    ([1455.982, 1455.982 - 1e-10, 1455.982 + 1e-10], "us", False, ["1{,}456", "1{,}456", "1{,}456"]),  # rounding noise
    # a proportion that is exactly zero is 0%, whatever decimals its group has: 0 of 10,000 has no third decimal
    ([0.0, 0.0, 0.000384], "percent", False, [r"0\%", r"0\%", r"0.038\%"]),
    # a proportion that is exactly one is 100%, as an exact zero is 0%: 1000 of 1000 has no second decimal ...
    ([1.0, 0.99617, 1.0], "percent", False, [r"100\%", r"99.62\%", r"100\%"]),
    # ... and only an exact one: 999,999 of a million keeps the digits that tell it from 100%
    ([0.999999, 0.99, 1.0], "percent", False, [r"99.99990\%", r"99.00000\%", r"100\%"]),
    ([0.0017, 0.00099, 0.00272, 0.00106, 0.00272], "percent", False,  # one estimate, exact and Wilson bounds together
     [r"0.170\%", r"0.099\%", r"0.272\%", r"0.106\%", r"0.272\%"]),
    ([0.125, 0.0266, 0.324], "percent", False, [r"12.5\%", r"2.7\%", r"32.4\%"]),
    ([0.5, 0.187, 0.813], "percent", False, [r"50\%", r"19\%", r"81\%"]),
    ([0.0002, -0.0001, 0.0006], "percent", True, [PLUS + r"0.020\%", MINUS + r"0.010\%", PLUS + r"0.060\%"]),
    # a proportion with bounds is never in scientific notation: plain decimals, every member with its two significant
    # digits (the smallest member sets the number of decimals); an exact zero beside them is 0%
    ([1e-6, 2.5e-8, 5.6e-6], "percent", False, [r"0.0001000\%", r"0.0000025\%", r"0.0005600\%"]),
    ([0.0, 0.0, 3.7e-6], "percent", False, [r"0\%", r"0\%", r"0.00037\%"]),
    ([0.0, -0.0001, 0.0006], "percent", True, [r"0\%", MINUS + r"0.010\%", PLUS + r"0.060\%"]),  # a ratio of exactly 1
    # ... and only an exact zero: a member that is not zero keeps two significant digits and never prints as 0
    ([0.0017, 1e-9, 0.005], "percent", False, [r"0.17000000\%", r"0.00000010\%", r"0.50000000\%"]),
    ([5e-5, 1e-5, 1.2e-4], "percent", False, [r"0.0050\%", r"0.0010\%", r"0.0120\%"]),
    # a narrow interval: two significant digits each would print 2.7% [2.6%, 2.7%]; the estimate (first) and its
    # bounds get the decimals that show one significant digit of the smallest distance between them (0.03%)
    ([0.026525, 0.026210, 0.026842], "percent", False, [r"2.65\%", r"2.62\%", r"2.68\%"]),
    ([0.026525, 0.026210, 0.026842, 0.026211, 0.026843], "percent", False,  # exact and Wilson bounds together
     [r"2.65\%", r"2.62\%", r"2.68\%", r"2.62\%", r"2.68\%"]),
    ([0.0152, 0.0150, 0.0154], "percent", True, [PLUS + r"1.52\%", PLUS + r"1.50\%", PLUS + r"1.54\%"]),  # a ratio minus 1
    ([0.5, 0.4999, 0.5002], "percent", False, [r"50.00\%", r"49.99\%", r"50.02\%"]),
    # a bound that differs from the estimate only by rounding noise (a t-interval over identical repetitions) is the
    # estimate: no decimals are spent on it
    ([0.05, 0.05 - 1e-17, 0.05 + 1e-17], "percent", False, [r"5.0\%", r"5.0\%", r"5.0\%"]),
    ([10000, 9990, 10010], "count", False, ["10{,}000", "9{,}990", "10{,}010"]),
    ([100.0, 99.93, 100.07], "PDU/s", False, ["100.0", "99.9", "100.1"]),
])
def test_an_estimate_and_its_bounds_share_their_decimals(values, unit, signed, want):
    assert make_numbers.fmt_together(values, unit, signed) == want


def test_one_rounding_for_every_fixed_point_print_in_keys_and_tables():
    """Every number the toolkit prints with a fixed number of decimals or significant digits, of every unit, in a key
    or in a table cell, goes through one function: decimal arithmetic, half to even, from the value at its twelve
    significant digits. So a table cell can never differ from the key beside it in its last digit. The binary value of
    2.675 lies below the tie and that of 1.015 as well: the float formats gave 2.67 and 1.01."""
    import random
    from analysis import tables
    assert tables.rounded(2.675, 2) == "2.68" and tables.rounded(1.015, 2) == "1.02" and tables.rounded(2.665, 2) == "2.66"
    assert tables.rounded(87.5, 0) == "88" and tables.rounded(86.5, 0) == "86" and tables.rounded(-0.0875, 3) == "-0.088"
    assert tables.rounded(0.1 + 0.2, 1) == "0.3" and tables.rounded(1e-9, 2) == "0.00" and tables.rounded(123456.5, 0) == "123456"
    assert tables.significant(1.015, 3) == "1.02" and tables.significant(0.0002675, 3) == "0.000268" and tables.significant(9.995, 3) == "10"
    assert tables.significant(1234.5, 4) == "1234" and tables.significant(0, 3) == "0" and tables.significant(2.5e-7, 1) == "2e-07"
    assert tables.rounded(5.246526672674447e-06, 35) == "0.00000524652667267000000000000000000"  # twelve digits, then zeros
    assert tables.rounded(float("nan"), 2) == "nan" and tables.rounded(float("inf"), 1, sign=True) == "+inf" and tables.sig(float("nan")) == "nan"
    # the keys, whatever the unit
    assert fmt(0.02675, "percent", decimals=2) == r"2.68\%" and fmt(1.015, "1", decimals=2) == "1.02" and fmt(2.675, "s", decimals=2) == "2.68"
    assert fmt(424.815, "us", decimals=2) == "424.82" and fmt(0.99995, "percent") == r"99.9950\%"
    # the table cells beside them
    assert tables.num(424.815) == "424.82" and tables.num(86.315) == "86.32" and tables.num(91.185) == "91.18" and tables.num(None) == tables.DASH
    assert tables.pct(0.02675) == "2.68%" and tables.sig(1.015) == "1.02" and tables.ci((86.315, 91.185)) == "[86.32, 91.18]"
    rng = random.Random(20261123)
    for _ in range(20000):
        ns = rng.randint(1, 30_000_000)
        us, d = ns / 1000, rng.randint(0, 3)
        assert tables.num(us, d) == fmt(us, "us", decimals=d).replace("{,}", ""), (us, d)             # a time cell and its key
        k, n = rng.randint(1, 999), rng.choice((1000, 8000, 99000, 999000))
        assert tables.rounded(100 * (k / n), d) + r"\%" == fmt(k / n, "percent", decimals=d), (k, n, d)  # a share and its key


def test_a_time_rounds_the_same_way_in_both_units():
    """A time is a whole (or half) number of nanoseconds, and its two keys print the same value in us and in ms. The
    print is rounded once, in decimal arithmetic, from that exact value: a tie in one unit is a tie in the other. The
    binary value of 87.5 us is exact and that of 0.0875 ms lies just below, which printed "88" and "0.087"."""
    import random
    assert (fmt(87.5, "us"), fmt(87.5 / 1000, "ms")) == ("88", "0.088")
    assert (fmt(86.5, "us"), fmt(86.5 / 1000, "ms")) == ("86", "0.086")            # a tie goes to the even digit, in both
    assert (fmt(1015.0, "us"), fmt(1.015, "ms")) == ("1{,}015", "1.02")           # 1.015 ms is a tie at two decimals
    assert (fmt(2.675, "us", decimals=2), fmt(0.002675, "ms", decimals=5)) == ("2.68", "0.00268")
    assert (fmt(1455.982, "us", decimals=1), fmt(1.455982, "ms", decimals=4)) == ("1{,}456.0", "1.4560")  # no tie: as before
    assert fmt(-0.0875, "ms", signed=True) == MINUS + "0.088" and fmt(0.0004, "ms", decimals=2) == "0.00"
    rng = random.Random(20261123)
    for _ in range(20000):
        half_ns = rng.randint(1, 60_000_000)  # up to 30 ms, in half nanoseconds
        us = half_ns / 2000
        for d in range(0, 4):  # the us print with d decimals and the ms print with d + 3 show the same digits
            a, b = fmt(us, "us", decimals=d).replace("{,}", ""), fmt(us / 1000, "ms", decimals=d + 3)
            assert a.replace(".", "").lstrip("0") == b.replace(".", "").lstrip("0"), (us, d, a, b)


def test_the_distance_to_a_bound_is_exact_to_the_nanosecond():
    """The decimals that show one significant digit of the smallest distance between an estimate and a bound, against
    exact arithmetic with fractions. Times are whole (or half) nanoseconds, so a distance of exactly 1, 10 or 100 ns is
    common, and 423.926 - 423.925 is 0.00099999999998 in floating point: it must count as 0.001 (three decimals), not
    as below it (four). Found on the verify median of the second E1 session, printed 423.9250 [423.9080, 423.9260]."""
    import random
    from fractions import Fraction
    assert make_numbers.shared_decimals([423.925, 423.908, 423.926], "us") == 3
    assert make_numbers.fmt_together([423.925, 423.908, 423.926], "us") == ["423.925", "423.908", "423.926"]
    assert make_numbers.fmt_together([0.423925, 0.423908, 0.42392599999999997], "ms") == ["0.423925", "0.423908", "0.423926"]
    assert make_numbers._distance(2.263, 2.262) == 0.001 and make_numbers._distance(5.0, 5.0) == 0 == make_numbers._distance(0, 0)

    def exponent(q):  # floor(log10(q)) of a positive fraction, by comparison
        e = 0
        while Fraction(10) ** e > q:
            e -= 1
        while Fraction(10) ** (e + 1) <= q:
            e += 1
        return e

    rng = random.Random(20261123)
    for _ in range(5000):
        est = rng.randint(600, 40_000_000)  # in half nanoseconds: 300 ns to 20 ms
        lo, hi = est - rng.choice((1, 2, 4, 10, 20, 34, 200, 2000, 20000)), est + rng.choice((1, 2, 6, 20, 200, 500, 2000))
        for unit, per in (("us", 2000), ("ms", 2_000_000)):
            values = [x / per for x in (est, lo, hi)]
            own = max(make_numbers._decimals(v, unit, False, scientific=False) for v in values)  # the unit's rule, not under test
            assert make_numbers.shared_decimals(values, unit) == max(own, -exponent(Fraction(min(est - lo, hi - est), per))), values


@pytest.mark.parametrize("k,want", [
    (26498, [r"2.65\%", r"2.62\%", r"2.68\%"]),          # 2.6525% [2.6210%, 2.6842%]
    (434, [r"0.043\%", r"0.039\%", r"0.048\%"]),         # 0.04344% [0.0394%, 0.0477%]
    (6, [r"0.00060\%", r"0.00022\%", r"0.00131\%"]),     # plain decimals, no power of ten
    (1, [r"0.0001001\%", r"0.0000025\%", r"0.0005577\%"]),  # the lower bound, 2.5e-8, sets the seven decimals
    (0, [r"0\%", r"0\%", r"0.00037\%"]),                # nothing above the threshold: 0% with the upper bound of zero
])
def test_exceedance_of_a_long_series_is_printed_with_the_decimals_its_interval_needs(k, want):
    """k of 999,000 calls above a threshold, with the exact interval."""
    lo, hi = stats.clopper_pearson_interval(k, 999_000)
    assert make_numbers.fmt_together([k / 999_000, lo, hi], "percent") == want


def test_a_non_finite_value_is_refused_with_its_own_message():
    item = {"key": "k", "group": "k", "value": float("nan"), "unit": "us", "signed": False, "decimals": None}
    with pytest.raises(ValueError, match="cannot format the non-finite value"):
        make_numbers.format_items([item])
    with pytest.raises(ValueError, match="cannot format the non-finite value"):
        make_numbers.format_items([{**item, "value": float("inf")}])


@pytest.mark.parametrize("signed", [False, True])
def test_only_an_exact_one_prints_as_100_percent(signed):
    """'100%' means n of n. Just below one the distance to it shows, just above one the excess, with or without a
    sign and for a value alone as for an estimate with bounds."""
    assert printed(fmt(1.0, "percent", signed)) == 100 and printed(fmt(-1.0, "percent", True)) == -100
    for k in [*range(-3000, 3001), -123456, 123457]:
        if k:
            v = 1 + k * 1e-6
            assert printed(fmt(v, "percent", signed)) != 100, v
            assert printed(fmt(-v, "percent", True)) != -100, v
            assert 100 not in map(printed, make_numbers.fmt_together([v, 0.5, 1.2], "percent", signed)), v
    assert fmt(0.9997, "percent", True) == PLUS + r"99.97\%" and fmt(1.0004, "percent", True) == PLUS + r"100.04\%"
    assert make_numbers.fmt_together([1.0004, 0.99, 1.01], "percent") == [r"100.04\%", r"99.00\%", r"101.00\%"]


def printed(tex):
    """The number a formatted value shows."""
    t = tex.replace("{,}", "").replace(r"\%", "")
    m = re.fullmatch(r"\\ensuremath\{([+-]?)([0-9.]+)\\times10\^\{(-?\d+)\}\}", t)
    if m:
        return float(m[1] + m[2]) * 10 ** int(m[3])
    return float(t.replace(PLUS, "+").replace(MINUS, "-"))


def test_print_keeps_an_estimate_inside_its_bounds(out):
    """Every estimate with bounds of the synthetic run, and two intervals as narrow as a long series gives (26,498 of
    999,000 calls above 5 ms; a median of 1,455.98 us with the interval 1,455.80 to 1,456.19): a bound never lands on
    the other side of its estimate in print, and a bound of a proportion or of a time that differs from its estimate
    in value differs from it in print."""
    results = copy.deepcopy(out[1]["results"])
    e = next(e for f in results["crypto_ops"] for o in f["ops"] for e in o.get("exceedance", []))
    e.update(k=26498, n=999_000, p=26498 / 999_000, cp95=list(stats.clopper_pearson_interval(26498, 999_000)),
             wilson95=list(stats.wilson_interval(26498, 999_000)))
    o = next(o for f in results["crypto_ops"] for o in f["ops"] if "bootstrap" in o)
    o["time_us"]["p50"], o["bootstrap"]["p50_ci95_us"] = 1455.982, [1455.796, 1456.185]
    groups = {}
    for i in make_numbers.collect(results):
        groups.setdefault(i["group"], []).append(i)
    checked = {}
    for group, members in groups.items():
        est = next((m for m in members if m["key"] == group), None)
        if est is None or len(members) < 2 or est["unit"] in ("p", "id"):
            continue
        checked[est["unit"]] = checked.get(est["unit"], 0) + 1
        for m in members:
            a, b, pa, pb = est["value"], m["value"], printed(est["formatted"]), printed(m["formatted"])
            assert not (a < b and pa > pb) and not (a > b and pa < pb), (est["key"], est["formatted"], m["key"], m["formatted"])
            if est["unit"] in ("percent", "us", "ms") and float(f"{a:.12g}") != float(f"{b:.12g}"):
                assert pa != pb, (est["key"], est["formatted"], m["key"], m["formatted"])
    assert checked["percent"] >= 40 and checked["us"] >= 8 and checked["ms"] >= 8  # the property was tried, not vacuous
    narrow = {m["key"].rsplit(".", 1)[-1]: m["formatted"] for members in groups.values() for m in members
              if m["value"] in (e["p"], *e["cp95"])}
    assert narrow == {"p": r"2.65\%", "cp95_lo": r"2.62\%", "cp95_hi": r"2.68\%"}
    by_key = {m["key"]: m for members in groups.values() for m in members}
    shown = {k: m["formatted"] for k, m in by_key.items()}
    base = next(k for k in groups if k.endswith("p50_us") and by_key[k]["value"] == 1455.982)[:-len("p50_us")]
    assert [shown[base + name] for name in ("p50_us", "p50_ci95_lo_us", "p50_ci95_hi_us")] == ["1{,}456.0", "1{,}455.8", "1{,}456.2"]
    assert [shown[base + name] for name in ("p50_ms", "p50_ci95_lo_ms", "p50_ci95_hi_ms")] == ["1.4560", "1.4558", "1.4562"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_non_finite_values_are_refused(value):
    with pytest.raises(ValueError):
        fmt(value, "us")


# ---- key scheme ----------------------------------------------------------------------------------

@pytest.mark.parametrize("kind,source,want", [
    ("crypto_ops", "crypto/crypto_ops.csv", ""), ("crypto_ops", "crypto_ops.csv", ""),
    ("crypto_ops", "crypto_ops/crypto_ops.csv", ""), ("crypto_ops", "crypto_1e6/crypto_ops.csv", "1e6"),
    ("crypto_ops", "sign_tail/crypto_ops.csv", "sign_tail"), ("crypto_ops", "crypto/crypto_ops_iris.csv", "iris"),
    ("crypto_ops", "crypto_1e6/crypto_ops_iris.csv", "1e6-iris"), ("crypto_ops", "a/b/crypto/crypto_ops.csv", ""),
    ("attack", "attack/attack.csv", ""), ("attack", "attack_mac/attack.csv", "mac"), ("attack", "attack/attack_raw.csv", ""),
    ("overhead_paired", "overhead/overhead_paired.csv", ""), ("handshake", "handshake-run2/handshake.csv", "run2"),
    ("crypto_ops", "perf/tx_perf_10k.csv", "perf"), ("overhead_unpaired", "perf/phase_compare.csv", "perf"),
])
def test_label_from_directory_and_file_name(kind, source, want):
    assert make_numbers.label(kind, source) == want


def test_periodic_config_id():
    r = {"period_us": 10_000.0, "deadline_us": 10_000.0, "streams": 4, "cores": 1, "profile": "mldsa65", "scheduler": "fifo"}
    assert make_numbers.config_id(r) == "p10ms-s4-c1-mldsa65-fifo"
    assert make_numbers.config_id({**r, "deadline_us": 5_000.0}) == "p10ms-d5ms-s4-c1-mldsa65-fifo"
    assert make_numbers.config_id({**r, "period_us": 2_500.0, "deadline_us": 2_500.0, "scheduler": "fifo_isolated"}) == \
        "p2500us-s4-c1-mldsa65-fifo_isolated"
    assert make_numbers.config_id({**r, "period_us": 0.5, "deadline_us": 0.5}) == "p500ns-s4-c1-mldsa65-fifo"
    # optional header keys join the id when the file has them, in this order
    bench = {**r, "mainfunction": "cyclic", "mf_period_us": 1000, "phase": "sync", "partition": 0}
    assert make_numbers.config_id(bench) == "p10ms-s4-c1-mldsa65-fifo-cyclic-mf1ms-sync-part0"
    assert make_numbers.config_id({**bench, "mainfunction": "event", "partition": 3}) == "p10ms-s4-c1-mldsa65-fifo-event-mf1ms-sync-part3"
    assert make_numbers.config_id({**r, "mf_period_us": 250, "phase": "staggered"}) == "p10ms-s4-c1-mldsa65-fifo-mf250us-staggered"


def test_throughput_ladder_id():
    t = {"profile": "mldsa65", "cores": 4}
    assert make_numbers.ladder_id(t) == "mldsa65-c4"
    assert make_numbers.ladder_id({**t, "mainfunction": "cyclic", "mf_period_us": 1000}) == "mldsa65-c4-cyclic-mf1ms"
    assert make_numbers.ladder_id({**t, "profile": "mac", "mainfunction": "event"}) == "mac-c4-event"


# ---- the generated files -------------------------------------------------------------------------

LINE = re.compile(r"\\expandafter\\def\\csname meas@(?P<key>[^\\]+)\\endcsname\{(?P<formatted>.*?)\}"
                  r"(?:\\expandafter\\def\\csname measraw@(?P<rawkey>[^\\]+)\\endcsname\{(?P<raw>[^{}]*)\})?% (?P<comment>.*)")


def suppressed(out_dir):
    """suppressed_keys.txt as {key: reason}."""
    lines = (Path(out_dir) / "suppressed_keys.txt").read_text().splitlines()
    return dict(ln.split("\t") for ln in lines if ln and not ln.startswith("#"))


def parse_tex(path):
    """LaTeX-free reading of numbers.tex: (definition rows, other lines). The pattern anchors on the
    \\measraw definition or on '}% ' with the comment, so a \\% inside a value is not mistaken for the
    trailing comment. The \\measraw part is absent for an underflowed p-value."""
    rows, other = [], []
    for line in Path(path).read_text().splitlines():
        m = LINE.fullmatch(line)
        (rows if m else other).append(m.groupdict() if m else line)
    return rows, other


@pytest.fixture(scope="module")
def out(tmp_path_factory):
    run_dir = synth.make_run(tmp_path_factory.mktemp("run"))
    out = tmp_path_factory.mktemp("out")
    summary = make_tables.run(run_dir, out, **PARAMS)
    return out, summary


@pytest.fixture(scope="module")
def table(out):
    with open(out[0] / "numbers.csv", newline="") as f:
        rows = list(csv.DictReader(f))
    return {r["key"]: r for r in rows}, rows


def test_every_key_exactly_once_and_tex_agrees_with_csv(out, table):
    by_key, csv_rows = table
    tex_rows, other = parse_tex(out[0] / "numbers.tex")
    keys = [r["key"] for r in tex_rows]
    held_back = suppressed(out[0])  # percentiles with fewer than ten samples above them: in the CSV, not in the .tex
    assert len(keys) == len(set(keys)) == out[1]["numbers"]["keys"] > 400 and len(keys) + len(held_back) == len(csv_rows)
    assert keys == sorted(keys) == [r["key"] for r in csv_rows if r["key"] not in held_back]
    assert list(csv_rows[0]) == ["key", "value", "formatted", "unit", "n", "source_file", "how"]
    commit = out[1]["toolkit_commit"]
    no_raw = [t["key"] for t in tex_rows if t["raw"] is None]
    assert no_raw == ["overhead_paired.verify.tost_p"]  # the one p-value of this run that underflowed to 0
    assert by_key[no_raw[0]]["value"] == "<1e-300" and by_key[no_raw[0]]["formatted"] == r"\ensuremath{<10^{-300}}"
    for t in tex_rows:
        c = by_key[t["key"]]
        assert t["formatted"] == c["formatted"]
        if t["raw"] is not None:
            assert t["rawkey"] == t["key"] and t["raw"] == c["value"]
            float(t["raw"])  # the raw value is a plain number
        assert all(make_numbers.SEGMENT.fullmatch(seg) for seg in t["key"].split("."))
        assert t["formatted"].count("{") == t["formatted"].count("}") and "nan" not in t["formatted"].lower()
        source, experiment, filt, n, toolkit = t["comment"].split(" | ")
        assert (source, n, toolkit) == (c["source_file"], f"n={c['n']}", f"toolkit {commit}") and experiment and filt
        assert c["n"] == "-" or int(c["n"]) >= 0
    # everything that is not a definition is a comment or one of the three macro definitions
    assert all(line.startswith(("%", r"\newcommand{\meas", "  {")) for line in other)
    text = (out[0] / "numbers.tex").read_text()
    assert text.count(r"\newcommand{\meas}[1]") == text.count(r"\newcommand{\measraw}[1]") == 1 and "PackageError" in text
    assert r"\num" not in text  # that name belongs to siunitx


def test_number_keys_file_lists_every_key_with_meaning_unit_and_source_but_no_value(out, table):
    """number_keys.md is for writing \\meas{key} into the manuscript before the data exist."""
    _, csv_rows = table
    lines = (out[0] / "number_keys.md").read_text().splitlines()
    assert lines[0] == f"# Number keys of run {out[1]['run_dir']}" and f"{len(csv_rows)} keys" in lines[2]
    assert out[1]["toolkit_commit"] in lines[2] and out[1]["numbers"]["files"] == ["numbers.tex", "numbers.csv", "number_keys.md", "suppressed_keys.txt"]
    head = lines.index("| key | meaning | unit | source file |")
    assert lines[head + 1] == "|---|---|---|---|" and len(lines) == head + 2 + len(csv_rows)  # the table ends the file
    for line, c in zip(lines[head + 2:], csv_rows):  # one row per key, in the order of numbers.csv
        key, meaning, unit, source = (cell.strip() for cell in re.split(r"(?<!\\)\|", line)[1:-1])
        assert (key, unit, source) == (f"`{c['key']}`", c["unit"], c["source_file"])
        assert meaning.startswith(c["how"].replace("|", "\\|")) and meaning.endswith(")")  # what it is, then the filter
    row = next(ln for ln in lines if ln.startswith("| `crypto_ops.mldsa_sign.mean_us` |"))
    assert row == "| `crypto_ops.mldsa_sign.mean_us` | mean of post-warm-up time (op=mldsa_sign, seq>=10) | us | crypto/crypto_ops.csv |"
    row = next(ln for ln in lines if ln.startswith("| `crypto_ops.mldsa_sign.p50_us` |"))  # listed, and marked as not defined
    assert row == ("| `crypto_ops.mldsa_sign.p50_us` | p50 of post-warm-up time, type-7 percentile (op=mldsa_sign, seq>=10) "
                   "(not in numbers.tex: fewer than 10 samples above it) | us | crypto/crypto_ops.csv |")
    assert "not results" not in "\n".join(lines[:head])  # this run is not marked


@pytest.mark.parametrize("stat,n,above", [
    ("p99.99", 100_000, None), ("p99.99", 99_999, "9.9999"), ("p99.99", 99_000, "9.9"),  # exact: 100000 x 0.0001 is 10, not 9.99...
    ("p99.9", 10_000, None), ("p99.9", 9_999, "9.999"), ("p99", 1_000, None), ("p99", 999, "9.99"),
    ("p90", 100, None), ("p90", 99, "9.9"), ("p50", 20, None), ("p50", 19, "9.5"),
    ("mean", 3, None), ("sd", 3, None), ("min", 3, None), ("max", 3, None)])  # not percentiles
def test_percentile_is_a_manuscript_number_only_with_ten_samples_above_it(stat, n, above):
    why = make_numbers.scarce(stat, n)
    assert (why is None) == (above is None)
    if above:
        assert why == (f"{stat} of {n} values: {above} samples lie above it, fewer than 10; the value depends on the "
                       "percentile definition")


@pytest.mark.parametrize("stat,n,below", [("p0.1", 10_000, None), ("p0.1", 9_999, "9.999"), ("p10", 100, None), ("p10", 99, "9.9")])
def test_low_percentile_needs_ten_samples_below_it(stat, n, below):
    """The rule mirrored for a percentile below the median: what makes it definition-dependent is the samples below it."""
    why = make_numbers.scarce(stat, n)
    assert (why is None) == (below is None)
    if below:
        assert why == (f"{stat} of {n} values: {below} samples lie below it, fewer than 10; the value depends on the "
                       "percentile definition")


def test_scarce_percentiles_stay_in_the_csv_and_out_of_the_tex(out, table):
    by_key, _ = table
    tex_keys = {r["key"] for r in parse_tex(out[0] / "numbers.tex")[0]}
    listed = suppressed(out[0])
    assert set(by_key) - tex_keys == set(listed) and tex_keys <= set(by_key)
    assert out[1]["numbers"]["suppressed"] == len(listed) > 50 and "suppressed_keys.txt" in out[1]["numbers"]["files"]
    # ten signing samples after the warm-up: no percentile has ten samples above it
    assert listed["crypto_ops.mldsa_sign.p50_us"] == ("p50 of 10 values: 5 samples lie above it, fewer than 10; the value "
                                                     "depends on the percentile definition")
    # an interval goes with its estimate; the mean, the extremes, counts and proportions are not percentiles
    assert {"crypto_ops.mldsa_sign.p99_ms", "crypto_ops.mldsa_sign.p50_ci95_lo_us", "crypto_ops.mldsa_sign.p99_ci95_hi_ms"} <= set(listed)
    assert {"crypto_ops.mldsa_sign.mean_us", "crypto_ops.mldsa_sign.max_us", "crypto_ops.mldsa_sign.n",
            "crypto_ops.mldsa_sign.exceed_5ms.p", "crypto_ops.mldsa_sign.exceed_5ms.cp95_hi"} <= tex_keys
    # a median is the 50th percentile wherever it appears: of 10 pairs, of 3 handshakes, of 2 clock probes;
    # the Hodges-Lehmann estimate is a location estimate over all pairs of pairs, not a sample percentile
    assert {"overhead_paired.sign.median_diff_us", "overhead_paired.sign.median_csm_ms", "overhead_paired.sign.median_ratio_diff",
            "overhead_paired.sign.order_median_diff_ab_us", "handshake.iris.initiator.bytes_tx_median",
            CONFIG + ".clock_rtt_median_us"} <= set(listed)
    assert listed["handshake.iris.initiator.bytes_tx_median"].startswith("p50 of 3 values: 1.5 samples lie above it")
    assert {"overhead_paired.sign.hl_us", "overhead_paired.sign.hl_ci95_lo_us", "handshake.iris.initiator.bytes_tx_max"} <= tex_keys
    # 24 response times: the median has 12 above it and stays, p90 has 2.4 and goes
    assert CONFIG + ".response_p50_us" in tex_keys and "2.4 samples" in listed[CONFIG + ".response_p90_us"]
    # cyclictest percentiles are read from a histogram and follow the same rule: 1000 wake-ups
    assert "cyclictest.fifo-cpu3.p99_us" in tex_keys and "cyclictest.fifo-cpu3.p99_9_us" in listed
    text = (out[0] / "numbers.tex").read_text()
    assert f"% {len(listed)} more keys are in numbers.csv only: suppressed_keys.txt says why" in text
    assert (out[0] / "suppressed_keys.txt").read_text().startswith("# keys of numbers.csv that numbers.tex does not define")


def test_selected_values_from_the_hand_computed_run(table):
    f = {k: r["formatted"] for k, r in table[0].items()}
    assert (f["crypto_ops.mldsa_sign.p50_us"], f["crypto_ops.mldsa_sign.p50_ms"]) == ("5{,}500", "5.50")
    assert (f["crypto_ops.mldsa_sign.n"], f["crypto_ops.mldsa_sign.exceed_5ms.k"]) == ("10", "5")
    assert f["crypto_ops.mldsa_sign.exceed_5ms.p"] == r"50\%" and f["crypto_ops.mldsa_sign.exceed_10ms.p"] == r"0\%"
    assert (f["overhead_paired.sign.hl_us"], f["overhead_paired.sign.hl_ci95_lo_us"], f["overhead_paired.sign.hl_ci95_hi_us"]) == \
        (PLUS + "0.20", PLUS + "0.10", PLUS + "0.30")
    assert f["overhead_paired.sign.tost_margin"] == r"1.0\%" and f["overhead_paired.sign.gm_ratio_diff"] == PLUS + r"0.020\%"
    assert f["overhead_paired.sign.order_hl_us"] == PLUS + "0.20" and f["overhead_paired.sign.n_dropped"] == "10"
    # 3 of 24 with its exact [2.66%, 32.4%] and Wilson [4.34%, 31.0%] bounds: one decimal for all five
    assert (f[CONFIG + ".misses"], f[CONFIG + ".miss_ratio"]) == ("3", r"12.5\%")
    assert (f[CONFIG + ".miss_wilson95_lo"], f[CONFIG + ".miss_wilson95_hi"]) == (r"4.3\%", r"31.0\%")
    assert (f[CONFIG + ".miss_cp95_lo"], f[CONFIG + ".miss_cp95_hi"]) == (r"2.7\%", r"32.4\%")
    assert (f["crypto_ops.mldsa_sign.exceed_5ms.cp95_lo"], f["crypto_ops.mldsa_sign.exceed_5ms.cp95_hi"]) == (r"19\%", r"81\%")
    assert (f["attack.benign.false_rejection_rate"], f["attack.benign.false_rejection_cp95_lo"],
            f["attack.benign.false_rejection_cp95_hi"]) == (r"0\%", r"0\%", r"7.1\%")  # none rejected: an exact zero is 0%
    assert f[CONFIG + ".rx_reject_auth_fail_n"] == "0" and CONFIG + ".rx_reject_auth_fail_p50_us" not in f  # nothing rejected
    assert (f[CONFIG + ".response_max_ms"], f[CONFIG + ".s0.misses"], f[CONFIG + ".s1.misses"]) == ("13.00", "3", "0")
    assert (f[CONFIG + ".rx_delivered"], f[CONFIG + ".rx_lost"], f[CONFIG + ".rx_result_auth_fail"]) == ("23", "1", "0")
    assert (f[CONFIG + ".rx_verify_p50_us"], f[CONFIG + ".latency_p50_us"], f[CONFIG + ".end_to_end_max_ms"]) == ("430", "500", "13.95")
    assert f[CONFIG + ".model_utilisation"] == r"40\%" and f[CONFIG + ".model_measured_offsets"] == r"0\%"
    assert f["throughput.mldsa65-c1.saturation_pps"] == "100"
    assert (f["throughput.mldsa65-c1.r200.tx.drop_ratio"], f["throughput.mldsa65-c1.r200.tx.cpu_util"]) == (r"25\%", r"99.0\%")
    # loss of the step: 450 of 1800 with its exact [23.0%, 27.1%]; and 0 of 900 with [0, 0.41%]
    assert (f["throughput.mldsa65-c1.r200.lost_pdus"], f["throughput.mldsa65-c1.r200.offered_pdus"]) == ("450", "1{,}800")
    assert (f["throughput.mldsa65-c1.r200.loss_ratio"], f["throughput.mldsa65-c1.r200.loss_cp95_lo"],
            f["throughput.mldsa65-c1.r200.loss_cp95_hi"]) == (r"25\%", r"23\%", r"27\%")
    assert (f["throughput.mldsa65-c1.r100.loss_ratio"], f["throughput.mldsa65-c1.r100.loss_cp95_hi"]) == (r"0\%", r"0.41\%")
    # beside it the transmitter's own share: releases dropped at a full queue, 450 of the 1800 offered, and none at 100
    assert (f["throughput.mldsa65-c1.r200.dropped_pdus"], f["throughput.mldsa65-c1.r200.tx_drop_ratio_mean"],
            f["throughput.mldsa65-c1.r100.tx_drop_ratio_max"]) == ("450", r"25\%", r"0\%")
    how = {k: r["how"] for k, r in table[0].items()}
    assert "dropped at release" in how["throughput.mldsa65-c1.r200.tx_drop_ratio_mean"] and "inside the window" in how["throughput.mldsa65-c1.r200.dropped_pdus"]
    assert "not delivered inside the window" in how["throughput.mldsa65-c1.r200.loss_ratio"] and "not delivered inside the window" in how["throughput.mldsa65-c1.r200.lost_pdus"]
    # no key text of a ladder calls them lost PDUs any more (the one mention says what the figure is not)
    assert not [k for k, text in how.items() if k.startswith("throughput.") and re.search(
        r"PDUs lost,|lost / offered|lost PDUs|could not enqueue", text)]
    assert (f["throughput.mldsa65-c1.loss_max"], f["throughput.mldsa65-c1.r100.n_reps"], f["throughput.mldsa65-c1.r100.sustained_reps"],
            f["throughput.mldsa65-c1.r200.sustained_reps"]) == (r"0.10\%", "1", "1", "0")
    # across repetitions (here one): the same key shape whatever their number; no interval from a single repetition
    assert (f["throughput.mldsa65-c1.r200.delivered_pps_mean"], f["throughput.mldsa65-c1.r200.delivered_pps_max"],
            f["throughput.mldsa65-c1.r200.loss_ratio_mean"], f["throughput.mldsa65-c1.r200.tx_cpu_util_mean"]) == \
        ("150", "150", r"25\%", r"99.0\%")
    assert (f["throughput.mldsa65-c1.r200.sendq_slope_bytes_per_s_mean"], f["throughput.mldsa65-c1.r100.sendq_max_bytes_max"]) == \
        (PLUS + "10{,}000", "8{,}000")
    assert "throughput.mldsa65-c1.r200.delivered_pps_t95_lo" not in f and "throughput.mldsa65-c1.r100.rx.delivered_ratio" not in f
    assert f["throughput.mldsa65-c1.r100.tx.wire_bytes_per_pdu"] == "3{,}400"
    assert (f["attack.replay.rejection_rate"], f["attack.replay.rejection_cp95_lo"]) == (r"100\%", r"83\%")
    assert (f["attack.bitflip.auth.count"], f["attack.replay.auth.count"], f["attack.replay.auth.cp95_hi"]) == ("9", "0", r"17\%")
    assert f["attack.benign.false_rejection_cp95_onesided_hi"] == r"5.8\%"
    assert (f["cyclictest.fifo-cpu3.max_us"], f["cyclictest.fifo-cpu3.p99_9_us"], f["cyclictest.fifo-cpu3.samples"]) == \
        ("40", "10", "1{,}000")
    # latencies read from a 1 us histogram are whole microseconds and print as integers; the histogram mean keeps a decimal
    assert (f["cyclictest.fifo-cpu3.min_us"], f["cyclictest.fifo-cpu3.avg_us"], f["cyclictest.fifo-cpu3.p99_us"],
            f["cyclictest.fifo-cpu3.mean_us"], f["cyclictest.fifo-cpu3.min_ms"]) == ("3", "4", "6", "4.1", "0.0030")
    raw = {k: r["value"] for k, r in table[0].items()}
    assert (raw["cyclictest.fifo-cpu3.min_us"], raw["cyclictest.fifo-cpu3.max_us"]) == ("3", "40")
    assert (raw["cyclictest.other-cpu3.late_over_100us.k"], raw["cyclictest.other-cpu3.late_over_1ms.k"],
            raw["cyclictest.fifo-cpu3.late_over_100us.k"], table[0]["cyclictest.other-cpu3.late_over_100us.k"]["n"]) == ("10", "0", "0", "1000")
    assert (f["cyclictest.other-cpu3.max_us"], f["cyclictest.other-cpu3.max_ms"], f["cyclictest.other-cpu3.p99_us"]) == \
        ("300", "0.30", "55")
    assert (f["crypto_ops.cpu_share"], f["overhead_paired.cpu_share"]) == ("1.00", "1.00")
    assert (f["handshake.iris.initiator.total_p50_ms"], f["handshake.iris.initiator.failed"], f["handshake.iris.initiator.bytes_tx_median"]) == \
        ("2.00", "1", "3{,}000")


def test_figures_derived_for_the_letter_have_keys_that_say_what_they_assume(table):
    """Keys asked for on 2026-11-25: none is a measurement on its own, each is formed from figures that are, and the
    name or the definition says what is assumed."""
    f = {k: r["formatted"] for k, r in table[0].items()}
    how = {k: r["how"] for k, r in table[0].items()}
    # handshake: the mean own computation of a role over 1,000 PDUs of a session, and both roles added (771 and 576 us)
    ini, rsp, both = (f"handshake.{who}.compute_mean_per_pdu_session1000_us" for who in ("iris.initiator", "iris.responder", "both_roles"))
    assert (float(table[0][ini]["value"]), float(table[0][rsp]["value"]), float(table[0][both]["value"])) == \
        pytest.approx((0.771, 0.576, 1.347))
    assert "1,000 PDUs" in how[ini] and "assumption" in how[ini] and "mean" in how[both] and "both roles" in how[both]
    # signing series: adjacent pairs above a threshold beside what independence would give, and the squared share
    sign = "crypto_ops.mldsa_sign.exceed_5ms."
    assert (f[sign + "adjacent_pairs.k"], f[sign + "adjacent_pairs_if_independent"], f[sign + "p_squared_estimate"]) == ("4", "2.25", r"25\%")
    assert "independent" in how[sign + "p_squared_estimate"] and "estimate" in how[sign + "p_squared_estimate"]
    assert "(n - 1)" in how[sign + "adjacent_pairs_if_independent"]
    # counting run: measured upper percentiles of the processor time, what line and law imply, and the label of a
    # geometric share that lies beyond the data
    attrib = "crypto_attrib.sign_attrib_p8."
    law = attrib + "line_and_law."
    assert (f[law + "p50_cpu_us"], f[law + "p99_cpu_us"], f[law + "p99_9_cpu_us"]) == ("600", "2{,}600", "3{,}600")
    assert (f[law + "p50_rounds"], f[law + "p99_rounds"], f[law + "p99_9_rounds"]) == ("2", "10", "14")
    assert "not a measurement" in how[law + "p99_cpu_us"] and "geometric law" in how[law + "p99_rounds"]
    assert float(table[0][attrib + "cpu_p99_us"]["value"]) == pytest.approx(4435) and attrib + "cpu_p99_9_us" in f
    assert float(table[0][attrib + "rounds_at_least_threshold_10ms.share_geometric_extrapolation"]["value"]) == \
        pytest.approx(float(table[0][attrib + "rounds_at_least_threshold_10ms.share_geometric"]["value"]))
    assert attrib + "rounds_at_least_threshold_5ms.share_geometric_extrapolation" not in f  # 20 rounds were measured
    assert "beyond" in how[attrib + "rounds_at_least_threshold_10ms.share_geometric_extrapolation"]
    # ladder: the fitted growth of the send queue over the window, per repetition and the largest of a step
    assert f["throughput.mldsa65-c1.r200.tx.sendq_growth_bytes"] == PLUS + "90{,}000"
    assert f["throughput.mldsa65-c1.r200.sendq_growth_bytes_max"] == PLUS + "90{,}000" and "window" in how["throughput.mldsa65-c1.r200.tx.sendq_growth_bytes"]


def test_handshake_compute_time_and_header_numbers(table):
    f = {k: r["formatted"] for k, r in table[0].items()}
    assert (f["handshake.iris.initiator.compute_p50_us"], f["handshake.iris.initiator.compute_max_ms"], f["handshake.iris.responder.compute_mean_us"]) == \
        ("771", "0.87", "576")
    assert (f["handshake.iris.initiator.hash_p50_us"], f["handshake.iris.responder.mac_p50_us"]) == ("15", "5.0")
    assert (f["handshake.iris.header.mf_period_us"], f["handshake.iris.header.t_min_ms"]) == ("1{,}000", "0")
    assert table[0]["handshake.iris.initiator.compute_p50_us"]["n"] == "3" and "handshake.iris.header.mainfunction" not in f  # text


def test_time_off_the_processor_and_time_above_ten_milliseconds(out, table):
    """From the footer: wall_s - cpu_s (18.608 - 18.612 in the synthetic files). From the signing samples: the time
    beyond 10 ms in the calls above 10 ms (none here)."""
    f, n = {k: r["formatted"] for k, r in table[0].items()}, {k: r["value"] for k, r in table[0].items()}
    assert float(n["crypto_ops.header.off_cpu_s"]) == pytest.approx(-0.004) and "overhead_paired.header.off_cpu_s" in n
    assert (float(n["crypto_ops.mldsa_sign.excess_over_10ms_s"]), n["crypto_ops.mldsa_sign.excess_over_10ms_calls"]) == (0, "0")
    assert "crypto_ops.mldsa_verify.excess_over_10ms_s" not in n
    md = (out[0] / "tables" / "sign_excess.md").read_text()
    assert "| crypto/crypto_ops.csv | mldsa_sign | 10 | 18.608 | 18.612 | -0.004 | 0 | 0.000000 |" in md


def test_sign_attrib_keys_are_the_ones_the_manuscript_uses(out, table):
    """Base crypto_attrib.sign_attrib_p8 (directory, then the file name), for the synthetic counting run."""
    f, n = {k: r["formatted"] for k, r in table[0].items()}, {k: r["value"] for k, r in table[0].items()}
    b = "crypto_attrib.sign_attrib_p8."
    assert (n[b + "n"], n[b + "n_total"], n[b + "n_dropped"]) == ("20", "30", "10")
    assert float(n[b + "off_total_s"]) == pytest.approx(0.013184) and (n[b + "off_max_us"], f[b + "off_max_ms"]) == ("7000.0", "7.00")
    assert (n[b + "off_over_100us.k"], n[b + "off_over_1ms.k"], n[b + "off_over_5ms.k"]) == ("3", "2", "2")
    assert (n[b + "off_min_us"], n[b + "off_median_us"]) == ("2.0", "2.0")
    assert (n[b + "off_above_floor.k"], float(n[b + "off_above_floor_s"])) == ("3", pytest.approx(0.013144))
    assert (n[b + "wall_over_5ms.calls_with_rounds_min_or_more"], n[b + "wall_over_10ms.calls_with_rounds_min_or_more"]) == ("20", "1")
    assert b + "wall_over_20ms.calls_with_rounds_min_or_more" not in n
    # the plain sum of wall - cpu stays in the CSV for the record and is not a manuscript number
    tex_keys = {r["key"] for r in parse_tex(out[0] / "numbers.tex")[0]}
    assert b + "off_total_s" in n and b + "off_total_s" not in tex_keys and b + "off_above_floor_s" in tex_keys
    assert suppressed(out[0])[b + "off_total_s"] == "includes the per-call clock-read floor; not a time off the processor"
    keys_md = (out[0] / "number_keys.md").read_text()
    assert ("off_total_s` | sum over the calls of wall_ns - cpu_ns (seq>=10) (not in numbers.tex: includes the per-call "
            "clock-read floor; not a time off the processor) | s |") in keys_md
    assert "resid_p0_1_us` | " in keys_md and "(not in numbers.tex: fewer than 10 samples below it)" in keys_md
    assert (n[b + "wall_over_5ms.k"], n[b + "cpu_over_5ms.k"], n[b + "wall_over_5ms.max_off_us"], n[b + "wall_over_5ms.rounds_min"]) == \
        ("2", "1", "7000.0", "1")
    assert (n[b + "wall_over_10ms.k"], n[b + "cpu_over_10ms.k"], n[b + "wall_over_10ms.rounds_min"]) == ("1", "0", "20")
    assert (n[b + "wall_over_20ms.k"], n[b + "cpu_over_20ms.k"]) == ("0", "0")
    assert b + "wall_over_20ms.max_off_us" not in n and b + "wall_over_20ms.rounds_min" not in n  # no call above 20 ms
    # of the calls above t in wall time, those above t in processor time too (the same value here as cpu_over_<t>ms.k,
    # the calls with processor time above t whatever their wall time)
    assert (n[b + "wall_over_5ms.cpu_also_over"], n[b + "wall_over_10ms.cpu_also_over"], n[b + "wall_over_20ms.cpu_also_over"]) == ("1", "0", "0")
    assert "wall time and processor time both above 5 ms" in table[0][b + "wall_over_5ms.cpu_also_over"]["how"]
    assert table[0][b + "cpu_over_5ms.k"]["how"].startswith("calls with processor time above 5 ms (instrumented run")
    # the fewest rounds among the calls with processor time above t; no key when no call is above t
    assert (n[b + "cpu_over_5ms.rounds_min"], n[b + "cpu_over_5ms.calls_with_rounds_min_or_more"]) == ("20", "1")
    assert b + "cpu_over_10ms.rounds_min" not in n and b + "cpu_over_10ms.calls_with_rounds_min_or_more" not in n
    # the two-by-two against the line 100 + 250 us per round: the cells exist for every threshold, zeros included
    assert [n[b + f"rounds_threshold_{t}ms"] for t in (5, 10, 15, 20)] == ["20", "40", "60", "80"]
    assert [n[b + f"cpu_vs_rounds_5ms.{c}"] for c in ("both", "cpu_only", "rounds_only", "neither")] == ["1", "0", "0", "19"]
    assert [n[b + f"cpu_vs_rounds_20ms.{c}"] for c in ("both", "cpu_only", "rounds_only", "neither")] == ["0", "0", "0", "20"]
    assert "instrumented run" in table[0][b + "rounds_threshold_10ms"]["how"] and "instrumented run" in table[0][b + "cpu_vs_rounds_10ms.both"]["how"]
    assert "40" not in table[0][b + "cpu_vs_rounds_10ms.both"]["how"]  # the text names rounds_threshold_10ms, not its value
    # the off-diagonal calls beyond the round where the line crosses t
    assert (n[b + "cpu_vs_rounds_5ms.cpu_only_below_crossing"], n[b + "cpu_vs_rounds_5ms.rounds_only_above_crossing"]) == ("0", "0")
    assert table[0][b + "cpu_vs_rounds_5ms.cpu_only_below_crossing"]["how"].startswith(
        "calls with processor time above 5 ms and fewer than rounds_threshold_5ms - 1 rounds")
    assert table[0][b + "cpu_vs_rounds_5ms.rounds_only_above_crossing"]["how"].startswith(
        "calls with processor time not above 5 ms and more than rounds_threshold_5ms rounds")
    # shares: processor time above t; at least rounds_threshold rounds, measured and under a geometric law (0.6^19, 0.6^39)
    lo, hi = sps.binomtest(1, 20).proportion_ci(0.95, method="exact")
    # the share is printed with the decimals its bounds need (0.13% has two), as every estimate with an interval
    assert (n[b + "cpu_over_5ms.share"], f[b + "cpu_over_5ms.share"]) == ("0.05", r"5.00\%")
    assert (f[b + "cpu_over_5ms.share_cp95_lo"], f[b + "cpu_over_5ms.share_cp95_hi"]) == (r"0.13\%", r"24.87\%")
    assert (float(n[b + "cpu_over_5ms.share_cp95_lo"]), float(n[b + "cpu_over_5ms.share_cp95_hi"])) == pytest.approx((lo, hi))
    assert float(n[b + "cpu_over_20ms.share"]) == 0 and float(n[b + "cpu_over_20ms.share_cp95_lo"]) == 0
    at = b + "rounds_at_least_threshold_5ms."
    assert (n[at + "k"], n[at + "share"]) == ("1", "0.05")
    assert (float(n[at + "share_cp95_lo"]), float(n[at + "share_cp95_hi"])) == pytest.approx((lo, hi))
    assert float(n[at + "share_geometric"]) == pytest.approx(0.6 ** 19)
    assert float(n[b + "rounds_at_least_threshold_10ms.share_geometric"]) == pytest.approx(0.6 ** 39) and n[b + "rounds_at_least_threshold_20ms.k"] == "0"
    assert "independent calls assumed" in table[0][b + "cpu_over_5ms.share_cp95_lo"]["how"]
    assert "independent calls assumed" in table[0][at + "share_cp95_hi"]["how"]
    assert table[0][at + "share_geometric"]["how"].startswith("(1 - rounds_one_share)^(rounds_threshold_5ms - 1)")
    # its bounds: the formula at the exact bounds of the one-round share (8 of 20), the threshold of 20 rounds as given
    p_lo, p_hi = sps.binomtest(8, 20).proportion_ci(0.95, method="exact")
    assert (float(n[b + "rounds_one_share_cp95_lo"]), float(n[b + "rounds_one_share_cp95_hi"])) == pytest.approx((p_lo, p_hi))
    # the one-round share and its bounds are printed with one decimal (the text sets it next to a value from the
    # standard), the two mean numbers of rounds with two
    assert (f[b + "rounds_one_share"], f[b + "rounds_one_share_cp95_lo"], f[b + "rounds_one_share_cp95_hi"]) == (r"40.0\%", r"19.1\%", r"63.9\%")
    assert (f[b + "rounds_mean"], f[b + "rounds_mean_geometric"]) == ("3.05", "2.50")
    # ... whatever their size: three significant digits would print 12.3 and 10.4; and a share below 1% keeps the two
    # decimals the percentage rule gives it and its bounds (one decimal is the least, not a cut)
    other = copy.deepcopy(out[1]["results"])
    other["sign_attrib"][0]["rounds"].update(mean=12.345, geometric_mean=10.4, one_share=0.0095, one_share_cp95=[0.0082, 0.0110])
    shown = {i["key"]: i["formatted"] for i in make_numbers.collect(other)}
    # 12.345 is a tie at two decimals: half to even, whatever the unit (the binary value lies above it and gave 12.35)
    assert (shown[b + "rounds_mean"], shown[b + "rounds_mean_geometric"]) == ("12.34", "10.40")
    assert (shown[b + "rounds_one_share"], shown[b + "rounds_one_share_cp95_lo"], shown[b + "rounds_one_share_cp95_hi"]) == \
        (r"0.95\%", r"0.82\%", r"1.10\%")
    assert (float(n[at + "share_geometric_lo"]), float(n[at + "share_geometric_hi"])) == pytest.approx(((1 - p_hi) ** 19, (1 - p_lo) ** 19))
    assert table[0][at + "share_geometric_lo"]["how"].startswith(
        "from the exact interval of the one-round share; the rounds threshold is taken as given")
    assert table[0][at + "share_geometric_hi"]["how"].endswith("upper bound")
    assert (n[b + "rounds_mean"], n[b + "rounds_one_share"], n[b + "rounds_max"], n[b + "rounds_mean_geometric"]) == ("3.05", "0.4", "20", "2.5")
    assert (float(n[b + "cpu_per_round_us"]), float(n[b + "cpu_intercept_us"]), float(n[b + "r2"])) == pytest.approx((250, 100, 1))
    assert {b + "resid_sd_us", b + "resid_min_us", b + "resid_max_us", b + "resid_p0_1_us", b + "resid_p99_9_us"} <= set(n)
    assert "instrumented run" in table[0][b + "cpu_per_round_us"]["how"]
    # 20 residuals: 0.02 samples lie beyond either percentile, so neither is a manuscript number
    held_back = suppressed(out[0])
    assert held_back[b + "resid_p99_9_us"].startswith("p99.9 of 20 values: 0.02 samples lie above it")
    assert held_back[b + "resid_p0_1_us"].startswith("p0.1 of 20 values: 0.02 samples lie below it")
    assert b + "resid_sd_us" not in held_back and b + "resid_max_us" not in held_back
    assert (n[b + "header.shake_calls_min"], n[b + "header.shake_calls_step"]) == ("5", "3") and b + "cpu_share" in n
    assert float(n[b + "header.off_cpu_s"]) == pytest.approx(0.00015)
    # median and mean of wall time and of processor time (602 and 1521.7 us; 600 and 862.5 us, by hand in test_experiments)
    assert (n[b + "wall_p50_us"], n[b + "cpu_p50_us"], n[b + "cpu_mean_us"]) == ("602.0", "600.0", "862.5")
    assert float(n[b + "wall_mean_us"]) == pytest.approx(1521.7) and float(n[b + "wall_p50_ms"]) == pytest.approx(0.602)
    assert (f[b + "wall_p50_us"], f[b + "wall_p50_ms"], f[b + "cpu_mean_us"], f[b + "cpu_mean_ms"]) == ("602", "0.60", "862", "0.86")
    for key, what in (("wall_p50_us", "median wall time of a signing call, type-7 percentile"), ("cpu_mean_ms", "mean processor time of a signing call")):
        assert table[0][b + key]["how"] == what + " (instrumented run: the times include the counting)" and table[0][b + key]["n"] == "20"
    assert b + "wall_p50_us" not in held_back and b + "cpu_p50_ms" not in held_back  # 20 values: ten lie above the median
    # the two medians carry the interval of the E1 median, with its key suffixes; the means have none
    for which in ("wall", "cpu"):
        lo, mid, hi = (float(n[b + f"{which}_p50{part}_us"]) for part in ("_ci95_lo", "", "_ci95_hi"))
        assert lo <= mid <= hi and float(n[b + f"{which}_p50_ci95_hi_ms"]) == pytest.approx(hi / 1000)
        assert table[0][b + f"{which}_p50_ci95_lo_us"]["how"].startswith(f"moving-block bootstrap 95% CI of the median {'wall' if which == 'wall' else 'processor'} time")
        assert "(block 5, 50 replicates)" in table[0][b + f"{which}_p50_ci95_lo_us"]["how"] and "instrumented run" in table[0][b + f"{which}_p50_ci95_hi_ms"]["how"]
        assert b + f"{which}_mean_ci95_lo_us" not in n
    # above the median: none of the wall time; of the processor time p99 and p99.9 (since 2026-11-25, to stand beside
    # what line and law imply), held back here because 20 values leave 0.2 and 0.02 samples above them
    assert not [k for k in n if k.startswith(b) and re.search(r"wall_p(9|99)", k)]
    assert sorted(k.removeprefix(b) for k in n if k.startswith(b) and re.search(r"cpu_p(9|99)", k)) == \
        ["cpu_p99_9_ms", "cpu_p99_9_us", "cpu_p99_ms", "cpu_p99_us"] and held_back[b + "cpu_p99_us"].startswith("p99 of 20 values")


def test_sample_size_is_the_one_behind_each_statistic(table):
    n = {k: r["n"] for k, r in table[0].items()}
    assert (n["attack.bitflip.n"], n["attack.bitflip.detect_p50_us"]) == ("10", "9")  # all PDUs vs rejected ones
    assert (n["handshake.iris.initiator.n"], n["handshake.iris.initiator.total_p50_us"]) == ("4", "3")  # attempts vs successes
    assert (n[CONFIG + ".miss_ratio"], n[CONFIG + ".latency_p50_us"], n[CONFIG + ".s0.misses"]) == ("24", "23", "12")
    assert n["crypto_ops.mldsa_sign.p50_us"] == "10" and n["crypto_ops.mldsa_sign.n_dropped"] == "20"


def test_values_the_run_does_not_have_get_no_macro(table):
    keys = set(table[0])
    assert "overhead_paired.verify.wilcoxon_p" not in keys and "overhead_paired.sign.wilcoxon_p" in keys  # undefined: all zero
    assert "overhead_paired.verify.order_p" not in keys
    single = "periodic.p10ms-s1-c1-mldsa65-fifo"  # this configuration has no Rx file
    assert single + ".miss_ratio" in keys and not [k for k in keys if k.startswith(single) and ".rx_" in k]
    assert not [k for k in keys if k.startswith(single) and ("latency" in k or "end_to_end" in k)]
    assert "handshake.iris.initiator.encaps_p50_us" not in keys and "handshake.iris.responder.encaps_p50_us" in keys  # unused phase
    assert CONFIG + ".max_misses_in_10" in keys and CONFIG + ".max_misses_in_100" not in keys  # fewer than 100 jobs
    assert "attack.replay.auth.detect_p50_us" not in keys  # nothing was rejected at that stage
    assert not [k for k in keys if k.startswith("overhead_unpaired")]  # no legacy file in this run


def test_duplicate_keys_stop_the_run_before_anything_is_written(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "crypto_ops").mkdir()
    (run_dir / "crypto_ops" / "crypto_ops.csv").write_text(synth.crypto_ops())  # same key part as crypto/crypto_ops.csv
    with pytest.raises(ValueError, match=r"duplicate number key 'crypto_ops\.[\w.]+' from crypto/crypto_ops\.csv "
                                         r"and crypto_ops/crypto_ops\.csv"):
        make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert not (tmp_path / "out").exists()
    (run_dir / "crypto_ops").rename(run_dir / "crypto_host2")  # a distinct directory name resolves it
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    keys = [i["key"] for i in make_numbers.collect(s["results"])]
    assert "crypto_ops.mldsa_sign.p50_us" in keys and "crypto_ops.host2.mldsa_sign.p50_us" in keys


def test_repeated_periodic_configuration_needs_a_file_label(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "periodic_again").mkdir()
    (run_dir / "periodic_again" / "periodic_tx.csv").write_text(synth.periodic_tx_two_streams())  # same header as periodic_2s
    with pytest.raises(ValueError, match=r"duplicate number key 'periodic\.p10ms-s2-c1-mldsa65-fifo\.\w+' from "
                                         r"periodic_2s/periodic_tx\.csv and periodic_again/periodic_tx\.csv: .*periodic_tx_<label>\.csv"):
        make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert not (tmp_path / "out").exists()
    (run_dir / "periodic_again" / "periodic_tx.csv").rename(run_dir / "periodic_again" / "periodic_tx_rep2.csv")
    (run_dir / "periodic_again" / "periodic_rx_rep2.csv").write_text(synth.periodic_rx_two_streams())
    keys = {i["key"] for i in make_numbers.collect(make_tables.run(run_dir, tmp_path / "out", **PARAMS)["results"])}
    assert {CONFIG + ".miss_ratio", "periodic.rep2.p10ms-s2-c1-mldsa65-fifo.miss_ratio",
            "periodic.rep2.p10ms-s2-c1-mldsa65-fifo.rx_delivered"} <= keys


def test_two_throughput_ladders_with_one_id_are_refused(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "throughput_repeat").mkdir()
    for host in ("iris", "baolong"):
        (run_dir / "throughput_repeat" / f"throughput_{host}_100.csv").write_text(synth.throughput(host, 100))
    with pytest.raises(ValueError, match=r"duplicate number key 'throughput\.mldsa65-c1\.\w+' from throughput_1core and "
                                         r"throughput_repeat: .*one ladder per id"):
        make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert not (tmp_path / "out").exists()


SUMMARY_ONLY = [  # numeric fields of summary.json that deliberately have no macro (README.md, "Not in numbers.tex")
    r"\.(cv|lag1)$",                                  # reported for crypto_ops only (matched there by value)
    r"\.warmup$", r"\.trim$", r"\.bootstrap\.(block_len|n_boot)$",  # run parameters: run.warmup, run.trim, ...
    r"\.model\.(jobs_per_run|random_offsets\.draws|\w+\.runs|measured_offsets\.jobs_per_run)$",
    r"\.threshold_ms$", r"\.offered_pps$",             # part of the key
    r"\.tost_\w+(\[\])?\.(alpha|ci_level|df|margin)$", r"overhead_paired\[\]\.margin$",  # test constants; margin is tost_margin
    r"\.by_stage\.none$",                             # n - rejected
    r"\.failures\.\w+$",                              # same counts as results.<label>
    r"\.steps\[\]\.delivered_pps$",                   # the mean over repetitions: across.delivered_pps.mean
    r"\.across\.\w+\.n$",                              # repetitions behind an across-repetition value: the n column
    r"\.loss_max$",                                    # matched by value (0.001) only by accident: it has a key
    r"\.range_ended_at$",                              # the offered rate of a step: part of the keys
    r"\.pooled_loss\.reps$",                           # the n column of the pooled keys
    r"\.per_round\[\]\.\w+$",                         # the per-round table of a counting run: table and summary only
    r"\.threshold_us$", r"\.resid_us\.n$",             # part of the key; the n column of the residual keys
    r"\.cpu_steps$",                                   # the n column of cpu_one_tick_clamps.k
    r"\.no_retrans\.",                                 # the second line of a ladder: keys only when a file gives the count
    r"\.validity\.\w+$",                               # the same values as <experiment>.header.<name>
]


def uncovered(results, exemptions):
    """(numeric leaves of `results` that match no emitted value and no exemption, exemptions that match no leaf).
    Matching is by value (also value - 1, for the ratios published as differences), so it cannot tell two equal
    numbers apart; it does catch a new statistic that nobody gave a key."""
    emitted = sorted(float(i["value"]) for i in make_numbers.collect(results) if not isinstance(i["value"], str))

    def has(v):
        return any(abs(v - e) <= 1e-9 * max(1.0, abs(e)) or abs(v - 1 - e) <= 1e-9 for e in emitted)

    def leaves(o, path=""):
        if isinstance(o, dict):
            for k, v in o.items():
                yield from leaves(v, f"{path}.{k}" if path else k)
        elif isinstance(o, list):
            for v in o:
                yield from leaves(v, path + "[]")
        elif isinstance(o, (int, float)) and not isinstance(o, bool):
            yield path, o

    paths = {path for path, _ in leaves(results)}
    return (sorted({path for path, v in leaves(results) if not has(v) and not any(re.search(p, path) for p in exemptions)}),
            [p for p in exemptions if not any(re.search(p, path) for path in paths)])


def test_every_number_in_summary_has_a_macro_or_a_listed_reason(out):
    """Walks the numeric leaves of summary.json 'results' of the synthetic full run."""
    assert uncovered(out[1]["results"], SUMMARY_ONLY) == ([], [])  # nothing without a key or a reason, no stale exclusion


GATEWAY_ONLY = [  # the same for a functional run and a negative handshake test, which the synthetic full run does not have
    r"^functional\[\]\.payload_len$",                       # a header line: decides whether byte-exact is judged
    r"^hsneg\[\]\.record\.test$",                          # part of the key
    r"^hsneg\[\]\.record\.(expected|seen)_[tr]x\.\w+$",    # in the table; the seen counts are the counted ones
    r"^hsneg\[\]\.record\.tcp_nodelay_[tr]x$",             # in the table; the files themselves are judged by their own line
]


def test_every_number_of_a_functional_run_and_a_negative_test_has_a_key_or_a_listed_reason(tmp_path):
    from analysis.tests import test_functional, test_hsneg
    run_dir = tmp_path / "run"
    for rel, content in {"e3/FUNCTIONAL": "x\n", **{f"e3/{k}": v for k, v in test_functional.SOUND.items()},
                         "neg/hstest/handshake_gw_tx.csv": test_hsneg.side("initiator", test_hsneg.TX1, "iris"),
                         "neg/hstest/handshake_gw_rx.csv": test_hsneg.side("responder", test_hsneg.RX1, "baolong"),
                         "neg/hsneg.txt": test_hsneg.T1 + "\nPASS\n"}.items():
        (run_dir / rel).parent.mkdir(parents=True, exist_ok=True)
        (run_dir / rel).write_text(content)
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert len(s["results"]["functional"]) == len(s["results"]["hsneg"]) == 1 and s["invalid_runs"] == []
    assert uncovered(s["results"], GATEWAY_ONLY) == ([], [])


def test_numeric_header_lines_have_macros_and_text_ones_do_not(out, table):
    f = {k: (r["formatted"], r["n"], r["how"]) for k, r in table[0].items() if ".header." in k}
    paired = {k.removeprefix("overhead_paired.header."): v[0] for k, v in f.items() if k.startswith("overhead_paired.header.")}
    assert paired == {"cpu_affinity": "3", "freq_khz_start": "1{,}500{,}000", "timer_overhead_ns": "56", "n": "20",
                      "msg_bytes": "64", "seed": "20261123", "signature_mismatches": "0", "failed_calls": "0",
                      "freq_khz_end": "1{,}500{,}000", "wall_s": "18.6", "cpu_s": "18.6", "ctx_switches_involuntary": "135",
                      "ctx_switches_voluntary": "0",  # tool, commit, host, mode, ... are text
                      "off_cpu_s": MINUS + "0.00400"}  # derived: wall_s - cpu_s
    assert f["crypto_ops.header.msg_bytes"] == ("64", "-", "'# msg_bytes=' line of the file")
    for kind in ("crypto_ops", "overhead_paired"):  # every header value that is a number has a key, no other does
        for block in out[1]["results"][kind]:
            for name, value in block["header"].items():
                try:
                    float(value)
                except ValueError:
                    assert f"{kind}.header.{name}" not in table[0]
                else:
                    assert f"{kind}.header.{name}" in table[0]
            assert f"{kind}.header.off_cpu_s" in table[0]


def test_noise_floor_file_cannot_take_the_keys_of_the_comparison(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "overhead" / "overhead_paired_aa.csv").write_text(synth.overhead_paired(mode="aa"))  # as the harness names it
    (run_dir / "noise").mkdir()
    (run_dir / "noise" / "overhead_paired.csv").write_text(synth.overhead_paired(mode="aa"))  # a name that does not say so
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    items = {i["key"]: i for i in make_numbers.collect(s["results"])}
    for key in ("overhead_paired.sign.hl_us", "overhead_paired.aa.sign.hl_us", "overhead_paired.noise-aa.sign.hl_us"):
        assert key in items
    real, floor = items["overhead_paired.sign.median_diff_us"], items["overhead_paired.noise-aa.sign.median_diff_us"]
    assert real["how"] == "median of paired differences csm - standalone" and "mode" not in real["filter"]
    assert floor["how"] == "median of paired differences second standalone call (noise floor, mode=aa) - standalone"
    assert floor["filter"].endswith("mode=aa")
    wrong = [k for k, i in items.items() if ("overhead_paired.aa." in k or "noise-aa." in k)
             and ".header." not in k and "csm" in i["how"].replace("csm_ns", "")]
    assert wrong == []  # nothing about a noise-floor file is described as the Csm path
    # it is not judged against the margin: no TOST keys, and its own table
    assert "overhead_paired.sign.tost_p" in items and "overhead_paired.sign.tost_margin" in items
    assert not [k for k in items if ("overhead_paired.aa." in k or "noise-aa." in k) and "tost" in k]
    assert "overhead_paired.aa.sign.gm_ratio_diff" in items and "overhead_paired.aa.sign.gm_ratio_diff_ci90_hi" in items
    tables = tmp_path / "out" / "tables"
    rows = [ln.split(" | ") for ln in (tables / "overhead_paired.md").read_text().splitlines() if ".csv" in ln]
    assert [(r[0].lstrip("| "), r[1]) for r in rows] == [("overhead/overhead_paired.csv", "ab")] * 2
    floor_md = (tables / "overhead_noise_floor.md").read_text()
    assert "median standalone, second call (µs)" in floor_md and "margin" not in floor_md.splitlines()[1]
    assert sorted(ln.split(" | ")[0].lstrip("| ") for ln in floor_md.splitlines() if ".csv" in ln) == \
        ["noise/overhead_paired.csv"] * 2 + ["overhead/overhead_paired_aa.csv"] * 2
    aa = [f for f in s["results"]["overhead_paired"] if f["mode"] == "aa"]
    assert all(f["margin"] is None and o["tost_paired_log"]["equivalent"] is None for f in aa for o in f["ops"])


def test_every_bound_finds_its_estimate(out, hosts):
    """Bounds name their estimate, and the two are formatted together. A bound whose estimate key does
    not exist would silently be formatted alone."""
    from analysis.tests.test_make_tables import launch_run
    launches = make_tables.run(launch_run(hosts / "launch_run"), hosts / "launch_out", **PARAMS)["results"]
    for results, at_least in ((out[1]["results"], 100), (launches, 50)):
        items = {i["key"]: i for i in make_numbers.collect(results)}
        bounds = [i for i in items.values() if i["group"] != i["key"]]
        assert len(bounds) > at_least and all(i["group"] in items for i in bounds)
        for i in bounds:  # ... and really shares the decimals of its estimate when both are in fixed notation
            a, b = i["formatted"], items[i["group"]]["formatted"]
            whole = i["unit"] == "percent" and {i["value"], items[i["group"]]["value"]} & {0, 1}  # exact: 0% and 100%
            if "times" not in a and "times" not in b and not whole:
                assert len(a.rstrip(r"\%").rpartition(".")[2]) == len(b.rstrip(r"\%").rpartition(".")[2]) or "." not in a + b


def test_run_parameters_have_macros(table):
    f = {k: (r["formatted"], r["n"], r["source_file"]) for k, r in table[0].items() if k.startswith("run.")}
    # the warm-up is a parameter of the single-node series only, and its key says so: it stands in every numbers.csv
    how = table[0]["run.warmup"]["how"]
    assert "crypto_ops, sign_attrib, overhead_paired and overhead_unpaired" in how
    assert "nothing is dropped in the periodic, throughput, attack, handshake" in how
    assert f == {"run.seed": ("20261122", "-", "summary.json"), "run.warmup": ("10", "-", "summary.json"),
                 "run.block_len": ("5", "-", "summary.json"), "run.n_boot": ("50", "-", "summary.json"),
                 "run.trim": ("5", "-", "summary.json"), "run.sim_draws": ("3", "-", "summary.json"),
                 "run.sim_jobs": ("400", "-", "summary.json")}
    g = {k: r["formatted"] for k, r in table[0].items()}
    assert (g[CONFIG + ".period_ms"], g[CONFIG + ".deadline_ms"], g[CONFIG + ".streams"], g[CONFIG + ".payload_bytes"]) == \
        ("10.00", "10.00", "2", "64")
    assert (g[CONFIG + ".clock_probes"], g[CONFIG + ".clock_outside_span"], g[CONFIG + ".clock_rtt_median_us"]) == ("2", "0", "225")
    assert (g["handshake.iris.initiator.result_ok"], g["handshake.iris.initiator.result_timeout"], g["handshake.iris.responder.result_ok"]) == ("3", "1", "2")
    assert (g["throughput.mldsa65-c1.cores"], g["throughput.mldsa65-c1.r200.tx.sendq_slope_bytes_per_s"]) == ("1", PLUS + "10{,}000")
    assert (g["crypto_ops.mldsa_sign.n_total"], g[CONFIG + ".response_n"], g[CONFIG + ".latency_n"]) == ("20", "24", "23")


def test_text_that_cannot_be_a_latex_name_is_refused_not_mangled(tmp_path):
    run_dir = synth.make_run(tmp_path / "run")
    (run_dir / "attack").rename(run_dir / "attack v2.1")
    with pytest.raises(ValueError, match=r"attack v2\.1/attack\.csv: number key .* outside \[A-Za-z0-9_-\]"):
        make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert not (tmp_path / "out").exists()


def test_rebuild_from_summary_json(out, tmp_path, capsys):
    make_numbers.main([str(out[0]), "--out", str(tmp_path / "again.tex")])
    assert (tmp_path / "again.tex").read_bytes() == (out[0] / "numbers.tex").read_bytes()
    assert (tmp_path / "again.csv").read_bytes() == (out[0] / "numbers.csv").read_bytes()
    assert (tmp_path / "number_keys.md").read_bytes() == (out[0] / "number_keys.md").read_bytes()
    assert (tmp_path / "suppressed_keys.txt").read_bytes() == (out[0] / "suppressed_keys.txt").read_bytes()
    assert f"{out[1]['numbers']['keys']} keys" in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        make_numbers.main([str(tmp_path)])  # no summary.json there
    assert "summary.json" in str(e.value.code)


def test_rebuild_by_path_in_isolated_mode(out, tmp_path):
    cmd = [sys.executable, "-I", str(Path(make_numbers.__file__).resolve()), str(out[0]), "--out", str(tmp_path / "n.tex")]
    r = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "n.tex").read_bytes() == (out[0] / "numbers.tex").read_bytes()


# ---- several runs in one manuscript: key prefix and merge -----------------------------------------

def keys_of(path):
    with open(path, newline="") as f:
        return [r["key"] for r in csv.DictReader(f)]


def test_key_prefix_goes_in_front_of_every_key(tmp_path, capsys):
    run_dir = synth.make_run(tmp_path / "run")
    s = make_tables.run(run_dir, tmp_path / "out", key_prefix="s1.iris", **PARAMS)
    keys = keys_of(tmp_path / "out" / "numbers.csv")
    assert s["key_prefix"] == "s1.iris" and all(k.startswith("s1.iris.") for k in keys)
    assert {"s1.iris.crypto_ops.mldsa_sign.p50_us", "s1.iris.run.seed", "s1.iris." + CONFIG + ".miss_ratio"} <= set(keys)
    assert "key prefix 's1.iris'" in (tmp_path / "out" / "numbers.tex").read_text()
    for bad in ("s1 iris", "s1..iris", "iris.", "ünï"):
        with pytest.raises(ValueError, match="key prefix"):
            make_tables.run(run_dir, tmp_path / "never", key_prefix=bad, **PARAMS)
    assert not (tmp_path / "never").exists()
    # the stored prefix is kept on a rebuild, and can be replaced
    make_numbers.main([str(tmp_path / "out"), "--out", str(tmp_path / "same.tex")])
    assert keys_of(tmp_path / "same.csv") == keys
    make_numbers.main([str(tmp_path / "out"), "--out", str(tmp_path / "other.tex"), "--key-prefix", "s2.baolong"])
    assert all(k.startswith("s2.baolong.") for k in keys_of(tmp_path / "other.csv"))
    make_tables.main([str(run_dir), "--out", str(tmp_path / "cli"), "--warmup", "10", "--block-len", "5", "--n-boot", "20",
                      "--sim-draws", "0", "--key-prefix", "iris"])
    assert all(k.startswith("iris.") for k in keys_of(tmp_path / "cli" / "numbers.csv"))


@pytest.fixture(scope="module")
def hosts(tmp_path_factory):
    """Two runs of the same experiments, as two hosts give them: identical keys but for the prefix."""
    root = tmp_path_factory.mktemp("hosts")
    run_dir = synth.make_run(root / "run")
    for host in ("iris", "baolong"):
        make_tables.run(run_dir, root / host, key_prefix=host, **PARAMS)
    make_tables.run(run_dir, root / "plain", **PARAMS)
    (run_dir / "DRY_RUN").write_text("dry\n")
    make_tables.run(run_dir, root / "dry", key_prefix="dry", **PARAMS)
    return root


def test_merge_numbers(hosts, tmp_path, capsys):
    merge_numbers.main([str(hosts / "iris"), str(hosts / "baolong" / "numbers.tex"), "--out", str(tmp_path / "all.tex")])
    assert "from 2 run(s)" in capsys.readouterr().out
    rows, other = parse_tex(tmp_path / "all.tex")
    keys = [r["key"] for r in rows]
    want = sorted(keys_of(hosts / "iris" / "numbers.csv") + keys_of(hosts / "baolong" / "numbers.csv"))
    # the keys the percentile rule holds back are left out; <out>.suppressed.txt lists them: the union of the inputs' lists
    held_back = merged_suppressed(tmp_path / "all.tex")
    assert held_back == {**suppressed(hosts / "iris"), **suppressed(hosts / "baolong")} and len(held_back) > 100
    assert want == keys_of(tmp_path / "all.csv") and keys == [k for k in want if k not in held_back] and len(set(keys)) == len(keys)
    assert "iris.crypto_ops.mldsa_sign.mean_us" in keys and "baolong.crypto_ops.mldsa_sign.mean_us" in keys
    assert [r["key"] for r in rows if r["raw"] is None] == ["baolong.overhead_paired.verify.tost_p", "iris.overhead_paired.verify.tost_p"]
    text = (tmp_path / "all.tex").read_text()
    # the macros once, in a form that neither clashes with a definition the manuscript makes before the \input nor
    # overrides its \measundefined; no marked input
    assert text.count(r"\providecommand{\meas}[1]{}\renewcommand{\meas}[1]{") == 1 and r"\notaresult" not in text
    assert text.count(r"\providecommand{\measraw}[1]{}\renewcommand{\measraw}[1]{") == 1 and r"\newcommand" not in text
    assert text.count(r"\providecommand{\measundefined}[1]{\PackageError{numbers}{Undefined number key") == 1
    assert all(line.startswith(("%", r"\providecommand{\meas", "  {")) for line in other)
    # the header names every run: directory, key prefix, toolkit commit, number of keys
    commit = make_numbers.toolkit_commit()
    for host in ("iris", "baolong"):
        n = len(keys_of(hosts / host / "numbers.csv")) - len(suppressed(hosts / host))
        assert f"%   {host}: key prefix '{host}', toolkit {commit}, {n} keys" in text
    with open(tmp_path / "all.csv", newline="") as f:
        table = {r["key"]: r for r in csv.DictReader(f)}
    assert all(r["formatted"] == table[r["key"]]["formatted"] for r in rows)


def test_merge_refuses_a_key_with_two_values_and_inconsistent_inputs(hosts, tmp_path):
    """Two runs analysed without a prefix have the same keys. Different values under one key are an error that
    names both directories; the same directory twice (the same values) is harmless."""
    other = synth.make_run(tmp_path / "run")
    (other / "crypto" / "crypto_ops.csv").write_text(synth.crypto_ops().replace("mldsa_sign,19,10000000", "mldsa_sign,19,12000000"))
    make_tables.run(other, tmp_path / "plain2", **PARAMS)
    with pytest.raises(SystemExit) as e:
        merge_numbers.main([str(hosts / "plain"), str(tmp_path / "plain2"), "--out", str(tmp_path / "x.tex")])
    message = str(e.value.code)
    assert e.value.code != 0 and "has different values" in message and "--key-prefix" in message
    assert str(hosts / "plain") in message and str(tmp_path / "plain2") in message and "'crypto_ops.mldsa_sign." in message
    assert not (tmp_path / "x.tex").exists() and not (tmp_path / "x.csv").exists()
    merge_numbers.main([str(hosts / "plain"), str(hosts / "plain"), "--out", str(tmp_path / "same.tex")])
    assert keys_of(tmp_path / "same.csv") == keys_of(hosts / "plain" / "numbers.csv")
    # an output written before the percentile rule has no suppressed_keys.txt: its .tex may define keys that the rule
    # holds back, so it is refused and must be analysed again
    old = tmp_path / "old"
    shutil.copytree(hosts / "iris", old)
    (old / "suppressed_keys.txt").unlink()
    with pytest.raises(SystemExit) as e:
        merge_numbers.main([str(old), str(hosts / "baolong"), "--out", str(tmp_path / "x.tex")])
    assert "has no suppressed_keys.txt" in str(e.value.code) and "make_tables" in str(e.value.code)
    assert not (tmp_path / "x.tex").exists()
    broken = tmp_path / "broken"
    shutil.copytree(hosts / "iris", broken)
    lines = (broken / "numbers.csv").read_text().splitlines(keepends=True)
    (broken / "numbers.csv").write_text("".join(lines[:5] + lines[6:]))  # one key is missing from the audit table
    with pytest.raises(SystemExit) as e:
        merge_numbers.main([str(broken), str(hosts / "baolong"), "--out", str(tmp_path / "x.tex")])
    assert "do not list the same keys" in str(e.value.code)


def test_merge_refuses_a_marked_run_unless_told_and_then_says_so(hosts, tmp_path):
    with pytest.raises(SystemExit) as e:
        merge_numbers.main([str(hosts / "iris"), str(hosts / "dry"), "--out", str(tmp_path / "all.tex")])
    assert e.value.code != 0 and "DRY_RUN" in str(e.value.code) and "--allow-marked" in str(e.value.code)
    assert str(hosts / "dry") in str(e.value.code) and not (tmp_path / "all.tex").exists()
    merge_numbers.main([str(hosts / "iris"), str(hosts / "dry"), "--out", str(tmp_path / "all.tex"), "--allow-marked"])
    text = (tmp_path / "all.tex").read_text()
    assert "% CONTAINS VALUES THAT ARE NOT RESULTS (--allow-marked): dry (DRY_RUN)" in text.splitlines()[:4]
    assert any(ln.startswith("%   dry: key prefix 'dry'") and ln.endswith("NOT A RESULT (DRY_RUN)") for ln in text.splitlines())
    assert text.count(r"\DeclareRobustCommand{\notaresult}") == 1
    rows, _ = parse_tex(tmp_path / "all.tex")
    dry = [r for r in rows if r["key"].startswith("dry.")]
    assert dry and all(r["formatted"].startswith(r"\notaresult{") and r["raw"] is None for r in dry)
    assert all(not r["formatted"].startswith(r"\notaresult") for r in rows if r["key"].startswith("iris."))


def merged_suppressed(out):
    """<out>.suppressed.txt of a merged file as {key: reason}."""
    lines = Path(str(out) + ".suppressed.txt").read_text().splitlines()
    return dict(ln.split("\t") for ln in lines if ln and not ln.startswith("#"))


def test_merge_by_path_in_isolated_mode(hosts, tmp_path):
    cmd = [sys.executable, "-I", str(Path(merge_numbers.__file__).resolve()), str(hosts / "iris"), str(hosts / "baolong"),
           "--out", str(tmp_path / "all.tex")]
    r = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True)
    assert r.returncode == 0 and (tmp_path / "all.csv").is_file(), r.stderr


# ---- a real LaTeX run, where one is installed ----------------------------------------------------

pdflatex = pytest.mark.skipif(shutil.which("pdflatex") is None, reason="pdflatex is not installed")
KEYS = ("crypto_ops.mldsa_sign.mean_us", "overhead_paired.sign.hl_ci95_lo_us", CONFIG + ".miss_ratio", "overhead_paired.sign.tost_p")


def latex(tmp_path, out, body, preamble=""):
    """Compile a small article that \\inputs the numbers file (out[0]: a make_tables directory, or the file itself)."""
    shutil.copy(out[0] / "numbers.tex" if out[0].is_dir() else out[0], tmp_path / "numbers.tex")
    (tmp_path / "doc.tex").write_text("\\documentclass{article}\n" + preamble + "\\input{numbers.tex}\n\\begin{document}\n"
                                      + body + "\n\\end{document}\n")
    for _ in range(2):  # the second pass reads the caption back from the .lof file
        r = subprocess.run(["pdflatex", "-interaction=nonstopmode", "-halt-on-error", "doc.tex"], cwd=tmp_path,
                           capture_output=True, text=True, timeout=180)
        if r.returncode:
            break
    return r.returncode, (tmp_path / "doc.log").read_text(errors="replace")


@pdflatex
def test_latex_accepts_keys_in_text_math_caption_and_heading(out, tmp_path):
    a, b, c, d = (rf"\meas{{{k}}}" for k in KEYS)
    body = (rf"\listoffigures Text {a}, {b}, {c}, {d}, raw \measraw{{{KEYS[0]}}}. Math $t = {a}$, $\Delta = {b}$, $r = {c}$, "
            rf"$p = {d}$. \begin{{figure}}\caption{{Caption {c} and {a}.}}\end{{figure}} \section{{Heading {a}}}")
    code, log = latex(tmp_path, out, body)
    assert code == 0 and "Undefined number key" not in log, log[-2000:]
    assert r"Caption 12.5\% and 5{,}500." in (tmp_path / "doc.lof").read_text()  # expanded to the value in the list of figures


@pdflatex
def test_latex_merged_file_of_two_hosts(hosts, tmp_path):
    merge_numbers.main([str(hosts / "iris"), str(hosts / "baolong"), "--out", str(tmp_path / "all.tex")])
    code, log = latex(tmp_path, (tmp_path / "all.tex", None), r"Both hosts: \meas{iris.crypto_ops.mldsa_sign.mean_us} and "
                      r"\meas{baolong.crypto_ops.mldsa_sign.mean_us}; $p = \meas{iris.overhead_paired.sign.tost_p}$.")
    assert code == 0, log[-2000:]
    code, log = latex(tmp_path, (tmp_path / "all.tex", None), r"\measraw{iris.overhead_paired.verify.tost_p}")
    assert code != 0 and "Undefined number key" in log  # an underflowed p-value has no plain form to print


@pdflatex
def test_latex_merged_file_respects_what_the_manuscript_defined_before_the_input(hosts, tmp_path):
    """While the campaign is incomplete the manuscript predefines \\measundefined (a PENDING marker) and may carry a
    fallback \\meas: the merged file must not clash with either, must define the real \\meas, and must leave
    \\measundefined alone. Without the predefinition a missing key is a hard error again."""
    merge_numbers.main([str(hosts / "iris"), str(hosts / "baolong"), "--out", str(tmp_path / "all.tex")])
    pending = ("\\newcommand{\\measundefined}[1]{PENDING}\n\\providecommand{\\meas}[1]{FALLBACK}\n"
               "\\providecommand{\\measraw}[1]{FALLBACK}\n")
    body = r"Have \meas{iris.crypto_ops.mldsa_sign.mean_us}, lack \meas{e9.not.measured.yet} and \measraw{e9.not.measured.yet}."
    code, log = latex(tmp_path, (tmp_path / "all.tex", None), body, pending)
    assert code == 0, log[-2000:]
    if shutil.which("pdftotext"):
        text = subprocess.run(["pdftotext", "doc.pdf", "-"], cwd=tmp_path, capture_output=True, text=True).stdout
        assert "Have 5,500, lack PENDING and PENDING." in " ".join(text.split()) and "FALLBACK" not in text
    code, log = latex(tmp_path, (tmp_path / "all.tex", None), body)  # the final build: no predefinition
    assert code != 0 and "Undefined number key" in log


@pdflatex
@pytest.mark.parametrize("preamble", ["", "\\usepackage{xcolor}\n"])
def test_latex_dry_run_values_are_marked(hosts, tmp_path, preamble):
    """\\notaresult must work with and without a colour package, in text, math, a caption and a heading."""
    k = "dry.crypto_ops.mldsa_sign.mean_us"
    body = (rf"\listoffigures Text \meas{{{k}}}, math $t = \meas{{{k}}}$, $\meas{{dry.{CONFIG}.miss_ratio}}$. "
            rf"\begin{{figure}}\caption{{Caption \meas{{{k}}}.}}\end{{figure}} \section{{Heading \meas{{{k}}}}}")
    code, log = latex(tmp_path, (hosts / "dry" / "numbers.tex", None), body, preamble)
    assert code == 0, log[-2000:]
    assert r"\notaresult" in (tmp_path / "doc.lof").read_text()
    if shutil.which("pdftotext"):
        text = subprocess.run(["pdftotext", "doc.pdf", "-"], cwd=tmp_path, capture_output=True, text=True).stdout
        assert text.count("[DRY] 5,500") >= 4 and "[DRY] 12.5%" in text  # every use shows the tag
    code, log = latex(tmp_path, (hosts / "dry" / "numbers.tex", None), rf"\measraw{{{k}}}", preamble)
    assert code != 0 and "Undefined number key" in log  # no plain values in a marked run


@pdflatex
def test_latex_coexists_with_siunitx(out, tmp_path):
    """The reason the macros are not called \\num: siunitx owns that name."""
    code, log = latex(tmp_path, out, rf"siunitx \num{{1234.5}} and \qty{{10}}{{\milli\second}}; measured \meas{{{KEYS[0]}}}, "
                                     rf"$\meas{{{KEYS[1]}}}$, \measraw{{{KEYS[0]}}}.", preamble="\\usepackage{siunitx}\n")
    assert code == 0 and "Error" not in log, log[-2000:]


@pdflatex
@pytest.mark.parametrize("macro", ["meas", "measraw"])
def test_latex_stops_on_an_undefined_key(out, tmp_path, macro):
    code, log = latex(tmp_path, out, rf"Typo: \{macro}{{crypto_ops.mldsa_sign.p50}}.")
    assert code != 0 and "Package numbers Error: Undefined number key 'crypto_ops.mldsa_sign.p50'" in log
