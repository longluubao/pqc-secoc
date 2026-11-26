"""Footprint figures taken with standard tools (CAMPAIGN.md, E8): binary sizes, perf counts, resident set. Counts only."""
import csv

import pytest

from analysis import footprint, make_tables
from analysis.tests.test_make_numbers import uncovered
from analysis.tests.test_make_tables import PARAMS


def block(build=None, text=1000, bss=5000, total=None, sections=(".text", ".rodata", ".data", ".bss")):
    """One block of a size file as the campaign driver writes it: the two byte counts, then the table of `size -A`."""
    sizes = {".interp": 27, ".text": text, ".rodata": 300, ".data": 40, ".bss": bss, ".comment": 31}
    rows = [(s, n) for s, n in sizes.items() if s in sections or s in (".interp", ".comment")]
    return ((f"== {build}/\n" if build else "") + "unstripped_bytes=9000\nstripped_bytes=7000\n/dev/shm/SecOC.s  :\n"
            "section                 size     addr\n" + "".join(f"{s:<20}{n:>8}{100 * i:>9}\n" for i, (s, n) in enumerate(rows))
            + f"Total {sum(n for _, n in rows) if total is None else total:>20}\n\n\n")


BUILD = {"unstripped_bytes": 9000, "stripped_bytes": 7000, "text_bytes": 1000, "rodata_bytes": 300, "data_bytes": 40, "bss_bytes": 5000}


def test_size_file_known_values(tmp_path):
    p = tmp_path / "size_gw_tx.txt"
    p.write_text(block())
    assert footprint.sizes(p) == [{"build": None, **BUILD}]
    # several builds in one file, each under its '== <build>/' line
    p.write_text(block("build-rx") + block("build-tx", text=1200, bss=5200))
    assert footprint.sizes(p) == [{"build": "build-rx", **BUILD}, {"build": "build-tx", **BUILD, "text_bytes": 1200, "bss_bytes": 5200}]
    # a file of that name without the two byte counts is no footprint file: left alone
    p.write_text("notes on sizes\n")
    assert footprint.sizes(p) is None


@pytest.mark.parametrize("content, message", [
    (block(total=6399), "the rows add up to 6398 bytes, Total says 6399"),             # a cut or edited table
    (block(sections=(".text", ".rodata", ".data")), "bss_bytes missing"),             # a section the keys need
    (block("build-rx").replace("stripped_bytes=7000\n", ""), "stripped_bytes missing"),
    (block().replace("Total", "Sum"), "no Total line"),
])
def test_a_size_file_that_contradicts_itself_is_an_error(tmp_path, content, message):
    p = tmp_path / "size_gw_tx.txt"
    p.write_text(content)
    with pytest.raises(ValueError, match=message):
        footprint.sizes(p)


def perf_text(instructions, cycles, running="100.00"):
    return (f"# started on Mon Nov 23 17:58:17 2026\n\n{instructions},,instructions:u,1811694603,{running},2.33,insn per cycle\n"
            f"{cycles},,cycles:u,1811694603,100.00,,\n")


def test_perf_counts_and_the_figures_of_one_call(tmp_path):
    p = tmp_path / "perf_mldsa_sign_1000.csv"
    p.write_text(perf_text(6_000_500, 2_600_200))
    assert footprint.perf(p) == {"instructions": 6_000_500, "cycles": 2_600_200}
    # two runs that differ in the number of calls only: what the 1,000 calls between them cost, start-up cancelled
    assert footprint.per_call({1000: {"instructions": 6_000_500, "cycles": 2_600_200},
                               2000: {"instructions": 11_800_500, "cycles": 5_100_200}}) == {
        "instructions_per_call": 5800, "cycles_per_call": 2500, "instructions_per_cycle": 2.32}
    p.write_text("a,b\n1,2\n")  # a file of that name without the two events is no perf file: left alone
    assert footprint.perf(p) is None
    for content, message in ((perf_text("<not counted>", 5), "no whole count"), (perf_text(7, 5, "99.50"), "no whole count"),
                             (perf_text(7, 5).split("\n5,,")[0] + "\n", "needs both")):
        p.write_text(content)
        with pytest.raises(ValueError, match=message):
            footprint.perf(p)
    with pytest.raises(ValueError, match="does not count more"):  # the longer run must count more of both
        footprint.per_call({1000: {"instructions": 9, "cycles": 9}, 2000: {"instructions": 12, "cycles": 9}})


RSS = ("18:04:48 iris VmSize: 11116 kB VmHWM: 7308 kB VmRSS: 7308 kB VmData: 1632 kB \n"
       "18:04:49 baolong VmSize: 8316 kB VmHWM: 6024 kB VmRSS: 6024 kB VmData: 1488 kB \n"
       "18:05:17 iris VmSize: 11116 kB VmHWM: 7312 kB VmRSS: 7300 kB VmData: 1632 kB \n"
       "18:05:17 baolong VmSize: 8316 kB VmHWM: 6028 kB VmRSS: 6028 kB VmData: 1488 kB \n"
       "18:05:45 iris VmSize: 11116 kB VmHWM: 7312 kB VmRSS: 7308 kB VmData: 1632 kB \n")


def test_resident_set_samples_known_values(tmp_path):
    p = tmp_path / "rss_samples.txt"
    p.write_text(RSS)
    assert footprint.rss(p) == {"iris": {"samples": 3, "vmhwm_max_kb": 7312}, "baolong": {"samples": 2, "vmhwm_max_kb": 6028}}
    p.write_text("nothing sampled\n")
    assert footprint.rss(p) is None
    p.write_text(RSS + "18:06:13 iris\n")  # the process was gone: a sample without a reading is not passed over
    with pytest.raises(ValueError, match="18:06:13 iris"):
        footprint.rss(p)


def numbers(out):
    with open(out / "numbers.csv", newline="") as f:
        return {r["key"]: r for r in csv.DictReader(f)}


def test_a_directory_of_footprint_files_gets_keys_and_nothing_is_timed(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    files = {"size_gw_tx.txt": block(), "size_gateway_iris.txt": block("build-rx") + block("build-tx", text=1200),
             "perf_mldsa_sign_1000.csv": perf_text(6_000_500, 2_600_200), "perf_mldsa_sign_2000.csv": perf_text(11_800_500, 5_100_200),
             "perf_mldsa_verify_1000.csv": perf_text(8_000_000, 3_400_000), "perf_mldsa_verify_2000.csv": perf_text(15_000_000, 6_400_000),
             "perf_hmac_500.csv": perf_text(100, 50),  # one run alone gives no difference
             # the tool that only verifies (ruling of 2026-11-24): two run lengths, 2,000 calls apart
             "perf_mldsa_verify_only_1000.csv": perf_text(3_000_700, 1_300_100),
             "perf_mldsa_verify_only_3000.csv": perf_text(7_000_700, 2_900_100),
             "rss_samples.txt": RSS, "size_notes.txt": "not a size file\n", "stdout_mldsa_sign_1000.txt": "mldsa_sign: 1000 samples\n"}
    for name, content in files.items():
        (run_dir / name).write_text(content)
    s = make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    assert s["invalid_runs"] == [] and [(f["what"], f.get("op")) for f in s["results"]["footprint"]] == [
        ("size", None), ("size", None), ("perf", "mldsa_sign"), ("perf", "mldsa_verify_only"), ("rss", None)]
    assert {e["path"]: e["reason"] for e in s["skipped_csv"]} == {
        name: footprint.NOT_PER_CALL for name in ("perf_hmac_500.csv", "perf_mldsa_verify_1000.csv", "perf_mldsa_verify_2000.csv")}
    rows = numbers(tmp_path / "out")
    got = {k: r["value"] for k, r in rows.items() if k.startswith("footprint.")}
    assert got == {
        **{f"footprint.size.gw_tx.{k}": str(v) for k, v in BUILD.items()},
        **{f"footprint.size.gateway_iris.build-rx.{k}": str(v) for k, v in BUILD.items()},
        **{f"footprint.size.gateway_iris.build-tx.{k}": str(v) for k, v in {**BUILD, "text_bytes": 1200}.items()},
        "footprint.perf.mldsa_sign.n1000.instructions": "6000500", "footprint.perf.mldsa_sign.n1000.cycles": "2600200",
        "footprint.perf.mldsa_sign.n2000.instructions": "11800500", "footprint.perf.mldsa_sign.n2000.cycles": "5100200",
        "footprint.perf.mldsa_sign.instructions_per_call": "5800.0", "footprint.perf.mldsa_sign.cycles_per_call": "2500.0",
        "footprint.perf.mldsa_sign.instructions_per_cycle": "2.32",
        "footprint.perf.mldsa_verify_only.n1000.instructions": "3000700", "footprint.perf.mldsa_verify_only.n1000.cycles": "1300100",
        "footprint.perf.mldsa_verify_only.n3000.instructions": "7000700", "footprint.perf.mldsa_verify_only.n3000.cycles": "2900100",
        "footprint.perf.mldsa_verify_only.instructions_per_call": "2000.0", "footprint.perf.mldsa_verify_only.cycles_per_call": "800.0",
        "footprint.perf.mldsa_verify_only.instructions_per_cycle": "2.5",
        "footprint.rss.iris.vmhwm_max_kb": "7312", "footprint.rss.iris.samples": "3",
        "footprint.rss.baolong.vmhwm_max_kb": "6028", "footprint.rss.baolong.samples": "2"}
    per_call = rows["footprint.perf.mldsa_sign.instructions_per_call"]
    assert (per_call["formatted"], per_call["source_file"]) == ("5{,}800", "perf_mldsa_sign_1000.csv + perf_mldsa_sign_2000.csv")
    for words in ("one pair of runs", "user space", "no interval", "file names", "2,000 calls less that of the run of 1,000"):
        assert words in per_call["how"]
    assert rows["footprint.size.gw_tx.bss_bytes"]["formatted"] == "5{,}000" and rows["footprint.rss.iris.vmhwm_max_kb"]["n"] == "3"
    # every number the reader keeps has a key; the number of calls of a run is part of its key
    assert uncovered(s["results"], [r"^footprint\[\]\.runs\[\]\.calls$"]) == ([], [])
    table = (tmp_path / "out" / "tables" / "footprint.md").read_text()
    assert "| size_gateway_iris.txt | build-tx | .text (bytes) | 1200 |" in table and "| rss_samples.txt | iris | largest VmHWM (kB) | 7312 |" in table
    assert "| perf_mldsa_sign_1000.csv + perf_mldsa_sign_2000.csv | mldsa_sign | instructions per call | 5800 |" in table
    # files of these names without the shape are no footprint: a directory with nothing else is still refused
    lone = tmp_path / "lone"
    lone.mkdir()
    (lone / "size_notes.txt").write_text("not a size file\n")
    with pytest.raises(ValueError, match="no recognised"):
        make_tables.run(lone, tmp_path / "lone_out", **PARAMS)
