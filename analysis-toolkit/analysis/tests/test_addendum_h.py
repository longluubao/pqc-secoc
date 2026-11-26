"""The cells of Addendum H of E9_SPEC.md (2026-11-25), on synthetic files, before any of their runs exists: several
sender processes on one core (E6m), four processes on four cores (E6c), staggered release (E6p), and gateway runs with a
restart (E3r)."""
import csv

from analysis import make_tables
from analysis.tests import synth, test_functional as tf
from analysis.tests.test_make_tables import PARAMS

BENCH = dict(mainfunction="cyclic", mf_period_us=1000, phase="sync")


def cell(tmp_path, name, cores, **header):
    """A periodic cell of len(cores) sender processes, periodic_tx_p<i>.csv, each the synthetic two-stream file (24 jobs,
    3 missed); process i says cpu_affinity=cores[i], or has no such line where cores[i] is None."""
    run_dir = tmp_path / name
    (run_dir / "periodic").mkdir(parents=True)
    for i, core in enumerate(cores):
        pinned = {} if core is None else {"cpu_affinity": core}
        (run_dir / "periodic" / f"periodic_tx_p{i}.csv").write_text(
            synth.periodic_tx_two_streams(partition=i, partitions=len(cores), **{**BENCH, **header}, **pinned))
    s = make_tables.run(run_dir, tmp_path / (name + "_out"), **PARAMS)
    with open(tmp_path / (name + "_out") / "numbers.csv", newline="") as f:
        table = list(csv.DictReader(f))
    HOW.update({r["key"]: r["how"] for r in table})
    return s, {r["key"]: r["value"] for r in table}


HOW = {}  # what the keys of the last cell() say they are


def test_sender_processes_on_one_core_are_a_cell_of_one_core_without_the_per_process_model(tmp_path):
    """E6m (H4): four sender processes pinned to core 3. The cell's cores are the distinct cores of its files, one; the
    model of a process assumes a core of its own, so a cell whose processes share a core gets no model key."""
    s, rows = cell(tmp_path, "one_core", (3, 3, 3, 3))
    (c,) = s["results"]["periodic_cells"]
    assert (c["partitions"], c["cores"], c["streams"], c["jobs"], c["misses"]) == (4, 1, 8, 96, 12)
    name = "periodic.p10ms-s8-c1-mldsa65-fifo-cyclic-mf1ms-sync-parts4"
    assert [rows[f"{name}.{k}"] for k in ("partitions", "cores", "streams", "jobs", "misses", "miss_ratio")] == ["4", "1", "8", "96", "12", "0.125"]
    assert rows["periodic.p3.p10ms-s2-c1-mldsa65-fifo-cyclic-mf1ms-sync-part3.misses"] == "3"   # each process keeps its keys
    assert not [k for k in rows if ".model_" in k]
    assert all("model" not in r for r in s["results"]["periodic"])
    # nor the measured utilisation of a process: between its start_ns and auth_done_ns another process of the cell may
    # have held the core, so the covered time is not this process's own
    assert [k for k in rows if "auth_utilisation" in k] == [name + ".auth_utilisation"]
    assert all(r["auth_utilisation"] is None for r in s["results"]["periodic"])
    # the cell has the one figure of its shared core (ruling of 2026-11-25). The four files hold the same stamps, so the
    # time covered by all of them is that of one: 55 of 118 ms (test_coverage_keys derives it)
    assert float(rows[name + ".auth_utilisation"]) == __import__("pytest").approx(55 / 118)
    # the cell says what it is: processes that share a core, counted in distinct cores
    assert "distinct" in HOW[name + ".cores"] and "share" in HOW[name + ".jobs"] and "independent processes" not in HOW[name + ".jobs"]
    # two processes on one core and one on another: two distinct cores, and still no core per process
    s, rows = cell(tmp_path, "mixed", (2, 2, 3))
    assert "periodic.p10ms-s6-c2-mldsa65-fifo-cyclic-mf1ms-sync-parts3.jobs" in rows and not [k for k in rows if ".model_" in k]


def test_the_shared_core_of_a_cell_has_one_measured_utilisation(tmp_path):
    """Ruling of 2026-11-25 on H4: for a cell whose sender processes are all pinned to one core, the time covered by the
    intervals from start_ns to auth_done_ns of the jobs of ALL its processes, over the time from the first release to
    the last send over all its files. Two processes of one stream: twelve jobs every 10 ms, in the call from 1 ms to
    2.5 ms after the release; the second process runs 1 ms behind the first. In every period the core is in the call
    from 1 ms to 3.5 ms: 12 x 2.5 ms = 30 ms (each process alone 18 ms: together not 36), between the first release
    and the last send, 110 + 1 + 3 = 114 ms."""
    def files(cores, unrecorded=()):
        run_dir = tmp_path / ("cores_" + "_".join(map(str, cores)) + ("_unrecorded" if unrecorded else ""))
        (run_dir / "periodic").mkdir(parents=True)
        for i, core in enumerate(cores):
            rows = [(st, q, *(t + i * synth.MS for t in times)) for st, q, *times in (synth._job(0, s, 0, 3) for s in range(12))]
            silent = {"not_recorded": "auth_done_ns"} if i in unrecorded else {}   # a binary without that time stamp writes 0
            rows = [(*r[:4], 0, r[5]) for r in rows] if silent else rows
            (run_dir / "periodic" / f"periodic_tx_p{i}.csv").write_text(synth.text(synth.TX_HEADER, rows, synth.tx_meta(
                1, partition=i, partitions=len(cores), cpu_affinity=core, **BENCH, **silent)))
        make_tables.run(run_dir, tmp_path / (run_dir.name + "_out"), **PARAMS)
        with open(tmp_path / (run_dir.name + "_out") / "numbers.csv", newline="") as f:
            return {r["key"]: r for r in csv.DictReader(f)}

    rows = files((3, 3))
    key = "periodic.p10ms-s2-c1-mldsa65-fifo-cyclic-mf1ms-sync-parts2.auth_utilisation"
    assert float(rows[key]["value"]) == __import__("pytest").approx(30 / 114) and rows[key]["unit"] == "percent"
    assert "union" in rows[key]["how"] and "all sender processes" in rows[key]["how"] and rows[key]["n"] == "24"
    assert [k for k in rows if k.endswith("auth_utilisation")] == [key]            # the processes have none of their own
    # a core per process: each process has its own (18 of 113 ms), the cell has none
    rows = files((2, 3))
    assert sorted(k.split(".")[1] for k in rows if k.endswith("auth_utilisation")) == ["p0", "p1"]
    assert float(rows["periodic.p0.p10ms-s1-c1-mldsa65-fifo-cyclic-mf1ms-sync-part0.auth_utilisation"]["value"]) == __import__("pytest").approx(18 / 113)
    # three processes on two cores: neither the cell (not one core) nor a process (not a core of its own)
    assert not [k for k in files((2, 2, 3)) if k.endswith("auth_utilisation")]
    # one process of a one-core cell does not record the end of the authentication: the intervals of the other alone
    # would understate the core, so the cell has no figure
    rows = files((3, 3), unrecorded=(1,))
    assert not [k for k in rows if k.endswith("auth_utilisation")] and "periodic.p10ms-s2-c1-mldsa65-fifo-cyclic-mf1ms-sync-parts2.jobs" in rows


def test_four_sender_processes_on_four_cores(tmp_path):
    """E6c (H5): nothing is made for two processes only. Four processes on cores 0 to 3: four cores, every process with
    its keys and its model."""
    s, rows = cell(tmp_path, "four_cores", (0, 1, 2, 3))
    name = "periodic.p10ms-s8-c4-mldsa65-fifo-cyclic-mf1ms-sync-parts4"
    assert [rows[f"{name}.{k}"] for k in ("partitions", "cores", "streams", "jobs", "misses")] == ["4", "4", "8", "96", "12"]
    for i in range(4):
        part = f"periodic.p{i}.p10ms-s2-c1-mldsa65-fifo-cyclic-mf1ms-sync-part{i}."
        assert rows[part + "misses"] == "3" and part + "model_utilisation" in rows and part + "auth_utilisation" in rows
    assert s["invalid_runs"] == []
    # a cell with a core per process reads as before
    assert HOW[name + ".cores"] == "cores of the cell, added over the 4 partitions (independent processes) of the cell"
    # files that do not say where they were pinned (written before the harness wrote the line): the cores are added, as before
    s, rows = cell(tmp_path, "unpinned", (None, None))
    assert "periodic.p10ms-s4-c2-mldsa65-fifo-cyclic-mf1ms-sync-parts2.jobs" in rows and [k for k in rows if ".model_" in k]


def test_the_note_of_the_combined_table_is_true_for_the_layout_of_its_cell(tmp_path):
    """The note above tables/periodic_combined says what the files of the cell say: a core per process (their
    cpu_affinity lines all differ; core 0 is a core), processes that share a core (two lines name the same one, also when
    the cell has a second core), and, where a file has no such line, neither of the two."""
    def note(name, cores):
        cell(tmp_path, name, cores)
        md, tex = ((tmp_path / (name + "_out") / "tables" / f"periodic_combined.{ext}").read_text().splitlines()[0] for ext in ("md", "tex"))
        assert md == f"<!-- {tex[2:]} -->" and tex.startswith("% a cell measured as several partitions: ") and "--" not in tex
        return tex
    own, shared, unknown = note("own", (0, 3)), note("shared", (3, 3, 3, 3)), note("unknown", (None, None))
    assert "independent gateway processes side by side, each with its own streams, queue and core; releases and misses are " \
        "added over them (streams and cores are the sums); interval:" in own
    assert "sender processes side by side that share a core, each with its own streams and queue; releases and misses are " \
        "added over them; streams are the sum, the cores column is the number of distinct cores; interval:" in shared
    assert "sender processes side by side, each with its own streams and queue; releases and misses are added over them; " \
        "streams are the sum; the cores column is the number of distinct cores when every file of the cell records where " \
        "its process was pinned (cpu_affinity), else the sum of the cores the files name; interval:" in unknown
    assert note("two_of_three", (2, 2, 3)) == shared and note("one_unrecorded", (3, None)) == unknown
    # the rest of the note is the same for every layout
    assert len({n.split("; interval:")[1] for n in (own, shared, unknown)}) == 1


def test_a_staggered_cell_has_its_phase_in_the_name_and_its_misses_judged_per_job(tmp_path):
    """E6p (H3): '# phase=staggered'. Stream 1 of the synthetic file is released 5 ms after stream 0, half a period for
    two streams. The deadline is that of every job from its own release: stream 0 misses three (12, 13 and 11 ms)."""
    run_dir = tmp_path / "run"
    (run_dir / "periodic").mkdir(parents=True)
    (run_dir / "periodic" / "periodic_tx.csv").write_text(synth.periodic_tx_two_streams(**{**BENCH, "phase": "staggered"}))
    make_tables.run(run_dir, tmp_path / "out", **PARAMS)
    with open(tmp_path / "out" / "numbers.csv", newline="") as f:
        rows = {r["key"]: r for r in csv.DictReader(f)}
    base = "periodic.p10ms-s2-c1-mldsa65-fifo-cyclic-mf1ms-staggered."
    assert (rows[base + "jobs"]["value"], rows[base + "misses"]["value"], rows[base + "s0.misses"]["value"], rows[base + "s1.misses"]["value"]) == \
        ("24", "3", "3", "0")
    # the model keys are those of every cell: the one to set beside the measurement takes the release offsets measured in
    # the file (here the staggered ones); the synchronous and the random release are other patterns, and their keys say so
    assert "measured release offsets" in rows[base + "model_measured_offsets"]["how"]
    assert "synchronous" in rows[base + "model_synchronous"]["how"] and base + "model_random_mean" in rows


def test_a_gateway_run_with_a_restart_counts_what_was_lost(tmp_path):
    """E3r (H1). Restart of the receiver: 12 PDUs sent; the first receiver process delivers 0 to 4, its successor rejects
    5 and 6 at the freshness stage and delivers 7 to 11. lost = sent PDUs without a delivered row = 2."""
    seven = [(0, q, "freshness_fail") for q in (5, 6)] + tf.plain(0, range(7, 12))
    s, rows = tf.run(tmp_path, "restart_rx", {
        "app_tx.csv": tf.app_tx(tf.plain(0, range(12)), nodelay=("1", "1")),
        "app_rx.csv": tf.app_rx(tf.plain(0, range(5))), "app_rx2.csv": tf.app_rx(seven),
        "rx_payload.csv": tf.payload(tf.plain(0, range(5))), "rx_payload2.csv": tf.payload(tf.plain(0, range(7, 12))),
        "handshake_tx.csv": tf.handshake("initiator", ["ok", "ok"], "iris", nodelay=("1", "1")),
        "handshake_rx.csv": tf.handshake("responder", ["ok"], "baolong"), "handshake_rx2.csv": tf.handshake("responder", ["ok"], "baolong")})
    got = {k.removeprefix("functional."): r["value"] for k, r in rows.items() if k.startswith("functional.")}
    assert s["invalid_runs"] == []
    assert [got[k] for k in ("sent", "delivered", "lost", "s0.lost", "rejected_freshness_fail", "initiator.n", "initiator.result_ok",
                             "responder.n", "responder.result_ok", "tx.parts", "rx.parts")] == ["12", "10", "2", "2", "2", "2", "2", "2", "2", "1", "2"]
    assert "delivered_in_order" in rows["functional.lost"]["how"] and "sent" in rows["functional.lost"]["how"]
    # restart of the sender: its successor counts from 0 again (two runs of sequence numbers); nothing is lost
    s, rows = tf.run(tmp_path, "restart_tx", {
        "app_tx.csv": tf.app_tx(tf.plain(0, range(5))), "app_tx2.csv": tf.app_tx(tf.plain(0, range(7))),
        "app_rx.csv": tf.app_rx(tf.plain(0, range(5)) + tf.plain(0, range(7)), nodelay=("1", "1")),
        "rx_payload.csv": tf.payload(tf.plain(0, range(5)) + tf.plain(0, range(7)), nodelay=("1", "1")),
        "handshake_tx.csv": tf.handshake("initiator", ["ok"], "iris"), "handshake_tx2.csv": tf.handshake("initiator", ["ok"], "iris"),
        "handshake_rx.csv": tf.handshake("responder", ["ok", "ok"], "baolong", nodelay=("1", "1"))})
    assert s["invalid_runs"] == [] and [rows["functional." + k]["value"] for k in ("sent", "delivered", "lost", "tx.parts", "initiator.n")] == [
        "12", "12", "0", "2", "2"]
