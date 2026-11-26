# PQC-SecOC analysis toolkit

Turns a run directory of raw measurement files (formats: `DATA_SCHEMA.md`) into its tables, figures
and numbers; `sessions` sets the sessions of an experiment side by side, and `merge_numbers` joins
the analyzed runs of the campaign into the one `numbers.tex` of the paper.

## Requirements

- Python 3, with the standard library, numpy and scipy only.
- matplotlib is optional: without it the figures (`figures/*.pdf`) are not written and everything
  else is.
- pytest for the test suite; the LaTeX tests need `pdflatex` and are skipped when it is not
  installed.

## Commands

Run from the toolkit root. Under `python3 -I` (required when the run directory is untrusted) call
the scripts by path instead; the package then adds the user site-packages itself, because `-I`
hides it and numpy may live there.

| Command | What it does |
|---|---|
| `python3 -m analysis.make_tables <run_dir> --out <dir> [--key-prefix e1.s1.iris]` | Analyses everything it finds below `<run_dir>` and writes `tables/*.md`, `tables/*.tex`, `figures/*.pdf`, `summary.json`, `numbers.tex`, `numbers.csv`, `number_keys.md`, `suppressed_keys.txt` into `<dir>` |
| `python3 -I <toolkit>/analysis/make_tables.py <run_dir> --out <dir>` | The same, isolated |
| `python3 -m analysis.make_numbers <dir> [--out numbers.tex] [--key-prefix p]` | Rebuilds `numbers.tex`, `numbers.csv`, `number_keys.md` and `suppressed_keys.txt` from `<dir>/summary.json` |
| `python3 -m analysis.merge_numbers <dir> <dir> ... --out all.tex [--allow-marked]` | One `numbers.tex` for the manuscript from the analysis directories of several runs (below) |
| `python3 -m analysis.sessions --out <dir> <session dir> <session dir> ...` | Sessions of one experiment side by side: `sessions.md` / `.tex` (one row per session and statistic) and the smallest and largest session value of each quoted statistic as number keys; nothing is pooled |
| `python3 -I <toolkit>/analysis/clock_rate.py <inputs.tsv> --runs-root <dir> --out <dir> --key-prefix clock.e9p1` | Keys about the two boards' clocks from a list of clock probe files with their sha256 ("The clocks themselves"); no PDU, no latency |
| `python3 -m analysis.simulate <crypto_ops.csv> --op mldsa_sign --period-ms 10 --streams 3` | Modeled deadline-miss ratio from a measured service-time sample |
| `python3 -I -m pytest <toolkit>/analysis/tests` | The test suite ("Tests" below) |

`make_tables` options: `--seed` (bootstrap and model, recorded in `summary.json`), `--warmup`
(default 1000), `--block-len` (100), `--n-boot` (2000), `--thresholds-ms` (5,10,15,20), `--trim`
(0; throughput files), `--sim-draws` (20, 0 disables the model), `--sim-jobs` (200000), `--no-figures`,
`--key-prefix`. A short dry run needs `--warmup 0 --block-len 10`. Without `--out` the
output goes to `./analysis_out/<run_dir name>`, never into the run directory.

Any malformed row, missing header key or inconsistent file stops the run with the file (and line)
named; nothing is skipped silently and nothing is written after a failed check of the number keys.

Exit codes of `make_tables`: 0 done; 1 stopped by an error, nothing usable written; 2 wrong command
line; 3 everything was written, but at least one file was left unanalyzed as invalid (see
"Validity"). Re-running into an existing output directory replaces it: tables and figures that the
new run does not produce are removed.

## Tests

    python3 -I -m pytest <toolkit>/analysis/tests

The seven legacy regression tests (`analysis/tests/test_regression.py`) need the dataset of the
submitted version in the directory named by the environment variable `PQC_LEGACY_RUN` and are
skipped when it is absent. The LaTeX tests need `pdflatex` and are skipped when it is not
installed.

## Modules

The package is `analysis/`; its tests are in `analysis/tests/`.

| Module | Reads | Computes or writes |
|---|---|---|
| `__init__.py` | Nothing of a run | Makes the user site-packages importable under `python3 -I`; `toolkit_commit()`, the toolkit identity |
| `attack.py` | The columns of `attack.csv` | Per vector: delivered, rejected, the rejection rate with its Wilson and its exact Clopper-Pearson 95% interval, counts per reject stage, the time to detect over the rejected PDUs |
| `crypto_ops.py` | The columns of `crypto_ops.csv` (`op`, `seq`, `ns`) | Per op, with `seq < warmup` dropped: the sample summary and the moving-block bootstrap 95% intervals of the median and p99; for signing ops the exceedance per threshold, the time beyond 10 ms, the pairs of consecutive calls above a threshold, and the tail shape with its fit and expected counts |
| `csvio.py` | The CSV files of a run directory, their `# key=value` lines, the marker files and `env_<host>.txt` | Finds the files by name, validates header and rows against the schema, converts the three legacy files, and judges validity (trailer, counters, throttling, transport lines, jobs, footer counts) |
| `cyclictest.py` | `cyclictest*.txt` | Run conditions, sample count, cyclictest's min / avg / max, the percentiles read from the 1 µs histogram, the late wake-ups, validity |
| `e2e.py` | The columns of `clock_probe.csv` beside a sender and receiver pair, `background_traffic.txt`, the probe files of a `probetest` directory | The offset track of the probe with its bounds, the end-to-end latency of every delivered PDU on one clock, the reasons why a run is not a result for E9, the two tests of the method |
| `figures.py` | The samples and results that `make_tables` hands over | The optional PDF figures (needs matplotlib) |
| `footprint.py` | `size_*.txt`, `perf_<op>_<n>.csv`, `rss_samples.txt` | Binary and section sizes, instructions and cycles per call from a pair of runs, the largest VmHWM per host; counts only |
| `functional.py` | The files of a directory with the marker `FUNCTIONAL` (`app_tx*`, `app_rx*`, `rx_payload*`, `handshake_tx*`, `handshake_rx*`) | PDUs sent, delivered, delivered in order and byte-exact, rejected per result class, handshake rows, TCP connections; counts only |
| `handshake.py` | The columns of `handshake.csv` | Per role: attempts and counts per result; over the successful handshakes the total time, the compute time, the time of every stage and the message bytes |
| `hsneg.py` | `hsneg.txt` | The oracle's record of a negative handshake test, its key label, and the reasons why its `seen` counts are not those of the handshake files |
| `make_numbers.py` | `summary.json` of an analysis directory | The number keys with their formatting and the percentile rule: `numbers.tex`, `numbers.csv`, `number_keys.md`, `suppressed_keys.txt` |
| `make_tables.py` | A run directory | Finds and checks the files, runs the analyses of the other modules, and writes `tables/*.md`, `tables/*.tex`, `figures/*.pdf`, `summary.json` and the numbers files |
| `merge_numbers.py` | The analysis directories of several runs | One merged `numbers.tex` with its `.csv` and its list of suppressed keys |
| `overhead.py` | The columns of `overhead_paired.csv`, `equivalence_margin.txt`, the legacy `phase_compare.csv` | The paired comparison within a launch and across launches (Hodges-Lehmann estimates, TOST against the margin), and the unpaired comparison of the legacy file |
| `periodic.py` | The columns of `periodic_tx.csv`, `periodic_rx.csv` and `clock_offset.csv` | The configuration id, deadline misses and miss ratio with its intervals, response, queueing, authentication and service time, the combined miss ratio of a multi-partition cell, the receiver's counts and times, cross-host latency |
| `sessions.py` | The analysis directories of the sessions of one experiment | `sessions.md` / `sessions.tex` and the smallest and largest session value of each quoted statistic as number keys |
| `sign_attrib.py` | The columns of `sign_attrib.csv` (`seq`, `wall_ns`, `cpu_ns`, optionally `shake_calls`) | Wall time against processor time of every signing call, the time off the processor, the tail attribution, the rounds of a counting run and the line of processor time on rounds |
| `simulate.py` | A service-time sample (`crypto_ops.csv` or the legacy `tx_perf_10k.csv` on the command line) | The modeled deadline-miss ratio of the trace-driven queue model, also for the model columns of the `periodic` table |
| `stats.py` | Arrays of values | The shared statistics: sample summary with type 7 percentiles, lag-1 autocorrelation, Student-t interval of a mean, moving-block bootstrap, Wilson and Clopper-Pearson intervals, Hodges-Lehmann estimates, Mann-Whitney and Wilcoxon tests, TOST on log values, miss runs and windows, Poisson regression |
| `tables.py` | Rows of cells | The Markdown and LaTeX table files; `rounded()` and `significant()`, the one rounding of every printed number |
| `throughput.py` | The columns of `throughput.csv` | Per file the steady-state rates, CPU, wire rate and send queue; per repetition the loss ratio and whether the rate was sustained; per step and ladder the verdict, the saturation point and the sensitivity line without retransmissions |

## What is read from the run directory

CSV files are found recursively by name, `<kind>.csv` or `<kind>_<label>.csv`, and their header row
is validated. Lines starting with `#` and blank lines are ignored wherever they stand;
`# key=value` lines are metadata. CSV files with any other name are listed in `summary.json` under
`skipped_csv`.

| File | Rules beyond the schema |
|---|---|
| `crypto_ops.csv` | `seq < warmup` dropped per op; self-checks (Validity) |
| `sign_attrib.csv` | `seq,wall_ns,cpu_ns` with an optional fourth column `shake_calls` (experiment E1a, `crypto_attrib/sign_attrib_p<payload>.csv`); `seq` contiguous from 0, `seq < warmup` dropped; self-checks as `crypto_ops.csv` plus three row rules (below) |
| `overhead_paired.csv` | `seq < warmup` dropped; needs `equivalence_margin.txt`; self-checks; `# mode=aa` marks an A/A noise-floor file; `# launch=<n>` (or a file label `L<n>`, `launch<n>`) marks one launch of a set |
| `periodic_tx.csv` | All nine header keys mandatory; the optional keys `mainfunction`, `mf_period_us`, `phase`, `partition` are validated and become part of the configuration id; the files of a multi-partition cell (`periodic_tx_p<i>.csv`) also get a combined miss ratio (below); a `periodic_tx*.csv` / `periodic_rx*.csv` inside an `attack*`, `throughput*` or `calibration*` directory is the load generator's traffic log and is listed, not analyzed; one row per released job, `seq` contiguous from 0 per stream; a stage written as 0 was not reached, unless `# not_recorded=auth_done_ns` declares that the binary has no such timestamp |
| `periodic_rx.csv` | Paired with the `periodic_tx` file of the same directory and label; stage rules per result as in the schema; `framing_fail` rows carry `stream = seq = -1`, name no job and are only counted; `# not_recorded=rx_done_ns` is accepted (below) |
| `clock_offset.csv` | Serves the `periodic_rx` files of its directory (at most one per directory) |
| `clock_map_a.csv`, `clock_map_b.csv` | E9, Addendum E: the relation of a board's CLOCK_MONOTONIC and CLOCK_MONOTONIC_RAW, sampled every 5 ms by the probe; read beside a `clock_probe.csv` of format 2 only |
| `clock_probe.csv` | E9: the two-way exchanges of the clock probe, beside a periodic pair (at most one per directory); gives the keys `<config>.e2e.*` ("End-to-end latency across the two boards") |
| `throughput.csv` | Five header keys mandatory; one host and one rate per file; files of one directory with the same header (apart from `partition` and `rep`) form one ladder; the partitions of a rate step are summed and its repetitions analyzed one by one (below); an optional 13th column `proc_cpu_ns`: the cumulative processor time of the harness process |
| `attack.csv` | As in the schema; with `# oracle=gateway_app_log` the detection times are "not recorded" (that oracle writes `detect_ns` = 0 by construction) and get no keys |
| `handshake.csv` | Columns as in the schema (with `hash_ns`, `mac_ns`); `result` is one of the eight values of the schema; `# mainfunction=`, `# mf_period_us=`, `# t_min_ms=` are recorded; one file per host (`handshake/handshake_<host>.csv`), keyed by the host its `# host=` line names; a `handshake*.csv` inside an `attack*`, `throughput*` or `calibration*` directory, or in a subdirectory of one (`throughput/handshake_100pps_rep1/handshake_tx.csv`), is the session set-up before an attack run or a ladder step: listed, not analyzed. So is a handshake file with a `periodic_tx*.csv` or `periodic_rx*.csv` beside it (the one handshake before a periodic run), and one whose header says `pdu_stream` other than `none` (a PDU stream ran beside the handshakes); a file without that line does not say so and stays a handshake experiment unless one of the other two tests applies |
| `hstest*/…/handshake*.csv`, `hsneg.txt` | A negative handshake test: the handshake files in or below an `hstest*` directory (one pair per run; a batch has `hstest/r001/`, `r002/`, …) are counted per side and result class and never timed; `hsneg.txt` beside the directory is the oracle's record, one line `test=… verdict=…` in the format of the schema (a file without that line gives no record). A `periodic_tx*.csv` / `periodic_rx*.csv` there is the harness's traffic log, listed and not analyzed |
| `FUNCTIONAL` and, beside it, `app_tx*.csv`, `app_rx*.csv`, `rx_payload*.csv`, `handshake_tx*.csv`, `handshake_rx*.csv` | A functional run of the gateway binaries: counts only (below, "Functional runs"). Only in a directory that holds the marker; elsewhere the three gateway files stay unread |
| `cyclictest*.txt` | Output of `scripts/run_cyclictest.sh`: conditions, 1 µs histogram, cyclictest's summary lines |
| `size_*.txt`, `perf_<op>_<n>.csv`, `rss_samples.txt` | Footprint figures taken with standard tools (E8): counted, nothing timed ("Footprint figures") |
| `env_<host>.txt` | In the run directory: the `get_throttled` reading of every `===== before/after =====` block (Validity) |
| `DRY_RUN`, `PILOT`, `EXCLUDED` | Marker files in the run directory: nothing there is a result (below) |
| `phase_compare.csv`, `tx_perf_10k.csv`, `attack_raw.csv` | Legacy files of the dataset of the submitted version, converted on reading |

### Wall time and processor time of every signing call (sign_attrib)

`off` = `wall_ns − cpu_ns` of a call is, by the schema, the time the pinned thread did not run
during it (how interrupt time is counted depends on the kernel option named in the run record).
"Above" is strict everywhere.

- **Invalid file** (listed, not analyzed, exit code 3), besides the `crypto_ops` self-checks: the
  `cpu_ns` of all rows, warm-up included, differ from the footer's `cpu_s` by more than 1% (the
  footer also covers set-up, the probe calls of a counting run and the clock reads, so a counting
  run of only a few thousand calls fails this rule by construction); a row
  has `wall_ns < cpu_ns − 2000`; a `shake_calls` value is not `shake_calls_min` plus a whole
  multiple of `shake_calls_step`. Four columns without the two header lines, three columns with a
  `shake_counted` other than `off`, or a `seq` that is not contiguous from 0 are errors.
- **Per file** (table `sign_attrib`): `n`; the median and the mean of the wall time and of the
  processor time of a call, `wall_p50_us`, `wall_mean_us`, `cpu_p50_us`, `cpu_mean_us` (keys only;
  in a counting run they include the counting, and no higher percentile and no exceedance share is
  formed here: those belong to the `crypto_ops` series). The two medians carry the interval the E1
  median has, `wall_p50_ci95_lo_us`, `_hi_us` and `cpu_p50_ci95_lo_us`, `_hi_us`: the moving-block
  bootstrap with the run's `--block-len` and `--n-boot`, when two blocks fit; a median then prints
  with the decimals its interval needs, so the medians of a plain and of a counting run can be
  told apart or seen to agree. The means have no interval. Further: `off_min_us`, `off_median_us`, `off_max_us`; the calls
  with off above 100 µs, 1 ms and 5 ms (`off_over_100us.k`, `off_over_1ms.k`, `off_over_5ms.k`).
  Every call carries a floor of a few microseconds that is time on the processor (the two inner
  clock reads lie inside the wall interval and outside the processor-time interval); the median
  off shows its size. Time off the processor is therefore read from `header.off_cpu_s` (the
  footer's `wall_s − cpu_s`, whole file), from the counts, and from the off above the floor:
  `off_above_floor.k` calls whose off is more than 100 µs above the median, and
  `off_above_floor_s`, the sum of their off minus the median. The plain sum `off_total_s` contains
  the floor n times; it stays in `numbers.csv` and `summary.json`, has no macro, and is listed in
  `suppressed_keys.txt` with that reason.
- **Tail attribution** (table `sign_attrib_tail`), for wall time above 5, 10, 15 and 20 ms:
  `wall_over_<t>ms.k` calls; `wall_over_<t>ms.cpu_also_over` of them whose processor time is above t as well;
  `wall_over_<t>ms.max_off_us`, the largest off among them; `wall_over_<t>ms.rounds_min`, the
  fewest rounds among them; `wall_over_<t>ms.calls_with_rounds_min_or_more`, the calls of the whole
  sample with at least that many rounds (equal to `wall_over_<t>ms.k` when the two sets coincide).
  One call that was off the processor is enough to move `wall_over_<t>ms.rounds_min`, so the
  rounds are set against processor time:
- **Processor time against rounds** (table `sign_attrib_two_by_two`, files with `shake_calls`),
  for the same four thresholds, the calls taken by processor time whatever their wall time:
  `cpu_over_<t>ms.k` calls with processor time above t (also for a file without `shake_calls`; it
  differs from `wall_over_<t>ms.cpu_also_over` only by calls with processor time above t and wall
  time not above t, which the row rule allows within 2 µs); `cpu_over_<t>ms.rounds_min`, the fewest
  rounds among them, and `cpu_over_<t>ms.calls_with_rounds_min_or_more` (no key when no call is
  above t). `rounds_threshold_<t>ms` is the smallest whole number of rounds r ≥ 1 for which the
  fitted line (next item) is above t, and `cpu_vs_rounds_<t>ms.both`, `.cpu_only`, `.rounds_only`,
  `.neither` count the calls of the whole sample by processor time above t or not against at
  least r rounds or fewer (`both` + `cpu_only` = `cpu_over_<t>ms.k`; zeros are written). Calls
  with exactly r rounds, or one fewer, fall on either side of t by where the line crosses it within
  that round; beyond that one-round ambiguity, `cpu_vs_rounds_<t>ms.cpu_only_below_crossing` counts
  processor time above t with fewer than r − 1 rounds, and `.rounds_only_above_crossing` processor
  time not above t with more than r rounds. No threshold and nothing that needs it without a line
  or with a line that does not rise.
- **Shares** (table `sign_attrib_shares`): `cpu_over_<t>ms.share` = `cpu_over_<t>ms.k` / n (also
  for a file without `shake_calls`); `rounds_at_least_threshold_<t>ms.k` and `.share`, the calls
  with at least `rounds_threshold_<t>ms` rounds; each share with its exact Clopper-Pearson 95%
  interval `.share_cp95_lo`, `.share_cp95_hi` (independent calls assumed); and
  `rounds_at_least_threshold_<t>ms.share_geometric` = (1 − `rounds_one_share`)^(r − 1), the share of
  calls with at least r rounds under a geometric law with the measured one-round share, with
  `.share_geometric_lo` and `.share_geometric_hi`, the same formula at the two ends of the exact
  95% interval of the one-round share (`rounds_one_share_cp95_lo`, `_hi`; r is taken as given, so
  the uncertainty of the fitted line is not in them). No geometric keys when no call has one round.
- **With `shake_calls`** (an instrumented run: its times include the counting): rounds =
  (`shake_calls` − `shake_calls_min`) / `shake_calls_step` + 1; `rounds_mean`, `rounds_one_share`,
  `rounds_max`, and `rounds_mean_geometric` = 1 / `rounds_one_share`, the mean of a geometric law
  with the measured one-round share, next to the measured mean. Table `sign_attrib_rounds` gives
  per number of rounds n, the share, the share under that geometric law and the mean processor
  time. The ordinary least-squares line of processor time on rounds gives `cpu_per_round_us`,
  `cpu_intercept_us`, `r2`, and of its residuals `resid_sd_us` (divisor n − 2), `resid_p0_1_us`,
  `resid_p99_9_us` (type 7), `resid_min_us`, `resid_max_us`. No line when every call has the same
  number of rounds. Figure `sign_attrib_cpu_vs_rounds_paper.pdf` is the same figure for the paper:
  its legend does not name the file, and it has a thin line at 10 ms. Figure `sign_attrib_cpu_vs_rounds.pdf`: per number of rounds the mean and the
  range of the processor time, with the line.
- **Keys:** `crypto_attrib[.<directory label>].<file name without .csv>.<quantity>`, for example
  `crypto_attrib.sign_attrib_p8.off_above_floor_s`; header lines under `….header.<name>`.

### Equivalence margin

`<run_dir>/equivalence_margin.txt` holds one number, the relative margin of the equivalence test
(`0.01` means the geometric mean of csm/standalone must lie in [1/1.01, 1.01]). `#` comments are
allowed. It must be written before the data is collected: if `overhead_paired.csv` is present and
the file is missing or malformed, `make_tables` stops before reading any data. A file whose comment
calls it a placeholder is an error too, unless the directory is marked `DRY_RUN` or `PILOT`. The
legacy `phase_compare.csv` is tested against 1% and 2%, and those results are labeled post hoc.

In the campaign the A/A noise-floor block and the A/B block are two run directories, because the
margin is written between them. A directory whose paired files are all A/A files (`# mode=aa`)
needs no margin file and is not judged. The A/B directory carries `equivalence_margin.txt`; its
comment lines, which name the A/A block the margin was derived from, are copied with the value and
the file's SHA-256 into `summary.json` (`equivalence_margin`) and into the note of the
`overhead_across_launch` table. A directory with both blocks still works.

### The archived comparison of the submitted version (secondary, labeled)

`phase_compare.csv` of the dataset of the submitted version holds four phases, each a contiguous block of 11,000 rows in
this order: standalone signing, standalone verification, Csm-integrated signing, Csm-integrated
verification. The two phases of an operation therefore ran one after the other in one run: they are
not paired and not interleaved, and a change of the system between them is part of every
difference. The margins of 1% and 2% were chosen after the data had been seen. Every key of this
comparison says both in its definition. It is reported as a labeled secondary analysis; the paired,
launch-level E2 is the primary one.

Per operation, with `seq` < warm-up dropped (10,000 samples per phase at the default 1,000) and each
phase taken in the order of `seq`: the medians and their relative difference, the two-sample
Hodges-Lehmann shift with its 95% interval, Cliff's delta, the two-sided Mann-Whitney p, the two
one-sided Welch t-tests on log times at each margin (the larger p; the upper tail through the
survival function, the lower one through the distribution function of a negative argument, never
`1 - cdf`), and:

- `lag1_standalone`, `lag1_csm`: the lag-1 autocorrelation of each phase;
- `median_rel_diff_bb90_lo/hi`: the moving-block bootstrap 90% interval (percentile method) of
  median Csm / median standalone − 1, blocks of `run.block_len` consecutive samples resampled
  within each phase, `run.n_boot` resamples, seeded per file.

Both see dependence within a phase only: a drift between the two phases is confounded with the
comparison and no resampling can show it.

Command (the one file copied to a directory of its own, `perf/` kept so that the keys carry the
label of the dataset):

    python3 -I analysis/make_tables.py <copy with perf/phase_compare.csv> --out <dir> --key-prefix archive.e2

Keys: `archive.e2.overhead_unpaired.perf.<sign|verify>.<name>`.

### Figures formed from measured ones

Each is arithmetic on figures that are measured, kept as a key so that no number is formed by
hand. None changes an existing key. The name or the definition says what is assumed.

- **Handshake, amortised.** `handshake.<label>.<role>.compute_mean_per_pdu_session1000_us` (and
  `_ms`): the role's mean own computation per handshake (`compute_mean`) divided by 1,000, the cost
  per PDU when one handshake serves a session of 1,000 PDUs. `handshake.both_roles.…` is the sum of
  the two roles, emitted when a directory holds exactly one initiator and one responder. The
  session length is an assumption (`handshake.SESSION_PDUS`), not a measurement.
- **Signing series: neighbors and two attempts.** Per signing operation and threshold, beside
  `exceed_<t>ms.k` and `.p`: `exceed_<t>ms.adjacent_pairs.k`, the pairs of consecutive calls (in
  the order of `seq`) that are both above the threshold; `exceed_<t>ms.adjacent_pairs_if_independent`
  = (n − 1) (k / n)², their expected number if the calls were independent; and
  `exceed_<t>ms.p_squared_estimate` = (k / n)², the share above the threshold if two independent
  signing attempts ran side by side and the first to finish were taken. The last one is an
  estimate from an assumption (independent attempts, each with the measured share, neither slowed
  by the other), not a measurement. The lag-1 autocorrelation of the series is the existing key
  `lag1`.
- **Counting run: line and law.** `line_and_law.p50_rounds`, `.p99_rounds`, `.p99_9_rounds`: the
  smallest number of rounds r with 1 − (1 − `rounds_one_share`)^r at or above 0.5, 0.99, 0.999
  under the geometric law; `line_and_law.p50_cpu_us`, `.p99_cpu_us`, `.p99_9_cpu_us` (and `_ms`):
  the least-squares line of processor time on rounds at that many rounds. These are model
  figures. Beside them stand the measured `cpu_p50`, `cpu_p99` and
  `cpu_p99_9` of the same run (the times of a counting run include the counting).
  `rounds_at_least_threshold_<t>ms.share_geometric_extrapolation` repeats
  `…share_geometric` under the name of what it is whenever no call of the run has
  `rounds_threshold_<t>ms` rounds: the law extended beyond the data.
- **Ladder: growth of the send queue.** `…rep<k>.tx.sendq_growth_bytes`: the fitted slope of the
  send-queue depth times the length of the window (with several partitions, each connection's,
  added); per step `sendq_growth_bytes_mean`, `_t95_lo/hi`, `_min`, `_max` over the repetitions.
  The verdict does not use it: that is `sendq_growth_lo95_bytes`.

### Keys added by the coverage audit (2026-11-25)

Figures that the documents print and for which no key existed. Each is a plain ratio of quantities
the toolkit already read.

- **Measured utilization of a periodic cell** (`periodic.<config>.auth_utilisation`, unit
  `percent`): the time covered by the intervals from `start_ns` to `auth_done_ns` of the jobs of
  all streams of the sender's file, divided by the time from the smallest `release_ns` to the
  largest `send_done_ns` of the file; n = the jobs with an authentication time. Covered time, not
  the sum of the lengths: the jobs of the streams of one cycle start together and are
  authenticated one after the other, so the intervals of a file with several streams overlap
  and their lengths add up to more than the covered time. No key where `auth_done_ns` is declared not recorded. A cell of several
  sender processes has one key per file. There is no such key for the receiver: the interval from
  `rx_done_ns` to `verify_done_ns` holds the wait for the next cycle of the receiver's main
  function (about 1 ms for a MAC that is verified in microseconds), so the files do not carry the
  time of the verification call. `model_utilisation` is arithmetic from the mean
  service time.
- **Line and law against the measured percentiles** (counting run:
  `crypto_attrib.<file>.line_and_law.p50_cpu_rel_diff`, `p99_cpu_rel_diff`, `p99_9_cpu_rel_diff`,
  unit `percent`, signed): `line_and_law.<q>_cpu` ÷ the measured `cpu_<q>` of the same run − 1.
  What enters the model: the share of calls with one round (`rounds_one_share`), which fixes the
  geometric law, and the least-squares line of processor time on rounds (`cpu_intercept`,
  `cpu_per_round`), all of the same counting run; the measured side is the type-7 percentile of
  that run's processor times. A difference from a percentile that is held back is held back.
- **PDUs lost in a functional run** (`functional[.<directory>].lost` and `.s<k>.lost`, for the
  gateway runs with a restart, a rekey or a replaced key pair of Addendum H, H1): `sent` −
  `delivered_in_order`, the PDUs the transmitting gateway sent that are not among the delivered
  ones met in the order they were sent. A PDU that the receiver rejected at the freshness stage has
  no delivered row and is among the lost ones; `rejected_freshness_fail` counts those rows. The
  handshakes of each side have their own keys (`<role>.n`, `<role>.result_ok`).
- **Packet capture of a calibration run** (`capture[.<directory>].<host>.`, from
  `capture_<host>.txt`, the driver's summary of the capture taken on the sending board):
  `frames_with_payload`, `tcp_payload_bytes`, `frame_bytes` (the file's three lines),
  `jobs_confirmed` (its `# jobs_confirmed=` line), and `frames_per_pdu` = frames ÷ PDUs,
  `frame_bytes_per_frame` and `tcp_payload_bytes_per_frame` = bytes ÷ frames. Nothing is taken
  off: the capture also holds the frames of the session set-up. They are frames on the wire only
  when segmentation offload is off on that board (`offload_<host>.txt` beside the file, which the
  toolkit does not read). A file of the name that lacks one of the four lines stops the run.

### Stages a binary does not record

`# not_recorded=<column>` in a periodic file says that the writing binary has no timestamp for that
stage (the gateway application before its timestamp hooks): the column is 0 in every row and those
zeros are not missed stages. Two columns can be analyzed that way. `auth_done_ns` in a Tx file: the
authentication time is "not recorded", everything else is unchanged. `rx_done_ns` in an Rx file: the
counts are unchanged, arrival order is the order of `verify_done_ns`, and verification time,
delivery time, reject-decision time and cross-host latency are not reported. Any other column in
that line, or a named column that carries a value, is an error; so is a column of zeros without the
line. A stage that is not recorded gets no number key.

### Partitions of a throughput ladder

A multi-core run is one file pair per gateway process, told apart by `# partition=` (the harness
writes `partition=0` for a single process too). The partitions that offer the same rate are one
rate step whose offered rate is the sum of theirs: `PARTITIONS=4` at 350 PDU/s is four processes
offering 87 each, a step of 348. Per step and host the table and the keys give the sum: PDU/s added
interval by interval (aligned from the start of each steady-state window, over the intervals the
shortest partition has) with the Student-t interval of those sums; CPU as busy / total jiffies over
the partitions' cores; drops added; send queue: mean depths added, maximum of the deepest
connection, growing if any connection is (each one is judged against the size of one PDU of the
step, below). The interface counters are the host's, so the wire rate is taken from one partition
and never added, and the bytes per PDU divide by the PDUs of all partitions. The ladder's `cores` is the header's `cores` (per process)
times the number of partitions, which is the number of indices found: they must be 0..N-1, and a
step that lacks a partition on a host is not judged. When the files carry `# partitions=N` that
number is used; without it a run whose last partition is missing on both hosts in every step cannot
be told from a smaller run.

### Repetitions of a throughput ladder, loss ratio and verdict

The repetition is the unit of replication, as the launch is for the paired files. A file's
repetition number is its `# rep=` line, else `rep<k>` in its file label
(`throughput_tx_400pps_rep2_p0.csv`); the files of a ladder either all have one or none has. Two
files for the same host, rate, repetition and partition stop the run. Every repetition of a rate
step is analyzed on its own; the 1-second samples of different repetitions are never pooled.

- **Loss ratio of a repetition.** From the cumulative counters of both hosts over the same sample
  indices of the steady-state window (the two samplers start with the first PDU after the ramp and
  tick once per second): offered = `pdus_done` + `drops` of the generator; not delivered (the key
  `lost_pdus`) = offered − the receiver's `pdus_done`, not below 0; added over the partitions. The
  loss ratio is not delivered / offered. It is an end-to-end figure of the window: releases the
  generator dropped at a full queue, PDUs sent and not yet delivered when the window ends, and
  anything the receiver did not deliver. It is not a count of PDUs lost by the stack or by the
  network (`DATA_SCHEMA.md`, "Jobs given up, and what loss means in a ladder"). It
  is printed with its exact Clopper-Pearson interval. A tx and an rx file with different numbers of
  samples cannot be compared: that repetition is not judged.
- **What the transmitter alone dropped** stands next to it: the releases dropped at a full queue
  (`dropped_pdus` of a repetition; per step `tx_drop_ratio_mean`, `_t95_lo/hi`, `_min`, `_max`, the
  share of the offered PDUs), so that a reader sees how the loss ratio compares with the release
  rule of the harness. It is taken from the tx host's sampler column `drops` inside the same
  window; the footer's `jobs_dropped_at_release` counts the whole run, ramp included, and is not
  used. It is counted on the transmitter alone and is no subset of the PDUs not delivered: the
  count of those nets the PDUs in flight at the two ends of the window and is not below 0, so the
  dropped releases exceed it when the receiver delivers, inside the window, PDUs that were sent
  before it.
- **A repetition sustains its rate** when the tx host's send queue is not growing and the loss
  ratio is at most 0.001, compared in whole PDUs (`1000 × not delivered ≤ offered`).
- **The send queue is growing** only when the one-sided 95% lower bound of its least-squares
  slope, times the length of the window, is at least one PDU as it is queued. A smaller growth is
  "not growing". With several partitions each connection is judged against that size, and the
  queue of the step grows if any does. The bound times the window (`sendq_growth_lo95_bytes`; for
  several partitions the largest of their bounds; 0 for a queue whose depth never changes, for
  which the regression has no error) and the size (`queued_bytes_per_pdu`) are keys of every tx
  row and columns of `throughput_reps`.
  *One PDU as it is queued* is taken from the step's own tx file: the bytes the tx host's
  interface sent in the window, less 66 bytes of Ethernet, IPv4 and TCP header (14 + 20 + 32, TCP
  timestamps on) per packet sent, over the PDUs sent (of all partitions, because the interface
  counters are the host's). No file header carries the size, and the calibration run covers one
  profile in another directory. On the loopback interface the 66 bytes are wrong, so a
  loopback dry run is judged against a size that is too small. When the counters leave no payload
  there is no size: the queue is then not judged, and a repetition that passes the loss criterion
  is not judged either (never "not growing"). At exact equality the last bits of the regression
  decide.
- **A step is sustained** only if every repetition of the ladder sustained it. It is not sustained
  as soon as one repetition did not. Otherwise, with a repetition that cannot be judged (a missing
  or invalid file, a missing partition), it is not judged.
- **Saturation point:** the highest rate such that it and every lower step of the ladder are
  sustained. The first step that is not sustained or not judged ends the sustained range; a higher
  step that passes does not count, is marked "above the sustained range", and is listed in the
  table note as non-monotone (`<ladder>.non_monotone_steps` counts them).
- **Per step**, for delivered PDU/s, loss ratio, share dropped at release, CPU of each host, the tx host's wire rate and its
  send-queue mean, maximum and slope: the mean over the repetitions, the Student-t 95% interval of
  that mean (none for one repetition), the minimum and the maximum.

- **Secondary, per step:** the PDUs not delivered and offered of its repetitions added up, with the exact
  interval of that proportion (`loss_pooled`, `loss_pooled_cp95_lo/hi`, `lost_pdus_pooled`,
  `offered_pdus_pooled`; two labeled columns of `throughput_saturation`). It ignores the variation
  between repetitions; the per-repetition exact intervals are the primary statement. The Student-t
  interval over repetitions of a proportion (the loss ratio, the CPU utilization of either host) is
  clamped to [0, 1], the range of a proportion; the key description says so.

**Trim: 0.** The harness starts sampling after the ramp, so every sample of a throughput file is
steady state and none is dropped; a verdict must not depend on an arbitrary trim. `--trim N`
remains available and every throughput table states the trim that was used.

### Partitions of a periodic cell

Periodic files of one directory whose headers agree apart from `partition` (and `streams`), named
alike apart from a trailing `p<i>` (`periodic_tx_p0.csv`, `periodic_tx_p1.csv`), are the partitions
of one cell: sender processes side by side, each with its own streams and queue. With a core per
process they are independent gateway processes, each with its own streams, queue and core (streams
and cores are the sums); sender processes that share a core are counted in distinct cores (below).
Each keeps its own rows and keys; in addition the cell gets a combined miss ratio, misses over
releases added over the partitions' streams, with its exact interval (table `periodic_combined`).
The number of partitions is `# partitions=N` when the files say it, else the highest index found
plus one; a lone `partition=0` file is a single process and not a cell. When a partition is not on
file or invalid, the cell is listed and nothing is combined.

The cell's `cores` is the number of DISTINCT cores of its processes: the distinct values of the
`# cpu_affinity=` line of its files (`E9_SPEC.md`, Addendum H, H4: several sender processes may be
pinned to one core, and four processes on core 3 are a cell of one core, `…-s20-c1-…-parts4`).
Where a file has no such line the files' `cores` are added. A cell in
which fewer cores than processes were used gets no `model_*` key for any of its processes (the
queue model gives a process a core of its own) and no `auth_utilisation` (between `start_ns` and
`auth_done_ns` of a process another process of the cell may have held the core); its cell keys say
"sender processes ... which share a core" where those of other cells say "independent processes".
A cell whose processes are ALL pinned to one core gets one measured figure of its own,
`<config>-parts<N>.auth_utilisation`: the time covered by the union of the intervals from
`start_ns` to `auth_done_ns` of all jobs of all its files, over the time from the smallest
`release_ns` to the largest `send_done_ns` over all its files (ruling of 2026-11-25; the stamps of
processes on one board are on one clock). It is emitted only when every file of the cell records
the end of the authentication (no `not_recorded=auth_done_ns`) and has a finished job: the
intervals of a part of the processes would understate the core. No other cell has that key. Nothing is made for two processes only; four
processes on four cores are a cell of four cores with every process's keys. A file with
`# phase=staggered` carries `-staggered` in its configuration name where a synchronous one carries
`-sync`; a deadline miss is judged per job from its own release in either; its model keys are those
of every cell (`model_measured_offsets` takes the release offsets measured in the file, here the
staggered ones; `model_synchronous` and `model_random_*` are what other release patterns would
give, as their definitions say).

### Functional runs of the gateway binaries

A directory that holds the marker file `FUNCTIONAL` is one functional run (`DATA_SCHEMA.md`,
"Functional runs of the gateway binaries"). It gives counts and never a
time: no time column of its files is read, its handshake files are counted and not timed, and any
other timing file in it is listed and not analyzed. The marker is not a "not a result" marker: the
counts are results. The marker covers the CSV files directly in its directory: a file in a
subdirectory, or a cyclictest text file, is not covered by it.

The files are those of the gateway's contract (`DATA_SCHEMA.md`, "Contract of the gateway's
application logs"): `app_tx` has `stream,seq,submit_ns,start_ns,auth_done_ns,send_done_ns`, one row per PDU
whose transmission was confirmed; `app_rx` has the `periodic_rx` columns, one row per outcome at
the receiver (a rejected PDU has seq -1, a framing failure stream -1 as well); `rx_payload` has
`stream,seq,payload_hex`, one row per delivered PDU in the order of the ok rows. A replaced gateway
process continues in a numbered part (`app_rx2.csv`); the parts are read in numeric order and
added. The driver's joined copies (`*_all.csv`) hold the same rows again: listed, not read.

- **sent**: rows of `app_tx*`, per stream (a row is a confirmed PDU).
- **delivered**: rows of `app_rx*` with result ok, per stream.
- **delivered in order**: per stream, each delivered sequence number is looked for in the
  transmitter's rows (all its parts, one after the other) after the last one found. A PDU that
  arrives late, twice, or was never sent is not counted. A replaced transmitter counts from 0
  again; its rows follow those of the first, so its PDUs are in order without a rule of their own.
- **delivered byte-exact**: among the PDUs in order, those whose payload in `rx_payload*` has the
  pattern of a PDU that the transmitter sent on that stream: byte 0 the stream index, bytes 1 to 3
  zero, bytes 4 to 7 the sequence number, big-endian. The receiver takes the stream of a delivered
  row from the PDU ID and decodes the sequence number from those last four bytes, so the check does
  not test the sequence number independently of the payload: it tests byte 0, the three zero bytes
  and, through the order, that this number was the transmitter's next. The pattern is defined for
  8-byte payloads only; for another `payload_len` nothing is judged and there is no key.
- **rejected**: the other rows of `app_rx*`, per result class; each class has a key also when it
  is 0. They count what the streams of the run's variant saw: a PDU of a row that is not a stream
  of the variant writes no row at all (in a MAC run a forged signature PDU leaves no trace).
  `auth_fail` means that the verification failed or could not be done, not only a wrong
  authenticator.
- **handshakes**: rows per role and result class over all handshake files of the directory; a
  gateway writes a row for an attempt that ended and for a message discarded without ending one.
- **TCP connections**: per side, the `# tcp_nodelay=` lines of its app files, one per connection.

Validity. Every `# tcp_nodelay=` line of every file of the run must read 1, and a file without any
such line is a reason when its process carried PDUs (its app file has rows): a connection existed
and was not read back. A run without a session carried no PDU and is not invalid for a missing
line. The read-backs of a valid run are keys as well.

Three outcomes. A run in which nothing was sent (a wrong peer key: every handshake fails) has its
files and is a result with zeros. A directory with the marker and neither `app_tx*` nor `app_rx*`
is listed as invalid ("no functional run is recorded here"): a run cut off before the gateways
wrote anything, but also a build or link step that carries the marker. A run that lacks one of
`app_tx*`, `app_rx*`, `rx_payload*`, whose `rx_payload*` rows are not the delivered rows in their
order, or with a file that cannot be read (these files have no trailer, so a cut row is all a
killed process leaves) is invalid too; its other files are listed. No completeness is inferred
from the `count` line of the headers (in a receiver file it is the number of outcomes after which
the process exits).

### Footprint figures (E8, standard tools)

Counts only: no statistics, nothing timed, no validity rules of the timing files (`CAMPAIGN.md`,
E8). Three kinds of file, found anywhere under the run directory:

- **`size_<label>.txt`**: `unstripped_bytes=N`, `stripped_bytes=N`, then the table of `size -A` of
  the stripped binary. Keys: the two byte counts and the sections `.text`, `.rodata`, `.data`,
  `.bss` (`text_bytes`, ...). A file may hold several such blocks, each under a line
  `== <build>/`; then every build has its own keys (`footprint.size.gateway_iris.build-tx.…`).
  The rows of a block must add up to its `Total` line.
- **`perf_<op>_<n>.csv`** (`perf stat -x,` with `instructions:u` and `cycles:u`): for `mldsa_sign`
  and `mldsa_verify_only` (the tool that signs once and then only verifies),
  each with exactly two runs of different length in one directory, per call = the count of the
  longer run less that of the shorter, over the calls between them, for instructions and for
  cycles, and instructions per cycle as the ratio of the two differences. The numbers of calls are
  those of the file names. It is one pair of runs, user space only, and has no interval; what the
  tool does before and after its calls cancels in the difference. The counts of the two runs are
  keys too. Files of any other operation are listed as not turned into a per-call figure and give
  no key: `mldsa_verify` of the primitive benchmark also signs in every iteration.
- **`rss_samples.txt`** (`<time> <host> … VmHWM: N kB …`, one line per host and sample): per host
  the largest VmHWM (`vmhwm_max_kb`, in kB as `/proc/<pid>/status` gives it) and the number of
  sample lines.

A file of such a name without the shape (no `unstripped_bytes` line, neither event, no `VmHWM`
field) is no footprint file: not read, and a CSV file listed as not recognized. A file that has the shape and contradicts itself stops the run with
an error that names it: rows that do not add up to `Total`, a build without one of the six
figures, a perf value that is no whole number or whose counter did not run 100.00% of the time
(the count would be an estimate), a longer run that counts no more than the shorter, a sample line
without a host and a VmHWM. The figures stand on their own: a footprint file in the directory of a
functional run is read whether or not that functional run is valid.

### Marked directories: DRY_RUN, PILOT and EXCLUDED

A file named `DRY_RUN` or `PILOT` means nothing in its directory may be quoted; so does `EXCLUDED`,
which the measurement drivers write when one of their validity gates fails (link, temperature,
other busy processes, ...), with the reason as its text. The marker counts
when it is in the analyzed directory, in a directory above it (analyzing a part of a dry run), or
anywhere below it (analyzing a collection that contains a dry run). The analysis still runs, and
marks its output: `summary.json` has `"not_a_result"` and the marker's path, every table starts
with a visible "DRY RUN: not a result" (or "PILOT: …", "EXCLUDED RUN: …") line, every figure carries
the same line in red, and every value in `numbers.tex` is wrapped in `\notaresult{…}`
(`\notaresult[PILOT]{…}`, `\notaresult[EXCL]{…}`), which the file defines to print the value bold,
in red when a color package is loaded, with a leading `[DRY]`, `[PILOT]` or `[EXCL]`. `\measraw`
is not defined for any key of such a run, so no number can be printed unmarked. With several
markers the label is the first of DRY_RUN, PILOT, EXCLUDED; `summary.json` (`markers`) and the head
of `numbers.tex` list every marker with its text. A marker does not change the exit code.

### Validity (timing files)

The harnesses write `# key=value` lines above and below the rows of `crypto_ops.csv`,
`overhead_paired.csv` and the networked `periodic_tx.csv`, `periodic_rx.csv` and `throughput.csv`
(`handshake.csv`: its trailer lines are judged where present, none is required). For the
single-node files the whole header is copied into `summary.json`. These checks decide whether the
file is used. `cyclictest*.txt` files are checked for the frequency, throttling, completeness and
the scheduling class that was read back. `attack.csv` is the output of a join script: only its
transport line is checked (below).

| Check | Effect |
|---|---|
| `signature_mismatches`, `failed_calls` not 0 | **Invalid** |
| A harness file (`# tool=`) without `freq_khz_end`, `wall_s`, `cpu_s` (paired files: also the two counters), or without `mlockall` | **Invalid**: the run did not finish, and absent values are not zero. A cut last row in such a file is reported with it instead of stopping the run |
| `mlockall` not `ok` | **Invalid** |
| `freq_khz_start` ≠ `freq_khz_end` | **Invalid** (the governor is fixed, so a change means throttling) |
| `cpu_s / wall_s` below 0.97, `crypto_ops` and `overhead_paired` only | **Invalid** (the core was shared). A networked gateway process waits between PDUs: its share is shown, not judged |
| `get_throttled`, in the file's own `throttled_start` / `throttled_end` or in `env_<host>.txt` of the file's host: an active bit (0 to 3) in any reading, or readings that differ | **Invalid** for every timing file of that host |
| The same sticky bits (16 to 19) before and after | Warning |
| `tcp_nodelay` is not exactly 1, or the line is missing, in a networked harness file (`# tool=`): `periodic_tx`, `periodic_rx`, `throughput`, `handshake`, and the join script's `attack.csv` with either oracle | **Invalid**: with Nagle's algorithm on, several PDUs share a segment and wait for it; a value of -1 means the option could not be read back, which is not 1. A process writes one such line per TCP connection it had (a restarted peer gives a second): every line must read 1 |
| The receiver's file of a periodic pair fails that line | **Invalid as a pair**: the sender's file goes with it, since one connection has one configuration. Sampler and handshake files have no partner and are judged alone |
| The sender's file of a periodic pair is invalid, for whatever reason | The receiver's file is **invalid** with it, in the same list, with a reason that names the sender's file (one rule, both directions; each file is listed once, with its own reasons and the other end's) |
| A harness-written `periodic_tx` file with no receiver's file beside it and no `tcp_nodelay_rx=1` line | **Invalid**: the receiving end of the connection was not read back (the gateway binary as receiver of a periodic run; no campaign experiment has that) |
| The join script's `attack.csv`: `jobs_started` ≠ `jobs_confirmed` in the footer of `periodic_tx.csv` beside it, the lines missing there, or no such log | **Invalid**: no attack vector breaks the connection, so a job that was started and not confirmed means the transmitting side failed; without the log nothing says |
| `tcp_connections_at_first_release` ≠ `tcp_connections_at_end` in a transmitter file (`periodic_tx`, the tx host's `throughput` file), or either line missing or no count | **Invalid**: the connection was made again inside the measured window, or that cannot be told |
| `jobs_started` ≠ `jobs_confirmed` in a transmitter file (the same two kinds), or either line missing or no count | **Invalid**: a started job was not confirmed (the schema: given up without a confirmation, and its row received the next PDU), or that cannot be told. Releases dropped at a full queue (`jobs_dropped_at_release`) are not a reason |
| The footer of a `periodic_tx` file counts other jobs than its rows hold: `jobs_released` ≠ rows, `jobs_started` ≠ rows with a `start_ns`, `jobs_confirmed` ≠ rows with a `send_done_ns`, `jobs_dropped_at_release` ≠ rows without a `start_ns` | **Invalid**: the file contradicts itself. Only the lines the footer has are compared. A traffic log is not judged by this (its rows are never read) |
| A networked file counts other rows than it holds: `rows` (receiver and handshake files) or `pdus` (the join script's `attack.csv`) ≠ its rows | **Invalid**: the file contradicts itself (rows are missing) |
| `rows_lost` other than 0 (receiver and handshake files) | **Invalid**: the log does not hold every row |
| `stopped_early` other than 0 in a `periodic_tx` file, or in the traffic log beside a ladder's transmitter sampler file | **Invalid**: the run was stopped before its end (the driver's thermal stop; such a run is marked `EXCLUDED` as well). A periodic sender takes its receiver's file with it |
| `contradicting_pdus` other than 0 in `attack.csv` | **Invalid**, with the count in the reason |
| The traffic logs beside `attack.csv` (`periodic_tx.csv`, `periodic_rx.csv`): `stopped_early` or `rows_lost` other than 0, or `rows` ≠ the log's rows | `attack.csv` is **invalid**: it is joined from the proxy's log and the receiver's file (`periodic_rx.csv` when the harness is the oracle), so a receiver's log that lost rows or does not hold the rows it counts spoils the join; `stopped_early` of the generator's log means the attack run was cut short |
| `rows_lost` or a wrong `rows` in the traffic log beside a ladder's sampler file | Not a reason: a ladder reads the sampler's counters and never the rows of a log |
| Retransmitted segments (`tcp_total_retrans_in_window` and the other counts) | Never invalid: excluding such a file would select on the outcome |
| A reading such as `unavailable`, a single reading (nothing to compare it with), or no `env_<host>.txt` | Unknown, reported as such |

An invalid file is listed in `summary.json` (`invalid_runs`) and in the `validity` table, gets no
other table and no number key, and makes `make_tables` exit with code 3 after everything else is
written. A file with none of these lines and no env file is analyzed unchecked. An invalid
`periodic_tx` file takes its `periodic_rx` file with it; an invalid `periodic_rx` file leaves the
sender side of the configuration standing, unless it fails the `tcp_nodelay` line (then the pair is
invalid, above); an invalid throughput file leaves its rate step unjudged.

**CPU counters of a throughput file.** The harness reads `total = busy + idle + iowait` from one `/proc/stat` line, each field in
whole ticks. From one sample to the next, over every sample of the file:
- busy grows by no more than total: as measured;
- busy grows by exactly one tick more than total: rounding, not a broken counter. The kernel's
  split between idle and iowait is provisional, so the two truncated parts of their growing sum can
  read one tick less than before (5.0 + 4.0 reads 9; later 5.95 + 3.95 reads 8). The step counts as
  fully busy (its total growth is raised to its busy growth) and is counted:
  `….<tx or rx>.cpu_one_tick_clamps.k`, with the file's sample steps as n, and a note in the
  warnings column of the `validity` table. The count is reported, not judged;
- busy grows by 2 or more ticks more than total, or busy goes backwards: the file is invalid. A
  utilization below zero or above one can then not reach a mean. When busy stands still and the
  total drops, the reason reads "idle plus iowait went backwards by N ticks".

**No CPU figure of the sampler is a manuscript number.** The boards' kernels account CPU time by
tick, which misses work that starts on a timer and ends before the next tick. The keys `….cpu_util`, `tx_cpu_util_*` and
`rx_cpu_util_*` stay in `numbers.csv` and `summary.json`, have no macro, and are listed in
`suppressed_keys.txt` with that reason; the CPU column and rows of the throughput tables say so in
their notes. `cpu_one_tick_clamps.k` is a count about the counters and keeps its macro.

**Sensitivity line of a ladder.**
A retransmission never drops a file, so every delivery figure of a ladder is formed over all valid
repetitions. It is formed a second time over the repetitions whose transmitter files all report
`tcp_total_retrans_in_window` = 0; a repetition with a count above 0, or with a count that was not
given, is left out. The second figure stands beside the first, never instead of it:
- table `throughput_no_retrans`: per step the repetitions, how many remain and how many are left
  out for each reason, and delivered mean, largest loss ratio, verdict and saturation point over
  all and over the remaining ones; its note counts the repetitions and files left out;
- keys `throughput.<ladder>.no_retrans.saturation_pps`, `.reps_left_out`, `.files_with_retrans`,
  `.files_unknown`, and per step `….r<rate>.no_retrans.n_reps`, `.judged_reps`, `.sustained_reps`,
  `.delivered_pps_mean` and `.loss_ratio_mean` with `_t95_lo`, `_t95_hi`, `_min`, `_max`.
A step with no repetition left is not judged and ends the sustained range of the second line. A
ladder whose files give no count has no second line: no table, no keys, and the note of
`throughput_saturation` says so.

For periodic files the count is a column of the `periodic` table, and there is no line pooled over
the configurations of a run: each figure belongs to one file. A second figure is formed only where
several files already form one, the combined miss ratio of a multi-partition cell: the same
combination over the partitions whose count is 0 (table `periodic_combined`, last seven columns;
keys `periodic.<config>-parts<N>.no_retrans.partitions`, `.left_out_retransmitted`,
`.left_out_unknown`, `.streams`, `.jobs`, `.misses`, `.miss_ratio`, `.miss_cp95_lo/hi`). A count
that was not given is not 0 and leaves the partition out; with no partition left there are no
figures; a cell whose files give no count has no second figure.

**Processor time of the process.** From the sampler's `proc_cpu_ns` column: its growth over the steady window divided by
the growth of `t_ns`, the share of one core the harness process used, all its threads together.
Keys `throughput.….<rep>.<tx or rx>.proc_cpu_share` and, over the repetitions of a step,
`tx_proc_cpu_share_mean` with `_t95_lo`, `_t95_hi`, `_min`, `_max` (likewise `rx_…`); column
"process CPU" of the `throughput` table and two rows of `throughput_steps`. The partitions of a
step are processes of their own: their shares add up. It is the processor time of the process,
not board utilization: work the kernel does in other contexts is not in it, and interrupt time
that interrupts the process is charged to it on these kernels. It is not a proportion (several
threads, summed partitions), so its interval is not clamped and it may exceed 100%. A 12-column
file has no such figure.

**Counts of the transmitter's connection.** `tcp_total_retrans_in_window`, `tcp_dsack_dups_in_window`
and `tcp_total_rto_in_window` (TCP_INFO at the end minus at the first release) are reported per
transmitter file: keys `periodic.<config>.<count>` and `throughput.….<rep>.tx.<count>` (the sum over
the partitions of a step), and the last three columns of the `periodic` and `throughput` tables. A
value of -1, or a missing line, means the kernel did not give the field: a dash and no key, never
0. Any other value that is no count stops the run.

**Transport lines** (`DATA_SCHEMA.md`, "Transport keys of the networked harness files"). Each file
is judged by its own header and
footer. The sampler files of a ladder step need not carry these lines: what
`throughput_<role><label>.csv` lacks is read from the header and footer, never the rows, of the
generator's traffic log `periodic_<role><label>.csv` beside it, which must be from the same host,
repetition and partition. An `attack.csv` without the line takes `tcp_nodelay` from `periodic_tx.csv`
and `periodic_rx.csv` beside it, and both must say 1. This fails closed: without a usable log the
file is invalid, and a reason names the log when its line was read from there. A file without a
`# tool=` line (hand-made or legacy) is not judged by these lines. The gateway's handshake files
(`handshake_gw_tx.csv`, `handshake_gw_rx.csv`) carry `# tcp_nodelay=` and are judged by it; its
application logs are not of a schema kind.

**Negative handshake tests.** The handshake files of a test are judged like any networked harness
file (`tcp_nodelay` must read 1). When the harness was the transmitting end, its traffic log
`periodic_tx.csv` is beside them and its two jobs lines judge them as well (they differ, or the log
does not say: invalid); with gateway binaries on both ends there is no such log, and the record's
`pdus_given_up` is reported as a key. One invalid file takes the test with it: the counts of the
files that are left are not the test, so they are listed and the test has no keys. A record whose
`seen_tx` / `seen_rx` are not the counts found in the files makes the test invalid too (the oracle
read the same files), and a record line that is not in the schema's format stops the run.

**Jobs given up** (`DATA_SCHEMA.md`, "Jobs given up, and what loss means in a ladder"). A transmitter
file whose footer has `jobs_started` different from `jobs_confirmed` is invalid. The two lines are
in the footer of the traffic log, so a ladder's transmitter sampler file is judged by the log
beside it, as above; a transmitter file for which neither says is invalid. An `attack.csv` is
judged by the two lines of `periodic_tx.csv` beside it, and the handshake files of a negative test
by those of a `periodic_tx.csv` beside them when there is one. Receiver files and other handshake
files are not judged by these lines. The reason states the two counts and, when the footer's
`tx_confirmations_failed` fits, how many of the jobs had a failed confirmation and how many were
given up without one. By the
source of the harness (`bench_net_tx.c`) a transmitter writes its
file only after every started job is settled, also after an early stop, so a difference never
comes from a job in flight at the end of a run: it is `tx_confirmations_failed` jobs with a
negative confirmation plus jobs given up after the limit, and overload alone produces neither. The
rule is the schema's.

**Footer counts** (`CAMPAIGN.md`, "Invalid files"). A networked file whose own count of its rows is not the
number of its rows, or with `rows_lost`, `stopped_early` or `contradicting_pdus` other than 0, is
invalid with that reason; anything but 0 is a reason, also a value that is no count. A line a file
does not have is not judged: files written before these lines existed and the gateway's logs carry
none, and single-node files are not read for them. A receiver's file that is invalid by its own footer leaves the sender's side of the pair
standing, as for any other fault of the receiver's file alone. The lines of a traffic log judge
the file beside it only where that file depends on them: `stopped_early` for a ladder's sampler
file (the step was cut), all of them and the row count for `attack.csv`. That file is joined from
the proxy's log and the receiver's file (its `proxy_log_sha256` and `rx_file_sha256` lines), which
is `periodic_rx.csv` when the harness is the oracle: a receiver's log that lost rows or does not
hold the rows it counts spoils the join, and `stopped_early` of the generator's log
`periodic_tx.csv` means the attack run was cut short. The proxy's log and the gateway's own log
carry none of these lines. The handshake files of a negative test are judged by their own lines.

Not checked here, because the files carry no agreed line for it: temperature, other busy
processes, link state and TCP counters. The drivers gate those and write `EXCLUDED`.

### Paired overhead: launches and the noise floor

Identical process launches differ in their csm − standalone difference by more than the interval
each launch reports for itself (a per-launch layout effect). The process launch is therefore the
unit of replication. Files of one directory and mode that carry a launch number form a launch
set; they must agree in `commit`, `host` and `msg_bytes`, and a launch number may appear once.

- **Within launch (optimistic):** every file is analyzed, and so are the pooled pairs of a
  set. These intervals treat the pairs as independent and leave out the difference between launches.
- **Across launch (headline):** one paired Hodges-Lehmann estimate and one geometric-mean ratio per
  launch; their mean, SD, minimum, maximum and Student-t 95% and 90% intervals; and a TOST of the
  launch-level log-ratios against the margin with n = number of launches. Fewer than 5 valid
  launches give no verdict. Invalid launches are left out and counted.
- **A/A files** (`# mode=aa`): the `csm_ns` column holds a second standalone call. They are reported
  in their own noise-floor table with that column labeled "standalone, second call", their keys
  always contain `aa`, and they are not judged against the margin.

`--warmup` applies inside every launch file; a launch left with no pairs stops the run. A file
without a launch number in the directory of a launch set is refused when its keys would be those
of the pooled set: give it a launch number, a file label, or its own directory.

### Clock relation

As in the schema: `offset_ns` = Rx clock − Tx clock, probed at Rx-clock time `t_ns`. The toolkit
interpolates linearly between probes and uses the nearest probe outside them. If the fastest
delivered PDU appears to arrive before it was sent (by more than the largest probe round trip) or
more than 100 probe round trips after, the run stops: that pattern means the relation is wrong.
Without a `clock_offset.csv` next to `periodic_rx.csv`, cross-host latency is "not reported (no
clock relation)".

### End-to-end latency across the two boards (E9)

`E9_SPEC.md`, "Interface details", is the definition. The two boards' monotonic clocks are not synchronized.
A probe exchanges time stamps over the link during the run (`periodic/clock_probe.csv`: `seq`,
`t1_ns`, `t2_ns`, `t3_ns`, `t4_ns`; t1 and t4 on the sending board's clock A, t2 and t3 on the
receiving board's clock B; only completed exchanges are rows), and the toolkit brings the times of
board B to clock A with it.

**Since Addendum E of the spec (2026-11-25) the latency is measured on the boards' raw clocks.**
What follows describes the offset track and its rules; they now apply to the raw stamps of a probe
file of format 2 (`t1r_ns` to `t4r_ns` in the place of `t1_ns` to `t4_ns`), clock A and clock B
being the two boards' CLOCK_MONOTONIC_RAW. "End-to-end latency on the raw clocks" below says what
is added: the clock maps, the conversion of the PDU stamps, `bound_total_us` and the new keys. The
same computation on the monotonic columns stays in the code for the diagnostic `mono.*` keys and
for the probe test of a format-1 file; a format-1 probe file gives no latency any more.

- **Exchange:** offset theta = ((t2 − t1) − (t4 − t3)) / 2, clock B minus clock A; delay
  delta = (t4 − t1) − (t3 − t2); time tau = (t1 + t4) / 2 on clock A. The true offset lies within
  theta ± delta / 2 whatever the asymmetry of the two directions.
- **Anchors:** windows of 5 s of clock A from the first tau; in every window that has an exchange,
  the one with the smallest delta, the earliest on a tie. theta(t) is the straight line between
  the two neighboring anchors and the first or last anchor's value outside them. The bound of the
  run, `offset_bound_us`, is the largest delta / 2 among the anchors of the region below, the
  second to the second-to-last one. The first and the last anchor only delimit: the last window
  of a file is partial and can hold a single exchange, which is then
  an anchor whatever its delay, although no PDU uses its segment. `anchors`
  counts all of them, and `drift_ppm` is the least-squares line through all of them; only
  `e2e.offset_bound_us` leaves the two out.
- **Between the anchors** (`E9_SPEC.md`, "FINAL ruling on the clock track"). The rate
  between the two clocks is not constant: the receiving board's clock is disciplined by NTP. The bound
  of the anchors says nothing about the straight line between them; the probe's other exchanges do.
  The *region* runs from the second anchor to the second-to-last one (their tau, ends included).
  Every completed exchange of the region certifies the track at its own instant within
  `cert` = |track(tau) − theta| + delta / 2, because the true offset lies within delta / 2 of its
  theta. `offset_cert_us` is T(2 s): the smallest T such that the exchanges with `cert` ≤ T, taken
  with the two ends of the region, are nowhere more than 2,000 ms apart (0 when the ends themselves
  are not; compared in whole nanoseconds of 2 tau). `offset_bound_total_us` is the larger of
  `offset_bound_us` and `offset_cert_us`; the table prints it. What it supports: at instants no more
  than 2 s apart the probe certifies the offset estimate to within that figure. It is not a bound
  for every instant. `exchanges_outside` counts the exchanges of the region whose theta is further
  from the track than their delta / 2 plus the total bound: each proves the track off by more than
  the bound.
  The form above needs no threshold and no slope. Its known answers are tests: a 100 ppm step
  in the middle of a 5 s segment gives 125 µs (not a result); the same step in a 9.9 s segment
  between two short ones gives more than 200 µs; two anchors 101 ms and 2 µs apart at a constant
  offset stay valid; so does a constant drift of 100 ppm.
- **Per delivered PDU** (a receiver row with result ok, joined with the sender's row on stream and
  seq; a duplicate ok row counts twice; every stamp first carried onto the raw clock of its board,
  see below): latency = `deliver_ns` − theta(`release_ns`) −
  `release_ns`; receive part = `deliver_ns` − theta(`send_done_ns`) − `send_done_ns`; causality
  margin = `rx_done_ns` − theta(`send_done_ns`) − `send_done_ns`. theta is taken at the sender's
  time stamp, as the spec says, so what the offset changes while a PDU is under way stays in the
  figure: the drift times the latency, 80 ns at 20 ppm and 4 ms.
- **Arithmetic:** every difference is formed in integers, and the first anchor's time and offset
  are taken off before anything becomes a float (the time stamps are of the order of 1e14 ns).
- **Keys**, under `<config>.e2e.`, with the names and units of the spec: `n`, `latency_mean_ms`,
  `latency_p50_ms`, `latency_p90_ms`, `latency_p99_ms`, `latency_p99_9_ms`, `latency_max_ms`,
  `rxpart_p50_ms`, `rxpart_p99_ms`, `rxpart_max_ms`, `offset_bound_us`, `offset_cert_us`,
  `offset_bound_total_us`, `exchanges_outside`, `anchors`,
  `probes_completed`, `probe_delay_min_us`, `probe_delay_p50_us` (both over all completed
  exchanges), `probe_gap_max_ms` (largest difference between the tau of two consecutive
  exchanges), `drift_ppm` (least-squares slope of the anchors' theta over their tau; positive: clock
  B runs faster; none with a single anchor), `causality_min_us`, `causality_violations`; and the
  keys of Addendum E, listed below.
  Percentiles are of type 7. One with fewer than ten samples above it is in `numbers.csv` and is
  held back from `numbers.tex`, as every percentile of the toolkit, and the table prints a dash.
- **Not a result for E9** (each limit itself passes):
  - a gap above 1,000 ms between two completed exchanges;
  - fewer than four anchors; fewer than two anchors at or before the first release (the second
    anchor's tau against the smallest `release_ns` of the sender's file, both on clock A), or fewer
    than two at or after the last delivery (the second-to-last anchor's (t2 + t3) / 2 against the
    largest `deliver_ns` of all rows with result ok, both on clock B; the two PDU stamps carried
    onto the raw clocks);
  - no certified bound (the exchanges of the region leave more than 2,000 ms), or a total bound
    (`bound_total_us`, below) above 100 µs;
  - an exchange outside the offset bound (`exchanges_outside` not 0, against `offset_bound_total_us`);
  - a delivered PDU whose causality margin is below minus the total bound;
  - and, beyond those four (rulings in the spec): `exchanges_completed` that is not
    the number of rows or is missing (the footer rule of every file); a probe file with fewer than
    two completed exchanges, or with an exchange that contradicts itself (t4 before t1, t3 before
    t2, a negative delay); no delivered PDU that can be joined; a delivered PDU whose sender row
    has no `send_done_ns`; a sender whose rows repeat a stream and seq (a process that was started
    again leaves no unique row to join); and a harness receiver's file that declares `rx_done_ns`
    not recorded (the causality rule cannot be judged).
- **What happens then:** `clock_probe.csv` is listed under `invalid_runs` with the reasons
  (experiment `e2e`), the run has no `e2e` key and no row in the `e2e` table, and the exit code is
  3. The periodic keys of the pair are what they are without the probe file. A directory with
  several pairs is a result for E9 as a whole or not at all; a reason then names its pair.
- **Coverage is judged by the anchors**, two on each side of the PDUs (amendment 1a of the spec):
  the first and the last segment of the track are not used. An anchor lies anywhere in its window,
  so the driver gives the probe 12 s of lead before the transmitter and 12 s beyond its end.
- A probe that was killed leaves a cut row and no footer, or an empty file: its file is listed with
  both reasons and the run goes on (in a periodic directory, beside gateway files and in a
  `probetest` directory alike). A row that cannot be read in a file that has its footer stops the run, as in
  every finished file.
- A probe file without an analyzed receiver's file in its directory is listed as not used; two
  probe files in one directory stop the run. `clock_offset.csv` and its `latency` keys are
  untouched; a directory may hold both files.
- **The gateway binaries (cell g).** A `FUNCTIONAL` directory with `clock_probe.csv` beside the
  gateway files gets the same keys under `functional[.<directory>].e2e.`, from the
  gateways' own time stamps: latency = `deliver_ns` − theta(`submit_ns`) − `submit_ns`; receive
  part from `send_done_ns` as above; causality margin = `verify_done_ns` − theta(`send_done_ns`) −
  `send_done_ns`, because the gateway records no `rx_done_ns` (a PDU is not verified before it was
  sent). The parts of a replaced process are read one after the other. These four columns are the
  only time columns of a functional run that are ever read, and only for these keys; the counts of
  the run are what they are without the probe file. When the functional run itself is invalid, the
  probe file is listed with its other files and there is no E9 verdict.
- **Several streams (cells c and h).** A file with more than one stream
  gets, beside the keys over all streams, `e2e.stream<k>.n`, `.latency_p50_ms`, `.latency_p99_ms`,
  `.latency_p99_9_ms` and `.latency_max_ms` for every stream of the sender's file.
- **Both variants in one file (cell h).** `# profile=both` with `# stream_profiles=mldsa65,mac`
  (one profile per stream index; `DATA_SCHEMA.md`). The configuration id carries `both`
  (`p10ms-s2-c1-both-other-…`), and each stream says its variant in the text key
  `e2e.stream<k>.profile`. A file without the line, or with a line that does not name one profile
  per stream, stops the run; in a file of one variant the line is not needed and must not
  contradict the profile. The queue model is not run for such a file: it draws one service time
  for every stream, and the two variants have two.
- **The unrelated flow of cell i.** `background_traffic.txt` (in the directory of the periodic
  files or one above, the run directory) gives `<config>.bg.rate_offered_mbit_s`,
  `.rate_achieved_mbit_s`, `.bytes_sent`, `.bytes_received` and `.verdict` (text, the driver's
  PASS or FAIL; taken, not recomputed). A FAIL, a record without its verdict line, or one of the
  driver's markers `BG_INVALID` and `E9_INVALID` in those directories makes the run no result for
  E9: the probe file is listed with that reason and there is no `e2e` key (the markers judge a
  directory of gateway files in the same way). The flow's own keys
  stay, also with FAIL.
- **The two tests of the method (a `probetest` directory).** `zero_<host>.csv` is the probe with
  client and server on one board, where the true offset is zero: per host (the file's `host_a`)
  `probetest.zero.<host>.exchanges`, `.anchors`, `.offset_bound_us` (over all anchors of the file,
  unlike a run's) and
  `.theta_beyond_half_delay.k`, the exchanges whose theta is further from zero than delta / 2 (the
  estimator promises none). `pair_ab.csv` and `pair_ba.csv` are two probes at the same time, one
  with its client on each board: `probetest.pair.anchors_compared`, `.theta_sum_max_us` (the
  largest |theta_AB + theta_BA|) and `.limit_us` (the sum of the two total bounds; none when a track
  has fewer than four anchors). Compared are the anchors of the region of each track, the second to
  the second-to-last one (E11 m of the spec): one is
  compared when its instant, brought to the other board's clock with its own theta, lies in the
  region of the other track, ends included; the sum is its theta plus the other track's theta(t)
  there. The toolkit does not read the driver's own record (`probetest.txt`).
  A file whose count of its exchanges is wrong, that has
  fewer than two, or that contradicts itself is listed as invalid and gives no key (a pair needs
  both files). These keys are counts against what the estimator promises; none is a latency.
  A file of format 2 is judged on its raw stamps, one of format 1 on its monotonic columns (E11 f
  of the spec); a pair of one of each is invalid. A clock map in a `probetest` directory is
  recognized by its header row, whatever its name, and is not read.
- A directory without `clock_probe.csv`, periodic or functional, has no `e2e` key; its other keys
  are not affected.

### End-to-end latency on the raw clocks (E9, Addendum E)

`E9_SPEC.md`, "Addendum E" (E1 to E11, 2026-11-25), is the definition. CLOCK_MONOTONIC is steered
by the time-synchronization service, and such steering can break the offset track of a run
(`E9_SPEC.md`, Addendum C). CLOCK_MONOTONIC_RAW is
not steered. The PDU stamps stay CLOCK_MONOTONIC (the harness and the gateway are not changed);
the readers carry them onto the raw clock of their board, and the offset between the boards is
tracked on the raw clocks.

- **Files.** `clock_probe.csv` of format 2: `# format=2`, `# clock_raw=CLOCK_MONOTONIC_RAW` and the
  columns `seq,t1_ns,..,t4_ns` (the monotonic reads), `t1r_ns,..,t4r_ns` (the raw stamps of the
  exchange), `w1_ns,..,w4_ns` (the widths: at each point the probe reads RAW, MONOTONIC, RAW; the
  raw read next to the datagram is the stamp, so the other one lies one width before the stamp at
  points 1 and 3 and one width after it at points 2 and 4). Beside it `clock_map_a.csv` and
  `clock_map_b.csv` (`raw1_ns,mono_ns,raw2_ns`, one reading every 5 ms; footer `samples`,
  `samples_dropped`). The format is told by the columns; a header that says another one is a
  reason.
- **Map of a board.** A sample is valid when 0 ≤ raw2 − raw1 ≤ 5,000 ns. Its abscissa is its
  monotonic read, its value m = mono − (raw1 + raw2) / 2, its half width (raw2 − raw1) / 2. A stamp
  x is carried over as x_raw = x − m(x), m(x) by linear interpolation between the two valid samples
  around x. Carried over are, on board A, `release_ns` and `send_done_ns` of every delivered PDU and
  the smallest `release_ns` of the sender's file; on board B, `rx_done_ns` (the gateway:
  `verify_done_ns`) and `deliver_ns` of every delivered PDU and the largest `deliver_ns` of all
  rows with result ok. The *used range* runs from the last valid sample at or before the earliest
  of these stamps to the first valid sample at or after the latest.
- **Bound of a map:** `map_X.bound_us` = max(`map_X.holdout_us`, `map_X.kink_us`) +
  `map_X.half_us`. The hold-out is the largest distance of a sample of the used range from the
  straight line through its two neighbors in the file (both must be valid; they may lie outside
  the range). It covers a change of rate only where the samples are evenly spaced, and the sampler
  can wake late, so E12.1 of the spec adds the kink term: the valid samples in the order of the
  file bound intervals; for every interval of the used range, |slope of m after it − slope before
  it| × its length / 4 is the most a single change of rate inside it can put the straight line
  off; `map_X.kink_us` is the largest (6,900 ppm across a gap of 30 ms: 51.75 µs, where the
  hold-out sees 14.9 µs). Each slope is read over a baseline of at least 4 ms (E12.7): before the
  interval from the last sample at least 4 ms earlier, after it to the first sample at least 4 ms
  later. A sampler that woke late takes the samples it owes microseconds apart, and a slope between
  two of those would be read noise. `map_X.half_us` is the largest half width in the range.
  `map_X.gap_max_ms` is the largest distance between two consecutive valid samples of the range.
- **Independent certificate.** Every stamp point of an exchange reads the same relation of the two
  clocks in another thread at another instant (board A: points 1 and 4; board B: points 2 and 3).
  A point no wider than 5,000 ns whose monotonic read lies in the used range (ends included) is a
  check point: `map_X.check_n`; `map_X.check_max_us` is the largest |mono − mean of its two raw
  reads − m(mono)|; `map_X.check_violations` counts those further off than `map_X.bound_us` plus
  half their width.
- **The bound that is printed:** `bound_total_us` = `offset_bound_total_us` + `map_a.bound_us` +
  `map_b.bound_us`. The table prints it, and causality is judged against it.
- **What the maps say about each clock (E6):** the valid samples of a board in windows of 1 s of
  abscissa from the first one; a window whose first and last sample are at least 0.8 s apart has
  the rate (m_last − m_first) / (abscissa_last − abscissa_first) in ppm, positive when
  CLOCK_MONOTONIC runs faster than the raw clock. `clock_X.adj_ppm_min`, `adj_ppm_max`,
  `adj_ppm_median`; `adj_step_ppm_max` (the largest difference between two windows that follow each
  other; 0 with fewer than two); `adj_offset_range_us` (largest minus smallest m);
  `adjusted` (1 when the rates range over more than 1 ppm: the correction CHANGED during the run;
  a clock at a constant −1.8 ppm has 0 here, E11 n). Only these keys say which board's clock was
  steered; statements about how much rest on the ppm keys and on `adj_offset_range_us`. The rate is per unit of the board's CLOCK_MONOTONIC, the abscissa (E11 k): "steered
  by 5,000 ppm" means that CLOCK_MONOTONIC gains 5,000 ns on the raw clock per 1,000,000 ns of its
  own reading.
- **Keys** under `<config>.e2e.` (the gateway run: `functional.e2e.`), 61 for a run with one
  stream: the 22 above, now on the raw values; `bound_total_us`, `probe_format` (2),
  `probe_width_p50_ns`, `probe_width_max_ns` (the widths of all exchange points); for X in a, b
  `map_X.samples` (rows of the file), `map_X.samples_invalid`, `map_X.gap_max_ms`,
  `map_X.holdout_us`, `map_X.kink_us`, `map_X.half_us`, `map_X.bound_us`, `map_X.check_n`, `map_X.check_max_us`,
  `map_X.check_violations` and the six `clock_X.*` keys; and the diagnostic `mono.verdict` (1 when
  the earlier definitions on the monotonic columns would call the run a result),
  `mono.offset_bound_total_us` and `mono.latency_p50_diff_us` (only with verdict 1). The three
  `mono.*` keys are in `numbers.csv` and are no macros: they are never printed as a result.
- **Not a result** (each limit itself passes), besides the rules of the track above: a probe file
  of format 1 (the reason names the format); a map that is missing, has no footer, counts its
  samples wrongly or has `samples_dropped` other than 0; a stamp before the first or after the last
  valid sample of its map; `map_X.gap_max_ms` above 50; no sample of the used range that can be
  tested against its neighbors; an interval of the used range without a valid sample at least
  4 ms before it or after it in the file (no kink term); probe files that are not those of one run (E12.2: a
  map whose `role` is not that of its file name, whose `host` is not `host_a` or `host_b` of the
  probe file, `commit` lines that differ among the three files, a `clock` or `clock_raw` line
  other than CLOCK_MONOTONIC and CLOCK_MONOTONIC_RAW, a map's `interval_ms` other than 5; a
  missing line is not what it must be); a check point that is a violation; fewer than 100 check points on
  a board (20 in the gateway run); `bound_total_us` above 100 µs; a causality margin below minus
  `bound_total_us`. A run that is not a result has no key under `.e2e.` at all (E11 j). What its
  maps say is kept in `summary.json`, under `record` of its entry in `invalid_runs`, per pair: the
  `clock` figures of each board whose map could be read, and the `map` figures when its stamps
  could be carried over. That is for the record and never a key.
- **What the keys may support:** the sentence of the FINAL ruling with B = `bound_total_us`: "at
  instants no more than 2 s apart the measurement certifies the estimate to within B µs"; the two
  map terms bound the conversion in every interval between two samples of the map and are included
  in B. It is not a bound for every instant.
  Latencies are in seconds of board A's raw clock.
- **Arithmetic:** 2 m, the abscissae and the doubled stamps are integers; a difference against the
  first valid sample of a map or the first anchor is formed in integers, the interpolation in
  floats on these differences. Sums of bounds are formed in nanoseconds.
- **Printed forms** (E11 o): every bound in microseconds with one decimal (`offset_bound_us`,
  `offset_cert_us`, `offset_bound_total_us`, `map_X.holdout_us`, `kink_us`, `half_us`, `bound_us`,
  `check_max_us`, `bound_total_us`, and of the probe test `zero.<host>.offset_bound_us` and
  `pair.limit_us`), so that the printed terms add up to the printed total within rounding; the adjustment rates with two decimals, the widths in whole nanoseconds; the other
  earlier keys print as before. `sessions` gives `bound_total_us` its range
  over sessions.
- **Readings** (E11 j and k of the spec rule the first four): a stamp or check point exactly on a
  sample takes that sample's value; a map whose valid samples do not strictly ascend in their
  monotonic read, or without a valid sample, makes the run no result; the step of E6 is taken
  between neighbors in the list of windows that have a rate; in a directory with several pairs
  every pair has its own used range, map keys and verdict. E11 o makes common rules of: a map in
  which no sample of the used range has two valid neighbors is no result; `map_X.samples` counts
  the rows of the file; the windows of E6 take all valid samples of the file, not the used range.
  The toolkit's own: without any rate there is no rate key and no `adjusted`; a used range of a
  single sample has no interval and a kink term of 0; the probe file's `interval_ms` is not judged
  (E2 fixes none).

### The clocks themselves, from the probe files (keys `clock.*`)

`E9_SPEC.md`, "Addendum C" (2026-11-25), is the definition.
Both boards run `systemd-timesyncd`; board B is synchronized to a pool server, board A is not, and
in the first pass of E9 the clock rule rejected runs because a clock was being adjusted. Every
experiment measures durations on the boards' CLOCK_MONOTONIC, which such an adjustment scales while
it lasts. These keys say how the two clocks moved against each other during the probe runs. No PDU
and no latency enters, and they do not depend on whether a run is a result for E9.

`python3 -I <toolkit>/analysis/clock_rate.py <inputs.tsv> --runs-root <dir> --out <out_dir> --key-prefix clock.e9p1`

- **Inputs.** `<inputs.tsv>`: comment lines, then per probe file four fields separated by tabs: the
  cell (`s1.a`, the part of the key), the run directory under `--runs-root`, the file inside it, its
  sha256. Refused: a file whose sha256 is not the listed one, a line without its four fields, a cell
  named twice, the cell `all`, a file the reader cannot read or with a row that contradicts itself
  (t4 before t1, t3 before t2, a negative delay). After a refusal nothing is written. The footer of
  a probe file is not judged here: the hash says which file it is. The output directory holds
  `numbers.tex`, `numbers.csv`, `number_keys.md` and `suppressed_keys.txt` and is merged like any
  other.
- **Anchors** are those of the latency keys, selected by the same function (`e2e.anchors`): windows
  of 5 s from the first exchange, in each the exchange with the smallest delay, the earlier one on a
  tie. All anchors are used here, the first and the last included.
- **Segment:** two neighboring anchors whose tau differ by at least 2.0 s (exactly 2.0 s is one;
  compared in whole nanoseconds). Its rate is (theta_2 − theta_1) / (tau_2 − tau_1) in ppm; theta is
  board B's clock minus board A's, so a positive rate means board B's clock runs faster.
- **Per file**, `<prefix>.<cell>.<stat>`: `segments`; `rate_ppm_min`, `rate_ppm_max` and
  `rate_ppm_median` over its segments (an even number: the mean of the two middle rates);
  `rate_step_ppm_max`, the largest absolute difference between the rates of two segments that
  follow each other in the file's list of segments (the size of an abrupt change; also across a
  pair of anchors too close to form a segment; 0 with fewer than two segments); a file without a
  segment has no rate key; `offset_range_ms`, the largest minus the smallest
  theta over the anchors; `span_s`, tau of the last anchor minus tau of the first.
- **Over the files**, `<prefix>.all.<stat>`: `files`; `rate_ppm_min` and `rate_ppm_max` (the
  smallest and the largest segment rate of any file); `rate_abs_max_ppm`, the larger of their
  absolute values, and `rate_abs_max_pct`, the same as a percentage (its value in `numbers.csv` and
  `\measraw` is the percentage itself, 0.25 for 2,500 ppm, and its unit is `%`: every key of unit
  `percent` holds a proportion); `rate_step_ppm_max`;
  `offset_range_ms_max`; `files_steady`, the files whose `rate_step_ppm_max` is at most 5 ppm (5
  itself is steady; the unrounded value is compared), and `files_adjusted`, the others;
  `rate_ppm_steady_min` and `rate_ppm_steady_max`, the smallest and the largest median rate among
  the steady files. A file without a segment enters no rate and, with its step of 0, counts as
  steady. These readings are (a) to (d) of the addendum's "Readings fixed on 2026-11-25".
- **Printed forms:** rates to 1 ppm, the minimum, maximum, median and steady rates with their sign;
  the percentage with two significant digits; offsets to 0.1 ms; the span to 1 s.
- **Uncertainty** (stated in the text, not a key): each anchor's theta is known to within its
  delta / 2 (about 50 µs), so a rate over 5 s is known to within about 20 ppm; by the same
  arithmetic a segment of the smallest length, 2 s, to within about 50 ppm.
- **What the keys may support:** statements about the clocks during the latency runs: the range of
  the relative rate, the largest abrupt change, the largest offset worked off in a run, how many
  runs were steady. **What they may not:** any statement about a latency, a deadline or a duration
  measured in another experiment; and no key says which clock was adjusted. That board B is the
  adjusted one rests on the service status of the two boards (environment records: board B
  synchronized, board A not), which the text states as such. The sentence on the other experiments
  is an inference and is worded as one: "a duration measured on a board whose clock is being
  adjusted is scaled by the adjustment rate of that moment, at most N % in these runs".

## Tables

Each table is written as Markdown and as a booktabs `tabular` (no preamble). Times are in µs. The
`ladder` column of the throughput tables is the ladder id of the number keys
(`mldsa65-c1-cyclic-mf1ms`), so two ladders of one directory can be told apart.

| Table | Rows | Meaning |
|---|---|---|
| `validity` | checked file | Valid or invalid with the reason, the two counters, mlockall, CPU share, start and end frequency, throttled, warnings |
| `crypto_ops` | file × op | n, mean, sd, min, percentiles (type 7), max, CV, lag-1 autocorrelation of the post-warm-up times |
| `crypto_ops_ci` | file × op | Moving-block bootstrap 95% intervals of the median and p99 |
| `exceedance` | file × signing op × threshold | Samples above the threshold, P(t > d), exact Clopper-Pearson 95% interval |
| `sign_excess` | file × signing op | From the file footer: `wall_s`, `cpu_s` and their difference, the time the process was not on a processor (whole file, warm-up included). From the samples: the calls above 10 ms and the time they spent beyond 10 ms each (sum of t − 10 ms). Keys `….header.off_cpu_s`, `<op>.excess_over_10ms_s`, `<op>.excess_over_10ms_calls` |
| `sign_tail_fit`, `sign_tail_counts.csv` | signing series | For a series of at least 100,000 values: the counts above 1, 2, …, 25 ms (CSV: `file,op,n,threshold_ms,count_above,in_fit`), the largest value, the fit of a geometric decay (range, ratio per ms with its 95% interval, dispersion), the same fit from 1 ms, the samples above the fit end. For every signing series of the run: the expected count above its largest value under the fitted decay, for its number of calls |
| `sign_attrib`, `sign_attrib_tail`, `sign_attrib_two_by_two`, `sign_attrib_shares`, `sign_attrib_rounds` | file; × threshold; × number of rounds | Wall time against processor time of every signing call, and the rounds of a counting run: see "Wall time and processor time of every signing call" above |
| `overhead_paired` | file or pooled launch set × op | Within launch, optimistic: median paired difference and ratio, paired Hodges-Lehmann estimate with 95% CI, Wilcoxon p, TOST on paired log-ratios against the margin (geometric mean of the ratios, 90% CI), Cliff's delta |
| `overhead_across_launch` | launch set × op | The headline: launch-level Hodges-Lehmann estimates (mean, SD, min, max, 95% and 90% t-intervals), geometric-mean ratio with 90% t-interval, TOST over launches, verdict |
| `overhead_launches` | launch × op | The Hodges-Lehmann estimate and geometric-mean ratio of each launch |
| `overhead_noise_floor` | A/A file or pooled A/A set × op | Second standalone call against the first: the noise floor of the paired comparison, no margin |
| `overhead_order` | file or pooled set × op | Order effect: paired differences of AB pairs against BA pairs |
| `overhead_unpaired` | legacy file × op | Mann-Whitney p, two-sample Hodges-Lehmann shift with 95% CI, Cliff's delta, post hoc TOST, lag-1 autocorrelation of each phase, moving-block bootstrap 90% interval of the relative median difference |
| `periodic` | configuration | Jobs, unfinished jobs, deadline misses (unfinished or `send_done − release > deadline`), miss ratio with exact Clopper-Pearson interval, longest miss run and most misses in any 10 / 100 / 1000 consecutive jobs (worst stream), and the queue model |
| `periodic_combined` | multi-partition cell | Partitions, summed streams, cores, releases and misses added over the partitions, miss ratio with its exact interval; the note says what the cell is: independent gateway processes, each with its own core (streams and cores are the sums), or sender processes that share a core (the cores column is the number of distinct cores) |
| `periodic_times` | configuration × quantity | Response, queueing, authentication and service time over the jobs that reached the stage |
| `periodic_rx` | configuration | Tx jobs delivered and not delivered, duplicate and out-of-order Rx rows; rows per result |
| `periodic_rx_times` | configuration × quantity | Verification (`verify_done − rx_done`) and delivery (`deliver − rx_done`) time over ok rows; reject-decision time (`verify_done − rx_done`) per failure class; one-way latency (`rx_done − send_done`) and end-to-end response (`deliver − release`) when a clock relation exists |
| `periodic_rx_streams` | configuration × stream | Jobs delivered and not delivered, Rx rows per result (`framing_fail` rows name no stream) |
| `e2e` | configuration | E9: delivered PDUs, end-to-end latency median, 99th and 99.9th percentile and maximum, median of the receive part, and what the offset is known to within (`offset_bound_total_us`); only runs that are a result for E9 |
| `throughput` | ladder × rate × repetition × host, then one row per partition | Steady-state PDU/s with Student-t 95% CI, CPU utilization, wire Mbit/s and bytes per PDU, send-queue mean and maximum, drops, drop ratio (drops / (done + drops) on that host alone); "sum of N" rows add the partitions of a step |
| `throughput_reps` | ladder × rate × repetition | Delivered PDU/s, PDUs offered, not delivered inside the window and, beside them, the releases dropped at a full queue (no subset of the former); loss ratio with its exact Clopper-Pearson 95% interval; the growth bound of the send queue and the size of one queued PDU, whether the queue grows by that rule, whether the repetition sustained the rate |
| `throughput_steps` | ladder × rate × quantity | One value per repetition: number of repetitions, mean, Student-t 95% interval, minimum, maximum of delivered PDU/s, loss ratio, share dropped at release, CPU of each host, wire rate, send-queue mean, maximum and slope |
| `throughput_no_retrans` | ladder × rate | The sensitivity line: repetitions, how many are without a retransmission and how many are left out for each reason; delivered mean, largest loss ratio, verdict and saturation point over all repetitions and over those without a retransmission, side by side. Written only when a transmitter file gives the count |
| `throughput_saturation` | ladder × rate | Repetitions, mean delivered rate, largest loss ratio, largest share dropped at release, whether the send queue grows in any repetition, in how many repetitions the step was sustained, the verdict, the saturation point (highest rate such that it and every lower step are sustained), and as labeled secondary columns the pooled loss ratio with its exact interval. The note states the thresholds (loss ratio at most 0.001, queue not growing), the trim, and any non-monotone steps |
| `attack` | file × vector | Delivered, rejected, rejection rate with exact Clopper-Pearson 95% interval, counts per stage, time to detect; for benign the one-sided 95% upper bound on false rejection (its two-sided interval is in `summary.json` and the keys) |
| `attack_stages` | file × vector × reject stage | PDUs rejected at that stage, exact interval of that proportion, time to detect there |
| `handshake` | file × role | Main-function mode and period, minimum handshake interval, attempts, count per result; over the successful handshakes the total time, the compute time (sum of the role's stage columns) and the bytes. The note says what each role's total spans: the responder's includes the initiator's computation and two network legs, and both include main-function scheduling |
| `functional` | functional run | Profile, streams, parts per side; PDUs sent, delivered, delivered in order, byte-exact; rejected per result class; handshake rows per role and result; TCP connections per side (every one reads `tcp_nodelay=1` in a valid run) |
| `functional_streams` | functional run × stream | Sent, delivered, in order, byte-exact |
| `hsneg` | negative-test directory | Test, variant and verdict of the oracle's record; repetitions asked and done, attacked handshakes, runs and runs passed; what each side logged per result class (counted here, added over the files of the test) next to what the oracle expected; PDUs sent, delivered, rejected and given up; key installations and `tcp_nodelay` per end. Dashes where there is no record line |
| `handshake_phases` | file × role × phase | Time of each stage the role uses (`hash` = all transcript hashes, `mac` = key-confirmation HMAC generate and verify) |
| `cyclictest` | file | Policy, load, duration, samples, cyclictest's min / avg / max, p99, p99.9 and p99.99 read from the histogram ("> N" when the percentile lies among the overflows), overflows, and the wake-ups later than 100 µs and than 1 ms (strictly above, overflows included; keys `late_over_100us.k`, `late_over_1ms.k`) |
| `footprint` | file × build, operation or host | Binary file size before and after strip and the sections `.text`, `.rodata`, `.data`, `.bss` of the stripped binary; instructions and cycles per signing call and their ratio; largest VmHWM and number of samples per host |

**Tail shape of signing.** For a signing series of at least 100,000 values the toolkit counts the
samples above every whole millisecond from 1 to 25 ms and fits a geometric decay: the ratio per ms
is the factor by which the count falls from one millisecond to the next.

- **Fit range**, computed for each series: from the first whole millisecond above its median to
  the last whole millisecond with at least 100 samples above it (`TAIL_START_QUANTILE`,
  `TAIL_MIN_COUNT` in `crypto_ops.py`).
- **Method.** What is fitted are the counts in the 1-ms bins between those thresholds, by Poisson
  regression with a log link; the counts above are nested in one another, so an interval from them
  would be too narrow. The 95% interval is the Wald interval of the log ratio with Student-t
  (bins − 2 degrees of freedom) and the standard error multiplied by the square root of the
  dispersion (Pearson χ² / (bins − 2)) when that is above 1. A dispersion far above 1 means the
  counts do not fall by a constant factor over the range.
- **Sensitivity.** The same fit started at 1 ms is reported beside it (`tail_ratio_from1ms`,
  `tail_dispersion_from1ms`).
- **Expected counts.** For every signing series of the run, table `sign_tail_fit` gives the
  expected count above x ms under the fitted decay, for n calls, where x is the largest value and n
  the number of calls of that series, and the fit is the series' own or that of the longest series
  of the same operation in the run (`tail_expected_above_max`). Beyond the fit end this continues
  the fitted decay.
- **Keys:** `<op>.tail_ratio_per_ms`, `.tail_ratio_lo`, `.tail_ratio_hi`, `.tail_dispersion`,
  `.tail_fit_from_ms`, `.tail_fit_to_ms`, `.tail_fit_bins`, `.tail_above_fit_end`,
  `.tail_ratio_from1ms`, `.tail_dispersion_from1ms`, `.tail_expected_above_max`.
- **Figure** `sign_tail_survival.pdf`: the fraction of samples above t on a log axis with the
  fitted slope.

The output describes the shape only.

Every proportion carries the exact two-sided Clopper-Pearson interval in the tables; the Wilson
interval is kept in `summary.json` and under `wilson95` keys. Both assume independent trials:
deadline misses come in bursts, so for the miss ratio either interval is too narrow under overload.

cyclictest puts a latency at or above the histogram size into the overflow counter only; its
`# Total:` is the sum of the printed buckets and leaves the overflows out, while its Min, Avg and
Max lines include them (rt-tests source). The sample count is therefore Total plus overflows, and
the percentiles are the smallest latency with at least that share of all samples at or below it, on
1 µs buckets (not the interpolating estimator of the other tables), the overflows counted as values
above the last bucket. A percentile that lies among them is printed as "> <last bucket>" (for
example "> 4999") and has no number key. The load condition is the file's `# load=` line; a file
without one is labeled `cpu<N>`. The two thresholds of the late wake-ups (100 µs, 1 ms) are round
values. They are descriptive counts, not a test, and no decision depends on them.

The model columns of `periodic` come from a trace-driven queue simulation (global non-preemptive
FIFO, the configuration's cores, service times resampled from a single-stream run of the same
profile, scheduler, payload, host and main-function setting when there is one): with the measured release offsets and job
count, with random offsets (mean and range), and with synchronous release.

`summary.json` holds every number of every table, each next to the path and SHA-256 of its source
file, plus the seed, the parameters and the toolkit identity. Probabilities there are fractions.

## numbers.tex: no number is typed by hand

`\input{numbers_all.tex}` (the merged file of the campaign, below; for a single run its own
`numbers.tex`) in the preamble, then:

```latex
The median signing time was \meas{e1.s1.iris.crypto_ops.sign_p8.mldsa_sign.p50_us}\,\textmu s in
session 1 and at most \meas{e1.all.iris.crypto_ops.sign_p8.mldsa_sign.p50_us.max_over_sessions}\,\textmu s
in any session.
% \measraw{key} gives the unformatted value
% a run analysed without --key-prefix has the same keys without the prefix: \meas{crypto_ops.sign_p8.mldsa_sign.p50_us}
```

An unknown key is a LaTeX error ("Undefined number key"), never an empty string. A value the run
does not have (a missing file, an undefined statistic, an unused handshake phase) gets no macro,
so citing it fails the build. The macros are `\meas` and `\measraw`, so siunitx (which owns `\num`)
can be loaded as well. Each definition line ends in a comment with source file, experiment, filter,
sample size and toolkit identity; `numbers.csv` (`key,value,formatted,unit,n,source_file,how`)
lists the same keys for auditing, and `number_keys.md` lists them without values (key, meaning,
unit, source file), for writing `\meas{key}` into the manuscript before the data exist: analyze a
dry run laid out like the campaign run and take the keys from there. It says which keys depend on
the data and which key parts follow the names of the run's files. `merge_numbers` does not write
one; the merged `numbers.csv` lists the merged keys.
The toolkit identity is the git commit of the toolkit (`-dirty`
if its sources have uncommitted changes), or `nogit-<hash of the sources>` outside a git repository.

**Percentile rule.** A percentile p of n values is a manuscript number only when at least 10
samples lie above it, n(1 − p) ≥ 10 (computed exactly; n is the number of values behind that
statistic, after any warm-up drop). With fewer, the value depends on the percentile definition
(nearest rank against the interpolating type 7). A percentile that fails the rule, and the bootstrap
interval of such a percentile, stays in `numbers.csv` and in `summary.json` but gets no macro:
`numbers.tex` leaves it out, `number_keys.md` marks it, and `suppressed_keys.txt` lists it with the
reason (`key <tab> reason`). For a percentile below the median the rule is mirrored: n p samples
must lie below it (`resid_p0_1`). The rule covers every percentile key: `p50 … p99_99` of any time, the
`p50_ci95` / `p99_ci95` bounds, the cyclictest percentiles read from the histogram, and every
median (`median_…` of the overhead files, `bytes_…_median`, `clock_rtt_median`), which needs 20
values. Mean, sd, minimum, maximum, counts, proportions and the Hodges-Lehmann estimates are not
sample percentiles. Examples: 999,000 values (a series of 1,000,000 calls after the warm-up) keep
p99.99 (99.9 above); 99,000 values keep p99.9 (99 above) and lose p99.99 (9.9 above); 19,000 values
lose p99.99 (1.9 above). `merge_numbers`
carries the list along and accepts a `.csv` that has exactly those keys more than its `.tex`.

`\measraw` is not defined for a p-value that underflowed (at or below 1e-300: it has no plain form,
and 0 would be wrong; `numbers.csv` shows `<1e-300`), nor for any key of a `DRY_RUN`, `PILOT` or `EXCLUDED` run.

### One numbers.tex for the whole campaign

`python3 -I <toolkit>/analysis/merge_numbers.py <analysis dir> <analysis dir> ... --out numbers_all.tex`
takes directories written by `make_tables` or `sessions` and writes:

- `numbers_all.tex`: a header naming every run (directory, key prefix, toolkit commit, number of
  keys), the macros once, then every key definition;
- `numbers_all.csv`: the audit rows of all inputs;
- `numbers_all.tex.suppressed.txt`: the keys that the percentile rule keeps out of the `.tex` file.

A per-run `numbers.tex` defines its macros with `\newcommand`, so two of them cannot be `\input`
together. The merged file is made for a manuscript that may define things before the `\input`:
`\measundefined` is only provided (`\providecommand`), so a manuscript that predefines it, for
example as a red PENDING marker while runs are missing, keeps its own, and without that
predefinition an unknown key is a hard error; `\meas` and `\measraw` are provided and then
redefined, so a fallback definition made earlier does not clash and is replaced.

It stops with exit code 1 and writes nothing when a key has different values in two inputs (both
directories are named; the same value twice is accepted), when an input's `.tex` and `.csv`
disagree beyond its suppressed keys, or when an input comes from a `DRY_RUN`, `PILOT` or `EXCLUDED`
run. `--allow-marked` accepts such an input: the header then says `CONTAINS VALUES THAT ARE NOT
RESULTS`, names the run, and the values stay wrapped in `\notaresult`. An input without
`suppressed_keys.txt` was written before the percentile rule and is refused too. The merge sees
what the analysis recorded, not the run directory: a run that was marked or relabelled after it was
analyzed must be analyzed again before it is merged.

### Key prefixes

Two runs of the same experiments have the same keys. Give each run a prefix when it is analyzed,
`<experiment>.<session>.<host>` (`--key-prefix e1.s1.iris`), and merge the results as above. The
campaign keeps the session part also where an experiment has one session so far (`e0.s1.iris`,
`e1a.s1.iris`), and a pilot takes `pilot` in its place (`e1.pilot.iris`), so that its keys cannot be
taken for a session's. Two runs that share a prefix collide in the merge as soon as one key has two
values.

### Sessions: ranges, never a pooled estimate

An experiment that is run in several sessions is reported per session. `analysis.sessions` takes
the analysis directories of the sessions, whose key prefixes must differ in exactly one part
(`e1.s1.iris`, `e1.s2.iris`, `e1.s3.iris`) and whose `--warmup` must be the same, and writes:

- `sessions.md` / `sessions.tex`: one row per session and statistic (a cell has two decimals, a
  percentage four significant digits, and more where the smallest and the largest session value would
  otherwise read alike: `0.02719` and `0.02722` ms, not `0.03` twice), followed by the smallest and
  the largest session value;
- `numbers.tex`, `numbers.csv`, `number_keys.md`, `suppressed_keys.txt` with the keys
  `<prefix with the session part replaced by all>.<statistic>.min_over_sessions`,
  `.max_over_sessions` and `.range_over_sessions`, for example
  `e1.all.iris.crypto_ops.sign_p8.mldsa_sign.p99_us.max_over_sessions`. Merge them with the
  sessions' own files by `merge_numbers`.

The statistics are those the manuscript quotes: `p50`, `mean`, `p99`, `p99_9`, `p99_99`, `max`
(each as `_us` and `_ms`), `exceed_5ms.p`, `exceed_10ms.p`, `exceed_20ms.k`,
`tail_ratio_per_ms` and, for E9, `e2e.offset_bound_us`, `e2e.offset_bound_total_us` and
`e2e.bound_total_us` (the bound stands beside every latency across the two boards; by the suffix
rule `e2e.map_X.check_max_us` and `e2e.map_X.gap_max_ms` get a range as well). Every key of the sessions that ends in one of these gets a range, whatever its
experiment: the signing times of E1, and likewise `cyclictest.<policy>-<load>.max_us` or
`crypto_attrib.<file>.off_max_us`. No other statistic gets one: not the counts and shares of
`sign_attrib`, not `late_over_*.k`. The largest maximum over the sessions is
`….max_us.max_over_sessions`. There is no mean over sessions and no pooled estimate. A key named
`n` (the number of values of a file and operation) that differs between the sessions stops the
command, because a caption states one n; the cyclictest sample count (`samples`) is not compared,
and neither is `e2e.n` of E9 (nor `e2e.stream<k>.n`), the PDUs delivered in a session, which is an
outcome and not a count that the design fixes (so the E9 sessions of a cell give, among their `e2e` keys, ranges for the
latency and receive-part mean, median, p99, p99.9 and maximum, the probe's median delay and largest
gap, and the offset bound; not for `latency_p90_ms`, the counts, the drift or the causality margin).
Each board is its own set of sessions: the part of the prefix that varies is the session, so
`e1.s1.baolong`, `e1.s2.baolong`, `e1.s3.baolong` give `e1.all.baolong.…` in a second command.

**How a range is printed.** A range is its own statistic. Both ends have the same number of
decimals, and that number shows one significant digit of the distance between the two ends,
nothing else: no floor from the decimals a session prints, none from the unit's own rule.
- `3.2629` to `3.2635` for two tail ratios that each print `3.26`; `3.652\%` to `3.657\%` where
  the sessions print `3.65\%` and `3.66\%`;
- `523.9` to `524.5` µs for two medians of which one session prints `523.925`; `28` to `29` ms for
  two maxima of 27.83 and 29.29 ms; `2{,}453` to `2{,}456` µs for two medians 2.6 µs apart;
- one more decimal only where that digit would print the two ends alike, which takes two ties that
  round to the same digit (11.5 and 12.5 would both be `12`): a range tells its ends apart whenever
  they differ;
- one floor: where that digit would print a non-zero end as zero, both ends get the decimals that
  show one significant digit of the smaller non-zero end (`0.06` to `4.00` ms for maxima of 0.062
  and 4.0 ms; `0.0004\%` to `0.3000\%`). An end that is exactly zero prints as zero;
- counts stay whole;
- ends that are exactly equal have no distance and print as the sessions do. Two values less than
  a nanosecond apart are different values and print as a range. "Exactly equal" is equal to twelve
  significant digits, the precision a value is taken to have everywhere in the decimals rules: a
  difference beyond that is floating-point noise, adds no decimals, and is not a range.

`.range_over_sessions` is the third key of a statistic: the whole range as one piece of text, the
two ends as their own keys print them with an en dash between (`2{,}453--2{,}456`), or the one
value when the ends are exactly equal (`1.8`, where two end keys would give "1.8--1.8"). Its unit is
`text`; `\measraw` gives the plain ends (`2453.352--2455.982`). The dash is an en dash in text
mode only.

A statistic that one session lacks gets no range (the table says
which session lacks it), and the range of a percentile that the percentile rule holds back in any
session is held back too. A marker in any session marks the output. The values are rebuilt from
each session's `summary.json`, so the current percentile rule applies to sessions analyzed earlier.

### Keys

The key scheme is a contract with the manuscript: a key that has been published keeps its name and
meaning. New quantities get new keys.

`[<prefix>.]<experiment>[.<label>].<selector>.<quantity>`, built only from `A-Z a-z 0-9 _ -` and
dots. Text from a file or directory name that does not fit is an error, not silently changed. Two
files that would produce the same key are an error naming both.

| Experiment | Key | Example |
|---|---|---|
| `crypto_ops` | `crypto_ops[.<label>].<op>.<stat>_<unit>` | `crypto_ops.mldsa_sign.p99_9_ms`, `crypto_ops.mldsa_sign.exceed_10ms.cp95_hi` |
| file header | `<experiment>[.<label>].header.<name>` | `overhead_paired.header.signature_mismatches`, `crypto_ops.header.msg_bytes` |
| `overhead_paired` | `overhead_paired[.<label>].<op>.<quantity>` | `overhead_paired.sign.hl_ci95_lo_us`, `overhead_paired.L07.sign.hl_us`, `overhead_paired.aa.sign.hl_us` |
| across launches | `overhead_paired[.<label>].<op>.across_launch.<quantity>` | `overhead_paired.sign.across_launch.hl_mean_us`, `….hl_t95_lo_us`, `….gm_ratio_diff_t90_hi`, `….tost_p`, `….n_launches` |
| `overhead_unpaired` | as `overhead_paired`; TOST per margin; `lag1_standalone`, `lag1_csm`, `median_rel_diff_bb90_lo/hi` | `overhead_unpaired.perf.sign.tost_m1pct_p`, `archive.e2.overhead_unpaired.perf.verify.lag1_csm` (with `--key-prefix archive.e2`) |
| `periodic` | `periodic[.<file label>].<config>[.s<stream>].<quantity>` | `periodic.p10ms-s4-c1-mldsa65-fifo-cyclic-mf1ms-sync-part0.miss_cp95_lo`, `….s2.misses`, `….rx_verify_p50_us`, `….latency_p99_ms` |
| `periodic`, E9 | `periodic[.<file label>].<config>.e2e.<quantity>` | `….e2e.latency_p50_ms`, `….e2e.latency_p99_9_ms`, `….e2e.rxpart_p50_ms`, `….e2e.offset_bound_us`, `….e2e.causality_violations` (the names of `E9_SPEC.md`, each in the one unit its name says; 22 on a valid run) |
| `throughput` | `throughput.<ladder>[.r<rate>[.rep<k>][.<tx or rx>]].<quantity>` | `throughput.mldsa65-c1-cyclic-mf1ms.saturation_pps`, `….r400.delivered_pps_mean`, `….r400.loss_ratio_max`, `….r400.rep2.loss_ratio`, `….r400.rep2.rx.pps_mean`, `….loss_max` |
| `attack` | `attack[.<label>].<vector>[.<stage>].<quantity>` | `attack.replay.rejection_cp95_lo`, `attack.replay.freshness.count` |
| `handshake` | `handshake[.<label>].<role>.<quantity>`, `handshake[.<label>].header.<name>` | `handshake.iris.initiator.total_p50_ms`, `handshake.iris.initiator.compute_p50_us`, `handshake.raspberrypi.responder.hash_p99_us`, `handshake.iris.initiator.result_sig_fail`, `handshake.iris.header.t_min_ms` |
| `functional` | `functional[.<directory>].<quantity>`, `.s<stream>.<quantity>`, `.<role>.n`, `.<role>.result_<class>`, `.tx.<quantity>`, `.rx.<quantity>` | `functional.sent`, `functional.delivered_in_order`, `functional.delivered_byte_exact`, `functional.rejected_auth_fail`, `functional.s2.delivered`, `functional.initiator.result_ok`, `functional.rx.tcp_connections`, `functional.rx.tcp_nodelay_1`, `functional.tx.parts` (the directory part is the name of the marked directory when it lies below the run directory; there is none when the run directory itself holds the marker). All counts; no time is a key |
| `hsneg` | `hsneg.<test>.<role>.n`, `.result_<class>`; from the record `hsneg.<test>.verdict` (text: `PASS` or `FAIL`), `.repetitions`, `.repetitions_done`, `.attacked`, `.runs`, `.runs_passed`, `.pdus_sent`, `.pdus_delivered`, `.pdus_rejected`, `.pdus_given_up`, `.installs_tx`, `.installs_rx` | `hsneg.t1.initiator.result_sig_fail`, `hsneg.t12-flip.verdict` (`<test>` is `t<test>[-<variant>]` from the record; without a record line it is the directory's name, `hstest`, and there are only the counts). No time is a key |
| `cyclictest` | `cyclictest[.<label>].<policy>-<load>.<quantity>` | `cyclictest.fifo-idle.max_us`, `cyclictest.other-idle.p99_9_us` (`<load>` is the `# load=` line; `cpu<N>` for a file without one) |
| `footprint` | `footprint.size.<file label>[.<build>].<name>`, `footprint.perf.<op>.<quantity>`, `footprint.perf.<op>.n<calls>.<event>`, `footprint.rss.<host>.<quantity>` | `footprint.size.gw_tx.stripped_bytes`, `footprint.size.gateway_iris.build-tx.text_bytes`, `footprint.perf.mldsa_sign.instructions_per_call`, `footprint.perf.mldsa_sign.n2000.cycles`, `footprint.rss.iris.vmhwm_max_kb` |
| `sign_attrib` | `crypto_attrib[.<label>].<file name without .csv>.<quantity>` | `crypto_attrib.sign_attrib_p8.off_above_floor_s`, `….cpu_over_10ms.share`, `….rounds_threshold_10ms` |
| run parameters | `run.<parameter>` | `run.seed`, `run.warmup`, `run.block_len`, `run.n_boot`, `run.trim`, `run.sim_draws`, `run.sim_jobs`. `run.warmup` stands in every `numbers.csv`; it applies to the single-node series (`crypto_ops`, `sign_attrib`, `overhead_paired`, `overhead_unpaired`) and to nothing else, and its `how` says so |
| over sessions (`analysis.sessions`) | `<prefix with the session part replaced by all>.<key of a session without its prefix>.min_over_sessions`, `.max_over_sessions`, `.range_over_sessions` (text: both ends, or the one value) | `e1.all.iris.crypto_ops.sign_p8.mldsa_sign.p99_us.max_over_sessions` |

- `<config>` is read from the Tx file header:
  `p<period>[-d<deadline>]-s<streams>-c<cores>-<profile>-<scheduler>[-<mainfunction>][-mf<period>][-<phase>][-part<partition>]`;
  the deadline appears only when it differs from the period, and each of the last four only when
  the file has that optional header key. The networked harness writes all four in every file, so
  its configurations read `p10ms-s1-c1-mldsa65-other-cyclic-mf1ms-sync-part0`; a file without them
  keeps the short id. The header values themselves are `….period_ms`, `….deadline_ms`, `….streams`,
  `….cores`, `….payload_bytes`, `….mf_period_ms`, `….partition`. A multi-core periodic run is one
  configuration per partition. The combined cell is keyed `periodic[.<label>].<config>-parts<N>.…`,
  where `<config>` carries the summed streams, the distinct cores and no `-part<i>`
  (`periodic.p10ms-s8-c4-mldsa65-other-cyclic-mf1ms-sync-parts4.miss_ratio`), with `jobs`, `misses`,
  `miss_ratio`, `miss_cp95_lo/hi`, `streams`, `cores`, `partitions`. A second file with the
  same header (a repeat, another payload or host) must be named `periodic_tx_<label>.csv` /
  `periodic_rx_<label>.csv`; its keys are then `periodic.<label>.<config>.…`.
- `<ladder>` is `<profile>-c<cores>[-<mainfunction>][-mf<period>]`: `<cores>` is the header's `cores`
  times the number of partitions (`c4` for four single-core processes), the last two parts appear
  when the files have the optional header key. A run directory can hold one ladder per id; files
  that disagree in another header key (for example `commit`) count as two ladders with one id and
  are refused. `r<rate>` is the summed offered rate of the step.
- Throughput step keys have one shape whatever the number of repetitions: `….r<rate>.n_reps`,
  `.judged_reps`, `.sustained_reps`, and per quantity (`delivered_pps`, `loss_ratio`, `tx_drop_ratio`, `tx_cpu_util`,
  `rx_cpu_util`, `wire_mbit_s`, `sendq_mean_bytes`, `sendq_max_bytes`, `sendq_slope_bytes_per_s`)
  `_mean`, `_t95_lo`, `_t95_hi`, `_min`, `_max`. Values of one repetition sit under `.rep<k>`:
  `.offered_pdus`, `.lost_pdus`, `.dropped_pdus`, `.loss_ratio`, `.loss_cp95_lo/hi` and the host rows `.tx.…`,
  `.rx.…` (`pps_mean`, `cpu_util`, `drops`, `drop_ratio`, …). Files without a repetition number
  have the same keys without the `.rep<k>` part. `….loss_max` is the threshold. The rows of single
  partitions are in the table and in `summary.json` only.
- `<label>` distinguishes several files of one experiment. It is the directory name without the
  leading words it shares with the experiment, then the file's own label: none for
  `crypto/crypto_ops.csv`, `mac` for `attack_mac/attack.csv`, `1e6` for `crypto_1e6/crypto_ops.csv`,
  `single` for `overhead/overhead_paired_single.csv`.
- A launch set takes the keys a single file in its directory would take: `overhead_paired.sign.hl_us`
  is the pooled within-launch estimate, `overhead_paired.sign.across_launch.…` the headline. Each
  launch of the set is keyed by its number, whatever its file is called: `overhead_paired.L07.sign.…`
  (`overhead_paired.aa-L07.sign.…` in an A/A set).
- `header.<name>` exists for every numeric `# name=value` line of a single-node harness file
  (message size, timer overhead, context switches, the two counters); `….cpu_share` is `cpu_s / wall_s`.
- Receiver times: `rx_verify_…`, `rx_deliver_…`, `rx_reject_freshness_fail_…`, `rx_reject_auth_fail_…`.
- Handshake: `total_…` is the role's `total_ns` (not crypto time; see the table note), `compute_…`
  the sum of its stage columns, then one group per stage the role uses (`keygen_`, `encaps_`,
  `decaps_`, `sign_`, `verify_`, `kdf_`, `hash_`, `mac_`), all over successful handshakes;
  `result_<value>` counts attempts; `header.mf_period_us` and `header.t_min_ms` are the file's lines.
  The label of a handshake file is the host its `# host=` line names (`handshake.raspberrypi.responder.…`
  for a file whose line reads `# host=raspberrypi`, whatever the file is called); a file without that line uses its file label.
- Percentiles are `p50 p90 p95 p99 p99_9 p99_99`; `<prefix>n` is the number of values behind them
  (`response_n`, `latency_n`). Every time exists as `_us` and as `_ms`.
- An interval names its method: `cp95_lo/hi` (exact two-sided Clopper-Pearson; every proportion has
  it: `exceed_<d>ms.cp95`, `miss_cp95`, `rejection_cp95`, `false_rejection_cp95`), `wilson95_lo/hi`,
  `cp95_onesided_hi`, `t95_lo/hi` and `t90_lo/hi` (Student-t of a mean), `ci95_lo/hi` (bootstrap and
  Hodges-Lehmann), `ci90_lo/hi` (TOST).
- `…_diff` quantities are signed. `gm_ratio_diff` and `median_ratio_diff` are the ratio minus 1.

### Not in numbers.tex

These numbers of `summary.json` have no macro: the coefficient of variation and lag-1
autocorrelation of anything but `crypto_ops`; the constants of the equivalence test (alpha 0.05, the
90% level, degrees of freedom); the number of fixed-offset model runs (3); exceedance thresholds
and offered rates, which are part of the key; the per-round rows of a counting run (table
`sign_attrib_rounds`); and fields that repeat another value (`by_stage.none` = n − rejected, the
per-file copies of the run parameters, the validity fields that are header lines). A test fails
when a new number in `summary.json` has neither a key nor an entry in that list (a second test does
the same for a functional run and a negative handshake test, which the synthetic full run of the
first does not contain). The plain sum
`off_total_s` of a `sign_attrib` file has a key in `numbers.csv` and no macro (above).
The `payload_len` of a functional run has no key (a header line; it decides whether byte-exact is
judged). Of a negative handshake test, the record's `expected_*` and `seen_*` lists and its `tcp_nodelay_*`
fields are in the table `hsneg` and have no key: the `seen` counts are those counted here (a
difference makes the test invalid), and the result classes that did not occur have no key at all.
Also without a macro, because there is no number to print: a cyclictest percentile among the
overflows, a time whose stage is declared not recorded, the confidence bound of a send-queue slope
summed over partitions, and the rows of single partitions.

### Formatting, by unit

| Unit | Rule | Examples |
|---|---|---|
| `us` | Integer, thousands separator `{,}` | 2527.4 → `2{,}527` |
| `us`, cyclictest | min, avg, max and the percentiles are whole microseconds read from a 1 µs histogram: always an integer (the histogram mean follows the general rule) | 3 → `3`, 52 → `52` |
| `ms` | Two decimals | 2.5274 → `2.53` |
| both | Never fewer than two significant digits | 0.321 µs → `0.32`, 4.27 µs → `4.3` |
| `percent` | Percentage with two significant digits of the smaller of p and 1 − p; above one, one significant digit of the excess over 100%; a value that stands alone is scientific below 0.01%; `\%` included | 0.0023 → `0.23\%`, 0.99512 → `99.51\%`, 3.4e-5 → `3.4\times10^{-3}\%` |
| `p` | Two significant digits; scientific below 0.001; `<10^{-300}` at or below 1e-300, also for an exact 0 | 0.427 → `0.43`, 3.2e-7 → `3.2\times10^{-7}` |
| `count`, `bytes` | Integer with separators | 10000 → `10{,}000` |
| `id` | The integer as it is (the seed) | `20261122` |
| `text` | A word of a fixed vocabulary that the reader has checked, or text the toolkit composed from numbers it formatted (a range over sessions), printed as it is; `\measraw` gives the same word, or the plain ends of a range | `PASS`, `2{,}453.4--2{,}456.0` |
| `clock.*` keys | Rates in ppm: whole numbers, the signed ones always with their sign; offsets in ms: one decimal; the span in s: whole | 499.6 ppm → `\ensuremath{+}500`, 7.46 ms → `7.5` |
| other | Three significant digits | 4.56 Mbit/s → `4.56` |
| `sign_attrib` rounds | `rounds_mean`, `rounds_mean_geometric`: two decimals. `rounds_one_share` and its two bounds: one decimal, more where the percentage rule gives more. The text sets them next to values of the standard | 4.87, 4.92; 0.2033 → `20.3\%`, not `20\%` |

An estimate and all its confidence bounds are printed with the same number of decimals: the
largest any of them needs under the rule above. So `13.4 [8.6, 16.1]`, `+2.1 [−10.9, +18.3]`; and
an estimate takes the decimals of its bounds also when it is cited alone: 13 of 10,000 prints
`0.130\%` next to its lower bound `0.069\%`.

A proportion (unit `percent`) or a time (`us`, `ms`) with bounds gets at least the decimals that
show one significant digit of the smallest distance between the estimate and a bound that differs
from it, so that a narrow interval is not printed as its estimate. Two significant digits each
would print 31,250 of 999,000 calls as `3.1\% [3.1\%, 3.2\%]`; it is `3.13\% [3.09\%, 3.16\%]`. A
median of 2,455.98 µs with the interval 2,455.80 to 2,456.19 is `2{,}456.0 [2{,}455.8, 2{,}456.2]`
and, in ms, `2.4560 [2.4558, 2.4562]`; the median has these decimals also when it is cited alone.
A time without bounds keeps the unit's rule. A distance that vanishes at 12 significant digits is
rounding noise and adds no decimals. Other units (ratios, rates, counts) keep the rule of the
paragraph above.

The distance is taken at the precision of the two values, not of their floating-point difference:
a bound exactly 1 ns from a median of 523.925 µs is 0.001 µs away and gives three decimals. The
test compares the rule with exact arithmetic.

A time is rounded once, in decimal arithmetic and half to even, from the value at its twelve
significant digits; for a whole or half number of nanoseconds that is the exact value, in µs and
in ms alike, so a tie in one unit is a tie in the other: 67.5 µs prints `68` and `0.068`.

**One rounding for everything that is printed.** Every number that is printed with a fixed number
of decimals or of significant
digits goes through one function, `tables.rounded()` (and `tables.significant()` on top of it):
the number keys of every unit and every cell of every table, the sessions table included. Decimal
arithmetic, half to even, from the value at its twelve significant digits. A table cell can
therefore never differ in its last digit from the key beside it. Not through this function, because they are not such prints: the
scientific notation of a very small proportion or p-value, the exact parameters written with the
format `g` (a threshold, a period, an offered rate), the texts of validity reasons, and the
legends of the figures.

A proportion with bounds is always in fixed notation: `0.050\% [0.046\%, 0.055\%]`, and
`0.00070\% [0.00028\%, 0.00144\%]` for 7 of 999,000. The smallest member sets the decimals: one
call of 999,000 prints `0.0001001\% [0.0000025\%, 0.0005577\%]`. A proportion that is exactly zero
prints `0\%`, and one that is exactly one `100\%`, whatever the decimals of its group, because a
count of none or of all has no such precision: none of 999,000 is `0\% [0\%, 0.00037\%]`, and 1000
of 1000 is `100\% [99.63\%, 100\%]`. Only the exact values do: a proportion that is not zero never
prints as zero, and one below one never as 100% (999,999 of a million is `99.99990\%`). A value
above one (a utilization under overload) prints with the decimals that show one significant digit
of its excess over 100%: `100.04\%`, `100.3\%`, `104\%`. So `100\%` always means exactly one.

A test checks on every estimate with bounds that printing never puts a bound on the other side of
its estimate, and for proportions and times that a bound which differs in value differs in print.

Signs are typeset with `\ensuremath`, so every macro works in text and in math mode; a value that
rounds to zero carries no sign. Time macros carry no unit; write it after `\meas{…}`.
