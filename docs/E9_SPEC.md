# Spec: E9, end-to-end latency across the two boards

Status: APPROVED by the author on 2026-11-24 (23:10). The accompanying letter commits to this figure ("End-to-end latency from transmission request to application delivery has a median of [XX] ms and p99 of [XX] ms"). Decisions on the open questions: assumption 1 holds; cells f and g and the verification-only operation are included; no cooling hardware, so more than two sender processes stay a stated limitation.

## Assumptions

1. "Receive path end-to-end" means ONE latency per PDU from its release on the sender (board A) to its delivery to the application on the receiver (board B), so that the receive path (reception, reassembly, freshness check, verification, delivery) is inside the measured interval. Delivery itself is already shown end to end (10,000 of 10,000 PDUs, gateway binaries on both boards); what the paper does not have is this latency, because the two boards' clocks are not synchronized.
2. The clocks are NOT disciplined (no PTP, no chrony on eth0). The Raspberry Pi 4 Model B has no hardware time stamping, a clock daemon would need a package installation and root, and it would change the platform that every other experiment was measured on. Instead the offset between the two monotonic clocks is MEASURED during each run by a two-way exchange, and the latency is reported with the bound of that measurement.
3. The measurement harness is used (as for Table 13), because it releases in open loop and records every stage; one further cell with the gateway binaries on both boards confirms the figure if their files carry the two time stamps (to be checked in the plan).
4. The product code (`source/`, `include/`) stays byte-identical to the measured commit 09d6946. Only `bench/` and `scripts/` get a new commit, and the analysis toolkit a new head at which all 29,768 existing keys reproduce unchanged.
5. E9 adds one paragraph and one table to the manuscript. The Zenodo draft is not published before the E9 data are in it.

## Objective

The receive path is to be validated end to end, and real-time suitability is to rest on measurements. The revised paper reports sender-side deadlines and receiver-side times separately and says that no latency across the boards is computed. E9 closes that gap: for periodic streams, the distribution of the time from release on board A to delivery on board B, with a stated bound on the error of the clock-offset measurement.

Success looks like: a table with, per cell, the number of PDUs, the end-to-end latency (median, 99th and 99.9th percentile, maximum) and the offset bound in microseconds; one paragraph in Section 4.2.2; the sentences "no latency across the two boards" replaced by what was measured and how.

## Method

- Both harness files already carry absolute `CLOCK_MONOTONIC` time stamps per PDU: `periodic_tx.csv` (`release_ns`, `send_done_ns`, board A) and `periodic_rx.csv` (`rx_done_ns`, `verify_done_ns`, `deliver_ns`, board B). Missing is the offset θ = clock B minus clock A over the run.
- Clock probe: a small program without the stack, client on A and server on B, UDP on the eth0 link, ten exchanges per second for the whole run, on a core that the measurement does not use. Per exchange four time stamps: t1 (A sends), t2 (B receives), t3 (B replies), t4 (A receives). Offset sample θ = ((t2 − t1) − (t4 − t3)) / 2, round-trip delay δ = (t4 − t1) − (t3 − t2). The true offset lies within θ ± δ/2 whatever the asymmetry of the two directions.
- Offset track: in every window of 5 s the exchange with the smallest δ is an anchor; θ(t) is the straight line between neighboring anchors. Bound of a run: b = the largest δ/2 among its anchors.
- Per PDU: end-to-end latency = `deliver_ns` − θ(t) − `release_ns`; transfer and receive part = `deliver_ns` − θ(t) − `send_done_ns`.
- File `clock_probe.csv` (new section of DATA_SCHEMA.md): comment header (both hosts, clock, interval, port, commit), columns `seq,t1_ns,t2_ns,t3_ns,t4_ns`, footer with exchanges sent and completed.

## Validity of an E9 run (in addition to the rules of the periodic runs)

1. Probe coverage: first completed exchange before the first release, last one after the last delivery, no gap above 1 s.
2. Offset bound b at most 100 µs; a run with a larger bound is kept on file and not reported.
3. Causality: for every delivered PDU, `rx_done_ns` − θ(t) − `send_done_ns` ≥ −b (a PDU is not received before it was sent). One violation excludes the run.
4. No number from a dry run is quoted; sessions are not pooled.

## Cells (100 Mbit/s, deadline = period, as Table 13)

| Cell | Variant | Period | Streams | Scheduler | Releases | Sessions |
|---|---|---|---|---|---|---|
| a | signature | 10 ms | 1 | default | 100,000 | 3 |
| b | signature | 10 ms | 1 | SCHED_FIFO | 100,000 | 1 |
| c | signature | 10 ms | 2 | default | 100,000 per stream | 1 |
| d | signature | 20 ms | 1 | default | 50,000 | 1 |
| e | MAC | 10 ms | 1 | default | 100,000 | 1 |
| f | signature, receiver on another core | 10 ms | 1 | default | 100,000 | 1 |
| g | signature, gateway binaries on both boards (confirmation) | 10 ms | 1 | default | as the binary allows | 1 |
| h | one signature stream and one MAC stream in one sender process (concurrent protected PDUs of both variants) | 10 ms | 1 + 1 | default | 100,000 per stream | 1 |
| i | signature, with an unprotected TCP flow of about 50 Mbit/s on the same link (unrelated concurrent traffic) | 10 ms | 1 | default | 100,000 | 1 |

About 3.5 hours of board time in all, in two windows with idle time between them.

Small addition in the same harness commit (not part of E9 proper): an operation of the primitive benchmark that verifies one signature repeatedly without signing, so that the instructions per verification can be measured the way those per signature were.

## Tech stack and structure

- Harness: C, in `Autosar_SecOC/bench/` of the code repository (new file `bench_clock_probe.c`, entry in `bench/CMakeLists.txt`), driver `scripts/run_bench_net.sh` (the `periodic` mode starts and stops the probe when `CLOCK_PROBE=1`). New commit on top of 09d6946.
- Analysis toolkit: parser for `clock_probe.csv`, module for the offset track and the latency keys under the prefix `e9.s<n>.<cell>`, a table for the manuscript.
- Own reader: `own/e2e_compare.py` of the campaign directory, written without the toolkit, compared key by key.
- Records: this file, CAMPAIGN.md (plan and rulings), DATA_SCHEMA.md (format), RESULTS.md (outcome).

## Commands

    scripts/run_bench_net.sh build                                              # both boards, under the board locks
    DRY_RUN=1 CLOCK_PROBE=1 scripts/run_bench_net.sh periodic <id> 10000 2000 other     # dry run, never quoted
    DRY_RUN=0 HOLDING_MEASURING=1 CLOCK_PROBE=1 scripts/run_bench_net.sh periodic <id> 10000 100000 other
    python3 -I analysis/make_tables.py <run dir> --out <dir> --key-prefix e9.s1.<cell>
    python3 own/e2e_compare.py <run dir> <analysis dir> e9.s1.<cell>

## Code style

As the existing harness files, for example:

    (void)fprintf(out, "stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result\n");

Fixed-width integer types, every return value used or cast to void, one `# key=value` comment line per header field, time stamps in integer nanoseconds of `CLOCK_MONOTONIC`.

## Testing strategy

1. Same-host test: client and server of the probe on ONE board, where the true offset is zero: every anchor must give |θ| ≤ δ/2. This tests the estimator against a known answer.
2. Two-direction test: one probe A to B and one B to A at the same time: the two offset tracks must sum to zero within their bounds.
3. Parser and track computation: unit tests in the toolkit with synthetic exchanges (known offset, known drift, asymmetric delay).
4. Dry runs of every cell before the campaign; the causality rule is checked on each.
5. Toolkit at the new head: all existing keys identical (regeneration of the 88 accepted runs).
6. Own reader agrees with the toolkit on every E9 key before a run is accepted.

## Boundaries

- Always: board lock and measurement markers for every board use; a dry run before a campaign run; numbers reach the manuscript only as keys; an independent reader on the changed manuscript text.
- Ask first (the author decides): installing a package or changing clock discipline on a board; any change of product code; publishing the Zenodo record; uploading the manuscript.
- Never: touch wlan0 or the default route; make an eth0 setting persistent; change anything that was on the boards before 2026-11-22; quote dry-run data; store a credential in a repository or a record.

## Success criteria

1. Tests 1 to 3 pass and their logs are on file.
2. Every reported cell satisfies the four validity rules; the bound b is printed beside its latency figures.
3. Product trees byte-identical to 09d6946; existing keys unchanged.
4. Manuscript: paragraph and table in Section 4.2.2, the statements about clocks in Sections 4.2.1, 4.2.2 and 5.1 and in the accompanying letter updated; abstract and highlights changed only if a headline number is added.
5. Dataset rebuilt with the E9 runs; Zenodo draft updated, not published.

## Open questions

1. Is assumption 1 what is meant by "receive path end-to-end"?
2. Cells f (receiver on another core) and g (gateway binaries) and the verification-only operation: include them (the default) or leave them out?
3. More than two sender processes stay out: three busy cores bring a board to its throttling temperature within about a minute. It would need cooling hardware on the boards.

## Interface details (binding for harness, toolkit and own reader)

File `periodic/clock_probe.csv` in the run directory, written by the probe client on board A:

    # tool=bench_clock_probe
    # commit=<12 hex>
    # host_a=<host>            (client; t1 and t4 are on its clock)
    # host_b=<host>            (server; t2 and t3 are on its clock)
    # clock=CLOCK_MONOTONIC
    # interval_ms=100
    # port=<udp port>
    # cpu_a=<core>
    # cpu_b=<core>
    seq,t1_ns,t2_ns,t3_ns,t4_ns
    0,119899302191756,99940948741547,99940948760001,119899302291000
    ...
    # exchanges_sent=<n>
    # exchanges_completed=<n>

Only completed exchanges are rows; `seq` counts the exchanges sent, so a lost one shows as a gap in `seq`. All values are integer nanoseconds.

Definitions (integer arithmetic until the final division):
- offset of exchange i: theta_i = ((t2 - t1) - (t4 - t3)) / 2, in ns, clock B minus clock A; delay delta_i = (t4 - t1) - (t3 - t2); time of the exchange on clock A: tau_i = (t1 + t4) / 2.
- anchors: the run is cut into windows of 5 s of clock A starting at the first tau; in each window that has an exchange, the exchange with the smallest delta (the earliest one on a tie) is the anchor.
- theta(t) for a time t on clock A: linear interpolation between the two neighboring anchors by their tau; before the first and after the last anchor, the value of that anchor.
- bound of the run: b = max over anchors of delta / 2.
- per delivered PDU (rows of periodic_rx.csv with result ok, joined with periodic_tx.csv on stream and seq): latency = deliver_ns - theta(release_ns) - release_ns; receive part = deliver_ns - theta(send_done_ns) - send_done_ns; causality margin = rx_done_ns - theta(send_done_ns) - send_done_ns.

Keys, under `<prefix>.periodic.<configuration>.e2e.` (percentiles of type 7; a percentile is emitted only when at least ten samples lie above it):
`n`, `latency_mean_ms`, `latency_p50_ms`, `latency_p90_ms`, `latency_p99_ms`, `latency_p99_9_ms`, `latency_max_ms`, `rxpart_p50_ms`, `rxpart_p99_ms`, `rxpart_max_ms`, `offset_bound_us`, `anchors`, `probes_completed`, `probe_delay_min_us`, `probe_delay_p50_us`, `probe_gap_max_ms`, `drift_ppm` (slope of the anchors' theta over tau, least squares, informational), `causality_min_us` (smallest causality margin), `causality_violations` (PDUs with margin below -b).

A run is not a result for E9 when `probe_gap_max_ms` exceeds 1000, when the first anchor lies after the first release or the last anchor before the last delivery, when `offset_bound_us` exceeds 100, or when `causality_violations` is not 0.

## Rulings of 2026-11-24 (answers to questions from the harness work)

1. Header: one key per comment line, so `# cpu_a=<core>` and `# cpu_b=<core>` are two lines (corrected above).
2. Instructions per verification: a separate small tool `bench_verify_only` (signs once before the loop, then only verifies, same library calls, flags and context as the verify row of the primitive benchmark). `bench_crypto_ops.c` and `bench_common.h` stay byte-identical, because the primitive timings were measured with them. Its `perf stat` files are named `perf_mldsa_verify_only_<n>.csv`; the toolkit turns exactly two run lengths of this operation into a per-call figure, as it does for `mldsa_sign`.
3. (Changed 2026-11-24 23:55.) Development and the dry runs on the boards happen in `~/pqc-secoc-rev1-bench`, the standing harness directory, and not in a new directory `~/pqc-secoc-rev1-e9`. The campaign of 2026-11-24 is complete and its data are on the Mac, so the directory is free. For the E9 campaign the accepted commit is deployed into the same directory through the driver's build mode.
4. The probe runs at least 5 s before the first release and 10 s after the transmitter has ended, on core 1.
5. Cell g (gateway binaries): the gateway files carry `submit_ns` and `send_done_ns` (app_tx.csv) and `verify_done_ns` and `deliver_ns` (app_rx.csv), no `rx_done_ns`. For this cell: latency = deliver_ns - theta(submit_ns) - submit_ns; receive part = deliver_ns - theta(send_done_ns) - send_done_ns; causality margin = verify_done_ns - theta(send_done_ns) - send_done_ns (a PDU is not verified before it was sent). The keys carry the same names under `<prefix>.functional.e2e.`. The probe file lies beside the gateway files in the run directory (`clock_probe.csv`).

## Rulings of 2026-11-24, second set (definitions shared by the toolkit and the own reader)

- Coverage rule: the anchor version of "Interface details" is the rule (an anchor on each side of the PDUs); the wording under "Validity" about the first and last completed exchange is superseded. The probe therefore runs from at least 5 s before the first release to at least 10 s after the last delivery.
- Exchanges are ordered by tau = (t1 + t4) / 2. Gap: the largest difference between the tau of two consecutive completed exchanges.
- First anchor against first release: both on clock A (the anchor's tau against the smallest `release_ns`, or `submit_ns` for the gateway files). Last anchor against last delivery: both on clock B without conversion (the anchor's (t2 + t3) / 2 against the largest `deliver_ns` of the ok rows).
- Joined rows: every receiver row with result ok whose stream and seq are in the sender's file; a duplicate ok row counts twice. An ok row whose sender row has `send_done_ns` = 0 makes the run invalid for E9.
- A percentile with fewer than ten samples above it is written to `numbers.csv` and held back from `numbers.tex`, as every other percentile of the toolkit.
- `drift_ppm`: least-squares slope of the anchors' theta over their tau, times 1e6, signed (positive: clock B runs faster); no key with fewer than two anchors.
- `probe_delay_min_us` and `probe_delay_p50_us`: over all completed exchanges.
- "Exceeds" is strict: a gap of exactly 1,000 ms, a bound of exactly 100 us and a margin of exactly minus the bound pass.
- The probe file: `exchanges_completed` must equal its rows; a file without that line is invalid; a row with t4 before t1, t3 before t2 or a negative delta makes the file invalid.
- A run that fails a rule: `clock_probe.csv` is listed under `invalid_runs` with the reason, there is no `e2e` key, and the periodic (or functional) keys of the directory stay as today.
- Harness files in which `rx_done_ns` is declared not recorded: no `e2e` key (causality cannot be judged), listed with that reason; the gateway cell uses `verify_done_ns` as ruled above.
- Archive analysis: as in the accompanying letter, a moving-block bootstrap with block length 100 of the relative difference of the medians (integrated over standalone, minus 1), blocks resampled within each phase; lag-1 autocorrelation per phase; two one-sided tests with the survival function.

## Addendum A (2026-11-25): the attacker as a separate network node, simulated (cell j)

Reason: the revision describes a third node that acts as an in-line attacker. No third machine is available; the question of 2026-11-25 was whether the node can be simulated. It can, as a separate network stack on the sender's board.

Layout on board A (non-persistent, created and removed by the driver; eth0, wlan0 and the default route are not changed):
- network namespace `txns` with one end of a virtual Ethernet pair (`veth-tx`, 10.99.0.1/30); the transmitter runs inside it and has no route to the receiver;
- the other end (`veth-atk`, 10.99.0.2/30) in the root namespace, which owns eth0 with board A's address: this is the attacker node. The relay (`relay_tamper.py`, unchanged, holds no key) listens on 10.99.0.2 and connects to the receiver from board A's address, so the receiver sees its configured peer;
- the transmitter is the build whose peer is the relay, as in E4, with the peer address 10.99.0.2; the relay is pinned to a core other than the transmitter's.

Cells: j-sig and j-mac = the layout and counts of the accepted E4 runs (13,000 PDUs, the relay acts on every third, five kinds of manipulation, 1,000 each), one run per variant, receiver = gateway binary on board B.

Validity, in addition to the rules of E4: `ip netns exec txns ip route get <receiver address>` fails before the run (recorded in the run directory as `netns_check.txt`, with `ip -d link show` of both ends and the addresses); the relay's log shows the peer address 10.99.0.1 for the transmitter's connection; namespace and pair are gone after the run.

What may be written from it: the manipulated PDUs came from a node with its own network stack and address between the sender's stack and the cable; both stacks run on board A, because no third machine was available; manipulation below TCP is still not covered. What may not be written: "a third machine", "a bridge with NFQUEUE", or any timing comparison with E4.

Keys: the same key names as the E4 attack table under the prefix of the new run (e4n).

Open when this was written: whether `ip netns` and the veth module are present on board A and usable with the rights the campaign already uses; whether the peer address of the transmitter build is a build parameter.

## Addendum B (2026-11-25): further periodic cells (rows that had not been measured), experiment E6x

Reason: the plan of the revision named further cells that had not been measured (10 ms with 3 and 5 streams, 20 ms with 6 and 8, 50 ms with 20, 100 ms with 40) and speaks of the MAC variant at periods "of 10 ms or less". From the code at 8e38d08: the product configures 8 signature PDUs and one MAC PDU, and a sender process takes `STREAMS=1..8`, so everything up to 8 streams runs without any change; 20 and 40 streams would need new rows in the product configuration, which stays as measured.

Cells (100 Mbit/s, one sender process on one core, default scheduler, deadline = period, all streams released at the same instants, no clock probe: the conditions of the periodic table), harness and product of the E9 campaign commit:

| Cell | Variant | Period | Streams | Releases per stream |
|---|---|---|---|---|
| sig_p10000_k3 | signature | 10 ms | 3 | 100,000 |
| sig_p10000_k5 | signature | 10 ms | 5 | 100,000 |
| sig_p20000_k6 | signature | 20 ms | 6 | 50,000 |
| sig_p20000_k8 | signature | 20 ms | 8 | 50,000 |
| sig_p50000_k8 | signature | 50 ms | 8 | 20,000 |
| sig_p100000_k8 | signature | 100 ms | 8 | 10,000 |
| mac_p5000_k1 | MAC | 5 ms | 1 | 100,000 |
| mac_p2000_k1 | MAC | 2 ms | 1 | 100,000 |

One session, cells in a seeded order, about 2 hours. Run names `E6x_s1_<cell>_other_<time>`, key prefix `e6x.s1.<cell>_other`, the periodic keys and the own reader of E6. Validity: the rules of E6.

What may be written: the measured miss share of each cell with its exact interval and its longest run, labeled as measured with the harness of the E9 commit (the product code is the same). For a cell above the sustained rate (five streams at 10 ms are 500 PDU/s) the text says so and does not present the share as a deadline figure of a schedulable load. Eight streams is the largest count the product configuration has; the 20 and 40 streams of that plan are answered by that sentence, not by a number. No simulated value enters the paper.

## Rulings of 2026-11-25 (after the own reader was proved on the dry-run directories)

- Per-stream latency keys for a file with more than one stream (cells c and h): `<prefix>.periodic.<configuration>.e2e.stream<k>.` with n, latency_p50_ms, latency_p99_ms, latency_p99_9_ms, latency_max_ms. The keys over all streams stay. In cell h the paper gives the two streams separately and says that the MAC PDU of a tick leaves behind the signature PDU of the same tick.
- The background flow of cell i has keys (`...bg.rate_offered_mbit_s`, `rate_achieved_mbit_s`, `bytes_sent`, `bytes_received`, `verdict`); a FAIL verdict or the marker BG_INVALID makes the latency keys of the directory not a result.
- A `probetest` directory has keys for the two tests of the method; they are quoted in the supplement only, as the check of the estimator.
- Own check of an E9 directory: `own/e9_compare.py` = the layout reader (periodic or gateway) and the latency reader; both must agree with the toolkit.
- Cells a and f have the same configuration id; the key prefix (`e9.s1.a`, `e9.s1.f`) tells them apart.

### Addendum A, corrected 2026-11-25 01:20 (after it was built; this replaces the wording above where they differ)

- The accepted E4 data come from the `attack` mode of `scripts/run_bench_net.sh` with `attack_proxy.py` (not from `run_e2e.sh` with `relay_tamper.py`), and the proxy ran on board A. Cell j is therefore the three E4 lines of each variant with `RELAY_NETNS=1`: the run with four manipulation kinds (13,000 PDUs, every third), the recording run, and the replay of the recorded earlier session. Run names `E4n_s1_<sig|mac>[_rec|_old]`, key prefix `e4n.s1.<...>`.
- The peer address of the harness transmitter is a run-time option (`--peer 10.99.0.2:<port>`); nothing is built for it.
- `attack_proxy.py` gained the option `--bind` and one log line with the transmitter's address; forwarding and manipulation are unchanged (control run without the namespace: same judging output, same rows and keys). Accepted.
- Creating the pair loads the stock `veth` kernel module on board A, which stays loaded until the next boot. Accepted and recorded; nothing else remains after a run.
- Validity as written above; a run without the failing route check, the transmitter's address in the proxy log or the removal of namespace and pair is EXCLUDED by the driver.

## Rulings of 2026-11-25 01:35 (after the independent review of the harness diff; binding for harness checker, toolkit and own reader)

Finding of the review (verified from the dry-run files): board B's clock is disciplined by systemd-timesyncd over Wi-Fi, so the rate between the two CLOCK_MONOTONIC clocks is not constant during a campaign (the probe files show -8.3 ppm, then +92 ppm falling to +9 ppm within 25 minutes). Assumption 2 of this specification ("free-running clocks, constant drift within a run") is withdrawn. The track is a straight line between anchors up to 10 s apart; a change of rate inside a segment puts it off by up to (change) x (length) / 4, which the anchor bound b does not cover. The service on the board is not stopped (it existed before this work; changing it is an "ask first" item). Instead the data must show that the track holds:

1. Interpolation term. Anchors k = 0..K-1 with (tau_k, theta_k); segments i = 0..K-2 with length L_i = tau_{i+1} - tau_i and slope s_i = (theta_{i+1} - theta_i) / L_i. For segment i: d_i = |s_i - s_{i-1}| (if i >= 1) + |s_{i+1} - s_i| (if i <= K-3); c_i = d_i x L_i / 4. `offset_interp_us` = max_i c_i over all segments (0 with fewer than three anchors). It bounds the deviation of the line from the true offset inside a segment when the rate changes monotonically between the neighboring segments. Not a result when `offset_interp_us` > 50.
2. Total bound. `offset_bound_total_us` = `offset_bound_us` + `offset_interp_us`. This is the figure the paper prints for "known to within". The existing rule `offset_bound_us` <= 100 stays.
3. Consistency of every exchange. For every completed exchange j with tau_first_anchor <= tau_j <= tau_last_anchor: it is outside when |track(tau_j) - theta_j| > delta_j / 2 + offset_bound_total (exact integer arithmetic in ns where the implementation has it). `exchanges_outside` = their number. Not a result when it is not 0: an exchange outside contradicts the claimed bound.
4. Probe interval 101 ms instead of 100 ms, so that the probe does not keep one phase to the 10 ms releases and the 1 ms cycle for a whole run. The rule on gaps (1000 ms) is unchanged.
5. A run with CLOCK_PROBE=1 whose `clock_probe.csv` was not collected is E9_INVALID with exit status 1, as an invalid file is.
6. Driver and tools, small corrections: the commit comparison must not cut off a `-dirty` suffix (compare the 12 hex digits AND keep the suffix; the probe header prints it); `bench_net_rx` refuses an unknown profile name, and the pair of periodic files is checked for the same `# profile=`; `bg_traffic.py` records the largest deficit behind the nominal byte count and the number of send time-outs in its report (`max_deficit_bytes`, `send_timeouts`; recorded, not judged).
7. Instructions per verification: the two run lengths are 10,000 and 20,000 calls (key generation and the one signature differ between two launches by whole rounds of the rejection loop; with 10,000 calls of difference that is below 0.05 % of the per-call figure).
8. Notes that go into the text or the schema, no code: the end-of-run temperature gate is read 10 to 17 s after the run when the probe is used; the receiver processes in its 1 ms cycle, so a latency contains a wait of up to one cycle whose phase moves with the drift (the keys print `drift_ppm`); the paper says that the two clocks are not synchronized with each other and that board B's clock is disciplined by NTP, never "free-running" or "undisciplined"; every run line of the campaign carries LINK_SPEED=100 (the campaign script does).

### Amendment to rulings 1 to 3 (2026-11-25, 01:25; found before any campaign file exists)

In the first and the last segment the interpolation term has one neighbor only, so a rate step there is not bounded (a 100 ppm step in a first segment of 5.4 s: term 67.5 us, line 135 us off). Counting the one neighbor twice does not bound it either (a step early in the segment). Therefore the end segments are not used:

1a. Coverage: at least TWO anchors lie at or before the first release, and at least two at or after the last delivery (first release >= tau of the second anchor on clock A; last delivery <= tau of the second-to-last anchor on clock B). This replaces "one anchor on each side". With fewer than four anchors a run is not a result.
1b. `offset_interp_us` = max of c_i over the interior segments i = 1..K-3 (the segments with a neighbor on both sides), c_i as defined in ruling 1.
3a. `exchanges_outside` counts the completed exchanges with tau of the second anchor <= tau_j <= tau of the second-to-last anchor.
3b. Causality is judged against the total bound: a violation is `rx_done_ns - theta(send_done_ns) - send_done_ns < -offset_bound_total` (gateway layout: `verify_done_ns` in place of `rx_done_ns`). A margin between -total and 0 does not contradict the claimed bound.
4a. Driver: the probe starts 12 s before the transmitter and runs 12 s beyond its end (`PROBE_LEAD_IN`, `PROBE_LEAD_OUT`), so that two anchors lie on each side.
`offset_bound_us` stays the maximum over all anchors.

### On hold (2026-11-25, 01:32): the definition of `offset_interp_us`

On the real probe files it was shown that a term built from slopes of neighboring segments (rulings 1 and 1b) is inflated when two anchors of neighboring windows lie close together: 2 us over 0.101 s is 20 ppm, which a 7 s neighbor turns into 36 us with no change of rate; about 8 % of campaign cells would meet such a pair. Rulings 1 and 1b are suspended; amendments 1a, 3a, 3b and 4a stay.

Candidate, being evaluated on the dry-run files before it is ruled (no campaign file exists): the probe's low-delay exchanges that are not anchors serve as a hold-out set. V = the completed exchanges j in the region (second anchor to second-to-last anchor) with delta_j / 2 <= offset_bound; `offset_interp_us` = max over V of |track(tau_j) - theta_j|; `offset_bound_total_us` = offset_bound + offset_interp; `validation_exchanges` = |V|; `validation_gap_max_ms` = largest distance in tau between consecutive members of V. Statement it supports exactly: at every instant of V the track is within the total bound of the true offset (|track - true| <= |track - theta_j| + delta_j / 2). Not a result: offset_interp_us > 50; validation gap above a limit to be fixed from the dry-run figures; exchanges_outside != 0. The probe test of the two directions uses the sum of the two total bounds as its limit.

### FINAL ruling on the clock track (2026-11-25, 01:40; replaces rulings 1, 1b, 2 and the candidate "on hold"; amendments 1a, 3a, 3b, 4a and rulings 4 to 8 stay)

Evaluation on the 17 real dry-run probe files: the hold-out candidate with the threshold b leaves gaps of 4 to 8 s (in the window of the worst anchor nothing else is as good as it), and a wider threshold inflates the term. The form below needs no threshold and no slope.

Definitions (binding for check_clock_probe.py, the toolkit and the own reader):
- Region: from tau of the second anchor to tau of the second-to-last anchor (amendment 1a; fewer than four anchors is not a result).
- For every completed exchange j with tau_j in the region: `cert_j = |track(tau_j) - theta_j| + delta_j / 2`, track = the straight line between the two anchors around tau_j. At tau_j the track is within cert_j of the true offset, since the true offset lies within delta_j / 2 of theta_j. An anchor has cert = its own delta / 2.
- G = 2,000 ms. T(G) = the smallest T such that the exchanges of the region with cert_j <= T, taken together with the two ends of the region, leave no distance in tau above G between neighbors. `offset_cert_us` = T(G). Statement it supports exactly: at instants no more than 2 s apart the probe certifies the track to within T of the true offset.
- `offset_bound_total_us` = max(`offset_bound_us`, `offset_cert_us`). This is the figure the paper prints. `offset_bound_us` stays the largest delta / 2 over all anchors.
- `exchanges_outside`: exchanges j of the region with |track(tau_j) - theta_j| > delta_j / 2 + offset_bound_total (such an exchange proves that the track is off by more than the printed bound at that instant).
- Causality: a violation is a margin below minus offset_bound_total (amendment 3b).
- Not a result: no T exists; `offset_bound_total_us` > 100; `exchanges_outside` != 0; a causality violation; the coverage rule of amendment 1a; the existing rules (gap between exchanges above 1,000 ms, footer, impossible exchange).
- Keys: `e2e.offset_cert_us`, `e2e.offset_bound_total_us`, `e2e.exchanges_outside`. The keys `offset_interp_us`, `validation_exchanges`, `validation_gap_max_ms` are not introduced.
- Probe test of the two directions: the limit is the sum of the two total bounds.
- Arithmetic: tau_j = (t1 + t4) / 2 and the comparison with G in exact arithmetic (work with 2 tau in integer ns); cert_j exact where the implementation has rationals, otherwise the agreement tolerance of the readers applies.

Known answers that every implementation carries as tests: a 100 ppm step in the middle of a 5 s segment gives T(2 s) of about 125 us (not a result); a 100 ppm step in a 9.9 s segment between two short ones gives more than 200 us (not a result); two anchors 101 ms and 2 us apart with constant offset stay valid; a constant drift of 100 ppm stays valid.
On the 17 dry-run files T(2 s) is 42 to 67 us.

What the paper may say: "the offset between the two clocks was measured during each run; at instants no more than 2 s apart the measurement certifies the estimate to within B us". It may not say that the offset is known to within B at every instant.

### Addition to the FINAL ruling (2026-11-25, 01:48): which anchors set `offset_bound_us`

`offset_bound_us` is the largest delta / 2 over the anchors OF THE REGION (second anchor to second-to-last anchor, both included), not over all anchors. Reason (found on a new dry run, also note 12 of the review): the last window of a probe file is partial and can hold a single exchange, which is then an anchor whatever its delay (825 us in dry run i 183022Z); that anchor lies outside the region, no PDU uses its segment, and yet it alone set the bound to 413 us. The first and the last anchor only delimit; they do not enter any figure. Everything else of the FINAL ruling is unchanged.

## Addendum C (2026-11-25, 09:53; written after the first pass of E9, before any key of it exists): what the probe files say about the clocks themselves (keys `clock.*`)

**Why.** Both boards run `systemd-timesyncd`. Board B is synchronized to a pool server over its wireless interface (status read on 2026-11-25 after the campaign: delay 136.6 ms, jitter 31.8 ms); board A is not synchronized (every server times out). In the first pass of E9 the clock rule rejected 6 of 11 runs because board B's clock was being adjusted. Every experiment of the campaign measures durations on the boards' CLOCK_MONOTONIC, which such an adjustment scales while it lasts. The documents must state this with a figure, and the figure must come from the probe files through keys, independent of whether an E9 run is a result and of how the rejected cells are repeated.

**Inputs.** The `clock_probe.csv` of every run of the first pass that has one, valid for E9 or not: E9_s1_a, b, c, d, e, f, h, i (`periodic/clock_probe.csv`), E9_s1_g (`clock_probe.csv` beside the application logs), E9_s2_a, E9_s3_a; 11 files. They are listed with their sha256 in `clock_inputs/inputs.tsv` of the campaign directory (run directory, path of the file inside it, sha256); the run directories stay where they are until the E9 acceptance is decided.

**Definitions** (the same in the toolkit and in the own reader; none of them uses a PDU or a latency):
1. Exchanges, tau, theta and delta as in "Interface details"; anchors as in the FINAL ruling: windows of 5 s counted from the first completed exchange, the anchor of a window is its exchange with the smallest delta (the earlier one on a tie). ALL anchors are used here, the first and the last included.
2. Segment: two consecutive anchors whose tau differ by at least 2.0 s. Its rate is (theta_2 - theta_1) / (tau_2 - tau_1), in parts per million (theta is board B's clock minus board A's; a positive rate means board B's clock runs faster than board A's).
3. Per file: `segments`; `rate_ppm_min`, `rate_ppm_max`, `rate_ppm_median` over its segments; `rate_step_ppm_max`, the largest absolute difference between the rates of two consecutive segments (the size of an abrupt change); `offset_range_ms`, the largest minus the smallest theta over its anchors; `span_s`, tau of the last anchor minus tau of the first.
4. Over the 11 files: `files`; `rate_ppm_min` and `rate_ppm_max` (the smallest and the largest segment rate of any file); `rate_abs_max_ppm` (the larger of their absolute values) and the same as a percentage, `rate_abs_max_pct`; `rate_step_ppm_max`; `offset_range_ms_max`; `files_steady`, the number of files whose `rate_step_ppm_max` is at most 5 ppm, and `files_adjusted`, the others; `rate_ppm_steady_min` and `rate_ppm_steady_max`, the smallest and largest median rate among the steady files.
5. Uncertainty of a segment rate, stated once in the text and not as a key: each anchor's theta is known to within its delta / 2 (about 50 us), so a rate over 5 s is known to within about 20 ppm; the figures quoted are hundreds to thousands of ppm.
6. Keys: per file `clock.e9p1.<cell>.<stat>` with cell = s1.a, s1.b, ... s1.i, s2.a, s3.a; overall `clock.e9p1.all.<stat>`. Rounding: rates to 1 ppm, the percentage to two significant digits, offsets to 0.1 ms, by the toolkit's one rounding rule.
7. Known answers that both implementations carry as tests: a file with constant offset gives rate 0 everywhere and step 0; a file with a constant drift of 25 ppm gives min = max = median = 25 and step 0 (to rounding); a file whose drift changes from -25 to +500 ppm at an anchor gives rate_ppm_max 500, rate_step_ppm_max 525 and offset range as computed by hand in the test; anchors closer than 2 s form no segment.

**Readings fixed on 2026-11-25 (before the two implementations were compared):** (a) "two consecutive segments" are neighbors in the list of segments of a file; a pair of anchors closer than 2 s forms no segment and is skipped, so the two segments around it count as consecutive. (b) The median of an even number of rates is the mean of the two middle ones. (c) A file with fewer than two segments has `rate_step_ppm_max` 0; a file without a segment has no rate key and takes no part in `rate_ppm_steady_*`. (d) Windows are counted from the smallest tau of the file; every row is used as it stands. (e) Definition 5 holds for a segment of 5 s; segments go down to 2 s, where the same bound is about 50 ppm; the steady files show steps of 1 to 2 ppm, so the anchors are in practice much better than their delta / 2, and the 5 ppm limit separates steady from adjusted files by a wide margin on both sides (largest step of a steady file 1.7 ppm, smallest of an adjusted file 12 ppm, as first computed by the own reader).

**Limits of the figures, fixed on 2026-11-25 13:02:** (1) every rate is a MEAN over a segment of 2 to 10 s; where an adjustment begins inside a segment the momentary rate was higher than the segment's mean, so no document says "at most N % at any moment": the wording is "mean rates of up to N % over segments of 2 to 10 s". (2) A steady file is not an unadjusted file: the three steady files have medians of -25, +51 and -25 ppm on the same two boards, because the frequency correction that the service had set differed between them; `rate_ppm_steady_*` is therefore not a free-running difference of the two crystals. (3) The 8 files that are not steady are not the 6 runs that the E9 rule rejected: two runs (s1 i and s2 a) lay in a smooth decay of an adjustment and passed the rule. The two counts are never equated. (4) The raw value of `rate_abs_max_pct` is a percentage (0.6357...), printed "0.64 %".

**What these keys may and may not support.** They support statements about the clocks during the latency runs: the range of the relative rate, the largest abrupt change, the largest offset worked off in a run, how many runs were steady. They do NOT support any statement about a latency, a deadline or a duration measured in another experiment, and no key of them says which clock was adjusted; that board B is the adjusted one rests on the service status of the two boards (environment records: board B synchronized, board A not), which the text states as such. The sentence on the other experiments is an inference and is worded as one: "a duration measured on a board whose clock is being adjusted is scaled by the adjustment rate of that moment, at most N % in these runs".

**Where it runs.** Toolkit: a module with its tests and a command that takes the inputs file and writes numbers under the prefix; `regen_all.sh` gets a block for it like the one for the archived inputs. Own reader: `own/clock_rate.py`, written from this addendum alone, compared key by key. Both read files only; no board is used.

## Addendum D (2026-11-25, 09:53; NOT in force until the author allows it): repeating the rejected E9 cells with the time-synchronization service stopped

**NOT USED (author's decision of 2026-11-25, 12:43): the author chose the harness change (Addendum E) and not the stopping of the service. Nothing of this addendum was run; `campaign_e9c.sh` stays in the campaign repository unused.**

**Status.** This is the prepared answer for one of two possible decisions of the author (the other: a harness change so that the probe also records CLOCK_MONOTONIC_RAW). Stopping `systemd-timesyncd` changes the clock discipline of the boards and needs the author's leave; until it is given nothing of this addendum is run.

**Protocol, fixed before any repeat run:**
1. Cells: only the six cells whose run of the first pass was not a result: s1 b, c, f, g, h and s3 a. A cell that has its result is not run again (rule "one result per cell"). Same commit (b42716bc3e8c), same parameters and same driver options as in the first pass, and the same block structure: the session-1 cells b, c, f, h in one block in an order drawn from a new seed that is written to the log (one idle minute between runs), then the gateway cell g as a block of its own, then s3 a as a block of its own, each block after five idle minutes (`campaign_e9c.sh`, which calls `campaign_e9b.sh rs1 rg rs3`).
2. Both boards: `sudo systemctl stop systemd-timesyncd` on board A and on board B before the block (runtime only: the unit stays enabled, no file is changed, the service starts again at the next boot). The script restarts the service on both boards when the block ends, on every way out (trap on EXIT, INT, TERM), and records for each board the service state before the stop, after the stop and after the restart.
3. The kernel keeps working off an offset that the service handed it before the stop. Whether the clocks are steady is therefore JUDGED BY A PROBE-ONLY RUN, not by a waiting time: `run_bench_net.sh probetest <id> 120` (two probes over the link for 120 s, no PDU). The block starts only if, in that run, the rate between the boards is steady: the largest absolute difference between the rates of two consecutive anchor segments (definition of Addendum C) is at most 5 ppm in both directions' files. If not, wait five minutes and probe again; after six failed probes the block is not run, the service is restarted and the reason is logged.
4. Every run's environment record already carries `clock_services=...` for each board before and after the run (active or inactive); the run index names the service state of every E9 run, so that the runs of the first pass (service active) and the repeats (service stopped) are told apart, and the text states that the repeats were measured with the service stopped on both boards and why.
5. The clock rule itself is unchanged (FINAL ruling). A repeat that fails it is not a result either; a cell is repeated at most twice more, and a cell without a result after that is reported as such.
6. Nothing else on the boards is changed: wlan0, the default route, eth0 settings and every other service stay as they are.

## Addendum E (2026-11-25, 12:53; the author's decision of 12:43; written before any file of the new form exists): the latency measured on the raw clocks

**Why.** CLOCK_MONOTONIC is steered by the time-synchronization service (rate and offset corrections); in the first pass the corrections on board B were abrupt enough to break the track between two anchors in 6 of 11 runs (Addendum C). CLOCK_MONOTONIC_RAW of the same board is not steered at all. The author decided (2026-11-25 12:43) that no service on the boards is touched and that the probe records the raw clock as well. The PDU stamps stay what they are (CLOCK_MONOTONIC, the harness and the gateway logs are not changed); they are carried onto the raw clock of their board by a locally measured relation of the two clocks, and the offset between the boards is tracked on the raw clocks.

**Calibration behind the parameters** (2026-11-25 12:50, read-only on both boards): board A's CLOCK_MONOTONIC did not move against its raw clock (0.00 ppm); board B's moved at -14.9 to -10.6 ppm in a quiet stretch; within one second the relation is a straight line to within 0.14 us. The largest step of the relative rate between the boards in the first pass was about 6,900 ppm.

### E1. Scope of the change (binding)
- Changed: `Autosar_SecOC/bench/bench_clock_probe.c`, `check_clock_probe.py`, their tests and CMake entries, the two drivers `scripts/run_bench_net.sh` and `scripts/run_e2e.sh` (they start the probe, collect its files and call the checker), the documentation files of the harness.
- NOT changed, checked by diff list and tree hashes before the campaign commit is named: `Autosar_SecOC/source` (tree b82e1813...), `Autosar_SecOC/include` (tree 57e80b2b...), `bench_net_tx.c`, `bench_net_rx.c`, `bench_net.c`, `bench_net.h`, `bench_common.h`, `bg_traffic.py`, `attack_proxy.py` and every other harness that produces a PDU stamp. The gateway binaries are not changed either: cell g's stamps come from the product's own application logs, so the conversion of stamps is done by the readers, for both boards, never by the program that takes the stamp.

### E2. What the probe records (format 2)
- At each of its four stamp points the probe reads RAW, MONOTONIC, RAW in this order without anything in between. The raw read next to the datagram is the stamp of the exchange: before a send (t1 on board A, t3 on board B) the SECOND raw read; after a receive (t2 on board B, t4 on board A) the FIRST raw read. The monotonic read is kept, and the distance between the two raw reads is the width of that point.
- `clock_probe.csv` (written by the client on board A): header lines as before plus `# format=2` and `# clock_raw=CLOCK_MONOTONIC_RAW`; columns `seq,t1_ns,t2_ns,t3_ns,t4_ns,t1r_ns,t2r_ns,t3r_ns,t4r_ns,w1_ns,w2_ns,w3_ns,w4_ns`: the four monotonic reads (same meaning and position as in format 1), the four raw stamps of the exchange, the four widths. The other raw read of a point is its raw stamp minus the width (points 1 and 3) or plus the width (points 2 and 4). The reply datagram carries the server's six values.
- A second thread in each probe process (client and server), pinned to the probe's core, reads RAW, MONOTONIC, RAW every 5 ms from the start of the process until it ends and keeps the samples in memory. At the end the client writes `clock_map_a.csv` and the server `clock_map_b.csv`: header `# tool=bench_clock_probe`, `# commit=`, `# host=`, `# role=a|b`, `# clock=CLOCK_MONOTONIC`, `# clock_raw=CLOCK_MONOTONIC_RAW`, `# interval_ms=5`, `# cpu=`; columns `raw1_ns,mono_ns,raw2_ns`; footer `# samples=<n>` and `# samples_dropped=<n>` (samples that found the memory full; the memory is sized for one hour). The server ends on SIGTERM as before and then writes its file; the driver collects it. Both files lie beside `clock_probe.csv` (`periodic/` of a harness run, beside the application logs of a gateway run).
- The probe is started and stopped as before (12 s before the first release, 12 to 17 s after the last delivery), so both maps cover every PDU stamp.

### E3. The offset between the boards, on the raw clocks
For every exchange: tau = (t1r + t4r) / 2, theta = ((t2r - t1r) - (t4r - t3r)) / 2, delta = (t4r - t1r) - (t3r - t2r). Windows, anchors, region, `offset_bound_us`, cert_j, T(2 s) = `offset_cert_us`, `offset_bound_total_us` = max of the two, `exchanges_outside`, the gap rule (1,000 ms) and the coverage rule are those of the FINAL ruling, applied to these raw values. The time axis of the track is board A's raw clock.

### E4. Carrying a CLOCK_MONOTONIC stamp onto the raw clock of its board
- Map of board X (from `clock_map_<x>.csv`): a sample is VALID when 0 <= raw2 - raw1 <= 5,000 ns (a wider one was interrupted between its reads). For a valid sample: abscissa = mono, value m = mono - (raw1 + raw2) / 2 (exact: work with 2 m), half-width h = (raw2 - raw1) / 2.
- Conversion of a stamp x (CLOCK_MONOTONIC of board X): x_raw = x - m(x), with m(x) by linear interpolation between the two valid samples around x by their abscissa. A stamp before the first or after the last valid sample of its board cannot be converted: the run is not a result.
- Used range of board X: from the last valid sample at or before the earliest converted stamp to the first valid sample at or after the latest converted stamp.
- `map_gap_max_ms`: the largest distance in abscissa between two consecutive valid samples of the used range. Above 50 ms: not a result.
- `map_holdout_us`: the largest |m_k - L_k| over the valid samples k inside the used range that have a valid neighbor on each side, L_k being the straight line between samples k-1 and k+1 evaluated at k. `map_half_us`: the largest h in the used range. `map_bound_us` = map_holdout_us + map_half_us. (A rate that changes once inside two sample intervals shows up in the hold-out of a neighboring sample at least as large as the error it causes between two samples.)
- INDEPENDENT CERTIFICATE (the map is not only tested against itself): every stamp point of an exchange carries its own reading of the same relation, taken by another thread at another instant. For point p of board X with width w_p <= 5,000 ns: abscissa = its monotonic read, value = mono - (the mean of its two raw reads), half-width w_p / 2. `map_check_n`: the number of such points inside the used range; `map_check_max_us`: the largest |value - m(abscissa)| among them; `map_check_violations`: the points with |value - m(abscissa)| > map_bound_us + w_p / 2. Any violation: not a result. Fewer than 100 such points on a board in a harness run of 1,000 s (20 in the gateway run): not a result.
- Keys per board (a, b): `map_samples`, `map_samples_invalid`, `map_gap_max_ms`, `map_holdout_us`, `map_half_us`, `map_bound_us`, `map_check_n`, `map_check_max_us`, `map_check_violations`.

### E5. Latency, causality and the bound
- For a delivered PDU: release_raw and send_done_raw are the transmitter's stamps converted with map a; rx_done_raw and deliver_raw the receiver's converted with map b. latency = deliver_raw - theta(release_raw) - release_raw; receive part = deliver_raw - theta(send_done_raw) - send_done_raw; causality margin = rx_done_raw - theta(send_done_raw) - send_done_raw. theta(t) is the raw track of E3. (For the gateway run the stamps are those of the application logs, converted the same way.) Durations are in seconds of board A's raw clock; its rate differs from the SI second by the crystal's error, which changes a latency of milliseconds by less than a nanosecond.
- `bound_total_us` = `offset_bound_total_us` + `map_bound_us` of board A + `map_bound_us` of board B. Limit 100 us, as before. This is the figure the documents print, with the sentence of the FINAL ruling ("at instants no more than 2 s apart the measurement certifies the estimate to within B us"); the two map terms are certified every 5 ms and are included in B.
- A causality violation is a margin below minus `bound_total_us`. `exchanges_outside` is judged against `offset_bound_total_us` as before.
- Not a result: any rule of the FINAL ruling on the raw track; a stamp outside its map; `map_gap_max_ms` above 50 on either board; a `map_check` violation or too few check points; `samples_dropped` other than 0; `bound_total_us` above 100; a causality violation; a probe file of format 1 (no raw stamps: refused for latency).
- Verdict line of `e9_check.txt`: `PASS|FAIL offset_bound_us= offset_cert_us= offset_bound_total_us= map_bound_a_us= map_bound_b_us= bound_total_us= exchanges_outside=`.

### E6. What the maps say about each clock (keys per run and board; these replace Addendum C for the new runs)
Per board X, over its valid samples cut into windows of 1 s of abscissa counted from the first valid sample (a window needs samples at least 0.8 s apart): rate of the window = (m_last - m_first) / (abscissa_last - abscissa_first) in ppm (positive: CLOCK_MONOTONIC runs faster than the raw clock). Keys `clock.<x>.adj_ppm_min`, `adj_ppm_max`, `adj_ppm_median`, `adj_step_ppm_max` (largest absolute difference between consecutive windows), `adj_offset_range_us` (largest minus smallest m over the valid samples), `adjusted` (1 when adj_ppm_max - adj_ppm_min exceeds 1 ppm, else 0). Only these keys say WHICH board's clock was steered and by how much; the validity sentence of the documents rests on them. Addendum C remains the record of the first pass.

### E7. Tests every implementation carries (known answers)
1. Synthetic run, raw clocks with a constant relative rate of -25 ppm, board B's CLOCK_MONOTONIC steered by a step of +5,000 ppm for 10 s in the middle, PDUs with a known true latency: under this addendum it is a result, every latency is recovered to within `bound_total_us`, both map bounds are below 20 us; the same exchanges read on their monotonic columns by the FINAL ruling are not a result.
2. Steady clocks (CLOCK_MONOTONIC = raw + constant on both boards): the latencies of this addendum and those computed from the monotonic columns by the format-1 definitions agree to within `bound_total_us`; map hold-out 0.
3. A gap of 60 ms between valid samples inside the used range: not a result. A stamp 1 ms before the first valid sample: not a result.
4. A sample with raw2 - raw1 = 6,000 ns is not valid and is not used; with every other sample valid the run is still a result.
5. One exchange point whose own reading is off the map by 50 us (a corrupted value): one `map_check` violation, not a result.
6. `samples_dropped=3` in a footer: not a result.
7. A format-1 file: refused for latency with a message that names the format; the Addendum C statistics still read it.
8. E6: a board whose CLOCK_MONOTONIC equals raw plus a constant gives adj rates 0 and adjusted=0; the board of test 1 gives adj_ppm_max 5,000 and adjusted=1.

### E8. Acceptance of the new commit before the campaign
- Harness tests and the probe test (same host: true offset zero; both directions over the link) pass on both boards with format 2.
- Dry runs of cells a, e, i and g: PASS; in each, on its steady stretch (or the whole run if the clocks were steady), the latencies of this addendum and those from the monotonic columns agree within the bound (test 2 on real files); if a dry run happens to contain an adjustment, the old rule's verdict and the new one are both recorded.
- Review of the C diff by an independent reviewer (the second thread, the signal path, the file writes) with no open finding of importance.
- The diff list and the tree hashes of E1.

### E9. The campaign
All eleven cells of the first pass again at the new commit, same parameters, same block structure (prep, probe test, session 1 with cells a b c d e f h i in a seeded order with a new seed, g, s2, s3), one result per cell. The eleven runs of the first pass (commit b42716bc3e8c, format 1) are NOT used for any latency key, the five that passed the clock rule included: all cells are measured by one method at one commit. They stay in the dataset as measured and not used, with this reason, and Addendum C reports what the clocks did in them.

### E10. Key names (the same in the toolkit and in the own reader)
Under `<prefix>.periodic.<configuration>.e2e.` (gateway run: the place where the format-1 keys of that run are): every key of the earlier rulings keeps its name and now refers to the raw values (`n`, `latency_*`, `rxpart_*`, `offset_bound_us`, `offset_cert_us`, `offset_bound_total_us`, `exchanges_outside`, `anchors`, `probes_completed`, `probe_delay_min_us`, `probe_delay_p50_us`, `probe_gap_max_ms`, `drift_ppm`, `causality_min_us`, `causality_violations`). New: `bound_total_us`; `probe_format` (2); `probe_width_p50_ns` and `probe_width_max_ns` (the widths w of all exchange points of the file); for X in a, b: `map_X.samples`, `map_X.samples_invalid`, `map_X.gap_max_ms`, `map_X.holdout_us`, `map_X.half_us`, `map_X.bound_us`, `map_X.check_n`, `map_X.check_max_us`, `map_X.check_violations`, and `clock_X.adj_ppm_min`, `clock_X.adj_ppm_max`, `clock_X.adj_ppm_median`, `clock_X.adj_step_ppm_max`, `clock_X.adj_offset_range_us`, `clock_X.adjusted`. Diagnostic, emitted but never printed in a document as a result: `mono.offset_bound_total_us` and `mono.verdict` (1 = the format-1 definitions on the monotonic columns would call the run a result, 0 = not), and `mono.latency_p50_diff_us` (median latency by the monotonic columns minus median latency of this addendum; present only when `mono.verdict` is 1).

### E11. Readings fixed on 2026-11-25 13:00 (before any code; binding for the checker, the toolkit and the own reader)
- a. Hold-out: sample k takes part when the samples next to it in the file, k-1 and k+1, are both valid; they may lie outside the used range, so the two end samples of the range take part.
- b. "Inside the used range" is inclusive at both ends (check points and samples).
- c. Converted stamps. Board A: release and send_done of every joined delivered PDU, and the smallest release of the sender's file (for the coverage rule). Board B: the arrival stamp (rx_done in a harness run, verify_done in the gateway files) and deliver of every joined PDU, and the largest deliver over all rows with result ok. The used range of each board follows from these stamps.
- d. Minimum of check points: 100 per board in a harness run and 20 in a gateway run, whatever the length of the run.
- e. Limits are "not above": a width of exactly 5,000 ns is valid, a gap of exactly 50 ms passes, a bound of exactly 100 us passes.
- f. Probe test (same host; two directions): on the raw stamps for a format-2 file; a format-1 file is still judged on its monotonic columns there; only the latency reading refuses format 1.
- g. `check_csv.py` stays unchanged (E1). The driver and the CTest leave the probe's files (`clock_probe.csv`, `clock_map_a.csv`, `clock_map_b.csv`, the probe test's files) to `check_clock_probe.py`, which judges their format, footers and counts; the driver writes one line per such file into `check.txt` in the usual form (`<path>: ok` or `<path>: <fault>`), so that every CSV of a run directory still has its line there.
- h. Probe options and datagrams: both roles take `--map-out FILE`; a reply is matched on its sequence number alone (the request no longer carries t1, so that nothing lies between the second raw read of t1 and the send); a format-2 server refuses a format-1 request by name; a format-2 client that gets no reply says that there is no server or a server of another probe format.
- i. Whatever ends the server waits until it has written its map file (about 10 MB for a run of 1,000 s) before the files are collected.
- j. (ruled 13:07) A run that is not a result gets no key under `.e2e.`, the `clock_X.*`, `map_X.*` and `mono.*` keys included; the toolkit's `summary.json` carries the map and clock statistics of such a run as far as they can be computed, for the record, never as keys. The `mono.*` keys of a result are in `numbers.csv` and `number_keys.md` only and are listed as suppressed with the reason "diagnostic", so that no document can print them. In a directory with more than one sender and receiver pair the used range, the map keys and the verdict are per pair, and the run is a result as a whole or not at all (no E9 cell has more than one pair).
- k. (ruled 13:18) Also not a result: a map file whose footer `samples` differs from its number of rows; valid samples whose monotonic reads do not strictly increase in file order; a board with no valid sample, or with no stamp to carry. A stamp or check point that lies exactly on a sample takes that sample's value. E6: the step is taken between neighbors in the list of windows that have a rate. The rates of E6 are per unit of the board's CLOCK_MONOTONIC (the abscissa), so in the known answers of E7 "steered by +5,000 ppm" means that CLOCK_MONOTONIC gains 5,000 ns against the raw clock per 1,000,000 ns of its OWN reading; a generator that steers per unit of raw time gives 4,975.12 and is not the test.
- l. (ruled 13:42, measured during the harness development) The request datagram is as long as the reply (100 bytes each): on an idle 100 Mbit/s link the tracks of two probes running in opposite directions were 8.9 us apart with a 16-byte request and 1.7 us apart with equal lengths; equal lengths remove an asymmetry of one sign from every offset at the cost of about 3 us of bound.
- m. (ruled 13:47, from the own reader's run on the first real format-2 files) Probe test of the two directions: the anchors compared are the REGION anchors of each track (second to second-to-last) at instants inside the other track's region; the end segments of a track are not certified by the FINAL ruling and take no part. (The harness checker did this already; the toolkit and the own reader compared every anchor between the first and the last anchor of the other track and change to this.) A median is of type 7 everywhere, also in the checker's printed lines: with an even count the mean of the two middle values.
- n. What `clock_X.adjusted` means: 1 when the correction of the board's CLOCK_MONOTONIC CHANGED by more than 1 ppm during the run (adj_ppm_max - adj_ppm_min above 1), not whether a correction exists. A board whose CLOCK_MONOTONIC runs at a constant -1.8 ppm against its raw clock has adjusted = 0 and adj_ppm_median = -1.8. Statements in the documents about which clock was steered and by how much rest on the ppm keys (`adj_ppm_min`, `adj_ppm_max`, `adj_ppm_median`) and on `adj_offset_range_us`; the key `adjusted` only counts the runs in which the steering changed.
- o. (ruled 14:35, readings of the toolkit made common rules) Also not a result: a map in which no sample of the used range has two valid neighbors (no hold-out can be formed); a file whose `format=` header line disagrees with its columns; a map file with samples but without a `samples_dropped` footer line. A probe-test pair made of one file of each format is invalid. `map_X.samples` is the number of rows of the file. E6 is computed over all valid samples of the file, not over the used range. Printing: every bound of this addendum and of the FINAL ruling prints one decimal (microseconds), adjustment rates two decimals (ppm), widths whole nanoseconds.

### E12. Amendment after the independent review of the change (14:49; five reviewers, eight findings confirmed by a second reader each, none refuted; written before any campaign file of format 2 exists)

**E12.1 The map bound when the samples are not evenly spaced (a defect of E4, found by the review).** E4 said that a rate change inside two sample intervals shows in the hold-out of a neighboring sample at least as large as the error it causes. That holds only for equal spacing. The sampler can wake late, so two consecutive valid samples may lie g > 5 ms apart (E4 admits up to 50 ms), and a rate change of D inside such a gap puts the straight line across it off by up to D x g / 4, while the hold-out of the samples next to the gap sees less (the review's experiment on the checker: at a step of 6,900 ppm the printed bound was short by 5.3 us for a gap of 8.2 ms, the largest gap of the dry runs, by 22 us for 20 ms and by 69.5 us for 49 ms; a complete synthetic run with a 30 ms gap passed with a printed total of 70.7 us while one stamp was 50.6 us off). The bound is therefore extended by a term that is exact for one rate change per interval:
- Take the VALID samples of board X in file order (abscissa a_j, value m_j). Interval j lies between valid samples j and j+1; its length is g_j = a_(j+1) - a_j and its slope s_j = (m_(j+1) - m_j) / g_j.
- For every interval j whose two samples lie inside the used range (ends included): kink_j = |s_(j+1) - s_(j-1)| x g_j / 4, the largest error a single rate change inside interval j can cause, the rates before and after being read from the neighboring intervals. An interval of the used range that lacks a neighboring interval on either side (it would have to be the first or the last of the file) makes the run not a result.
- `map_X.kink_us` = the largest kink_j. New key.
- `map_X.bound_us` = max(`map_X.holdout_us`, `map_X.kink_us`) + `map_X.half_us`. (With evenly spaced samples the kink term is the error itself; the hold-out stays as a second, independent look.) Everything that uses the map bound follows: `bound_total_us`, the limit of 100 us, the map_check rule, causality.
- The gap limit of 50 ms stays; a gap is now paid for in the bound whenever the rate changed around it.
- The sentence of E5 "the two map terms are certified every 5 ms" is replaced by: "the two map terms bound the conversion in every interval between two samples of the map".
- Known answer 9 (added to E7): a map evenly spaced at 5 ms except for one gap of 30 ms; the board's CLOCK_MONOTONIC changes its rate by +6,900 ppm (per unit of its own reading) in the middle of the gap and keeps the new rate: `map_X.kink_us` is 51.75 us to within the generator's rounding, the true error of the straight line at the change is 51.75 us, the hold-out alone is smaller; with an offset bound of about 40 us the run is a result whose `bound_total_us` covers the error of every stamp. The same with a gap of 49 ms gives a kink term of about 84.5 us and, with the same offset bound, a total above 100 us: not a result.

**E12.2 Identity of the three probe files (review note made a rule).** Not a result: a map file whose `role` line is not the role of its file name (`clock_map_a.csv`: a; `clock_map_b.csv`: b); a map whose `host` line differs from `host_a` (map a) or `host_b` (map b) of `clock_probe.csv`; `commit` lines that differ among the three files; a `clock`, `clock_raw` or `interval_ms` line other than specified in E2. (That the commit of the probe files equals the campaign commit is checked at acceptance by `campaign_post.sh`.)

**E12.3 The harness checker's self-test** pins every rule that decides validity with one known answer each (E4, E5, E11 e, k, o, E12.1, E12.2); a rule without a test is listed in the harness notes (`docs/EXPERIMENTS.md`) as not tested.

**E12.4 Drivers.** When a probe process has not ended inside the driver's wait, the driver says so in one line that names the process and the wait, and it does not remove the board's run directory while a probe process is still running (it waits or ends the process first). After an interrupted run the probes are ended and waited for before the locks are released.

**E12.5 Not changed, on purpose.** The probe program (`bench_clock_probe.c`) stays as reviewed and as used in the dry runs: the review found no data race, no ordering fault and no accounting fault in the thread code and no fault in the stamps, the datagrams or the file formats. Its robustness notes are recorded in the harness notes (`docs/EXPERIMENTS.md`) as limits of its command line that the drivers never reach: option values are not fully validated (an unknown option before `--port`, a non-numeric value, a negative interval); a complete file of the same name left by an earlier run would survive a failed write (the drivers give every run a new directory); a full disk shows only at the end of a run, as a missing file, which makes the run E9_INVALID; after a late wake-up the sampler takes its next sample on the original grid, so two samples can lie close together (covered by E12.1); the return value of the clock reads is not checked (the clock ids are valid on Linux).

**E12.6 Readings of E12 fixed 14:58 (from the own reader's implementation).** The `interval_ms` rule of E12.2 concerns the two MAP files (5); the `interval_ms` of `clock_probe.csv` is the exchange interval (101 in the campaign), which E2 does not fix and which is not judged. A header line that is missing counts as a departure. A used range of a single sample has no interval and a kink term of 0 (it cannot occur with real stamps).

**E12.7 The slopes of the kink term are read over a baseline of at least 4 ms (15:19; found while E12.1 was built, before any campaign file).** After a wake-up more than one interval late the sampler takes the owed samples at once, so two valid samples can lie microseconds apart; a slope read between them is read noise divided by a tiny time, and E12.1 as first written multiplied it by the long gap beside it: one such wake-up put into the real maps of a clean dry run gave kink terms of 12 to 19 us in the median and up to 317 us, enough to fail a clean run. The two slopes are therefore read over at least 4 ms:
- For interval j (valid samples j and j+1, length g_j): slope before = (m_j - m_i) / (a_j - a_i) with i the LARGEST index below j for which a_j - a_i >= 4,000,000 ns; slope after = (m_k - m_(j+1)) / (a_k - a_(j+1)) with k the SMALLEST index above j+1 for which a_k - a_(j+1) >= 4,000,000 ns (indices over the valid samples in file order). kink_j = |slope after - slope before| x g_j / 4. An interval of the used range for which no such i or no such k exists in the file is not a result.
- With samples about 5 ms apart i = j-1 and k = j+2, so nothing changes there: known answer 9 stays (51.75 us and about 84.5 us). On the campaign-length dry run both forms give the same terms (board A: 0.056 us over the intervals of the used range, which is what the key holds, and 0.084 us over every interval of the file, the figure first reported; board B: 0.104 us either way; no two valid samples closer than 1.27 ms in 412,000).
- Known answer 10: a map of steady clocks (CLOCK_MONOTONIC equal to raw plus a constant) with read noise of up to 150 ns per sample, in which one wake-up comes 12 ms late and the two owed samples follow it 2 us apart: `map_X.kink_us` stays below 1 us and the run is a result. (By the first wording of E12.1 the same file gives tens of microseconds.)
- The hold-out is unchanged: it predicts a sample from its two file neighbors and has no such division.

## Addendum F (2026-11-25, 16:38 by the clock; written while the campaign of Addendum E runs and before any of its latency files was read; the last line of the campaign summary at this minute is "--- block probetest starts 16:35:10"): what the documents print from E9

The choices below are fixed before the data. They follow the places reserved in the article before the first pass (panel (b) of the periodic table, the sentence in the results, the row of the levels table). Nothing here is chosen by a value.

### F1. Article
1. Panel (b) of the periodic table, two rows as reserved. Row "signature variant, 10 ms, one stream" = cell a of session 1 (prefix `e9.s1.a`). Row "MAC variant, 10 ms, one stream" = cell e of session 1 (`e9.s1.e`). Columns, in order, from `<prefix>.periodic.<configuration>.e2e.`: `n`, `latency_p50_ms`, `latency_p99_ms`, `latency_p99_9_ms`, `latency_max_ms`, `bound_total_us`. The last column is headed as the bound within which the relation of the two clocks is certified (it now contains the two map terms).
2. The sentence in the results: the median and the 99th percentile of each of the three sessions of cell a (`e9.s1.a`, `e9.s2.a`, `e9.s3.a`; keys `latency_p50_ms`, `latency_p99_ms`), each printed, in session order, and the same two keys of cell e. No pooled figure and no range picked by hand. For the bound the sentence names the limit of the rule (100 us) and points to the panel.
3. Concurrent traffic (cells h and i; results sentence and limitation (7)): for cell h, per stream (signature stream, MAC stream), `latency_p50_ms` and `latency_p99_9_ms` and the deadline misses with the keys of panel (a); for cell i the same for its stream, with `bg.rate_achieved_mbit_s`. If the page limit does not allow it, the article prints the medians and the misses only and points to the Supplementary Material; that choice is made by the page count.
4. The clocks (validity): words only in the article, no count over runs (there is no key for a count). By rule: if in at least one result run `clock_X.adjusted` is 1, the article says that the time-synchronization service changed the rate of CLOCK_MONOTONIC of that board during the campaign and points to the per-run table; if in no result run, it says that the service was active and that the rate it applied did not change by more than 1 ppm in the reported runs. In both cases: latency is taken on CLOCK_MONOTONIC_RAW; a first pass measured on CLOCK_MONOTONIC is not used (one clause, pointer to the Supplementary Material); the latency contains the wait for the receiver's 1 ms cycle (one clause, no figure).
5. Abstract, highlights and conclusion: no latency figure. The abstract changes only where a statement is no longer true, with a cut of equal length (250 words).
6. Levels table: the marker goes, the wording stays.

### F2. Supplementary Material
1. One table of all result runs (session 1: a, b, c per stream, d, e, f, g, h per stream, i; sessions 2 and 3: a): `n`, `latency_p50_ms`, `latency_p99_ms`, `latency_p99_9_ms` (where the toolkit defines it), `latency_max_ms`, `rxpart_p50_ms`, `bound_total_us`.
2. One table of the clock record per run: `offset_bound_total_us`, `map_a.bound_us`, `map_b.bound_us`, `map_a.gap_max_ms`, `map_b.gap_max_ms`, and for each board `clock_X.adj_ppm_min`, `adj_ppm_max`, `adj_step_ppm_max`, `adj_offset_range_us`, `adjusted`; `drift_ppm`.
3. The first pass: the keys `clock.e9p1.*` of Addendum C, and the eleven runs listed as measured and not used, with the reason.
4. Not printed anywhere in the article, the Supplementary Material or the accompanying letter: the diagnostic keys `mono.*` (they stay suppressed; the text says in words that each run carries them), and every figure of a dry run (82.95 against 4,676.5 us; 4.03 against 3.73 ms). The campaign record (CAMPAIGN.md) may describe the dry run with the real adjustment as an acceptance test of the method, labeled as a dry run.

### F3. A cell without a result
A cell that has no result after its three tries is printed as "no result" with the reason and its tries in the run index; no figure of a try is printed. For row 1 of the panel the first session of cell a that has a result takes the row (session 2, then 3) and the caption names the session; row 2 has no substitute. No cell is left out of the supplementary table because of its values.

### F4. Gate
Every E9 key printed in the article, the Supplementary Material and the accompanying letter belongs to the set of keys that the own readers compared in an accepted run (mechanical check on the built documents). Keys outside that set are not printed. On the nine dry-run directories the own readers compared every `e2e` key (60, 61 or 73 per run), every `bg` key (5) and every `functional` key of the gateway run (23); of the periodic keys they recompute 36 per stream pair (41 with two streams) and leave 146 to the toolkit alone; the seven `run.*` keys are parameters of the analysis.

### F5. Accompanying letter
It prints the keys of F1.1 and F1.2 and names the first pass and the clocks as the article does.

### F6. Readings of F1 (16:58 by the clock; questions from the staging build with dry-run values; no latency file of the campaign has been read, the last finished run in the summary is E9_probetest_20261125T092245Z and cell h of session 1 is running)
1. A percentile that the toolkit does not define for a cell (fewer than ten samples above it) is printed as "n/a" with that rule named. No other percentile takes its place. (In the staging files the 99.9th percentile is absent for cells e, h and i because the dry runs have 3,000 PDUs; the campaign cells have 100,000.)
2. Per stream the misses are printed as counts with their releases (`sK.misses` of `sK.jobs`): there is no per-stream share or interval key. Stream K of the periodic keys is stream K of the `e2e` keys (the order of `# stream_profiles=` in the transmitter's file); which stream is the signature stream is read from the text key `e2e.streamK.profile`, which the own reader compares, and is checked mechanically before the text is filled.
3. Article wording of the bound: "the measurement certifies the relation of the two clocks to within the bound of the panel" is allowed in place of "certifies the estimate to within B" (the printed bound now contains the two map terms). The sentence "The two clocks are not synchronized with each other; their offset was measured during each run" may be dropped for space, since the sentence on the raw clocks says the same.
4. "The service was active on both boards" may be written only if the environment record (`clock_services=`) of every result run says so for both boards; otherwise the sentence names what the records say.
5. The article's pointer for the clocks goes to the label of the per-run clock table of the Supplementary Material.
6. Full or reduced form of F1.3: by the page count of the build with the campaign's values, as F1.3 says; with dry values both forms fit on 13 numbered pages.
7. (17:02:55; last finished run in the summary: E9_probetest_20261125T092245Z; no latency file read) The table of F2.1 has one more column, "Deadlines missed", printed as a count of the releases (`misses` of `jobs` for a one-stream cell, `sK.misses` of `sK.jobs` per stream; a dash for the gateway run, whose application logs carry no deadline). It was proposed from the staging build and is accepted for every cell alike.

## Note on the record itself (2026-11-25, 17:17 by the clock)

1. Clock times. The headings of the entries written on 2026-11-25 between about 01:20 and 01:48 carry times that were estimated when they were written, not read from the clock, and they are not in order: the rulings headed 01:35 are amended by an entry headed 01:25 and put on hold by one headed 01:32. The entries stand in this file in the order in which they were written, which is the order that binds. Times marked "by the clock" were read from the clock; the other times of this file were written by hand and can be off by some minutes.
2. The finding that withdraws assumption 2 quotes it as "free-running clocks, constant drift within a run". Assumption 2 says that the clocks are not disciplined and that the offset is measured during each run; the quoted words are a paraphrase of what the method then assumed, not the wording of the assumption.

## Addendum G (2026-11-25, 19:39 by the clock): the campaign was interrupted by the workstation; how it continues

Written before the acceptance script and the toolkit have read any run of the campaign. What has been seen of the data at this minute: the checker's verdict lines of six cells (their bounds), and for cell h the checker's line with the smallest, the median and the largest latency; no key exists yet.

### G1. What happened
1. Session 1, in the drawn order h, b, d, e, c, a: six runs, each the first try of its cell, each ended by the driver with status 0 and passed by the checker (bound in total 61.9, 63.2, 60.5, 54.3, 69.8 and 65.9 us).
2. Cell f, try 1 (E9_s1_f_20261125T092245Z), started 18:39:37. At 18:42:23 the measuring workstation went to sleep (its lid was closed while it ran on battery) and woke at 19:06:27 in another network, from which the boards cannot be reached. The driver lost its waiting sessions and ended with status 255 at 19:19:41. The run itself went on on the boards; its files were never collected and nobody has read them.
3. After that the script went on by its own rules without reaching a board: E9_s1_f_r2 (status 1), E9_s1_i (status 1), E9_s1_g and E9_s1_g_r2 (status 255). Nothing ran on a board in these four. The script was stopped by hand at 19:38 so that no connection attempt goes to foreign hosts at the boards' addresses. The boards' host keys are known to the workstation and its SSH configuration refuses a host whose key differs, and no host answered at those addresses.

### G2. Rulings
1. Try 1 of cell f is not a result (driver status 255; files not collected). Its files are not fetched or read later, whatever is left of them on the boards. It counts as the first of the three tries of cell f.
2. E9_s1_f_r2, E9_s1_i, E9_s1_g and E9_s1_g_r2 of this evening are not tries: no measurement was started. They are listed in the record with this reason and do not count toward the three tries of their cells.
3. The six runs of G1.1 are the runs of their cells. They go through acceptance as they are and are not measured again; if acceptance finds one not to be a result, the rule of the repeats applies to that cell as before.
4. The remaining cells are measured when the boards can be reached again, by the same script at the same commit, in this order: build check (prep) and probe test again, then the two remaining cells of session 1 (f and i) in one block in an order drawn from the seed 61125095, then cell g, then session 2 (cell a), then session 3 (cell a), each block after five idle minutes as before. The gateway build is not repeated unless the binaries are gone. The second probe test is a check of the set-up; the first one stays the probe test of the record.
5. The documents say that session 1 was measured in two windows and give the times of every run in the run index. The names of the sessions stay.
6. Before the script is started again the workstation is on mains power with its lid open and in the boards' network, and the host keys of both boards are checked against the known ones.
7. Cells that the coverage audit of this evening adds are written into this file before they are started.

## Addendum H (2026-11-25, 20:31 by the clock; written before any run of these cells, dry run or other, and while the boards are out of reach): further cells from the coverage audit

Reason: on 2026-11-25 every request that the revision answers and every commitment of the plan of the revision was checked against the documents and the data (480 items). The cells below are those that can be measured on the two boards as they are. They are not part of E9; they are recorded here because this file holds the rulings of this evening. The rules of E6 (periodic cells) and of E3 (functional runs) apply unless said otherwise, and so does "one result per cell".

### H1. E3r: restart, rekey and replacement of the key pair, gateway binaries on both boards
- Commit and binaries: those of cell g (harness commit 02b340b0367, gateway build E9_gwbuild). Driver `scripts/run_e2e.sh twonode 500 <id>` with LINK_SPEED=100, HOLDING_MEASURING=1, PI_TREE=pqc-secoc-accept, PERIOD_CYCLES=10, STREAMS=1.
- Cells, each one run of 500 PDUs: for PROFILE=mldsa65 and for PROFILE=mac: restart of the sender (RESTART=tx RESTART_AFTER=200), restart of the receiver (RESTART=rx RESTART_AFTER=200), rekey (REKEY_AT=200); and for PROFILE=mldsa65 the replacement of a key pair: before the run the campaign script removes the two key files of board A's gateway (its identity key pair) and records the checksum of the public key before and after; the driver then generates a new pair and exchanges the public keys. Run identifiers `E3r_s1_<sig|mac>_<restart_tx|restart_rx|rekey>` and `E3r_s1_sig_keyrepl`, key prefix `e3r.s1.<...>`.
- A run is a result when the driver ends with status 0, the checker of the gateway run passes (restart of the sender: two runs of sequence numbers per stream, nothing lost, two successful handshakes on each side; restart of the receiver: one run of consecutive PDUs lost per stream, rejections at the freshness stage not more than those, two successful handshakes; rekey: two successful handshakes on each side, every PDU delivered; key replacement: one successful handshake, every PDU delivered, the checksum of the public key changed), the toolkit calls no file invalid and the own reader agrees.
- What may be written: per run the PDUs sent, delivered, lost and rejected at the freshness stage and the handshakes, and what a restart or a rekey does to the freshness state as these counts show it. Not: a statement about revocation, about a key store, or about a counter that survives a restart.

### H2. Harness commit for the new periodic cells
Commit 524cf0902eea (on 02b340b0367: `scripts/run_bench_net.sh` gains the variable PHASE=sync|staggered, which passes `--phase staggered` to the transmitter of the periodic mode; one paragraph of documentation; without the variable the transmitter's options are those of 02b340b0367 to the byte; product trees unchanged, source b82e18138d8c, include 57e80b2bb55c; two files changed). It is the commit of E6p, E6m and E6c. The board build at this commit is made only after the last cell at 02b340b0367 (the remaining latency cells and E3r).

### H3. E6p: periodic cells with staggered release
- Staggered release: stream s of the k streams of a sender process is released s/k of a period after stream 0, in every period (the transmitter's `--phase staggered`). It is an evenly spaced release, not a random one, and no document calls it random.
- Cells (signature variant, one sender process, default scheduler, 100 Mbit/s, deadline equal to the period): 10 ms with 2, 3, 4 and 5 streams, 100,000 releases per stream; 20 ms with 4, 6 and 8 streams, 50,000 releases per stream. Run identifiers `E6p_s1_sig_p<period in us>_k<streams>_other`, prefix `e6p.s1.<...>`; the keys carry `-staggered` in the configuration name where the synchronous cells carry `-sync`. Order drawn from the seed 61125096.
- What may be written: the miss share of each cell with its exact interval and longest run, beside the synchronous cell of the same parameters (E6 or E6x, session 1). Five streams at 10 ms are above the sustained rate in either release; the text says so.

### H4. E6m: more than eight streams on one core, as several sender processes
- The product configures eight signature PDUs, so one sender process has at most eight streams. Cells: 20 streams at 50 ms as four sender processes of five streams each (PARTITIONS=4 MAX_PARTITIONS=4 CORES="3 3 3 3" STREAMS=5, 20,000 releases per stream), and 40 streams at 100 ms as five sender processes of eight streams each (PARTITIONS=5 MAX_PARTITIONS=5 CORES="3 3 3 3 3" STREAMS=8, 10,000 releases per stream); default scheduler, synchronous release within a process (the phase between processes is not controlled), all sender processes on one core of board A and all receiver processes on one core of board B. Run identifiers `E6m_s1_sig_p50000_k20_other` and `E6m_s1_sig_p100000_k40_other`, prefix `e6m.s1.<...>`.
- Toolkit: the configuration name of such a cell states the number of DISTINCT cores of its files (one), not the number of files; the keys of the per-process model, which assumes a core per process, are not emitted for it. No existing key changes.
- What may be written: jobs and misses added over the processes, with the exact interval, and the longest run of a stream; always with the words "as N sender processes on one core". Not: that one stack instance carries 20 or 40 PDUs.

### H5. E6c: four sender processes on four cores at a moderate load
- Cells: 10 ms, four sender processes on cores 0 to 3 (PARTITIONS=4 MAX_PARTITIONS=4 CORES="0 1 2 3"), with 2 streams per process (8 streams) and with 3 streams per process (12 streams), 20,000 releases per stream, default scheduler. Run identifiers `E6c_s1_sig_p10000_k8_4proc_other` and `E6c_s1_sig_p10000_k12_4proc_other`, prefix `e6c.s1.<...>`. No core of either board is isolated, and core 0 also carries the driver's session; the text says so.
- These cells run last. A run that the temperature gate stops or that a throttling flag marks is not a result. After three such runs of a cell the documents say that the cell could not be measured on these boards without cooling and give the gate's reason, without a figure of the stopped runs.

### H6. Common rules
1. Every new kind of run is dry-run first (short, marked DRY_RUN, never a result): the two shapes of E6m, one cell of E6c for 20 s, one staggered cell, the MAC restart, the two-node MAC rekey and the key replacement.
2. A start that the temperature rule refuses (driver status 75) is not a try; the script waits and starts again, at most three times per cell.
3. Acceptance as for every campaign run: the acceptance script, the toolkit at its head, the own reader of the experiment (periodic or functional); the runs enter `accepted_runs.tsv` and the run index.
4. Where the results go: the Supplementary Material (one table per experiment, beside the cells they extend) and the accompanying letter; the article gets at most one sentence per experiment if its page limit allows.
5. Order after the remaining latency cells: dry runs of E3r, E3r; build and tests at 524cf0902eea; dry runs; E6m; E6p; E6c.
6. Not run unless the author asks for it: cells of at least 200,000 jobs per configuration (the count named in the plan of the revision); they would be new cells of a further session, about four to five hours of board time.

### H7. What the audit found that no run on these boards can answer
A job interface below the Csm; a signature on the first handshake message and nonces; key rotation and revocation through a backend; a freshness counter that survives a session; an attacker on a third machine that alters frames below TCP; four cores at full load (cooling). The documents state each as it is.

### H8. Readings of H5 and H6 (20:41 by the clock; questions raised while the campaign script is written; no run of these cells exists)
1. Throttling flags that are only left over since boot (none active, none changed during the run; the driver writes the note `NOTE_throttled_since_boot`) do not make an E6c run "not a result": the rule is that of every other experiment. Only a run whose EXCLUDED file names the temperature or a throttling flag is run again, at most three runs per cell.
2. A cell whose start the temperature rule refuses three times (status 75 each time) is noted as not run in this window; it is not a try, it does not count toward the stop after three runs in a row without status 0, and the script goes on. Such a cell may be started again in a later window; until then the documents print nothing for it.
3. The campaign script, not the driver, does three things, and the record says so: it writes the DRY_RUN marker into a dry run of the gateway driver (identifiers of dry runs begin with `dry_`); it decides a rerun from the EXCLUDED file (a run stopped by the 78 degree rule ends with driver status 0); and for the key replacement it compares the checksum of the public key before and after, writes both into a file of the run directory, and marks the run EXCLUDED with that reason if the key did not change. Files that the campaign script adds to a run directory are not in the directory's own manifest; the manifest of the dataset lists them.

### H9. Start temperature of the E6m cells (21:47 by the clock; before any run of the new cells, dry runs included)
The driver starts a run of one sender process below 68 C and a run of several sender processes below 62.1 C on both boards, because several busy cores heat a board within a minute. In E6m all sender processes share one core of board A and all receiver processes one core of board B, so the load is that of a one-process run. The E6m cells and their dry runs therefore start by the rule of a one-process run, below 68 C on both boards (the driver's variable START_BELOW_PARTITIONS_C is set to 68 for these runs by the campaign script, and the run's files record it); the rules during and after a run are unchanged (stop at 78 C, exclusion by a throttling flag). For E6c (four busy cores) the 62.1 C rule stays. Reason for ruling now: board B idles at 55.5 to 61 C, so the 62.1 C rule would refuse most starts of a kind of run that it was not made for.

## Addendum I (2026-11-26, 06:13 by the clock; written before any run of E6c exists, dry run or other): E6c in a later window

### I1. What is known at this minute
The block of 03:23 was refused at its start four times (board B at 64.7, 63.7, 64.7 and 64.2 C) and stopped by hand at 04:39 (CAMPAIGN.md). No run directory of E6c exists, dry or real, and no datum of these cells has been seen. At 06:06 both boards are idle (load averages 0.05 and 0.00, throttling flags 0x0), board A at 58.9 C and board B at 64.2 C: at the fixed clock frequency board B idles above 62.1 C in this room, so the start rule as written cannot be met on board B without cooling, whatever the cell.

### I2. Start rule of the E6c runs
Board A carries the four sender processes on its four cores and keeps the rule of a run with several busy cores: below 62.1 C. Board B starts by the general rule of the driver, below 68 C (`START_BELOW_PARTITIONS_C_baolong=68`: the per-board limit that the driver has, and that the rulings of CAMPAIGN.md already apply to board B in the steps with two sender processes). The reason, from measured keys: in these cells board B runs four receiver processes, each receiving 200 PDU/s (2 streams at 10 ms) or 300 PDU/s (3 streams). A receiver process used 10.72% of a core at 200 PDU/s and 15.17% at 300 PDU/s (`e7.s1.sig.throughput.mldsa65-c1-cyclic-mf1ms.r200.rx_proc_cpu_share_mean` and `...r300.rx_proc_cpu_share_mean`), so the four together use about 43% and 61% of one core: less than one busy core, which is the load the general rule is for (the reasoning of H9 for E6m). The limit is the existing general limit and not a number chosen for the temperature of this morning. This amends, for board B only, the last sentence but one of H9 ("For E6c (four busy cores) the 62.1 C rule stays"): the four busy cores are those of board A, and for board A the rule stays. Nothing else changes: the stop at 78 C on both boards, the throttling rule (H8.1), at most three runs per cell (H5), a refused start is no try (H8.2), and nothing is changed between tries.

### I3. Order, and when the attempt ends without a change
The block is split into `e6cdry` (the dry run of 20 s alone) and `e6c` (the two cells), given in two calls (ruling of 2026-11-25, 23:19: a dry block and a real block never in one call). The dry directory is read by the toolkit and by the second reader (`own/periodic_compare.py`) on scratch copies; both must end with their agreeing verdict, and the second reader must have compared every key that I4 names. If the dry run is refused, fails, or its inspection does not agree, E6c stays "not run in this window", the state of 05:35 stands, and no document changes. The first real run is the point after which the documents change in every outcome (H5).

### I4. Print rule (before any run)
1. A cell has a result when `campaign_post.sh` accepts its run: status 0, no EXCLUDED file, the second reader agrees. Its keys stand under `e6c.s1.<cell>.periodic.<configuration>-parts4.`: `partitions`, `streams`, `cores`, `jobs`, `misses`, `miss_ratio`, `miss_cp95_lo`, `miss_cp95_hi`, `auth_utilisation`, and per sender process the `misses` and `longest_miss_run` of its part, as in the E6m rows.
2. Supplement: the table of the cells with several sender processes (Supplementary Table S28) gains a block "four sender processes on four cores" with one row per cell that has a result, in the columns of its present rows. Its text says that no core of either board is isolated and that core 0 also carries the driver's session (H5). The two sentences of the Supplement that say that more than two busy cores were not measured are changed to say what was measured: four sender processes on four cores with two and with three streams each, in periodic cells; the throughput ladder still ends at two sender processes, for the reason given there.
3. Article: one sentence in Section 4.3 behind the sentence on two sender processes. For each cell with a result it gives the misses of the releases and the share, beside the share of the one-process cell of the first session with the same number of streams per process (two streams, 0.64%; three streams, 4.27%). No word of comparison is fixed or added: the two shares stand side by side ("against"). In limitation (8), "at most two busy cores" becomes "at most two fully loaded cores (four cores at a partial load in the periodic cells of Supplementary Table S28)" if at least one cell has a result.
4. Accompanying letter: the same sentence, in item 3; in item 4, "on two cores and on one core" becomes "on two cores, on four cores and on one core" if at least one cell has a result.
5. A cell of which three runs were stopped by the temperature gate or marked by a throttling flag: the documents say that it could not be measured on these boards without cooling and give the gate's reason, without a figure of the stopped runs (H5). If both cells end so, the sentences on more than two busy cores stay and gain that statement.
6. A cell whose start is refused three times is again "not run in this window", and nothing is printed for it (H8.2).
7. A cell in which releases were never started is reported as overload, as the cell with five streams at 10 ms is, and its figures are not a statement about deadlines.

### I5. Records
`results_section.py` gains the family E6c with the key tails of E6m. In `cells2_tries.tsv` the two `not_run` lines of the first window stay, and the outcome lines of this window follow them. The dataset, the public tree and the documents are rebuilt beside the state of 05:35 and replace it only after every gate has passed.

### I6. The dry run and a reading of I4.1 (06:24 by the clock; the dry directory has been read on a scratch copy; no real run of E6c exists)
- Dry run `dry_E6c_p10000_k8_4proc_20261125T231547Z` (06:21, 20 s, 2,000 releases per stream): driver status 0, marker DRY_RUN, no EXCLUDED, the note NOTE_tcp_host_wide (two retransmitted segments in the host-wide counter of board B during the run; a note, as in other runs). Throttling flags 0x0 on both boards before and after; board A 60.3 to 61.8 C, board B 64.2 to 65.2 C. Toolkit: 7 tables, no invalid file. Second reader: OWN-CHECK AGREES, 118 keys compared per sender process and 8 of the cell, no difference. By I3 the attempt goes on.
- Compared by the second reader, of the keys that I4 names: at the cell `partitions`, `streams`, `cores`, `jobs`, `misses`, `miss_ratio`, `miss_cp95_lo`, `miss_cp95_hi`; per sender process `misses`, `longest_miss_run`, `auth_utilisation`, `not_started` (four of four each).
- Reading of I4.1: it named `auth_utilisation` among the keys of the cell. The toolkit defines that key for the cell only when all sender processes share one core (E6m); with sender processes on separate cores it stands per sender process (`...p<i>.<configuration>-part<i>.auth_utilisation`), as in the cell with two sender processes of the first session. An E6c row therefore gives the utilization of its sender processes (per process; the range over the four where the table has one entry). No key is added to the toolkit for this.
- Seen at this minute and not used: the figures of the dry run (158 misses in 16,000 releases in 20 s, 66 of them in the sender process on core 0, which also carries the driver's session). They are not results, and nothing is changed because of them.

### I7. Outcome of the block, and what the documents say for the cell without a result (06:53 by the clock; written after the block; the figures of the accepted run have been seen)
- `E6c_s1_sig_p10000_k8_4proc_other_20261125T232507Z` (06:30 to 06:34): driver status 0, no EXCLUDED, the notes NOTE_tcp_host_wide and NOTE_tcp_retrans (retransmitted segments on the connection of the sender process on core 0); board A 58.9 to 67.6 C, board B 65.7 to 67.6 C, throttling flags 0x0 before and after. Accepted by `campaign_post.sh`: no invalid file for the toolkit, OWN-CHECK AGREES for the second reader. The cell has its result.
- `E6c_s1_sig_p10000_k12_4proc_other_20261125T232507Z` (06:35 to 06:40): stopped by the temperature gate when board A reached 78 C (EXCLUDED). Not a result; run again by H5.
- `E6c_s1_sig_p10000_k12_4proc_other_r2_20261125T232507Z` (06:41 to 06:48): ran to its end (board A 62.8 to 74.5 C, board B 67.2 to 71.1 C, flags 0x0) and is EXCLUDED by the rule on other busy processes: the snapshot after the run on board A lists a process `pgrep` above the limit of that gate. The process was short-lived; whose it was is not established. Not a result. By H8.1 only a run excluded for the temperature or for a throttling flag is run again, so the script went on as written and the cell was not run again.
- I4 has a rule for a cell of which three runs were stopped by the temperature gate (I4.5) and for a cell refused three times (I4.6); it has none for this outcome. Reading, made after the outcome and on the cautious side: the cell with three streams per sender process has no result, and no figure of its two runs is printed. The Supplement says in one sentence what happened, with the two reasons: the temperature limit on board A in the first run, the exclusion by the rule on other busy processes in the second, which by the rule is not run again. The statement of I4.5 (that the cell could not be measured on these boards without cooling) is not made, because only one of the two runs was stopped by the temperature. The article and the accompanying letter name the cell that has a result and say in a clause that the cell with three streams per sender process has no result, with a pointer to the Supplement. Limitation (8) and item 4 of the accompanying letter change as I4.3 and I4.4 say, since one cell has a result.
- No rule provides a further run of this cell. A later attempt would be a new experiment with a rule of its own and is for the authors to decide.
