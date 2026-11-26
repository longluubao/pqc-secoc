# bench: measurement harnesses

The binding contract for every file is `DATA_SCHEMA.md` of the revision plan; this page says which
tool writes which file. Every CSV starts with `# key=value` lines (commit, host, compile flags,
liboqs version, CPU affinity, governor, frequency, mlockall, clock) and ends with the process's
wall time, CPU time and context switches. `check_csv.py <file>` fails on a file that breaks the
contract; `ctest --test-dir <build>` runs every harness briefly and checks its output.

| Tool | Experiment | File | Columns |
|---|---|---|---|
| `bench_crypto_ops` | E1 primitives | `crypto_ops*.csv` | `op,seq,ns` |
| `bench_sign_attrib` | E1a tail attribution | `sign_attrib*.csv` | `seq,wall_ns,cpu_ns` |
| `bench_overhead_paired` | E2 abstraction overhead | `overhead_paired*_L<nn>.csv` | `seq,order,op,standalone_ns,csm_ns` |
| `bench_net_tx` | E6 periodic, E7 load | `periodic_tx*.csv`, `throughput_tx*.csv` | see DATA_SCHEMA.md |
| `bench_net_rx` | E6, E7, reject time | `periodic_rx*.csv`, `rx_payload*.csv`, `throughput_rx*.csv` | see DATA_SCHEMA.md |
| `attack_proxy.py`, `join_attack.py` | E4 attacks | `proxy_log.csv`, `attack.csv` | `vector,iter,delivered,reject_stage,detect_ns` |
| `bench_clock_probe`, `check_clock_probe.py` | E9 clock offset between the boards, on the raw clocks (probe format 2) | `clock_probe.csv` | `seq,t1_ns,t2_ns,t3_ns,t4_ns,t1r_ns,t2r_ns,t3r_ns,t4r_ns,w1_ns,w2_ns,w3_ns,w4_ns` |
| `bench_clock_probe` (second thread) | E9 each board's CLOCK_MONOTONIC against its CLOCK_MONOTONIC_RAW, every 5 ms | `clock_map_a.csv`, `clock_map_b.csv` | `raw1_ns,mono_ns,raw2_ns` |
| `bench_verify_only` | instructions per verification (`perf stat`) | none | none |
| `bg_traffic.py` | E9 unrelated TCP flow beside a periodic run | `background_traffic.txt` | `key=value` lines |

Drivers: `scripts/run_single_node.sh e1|e1a|e0|e2` on a board (E0 is `cyclictest` through
`scripts/run_cyclictest.sh`); `scripts/run_bench_net.sh` at the repository root, from the Mac, for
everything with two boards.

## sign_attrib*.csv

One row per ML-DSA-65 signing call, same call and set-up as `bench_crypto_ops --ops mldsa_sign`.

- `seq` counts from 0.
- `wall_ns` is CLOCK_MONOTONIC around the call, `cpu_ns` is CLOCK_THREAD_CPUTIME_ID around the same
  call. The clocks are read in the order monotonic, thread CPU, sign, thread CPU, monotonic
  (`# clock_order=`), so `wall_ns >= cpu_ns` up to the resolution of the two clocks.
- `wall_ns - cpu_ns` is the time the pinned thread did not run during the call: preemption;
  interrupt handling too when the kernel accounts interrupt time separately
  (CONFIG_IRQ_TIME_ACCOUNTING, recorded as `kernel_irq_time_accounting` in `env_<host>.txt`;
  without it interrupt time is charged to the thread and sits in `cpu_ns`). A slow call with
  `cpu_ns` close to `wall_ns` computed longer.
- Header keys beyond those of `crypto_ops.csv`: `clock_order`, `cpu_clock`, `cpu_timer_overhead_ns`
  (`timer_overhead_ns` is the monotonic clock's; both are medians of 1,001 back-to-back reads).
- With `--count-shake` a fourth column `shake_calls`: SHAKE-256 state initialisations inside the
  call, counted through liboqs's hook `OQS_SHA3_set_callbacks`. The number of rounds of the
  rejection loop is `(shake_calls - shake_calls_min) / shake_calls_step + 1` (both in the header,
  with `shake_counted`). Off by default: it puts one more indirect call on every SHAKE-256 start.

## bsw_stamps.c

The five instants of the BSW data path (rx_done, verify_done, deliver, auth_done, send_done) taken by
link-time wraps, with getters per PDU ID. The networked harnesses use it; the gateway can link it
with the six `--wrap` options listed at the top of `bsw_stamps.h`. No BSW source is edited.

## Stream labels

`stream` in the periodic and payload files is the stream index 0..K-1; the header lines
`stream_pdu_ids` and `stream_header_ids` give the SecOC PDU ID and the PDU header ID of each index.

## The TCP connection and the processor time in the networked files

- `tcp_nodelay=` (header of the Tx and the Rx file): TCP_NODELAY read back with `getsockopt` on the
  harness's own connection, after the stack has set it up: 0, 1, or -1 if it could not be read. It is
  also in the sampler and handshake files. A file is valid only with 1: the harnesses stop before the
  first release (exit status 6) when they read anything else, and the driver excludes such a file.
- Footer of the Tx file: `TCP_INFO` of that connection at two instants, in the 200 ms before the first
  release and at the end after the send queue has drained. Cumulative counters at both instants and
  as a difference: `tcp_total_retrans_*`, `tcp_dsack_dups_*`, `tcp_total_rto_*` with the suffixes
  `_at_first_release`, `_at_end`, `_in_window`. Current values at both instants: `tcp_lost_*`,
  `tcp_retrans_*`, `tcp_rto_us_*`, `tcp_rtt_us_*`. -1: the kernel, or the kernel header of the board
  that built the binary, does not give the field. A retransmission is reported
  (`NOTE_tcp_retrans`), never a reason to exclude a file.
- `tcp_connections_at_first_release`, `tcp_connections_at_end`: `connect()` calls of the stack
  (transmitter). A file where they differ is excluded: the connection was made again inside the
  measured window.
- `jobs_started` must equal `jobs_confirmed` (footer of the Tx file), or the file is invalid: a job that
  SoAd never confirmed is given up after 2,000 ticks (cyclic) or four cycles (event) and its SecOC row
  then takes the next PDU. The loss a valid file can show is `jobs_dropped_at_release` alone: a release
  that found its stream's queue of `backlog_jobs` full, with its row kept. The transmitter does not
  look at the return value of `SecOC_TpTransmit`; a refused request never reaches the signing hook
  and the end check (sign calls = started jobs) ends the program with status 4.
- Sampler files: `proc_cpu_ns` is `CLOCK_PROCESS_CPUTIME_ID` of the harness process at the sampling
  instant, cumulative, all its threads. It is the processor time of the process, not the load of the
  board. `cpu_busy_jiffies` / `cpu_total_jiffies` come from `/proc/stat`, which on these kernels
  (tick accounting) misses work that starts on a timer and ends before the next tick; no figure is
  taken from them.

## Handshake records

Every networked harness runs the handshake of the tree before its measured interval and writes the
attempt record of its side (`handshake_tx.csv`, `handshake_rx.csv`, schema `handshake.csv`). The Tx
header gives `established_ns` and `first_release_ns`; `hs_records_in_run` counts handshake rows that
fall inside the measured interval (0 in a timing run). A directory holds one handshake file per host:
a ladder step or a partition writes into its own subdirectory `handshake_<step>[_p<i>]/`.
`bench_handshake` is the E5 initiator (n handshakes, default timers, no PDU stream).

## Attack proxy and the on-wire handshake tests

`attack_proxy.py` runs on the transmitter's board (transmitter -> 127.0.0.1 -> proxy -> link ->
receiver): the receiver's SoAd accepts a connection from the peer address only. It never runs in a
timing experiment. PDU vectors: `replay`, `bitflip`, `auth_tamper`, `freshness_rollback`, and
`session_replay` (a PDU recorded with `--record` in an earlier session, given as `--session-file`).

Handshake edits (`--hs`, `--hs-inject`; header IDs 0x30..0x33 = M1..M4; `@2+` = every handshake after
the first, `@2/2` = every second one). The numbers are the tests of SPEC.md "Negative tests":

| Test | Proxy options |
|---|---|
| 1 foreign `ek` | `--hs 0x30:replace:33:<ek>@2+`, `<ek>` from `bench_hs_forge ek` |
| 2 other `ct` | `--hs 0x31:replace:33:<ct>@2+`, `<ct>` from `bench_hs_forge ct` |
| 3 M2 signed by another key | `--hs 0x31:resign@2+` |
| 4 `mac_B` altered | `--hs 0x31:flip:4430:32@2+` |
| 5 old M1 | `--hs-inject 0x30:<m1>:to_receiver:<start>:<period>:<n>`, period above T_pend |
| 6 old M2 | `--hs 0x31:replace:0:<m2>@2+` |
| 7 old M3 | `--hs-inject 0x32:<m3>:to_receiver:<start>:<period>:<n>` |
| 8 unknown `ID_A` | `--hs 0x30:flip:1:32@2+` |
| 11 M3 dropped / `sig_A` / `mac_A` altered / signed by another key | `--hs 0x32:drop@2/2`, `0x32:flip:1:3309@2/2`, `0x32:flip:3310:32@2/2`, `0x32:resign@2/2` |
| 12 M4 dropped / altered | `--hs 0x33:drop@2/2`, `0x33:flip:1:32@2/2` |

`<m1>`, `<m2>`, `<m3>` are the files of an earlier run made with `--hs-record <prefix>`. After a failed
attempt the initiator starts the next handshake by itself T_A after its M1, so `@2+` repeats a test
every T_A while session 1 stays in use.

Two deviations from the wording of the specification. Test 8 is an altered `ID_A` on the wire: a
responder that has no key pinned for the initiator cannot hold session 1. `resign` needs a signer:
`bench_hs_forge sign` makes a key pair for the call, signs the data the genuine side signs
('R' || th2 or 'I' || th3, computed from the forwarded messages, under the product's handshake
context) and forgets the key; the proxy holds no key of either gateway.

The initiator of these tests is the gateway transmitter, a build whose peer is the proxy on its own
board (`run_bench_net.sh build-gw-tx`, once after `build`); `run_bench_net.sh hsneg <run_id> <test>
<reps>` runs one test and `check_hsneg.py` judges it (per side: the rows of the attempt record, the
session identifier and installation counter, the PDU deliveries). Tests 11 and 12 with several
repetitions are that many short runs, each with one rekey request.
