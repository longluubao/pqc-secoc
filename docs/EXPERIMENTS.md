# Command lines of the campaign experiments

Paths are relative to the root of the repository. `DATA_SCHEMA.md` and `CAMPAIGN.md` (in this
directory) are the binding contract for files and sizes; `Autosar_SecOC/bench/README.md` says which
tool writes which file. The single-node experiments E0, E1 and E1a are run with
`Autosar_SecOC/scripts/run_single_node.sh e0|e1|e1a`; its header gives their options. The lines
below leave out the variables that only name paths of the measuring workstation (the SSH
configuration `PI_SSH_CFG`) and the name under which the board lock is taken.

Everything two-node goes through `scripts/run_bench_net.sh` on the Mac (transmitter iris, receiver
baolong). Its results land in `runs/<run_id>/` of the clone on the Mac; on the boards it uses
`/dev/shm/bench/<run_id>` and removes it after the copy. E2 runs on the board itself.

## Common to every two-node line

    PI_SSH_CFG=<ssh config> DRY_RUN=0 [HOLDING_MEASURING=1] [LINK_SPEED=100] scripts/run_bench_net.sh <mode> <run_id> ...

- `DRY_RUN=0`: no DRY_RUN marker in the directory (default 1 writes it). `HOLDING_MEASURING=1`: for
  the holder of the measuring marker; no board lock is taken and the marker is no obstacle.
  `LINK_SPEED=100|1000`: the link is put to that speed first; without it the speed found is kept.
- Once per commit: `scripts/run_bench_net.sh build` (syncs the tree, builds the harnesses on both
  boards and the gateway receiver on baolong, exchanges the public keys; under the
  board locks). For the negative handshake tests once more: `scripts/run_bench_net.sh build-gw-tx`
  (the gateway transmitter on iris; refuses below 200 MB free disk, `GW_BUILD_MIN_FREE_MB`).
- Exit status: 0 done, 75 not started (a board is measured, a lock not obtained within `LOCK_WAIT`,
  a board too warm after `COOL_WAIT`), 1 a step failed or the oracle said REJECT, 2 usage.

**Stops before a start** (nothing has run): local marker `MEASURING_<board>` on the Mac; board lock;
a marker, a SecOC or a harness process on a board; other traffic on eth0; temperature (below); the
link step (20 of 20 pings, EEE off).
**Stops of the harness itself**: exit 6 before the first release when TCP_NODELAY does not read back
1; exit 5 when no session comes up; exit 4 when the hook counts do not match the jobs.
**Reasons written to `EXCLUDED` after a run**: get_throttled changed or a low bit active; eth0
carrier changes, address, rbuf_ovflow or rx_errors moved; the board reached the stop temperature;
another process above 20 % of a core; different commits in the files; the two ends name different
sessions; a handshake record inside the measured window; `tcp_nodelay` not 1 in a file;
`jobs_started` not equal `jobs_confirmed`; the TCP connection made again inside the window.
`check.txt` lists files that break the schema (then the driver's status is not 0).
**Notes, not judged**: `NOTE_tcp_retrans` (retransmissions, duplicate SACKs, time-outs inside the
window), `NOTE_tcp_host_wide`, `NOTE_throttled_since_boot`, `NOTE_hot_start`.

## Temperatures the two-node driver enforces

| Rule | Default | Variable | Effect |
|---|---:|---|---|
| start of a run, one sender process | below 68 C on each board | `START_BELOW_C` | waits `COOL_WAIT` s (default 120, read every 5 s), then exit 75 |
| start of a step with several partitions | below 62.1 C on each board | `START_BELOW_PARTITIONS_C` | the same |
| stop during a step with several partitions | 78 C on either board (whole degrees) | `STOP_AT_C` | the transmitters get SIGTERM, files complete with `stopped_early=1`, `EXCLUDED` |
| any run: highest temperature of the gate snapshots | 78 C | `STOP_AT_C` | `EXCLUDED` |

Each variable can be given per board as `<NAME>_iris` or `<NAME>_baolong`; the per-board value wins
over the plain one, the plain one over the default. `ALLOW_HOT_DRYRUN=1` lets a run start on a
warmer board, but only with the DRY_RUN marker (it is ignored with `DRY_RUN=0`). A run with one
sender process is not stopped at the stop temperature while it runs; it is excluded afterwards.
More than two partitions are refused (`MAX_PARTITIONS`).
E2 on the board (`run_single_node.sh`): no start at 68 C or more (waits `COOL_WAIT`, default 900 s,
then exit 75), `EXCLUDED` for the end temperature, throttling flags, other busy cores, the pinned
core's share and memory locking.

## E2, standalone against Csm path, paired (iris, on the board)

    cmake -S Autosar_SecOC/bench -B build-bench -G Ninja -DCMAKE_BUILD_TYPE=Release -DLIBOQS_ROOT=$HOME/opt/liboqs-0.15.0
    taskset -c 0-2 nice -n 10 ninja -j2 -C build-bench bench_overhead_paired
    MARKER=none E2_BLOCK=aa LAUNCHES=10 PAIRS=3000 Autosar_SecOC/scripts/run_single_node.sh e2 build-bench <run_dir_aa> 3
    # the margin is written from the aa block into a file, then:
    MARKER=none E2_BLOCK=ab MARGIN_FILE=<file> LAUNCHES=30 PAIRS=3000 Autosar_SecOC/scripts/run_single_node.sh e2 build-bench <run_dir_ab> 3

Output: `<run_dir>/overhead/overhead_paired[_aa]_L<nn>.csv`,
`equivalence_margin.txt` (ab), `harness_<host>.txt`, `gates_<host>.txt`, `env_<host>.txt`,
`MANIFEST.sha256`. Stops: the temperature and busy-core rules above; the harness ends with status 3
when the context of the direct call (`CTX_BYTES`, default 64) is not the one the Csm path signs with;
`E2_BLOCK=both` is refused with `MARKER=none`; `ab` without `MARGIN_FILE` is refused.

## E3, two-node functional delivery (100 Mbit/s, 10,000 PDUs per profile)

    LINK_SPEED=100 DRY_RUN=0 scripts/run_bench_net.sh periodic <run_id>_sig 10000 10000
    LINK_SPEED=100 DRY_RUN=0 PROFILE=mac scripts/run_bench_net.sh periodic <run_id>_mac 10000 10000

Output: `runs/<run_id>/periodic/` with `periodic_tx.csv`, `periodic_rx.csv`,
`rx_payload.csv` (every delivered payload, for the byte-exact comparison), the handshake files.
These are the harnesses on both ends. The gateway binary on both ends is `scripts/run_e2e.sh`,
not a tool of `Autosar_SecOC/bench`. The harness transmitter against the gateway receiver
without a proxy is `attack <run_id> 10000 0 none`.

The campaign's functional delivery runs were made with the gateway binaries on both ends (four
signature streams of 2,500 PDUs each, then the MAC stream); the two lines above are the harness
variant:

    BOARD_LOCK_WAIT=1800 PI_TREE=<board directory> PERIOD_CYCLES=10 scripts/run_e2e.sh buildall <run_id>
    BOARD_LOCK_WAIT=1800 PI_TREE=<board directory> PERIOD_CYCLES=10 LINK_SPEED=100 scripts/run_e2e.sh link <run_id>
    BOARD_LOCK_WAIT=1800 PI_TREE=<board directory> PERIOD_CYCLES=10 LINK_SPEED=100 STREAMS=4 scripts/run_e2e.sh twonode 2500 <run_id>
    BOARD_LOCK_WAIT=1800 PI_TREE=<board directory> PERIOD_CYCLES=10 LINK_SPEED=100 PROFILE=mac scripts/run_e2e.sh twonode 10000 <run_id>

Restart, new session key and replaced key pair (E3r): gateway binaries on both ends, 500 PDUs, one
stream; the first three lines once with `PROFILE=mldsa65` and once with `PROFILE=mac`:

    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 PI_TREE=<board directory> PERIOD_CYCLES=10 STREAMS=1 PROFILE=<mldsa65|mac> RESTART=tx RESTART_AFTER=200 scripts/run_e2e.sh twonode 500 <id>
    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 PI_TREE=<board directory> PERIOD_CYCLES=10 STREAMS=1 PROFILE=<mldsa65|mac> RESTART=rx RESTART_AFTER=200 scripts/run_e2e.sh twonode 500 <id>
    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 PI_TREE=<board directory> PERIOD_CYCLES=10 STREAMS=1 PROFILE=<mldsa65|mac> REKEY_AT=200 scripts/run_e2e.sh twonode 500 <id>

Replacement of the signature key pair of the gateway on iris, in two steps. First, on iris, the
checksum of the public key is read and the two key files are removed in one command:

    cd <board directory>/keys && [ -f mldsa_secoc.key ] && [ -f mldsa_secoc.pub ] && s=$(sha256sum mldsa_secoc.pub | cut -d' ' -f1) && [ ${#s} = 64 ] && rm mldsa_secoc.key mldsa_secoc.pub && echo $s

Then the run, in which the driver makes a new pair and exchanges the public keys:

    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 PI_TREE=<board directory> PERIOD_CYCLES=10 STREAMS=1 PROFILE=mldsa65 scripts/run_e2e.sh twonode 500 <id>

After it `sha256sum <board directory>/keys/mldsa_secoc.pub` gives the second checksum; both stand in
`keyrepl_pubkey_sha256.txt` of the run directory (`before=`, `after=`).

## E4, attacks on the wire (harness transmitter, proxy on iris, gateway receiver as oracle)

    DRY_RUN=0 PROXY_OPTS="--count 4000" scripts/run_bench_net.sh attack <run_id> 13000 3 replay,bitflip,auth_tamper,freshness_rollback
    DRY_RUN=0 RECORD_SESSION=/dev/shm/s.bin scripts/run_bench_net.sh attack <run_id>_rec 5200 0 replay
    DRY_RUN=0 REPLAY_SESSION=/dev/shm/s.bin PROXY_OPTS="--count 1000" scripts/run_bench_net.sh attack <run_id>_old 5000 4 session_replay

First line: every third PDU attacked, the four vectors in turn, 1,000 each, 10,000 benign.
Second and third: a session is recorded (5,200 PDUs), then 1,000 of its PDUs are
sent into a new session. The same three lines with `ORACLE=harness` give the detect
time (the harness receiver instead of the gateway); with `PROFILE=mac` the second profile. Output:
`runs/<run_id>/attack/attack.csv` (by `join_attack.py`), `proxy_log.csv`, the gateway's `app_rx.csv`,
`periodic_tx.csv`, `session_replay.txt` (the two session identifiers). Stops: the common ones; the
join's status is not 0 when an attacked PDU was delivered or a benign one was not; `attack.csv` is
judged for `tcp_nodelay` over both ends. The proxy sits on the transmitter's board because the
receiver accepts a connection from its peer address only.

Cell j of the E9 addendum, the attacker as a network node of its own (simulated on iris): the same
lines with `RELAY_NETNS=1`, for example

    LINK_SPEED=100 RELAY_NETNS=1 PROXY_OPTS="--count 400" scripts/run_bench_net.sh attack <id> 1300 3 replay,bitflip,auth_tamper,freshness_rollback
    LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 RELAY_NETNS=1 PROXY_OPTS="--count 4000" scripts/run_bench_net.sh attack <id> 13000 3 replay,bitflip,auth_tamper,freshness_rollback

and with `PROFILE=mac`; the old-session replay is the record line and the replay line above, each
with `RELAY_NETNS=1`. The campaign's runs of this variant (E4n) are these three lines, once as they
are and once with `PROFILE=mac`, six runs:

    LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 COOL_WAIT=900 RELAY_NETNS=1 PROXY_OPTS="--count 4000" scripts/run_bench_net.sh attack <id> 13000 3 replay,bitflip,auth_tamper,freshness_rollback
    LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 COOL_WAIT=900 RELAY_NETNS=1 RECORD_SESSION=/dev/shm/<file> scripts/run_bench_net.sh attack <id>_rec 5200 0 replay
    LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 COOL_WAIT=900 RELAY_NETNS=1 REPLAY_SESSION=/dev/shm/<file> PROXY_OPTS="--count 1000" scripts/run_bench_net.sh attack <id>_old 5000 4 session_replay

The driver makes a network namespace `txns` on iris with one end of a virtual
Ethernet pair (`veth-tx`, 10.99.0.1/30) and no other interface or route, starts the harness
transmitter in it as the normal user (`ip netns exec` as root, then `setpriv` back) with the proxy's
address 10.99.0.2 as its peer (a run-time option of the transmitter, nothing is built for it), and
the proxy (`attack_proxy.py`, which holds no key) in the root namespace, bound to the other end
(`veth-atk`, 10.99.0.2/30) and pinned to core 2 (`RELAY_CPU`); it connects to the gateway receiver
from iris's eth0 address as before. Namespace and pair are removed when the run ends and on every
other way out of the driver (after an abort in mid-run the transmitter and the proxy are ended
first). What a killed driver left of these two names is removed before the next start of any mode
when no process runs in the namespace; when one does, that start is refused. The option with
another mode than `attack` is refused. eth0, wlan0 and the default route are not touched; the kernel's veth
module, once loaded, stays loaded until the next boot.
`netns_check.txt` in the run directory: `route_check=fails ...` (the route look-up for the receiver
from inside the namespace; the run does not start when it succeeds), the namespace's routes and
addresses, `ip -d link show` of both ends, a ping across the pair, the default route, and after the
run `gone_after_run=yes`. `attack/proxy.log` has the line `transmitter connected from 10.99.0.1:<port>`.
A run without one of the three (failing route check, that address, gone afterwards) is `EXCLUDED`.
Files, vectors, join and exit status are those of the attack mode without the option.

## E5, handshake

    DRY_RUN=0 scripts/run_bench_net.sh handshake <run_id> 1000
    DRY_RUN=0 scripts/run_bench_net.sh build-gw-tx
    DRY_RUN=0 scripts/run_bench_net.sh hsneg <run_id>_rec record 1
    DRY_RUN=0 scripts/run_bench_net.sh hsneg <run_id>_t<n> <n> 100          # n = 1 .. 10
    DRY_RUN=0 scripts/run_bench_net.sh hsneg <run_id>_t11<v> 11<v> 25       # v = drop, sig, mac, key
    DRY_RUN=0 scripts/run_bench_net.sh hsneg <run_id>_t12<v> 12<v> 50       # v = drop, flip

Timing: 1,000 handshakes, one every T_min + 50 ms with the tree's timers, no PDU stream;
`runs/<run_id>/handshake/handshake_tx.csv` and `handshake_rx.csv` (`pdu_stream=none`).
Negative tests: gateway binaries on both ends, the proxy between them.
Output: `runs/<run_id>/hstest/` (for 11 and 12: `hstest/r001` ..), `hsneg.txt` with the record line
and `PASS` or `REJECT` as its last line. Stops: the common ones; the oracle (`check_hsneg.py`) rejects
a run whose rows, sessions, installation counters, deliveries or TCP_NODELAY read-backs are not the
expected ones, or with a transmitter PDU given up. The restart test of CAMPAIGN.md is made with
`scripts/run_e2e.sh`, not with the harnesses.

## E6, periodic streams (deadline = period, open loop)

    DRY_RUN=0 [STREAMS=<k>] [PHASE=staggered] scripts/run_bench_net.sh periodic <run_id> <period_us> <releases> <other|fifo>
    DRY_RUN=0 PROFILE=mac scripts/run_bench_net.sh periodic <run_id> 10000 100000 <other|fifo>

`PHASE=staggered` (periodic mode only; any other value than `sync` or `staggered` is refused, as is
`staggered` with another mode): the transmitter gets `--phase staggered`, releases stream s of its k
streams s/k of a period after stream 0 and writes `phase=staggered` into its file, which makes the
toolkit's configuration name end in `-staggered` instead of `-sync`. Without the variable the
command line and the files are unchanged. With several partitions each process staggers its
own streams; the processes start their schedules independently of each other in either phase.

Cells of CAMPAIGN.md: period_us 10000 / 20000 / 50000 / 100000 with 100000 / 50000 / 20000 / 10000
releases, `STREAMS` 1, 2, 4, both schedulers. Output: `runs/<run_id>/periodic/`.
Two cells of the plan cannot be run as written: the MAC profile has one stream (the product
configures one MAC row), and a sender on four cores does not exist (one worker thread per process;
more than one core is used by several sender processes, each with its own connection:
`PARTITIONS=2 CORES="2 3"` gives two). The driver refuses more than two sender processes unless
`MAX_PARTITIONS` raises that limit, as in the cells with four and five sender processes (E6m, E6c).

Further cells (E6x), without the clock probe, one session, in an order fixed by a seed (61125092):

    LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 COOL_WAIT=900 STREAMS=3 scripts/run_bench_net.sh periodic <id> 10000 100000 other
    LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 COOL_WAIT=900 STREAMS=5 scripts/run_bench_net.sh periodic <id> 10000 100000 other
    LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 COOL_WAIT=900 STREAMS=6 scripts/run_bench_net.sh periodic <id> 20000 50000 other
    LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 COOL_WAIT=900 STREAMS=8 scripts/run_bench_net.sh periodic <id> 20000 50000 other
    LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 COOL_WAIT=900 STREAMS=8 scripts/run_bench_net.sh periodic <id> 50000 20000 other
    LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 COOL_WAIT=900 STREAMS=8 scripts/run_bench_net.sh periodic <id> 100000 10000 other
    LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 COOL_WAIT=900 PROFILE=mac scripts/run_bench_net.sh periodic <id> 5000 100000 other
    LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 COOL_WAIT=900 PROFILE=mac scripts/run_bench_net.sh periodic <id> 2000 100000 other

Several sender processes on one core (E6m), synchronous release within a process: four processes of
five streams at 50 ms and five processes of eight streams at 100 ms, all on core 3.
`START_BELOW_PARTITIONS_C=68` starts these runs by the rule of a run with one process (E9_SPEC.md, H9):

    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 START_BELOW_PARTITIONS_C=68 PARTITIONS=4 MAX_PARTITIONS=4 CORES="3 3 3 3" STREAMS=5 scripts/run_bench_net.sh periodic <id> 50000 20000 other
    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 START_BELOW_PARTITIONS_C=68 PARTITIONS=5 MAX_PARTITIONS=5 CORES="3 3 3 3 3" STREAMS=8 scripts/run_bench_net.sh periodic <id> 100000 10000 other

Four sender processes on four cores (E6c), two and three streams per process.
`START_BELOW_PARTITIONS_C_baolong=68` lets baolong (board B) start below 68 C, the general limit; iris
(board A), which has the four busy cores, keeps the 62.1 C of a run with several sender processes
(E9_SPEC.md, I2). The dry run of this kind was a block of its own in the campaign script (`e6cdry`:
the first line with `DRY_RUN=1` and 2000 releases), read before the two cells were started:

    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 START_BELOW_PARTITIONS_C_baolong=68 PARTITIONS=4 MAX_PARTITIONS=4 CORES="0 1 2 3" STREAMS=2 scripts/run_bench_net.sh periodic <id> 10000 20000 other
    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 START_BELOW_PARTITIONS_C_baolong=68 PARTITIONS=4 MAX_PARTITIONS=4 CORES="0 1 2 3" STREAMS=3 scripts/run_bench_net.sh periodic <id> 10000 20000 other

Staggered release (E6p), one sender process, in an order fixed by a seed (61125096):

    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 PHASE=staggered STREAMS=8 scripts/run_bench_net.sh periodic <id> 20000 50000 other
    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 PHASE=staggered STREAMS=4 scripts/run_bench_net.sh periodic <id> 10000 100000 other
    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 PHASE=staggered STREAMS=6 scripts/run_bench_net.sh periodic <id> 20000 50000 other
    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 PHASE=staggered STREAMS=5 scripts/run_bench_net.sh periodic <id> 10000 100000 other
    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 PHASE=staggered STREAMS=4 scripts/run_bench_net.sh periodic <id> 20000 50000 other
    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 PHASE=staggered STREAMS=3 scripts/run_bench_net.sh periodic <id> 10000 100000 other
    DRY_RUN=0 HOLDING_MEASURING=1 LINK_SPEED=100 PHASE=staggered STREAMS=2 scripts/run_bench_net.sh periodic <id> 10000 100000 other

## E7, sustained load

    DRY_RUN=0 scripts/run_bench_net.sh ladder <run_id> 60 15 5 100 200 300 350 400 425 450 475 500 525 550 600
    DRY_RUN=0 PARTITIONS=2 CORES="2 3" scripts/run_bench_net.sh ladder <run_id> 60 15 5 <rates, each divisible by 2>
    DRY_RUN=0 PROFILE=mac [MAINFUNCTION=event] scripts/run_bench_net.sh ladder <run_id> 60 15 5 <rates>
    DRY_RUN=0 scripts/run_bench_net.sh calibrate <run_id> 100 15

A step is ramp + duration (75 s); the first line is 60 steps.
Output: `runs/<run_id>/throughput/` with `periodic_{tx,rx}_<rate>pps_rep<k>[_p<i>].csv`,
`throughput_{tx,rx}_...csv` (one row per second, with `proc_cpu_ns`), one `handshake_<step>/` per
step; calibration in `runs/<run_id>/calibration/`. What a step loses at the transmitter is
`jobs_dropped_at_release` (a release that found its queue of `backlog_jobs` = 4 full). In cyclic mode
one PDU per stream and tick is the bound (1,000 PDU/s per stream at 1 ms), and a step at exactly
that rate keeps the backlog any hiccup leaves; event mode has no tick. Stops: the common ones, and
for two partitions the start below 62.1 C and the stop at 78 C.

## E8, footprint

No tool of `Autosar_SecOC/bench` measures it. With standard tools on the board, on the binaries
the harness build produces:

    strip -o /dev/shm/SecOC.stripped build-gw-rx/SecOC && size -A /dev/shm/SecOC.stripped
    /usr/bin/time -v taskset -c 3 build-bench/bench_crypto_ops --ops mldsa_sign --n 1000 --msg-bytes 14 --ctx-bytes 64 --out /dev/shm/x.csv
    perf stat -e instructions,cycles -- taskset -c 3 build-bench/bench_crypto_ops --ops mldsa_sign --n 1000 --msg-bytes 14 --ctx-bytes 64 --out /dev/shm/x.csv

The second line gives the peak resident set of the signing process, not of a gateway over ten
minutes, and the tool locks its memory (mlockall), which puts every mapped page into that figure.

The campaign's footprint figures were taken with the following lines. On board A, the size of the
gateway transmitter and the instructions per call, from two run lengths so that the start-up of the
process cancels in the difference (`<op>` = `mldsa_sign`, `mldsa_verify`; `<n>` = 1000, 2000; with
`sudo -n` in front when the plain `perf stat` is refused):

    ls -l build-gw-tx/SecOC
    strip -o <tmp>/SecOC_tx.stripped build-gw-tx/SecOC && ls -l <tmp>/SecOC_tx.stripped && size -A <tmp>/SecOC_tx.stripped
    perf stat -x, -e instructions:u,cycles:u -o <tmp>/perf_<op>_<n>.csv -- taskset -c 3 build-bench/bench_crypto_ops --ops <op> --n <n> --msg-bytes 14 --ctx-bytes 64 --out <tmp>/x.csv

The resident memory of the gateway processes, over one functional run of 60,000 PDUs on one
signature stream; while it runs, the second line is read every 30 s on each board in a short session
of its own (allowed there: a functional run, nothing is timed):

    BOARD_LOCK_WAIT=1800 PI_TREE=<board directory> PERIOD_CYCLES=10 LINK_SPEED=100 scripts/run_e2e.sh twonode 60000 <run_id>
    p=$(pgrep -x SecOC | head -1); grep -E "VmHWM|VmRSS|VmData|VmSize" /proc/$p/status

The sizes of the gateway binaries, in the gateway's directory on each board:

    for b in build*/; do ls -l $b/SecOC; strip -o /dev/shm/SecOC.s $b/SecOC && ls -l /dev/shm/SecOC.s && size -A /dev/shm/SecOC.s; done

## E9, latency across the two boards (100 Mbit/s, deadline = period)

`CLOCK_PROBE=1` puts `bench_clock_probe` beside a `periodic` run: server on baolong, client on iris,
core 1 on both (`PROBE_CPU`), UDP port `PORT`+3, one exchange every 101 ms (`PROBE_INTERVAL_MS`: the
phase to the 10 ms releases moves through its ten values 1 ms apart instead of staying at one; the
phase to the 1 ms cycle stays fixed, 101 ms being 101 cycles), from 12 s before the transmitter starts
(`PROBE_LEAD_IN`) to 12 s after it has ended (`PROBE_LEAD_OUT`) and on to the end of the probe's
window of 5 s that is running then. The two leads put two anchors of
the offset track on each side of the run.
The probe writes three files, all in `periodic/` (beside the application logs in a gateway run):
- `clock_probe.csv`, written by the client on iris: per completed exchange the four `CLOCK_MONOTONIC`
  reads, the four `CLOCK_MONOTONIC_RAW` stamps of the exchange and the four widths (the
  probe reads RAW, MONOTONIC, RAW at each of its four points; the width is the distance of the two
  raw reads). Header lines `format=2` and `clock_raw=CLOCK_MONOTONIC_RAW`.
- `clock_map_a.csv` (iris, by the client) and `clock_map_b.csv` (baolong, by the server): a second
  thread of each probe process reads RAW, MONOTONIC, RAW every 5 ms from its start to its end; columns
  `raw1_ns,mono_ns,raw2_ns`, footer `samples` and `samples_dropped`. About 10 MB per board for a run
  of 1,000 s. With them a reader carries the PDU stamps, which are `CLOCK_MONOTONIC`, onto the raw
  clock of their board; the offset between the boards is tracked on the raw stamps.
No clock is set, no root, no package, no service touched. Without the variable no probe runs.

Dry run (DRY_RUN marker, 2,000 releases) and campaign line of each cell:

    a  LINK_SPEED=100 CLOCK_PROBE=1 scripts/run_bench_net.sh periodic <id> 10000 2000 other
       LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 CLOCK_PROBE=1 scripts/run_bench_net.sh periodic <id> 10000 100000 other
    b  LINK_SPEED=100 CLOCK_PROBE=1 scripts/run_bench_net.sh periodic <id> 10000 2000 fifo
       LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 CLOCK_PROBE=1 scripts/run_bench_net.sh periodic <id> 10000 100000 fifo
    c  LINK_SPEED=100 CLOCK_PROBE=1 STREAMS=2 scripts/run_bench_net.sh periodic <id> 10000 2000 other
       LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 CLOCK_PROBE=1 STREAMS=2 scripts/run_bench_net.sh periodic <id> 10000 100000 other
    d  LINK_SPEED=100 CLOCK_PROBE=1 scripts/run_bench_net.sh periodic <id> 20000 1000 other
       LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 CLOCK_PROBE=1 scripts/run_bench_net.sh periodic <id> 20000 50000 other
    e  LINK_SPEED=100 CLOCK_PROBE=1 PROFILE=mac scripts/run_bench_net.sh periodic <id> 10000 2000 other
       LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 CLOCK_PROBE=1 PROFILE=mac scripts/run_bench_net.sh periodic <id> 10000 100000 other
    f  LINK_SPEED=100 CLOCK_PROBE=1 CORE_RX=2 scripts/run_bench_net.sh periodic <id> 10000 2000 other
       LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 CLOCK_PROBE=1 CORE_RX=2 scripts/run_bench_net.sh periodic <id> 10000 100000 other
    g  LINK_SPEED=100 CLOCK_PROBE=1 PI_TREE=<board directory> scripts/run_e2e.sh twonode 2000 <id>
       LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 CLOCK_PROBE=1 PI_TREE=<board directory> PERIOD_CYCLES=10 STREAMS=1 PROBE_BIN='$HOME/pqc-secoc-rev1-bench/build-bench/bench_clock_probe' scripts/run_e2e.sh twonode 10000 <id>
    h  LINK_SPEED=100 CLOCK_PROBE=1 PROFILE=both scripts/run_bench_net.sh periodic <id> 10000 2000 other
       LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 CLOCK_PROBE=1 PROFILE=both scripts/run_bench_net.sh periodic <id> 10000 100000 other
    i  LINK_SPEED=100 CLOCK_PROBE=1 BG_MBIT=50 scripts/run_bench_net.sh periodic <id> 10000 2000 other
       LINK_SPEED=100 DRY_RUN=0 HOLDING_MEASURING=1 CLOCK_PROBE=1 BG_MBIT=50 scripts/run_bench_net.sh periodic <id> 10000 100000 other

Cells a to f: 1,000 s of releases per campaign run; cell a is three such runs, one
per session. In cell c `<releases>` is per stream. In cell f the receiver process runs on core 2 of
baolong (`CORE_RX`; `CORE_TX` exists as well), the probe stays on core 1.

Judgment: after the copy `check_clock_probe.py --run` reads the three probe files with
`periodic_tx.csv` and `periodic_rx.csv` and writes `e9_check.txt`: the figures of the raw track and
of the two maps, the widths, where the run lies between the anchors, the smallest causality margin
and the number of violations, one line with what the definitions of probe format 1 make of the
monotonic columns of the same run (a diagnostic, never the verdict), then the verdict line
`PASS offset_bound_us=<b> offset_cert_us=<T> offset_bound_total_us=<max of the two> map_bound_a_us=<A>
map_bound_b_us=<B> bound_total_us=<the three added> exchanges_outside=<n>` or the same with `FAIL`
and `; <reason>; ...` (a figure that the files do not give reads `none`). The rules are those of
E9_SPEC.md, Addendum E, and of the FINAL ruling on the clock track, which holds on the raw stamps:
- the track: region from the second anchor to the second-to-last one, `offset_bound_us` the largest
  delta/2 of its anchors, `offset_cert_us` the smallest T such that the exchanges which certify the
  line to within T are nowhere more than 2 s apart, no exchange of the region farther from the line
  than its own delta/2 plus the larger of the two;
- a map: a sample is valid when its two raw reads are at most 5,000 ns apart; a stamp is carried over
  on the straight line between the two valid samples around it; in the range the stamps use no two
  valid samples are more than 50 ms apart. `map_bound` is the larger of two terms plus the largest
  half-width. The hold-out: the largest distance of a sample from the line through its two
  neighbors in the file, both valid (at least one sample of the range must have them). The kink
  term (E12.1, E12.7): over the intervals between two valid samples of the range, the largest
  |slope behind - slope before| x length / 4, which is what one rate change inside an interval
  does to the straight line across it. The slope before is read from the interval's first sample
  back to the nearest valid sample at least 4 ms before it, the slope behind from its second
  sample on to the nearest one at least 4 ms behind it; an interval of the range without such a
  sample in the file (the range begins or ends at the edge of the file) is not a result. The exchange points of
  the same board (another thread, other instants) must lie within `map_bound` plus half their own
  width of the map, and at least 100 of them (20 in a gateway run) must lie in the range;
- the three files are those of one probe pair (E12.2): each map says the role it is read as (`a`
  for `clock_map_a.csv`), the host of that end (`host_a` or `host_b` of `clock_probe.csv`) and the
  commit of the probe file; `clock` and `clock_raw` name the two clocks in all three files, and
  `interval_ms` is 5 in the maps. A missing line counts as a wrong one;
- the bound in total, offset plus the two maps, may not exceed 100 us, and no causality margin
  (`rx_done_ns` - theta(`send_done_ns`) - `send_done_ns`, on the raw clocks) may lie below minus it.
Reasons for FAIL: a probe file of format 1 (refused for latency by name); a probe or map file that
was not collected, has no footer, or a count that is not its rows; `samples_dropped` other than 0; a
stamp outside its map; a map gap above 50 ms; a map without a hold-out or with an interval at the
edge of the file; a header line that is not that of the pair; an exchange point off the map; too
few such points;
fewer than four anchors; more than 2 s of the region without an exchange; an exchange outside the
track; a bound in total above 100 us; fewer than two anchors before the first release or after the
last delivery; a gap between two exchanges above 1,000 ms; a delivered PDU whose sender row has
`send_done_ns` = 0; a causality violation; `rx_done_ns` not recorded; an impossible exchange. A FAIL
leaves `E9_INVALID` and exit status 1; it does not go into `EXCLUDED`, the periodic files are judged
as without the probe. The latency line of `e9_check.txt` is a plausibility figure of the driver, not
a result: the keys come from the toolkit. The three probe files are not given to `check_csv.py`;
`check_clock_probe.py --form` judges their form (column line, footers, counts) and the driver puts
its line for each into `check.txt` as for every other csv (`<path>: ok` or the fault). A run that is
not a result gets no latency line in `e9_check.txt`; what the maps say is printed in any case.
Stops before a start, in addition to the common ones: a clock probe or `bg_traffic.py` process left
on a board; `PROBE_CPU` or `BG_CPU` equal to a harness core or to each other; more than one partition.

How the probes are ended (E12.4, both drivers): SIGTERM, then a wait of up to `PROBE_WAIT` s
(default 20) that ends when the process has gone. A process still there after the wait is named in
one line of the driver's output (`the probe server (bench_clock_probe --server) on <host> has not
ended within 20 s of its SIGTERM: SIGKILL`) and killed; the file it did not write is then missing
and the check says so (`E9_INVALID`). So no probe is running when the board's run directory is
removed, also at the end of `probetest`. A driver that is interrupted ends its probes the same way
before it releases the board locks.

Limits of the probe's command line, known and left as they are (E12.5; the drivers never reach
them): option values are not fully validated (an unknown option before `--port`, a non-numeric
value, a negative `--interval-ms`, with which a client did not end on SIGTERM); a complete file of
the same name from an earlier run survives a failed write (the drivers give every run a new
directory); a full disk shows only at the end of a run, as a missing file; the return values of
the clock reads are not checked (both clock ids exist on Linux). After a late wake-up the sampler
takes the samples it owes at once and then goes on in the original grid, so two samples can lie
microseconds apart. That is why the slopes of the kink term are read over at least 4 ms (E12.7): a
slope between two such samples is their read noise divided by almost nothing.

What the self-test of `check_clock_probe.py` pins (E12.3): every reason of `--run`, `--zero`,
`--pair` and `--form`, each limit at its value ("not above"), each term of the bounds and each
header line of E12.2 were switched off or turned one at a time in a copy of the checker, and the
self-test failed each time (66 changes). Not pinned by the self-test: the rules of `--files` (the
CTest on the programs' own output: a missing header line, a role or interval other than expected,
fewer than 8 samples in 10, more than one sample in ten not valid, a map that does not cover the
exchanges, a median width above 5,000 ns; of that mode only the passing case and `samples_dropped`
have a known answer), and the four reasons of the diagnostic line on the monotonic columns (never
the verdict; only that it says PASS or FAIL where it must).

Cell h, both variants at once (`PROFILE=both`): one transmitter process with two streams on the one
connection, stream 0 the first signature stream (PDU 2, header 0x10) and stream 1 the MAC stream
(PDU 13, header 0x20), as the gateway's `PROFILE=both`; `<releases>` is per stream and `STREAMS` is
set to 2. The usual files, with the rows of both streams under their stream index; both files say
`profile=both`, `stream_pdu_ids=2,13`, `stream_header_ids=0x10,0x20` and `stream_profiles=mldsa65,mac`.
Both streams are released at the same instants (the tool's default phase, `PHASE=sync`)
and handed to SecOC in the same tick, stream 0 first. In which
order the two leave is the product's processing order, so each stream's figures contain the other
stream's work of the same tick.

Cell i, unrelated traffic on the link (`BG_MBIT=<Mbit/s>`): `bg_traffic.py` sends zero bytes on one
unprotected TCP connection (default socket options, port `PORT`+4) from iris to baolong, core 2 on
both (`BG_CPU`), started behind the quiet-link check, 2 s before the probe, and stopped after the
probe. Its writes come at gaps drawn uniformly from 0.5 to 1.5 ms by a seeded generator (seed
20261124), each bringing the bytes sent up to rate x elapsed time: a fixed mean rate, not a fixed
tick, because a tick would meet the 10 ms releases and the 100 ms probe at one phase for a whole
run. `background_traffic.txt` in the run directory, written by the driver from the two ends' files
(`periodic/bg_source.txt`, `bg_sink.txt`): `rate_offered_bit_s`, `rate_achieved_bit_s`, `pattern`,
`seed`, `bytes_sent`, `bytes_received`, `writes`, `max_deficit_bytes` and `send_timeouts` (how far the
source fell behind; recorded, not judged), the durations, hosts and cores of both ends, first
and last byte of each end on its board's clock, how each end ended, and `verdict=PASS` or
`verdict=FAIL: <reasons>` (achieved below 95 % of offered; nothing received; the flow began after
the first release or ended before the last PDU was sent). A FAIL leaves `BG_INVALID` and exit status
1 and is not in `EXCLUDED`. The probe's exchanges share the loaded link.

A probe and a flow end by themselves when their driver is lost: `timeout` around both probe ends and
`--max-seconds` for the flow, both the run's length plus 300 s.

Cell g, the gateway binaries on both boards: their own files carry what is needed except the arrival
time. `app_tx.csv` has `submit_ns` and `send_done_ns` (board A), `app_rx.csv` has `verify_done_ns` and
`deliver_ns` (board B), all absolute `CLOCK_MONOTONIC`; `rx_done_ns` is declared not recorded, so the
causality rule is judged on `verify_done_ns` (a PDU is not verified before it was sent), which is
weaker by the verification time. The line is the gateway driver (`scripts/run_e2e.sh`) with the probe
added: `clock_probe.csv` and `e9_check.txt` lie beside the application logs in `runs/<id>/` (marker
`FUNCTIONAL`, and `DRY_RUN` unless `DRY_RUN=0`). `e9_check.txt` begins with the period of the
gateway's own application from its own files: `period_cycles` (`app_tx.csv`) times `mf_period_us`
(`handshake_tx.csv`), closed loop (the next PDU of a stream that many cycles after the last).
`PI_TREE` is the gateway driver's directory under the home directory of the boards (it syncs the
tree into it, builds `build-tx` on iris and `build-rx` on baolong there, refuses below
250 MB free, and ties the directory to the clone that used it first: `<PI_TREE>/.origin`). Always
give it: the default is the gateway driver's own default directory. The probe is taken from
`<PI_TREE>/build-bench`; when the harnesses were built into another directory, name the binary:
`PROBE_BIN='$HOME/pqc-secoc-rev1-bench/build-bench/bench_clock_probe'`.
With `HOLDING_MEASURING=1` the gateway driver behaves under the marker as the other modes do: the
local marker and the marker on the board are no obstacle, no board lock is taken, governor and
frequency cap are left as the holder set them, and while the transmitter runs one SSH session to
iris only waits, on core 0, and none goes to baolong. Without it the driver takes the board locks
(owner `BOARD_LOCK_OWNER`), sets the governor to performance on both boards and baolong's
`scaling_max_freq` to the content of `~/array_rev/DEV_FREQ_CAP` or, without that file, to
1,500,000 kHz, does not put them back, and looks for the transmitter's end in a new session every
40 s. What this line does not have in either case: the timing gates of `run_bench_net.sh` (no
`EXCLUDED` for throttling, other traffic or a busy foreign process; it starts below 78 C on baolong
and records `env_<host>.txt`) and a sender with a fixed period.

Tests of the probe on the boards, under the board locks:

    [LINK_SPEED=100] scripts/run_bench_net.sh probetest <id> [seconds]

For each board client and server on that one board over 127.0.0.1 (true offset zero), then two probes
at once over the link, iris to baolong and baolong to iris, `<seconds>` each (default 60;
the pair needs four anchors in each file, so at least 20 s). `probetest.txt`: per
board `PASS` when every exchange (so every anchor) gives |theta| <= delta/2, and for the pair `PASS`
when at every anchor of either file's region the two tracks sum to zero within the two total bounds
added. The first test fails on stamps that are not causal (taken on the wrong
side of a send or a read, columns exchanged); it cannot see an error of the track computation, which
the second test and `check_clock_probe.py --selftest` (known offset, drift of 30 ppm, asymmetric
delay, every rule broken once, the known answers of Addendum E and E12) are for. CTest runs the self-test, a same-host test of 12 s and
`bench_verify_only`.

Instructions per verification (not part of E9 proper), on a board, as for `mldsa_sign`:

    perf stat -x, -e instructions:u,cycles:u -o perf_mldsa_verify_only_<n>.csv -- taskset -c 3 build-bench/bench_verify_only --n <n> --msg-bytes 14 --ctx-bytes 64

for `<n>` = 10000 and 20000 in the campaign (E8v; the events and the options of the campaign's
`mldsa_sign` runs; 10,000 calls apart, because key generation and the one signature of the set-up
differ between two launches). The tool makes a key pair and one signature, then calls
`OQS_SIG_verify_with_ctx_str` `<n>` times on it and nothing else; it writes no CSV.
