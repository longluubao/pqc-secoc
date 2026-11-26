"""Small synthetic CSVs with hand-computable answers (see the comments), shared by the tests."""
MS = 1_000_000  # ns


def text(header, rows, comments=(), trailer=()):
    """CSV text: comment lines, header row, data rows, then trailing comment lines."""
    return ("".join(f"# {c}\n" for c in comments) + header + "\n" + "".join(",".join(map(str, r)) + "\n" for r in rows)
            + "".join(f"# {c}\n" for c in trailer))


def harness_head(tool, mode=None):
    """The comment block the single-node harnesses write above their rows (shape of a real file)."""
    head = [f"tool={tool}", "commit=eed269f3cef4d4f67ab8afdf84f33f165f164624", "host=iris",
            "compile_flags=GNU 14.2.0: -O2 -DLINUX -DMCAL_TARGET=MCAL_TARGET_PI4", "liboqs_version=0.15.0",
            "cpu_affinity=3", "cpu_pinned=yes", "governor=performance", "freq_khz_start=1500000", "mlockall=ok",
            "clock=CLOCK_MONOTONIC", "timer_overhead_ns=56", "n=20", "msg_bytes=64"]
    if mode:
        head += ["seed=20261123", "op=both", f"mode={mode}",
                 "csm_ns=Csm_SignatureGenerate(job 10) / Csm_SignatureVerify(job 8192), synchronous" if mode == "ab" else
                 "csm_ns=NOT the Csm path: second standalone call of the pair (noise floor)"]
    return tuple(head)


# ... and below them: the counters and end-of-run readings exist only if the run finished
CRYPTO_TAIL = ("freq_khz_end=1500000", "wall_s=18.608", "cpu_s=18.612", "ctx_switches_involuntary=135", "ctx_switches_voluntary=0")
PAIRED_TAIL = ("signature_mismatches=0", "failed_calls=0", *CRYPTO_TAIL)


def crypto_ops(head=harness_head("bench_crypto_ops"), tail=CRYPTO_TAIL):
    """warmup=10. mldsa_sign: seq 0..9 garbage, seq 10..19 = 1..10 ms (rows written even seq first, then
    odd, so order-sensitive results are right only if rows are sorted by seq).
    mldsa_verify: seq 0..19 = 400 us + seq us."""
    sign = [("mldsa_sign", s, 9_000 * MS if s < 10 else (s - 9) * MS) for s in range(20)]
    verify = [("mldsa_verify", s, 400_000 + 1000 * s) for s in range(20)]
    return text("op,seq,ns", sign[::2] + sign[1::2] + verify, head, tail)


def geometric_times_us(below=1000, first=6400, bins=7):
    """Signing times (us): `below` values at 0.5 ms, then `first`, first/2, first/4, ... values in the
    1-ms bins (1, 2], (2, 3], ..., each at the middle of its bin. With the defaults the counts above
    1 .. 8 ms are 12700, 6300, 3100, 1500, 700, 300, 100, 0."""
    values = [500.0] * below
    for i in range(bins):
        values += [1000.0 * (i + 1) + 500] * (first >> i)
    return values


def crypto_ops_geometric(**kw):
    """A crypto_ops.csv whose mldsa_sign series is ten warm-up rows and then geometric_times_us()."""
    rows = [("mldsa_sign", s, 9_000 * MS) for s in range(10)]
    rows += [("mldsa_sign", 10 + i, int(1000 * v)) for i, v in enumerate(geometric_times_us(**kw))]
    return text("op,seq,ns", rows)


ATTRIB_ROUNDS = [1] * 8 + [2] * 5 + [3] * 3 + [4] * 2 + [6, 20]  # rounds of the 20 calls after the warm-up
ATTRIB_OFF_US = {0: 7000, 16: 150, 19: 6000}  # wall - cpu of call 0 (1 round), 16 (4 rounds), 19 (20 rounds); 2 us otherwise


def sign_attrib(counted=True, rows=None, head=(), tail=("freq_khz_end=1500000", "wall_s=0.0209", "cpu_s=0.02075")):
    """warmup=10. Ten warm-up calls of one round, then 20 calls with ATTRIB_ROUNDS rounds. Processor time
    is exactly 100 us + 250 us per round; wall time is that plus ATTRIB_OFF_US. shake_calls = 5 + 3 per
    further round. Sum of cpu_ns over all 30 rows: 10 x 350 + 20 x 100 + 250 x 61 = 20750 us (the footer).
    After the warm-up: off total 17 x 2 + 150 + 7000 + 6000 = 13184 us; wall above 5 ms: calls 0 (7.35 ms,
    1 round) and 19 (11.1 ms, 20 rounds, the only one whose processor time is above 5 ms too)."""
    if rows is None:
        rounds = [1] * 10 + ATTRIB_ROUNDS
        rows = []
        for seq, r in enumerate(rounds):
            cpu = 1000 * (100 + 250 * r)
            wall = cpu + 1000 * (ATTRIB_OFF_US.get(seq - 10, 2) if seq >= 10 else 2)
            rows.append((seq, wall, cpu, 5 + 3 * (r - 1)))
    shake = ("shake_counted=OQS_SHA3_shake256_inc_init, through OQS_SHA3_set_callbacks", "shake_calls_min=5",
             "shake_calls_step=3", "shake_probes=64") if counted else ("shake_counted=off",)
    return text("seq,wall_ns,cpu_ns" + (",shake_calls" if counted else ""), [r if counted else r[:3] for r in rows],
                (*harness_head("bench_sign_attrib"), "clock_order=monotonic,thread_cpu,sign,thread_cpu,monotonic",
                 "cpu_clock=CLOCK_THREAD_CPUTIME_ID", "cpu_timer_overhead_ns=1203", *shake, *head), tail)


def overhead_paired(mode="ab", tail=PAIRED_TAIL):
    """warmup=10. op sign: standalone 1 ms; csm - standalone = 100 ns in AB pairs (even seq) and 300 ns
    in BA pairs (odd seq); the 10 warm-up pairs carry a 9 ms difference that must be dropped.
    op verify: standalone 400 us, csm identical."""
    rows = []
    for s in range(20):
        order = "AB" if s % 2 == 0 else "BA"
        diff = 9 * MS if s < 10 else (100 if order == "AB" else 300)
        rows.append((s, order, "sign", MS, MS + diff))
        rows.append((s, order, "verify", 400_000 + s, 400_000 + s))
    return text("seq,order,op,standalone_ns,csm_ns", rows[::-1], harness_head("bench_overhead_paired", mode), tail)


TX_HEADER = "stream,seq,release_ns,start_ns,auth_done_ns,send_done_ns"
RESPONSE_MS_STREAM0 = [2, 12, 13, 2, 2, 11, 2, 2, 2, 2, 10, 2]  # misses at seq 1, 2, 5 (10 ms is not a miss)


def _job(stream, seq, offset_ms, response_ms):
    """Queueing 1 ms, authentication = response - 1.5 ms, send 0.5 ms."""
    release = 1_000 * MS + seq * 10 * MS + offset_ms * MS
    done = release + response_ms * MS
    return (stream, seq, release, release + MS, done - MS // 2, done)


def tx_meta(streams, **override):
    """The mandatory Tx comment block; override a key, or set it to None to leave it out."""
    meta = dict(period_ns=10 * MS, deadline_ns=10 * MS, streams=streams, cores=1, profile="mldsa65", scheduler="fifo",
                payload_bytes=64, commit="abc1234", host="iris")
    meta.update(override)
    return tuple(f"{k}={v}" for k, v in meta.items() if v is not None)


def periodic_tx_rows():
    """Stream 0: 12 jobs with RESPONSE_MS_STREAM0; stream 1 (offset 5 ms): 12 jobs, all 3 ms."""
    return [_job(0, s, 0, r) for s, r in enumerate(RESPONSE_MS_STREAM0)] + [_job(1, s, 5, 3) for s in range(12)]


def periodic_tx_two_streams(rows=None, **override):
    """Period and deadline 10 ms. Rows are written even positions first, then odd, so miss runs need
    sorting by seq."""
    rows = periodic_tx_rows() if rows is None else rows
    return text(TX_HEADER, rows[::2] + rows[1::2], tx_meta(**{"streams": 2, **override}))


def periodic_tx_one_stream():
    """Period 10 ms, one stream, 12 jobs, response 3 ms, service 2 ms."""
    return text(TX_HEADER, [_job(0, s, 0, 3) for s in range(12)], tx_meta(1))


RX_HEADER = "stream,seq,rx_done_ns,verify_done_ns,deliver_ns,result"
CLOCK_HEADER = "t_ns,offset_ns,rtt_ns,method"
RX_AHEAD = 7_000 * MS  # the receiver's clock reads 7 s more than the sender's


def rx_row(tx_row, latency_us=500, verify_us=430, handoff_us=20, result="ok", offset=RX_AHEAD):
    """Rx row of a Tx job: received latency_us after send_done, verified verify_us later, delivered
    handoff_us after that; timestamps on the receiver's clock."""
    rx_done = tx_row[5] + offset + 1000 * latency_us
    return (tx_row[0], tx_row[1], rx_done, rx_done + 1000 * verify_us, rx_done + 1000 * (verify_us + handoff_us), result)


def periodic_rx_two_streams():
    """Every job of periodic_tx_two_streams delivered once and in order, except stream 1 seq 11 (lost):
    one-way latency 500 us, verification 430 us, delivery 450 us after reception."""
    return text(RX_HEADER, [rx_row(r) for r in periodic_tx_rows()[:-1]])


def clock_offset(offset=RX_AHEAD):
    """Two probes on the receiver's clock that bracket the run (rx_done is 8.0e9 .. 8.13e9 ns)."""
    return text(CLOCK_HEADER, [(7_900 * MS, offset, 200_000, "ping"), (8_300 * MS, offset, 250_000, "ping")])


TPUT_HEADER = ("t_ns,host,offered_pps,pdus_done,cpu_busy_jiffies,cpu_total_jiffies,if_tx_bytes,if_tx_packets,"
               "if_rx_bytes,if_rx_packets,sendq_bytes,drops")
_GARBAGE = (1, 1, 100, 7, 1, 7, 1, 0)  # increments outside the steady-state window; must not reach any result
_STEADY = {  # per-second increments: pdus, busy, total, if_tx_bytes, if_tx_packets, if_rx_bytes, if_rx_packets, drops
    ("iris", 100): (100, 25, 100, 340_000, 250, 6_600, 100, 0),
    ("iris", 200): (150, 99, 100, 510_000, 375, 9_900, 150, 50),
    ("baolong", 100): (100, 10, 100, 6_600, 100, 340_000, 250, 0),
    ("baolong", 200): (150, 15, 100, 9_900, 150, 510_000, 375, 0),
}


TPUT_META = ("tx_host=iris", "rx_host=baolong", "profile=mldsa65", "cores=1", "commit=abc1234")


def throughput_rows(host, rate, steady=None, samples=20, offered=None):
    """One host at one rate step: `samples` one-second samples, of which only the 9 intervals between
    samples 5..14 carry the steady increments. iris is the sender: its send queue alternates
    8000 / 6000 bytes at 100 pps and grows by 10,000 bytes/s at 200 pps. `steady`, if given, replaces
    the PDUs done in the steady intervals (cycled: (90, 110) gives 90, 110, 90, ...); `offered`
    relabels the step (the offered_pps column) while the counters behave as at `rate`."""
    counters = [1_000, 5_000, 20_000, 1_000_000, 1_000, 2_000_000, 2_000, 0]
    rows, t = [], 5_000_000_000 if host == "iris" else 77_000_000_000  # each host has its own clock
    for i in range(samples):
        if i:
            step = list(_STEADY[host, rate] if 6 <= i <= 14 else _GARBAGE)
            if steady and 6 <= i <= 14:
                step[0] = steady[(i - 6) % len(steady)]
            counters = [c + d for c, d in zip(counters, step)]
        sendq = 0 if host != "iris" else (10_000 * i if rate == 200 else 6_000 + 2_000 * (i % 2))
        rows.append((t, host, offered or rate, *counters[:7], sendq, counters[7]))
        t += 1_000_000_000
    return rows


def throughput(host, rate, comments=TPUT_META, steady=None, samples=20, offered=None, proc_ns=None):
    """`proc_ns`: a 13th column proc_cpu_ns, the cumulative processor time of the harness process, growing by that many
    nanoseconds in each steady second (samples 6..14) and by 1 ms in every other second."""
    rows = throughput_rows(host, rate, steady, samples, offered)
    if proc_ns is None:
        return text(TPUT_HEADER, rows, comments)
    total, with_proc = 7_000_000, []
    for i, r in enumerate(rows):
        total += (proc_ns if 6 <= i <= 14 else 1_000_000) if i else 0
        with_proc.append((*r, total))
    return text(TPUT_HEADER + ",proc_cpu_ns", with_proc, comments)


def attack():
    """benign: 50 delivered. replay: 20 rejected at freshness, detect 1..20 us. bitflip: 9 rejected at
    auth (detect 5 us), 1 delivered."""
    rows = [("benign", i, 1, "none", 0) for i in range(50)]
    rows += [("replay", i, 0, "freshness", 1000 * (i + 1)) for i in range(20)]
    rows += [("bitflip", i, 0, "auth", 5000) for i in range(9)] + [("bitflip", 9, 1, "none", 0)]
    return text("vector,iter,delivered,reject_stage,detect_ns", rows)


HANDSHAKE_HEADER = "seq,role,result,total_ns,bytes_tx,bytes_rx,keygen_ns,encaps_ns,decaps_ns,sign_ns,verify_ns,kdf_ns,hash_ns,mac_ns"


def handshake(comments=("commit=abc1234", "host=iris", "mainfunction=cyclic", "mf_period_us=1000", "t_min_ms=0")):
    """initiator: 3 ok (total 1, 2, 3 ms; keygen 100, 200, 300 us; no encaps; decaps 50, sign 400,
    verify 100, kdf 1, hash 15, mac 5 us: compute 671, 771, 871 us) and 1 timeout.
    responder: 2 ok (total 1.5, 2.5 ms; no keygen, no decaps; encaps 60, hash 10 us: compute 576 us)."""
    rows = [(0, "initiator", "ok", 1 * MS, 3000, 5000, 100_000, 0, 50_000, 400_000, 100_000, 1_000, 15_000, 5_000),
            (1, "initiator", "ok", 2 * MS, 3000, 5000, 200_000, 0, 50_000, 400_000, 100_000, 1_000, 15_000, 5_000),
            (2, "initiator", "timeout", 9_000 * MS, 3000, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (3, "initiator", "ok", 3 * MS, 3000, 5000, 300_000, 0, 50_000, 400_000, 100_000, 1_000, 15_000, 5_000),
            (0, "responder", "ok", 1_500_000, 5000, 3000, 0, 60_000, 0, 400_000, 100_000, 1_000, 10_000, 5_000),
            (1, "responder", "ok", 2_500_000, 5000, 3000, 0, 60_000, 0, 400_000, 100_000, 1_000, 10_000, 5_000)]
    return text(HANDSHAKE_HEADER, rows, comments)


def make_run(root):
    """A complete synthetic run directory (analyse with warmup=10, block_len=5)."""
    files = {"crypto/crypto_ops.csv": crypto_ops(), "overhead/overhead_paired.csv": overhead_paired(),
             "crypto_attrib/sign_attrib_p8.csv": sign_attrib(),
             "periodic_1s/periodic_tx.csv": periodic_tx_one_stream(),
             "periodic_2s/periodic_tx.csv": periodic_tx_two_streams(), "periodic_2s/periodic_rx.csv": periodic_rx_two_streams(),
             "periodic_2s/clock_offset.csv": clock_offset(),
             **{f"throughput_1core/throughput_{h}_{r}.csv": throughput(h, r) for h in ("iris", "baolong") for r in (100, 200)},
             "attack/attack.csv": attack(),
             "handshake/handshake.csv": handshake(), "equivalence_margin.txt": "0.01\n",
             "clock/clock_offset.csv": "t_ns,offset_ns,rtt_ns,method\n1,2,3,ptp\n", "env_iris.txt": env_file(),
             "cyclictest/cyclictest_fifo_cpu3.txt": cyclictest("fifo"),
             "cyclictest/cyclictest_other_cpu3.txt": cyclictest("other", {12: 900, 55: 90, 300: 10}, size=400)}
    for name, content in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(content)
    return root


def env_file(before="0x0", after="0x0", host="iris"):
    """env_<host>.txt as capture_env.sh writes it: a 'before' and an 'after' block."""
    block = "===== {} 2026-11-23T00:42:59+07:00 =====\nhostname={}\nkernel=6.18.29+rpt-rpi-v8\ngovernor=performance \n" \
            "temp=temp=60.3'C\nthrottled=throttled={}\neth0_speed_mbit=100\n"
    return block.format("before", host, before) + block.format("after", host, after)


CYCLIC_COUNTS = {3: 100, 4: 800, 5: 80, 6: 15, 10: 4, 40: 1}  # 1000 wake-ups: min 3, max 40, mean 4.07, p99 6, p99.9 10


def cyclictest(policy="fifo", counts=CYCLIC_COUNTS, overflows=0, max_line=None, load=None, complete=True, observed=None,
               end=("freq_khz_end=1500000", "temp_end=temp=60.3'C", "throttled_end=throttled=0x0"), size=50):
    """A file in the shape run_cyclictest.sh writes: conditions, a histogram of `size` 1 us buckets,
    cyclictest's summary lines, then the conditions after the run."""
    head = ["tool=cyclictest V 2.60", "host=iris", "kernel=Linux 6.18.29+rpt-rpi-v8 #1 SMP PREEMPT", "cpu=3",
            f"policy={policy}", f"priority={80 if policy == 'fifo' else 0}", "interval_us=1000", "duration_s=1",
            "governor=performance", "freq_khz_start=1500000", "temp_start=temp=60.3'C", "throttled_start=throttled=0x0",
            "cmd=sudo cyclictest --quiet --mlockall --affinity=3 --threads=1 --interval=1000 --histogram=50"]
    lines = [f"# {h}" for h in head + ([f"load={load}"] if load else [])] + ["# /dev/cpu_dma_latency set to 0us", "# Histogram"]
    lines += [f"{i:06d} {counts.get(i, 0):06d}" for i in range(size)]
    if complete:
        total = sum(counts.values())
        lines += [f"# Total: {total:09d}", f"# Min Latencies: {min(counts):05d}",
                  f"# Avg Latencies: {sum(k * v for k, v in counts.items()) // total:05d}",
                  f"# Max Latencies: {max(counts) if max_line is None else max_line:05d}",
                  f"# Histogram Overflows: {overflows:05d}", "# Histogram Overflow at cycle number:",
                  "# Thread 0:" + "".join(f" {c:05d}" for c in range(overflows)), "",
                  "# threads_observed_class_rtprio_cpu=" + (observed or ("TS - 3;FF 80 3" if policy == "fifo" else "TS - 3;TS - 3"))]
        lines += [f"# {e}" for e in end]
    return "\n".join(lines) + "\n"


def paired_launch(launch, sign_diff_ns, mode="ab", pairs=14, launch_line=True):
    """One launch of a set, warmup=10: standalone 1 ms (sign) / 400 us (verify); csm - standalone is
    sign_diff_ns for sign and 0 for verify in every pair after the warm-up; `pairs` pairs per op."""
    rows = []
    for s in range(pairs):
        order = "AB" if s % 2 == 0 else "BA"
        rows.append((s, order, "sign", MS, MS + (9 * MS if s < 10 else sign_diff_ns)))
        rows.append((s, order, "verify", 400_000, 400_000))
    head = harness_head("bench_overhead_paired", mode) + ((f"launch={launch}",) if launch_line else ())
    return text("seq,order,op,standalone_ns,csm_ns", rows, head, PAIRED_TAIL)


# ---- E9 on the raw clocks (E9_SPEC.md, Addendum E): one run generated from true time -----------------------------------
# True time t, in ns, is the time of board A's raw clock counted from the start of the run. Every stamp of the run
# follows from the two clock functions; nothing here uses the code under test.

E9_RAW = {"a": 119_899_302_191_756, "b": 99_940_948_741_547}  # each board's CLOCK_MONOTONIC_RAW at true time 0
E9_MONO = {"a": 3_456_789_013, "b": 1_234_567_891}            # its CLOCK_MONOTONIC minus its raw clock at true time 0
PROBE2_HEADER = "seq,t1_ns,t2_ns,t3_ns,t4_ns,t1r_ns,t2r_ns,t3r_ns,t4r_ns,w1_ns,w2_ns,w3_ns,w4_ns"
MAP_HEADER = "raw1_ns,mono_ns,raw2_ns"


def e9_clocks(rate_b_ppm=0, steer=None):
    """(raw, mono): the two clocks of a board ('a' or 'b') at true time t, whole ns. Board B's raw clock gains
    `rate_b_ppm` on board A's. `steer` maps a board to a function of what the board's raw clock has run since the start
    of the run -> the ns its CLOCK_MONOTONIC has gained on its raw clock by then (the time-synchronisation service at
    work); a board not named there is not steered."""
    steer = steer or {}

    def raw(board, t):
        return E9_RAW[board] + t + (t * rate_b_ppm // 1_000_000 if board == "b" else 0)

    def mono(board, t):
        return raw(board, t) + E9_MONO[board] + (steer[board](raw(board, t) - E9_RAW[board]) if board in steer else 0)

    return raw, mono


def steered(ppm, start_s, seconds):
    """A steering function for e9_clocks: from `start_s` of the board's raw clock on, for `seconds` of it, the board's
    CLOCK_MONOTONIC gains `ppm` ns on the raw clock per 1,000,000 ns of its OWN reading (E9_SPEC.md, E11 k). With the
    gain g after r ns of the raw clock, g = ppm x (r + g) / 1,000,000, so g = r x ppm / (1,000,000 - ppm)."""
    start, length = round(start_s * 1000 * MS), round(seconds * 1000 * MS)
    return lambda r: min(max(r - start, 0), length) * ppm // (1_000_000 - ppm)


def e9_run(seconds=40, rate_b_ppm=0, steer=None, map_step=5 * MS, map_width=0, probe_step=101 * MS, point_width=0,
           forward=50_000, back=50_000, served=18_000, pdus=300, first=12_000 * MS, period=10 * MS, response=3 * MS,
           wire=400_000, receive=600_000, map_times=None, map_noise=0):
    """One run of `seconds` as rows: 'map_a' and 'map_b' (MAP_HEADER; a sample every `map_step`, its two raw reads
    `map_width` ns apart and the monotonic read half way), 'probe' (PROBE2_HEADER; an exchange every `probe_step`,
    `forward` ns to board B, held `served` ns, `back` ns to board A; at each of its four points RAW, MONOTONIC, RAW
    over `point_width` ns, the raw read next to the datagram being the stamp), 'tx' (TX_HEADER) and 'rx' (RX_HEADER):
    `pdus` jobs of stream 0 released every `period` from `first`, sent `response` later, received `wire` after that
    and delivered `receive` later; 'latency_ns' is their true latency, release to delivery.
    map_width(board, k), point_width(i, point), forward(i) and back(i) may be functions. `map_times` gives a board the
    true times of its samples in place of the even ones (a sampler that woke late); map_noise(board, k) is added to the
    monotonic read of sample k (read noise)."""
    raw, mono = e9_clocks(rate_b_ppm, steer)

    def of(v, *args):
        return v(*args) if callable(v) else v

    maps = {}
    for board in "ab":
        times = (map_times or {}).get(board) or [k * map_step for k in range(seconds * 1000 * MS // map_step + 1)]
        maps[board] = [(raw(board, t), mono(board, t + w // 2) + of(map_noise, board, k), raw(board, t + w))
                       for k, t in enumerate(times) for w in [of(map_width, board, k)]]
    probe = []
    for i in range(seconds * 1000 * MS // probe_step):
        w1, w2, w3, w4 = (of(point_width, i, p) for p in (1, 2, 3, 4))
        t = i * probe_step                     # the request leaves board A
        u = t + of(forward, i)                 # ... arrives on board B
        v = u + served                         # the reply leaves board B
        z = v + of(back, i)                    # ... arrives on board A
        p1 = (raw("a", t - w1), mono("a", t - w1 // 2), raw("a", t))    # before a send the SECOND raw read is the stamp
        p2 = (raw("b", u), mono("b", u + w2 // 2), raw("b", u + w2))    # after a receive the FIRST one
        p3 = (raw("b", v - w3), mono("b", v - w3 // 2), raw("b", v))
        p4 = (raw("a", z), mono("a", z + w4 // 2), raw("a", z + w4))
        probe.append((i, p1[1], p2[1], p3[1], p4[1], p1[2], p2[0], p3[2], p4[0],
                      p1[2] - p1[0], p2[2] - p2[0], p3[2] - p3[0], p4[2] - p4[0]))
    tx, rx = [], []
    for j in range(pdus):
        release = first + j * period
        sent, got = release + response, release + response + wire
        tx.append((0, j, mono("a", release), mono("a", release + MS), mono("a", sent - MS // 2), mono("a", sent)))
        rx.append((0, j, mono("b", got), mono("b", got + receive - 20_000), mono("b", got + receive), "ok"))
    return {"map_a": maps["a"], "map_b": maps["b"], "probe": probe, "tx": tx, "rx": rx,
            "latency_ns": response + wire + receive}
