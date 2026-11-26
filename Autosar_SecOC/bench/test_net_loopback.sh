#!/usr/bin/env bash
# bench/test_net_loopback.sh <build_dir> <bench source dir>
# 40 periodic PDUs, then 3 s of sustained load with the per-second sampler, from bench_net_tx to
# bench_net_rx over 127.0.0.1 through the real BSW path; fails when a CSV (periodic_tx, periodic_rx,
# throughput) violates DATA_SCHEMA.md or a PDU is not delivered. Exit 77 (skipped) when the networked
# targets have not been built: they compile the whole BSW and are not part of the default build.
set -euo pipefail
B="$1"; SRC="$2"; D="${B}/net_loopback_test"; PORT=50990
[[ -x "${B}/bench_net_tx" && -x "${B}/bench_net_rx" && -x "${B}/bench_keygen" ]] || { echo "networked targets not built: skipped"; exit 77; }
rm -rf "${D}"; mkdir -p "${D}"
"${B}/bench_keygen" "${D}/tx" > /dev/null
"${B}/bench_keygen" "${D}/rx" > /dev/null
cp "${D}/tx/mldsa_secoc.pub" "${D}/rx/mldsa_peer0.pub"
cp "${D}/rx/mldsa_secoc.pub" "${D}/tx/mldsa_peer0.pub"      # the handshake pins the peer's key on both ends
"${B}/bench_net_rx" --listen "${PORT}" --peer 127.0.0.1 --key-dir "${D}/rx" --cpu 0 --allow-unlocked \
    --out "${D}/periodic_rx.csv" --payload-out "${D}/rx_payload.csv" --handshake-out "${D}/handshake_rx.csv" > "${D}/rx.log" 2>&1 &
RX=$!
for _ in $(seq 100); do grep -q 'listening on port' "${D}/rx.log" 2>/dev/null && break; sleep 0.1; done
"${B}/bench_net_tx" --peer "127.0.0.1:${PORT}" --key-dir "${D}/tx" --cpu 0 --allow-unlocked \
    --period-us 5000 --count 40 --out "${D}/periodic_tx.csv" --handshake-out "${D}/handshake_tx.csv" > "${D}/tx.log" 2>&1
wait "${RX}"
python3 "${SRC}/check_csv.py" "${D}/periodic_tx.csv" "${D}/periodic_rx.csv"
# a transmitter and a receiver built from different commits may not even agree on the PDU layout
[[ "$(grep '^# commit=' "${D}/periodic_tx.csv")" == "$(grep '^# commit=' "${D}/periodic_rx.csv")" ]] \
    || { echo "bench_net_tx and bench_net_rx were built from different commits: rebuild both"; exit 1; }
[[ "$(grep -c ',ok$' "${D}/periodic_rx.csv")" == 40 ]] || { echo "not all 40 PDUs were delivered"; exit 1; }
grep -qx '# tcp_total_retrans=0' "${D}/periodic_tx.csv" || { echo "no clean retransmission count of the connection in the footer"; exit 1; }
# the connection at the first release and at the end, and TCP_NODELAY read back on both ends
grep -qx '# tcp_total_retrans_in_window=0' "${D}/periodic_tx.csv" && grep -q '^# tcp_dsack_dups_at_end=[0-9]' "${D}/periodic_tx.csv" \
    && grep -q '^# tcp_rtt_us_at_first_release=[0-9]' "${D}/periodic_tx.csv" && grep -q '^# tcp_connections_at_end=[1-9]' "${D}/periodic_tx.csv" \
    && [[ "$(grep '^# tcp_connections_at_first_release=' "${D}/periodic_tx.csv" | cut -d= -f2)" == "$(grep '^# tcp_connections_at_end=' "${D}/periodic_tx.csv" | cut -d= -f2)" ]] \
    && grep -qx '# tcp_nodelay=1' "${D}/periodic_tx.csv" && grep -qx '# tcp_nodelay=1' "${D}/periodic_rx.csv" \
    || { echo "the TCP_INFO footer of the transmitter or the tcp_nodelay read-back of an end is missing or wrong"; exit 1; }
grep -q '^# worker_ctx_switches_involuntary=[0-9]' "${D}/periodic_tx.csv" && grep -q '^# worker_ctx_switches_involuntary=[0-9]' "${D}/periodic_rx.csv" \
    || { echo "no context-switch count of the worker thread in the footers"; exit 1; }

# the handshake ran, ended ok on both ends, and both ends name the same session
python3 "${SRC}/check_csv.py" "${D}/handshake_tx.csv" "${D}/handshake_rx.csv"
SID="$(grep '^# session_id=' "${D}/periodic_tx.csv")"
[[ -n "${SID}" && "${SID}" == "$(grep '^# session_id=' "${D}/periodic_rx.csv")" ]] \
    && grep -q '^0,initiator,ok,' "${D}/handshake_tx.csv" && grep -q '^0,responder,ok,' "${D}/handshake_rx.csv" \
    || { echo "handshake: no ok record on both ends, or the two ends name different sessions"; exit 1; }

# a transmitter that pins another key gets no session and releases nothing
"${B}/bench_keygen" "${D}/stranger" > /dev/null
cp "${D}/stranger/mldsa_secoc.pub" "${D}/stranger/mldsa_peer0.pub"
"${B}/bench_net_rx" --listen "$((PORT + 4))" --peer 127.0.0.1 --key-dir "${D}/rx" --cpu 0 --allow-unlocked --idle-exit-ms 500 \
    --out "${D}/periodic_rx_stranger.csv" --handshake-out "${D}/handshake_rx_stranger.csv" > "${D}/rx_stranger.log" 2>&1 &
RX=$!
for _ in $(seq 100); do grep -q 'listening on port' "${D}/rx_stranger.log" 2>/dev/null && break; sleep 0.1; done
if "${B}/bench_net_tx" --peer "127.0.0.1:$((PORT + 4))" --key-dir "${D}/stranger" --cpu 0 --allow-unlocked --hs-timeout-ms 6000 \
    --period-us 5000 --count 10 --out "${D}/periodic_tx_stranger.csv" --handshake-out "${D}/handshake_tx_stranger.csv" > "${D}/tx_stranger.log" 2>&1; then
    echo "a transmitter with an unknown identity was given a session"; exit 1
fi
kill -TERM "${RX}" 2> /dev/null || true; wait "${RX}" || true
! grep -q ',ok$' "${D}/periodic_rx_stranger.csv" 2> /dev/null || { echo "a PDU was delivered without a session"; exit 1; }

# without the handshake component both ends still talk session-less (development mode)
"${B}/bench_net_rx" --listen "$((PORT + 5))" --peer 127.0.0.1 --key-dir "${D}/rx" --cpu 0 --allow-unlocked --no-handshake \
    --out "${D}/periodic_rx_nohs.csv" > "${D}/rx_nohs.log" 2>&1 &
RX=$!
for _ in $(seq 100); do grep -q 'listening on port' "${D}/rx_nohs.log" 2>/dev/null && break; sleep 0.1; done
"${B}/bench_net_tx" --peer "127.0.0.1:$((PORT + 5))" --key-dir "${D}/tx" --cpu 0 --allow-unlocked --no-handshake \
    --period-us 5000 --count 20 --out "${D}/periodic_tx_nohs.csv" > "${D}/tx_nohs.log" 2>&1
wait "${RX}"
[[ "$(grep -c ',ok$' "${D}/periodic_rx_nohs.csv")" == 20 ]] && grep -qx '# handshake=off' "${D}/periodic_tx_nohs.csv" \
    || { echo "session-less mode: not all 20 PDUs delivered"; exit 1; }

# the MAC stream: HMAC-SHA-256 under the session's key, so through the handshake
"${B}/bench_net_rx" --listen "$((PORT + 6))" --peer 127.0.0.1 --key-dir "${D}/rx" --cpu 0 --allow-unlocked --profile mac \
    --out "${D}/periodic_rx_mac.csv" > "${D}/rx_mac.log" 2>&1 &
RX=$!
for _ in $(seq 100); do grep -q 'listening on port' "${D}/rx_mac.log" 2>/dev/null && break; sleep 0.1; done
"${B}/bench_net_tx" --peer "127.0.0.1:$((PORT + 6))" --key-dir "${D}/tx" --cpu 0 --allow-unlocked --profile mac \
    --period-us 5000 --count 40 --out "${D}/periodic_tx_mac.csv" > "${D}/tx_mac.log" 2>&1
wait "${RX}"
python3 "${SRC}/check_csv.py" "${D}/periodic_tx_mac.csv" "${D}/periodic_rx_mac.csv"
[[ "$(grep -c '^0,.*,ok$' "${D}/periodic_rx_mac.csv")" == 40 ]] && grep -qx '# profile=mac' "${D}/periodic_tx_mac.csv" \
    && grep -qx '# stream_pdu_ids=13' "${D}/periodic_tx_mac.csv" && grep -qx '# stream_header_ids=0x20' "${D}/periodic_tx_mac.csv" \
    || { echo "MAC stream: not all 40 PDUs delivered, or the header does not name the MAC stream"; exit 1; }

# both variants in one process: stream 0 the signature stream, stream 1 the MAC stream, on both ends
"${B}/bench_net_rx" --listen "$((PORT + 7))" --peer 127.0.0.1 --key-dir "${D}/rx" --cpu 0 --allow-unlocked --profile both \
    --out "${D}/periodic_rx_both.csv" > "${D}/rx_both.log" 2>&1 &
RX=$!
for _ in $(seq 100); do grep -q 'listening on port' "${D}/rx_both.log" 2>/dev/null && break; sleep 0.1; done
"${B}/bench_net_tx" --peer "127.0.0.1:$((PORT + 7))" --key-dir "${D}/tx" --cpu 0 --allow-unlocked --profile both \
    --streams 2 --period-us 10000 --count 30 --out "${D}/periodic_tx_both.csv" > "${D}/tx_both.log" 2>&1
wait "${RX}"
python3 "${SRC}/check_csv.py" "${D}/periodic_tx_both.csv" "${D}/periodic_rx_both.csv"
[[ "$(grep -c '^0,.*,ok$' "${D}/periodic_rx_both.csv")" == 30 && "$(grep -c '^1,.*,ok$' "${D}/periodic_rx_both.csv")" == 30 ]] \
    && [[ "$(grep -c '^0,' "${D}/periodic_tx_both.csv")" == 30 && "$(grep -c '^1,' "${D}/periodic_tx_both.csv")" == 30 ]] \
    && for f in periodic_tx_both periodic_rx_both; do
           grep -qx '# profile=both' "${D}/${f}.csv" && grep -qx '# stream_pdu_ids=2,13' "${D}/${f}.csv" \
               && grep -qx '# stream_header_ids=0x10,0x20' "${D}/${f}.csv" && grep -qx '# stream_profiles=mldsa65,mac' "${D}/${f}.csv" \
               || { echo "both variants: the header of ${f}.csv does not name the two streams"; exit 1; }
       done \
    || { echo "both variants: not 30 PDUs sent and delivered for each of the streams 0 and 1"; exit 1; }
if "${B}/bench_net_tx" --peer "127.0.0.1:$((PORT + 7))" --key-dir "${D}/tx" --cpu 0 --allow-unlocked --profile both \
    --period-us 10000 --count 5 --out "${D}/periodic_tx_both1.csv" > "${D}/tx_both1.log" 2>&1; then
    echo "--profile both was accepted with one stream"; exit 1
fi

# a profile name the receiver does not know is a usage error: the profile decides the stream index of a MAC PDU
if "${B}/bench_net_rx" --listen "$((PORT + 8))" --peer 127.0.0.1 --key-dir "${D}/rx" --cpu 0 --allow-unlocked --profile bth \
    --out "${D}/periodic_rx_unknown.csv" > "${D}/rx_unknown.log" 2>&1; then
    echo "the receiver accepted an unknown profile name"; exit 1
fi

# two streams on the one connection: every PDU of both is delivered, under its own stream label
"${B}/bench_net_rx" --listen "$((PORT + 3))" --peer 127.0.0.1 --key-dir "${D}/rx" --cpu 0 --allow-unlocked \
    --out "${D}/periodic_rx_k2.csv" > "${D}/rx_k2.log" 2>&1 &
RX=$!
for _ in $(seq 100); do grep -q 'listening on port' "${D}/rx_k2.log" 2>/dev/null && break; sleep 0.1; done
"${B}/bench_net_tx" --peer "127.0.0.1:$((PORT + 3))" --key-dir "${D}/tx" --cpu 0 --allow-unlocked \
    --streams 2 --period-us 10000 --count 30 --out "${D}/periodic_tx_k2.csv" > "${D}/tx_k2.log" 2>&1
wait "${RX}"
python3 "${SRC}/check_csv.py" "${D}/periodic_tx_k2.csv" "${D}/periodic_rx_k2.csv"
grep -qx '# streams=2' "${D}/periodic_tx_k2.csv" && [[ "$(grep -c '^0,.*,ok$' "${D}/periodic_rx_k2.csv")" == 30 && "$(grep -c '^1,.*,ok$' "${D}/periodic_rx_k2.csv")" == 30 ]] \
    && grep -qx '# stream_pdu_ids=2,6' "${D}/periodic_tx_k2.csv" && grep -qx '# stream_header_ids=0x10,0x11' "${D}/periodic_tx_k2.csv" \
    || { echo "two streams: not 30 delivered PDUs for each of the streams 0 and 1, or no ID lines in the header"; exit 1; }

# a run ended from outside (the driver's temperature limit): the files are complete for what was released
"${B}/bench_net_rx" --listen "$((PORT + 2))" --peer 127.0.0.1 --key-dir "${D}/rx" --cpu 0 --allow-unlocked \
    --out "${D}/periodic_rx_stopped.csv" > "${D}/rx_stopped.log" 2>&1 &
RX=$!
for _ in $(seq 100); do grep -q 'listening on port' "${D}/rx_stopped.log" 2>/dev/null && break; sleep 0.1; done
"${B}/bench_net_tx" --peer "127.0.0.1:$((PORT + 2))" --key-dir "${D}/tx" --cpu 0 --allow-unlocked \
    --period-us 5000 --count 4000 --out "${D}/periodic_tx_stopped.csv" > "${D}/tx_stopped.log" 2>&1 &
TX=$!
# one second into the run, not one second after the start of a process that may still be initialising on a busy board
for _ in $(seq 100); do ss -tnH state established "( dport = :$((PORT + 2)) )" 2>/dev/null | grep -q . && break; sleep 0.1; done
sleep 1; kill -TERM "${TX}"; wait "${TX}" || { echo "the transmitter did not end cleanly on SIGTERM"; exit 1; }
wait "${RX}"
python3 "${SRC}/check_csv.py" "${D}/periodic_tx_stopped.csv" "${D}/periodic_rx_stopped.csv"
SENT="$(grep -c '^0,' "${D}/periodic_tx_stopped.csv")"
grep -qx '# stopped_early=1' "${D}/periodic_tx_stopped.csv" && [[ "${SENT}" -gt 0 && "${SENT}" -lt 4000 ]] \
    && [[ "$(grep -c ',ok$' "${D}/periodic_rx_stopped.csv")" == "${SENT}" ]] \
    || { echo "stopped run: ${SENT} rows sent, not all delivered, or not marked stopped_early"; exit 1; }

# sustained load: the same two binaries with the sampler on both ends
H="$(hostname)"
"${B}/bench_net_rx" --listen "$((PORT + 1))" --peer 127.0.0.1 --key-dir "${D}/rx" --cpu 0 --allow-unlocked --out "${D}/load_rx.csv" \
    --samples "${D}/throughput_rx.csv" --tx-host "${H}" --rate-pps 50 --duration 3 --iface lo > "${D}/rx_load.log" 2>&1 &
RX=$!
for _ in $(seq 100); do grep -q 'listening on port' "${D}/rx_load.log" 2>/dev/null && break; sleep 0.1; done
"${B}/bench_net_tx" --peer "127.0.0.1:$((PORT + 1))" --key-dir "${D}/tx" --cpu 0 --allow-unlocked \
    --rate-pps 50 --duration 3 --out "${D}/load_tx.csv" --samples "${D}/throughput_tx.csv" --rx-host "${H}" --iface lo > "${D}/tx_load.log" 2>&1
wait "${RX}"
python3 "${SRC}/check_csv.py" "${D}/throughput_tx.csv" "${D}/throughput_rx.csv"
# the keys the analysis groups by are in all four kinds of file
for f in periodic_tx periodic_rx throughput_tx throughput_rx; do
    grep -qx '# partitions=1' "${D}/${f}.csv" && grep -qx '# rep=1' "${D}/${f}.csv" || { echo "${f}.csv: no partitions / rep key"; exit 1; }
done
