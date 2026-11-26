# Spec: networked PQC-SecOC and new measurement campaign of the revision

Status: **APPROVED** by the author on 2026-11-22. Decisions on the open questions are recorded at the end.

## Capability map

| Module id | Responsibility | Depends on |
|---|---|---|
| `tree` | One source tree with a build-time role switch, built from the same commit on both Pis, commit hash stamped into every run | none |
| `rx-path` | Networked receive path over eth0: PDU boundary recovery on TCP, Tx/Rx data-to-authenticator symmetry, verified delivery to the application | `tree` |
| `handshake-auth` | ML-KEM handshake signed with the ML-DSA identity keys, key confirmation, session-key erasure on rekey | `rx-path` |
| `bench` | Harnesses: single-node crypto re-run, interleaved overhead A/B, sustained open-loop throughput, periodic deadline-miss, on-the-wire attack injection, handshake timing | `rx-path`, `handshake-auth` |
| `analysis` | Scripts that turn raw CSV into every table and figure: percentiles with bootstrap CIs, TOST / Hodges-Lehmann / Cliff's delta, deadline-miss ratios, throughput and utilization | `bench` (data format) |
| `artifact` | Dataset v2 and code artifact v2 with manifests and environment capture; Zenodo new version prepared, not published | `bench`, `analysis` |
| `paper` | Revised manuscript and the accompanying letter | `analysis`, research report |

Build order: `tree` → `rx-path` → `handshake-auth` → `bench` → `artifact` → `paper`; `analysis` starts in parallel against the existing CSVs.

## Objective

Answer the points of the revision with measurements, not estimates: a receive path that works between two endpoints, an authenticated key exchange, real throughput and deadline-miss data, an equivalence test, and an artifact that regenerates every number.

## Findings that shape the work (verified 2026-11-22)

1. Four divergent code trees, none equal to GitHub: Mac `main` (basis of Zenodo code v1.0), iris repo (Rx patches), baolong repo (Tx patches), and `iris:~/Desktop/THESIS/Autosar_SecOC` (non-git; produced the published dataset; superset of the baolong tree plus the harnesses). The Pis' base commit `c86965c` is not on GitHub.
2. Zenodo code v1.0 does not contain `tx_perf_10k.c`, `phase_compare.c`, `attack_bench.c` or `scripts/`, so it cannot regenerate the published dataset.
3. The May Tx→Rx runs went over **Wi-Fi** (wlan0, 192.168.1.x). eth0 is cabled (1 Gbit link up) but has no IPv4 address on either Pi.
4. The receive path has **two** defects, not one: TCP framing (1 of 88 PDUs reassembled) and a Tx/Rx data-to-authenticator mismatch (the one reassembled PDU failed verification). The manuscript discloses only the first.
5. The published sign/verify medians reproduce on iris today within 4% (sign 1,463 vs 1,522 µs, verify 426 vs 432 µs; kernel 6.18.29 vs 6.12.47 then). The harness signs a 256-byte message (`phase_compare`) or a 20-byte payload (`tx_perf_10k`); the manuscript says 8 bytes.
6. The Pis differ: iris Rev 1.2, 1.5 GHz, 2 GB, Debian 13, gcc 14.2, kernel 6.18; baolong Rev 1.5, 1.8 GHz, 4 GB, Debian 12, gcc 12.2, kernel 6.12.

## Assumptions

1. All new work happens in new directories (`~/pqc-secoc-rev1` on each Pi and a directory of its own on the Mac, its own local git repository). The four as-found trees stay untouched; snapshots of them are kept with SHA-256 sums.
2. Base for the unified tree is the dataset tree (`iris:~/Desktop/THESIS/Autosar_SecOC`), with the Rx-side changes from the iris repo and the release-audit fixes from the Mac ported in.
3. Experiments run over eth0 with non-persistent static addresses (10.10.10.1/24, 10.10.10.2/24). Link speed is forced to 100 Mbit/s full duplex for the headline runs, to match the 100 Mbit/s the manuscript claims, with one 1 Gbit/s run for comparison.
4. Every table in the manuscript is re-measured in one campaign on one commit; the May dataset stays as v1 and the new one becomes v2.
5. One-way latency across two hosts is not reported unless clocks are synchronized with a stated method (PTP or chrony over eth0, with its measured offset); otherwise round-trip and per-host timings.
6. PDU boundary recovery uses the AUTOSAR SoAd PDU header (32-bit ID + 32-bit length), which is the standard's own answer for TCP streams, instead of an ad-hoc length prefix.
7. Handshake authentication follows the SIGMA sign-and-MAC pattern on an ephemeral KEM; the exact protocol is fixed in "Handshake `PQC-SecOC-HS-v1`" below (that section supersedes any earlier wording here or in the task plan). No formal proof is claimed.

## Comparison with the AUTOSAR R25-11 specifications (author request, 2026-11-22)

Every change to a BSW module is checked against the governing AUTOSAR Classic Platform specification before it is written, and the result is recorded with requirement IDs. The R25-11 documents used: SWS SecOC, PRS SecOC Protocol, SWS Csm, SWS CryIf, SWS Crypto Driver, SWS KeyM, SWS SoAd, SWS PduR, RS Crypto Stack, Security Overview, Release Overview.

Points that must be settled from the specification text, not from memory:
- SecOC: data to authenticator (`DataId | Authentic I-PDU | complete freshness value`), freshness truncation and reconstruction, reception flow (verification attempts, verification status, drop before the upper layer), TP reception API, what the specification says about asymmetric authenticators.
- SoAd: the PDU header option for TCP streams (field widths, byte order, reception via TP-API).
- Csm / CryIf / Crypto Driver: job model, signature services, the existing key-exchange and key-derivation services, key elements; which calls of the prototype are standard and which are project-specific.
- KeyM: certificate handling for binding public keys to ECUs.

Deliverable: `AUTOSAR_CONFORMANCE.md`, a matrix of module × interface × requirement ID × status (follows the specification / simplified / project-specific extension / not implemented). This matrix also feeds the conformance table of the paper. A deviation is written down, never left implicit.

## Handshake `PQC-SecOC-HS-v1` (module `handshake-auth`, tasks T5/T5b/T6)

Revised 2026-11-23 after an independent review of the first version (four review perspectives, every finding checked by a second reader: 31 findings confirmed, none refuted). The review's change list carries the evidence with file, line and clause IDs; the first version is kept on file. Decisions on the review's open points are at the end of this section. Where this section and the change list differ, this section wins (it carries the decisions).

A SIGMA-style sign-and-MAC handshake (Krawczyk 2003: signatures authenticate the fresh contributions, a MAC under a key derived from the exchange binds the sender's identity; identities in clear; with the acknowledgment message of its Sec. 5.2), with the Diffie-Hellman shares replaced by an ephemeral ML-KEM-768 key and ciphertext. It is the authors' own mutual extension of the unilateral example in SP 800-227 Fig. 9 and follows the pattern of IKEv2 and TLS 1.3 (ephemeral key establishment authenticated by signatures over the transcript; their ML-KEM and ML-DSA instantiations are still Internet-Drafts). No formal proof is claimed (the SIGMA proof is for Diffie-Hellman). A = initiator, B = responder. Each side holds its ML-DSA-65 identity key pair and the peer's public key pinned from the key directory. `ID_X = SHA-256(pk_X)` (32 bytes) is only a lookup handle for a pinned key; it is computed inside Csm at `Csm_Init`, when the own key and each peer slot are loaded (a peer slot without a key file has no ID). Two-node and handshake runs initialize Csm with `CSM_MLDSA_BOOTSTRAP_FILE_STRICT`: start-up fails if the own key pair is missing, no key is generated silently.

Claimed: mutual authentication of the two pinned identities; key confirmation in both directions; no identity misbinding (unknown key-share); forward secrecy of the session keys against later compromise of an identity key, conditional on the wipe rule; separation of handshake signatures from per-PDU signatures and of one session's PDUs from another's. Not claimed: identity protection, resistance of the responder to CPU exhaustion, a formal proof, NIST category 3 for the MAC variant (128-bit tags). Key confirmation is a MAC over the transcript; do not describe it as "the layout of SP 800-227 Sec. 4.4.1".

**Transport.** The four messages are TP routes on the existing socket connection, each with its own named PDU-header-ID constant (allocation table: the ID allocation header). SoAd dispatches them by header ID to the handshake component as a SoAd generic upper layer (SoAd SWS 5.2, CDD-style `<Up>_SoAdTpStartOfReception` / `CopyRxData` / `RxIndication`), not through PduR or SecOC; conformance status "project-specific CDD on a standard SoAd upper-layer interface". A header length different from the fixed size for that ID is rejected at StartOfReception. The handshake routes sit in their own routing group, enabled from init and never disabled by BswM. B is the TCP listener, A connects; in the responder role SoAd keeps the accepted (connected) socket as the socket connection's Tx socket (M2, M4), and the handshake Tx IDs have their own TP Tx session slots outside the `SECOC_NUM_OF_TX_PDU_PROCESSING` bound.
Admission: the receiver's socket connection uses the message acceptance filter with the configured peer address ([SWS_SoAd_00524]); a connection from any other source is refused at accept ([SWS_SoAd_00099]). This is an availability measure, not authentication. While a stream is active a further connection is refused, also from the configured address (the "not online" precondition of [SWS_SoAd_00636]); for that to be workable TcpIp reports a closed or failed connection to SoAd (a PDU in progress is terminated with `TpRxIndication(E_NOT_OK)`, the stream becomes inactive, the transmitter's socket connection goes offline and reconnects), and TCP keep-alive is enabled on the connection with short timers (the SoAd keep-alive parameters) so that a peer that vanished without FIN or RST is detected within seconds instead of blocking the port. A header length above the receive buffer closes the connection (project decision: the SWS gives no plausibility limit and no resynchronization rule for TCP).
The old UDP control channel (7-byte ad-hoc header, 1184-byte payload cap) is retired, not extended: no socket is bound for it and no receive path parses the old control frame.

**Messages** (fixed-length fields, no length prefixes inside; `ver = 0x01`; a handshake PDU whose length is not exactly its table size is discarded before any field is read):

| | Fields | Bytes |
|---|---|---|
| M1 A→B | `ver ‖ ID_A ‖ ek` | 1 + 32 + 1184 = 1217 |
| M2 B→A | `ver ‖ ID_B ‖ ct ‖ sig_B ‖ mac_B` | 1 + 32 + 1088 + 3309 + 32 = 4462 |
| M3 A→B | `ver ‖ sig_A ‖ mac_A` | 1 + 3309 + 32 = 3342 |
| M4 B→A | `ver ‖ mac_ack` | 1 + 32 = 33 |

`ek` and `ct` are the fresh contributions of the two sides (the role `g^x`, `g^y` play in SIGMA; SP 800-227 Sec. 4.4.1 takes the ephemeral key and the ciphertext as the ephemeral data); there are no separate nonces. A fresh `ek` is generated for every attempt and never reused (SP 800-227 RS6). M4 gives the initiator peer awareness (SIGMA Sec. 5.2); the exchange is "three messages and an acknowledgment".

**Computation** (`L = "PQC-SecOC-HS-v1"`, 15 ASCII bytes without terminator in all its uses; transcript hash `H` = SHA-384, because FIPS 204 Sec. 5.4 asks for a digest of at least 2λ = 384 bits when an application-level digest is signed with ML-DSA-65; HKDF with HMAC-SHA-256; MAC = HMAC-SHA-256 with full 32-byte tags and constant-time comparison; M1 to M4 in every hash are exactly the table bytes, without the 8-byte SoAd PDU header; labels are ASCII without terminator):
- `th2 = H(L ‖ M1 ‖ ver ‖ ID_B ‖ ct)`
- `sig_B = ML-DSA-65.Sign(sk_B, msg = 'R' ‖ th2, ctx = L)` (49-byte message; hedged signing, the liboqs default)
- `PRK = HKDF-Extract(salt = th2, IKM = ss)`; every key `= HKDF-Expand(PRK, L ‖ label ‖ ID_A ‖ ID_B, 32)` with labels `"kc-r"`, `"kc-i"`, `"auth-i2r"`, `"auth-r2i"`. The label `"enc"` is reserved and **not derived** (no consumer).
- `mac_B = HMAC(K_kc_r, H(L ‖ M1 ‖ M2 without mac_B))` (covers `ID_B` and `sig_B`: sender identity inside the MAC data)
- `th3 = H(L ‖ M1 ‖ M2)`; `sig_A = Sign(sk_A, msg = 'I' ‖ th3, ctx = L)`; `mac_A = HMAC(K_kc_i, H(L ‖ M1 ‖ M2 ‖ ver ‖ sig_A))`
- `sess = H(L ‖ M1 ‖ M2 ‖ M3)` (48 bytes, the session transcript hash); `mac_ack = HMAC(K_kc_r, sess)` (M4; same key as `mac_B`: the two MAC inputs are hashes of preimages of different fixed lengths). `sid` = first 4 bytes of `sess`, used only as a label in logs and as a test oracle.

**Signature contexts (domain separation and session binding).** Handshake signatures use the FIPS 204 context string `L` (`OQS_SIG_sign_with_ctx_str` / `verify_with_ctx_str`; checked on 2026-11-23 on both boards against the pinned 0.15.0 build: the same 64-byte context verifies, a context differing in one bit, the empty context, plain verification and `L` are all rejected, a plain signature verifies only with the empty context, signature length unchanged at 3,309 bytes). Per-PDU SecOC signatures use `ctx_pdu = "PQC-SecOC-PDU-v1" ‖ sess` (16 + 48 = 64 bytes), held in the per-peer session object of the crypto layer and installed together with the keys (the long-term identity key is never rewritten or invalidated at installation: it is shared by all peers and by the handshake sign job); without a handshake (handshake compiled out, single-node harnesses) `sess` is 48 zero bytes. A handshake signature therefore never verifies as a PDU signature or the reverse, the role byte stops reflection between roles, and **a PDU signed in one session never verifies in another**, without relying on a short identifier.

**State machine (acceptance-critical).**
- Roles, trigger. Roles are fixed by configuration: only A sends M1 and M3, only B sends M2 and M4; a message for the other role is dropped. A starts a handshake (i) each time the TCP connection to B becomes established (SoAd socket connection ONLINE) and (ii) on an explicit "initiate handshake now" call (tests, `bench_handshake`). No time-based or counter-based rekey in the evaluated configuration (`SOAD_PQC_REKEY_INTERVAL_CYCLES = 0`; stated limit).
- Session state (`K_auth_*`, `ctx_pdu`, counters, flag `established`) is per pinned peer identity, not per TCP connection. Loss or re-establishment of the connection changes none of it; only a completed handshake replaces it. `established` is set only at key installation.
- The only code that installs a `K_auth` key element, a PDU signature context or `established` is acceptance of M2 on A and of M3 on B. No other message, on any socket, changes handshake, key or session state.
- Discard rule. A handshake PDU with a wrong length, `ver`, ID or signature, or one that matches no handshake state (M2 with no outstanding M1, M3 with nothing pending, M4 with no outstanding M3), is discarded and changes no state. A MAC failure after a valid signature wipes that handshake's state. An M4 with a wrong `mac_ack` is discarded; A waits out `T_A`.
- B, on M1: checks length and `ver`, looks up `ID_A` among pinned peers (unknown → drop), encapsulates (an encapsulation error is a failure: nothing is signed or sent), signs, sends M2 and keeps the derived keys **pending**. It writes or invalidates no key referenced by a SecOC job, no session state, no freshness. Pending state is bound to the TCP connection the M1 arrived on. One pending handshake per peer: a second M1 while one is pending is dropped, not substituted; an M1 earlier than `T_min` after the last accepted M1 of that peer is dropped. Pending state is wiped after `T_pend` or when the connection is replaced.
- A, on M2: checks `ver` and `ID_B` against the pinned peer, verifies `sig_B`, decapsulates, derives, checks `mac_B`. Cut-over: A stops authenticating new Secured I-PDUs, lets every PDU already handed to SoAd go out, hands M3 to TcpIp, only then installs and resumes. The session boundary on the A→B stream is the last byte of M3, at the first install as at a rekey. A installs without knowing that B accepted M3.
- B, on M3 (handled in a main function, never inside the SoAd indication): from the moment M3 is completely received, B parses nothing further from that connection until the handshake component has accepted or rejected it (stream gate: PDUs that follow M3 in the byte stream belong to the new session and must not reach SecOC under the old one). B verifies `sig_A` with the pinned key selected by `ID_A`, checks `mac_A`, waits until every Secured I-PDU received before M3 has been verified or dropped, **only then** installs, sets `established`, sends M4 and reopens the stream.
- A, on M4: checks `mac_ack`; the handshake is complete. No valid M2 within `T_A` of M1, or no valid M4 within `T_A` of M3: A cleanses the attempt and starts a new handshake with a fresh `ek` (the keys A installed stay in use meanwhile).
- Installation is one uninterrupted step in main-function context: both `K_auth` elements written (`Csm_KeyElementSet`), both keys set valid (`Csm_KeySetValid`), the PDU signature context written to the peer's session object, the session counters reset (`FVM_SessionInstall`), with no SecOC or Csm job started in between (Crypto Driver SWS 7.2.4 note: a key is changed only when no primitive works with it). MAC jobs still queued at the switch are discarded. If a call in the step fails, the session is torn down (`established` cleared), not left half-switched.
- Guarantee. A replayed or forged M1 or M3 leaves B's established session unchanged; a replayed or forged M2 or M4 leaves A's unchanged. If the genuine M3 is dropped or altered, A has switched and B has not: B rejects A's PDUs until the handshake that the missing M4 triggers has completed (stated limit; cost up to `T_A` plus one handshake).
- Timers: `T_pend` = 2 s, `T_min` = 1 s (`SOAD_PQC_HS_MIN_INTERVAL_MS`; `bench_handshake` may override it and records the value), `T_A` = 3 s; named configuration constants with `T_A > max(T_pend, T_min)` and `T_pend` above the measured worst-case honest M1→M3 time; the values in use go into the run's environment capture.
- Direction. Secured I-PDUs flow A→B only in the evaluated configuration. `K_auth_r2i` is installed and bound to A's verify job (reflection test); no B→A stream and no B→A cut-over is defined.
- Wipe, each with `OPENSSL_cleanse`: `dk` after decapsulation, or on failure or timeout; `ss` immediately after HKDF-Extract; `PRK` before the KDF call returns; `K_kc_i` after `mac_A` is generated or checked, or on failure or timeout; `K_kc_r` after `mac_ack` is generated or checked, or on failure or `T_A`; pending `K_auth_*` in the handshake state after installation, or on failure or timeout; the old active `K_auth_*` at installation of the new keys, in every table that holds them; the key locals of `Csm_KeyElementSet` and `Csm_KeySetValid` before return (or these functions write in place). `K_kc_*` are wiped wherever they are held (handshake state and the confirmation-key slot). `dk`, `ss` and `PRK` are cleansed by the crypto layer; the handshake component cleanses only its own buffers. Code rule, checked by review and not by a test: every named local buffer that held one of these objects is cleansed before return, in functions this revision writes or changes. Every OpenSSL return value in the HKDF and HMAC helpers is checked.
- Known limit, stated not solved: B encapsulates and signs on an unauthenticated M1 (CPU exhaustion). A host that can deliver an M1 carrying the public `ID_A` can hold B's pending slot and minimum interval and so delay establishment or rekey; a junk M3 costs B one signature verification while a handshake is pending. An established session is unaffected.

**Session binding and freshness (T5b).**
- Binding. A PDU from an earlier session fails authentication in a later one, without non-volatile storage: in the MAC variant because `K_auth_*` are per session, in the signature variant because `ctx_pdu` carries `sess`. The handshake takes the place of the trip-counter synchronization of SWS SecOC Annex A (application hints, informative).
- Freshness value. A 32-bit message counter per session-bound PDU, transmitted in full (`SecOCFreshnessValueLength = SecOCFreshnessValueTruncLength = 32`; both parameters allow 0..64, [ECUC_SecOC_00015], [ECUC_SecOC_00094]), big-endian, handled as bytes or shifts, never by `memcpy` of an integer.
- Counter. At key installation both sides store 0 meaning "last used / last accepted"; the first PDU of a session carries 1; the receiver accepts only a counter strictly greater than the last accepted one; there is no "uninitialized accepts anything" state. At 2³²−1 the sender stops authenticating on that session until a new handshake (about 497 days at a 10 ms period).
- No session. In a build with the handshake enabled, while `established` is clear for a peer the Rx freshness callout returns E_NOT_OK for that peer's PDUs in both variants ([SWS_SecOC_00256]: drop), and A releases no Secured I-PDU: transmission is held above SecOC (application / routing group started only once `established`), not through a recoverable freshness error ([SWS_SecOC_00229] would abandon the PDU after the build attempts).
- Scope. Session-bound: the Ethernet signature PDUs and the MAC-variant PDUs, Tx and Rx (IDs in the allocation header); reset at key installation. All other PDU configurations are unchanged.
- FVM. New `FVM_SessionInstall(id)` sets the counter to 0 inside the key-installation step. Session PDUs use the full-transmission comparison; the truncated-reconstruction and roll-over branch is not used for them.
- Conformance rows to add: "the freshness counter restarts per session; uniqueness across sessions comes from the per-session key or signature context (SWS 7.1.1.3 prose)" and "no Annex A reconstruction for these PDUs (the counter is sent in full)".

**Reaction to a verification failure.** Drop the PDU ([SWS_SecOC_00241]), call `SecOC_VerificationStatusCallout` ([SWS_SecOC_00048]), count it. A SecOC verification failure disables no SoAd routing group: the fail-counter term is removed from BswM's DIAG_ONLY condition (the old latch stays available only behind a default-off option); the CAN/Ethernet fault path is untouched. The SecOC-to-BswM mode request is a project-specific extension with no routing effect: one conformance row. SecOC accepts a PDU only when the Csm call returns E_OK together with `CRYPTO_E_VER_OK`; every other combination is a verification failure. Negative tests run on the real binary with BswM active, and a rejection is counted from the SecOC verification result, never from a missing delivery.

**Csm mapping (feeds the conformance table).**
- Standard API, standard meaning: `Csm_MacGenerate` / `Csm_MacVerify` (HMAC-SHA-256 behind them from T6 on), `Csm_KeyElementSet` (key element 1 = `CRYPTO_KE_MAC_KEY`, [SWS_Csm_01022]) + `Csm_KeySetValid` to install `K_auth_*` (the install pattern KeyM itself uses, [SWS_KeyM_00016], [SWS_KeyM_00018]).
- Standard API, standard service semantics, vendor algorithm and parameters: `Csm_SignatureGenerate` / `Csm_SignatureVerify`. ML-DSA-65 is not in `Crypto_AlgorithmFamilyType`, so the per-PDU and the handshake jobs are vendor custom family/mode jobs ([SWS_Csm_00942], [SWS_Crypto_00239], [SWS_Crypto_00240]; custom IDs 128..254). The signature APIs have no context parameter ([SWS_Csm_00992], [SWS_Csm_00996]): the FIPS 204 context is job data, the constant `L` for the handshake jobs and, for the PDU jobs, a vendor key element (ID ≥ 1000, [SWS_Csm_00952], a numbering recommendation) of the per-peer session key object (the same object that holds the handshake's vendor elements; never the identity key), written at session installation with `Csm_KeyElementSet`; the PDU sign and verify jobs for a peer read the context from that peer's session object. The key is selected by job id, not by `CsmJobKeyRef` (simplification). Jobs (job id, key, context): PDU sign (`CSM_JOBID`, local sk, `ctx_pdu`); PDU verify peer p (0x2000 + p, pk of p, `ctx_pdu`); handshake sign (new id, local sk, `L`); handshake verify peer p (second base + p, pk of p, `L`). The context travels through `CryIf_SignatureGenerate/Verify` to `PQC_MLDSA_Sign/Verify`; the handshake code never calls liboqs directly.
- Standard vendor hook, project-defined meaning: `Csm_CustomService` ([SWS_Csm_91107]) for ML-KEM key generation, encapsulation, decapsulation and the handshake key derivation. The KDF sits behind the hook although a standard derivation service exists ([SWS_Csm_91030], HKDF family), because [SWS_Csm_01022] has no key element for the HKDF `info` and the standard service returns one key per call; its conformance row reads "project-specific although a standard service exists". `Csm_KeyExchangeCalcPubVal/CalcSecret` are not used: they are Diffie-Hellman shaped and cannot return a ciphertext. `dk` and `ss` are held in vendor key elements of a per-peer handshake key that no SecOC job references and that has no read path; `PRK` exists only inside the KDF call; `Csm_KeyExchangeGetSharedSecret` is removed. The derived `K_kc_*` and `K_auth_*` are returned to the handshake component and held pending there; `K_auth_*` are installed with `Csm_KeyElementSet` + `Csm_KeySetValid` after the peer is confirmed; the component's copies are cleansed. The paper claims confinement to the crypto layer for `dk`, `ss` and `PRK` only.
- `mac_B`, `mac_A`, `mac_ack`: through `Csm_MacGenerate` / `Csm_MacVerify` on a per-peer confirmation-key slot that no SecOC job references (reuses the T6 HMAC; the slot is in the wipe list and the erasure scan).
- Transcript hashes: computed in the handshake component over public data, project-specific.
- The handshake state machine itself: a project-specific CDD on the SoAd generic upper-layer interface. In a production stack this function belongs to a KeyM key handler: key negotiation is in KeyM's scope only as that hook (SRS_CryptoStack_00108 traced to [SWS_KeyM_00011]).

**MAC variant (T6).** HMAC-SHA-256, 256-bit key, tag = the leftmost 128 bits (`SecOCAuthInfoTruncLength = 128`), `K_auth_i2r` for A→B PDUs and `K_auth_r2i` for B→A (no shared key across directions: no reflection). Restricted to point-to-point PDUs. (The word "profile" is avoided in the paper for these two variants: SecOC already has security profiles 1 to 3.)
- A variant is a SecOC PDU configuration row: its Csm job reference (hence primitive and key) plus `SecOCAuthInfoTruncLength` (26,472 bits for ML-DSA-65, 128 for HMAC). Both rows are compiled into one binary; SecOC dispatches MAC or signature per PDU from the row instead of `SECOC_USE_PQC_MODE`; the parser, the layout check and the verify length take the authenticator length from the row; the harness selects the PDU at run time and writes `profile=` from that row.
- Keys and jobs: two Csm keys per peer (key element 1, 32 bytes) and two MAC jobs per node with fixed key references: A: generate → `K_auth_i2r`, verify → `K_auth_r2i`; B the reverse. IDs: jobs 20/21, keys 300/301, unless the ID allocation table changes them. Family `CRYPTO_ALGOFAM_SHA2_256`, mode `CRYPTO_ALGOMODE_HMAC`; generate length 16 bytes, verify length 128 bits ([SWS_Csm_00982], [SWS_Csm_01050]).
- Return semantics: a job whose key is not valid returns `CRYPTO_E_KEY_NOT_VALID` and produces no tag; a tag mismatch is reported through `verifyPtr` (`CRYPTO_E_VER_NOT_OK`) with return E_OK; SecOC reads `verifyPtr`.
- Layout check, both variants, before the Secured I-PDU is parsed: authentic length ≤ the configured maximum, and header + authentic + transmitted freshness + authenticator bytes == the received length (the received length, not a length derived from the header).
- HMAC-SHA-256 replaces the placeholder behind `Csm_MacGenerate` (AES-128-ECB under a constant key, `source/Encrypt/encrypt.c`), which is removed.

**Negative tests.** Trigger: A's "initiate handshake now" call. Oracle: each side exports its current `sid` and an install counter (number of key installations). "No key installed" = both unchanged; "session still working" = same `sid` and N further PDUs delivered. Script: establish session 1, deliver N PDUs, run the attacked handshake, assert the result label on each side, the oracle, then N more PDUs. Field edits are byte flips on the wire made by the attack proxy; no test hook in the BSW. All run on the real binary with BswM active.

T5, each ends with no key installed on either side and session 1 still working (rejecting step in brackets):
1. substituted `ek` in M1, a valid keygen output [A: `sig_B`]
2. substituted `ct` in M2 [A: `sig_B`]
3. M2 signed with a wrong `sk` under the pinned `ID_B` [A: `sig_B`]
4. M2 with only `mac_B` bytes altered [A: `mac_B`, `sig_B` valid]
5. replayed M1 from an earlier run [B: no M3, `T_pend`]
6. replayed M2 from an earlier run [A: `sig_B`, or discarded with no outstanding M1]
7. replayed M3 from an earlier run [B: `sig_A`, or discarded with nothing pending]
8. initiator key not pinned at B [B: unknown `ID_A`]
9. old-format UDP control datagram sent to B on the old control port, before and after a session is established [ignored]; no UDP listener on that port on either host
10. second TCP connection from a non-peer address sending a replayed M1 during an established session [refused at accept]

T5, expectation per side:
11. M3 dropped; M3 with only `sig_A` bytes altered; M3 with only `mac_A` bytes altered; M3 signed with a wrong `sk` under the pinned `ID_A`. B installs nothing and its keys, session and last counter are unchanged. A has installed. With no valid M4 inside `T_A`, A runs a new handshake and delivery resumes; PDUs A sent in between are rejected at B and counted.
12. M4 dropped or altered: both sides hold the new session and delivery is not interrupted; A runs one more handshake after `T_A`.

T5 unit tests: a handshake signature presented to the PDU verify job and a PDU signature presented to the handshake verify job, same peer key, both fail; a PDU signature made under one `sess` fails under another; the erasure test (a test-only accessor records the `dk`, `ss`, `PRK`, confirmation-key and `K_auth` bytes of a run; after success, failure, timeout and rekey the test scans the static storage of the handshake state and of the Csm and PQC key tables and finds none of them except the currently active `K_auth`); the known-answer transcript (M1, M2, M3, `ss` and the derived keys of one run are dumped; a standard-library Python script recomputes `th2`, `th3`, `PRK`, the four keys, `mac_B`, `mac_A`, `sess`, `mac_ack` and `sid`, taking `ss` and the signatures as opaque bytes, and must match byte for byte).
Restart: B alone, then A alone, in both variants: traffic resumes after exactly one handshake and no PDU recorded before the restart is accepted.
T5b: a PDU recorded in session 1 replayed into session 2, in both variants; a PDU signed with the no-session context injected into a freshly started receiver before M3 and again after establishment, rejected both times; a rekey under the 10 ms stream with zero verification failures at the receiver.
Malformed `ek` (FIPS 203 Sec. 7.2 check; B sends no M2): added only once the measured liboqs build is confirmed to perform the check.

**Readings fixed during implementation (accepted 2026-11-23).** (a) The PDU sign job and every non-handshake job read the session object of peer 0 in the single-peer evaluated configuration; the verify job 0x2000 + p reads peer p (a simplification, one conformance row). (b) `ID_X` is computed at `Csm_Init` and refreshed whenever an identity or peer public key is set valid, and cleared when it is rewritten. (c) "MAC jobs still queued at the switch are discarded" is not applicable: this Csm processes every job synchronously and never queues. (e) The PDU signature jobs read only the context element (1002) of the per-peer session key object; `dk` and `ss` are other elements of that object and have no read path, so "no SecOC job references it" holds per key element, not per key object (review finding CSM-5). (d) OpenSSL 3.0.18 (baolong) allocates twice per MAC call inside the library although the driver creates no context per call; 3.5.5 (iris) does not: recorded as a deviation from "no dynamic allocation", not worked around.

**Changes after the handshake-branch review (accepted 2026-11-23).** (f) A fourth timer, `T_flush` = 1 s (`PQCHS_T_FLUSH_MS`): from the acceptance of M2 until SecOC reports its transmit path flushed; on expiry the attempt ends with result `timeout`, the hold is released, the secrets are wiped and A starts a new handshake as after `T_A`. `T_flush` < `T_pend` (static assert). The M1 deadline `T_A` stops when M2 is accepted; while M3 is in transmission no timer runs and the transmit confirmation decides (install on success, fail on failure). (g) First handshake after start-up: SoAd opens the connection only on a transmit request and no Secured I-PDU is released without a session, so EcuM calls `PqcHs_Initiate(peer)` once after `PqcHs_Init` on the initiator and the M1 request is repeated every main cycle until SoAd accepts it; trigger (i) (connection becomes ONLINE) applies to every later connection. (h) The three erasing calls are checked; a failure ends the attempt with a failure row (no retry of the erase). (i) Mapping additions: custom job `CSM_JOBID_KEM_DISCARD` (35), family 0x82, mode 0x86, cleanses `dk` and `ss` of a peer's session key object; `Csm_KeyElementGet(keyId, 1003)` [SWS_Csm_00959] on the identity key or a peer key returns `ID_X`. (j) The Rx rows of the CAN PDUs (0, 1, 3, 4, 5), which verify with the node's own key, get a listed job of their own (`CSM_JOBID_VERIFY_LOOPBACK`, proposed id 11, to be agreed in the ID allocation table); an unlisted job id is refused by every Csm service.

**Decisions taken during the review fixes (accepted 2026-11-23 05:00).** (k) After any failed attempt the next handshake is due `T_A` after that attempt's M1, not at once: by then the responder has dropped its pending state and takes an M1 again. A time-out of the wait for M4 therefore restarts at once (its M1 is older than `T_A`), a flush time-out waits until M1 + `T_A`. (l) "Initiate a handshake now" is served from idle, from the wait for the retry time and from the wait for M4; in the last case the attempt that waited for M4 ends with a STATE row and stays installed. In every other state the request stays pending until the attempt has ended. (m) The responder drops an M1 (STATE row, no encapsulation) while an answer of its own is still with SoAd. (n) A failed key installation also clears the session identifier that the test oracle exports and invalidates the PDU signature context; `established` is cleared as before, so the no-session gate holds after a failed installation. (o) A confirmation MAC has three outcomes: OK, MAC_FAIL (compared and wrong), STATE (the Csm call or the erasure of the key slot failed). (p) If ML-KEM key generation fails after SoAd has taken the M1 transmit request, the component gives that transmission up; SoAd then closes the connection ([SWS_SoAd_00651]) and the initiator retries at `T_A`. (q) Job identifier of the loopback verify job: `CSM_JOBID_VERIFY_LOOPBACK` = 11; job identifiers that are not configured are refused by every Csm service. (r) Not done, recorded as deviations with their reason (this amends (h): two of the three erasing calls are checked, the confirmation-key slot and `dk`/`ss`): the result of the zeroizing writes in the failure branch of the installation is not checked (the attempt has already failed and ends with a failure row; nothing can depend on the result); the direct ML-DSA calls that use the empty context stay in the build and are marked by header comments.

**Return value of signature verification (decided 2026-11-23 06:52).** `Csm_SignatureVerify` returns `E_OK` with `CRYPTO_E_VER_NOT_OK` when the verification ran and the signature is wrong ([SWS_Csm_00996]: `E_OK` = request successful, the verdict is returned through `verifyPtr`; [SWS_Csm_01024]), as `Csm_MacVerify` already does; `E_NOT_OK` only when the request itself failed (job not configured, key or context not valid, driver error). SecOC accepts only `E_OK` with `CRYPTO_E_VER_OK` and treats every other answer as a verification failure. The as-found behavior (`E_NOT_OK` for a wrong signature) is changed on the integrated branch before main moves, with tests for both cases.

**One source of MAC keys (decided 2026-11-23 05:49 at the integration of the MAC rows).** In a binary that contains the handshake component the MAC keys of session-bound PDUs come from the handshake only (`K_auth_i2r` / `K_auth_r2i` per session). The installation of MAC keys from a file exists only in test programs built without the component; the gateway does not read a MAC key file (no run-time switch), its MAC key slots are not valid before the first installation, and a test shows that a key file at the old path is not opened and that a PDU authenticated under that file's key is refused before and after a session exists. Reason: a static key next to the session keys would be a downgrade path and would falsify the session-binding claim for the MAC variant. One conformance row.

**Layout rule on both reception paths (decided 2026-11-23 after the MAC-branch review).** The lengths of header, authentic part, transmitted freshness and authenticator must equal the received length on the TP path and on the IF path alike; an over-long Secured I-PDU is rejected with the verification-status callout. This deviates from [SWS_SecOC_00264] (which discards trailing bytes) and is recorded as one conformance row. A SecOC row with no or an unknown Csm job reference is a configuration error, and each Csm service refuses a job id that is not configured for it.

**Decisions on the review's open points (2026-11-23).**
1. Lost M3: a fourth message M4 as acknowledgment; A installs at M3 and re-handshakes when M4 is missing (option a).
2. Transcript hash: SHA-384 for every `H` (option a).
3. Session binding of PDU signatures: the session transcript hash goes into the FIPS 204 context of every PDU signature (option b), and, because that makes the binding unconditional, the freshness value stays a plain 32-bit counter per session: no session identifier inside the freshness value, no 64-bit freshness value, no collision bound to argue. Single-node harnesses sign with a 64-byte context so that primitive timings match the PDU path.
4. Key derivation and installation in Csm: KDF behind `Csm_CustomService` with the reason stated, `K_auth_*` installed with `Csm_KeyElementSet`, confinement claimed for `dk`, `ss`, `PRK` only; confirmation MACs through `Csm_MacGenerate/Verify` (option a).
5. Variant selection: per PDU configuration row, both in one binary (option a).
6. Timers: `T_pend` 2 s, `T_min` 1 s, `T_A` 3 s.
7. On-wire handshake negative tests 1 to 12 are accepted at Checkpoint 2 with the attack proxy; T5 itself is accepted on the positive run, the restart test and the unit tests (option b).

## Toolchain and standards coverage (author request, 2026-11-23)

The author asked for the full toolchain on the Pis and for the stack and the standards to be covered, with measured numbers only. Tools are installed with `apt`; nothing is enabled as a service. iris has little disk, so heavy analysis tools go to baolong only.

| Standard / practice | What is checked | Tool or artifact |
|---|---|---|
| AUTOSAR CP R25-11 (SecOC, PRS SecOC, Csm, CryIf, Crypto Driver, KeyM, SoAd, PduR) | every touched interface against the SWS text | `AUTOSAR_CONFORMANCE.md` (requirement IDs, four statuses) |
| FIPS 203 / FIPS 204 | known-answer tests of the exact liboqs build that is measured | liboqs KAT / ACVP-vector tests built with the measurement flags |
| RFC 5869 (HKDF), FIPS 198-1 / RFC 4231 (HMAC) | published test vectors | unit tests in the tree |
| SP 800-227 | handshake requirements (authentication, key confirmation, ephemeral-key destruction) | handshake section above + the per-check negative tests (authentication, key confirmation); ephemeral-key destruction: erasure unit test over static storage, stack residue by coding rule (reviewed, not tested) |
| MISRA C:2012 | static analysis of the files this revision writes or changes | `cppcheck --addon=misra` (counts reported; **no compliance claim**) |
| Defensive coding | warnings, memory and undefined-behavior errors | `-Wall -Wextra -Wconversion`, ASan + UBSan test run, valgrind on the handshake |
| ISO/SAE 21434, UN R155 Annex 5 | threat ↔ control ↔ test mapping for the tested attacks | table in the manuscript (text level, no certification claim) |
| IEEE 802.3 | link speed and duplex forced and recorded; 100BASE-TX stands in for 100BASE-T1 and the paper says so | `ethtool` |
| IEEE 1588 / 802.1AS | clock offset between hosts when one-way latency is reported (software timestamps on the Pi 4 NIC, accuracy stated) | `linuxptp` |
| RFC 2544 / RFC 6349 | throughput method, on-wire accounting | `iperf3`, `tcpdump`, interface counters |
| Real-time baseline | scheduling latency of the platform next to the signing tail | `rt-tests` (`cyclictest`), `stress-ng` |

Packages: both Pis `ethtool iperf3 rt-tests linuxptp stress-ng linux-perf`; baolong additionally `cppcheck valgrind gcovr clang-tidy gdb`. `chrony` is not installed (it would replace the system time service).

**No number without a file.** Every figure in the manuscript and the accompanying letter comes from a raw CSV in the run bundle, through the tested analysis toolkit, and is read a second time from the raw file by an independent reader; estimates and model outputs are labeled as such; nothing is quoted from a summary alone.

## Tech stack

C11 (AUTOSAR-style BSW port), CMake + Ninja/Make, liboqs 0.15.0 (static), OpenSSL libcrypto (HKDF/HMAC), GoogleTest for existing unit tests, Python 3 standard library plus numpy/scipy on the Mac for analysis. Targets: Raspberry Pi 4 (aarch64 Linux).

## Commands

```
Configure:  cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DSECOC_ROLE=<TX|RX>
Build:      cmake --build build -j4 --target SecOC <bench targets>
Unit tests: ctest --test-dir build --output-on-failure
Link up:    sudo ip addr add 10.10.10.<1|2>/24 dev eth0     (non-persistent)
Run Rx:     taskset -c 3 build/SecOC --role rx --peer 10.10.10.1
Run Tx:     taskset -c 3 build/SecOC --role tx --peer 10.10.10.2
Analysis:   python3 analysis/make_tables.py <run_dir>
```
(Exact target and flag names are fixed in the plan once the existing role switch in `scripts/configure_role.sh` has been read.)

## Project structure

```
Autosar_SecOC/source, include   BSW modules (SecOC, Csm, CryIf, PQC, SoAd, TcpIp, PduR, ...)
Autosar_SecOC/test              unit tests + existing benches (tx_perf_10k, phase_compare, attack_bench)
Autosar_SecOC/bench             new networked harnesses (load generator, periodic sender, attack injector)
Autosar_SecOC/scripts           build, role, run and collection scripts
analysis/                       statistics and table/figure generation, with its own tests
runs/<run_id>/                  raw CSV, env capture, commit hash, manifest
```

## Code style

Match the surrounding module: AUTOSAR naming (`SoAd_TpTransmit`, `Std_ReturnType`, `E_OK`), `(void)` on ignored returns, no dynamic allocation in BSW paths, comments only for the why. Smallest change that fixes the defect; no new abstraction layers.

## Testing strategy

- Unit: existing GoogleTest suites keep passing; a new test pins Tx and Rx data-to-authenticator bytes to be identical for the same PDU, freshness and DataID.
- Loopback: Tx and Rx processes on one Pi over 127.0.0.1 before any two-node run.
- Two-node: over eth0; pass means byte-exact payload delivery and zero verification failures.
- Negative: on-the-wire attack injection and a man-in-the-middle substitution in the handshake must be rejected.
- Measurement validity: raw CSV kept for every run; analysis scripts have tests on synthetic data with known answers.

## Boundaries

- **Always:** snapshot before change; new directories only; non-persistent network settings; record commit hash, kernel, governor, temperature and throttling flags in every run; keep raw data; one writer per tree; read raw CSVs before quoting a number.
- **Ask first (the author decides):** reboot or boot-config change (needed only for an `isolcpus` run); deleting anything to free disk on iris; package installs beyond `ethtool`, `iperf3`, `linux-perf`, `chrony`; publishing a Zenodo version; `git push`; editing the manuscript project; changing what the paper claims as its contribution.
- **Never:** touch wlan0 or the default route; store credentials in files; modify the as-found trees; report an estimated or extrapolated number as measured.

## Success criteria

1. `tree`: one commit builds as Tx and as Rx on both Pis; the binary prints its commit hash.
2. `rx-path`: over eth0, at least 10,000 ML-DSA-65 secured PDUs sent and at least 10,000 delivered to the receiving application byte-exact, with 0 verification failures and 0 framing errors.
3. `rx-path` negative: replay, bit-flip, signature tamper and freshness rollback injected on the wire, 1,000 each, all rejected before delivery; 0 false rejections in 10,000 benign PDUs.
4. `handshake-auth`: signed handshake completes; substituted encapsulation key or ciphertext is rejected; timing reported with n ≥ 1,000.
5. `bench` throughput: open-loop load at several rates, each ≥ 60 s, reporting delivered rate, loss, CPU utilization on both hosts, on-wire bytes from interface counters, send-queue occupancy; saturation point located; 1-core and 4-core measured.
6. `bench` deadline: periodic release at 10, 20, 50, 100 ms, ≥ 100,000 releases at 10 ms; deadline-miss ratio with confidence interval, longest run of consecutive misses; one stream and several streams on one core; default scheduler and SCHED_FIFO.
7. `bench` overhead: interleaved standalone / Csm-integrated signing, N = 10,000 each; equivalence margin fixed before the run; TOST, Hodges-Lehmann estimate with 95% CI, Cliff's delta.
8. `artifact`: one command regenerates every table from raw CSV; manifest with SHA-256; environment file with liboqs version and configuration, compiler and flags.
9. `paper`: every number in the revised manuscript traces to a file in the bundle.

## Open questions (author decisions): HISTORICAL, superseded by "Decisions" and by the handshake section
(Kept for the record. Item 2's wording "key confirmation under K_auth" is obsolete: key confirmation uses dedicated keys.)

1. **Roles.** Recommended: iris = transmitter (same board, clock and compiler as the published signing numbers), baolong = receiver with its clock capped at 1.5 GHz. The May documents had it the other way round.
2. **What the KEM-derived keys are for.** Recommended minimum: signed handshake + key confirmation under K_auth, ML-DSA stays the only data-plane authenticator, and the paper says plainly that the signature-only data plane does not need the KEM. Option: also implement and measure a MAC data-plane mode (HMAC under K_auth) as a second configuration, which answers that question more strongly but adds about two days and changes the contribution. Option: drop the KEM from the paper.
3. **Core isolation.** An `isolcpus=3` run needs a boot-parameter edit and one reboot per Pi. Recommended: do the scheduling study with `taskset` + `SCHED_FIFO` first, and add the isolated-core run only with the author's go-ahead.
4. **Packages.** Whether to `apt install ethtool iperf3 linux-perf chrony` on the Pis.

## Decisions (author delegated them on 2026-11-22)

1. **Roles.** iris = Gateway A (transmitter, handshake initiator); baolong = Gateway B (receiver, responder) with its CPU clock capped at 1.5 GHz at run time. One reverse-direction run is added if time allows.
2. **KEM-derived keys: the two-variant option plus the signed handshake.** Two SecOC authentication profiles are implemented and measured on the same hardware: (a) ML-DSA-65 per-PDU signature (SWS SecOC 7.1.4, untruncated authenticator); (b) a MAC profile keyed with the ML-KEM-derived `K_auth` for short-cycle PDUs. The handshake is signed with the ML-DSA identity keys and confirmed with HMACs under dedicated key-confirmation keys (three messages and an acknowledgment; see "Handshake `PQC-SecOC-HS-v1`"). Secured I-PDUs flow initiator → responder only in the evaluated configuration. `K_enc` is reserved: its label exists, the key is not derived, and the paper says so.
3. **Core isolation.** Scheduling study with `taskset` + `SCHED_FIFO` first. An `isolcpus` run (boot-parameter edit + reboot) only after all other data is collected and copied off, and only if the Pis can be recovered by the author.
4. **Packages.** `ethtool`, `iperf3`, `linux-perf`, `chrony`/`linuxptp` installed as needed.
5. **Manuscript source.** The submitted version of the manuscript is the edit base. Edits go to a copy, so a marked-changes PDF can be produced against the original.
6. **Draft of the accompanying letter.** An existing draft is the starting text; every number in it is replaced by measured values from the new campaign, and the corrections from the check of that draft are applied.
