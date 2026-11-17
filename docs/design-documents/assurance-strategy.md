# Assurance Strategy

**Status:** decision record for the hardening branch. **Scope:** which assurance
techniques this project adopts for the v2 protocol and crypto code, which it rejected
and why, and what none of them says anything about. It is not a test plan; the tests
are in the tree and their rationale is in their doc comments.

**In one pass: Kani was adopted (seven harnesses), Verus was rejected after an
experiment, `sanitize_context_string` was measured and given up on, and the remaining
tools are recorded as decisions in §4.** `proptest` was adopted alongside Kani and is
listed in §4 because it was decided in the same pass.

***

## 1. Adopted: Kani, for seven harnesses

Seven `#[cfg(kani)]` harnesses, all in-file beside the function they prove, so no
production item changed visibility to reach them.

| Harness | Where | What it states | Measured cost (this machine) |
| :--- | :--- | :--- | :--- |
| `a_negotiated_algorithm_is_supported_and_was_advertised` | `shared/src/protocol/pairing/negotiation.rs:323` | Whatever `negotiate` selects is an algorithm this build implements **and** one the peer advertised, in every slot — soundness on both the pinned and the unpinned path | 4.0–6.5 s verify, ~555–570 MB peak RSS |
| `an_unpinned_negotiation_succeeds_exactly_when_every_slot_intersects` | `shared/src/protocol/pairing/negotiation.rs:368` | `Ok` iff every slot's intersection with `SUPPORTED_*` is non-empty, checked against `intersectable`, an oracle restated independently of `pick_first` | 4.0–6.5 s verify, ~555–570 MB peak RSS |
| `a_pinned_negotiation_selects_the_pin_only_when_both_sides_admit_it` | `shared/src/protocol/pairing/negotiation.rs:403` | `Ok` iff the pin is supported *and* advertised in both pinned slots and the signature slot intersects, checked against an `admissible` oracle restated in the harness rather than reused from `pick_first`. The `if let Ok` equality beside it proves nothing extra while there is one algorithm per slot — the pin is then the only admissible id — so "the pin outvoted our order" is the same vacuous register as `pinned_algorithms_win_over_the_baseline` in `cryptography-specification.md` §1.4, and becomes meaningful only with a second suite. The harness's content is the `Ok`-iff-admissible half | 4.0–6.5 s verify, ~555–570 MB peak RSS |
| `the_truncated_name_is_the_longest_prefix_within_budget` | `shared/src/protocol/pairing/fields.rs:73` | `truncate_utf8` returns the longest char-boundary prefix that fits the byte budget — it never cuts a code point that would have fit | ~20–21 s, ~693 MB |
| `encode_then_decode_is_the_identity` | `shared/src/ipc/framing.rs:173` | A length inside the cap survives `encode_len` → `decode_len` unchanged | ~5 s for all three framing proofs together |
| `decode_len_never_exceeds_the_cap` | `shared/src/ipc/framing.rs:194` | For **any** 4-byte prefix, a successful decode is ≤ `MAX_FRAME_LEN` — a peer can never make a reader reserve more than the cap | (as above) |
| `encode_len_refuses_above_the_cap` | `shared/src/ipc/framing.rs:204` | Everything above the cap is refused, the cap itself is accepted, and `MAX_FRAME_LEN + 1` is refused concretely — the inclusive boundary is not off by one on either side | (as above) |

Whole suite: **7/7 SUCCESSFUL**, ~47–51 s wall, ~0.9–1.0 GB peak for the run. Pinned
to Kani 0.68.0 / CBMC 6.11.0 in `.github/workflows/kani.yml`, because Kani's unwind and
slicing defaults move between releases and an unpinned upgrade can turn a verifying
harness into a spurious failure.

### They are advisory, and that is deliberate

* **`#[cfg(kani)]`, in-file.** Kani sets that cfg; no other build does. It is
  registered in `check-cfg` with `unexpected_cfgs` at `deny` (`shared/Cargo.toml`), so a
  misspelled `cfg(kanii)` is a build error rather than a harness the suite silently
  skips.
* **Ungated by the default suite.** `cargo test` never compiles them, so a merge cannot
  be blocked by a proof and a harness that no longer matches its function cannot rot
  the build — it only stops proving.
* **The job `Kani Proofs (shared)` is deliberately NOT a required context.** It is not
  in `scripts/ci/check-required-checks.sh` (eight contexts), and its `pull_request:`
  trigger carries no `paths:` filter precisely so that promoting it later cannot leave
  a required check `Pending` forever.

### Promoting it to a required check

Order matters, and both halves belong in **one** change:

1. Add the context `Kani Proofs (shared)` to ruleset `16779046` in the GitHub UI, or
   via the API — **first**.
2. Then add the same string to the `contexts` array in
   `scripts/ci/check-required-checks.sh`, which currently lists eight.

A required check that nothing reports never leaves `Pending`, so every queued
merge-queue entry waits out `check_response_timeout_minutes`. Doing (1) before (2) is
what makes the window between the two harmless; doing (2) first creates it.

***

## 2. Rejected: Verus

An experiment tried to prove `refine`'s monotonicity (a refinement may only add a skip)
in Verus.

| | Result |
| :--- | :--- |
| Proof time | **1.4 s** — for the model, not the code |
| Cost to build the model | **40** real code lines semantically rewritten, **93** real code lines dropped |
| Crate's own `libshared.rlib` | refused, `E0514` (incompatible rustc) |
| `use shared::config::DEFAULT_PAM_REFUSED_SERVICES` | refused |

The numbers describe a transcription, not `refine`. A model that has to rewrite 40 real
lines and drop 93 more to become expressible, and that cannot consume the crate it
belongs to, proves the transcription forever while the code drifts away from it — its
failure mode is silent and its maintenance cost is unbounded.

**Nothing from the experiment is committed.** The assertion it motivated survives as a
`#[test]`: `an_empty_configured_entry_does_not_match_an_empty_service`
(`client-pam/src/policy/refine.rs:63`) covers the `!name.is_empty()` guard that the
Verus model had had to restate by hand.

***

## 3. Not proven: `sanitize_context_string`

CBMC was pointed at the real function, not a model. It did not finish:

| Attempt | Result |
| :--- | :--- |
| Symbolic input | **46.8 GB** RSS after **751 s** → CBMC "appears to have run out of memory" |
| Concrete-input variant | did not finish in **2400 s** |
| Same function, concrete input, trimmed harness | ~1 s |

The cost is the **character tables** — two `matches!` over code-point ranges
(`is_context_whitespace`, `is_forbidden_context_char`) that CBMC has to reason about per
element — not the arithmetic. The arithmetic is already safe by construction and needs
no proof: the sanitizer uses `saturating_add`, has no `as` casts and no slice indexing
(it uses `bytes.get` / `input.get(..)`), so the overflow and out-of-bounds classes a
proof would target are unreachable.

Covered instead by, in the shipping suite:

* **A shared vector corpus** — `shared/testdata/context_sanitizer_vectors.json`, 130
  cases, five of them the truncation boundaries. It is read by both implementations,
  `test_context_sanitizer_vectors_are_honoured` (Rust) and `ContextSanitizerTest`
  (Kotlin), so the mirror cannot drift from the original unnoticed.
* **`proptest` properties** (`property_tests`, `shared/src/protocol/messages/context.rs`):
  the output fits its byte budget; it contains no forbidden code point (asserted with
  the module's own `is_forbidden_context_char`, not a re-transcription); it is valid
  UTF-8; and sanitizing twice changes nothing.

Honest limit on the last one: **idempotence holds only at budgets ≥ 4.** At 2 or 3 a
cut can land on the very space the next pass trims (`"a b"` at 2 bytes yields `"a "`),
so the property's domain starts at 4. That is unreachable from any shipped field
budget — `USERNAME_MAX_BYTES` 32, `PAM_SERVICE_MAX_BYTES` 32, `PROCESS_NAME_MAX_BYTES`
32, `HOSTNAME_MAX_BYTES` 64, `COMMAND_PREVIEW_MAX_BYTES` 128 — but it is a real hole in
the property, not a detail to skip.

***

## 4. Decided against, with reasons

| Technique | Verdict | Reason |
| :--- | :--- | :--- |
| `proptest` | **Adopted** | Fits the suite as written: properties live in-file, run under `cargo test`, and each one names the defect it catches. Used for the sanitizer, `truncate_utf8` and the QR URL round trip. |
| `cargo-fuzz` | **Adopted** — three targets | `fuzz/` drives the shipped entry points and is excluded from the workspace (`Cargo.toml`, `exclude = ["fuzz"]`), so no workspace build compiles it. `pairing_url`: `PairingInfo::parse` on arbitrary text, plus `generate_pairing_url_v2_for_key` → `parse` on arbitrary fields. `packet_decode`: `EncryptedPacket::decode`, the call `receive_udp_packet` makes once `datagram_within_size_cap` passes. `context_sanitizer`: `sanitize_context_string` with an unclamped `u64`-wide byte budget. Each asserts named invariants, not panic-freedom — the accepted URL's 512-byte cap, 32-hex `sid`, 64-hex non-zero `pk` and non-zero `p`, and the lossless parse∘generate round trip; a decode's determinism, its payload ≤ the datagram that produced it, and its stability under re-serialization; the sanitizer's byte budget, UTF-8 validity, emptiness under the module's own `is_forbidden_context_char`, and idempotence **only at budgets ≥ 4** (§3). The two private predicates are reached through a non-default `fuzz-api` feature that adds one `#[doc(hidden)]` one-line delegate beside each; no item became public in a default build. 18 in-tree seeds (~1.5 KB, `fuzz/corpus/`). Nightly only: `cargo +nightly fuzz run <target> fuzz/corpus/<target>-run fuzz/corpus/<target> -- -max_total_time=180 -max_len=<600, 16384, 512>`. CI is `.github/workflows/fuzz.yml`, `workflow_dispatch` plus a weekly `schedule:` and nothing else — deliberately not a required check, for the reasons in §1. Measured 2026-11-17, 181 s each: `pairing_url` 2.95 M execs (16.3 k/s), cov 795, corpus 6 → 359; `packet_decode` 10.96 M (60.6 k/s), cov 302, 6 → 255; `context_sanitizer` 4.87 M (26.9 k/s), cov 211, 6 → 406; no crash. |
| `miri` | **Not applicable to these paths** | The proven and property-tested paths — `negotiate`, `truncate_utf8`, the framing pair, `sanitize_context_string` — contain no `unsafe`, so there is no UB class for it to find there. And the one crate where `unsafe` is unavoidable, `client-pam/src/pam_sys.rs` (`unsafe fn` FFI shims, `CStr::from_ptr` over `libpam` handles the host owns), cannot run under it at all. |
| `loom` | **Not adopted** — closed, not deferred | Both Rust candidates were read to the bottom and neither holds a property a permutation search could establish. The `nonce_cache` is a `let mut HashSet` local to `authenticate_with_transport` (`tapauthd/src/auth_handler.rs:1117`), reached only as `&mut` from `wait_for_response` (`:1181`) inside one task future, and the UDP and BLE tasks each spawn their own call (`:795`, `:803`) — so there is nothing to interleave, and it is the borrow checker rather than a model that says so. `is_local_ip` (`shared/src/network/udp.rs:252`) is double-checked locking done right: the fast path is one `read()` whose result is a membership test (`:265`), and the miss path re-tests staleness **inside** the `write()` guard (`:276`), so every critical section is a pure function of the cache state it read and no two acquisitions must be atomic together — losing the race costs a redundant enumeration, and even deleting the re-test still yields a correct answer, only a second syscall. A model would first have to mock the clock (`Instant`, which is the entire subject of the handoff) and the `if_addrs` syscall — loom's own documentation puts both out of reach — and lift the state out of a process-global `static OnceLock<RwLock<_>>` (`:110`); that is a rewrite of the function to become expressible, the cost §2 refused. The one genuinely unsynchronised publication in that module is the `IPV6_AVAILABLE`/`IPV6_CHECKED` relaxed pair (`:106`), and loom cannot model that either: its documentation excludes reorderings across distinct atomics, which is exactly the shape. Recorded in §6 with its fix instead of modelled. What ships is a contract test on the handoff, `an_interface_address_is_local_and_a_documentation_address_is_not` (`shared/src/network/udp.rs:835`), and the phone's `RequestRateLimiter` stays out of reach by construction as a Kotlin `ConcurrentHashMap`. |

***

## 5. The honest limit

No harness in §1–§4 says **anything** about:

* **`aes-gcm`, `x25519-dalek`, `ed25519-dalek`, `hkdf`, `sha2`** — every harness above
  stops at our own code. The primitives are trusted implementations of standard
  constructions; no proof here covers them, and none of these proofs would notice a
  replacement that was broken the same way in both halves of a comparison.
* **Nonce freshness** — that a 12-byte AEAD nonce is never reused rests on the OS RNG
  (`getrandom`) and on the code calling it once per encryption. No property in this
  tree can observe that.
* **Constant-time behaviour** — out of reach entirely: the compiler decides it, and
  none of these tools reasons about timing.
* **Kotlin** — out of reach. The phone's assurance is a set of literal pins
  (`SharedProtocolLiteralsTest`), the shared vector corpora it re-reads
  (`ContextSanitizerTest`, `PairingUrlTest`) and one cancellation test
  (`PairingConfirmationCancellationTest`). That covers the *copied* logic and the
  commit/cancel interleaving; it says nothing about Kotlin's own crypto, its JNI
  boundary, or the derived `toString()` on data classes (see §6).
* **A passing fuzz run** — §4's three targets sample each parser's input space on one
  machine, toolchain and seed corpus. Their assertions are properties, but "no crash in
  181 s" is sampling and not proof, and a target that stops reaching a branch keeps
  reporting green. One property the packet target had to give up on the way is worth
  recording: a re-encoded packet is **not** always the size of its datagram. A
  non-minimal varint for `encryption_algorithm` truncates to a negative `i32` that
  protobuf re-encodes as a 10-byte sign-extended one, so `10ff85fc85fc9c9c62` (9 bytes)
  decodes to `-1061223681` and re-encodes to 11. Growth is bounded — one numeric field,
  `bytes` fields are copied verbatim — which is why the payload bound above holds, and
  the input is kept as a seed rather than as an assertion.

***

## 6. Backlog, and what this branch closes

Named and unfixed:

| Gap | Where | Why it is left |
| :--- | :--- | :--- |
| `the_negotiated_symmetric_algorithm_reaches_the_aead` has **no code site** — the assertion exists only as a recorded intention | `shared/src/crypto/encryption.rs` (`test_aead_roundtrip` passes `alg` in rather than exercising a dispatch); register on `SUPPORTED_SYMMETRIC_ALGORITHMS` in `shared/src/protocol/pairing/negotiation.rs` | Vacuous with one primitive per slot: both sides of every comparison are the literal `1`. It comes back with a second suite (see `cryptography-specification.md` §1.4). |
| A paired device's `toString()` prints the CSK, not an identity hash | `ParsedPairingProvision` (`shared/src/ffi.rs:158`, whose Kotlin form is the generated `data class` at `server-android/app/build/generated/uniffi/dev/rourunisen/tapauth/crypto/shared.kt:2091`) and `PairedDevice` (`server-android/app/src/main/java/dev/rourunisen/tapauth/data/Models.kt:200`). Neither has a `toString()` override, and the Kotlin compiler's derived one renders a `ByteArray` field through `java.util.Arrays.toString`, so `csk=[12, 255, …]` is the key itself rather than `[B@…` | Rust's hand-written `Debug` redacts the CSK (`shared/src/ffi.rs:167`) but cannot influence the Kotlin side. The fix is Kotlin-side — an override on `PairedDevice` and a holder for the generated record, or not exposing the CSK as a record field at all — so the rule is "Kotlin must not log either record" until then. No call site logs them today, so it is latent. |
| Kotlin's copy of the provisioned CSK is never cleared | `server-android/app/src/main/java/dev/rourunisen/tapauth/network/PairingSession.kt:781` hands `provision.csk` into `PairedDevice` by reference (no copy), and `zeroizeEphemeralState` (`:882`) clears only `initPacket` and `acceptedResponsePacket` (`:894`, `:896`); nothing under `server-android/app/src/main` fills the CSK, which lives on as a base64 string (`data/DeviceRepository.kt:137`) | Rust zeroizes the decrypted payload and its own `Zeroizing` copy (`shared/src/ffi/ops.rs:729`, `:173`) and cannot reach the Kotlin `ByteArray` that `to_vec()` (`shared/src/ffi.rs:216`) produced. A clear after `savePairedDevice` (`PairingSession.kt:790`) has to leave the live `PairedDevice` intact — it holds that same array, and every later authentication reads it — so the fix needs an ownership decision (copy at persist, wrapper, or clearing on device removal) rather than a `fill(0)` beside the save. |
| The 500 ms verdict-reuse window is an **assumption**, not a property | `VERDICT_REUSE_WINDOW`, `client-pam/src/conclusion_cache.rs:43` | The `(username, PAM service)` key cannot distinguish a host's duplicate `pam_authenticate` from an independent authentication for the same user and service inside 500 ms. Bounded by a human-initiated retry taking seconds, but not enforceable. |
| The `nonce_cache` of **one transport task** has **no cap**, and grows with the number of *distinct authenticated* frames it ingests | `wait_for_response`, `tapauthd/src/auth_handler.rs` | Since the insert moved behind the AEAD check, nothing an unauthenticated host sends is retained — but every *distinct authenticated* frame is, one entry per frame, for the life of the attempt (`get_session_timeout`, 120 s). Each entry is now a 32-byte `SHA-256(temporal_identifier ++ ciphertext)` in a `HashSet<[u8; 32]>` (`frame_fingerprint`, `tapauthd/src/auth_handler.rs`) instead of the frame bytes: the digest is a fixed-width content fingerprint for an in-memory set — not a secret, not a MAC, never serialized or logged — and it compares exactly the bytes the old `Vec<u8>` key compared, so the replay guarantee is unchanged and the per-entry cost drops from 1 543 B (MTU-sized frame) or 16 427 B (frame padded to the 16 KiB cap) to 56 B, measured over 600 entries. What that changes is the shape of the bound, not its existence, and the old figure here was wrong: one frame ends a wait and the next request waits out the retry interval (200 ms floor), so a device holding only the CSK — which can already mint authentic frames — ingests at most 600 per attempt per transport task (BLE and UDP run their own attempt loop with their own set), and retains ~34 KiB instead of ~0.88 MiB or ~9.4 MiB. ~1.4 GB would need ~710 frames of 16 KiB per second for the whole 120 s: a saturated 100 Mbit link, ignoring both the request schedule and IP fragmentation. Only a sender that can also sign as the phone, and so re-requests without waiting on an `InvalidMessage` verdict, is bounded by the receive loop rather than by the schedule, and that leaves single-digit MiB. Capping the set is still the wrong fix — it would evict entries and make a replay acceptable again; hashing was the half of that pair that cost nothing, and it is in this branch. Shape measured, not alleged: entries = distinct authenticated frames per attempt, dropped with the attempt. |
| `is_ipv6_available` publishes a **torn pair** on a weakly-ordered CPU | `shared/src/network/udp.rs:106` (`IPV6_AVAILABLE`/`IPV6_CHECKED`, both `Relaxed`) and `:347-350` | Two independent relaxed atomics are a two-word publication: a reader that observes `IPV6_CHECKED == true` may still observe the *initial* `IPV6_AVAILABLE == true` even though the probe returned `false`, and the wrong answer then sticks for the life of the process. One process start is the whole window, and the consequence is one family of multicast sends (`tapauthd/src/transport/udp.rs:94`): spurious IPv6 attempts, or IPv6 discovery silently skipped — not a security defect, but permanent once hit. Not modelled because loom excludes reorderings across distinct atomics; not fixed here because the fix is a shape change (one `AtomicU8`: unknown / available / not), not a line. |

Also carried forward from §4: no `cargo-fuzz` target and no `loom` model — and the `loom`
one is *closed*, not deferred: both caches were read and neither holds a compound
operation a bug could break, so the assurance they get is a contract test on the
read-then-write handoff (`an_interface_address_is_local_and_a_documentation_address_is_not`)
rather than a search over interleavings that cannot disagree. `cargo-fuzz` is no longer
carried forward either — §4 records it as adopted, and §5 records what its runs do and do
not say.

### Fixed in this PR

Two defects the audit named are closed, each by a commit that lands **after** this
record (named by subject, not shown by SHA):

* **`fix(net): a malformed datagram must not conclude an authentication attempt`** —
  an attempt now concludes only on a verified response from an authorised server, on
  its own deadline, or on an explicit local cancel/denial. Anything undecodable or
  unauthenticated from an arbitrary source is dropped and the attempt continues.
  **What that bounds, and what it does not** — what an attacker controls on this path
  is its log volume, its allocation, the state it can make the session retain, and
  whether the attempt can be held past its deadline. Three are bounded, and only the
  first is the log:
  * *Log.* Both drop sites report per occurrence at `debug` and the aggregate at `warn`
    at most once per 60 s with a running count (`shared/src/network/udp.rs`,
    `tapauthd/src/auth_handler.rs`), so a sender cannot turn one datagram into
    unbounded output. The one drop line that stays per-occurrence is the replay
    notice: a replayed frame is a frame that *did* authenticate, its rate is set by
    the retransmission interval (at most one datagram ends a wait, one wait follows
    each request: 200 ms … 6.4 s, the retry cap) rather than by the sender, and E2E
    Phase 2c asserts that exact phrase.
  * *Allocation.* A datagram is read into a fixed 64 KiB stack buffer and the 16 KiB
    framing cap is checked before the protobuf decode, so nothing an unauthenticated
    host sends can size an allocation beyond that, and the drop path itself allocates
    nothing that outlives the call.
  * *Retained state.* Nothing. Each transport task's nonce cache records only frames that
    authenticated — it is checked before the AEAD work and inserted after it — so a
    frame that fails to decode or fails AEAD occupies no memory, and an
    unauthenticated host cannot make a later legitimate frame look like a replay.
  * *Deadline.* Every drop branch in the receive loop yields to the scheduler before
    reading again. Without that a sustained flood keeps `recv_from` ready, the loop
    never returns `Pending`, and the caller's `tokio::time::timeout` never polls its
    sleep — so the attempt would run past the deadline it is supposed to conclude on.
    The yield is pure on every other path: it returns `Pending` once and reschedules
    the same task, reordering nothing observable one scheduler turn later.
  What is still uncapped is in the table above: the same cache grows with the number
  of *distinct authenticated* frames, i.e. with what a device holding the CSK sends —
  one 32-byte digest each now, ≤ 600 per attempt per transport task at our own request
  rate.
  **That commit also closes the replayed-frame backoff nit — as a consequence, not by a
  change of its own:** a replayed frame used to be classified `WaitOutcome::Timeout`,
  which counts as "the request went unanswered" and widened the retransmission
  interval, so a host that captured one datagram and replayed it could thin the
  requests aimed at the phone that may answer. It is now `WaitOutcome::Unattributable`,
  the same classification as any other frame that is not an answer to this request,
  and a drop leaves the interval alone. There is nothing left to fix here.
* **`feat(ble): apply post-auth rate limiting on the BLE path`** — the BLE transport
  now applies the same post-authentication limiter as UDP, keyed on the authenticated
  client public key, so a hammering client is throttled and one client's key cannot
  throttle another's.
