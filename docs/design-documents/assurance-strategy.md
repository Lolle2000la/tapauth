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
| `a_pinned_negotiation_selects_the_pin_only_when_both_sides_admit_it` | `shared/src/protocol/pairing/negotiation.rs:403` | `Ok` iff the pin is supported *and* advertised in both pinned slots and the signature slot intersects; on `Ok` the selected ids **are** the pinned ones (the pin outvotes our order) | 4.0–6.5 s verify, ~555–570 MB peak RSS |
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
| `cargo-fuzz` | **Not adopted** — follow-up | Needs nightly and a corpus kept in-tree, and a fuzz target per entry point. Worth doing for the parsers (`PairingInfo::parse`, the protobuf decode paths) once the branch that this record describes has landed; not a thing to bolt onto a hardening branch. |
| `miri` | **Not applicable to these paths** | The proven and property-tested paths — `negotiate`, `truncate_utf8`, the framing pair, `sanitize_context_string` — contain no `unsafe`, so there is no UB class for it to find there. And the one crate where `unsafe` is unavoidable, `client-pam/src/pam_sys.rs` (`unsafe fn` FFI shims, `CStr::from_ptr` over `libpam` handles the host owns), cannot run under it at all. |
| `loom` | **Not adopted now** — follow-up | The real candidates are `INTERFACE_ADDR_CACHE` / `is_local_ip` (`shared/src/network/udp.rs:231`, the read-then-write handoff of the interface cache), the per-attempt `nonce_cache` (`tapauthd/src/auth_handler.rs`, a plain `HashSet` owned by one task) and the phone's `RequestRateLimiter` (`server-android/app/src/main/java/dev/rourunisen/tapauth/service/RequestRateLimiter.kt`). Only the first two are Rust, and loom needs the synchronisation wrapped for it; the third is a Kotlin `ConcurrentHashMap` loom could not model anyway. |

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

***

## 6. Backlog, and what this branch closes

Named and unfixed:

| Gap | Where | Why it is left |
| :--- | :--- | :--- |
| `the_negotiated_symmetric_algorithm_reaches_the_aead` has **no code site** — the assertion exists only as a recorded intention | `shared/src/crypto/encryption.rs` (`test_aead_roundtrip` passes `alg` in rather than exercising a dispatch); register on `SUPPORTED_SYMMETRIC_ALGORITHMS` in `shared/src/protocol/pairing/negotiation.rs` | Vacuous with one primitive per slot: both sides of every comparison are the literal `1`. It comes back with a second suite (see `cryptography-specification.md` §1.4). |
| A paired device's `toString()` can print the CSK | `shared/src/ffi.rs` (`ParsedPairingProvision`: `Debug` is hand-written and redacted, but UniFFI generates a Kotlin `data class` whose `toString()` is derived from the field list and cannot be influenced from Rust) | Fixing it means not exposing the CSK as a record field at all, or a Kotlin-side wrapper; neither belongs in this branch, so the rule is "Kotlin must not log that record" until then. |
| The 500 ms verdict-reuse window is an **assumption**, not a property | `VERDICT_REUSE_WINDOW`, `client-pam/src/conclusion_cache.rs:43` | The `(username, PAM service)` key cannot distinguish a host's duplicate `pam_authenticate` from an independent authentication for the same user and service inside 500 ms. Bounded by a human-initiated retry taking seconds, but not enforceable. |

Also carried forward from §4: no `cargo-fuzz` target and no `loom` model for the
interface cache or the nonce cache.

### Fixed in this PR

Two defects the audit named are closed, each by a commit that lands **after** this
record (named by subject, not shown by SHA):

* **`fix(net): a malformed datagram must not conclude an authentication attempt`** —
  an attempt now concludes only on a verified response from an authorised server, on
  its own deadline, or on an explicit local cancel/denial. Anything undecodable or
  unauthenticated from an arbitrary source is dropped and the attempt continues, with
  rate-limited logging so the drop path is not itself an amplification vector.
  **That commit also closes the replayed-frame backoff nit — as a consequence, not by a
  change of its own:** a replayed frame used to be classified `WaitOutcome::Timeout`,
  which counts as "the request went unanswered" and widened the retransmission
  interval, so a host that captured one datagram and replayed it could thin the
  requests aimed at the phone that may answer. It is now `WaitOutcome::Unattributable`,
  the same classification as every other frame that does not authenticate, and a drop
  leaves the interval alone. There is nothing left to fix here.
* **`feat(ble): apply post-auth rate limiting on the BLE path`** — the BLE transport
  now applies the same post-authentication limiter as UDP, keyed on the authenticated
  client public key, so a hammering client is throttled and one client's key cannot
  throttle another's.
