# Cryptography Specification (v2)

This document specifies the cryptographic algorithms, key schedule, AEAD framing, and algorithm agility rules for TapAuth v2.

## 1. Real Cryptographic Agility

Protocol v2 replaces the nominal (unused) negotiation in v1 with **end-to-end enforced and persisted cryptographic agility**, respecting the shared-broadcast constraint of TapAuth:

**v2 ships one active primitive per slot**: `AES_256_GCM`, `SHA256` (HMAC-SHA256) and `ED25519`. The agility is in the enums, the `supported_*` / `selected_*` negotiation fields and their commitment into $H$ and into the AEAD AAD — not in shipped implementations, because there is exactly one implementation of each and it is the only one a build can name. Every rule below therefore still binds a *negotiated* value rather than a constant: the dispatch reads the stored/travelling algorithm id and refuses what it cannot implement.

1. **Client-Wide Broadcast Parameters** (associated with the Client's `CSK` because one multicast UDP / BLE advertisement targets **all** paired Servers simultaneously):
   * **`SymmetricAlgorithm`**: `AES_256_GCM` (`1`) — the one algorithm v2 implements. Tag `2` is `reserved` in `proto/auth_protocol.proto` (it was `CHACHA20_POLY1305` in pre-release builds) and must never be handed to a different algorithm; dispatch is `encrypt_with_alg` / `decrypt_with_alg` (`shared/src/crypto/encryption.rs:60`, `:74`).
   * **`HashAlgorithm`**: `SHA256` (`1`) — HMAC-SHA256 keyed by the CSK over the big-endian 60-second window (`keyed_window_mac`, `shared/src/crypto/temporal.rs:31`). Tag `2` is `reserved` (it was `BLAKE3` in pre-release builds).
   * **Client `SignatureAlgorithm`**: `ED25519` (`1`).
2. **Per-Server Parameters** (stored individually per `PairedServer` on Linux and `PairedDevice` on Android):
   * **Server `SignatureAlgorithm`** + Server static public key ($Ed_S$).
3. **Negotiation & Persistence Rules**:
   * **Android Server** advertises `supported_*` in `PairingInit` from the Rust constants (`SUPPORTED_SYMMETRIC_ALGORITHMS` / `SUPPORTED_HASH_ALGORITHMS` / `SUPPORTED_SIGNATURE_ALGORITHMS`, `shared/src/protocol/pairing/negotiation.rs`) — one element each today: `[AES_256_GCM]`, `[SHA256]`, `[ED25519]`. Kotlin builds none of these lists, so the phone cannot advertise a tag the desktop cannot implement. The protocol version itself is not negotiable: only `protocolVersion = 2` is accepted, and a v1 record must be re-paired (`check_protocol_version`, `shared/src/ffi/ops.rs`, [`authentication-flow.md`](authentication-flow.md) §2.6).
   * **Linux Client** intersects `supported_*` with its own supported set (and with the active CSK's algorithm if a `CSK` already exists from a prior pairing). `pick_first` walks the Client's own `SUPPORTED_*` slice in order, so the Client's preference is its list order, not the Server's. Rotating `CSK` (`RotateCsk`) allows upgrading the Client-wide algorithm when re-pairing.
   * Both sides **persist** what was negotiated, and the layout differs by side because the CSK is Client-wide:
     * **Linux**: the symmetric and hash algorithms live only in the Client-wide `CskMetadata` (in `shared/src/config.rs`), since the CSK they describe is shared by every paired Server; a `PairedServer` stores just its own `signature_algorithm` and $Ed_S$ (its `signature_algorithm` and `public_key` fields, `shared/src/config.rs`).
     * **Android**: `PairedDevice` stores all three per device — its `symmetricAlgorithm`, `hashAlgorithm` and `signatureAlgorithm` fields (`server-android/app/src/main/java/dev/rourunisen/tapauth/data/Models.kt:208-210`).
   * Runtime dispatch is strict on the stored values: `UNSPECIFIED` (`0`), the reserved tag `2` and any unknown id are refused — `CryptoError::UnsupportedAlgorithm` inside `shared`, `TapauthError::Argument` where the id is caller-supplied, `AlgorithmMismatch` when a packet header disagrees with the pinned algorithm — never a default.
   * The dispatch `match`es (`shared/src/crypto/encryption.rs:60`, `:74`; `keyed_window_mac`, `shared/src/crypto/temporal.rs:31`) are exhaustive over today's variants and carry **no** catch-all arm. That is deliberate and stronger than one: prost generates a plain Rust enum, so an unknown proto tag never arrives as a variant (the field decodes to its raw `i32` and the id comparison refuses it), while a variant added to the proto later is a compile error at every dispatch site instead of being silently absorbed by a wildcard.
4. **Adding an algorithm later**, which is the point of keeping the machinery: add the enum value with the **next free tag** (never reuse `2`), append it to the Client's `SUPPORTED_*` slice — first if it is newly preferred, since `pick_first` walks that slice in order — and leave the baseline in every Server's advertised list. No wire change is needed: `supported_*`, `selected_*` and the cleartext header tag already carry the id, and they are committed into $H$ and the AAD. Peer-supplied ids travel in two directions and are decoded **differently** — an advertisement is a compatibility surface, a selection is a claim:
   * **Advertised (`supported_*`): hashed as raw ids, skipped by the negotiation.** A peer's list may name algorithms a newer build implements and this one does not. It enters $H$ (§2.2) **exactly as it arrived on the wire** — the raw ids, in order, whatever this build can name — because a transcript that depended on what the *receiver* could decode would give two peers holding the same bytes different $H$, different keys and different SAS, which would make the compatibility promise below false. The negotiation then works on the decoded part: `symmetric_algorithms` / `hash_algorithms` / `signature_algorithms` (`shared/src/protocol/pairing/negotiation.rs`) drop the ids this build cannot name and `negotiate` intersects the survivors with `SUPPORTED_*`, so a peer advertising `[<new id>, AES_256_GCM]` still negotiates `AES_256_GCM` / `SHA256` instead of being refused over the id it *also* offered. Skipping can empty a list, and an empty list intersects with nothing, so a peer that advertises **only** ids this build does not implement is still refused: skipping is never a default.
   * **Selected (`selected_*`): hashed typed and validated.** A selection is a claim, not an offer: it is authenticated, it must be one we advertised, and an id this build cannot name is refused with `UnsupportedAlgorithm` before it can reach $H$ at all (`ServerPairingSession::verify_response`, `shared/src/protocol/pairing/server.rs`); the stored/negotiated value is then dispatched strictly as rule 3 above requires. $H$ therefore carries the validated variant, never a raw selection id.
   * Both sides thus hash the same bytes for the same advertisement — the phone over the list it sent, the desktop over the list it received — including when that list names an id one of them cannot implement.

   A second suite also carries back the three assertions a single suite makes vacuous, because both sides of each comparison are then the same literal `1`: `pinned_algorithms_win_over_the_baseline` (a pin outvotes the baseline), `the_negotiated_symmetric_algorithm_reaches_the_aead` (the negotiated id, not a literal at the call site, is what the AEAD receives) and `the_two_selected_algorithm_ids_are_not_transposed` (a swap of the two `selected_*` fields is invisible while both are `1`).
   Those three are a **register, not tests**: nothing in the tree is named `the_negotiated_symmetric_algorithm_reaches_the_aead`, `pinned_algorithms_win_over_the_baseline` or `the_two_selected_algorithm_ids_are_not_transposed` — grepping for them finds only comments, never a `#[test]`. The register is written at **five** sites, each beside the line a second suite would edit first:
   * `SUPPORTED_SYMMETRIC_ALGORITHMS` (`shared/src/protocol/pairing/negotiation.rs`) — all three;
   * `test_aead_roundtrip` (`shared/src/crypto/encryption.rs`) — the AEAD assertion;
   * the `NegotiatedAlgorithms` construction in `ServerPairingSession::verify_response` (`shared/src/protocol/pairing/server.rs`) — the transposition assertion;
   * `a_pinned_suite_is_selected_and_the_pairing_completes` (`shared/src/protocol/pairing/tests.rs`) and `a_v1_state_directory_pins_the_v1_suite_and_cannot_be_renegotiated` (`tapauthd/src/pairing.rs`) — the pin-outvotes-baseline assertion, on the client and daemon sides.
   The AEAD assertion is the weakest of the three: it is the only one with **no code site at all**. `test_aead_roundtrip` passes `alg` in and never exercises a dispatch, so the entry is a comment on a test that cannot demonstrate the assertion, and nothing else in the tree claims it. Adding a suite without these leaves pinning, plumbing and field mapping untested.

## 2. Cryptographic Primitives & Key Schedule

### 2.1 Asymmetric Primitives (Curve25519)
* **Key Exchange**: **X25519** (ephemeral $(x_C, X_C)$ on Client, $(x_S, X_S)$ on Server). Both peers must reject all-zero shared secrets $Z$.
* **Digital Signatures**: **Ed25519** (`SignatureAlgorithm::ED25519`).
  * Post-pairing messages sign the raw-payload transcript (`"tapauth-sig-v2" || be32(version) || be32(sig_alg) || be32(payload_type) || raw_payload`).
  * Pairing binds static Ed25519 keys via mutual signatures over the handshake transcript $H$.

### 2.2 Pairing Transcript Hash & HKDF-SHA256 Key Schedule

All pairing handshake parameters are committed into a deterministic length-prefixed SHA-256 transcript hash $H$:

```text
H = SHA-256(
    "tapauth-pair-transcript-v2"
    || be32(version)
    || session_id (16B)
    || client_x25519_public_key (32B)
    || server_x25519_public_key (32B)
    || client_ed25519_public_key (32B)
    || server_ed25519_public_key (32B)
    || be32(client_device_name.len()) || client_device_name
    || be32(server_device_name.len()) || server_device_name
    || be32(supported_sym.len())  || [be32(a) for a in supported_sym]
    || be32(supported_hash.len()) || [be32(a) for a in supported_hash]
    || be32(supported_sig.len())  || [be32(a) for a in supported_sig]
    || be32(selected_symmetric_algorithm)
    || be32(selected_hash_algorithm)
    || be32(selected_signature_algorithm)
)
```

The three `supported_*` lists are framed from the **raw advertised ids** — `a` is the id
as it travelled in `PairingInit`, in wire order, whether or not this build implements it
(`PairingTranscript::supported_*`, `shared/src/crypto/kdf.rs`). The three `selected_*`
fields are the validated variants the receiver accepted, framed as `be32` of the
variant's id; an id the receiver cannot name never reaches this hash (see §1 rule 4).

Using HKDF-SHA256 salted with $H$ and input keying material $Z = \text{X25519}(x, Y)$:

1. $\text{PRK} = \text{HKDF-Extract}_{\text{SHA256}}(\text{salt} = H,\; \text{IKM} = Z)$
2. $K_{\text{c2s}} = \text{HKDF-Expand}(\text{PRK},\; \texttt{"tapauth-pair-v2-c2s"},\; 32)$ — encrypts Client $\to$ Server pairing messages (`PairingConfirmClient`, Client `PairingAbort` MAC).
3. $K_{\text{s2c}} = \text{HKDF-Expand}(\text{PRK},\; \texttt{"tapauth-pair-v2-s2c"},\; 32)$ — encrypts Server $\to$ Client pairing messages (`PairingConfirmServer`, Server `PairingAbort` MAC).
4. $\text{SAS\_bytes} = \text{HKDF-Expand}(\text{PRK},\; \texttt{"tapauth-pair-v2-sas"},\; 8)$
5. $\text{SAS} = \text{u64::from\_be\_bytes}(\text{SAS\_bytes}) \bmod 1{,}000{,}000$ (6 decimal digits formatted `000-000`).

Salting HKDF with $H$ and using separate directional keys $K_{\text{c2s}} / K_{\text{s2c}}$ guarantees that **every** field in `PairingInit` and `PairingResponse` is cryptographically bound into both the SAS and the provisioning channel, and prevents reflection attacks.

### 2.3 Post-Pairing Signature Transcript

All `WrapperMessage` signatures are computed directly over `wrapper_signing_transcript` without re-serializing inner protobuf structs:

```text
"tapauth-sig-v2" || be32(version) || be32(signature_algorithm) || be32(payload_type) || payload
```

## 3. Single AEAD Nonce & Header AAD Construction

Protocol v2 **removes** all legacy challenge-derived nonce helpers (`derive_nonce`, `encrypt_with_csk`, `decrypt_with_csk`) so there is **one** unified AEAD construction across UDP, BLE, and Pairing:

* **Key Size**: 32 bytes (`AES-256-GCM`; a future `SymmetricAlgorithm` value must keep the 32-byte key, 12-byte nonce and 16-byte tag contract of §1, which is what lets the same framing carry it).
* **Nonce**: 12-byte cryptographically random CSPRNG nonce generated per encryption, prepended directly to `ciphertext || 16-byte tag`.
* **Associated Data (AAD)**:
  * **For `EncryptedPacket`**:
    ```text
    aad = "tapauth-pkt-v2"
          || be32(encryption_algorithm as u32)
          || be16(temporal_identifier.len() as u16)
          || temporal_identifier
    ```
  * **For `PairingConfirmClient`**: `aad = "tapauth-pair-v2-provision" || H`
  * **For `PairingConfirmServer`**: `aad = "tapauth-pair-v2-complete" || H`

Empty AAD (`&[]`) is forbidden in v2: binding cleartext packet headers into the AEAD tag detects any downgrade or temporal-ID tampering before inner decryption/parsing runs.

## 4. Symmetric Key Lifecycle Summary

* **Ephemeral Pairing Secrets ($x_C, x_S, Z, \text{PRK}$)**: zeroized when the session keys are derived, which is the only point at which they are used. $Z$ is held in a zeroizing buffer and dropped as soon as `derive_pairing_keys_and_sas` returns, the HKDF $\text{PRK}$ (and the extractor's own return buffer) is zeroized before that call returns, and each side takes — and zeroizes on drop — its ephemeral X25519 secret at the same point, so no later operation can re-derive a second key set.
* **Pairing Session Keys ($K_{\text{c2s}}, K_{\text{s2c}}, H$)**: strictly session-scoped. $K_{\text{c2s}}$ and $K_{\text{s2c}}$ live in zeroizing buffers and are zeroized by `conclude()` (`ClientPairingState::conclude` in `shared/src/protocol/pairing/client.rs` on the desktop, `ServerPairingSession::conclude` in `shared/src/protocol/pairing/server.rs` on the Phone), which the daemon runs on a proven completion (`Session::on_confirm_server` in `tapauthd/src/pairing.rs`) and on a cancel (`Session::on_cancel`, same file), and which the Phone runs itself once its linger is over, with `Drop` of the session object as the backstop. The daemon's other two endings do not conclude — an abort received from the Phone (`Session::on_abort`) and an expiry (`Session::on_expired`), both in the same file — so on those paths the keys are zeroized only by `Zeroizing`'s own `Drop`, when the session object goes. The completion proof is *not* the moment they go: the Phone keeps them for the linger that answers the Client's retransmitted `PairingConfirmClient` (Step 6 of [`initial-key-exchange.md`](initial-key-exchange.md)). $H$ is *dropped* rather than zeroized: it is an `Option<[u8; 32]>` that `conclude()` only sets to `None`.
* **Client Symmetric Key (`CSK`)**: 32-byte CSPRNG long-term key shared by one Client with all its paired Servers; protected at rest per [`security-hardening.md`](security-hardening.md) and rotated on demand via `RotateCsk`.
