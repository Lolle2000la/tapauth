# Security Hardening Guidelines (v2)

Beyond the core cryptographic primitives, TapAuth v2 enforces mandatory authorization, signature, sanitization, and rate-limiting invariants on both Client and Server.

## 1. Secure Key Storage

The cryptographic private keys are the foundation of the system's security. They **must never** be stored in plaintext, and shared symmetric keys should be protected at rest as well.

* **Server (Android)**: Private key material **must not** be written in clear. Because Android Keystore lacks an Ed25519 signing key type:
    * The long-term Ed25519 private key is generated in-app, encrypted with an AES-256-GCM key held in the **Android Keystore** (`tapauth_keypair_encryption_key`, `setUserAuthenticationRequired(false)`), with ciphertext + IV kept in app-private preferences (`server-android/app/src/main/java/dev/rourunisen/tapauth/data/KeypairRepository.kt`).
    * Per-client `CSK`s and pairing algorithm metadata are kept in app-private preferences (`tapauth_devices`, `DeviceRepository.kt`). Note: unless additionally wrapped by a Keystore key, `CSK` relies on the Android OS app sandbox and file-based encryption.
* **Client (Linux)**:
    * **Preferred Method: TPM (Trusted Platform Module)**: Sealed to TPM 2.0 SRK `0x81000001` as a `keyedseal` object (`tpm2_create -G keyedseal -g sha384`) under `standard` (`sha256:7,14`) or `paranoid` (`sha256:0,2,7,14`) PCR policy (`shared/src/tpm.rs`). Protects against offline disk theft and evil-maid boot tampering; unsealed into `tapauthd` memory at runtime.
    * **Fallback Method: Daemon-Protected File**: Stored in `/var/lib/tapauth/` (mode `0700`, `tapauthd:tapauthd`) with files mode `0600` (`0400` accepted on read), owned `tapauthd:tapauthd`.
    * **Unprivileged GUI**: `client-config-gui` never touches keys or secrets; all privileged state mutations cross the admin Unix socket to `tapauthd` under PolKit authorization.

## 2. Mandatory Authorization & Signature Invariants

### 2.1 Per-User Paired Server Authorization (`allowed_users`)
All paired Servers for a given Linux Client share that Client's `CSK`. Consequently, possession of `CSK` alone does **not** grant authority to approve authentication for every local Linux user:
* `tapauthd` **must** filter `paired_servers` by `server.is_user_allowed(&target_username)` into `allowed_servers` **before** passing the candidate key set into response verification.
* `verify_response_signature` / `handle_auth_grant` / `handle_auth_denial` **must** verify `WrapperMessage.signature` strictly against `allowed_servers` (and check that `wrapper.signature_algorithm` matches `server.signature_algorithm`).
* If Phone A is paired only for user `"bob"` and Phone B is paired for `"alice"`, Phone A cannot approve or deny an authentication attempt for `"alice"` even though Phone A can decrypt the multicast `EncryptedPacket`.

### 2.2 Mandatory Signature Verification Across ALL Message Types
* On Android, **all** incoming `WrapperMessage` envelopes — `AuthenticationRequest`, `GrantConfirmation`, and `AuthenticationCancel` — **must** have their Ed25519 signature verified inside the Rust JNI boundary (`shared/src/jni_api.rs`) against the paired Client's `ed25519_public_key` before Kotlin acts on the parsed message.
* Acting on an unverified `GrantConfirmation` or `AuthenticationCancel` (even when `CSK` AEAD decryption succeeded) is forbidden: doing so would let another device holding `CSK` cancel prompts or halt retransmissions.

### 2.3 QR Key Commitment & Transcript Binding at Pairing
* During pairing, Android **must** enforce `PairingResponse.client_x25519_public_key == qr.pk` in constant time before deriving SAS, and both sides must bind the entire handshake transcript $H$ into HKDF salt and mutual Ed25519 signatures (see [`initial-key-exchange.md`](initial-key-exchange.md)).
* `username` and `client_hostname` must be transmitted inside `PairingConfirmClient.encrypted_payload` (AEAD-encrypted under $K_{\text{c2s}}$ with $\text{AAD} = \texttt{"tapauth-pair-v2-provision"} \parallel H$), never in unauthenticated plaintext.

## 3. Contextual Request Metadata Sanitization & Spoof Resistance

When `AuthenticationRequest` includes optional context (`pam_service`, `process_name`, `command_preview`, `tty_present`):
1. **Kernel-Verified Caller Inspection**: `tapauthd` uses `SO_PEERCRED` (`caller_pid`, `caller_uid`) on the PAM Unix socket to read `/proc/<caller_pid>/exe` and `/proc/<caller_pid>/cmdline` directly rather than trusting arbitrary strings from an unprivileged socket caller.
2. **Strict Byte Caps**: `pam_service <= 32B`, `process_name <= 32B`, `command_preview <= 128B` (UTF-8 char-boundary truncated) so `EncryptedPacket` stays $\le 470\text{ B}$ (below the 512-byte BLE GATT attribute limit).
3. **Sanitization Against UI Spoofing**: Both `tapauthd` (before signing) and Android (before display) **must** strip all ASCII control characters (`0x00..=0x1F`, `0x7F`, ANSI CSI sequences) and Unicode bidirectional override characters (`U+202A..=U+202E`, `U+2066..=U+2069`), collapsing whitespace to single ASCII spaces.
4. **Visual Separation**: Primary security fields (`username` @ `hostname`) remain visually distinct from informational `command_preview` so a command argument cannot mimic another username or hostname.

## 4. Post-Authentication Rate Limiting

To mitigate DoS and notification fatigue from a malfunctioning or compromised peer:
* **Strategy**: Per-Client identifier (Ed25519 public key) escalating backoff with deduplication and burst allowance.
* **De-duplication**: Identical request challenges/payloads within 2 seconds return the prior decision without touching backoff state.
* **Burst Allowance**: Up to 3 requests in 2 seconds (accommodates simultaneous UDP + BLE + retransmission).
* **Escalation**: 1s initial cooldown, doubling on rejected bursts up to a 5s maximum backoff; reset on `GrantConfirmation`, verified `AuthenticationCancel`, explicit `AuthenticationDenial`, or session timeout.

## 5. Pre-Authentication DoS Mitigation

* **Temporal ID Cache**: `TemporalIdCache` pre-computes valid 16-byte (UDP/GATT) and 10-byte (BLE advertisement) identifiers for the current and previous 60-second time windows (`Algorithm`-matched per paired Client), refreshed lazily on window rollover and immediately on pairing list updates.
* Incoming packets whose `temporal_identifier` is absent from the cache are dropped in $O(1)$ without performing AEAD decryption or signature checks.
