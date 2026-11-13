# Security Hardening Guidelines

Beyond the core protocol, a secure implementation requires hardening the application on both the Client and Server. This document specifies mandatory security practices.

## 1. Secure Key Storage

The cryptographic private keys are the foundation of the system's security. They **must never** be stored in plaintext, and shared symmetric keys should be protected at rest as well.

* **Server (Android)**: Private key material **must not** be written in clear. The shipped implementation wraps it rather than storing it as a Keystore key, because Android Keystore has no Ed25519 signing key type:
    * The long-term Ed25519 private key is generated in-app, encrypted with an AES-256-GCM key that lives in the **Android Keystore** (`tapauth_keypair_encryption_key`, `setUserAuthenticationRequired(false)`), and the ciphertext plus IV are kept in app-private preferences; only the public key is stored in the clear (`server-android/app/src/main/java/dev/rourunisen/tapauth/data/KeypairRepository.kt`). Compromise of the app-private files alone therefore does not yield the signing key — the Keystore-held wrapping key is needed — but the unwrapped private key does exist in the process while a grant is signed.
    * The shared **`CSK`** per paired client is currently stored Base64-encoded, not encrypted, in app-private preferences (`tapauth_devices`, `deviceToJson` in `server-android/app/src/main/java/dev/rourunisen/tapauth/data/DeviceRepository.kt`). It relies on the OS app sandbox and file-based encryption, not on the Keystore; treating it as Keystore-protected would overstate the guarantee. Note also that hardware backing is not requested anywhere, so even the wrapping key may be software-only on some devices.

* **Client (Linux)**: The key storage strategy depends on the hardware capabilities of the machine and when the key is needed.

    * **Preferred Method: TPM (Trusted Platform Module)**: On systems with a TPM 2.0 chip, the Client's Ed25519 private key **must** be sealed to the TPM rather than written in plaintext. TPM 2.0 cannot sign Ed25519 natively, so the implementation seals the 32-byte private key as a `keyedseal` object (`tpm2_create -G keyedseal -g sha384`) parented to the SRK at `0x81000001`, under a PCR policy — `sha256:7,14` (Secure Boot + MOK) for `standard`, `sha256:0,2,7,14` for `paranoid` — and unseals it into the daemon's memory to sign (`shared/src/tpm.rs`, `shared/src/config/toml_config.rs`). What that buys is boot-state binding: the key exists on disk only as a sealed blob that will not unseal if the measured boot chain changes. It does **not** mean the daemon never holds the key material, and it does not stop a root process on the running, correctly-booted system from unsealing it — the protection is against offline extraction from disk and against an evil-maid boot, not against root at run time.

    * **Fallback Method: Daemon-Protected File**: On systems without a TPM, the daemon **must** read the Client's private key from a file that only the daemon's own user can read. In practice `/var/lib/tapauth/` is mode `0700` and owned `tapauthd:tapauthd` (`packaging/tmpfiles.conf`), each key/config file under it is mode `0600` and owned `tapauthd:tapauthd` (a `0400` file is also accepted on read) — writes made as root are chowned to `tapauthd` (`write_secure_file`/`init` in `shared/src/config.rs`). This isolates the key from every other user on the system.

    * **Management Applications (Post-Authentication)**: Any user-facing application for managing pairings after login **must not** read or write key material itself. The GUI (`client-config-gui`) runs unprivileged and delegates every privileged operation — pairing, device removal, CSK rotation, config changes — to `tapauthd` over the admin IPC socket, where PolKit authorizes the caller; keys never leave the daemon.

## 2. Post-Authentication Rate Limiting

To mitigate denial-of-service (DoS) and user annoyance attacks from a malicious or malfunctioning actor on the local network, the Server application **must** implement rate limiting on incoming *validated* authentication requests. This occurs *after* a packet has been successfully decrypted and its signature verified.

* **Strategy**: Per-Client identifier (based on the public key from the verified signature). A burst-tolerant escalating backoff is recommended.
* **Rule**: After receiving a validated `AuthenticationRequest` from a given Client and displaying a notification, the Server **must** ignore subsequent requests from that *same Client* for an escalating cooldown period, with an initial burst allowance and request de-duplication to accommodate multi-transport delivery and network retransmissions.
    * **Request De-duplication**: Identical request payloads (identified by a cryptographic hash of the decrypted message) arriving within a short window (e.g., 2 seconds) **must** return the same accept/reject result as the first occurrence without affecting backoff state. This handles retransmissions and concurrent multi-transport delivery of the exact same authentication request. The deduplication key **should** be scoped per Client to prevent cross-client collisions.
    * **Burst Allowance**: The first few requests (e.g., 3) within a short window (e.g., 2 seconds) **should** be accepted without penalty. This ensures that concurrent delivery over BLE and UDP, plus a retransmission, all pass through without triggering the rate limiter.
    * **Initial Backoff**: A 1-second cooldown after the burst allowance is exhausted.
    * **Escalation**: The cooldown doubles only for *rejected* requests (those arriving while a cooldown is active) up to a maximum of 5 seconds. Accepted requests (those arriving after cooldown expiry) reset the backoff to the initial 1 second and start a fresh burst window. Paired clients are trusted; the rate limiter targets third-party replay/DoS attacks, not misbehaving clients.
    * **Maximum Backoff**: 5 seconds. This ensures that rapid legitimate requests (e.g., retry after a failed attempt) are not blocked for too long.
    * **Reset**: The rate limit for a Client should be reset after a successful `GrantConfirmation`, an `AuthenticationCancel` is received, an explicit denial is sent, or the session times out (`RequestRateLimiter.resetClient` call sites in `server-android/app/src/main/java/dev/rourunisen/tapauth/service/AuthenticationService.kt`).
* **Rationale**: This prevents a flood of notifications from replayed or forged packets from overwhelming the user or draining the Server's battery. The burst allowance and de-duplication handle legitimate multi-transport delivery and retransmissions, while the escalating backoff ensures that persistent third-party attackers are increasingly throttled.

## 3. Pre-Authentication DoS Mitigation

To prevent resource exhaustion from an attacker replaying captured network packets, the server **must** implement a mitigation strategy *before* attempting decryption.

* **Strategy**: Per-client caching of valid `temporal_identifier` values.
* **Implementation**:
    1.  The Server **must** pre-calculate the two valid `temporal_identifier` values (for the current and previous time windows) for each paired client. The implementation refreshes the set lazily — on the first packet of a new 60-second window — and immediately whenever the paired-device list changes, so a suspended or Doze-frozen refresh loop can never leave it stale (`server-android/app/src/main/java/dev/rourunisen/tapauth/service/TemporalIdCache.kt`).
    2.  These values should be stored in a fast-access data structure (e.g., a hash set) for immediate lookups.
    3.  When a packet arrives, its `temporal_identifier` is checked against this set. If it is not present, the packet is silently dropped. This avoids performing any cryptographic operations for invalid or replayed identifiers.
    4.  **BLE-Specific**: For BLE advertisements, the Server maintains a separate cache of 10-byte shortened temporal identifiers (used for discovery). For BLE GATT characteristic transfers, the Server uses the standard 16-byte temporal identifier cache (same as UDP).
* **Rationale**: This significantly reduces the attack surface for DoS attacks by making the initial packet check a very low-cost operation, protecting the CPU and battery from being wasted on expensive HMAC and decryption attempts.