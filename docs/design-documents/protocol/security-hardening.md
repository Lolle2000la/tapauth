# Security Hardening Guidelines

Beyond the core protocol, a secure implementation requires hardening the application on both the Client and Server. This document specifies mandatory security practices.

## 1. Secure Key Storage

The cryptographic private keys are the foundation of the system's security. They **must never** be stored in plaintext.

* **Server (Android)**: All private keys and shared symmetric keys **must** be stored using the **Android Keystore System**. This ensures keys are protected by the operating system, often within a hardware-backed secure element, making them non-exportable and resistant to extraction even on a rooted device.

* **Client (Linux)**: The key storage strategy depends on the hardware capabilities of the machine and when the key is needed.

    * **Preferred Method: TPM (Trusted Platform Module)**: On systems with a TPM 2.0 chip, the Client's private key **must** be generated as a **non-migratable key** within the TPM. The PAM module will then interact with the TPM to perform signing operations without ever having access to the key material itself. This provides the highest level of security, as the key cannot be extracted even by a user with root privileges.

    * **Fallback Method: Root-Protected File**: On systems without a TPM, the PAM module **must** read the Client's private key from a file owned by `root` with permissions set to `600` (read/write for root only). A recommended location is `/etc/tapauth/client_key`. This isolates the key from all other users on the system.

    * **Management Applications (Post-Authentication)**: Any user-facing application for managing pairings after login **should** use the standard OS-level credential manager via the **Secret Service API (DBus)**.

## 2. Post-Authentication Rate Limiting

To mitigate denial-of-service (DoS) and user annoyance attacks from a malicious or malfunctioning actor on the local network, the Server application **must** implement rate limiting on incoming *validated* authentication requests. This occurs *after* a packet has been successfully decrypted and its signature verified.

* **Strategy**: Per-Client identifier (based on the public key from the verified signature). A token bucket or similar algorithm is recommended.
* **Rule**: After receiving a valid `AuthenticationRequest` from a given Client and displaying a notification, the Server **must** ignore subsequent requests from that *same Client* for a short, escalating period.
    * **Initial Backoff**: A 1-second cooldown after the first request is processed.
    * **Escalation**: The cooldown should double for each subsequent request (e.g., 2s, 4s, 8s) up to a maximum of 60 seconds.
    * **Reset**: The rate limit for a Client should be reset after a successful `GrantConfirmation`, an `AuthenticationCancel` is received, or the session times out.
* **Rationale**: This prevents a flood of notifications from a single rogue client from overwhelming the user or draining the Server's battery, while still allowing legitimate requests from other paired Clients to be processed immediately.

## 3. Pre-Authentication DoS Mitigation

To prevent resource exhaustion from an attacker replaying captured network packets, the server **must** implement a mitigation strategy *before* attempting decryption.

* **Strategy**: Per-client caching of valid `temporal_identifier` values.
* **Implementation**:
    1.  On startup and whenever the system's time window changes, the Server **must** pre-calculate the two valid `temporal_identifier` values (for the current and previous time windows) for each paired client.
    2.  These values should be stored in a fast-access data structure (e.g., a hash set) for immediate lookups.
    3.  When a packet arrives, its `temporal_identifier` is checked against this set. If it is not present, the packet is silently dropped. This avoids performing any cryptographic operations for invalid or replayed identifiers.
    4.  **BLE-Specific**: For BLE advertisements, the Server maintains a separate cache of 10-byte shortened temporal identifiers (used for discovery). For BLE GATT characteristic transfers, the Server uses the standard 16-byte temporal identifier cache (same as UDP).
* **Rationale**: This significantly reduces the attack surface for DoS attacks by making the initial packet check a very low-cost operation, protecting the CPU and battery from being wasted on expensive HMAC and decryption attempts.