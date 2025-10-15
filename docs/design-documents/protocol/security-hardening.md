# Security Hardening Guidelines

Beyond the core protocol, a secure implementation requires hardening the application on both the Client and Server. This document specifies mandatory security practices.

## 1. Secure Key Storage

The cryptographic private keys are the foundation of the system's security. They **must never** be stored in plaintext.

* **Server (Android)**: All private keys and shared symmetric keys **must** be stored using the **Android Keystore System**. This ensures keys are protected by the operating system, often within a hardware-backed secure element, making them non-exportable and resistant to extraction even on a rooted device.

* **Client (Linux)**: The key storage strategy depends on the hardware capabilities of the machine and when the key is needed.

    * **Preferred Method: TPM (Trusted Platform Module)**: On systems with a TPM 2.0 chip, the Client's private key **must** be generated as a **non-migratable key** within the TPM. The PAM module will then interact with the TPM to perform signing operations without ever having access to the key material itself. This provides the highest level of security, as the key cannot be extracted even by a user with root privileges.

    * **Fallback Method: Root-Protected File**: On systems without a TPM, the PAM module **must** read the Client's private key from a file owned by `root` with permissions set to `600` (read/write for root only). A recommended location is `/etc/tapauth/client_key`. This isolates the key from all other users on the system.

    * **Management Applications (Post-Authentication)**: Any user-facing application for managing pairings after login **should** use the standard OS-level credential manager via the **Secret Service API (DBus)**.

## 2. Rate Limiting

To mitigate denial-of-service attacks from a malicious actor on the local network, the Server application must implement rate limiting on incoming authentication requests.

* **Strategy**: Per-Client identifier (based on the public key from the verified signature).
* **Rule**: After receiving a valid `AuthenticationRequest` from a given Client, the Server **should** ignore any further requests *from that same Client* for a short, escalating period (e.g., ignore for 1 second, then 2, then 4).
* **Rationale**: This prevents a flood of notifications from a single rogue or misbehaving client from overwhelming the user or draining the Server's battery, while still allowing legitimate requests from other paired Clients.