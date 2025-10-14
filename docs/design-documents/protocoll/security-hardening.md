# Security Hardening Guidelines

Beyond the core protocol, a secure implementation requires hardening the application on both the Client and Server. This document specifies mandatory security practices.

## 1. Secure Key Storage

The cryptographic private keys are the foundation of the system's security. They **must never** be stored in plaintext.

* **Server (Android)**: All private keys and shared symmetric keys **must** be stored using the **Android Keystore System**. This ensures keys are protected by the operating system, often within a hardware-backed secure element, making them non-exportable and resistant to extraction even on a rooted device.

* **Client (Linux)**: Private keys and shared symmetric keys **must** be stored using a standard OS-level credential manager. Implementations should use the **Secret Service API (DBus)**, which is the standard interface for desktop keychains like GNOME Keyring and KWallet. This prevents storing keys in world-readable files and typically means they are encrypted on disk, protected by the user's login password.

## 2. Rate Limiting

To mitigate denial-of-service attacks from a malicious actor on the local network, the Server application must implement rate limiting on incoming authentication requests.

* **Strategy**: Per-Client identifier (based on the public key from the verified signature).
* **Rule**: After receiving a valid `AuthenticationRequest` from a given Client, the Server **should** ignore any further requests *from that same Client* for a short, escalating period (e.g., ignore for 1 second, then 2, then 4).
* **Rationale**: This prevents a flood of notifications from a single rogue or misbehaving client from overwhelming the user or draining the Server's battery, while still allowing legitimate requests from other paired Clients.