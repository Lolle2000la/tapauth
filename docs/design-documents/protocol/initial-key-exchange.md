# Initial Key Exchange Protocol (v2 — Unified UDP + BLE)

## Overview

This document specifies Protocol v2 for pairing a **Client** (Linux desktop) with a **Server** (Android phone). The protocol securely provisions the Client's long-term `CSK`, mutually exchanges and authenticates both devices' static Ed25519 identity keys, negotiates cryptographic algorithms, and prevents Man-in-the-Middle (MITM) and Unknown Key-Share (UKS) attacks using a QR code commitment plus a transcript-bound Short Authentication String (SAS).

Pairing runs over the exact same two transports as authentication — **UDP** and **Bluetooth Low Energy (BLE)** — using one unified protobuf state machine (`PairingPacket` in [`proto/auth_protocol.proto`](../../../proto/auth_protocol.proto)). Only devices that have scanned the QR code can discover the Client over BLE or locate its ephemeral UDP socket, preventing unsolicited pairing spam.

***

## Cryptography and Keys

* **Cryptographic Primitives**: Defined in [`cryptography-specification.md`](cryptography-specification.md).
* **QR Code Commitment**: The Client encodes a random 16-byte `session_id` (`sid`) and its ephemeral X25519 public key ($X_C$, `pk`) into the QR URL.
* **Transcript-Bound Ephemeral Keys ($K_{\text{c2s}}, K_{\text{s2c}}$)**: Derived via HKDF-SHA256 from the X25519 shared secret $Z = \text{X25519}(x, Y)$, salted by the full SHA-256 handshake transcript hash $H$.
* **Static Identity Proof**: Both sides exchange their long-term Ed25519 public keys ($Ed_C, Ed_S$) and sign the handshake transcript $H$ to prove possession before trusting the peer key.
* **Client Symmetric Key (`CSK`)**: The Client's long-term key (and its associated `SymmetricAlgorithm` and `HashAlgorithm`), provisioned inside an AEAD-encrypted payload together with `username` and `client_hostname`.

***

## Pairing Protocol Visualization

```mermaid
sequenceDiagram
    actor User
    participant Client (Desktop)
    participant Server (Phone)

    User->>Client (Desktop): Initiate pairing (StartPairing)
    Client (Desktop)->>Client (Desktop): Generate ephemeral X25519 (X_C), random sid (16B)
    Client (Desktop)->>Client (Desktop): Bind ephemeral UDP socket [::]:0 & start BLE pairing adv
    Client (Desktop)-->>User: Display QR Code (v=2, sid, pk=X_C, p, ip4, ip6)

    User->>Server (Phone): Scan QR Code
    Server (Phone)->>Server (Phone): Generate ephemeral X25519 (X_S)
    Note over Server (Phone): Derive 10B BLE adv ID from (sid, pk)

    par UDP + BLE Transport Race
        Server (Phone)->>Client (Desktop): UDP PairingInit (retransmit 500ms)
    and
        Note over Server (Phone): After 250ms head-start if BLE enabled, hardware ScanFilter matches adv ID
        Server (Phone)->>Client (Desktop): BLE GATT connect -> PairingInit
    end

    Client (Desktop)->>Client (Desktop): Intersect supported algorithms, compute transcript hash H
    Client (Desktop)->>Client (Desktop): Derive PRK, K_c2s, K_s2c, SAS; sign ("tapauth-pair-client-sig-v2" || H) with Ed_C
    Client (Desktop)->>Server (Phone): Send PairingResponse (locked onto winning transport)

    Server (Phone)->>Server (Phone): Verify response.client_x25519_public_key == qr.pk (constant-time)
    Server (Phone)->>Server (Phone): Compute H, verify client_signature under Ed_C, derive PRK, K_c2s, K_s2c, SAS

    Client (Desktop)-->>User: Display SAS (e.g., "123-456")
    Server (Phone)-->>User: Display SAS (e.g., "123-456")

    User->>User: Visually confirm SAS matches
    User->>Client (Desktop): Confirm SAS (CompletePairing)
    User->>Server (Phone): Confirm SAS

    Note over Server (Phone): Over UDP, send PairingKeepalive every 1000ms while waiting
    Client (Desktop)->>Server (Phone): PairingConfirmClient (AEAD(K_c2s, "tapauth-pair-v2-provision" || H, {CSK, username, hostname}))
    Server (Phone)->>Server (Phone): Decrypt provision payload under K_c2s, sign ("tapauth-pair-server-sig-v2" || H || CSK) with Ed_S
    Server (Phone)->>Client (Desktop): PairingConfirmServer (AEAD(K_s2c, "tapauth-pair-v2-complete" || H, {server_signature}))
    Client (Desktop)->>Client (Desktop): Decrypt & verify server_signature under Ed_S; persist PairedServer + CSK

    Note over Client (Desktop),Server (Phone): Discard X_C/X_S priv keys, PRK, K_c2s, K_s2c.
```

***

## Pairing Protocol Steps

### Step 1: Client Presents QR Code & Starts Dual-Transport Listeners

When the user triggers pairing (`StartPairing` IPC):

1. The Client generates a cryptographically random 16-byte `session_id` (`sid`) and an ephemeral X25519 keypair $(x_C, X_C)$. (The Client's long-term `CSK` is generated upon first completion if none exists yet.)
2. **UDP Listener** (if `enable_network` is true):
   * The daemon binds an ephemeral dual-stack UDP socket (`[::]:0`, `IPV6_V6ONLY = false`, without `SO_REUSEPORT`) and opens a UDP firewall rule via `FirewallGuard::new(port, Protocol::Udp)`.
   * Using an ephemeral pairing socket prevents datagram contention with `daemon.udp_socket` (`udp_port`) if an authentication attempt runs concurrently, and keeps the pairing socket isolated.
   * **Loopback / Emulator NAT**: Unlike the multicast auth socket, the UDP pairing socket does **not** filter out packets sourced from `127.0.0.1` (`is_local_ip`), allowing Android emulator QEMU SLIRP NAT (`10.0.2.2:<port>` $\to$ `127.0.0.1:<slirp_ephemeral>`) to work without port redirection, while still rejecting exact self-port echoes.
3. **BLE Discovery Advertisement** (if `enable_ble` is true):
   * The Client computes a 10-byte pairing advertisement identifier:
     $$\text{pairing\_adv\_id} = \text{SHA-256}(\texttt{"tapauth-ble-pair-v2"} \parallel \text{session\_id} \parallel X_C)[0..10]$$
   * The Client advertises `pairing_adv_id` in `ServiceData(SERVICE_UUID)` (3B Flags + 28B ServiceData = 31 bytes exact legacy BLE budget; see [`ble-gatt-specification.md`](ble-gatt-specification.md)).
   * Unpaired nearby phones that did not scan the QR code cannot recognize `pairing_adv_id` and silently ignore the advertisement — eliminating unsolicited pairing spam.
   * The daemon keeps the **same static 4-characteristic GATT service** registered (with `PAIRING_CHAR_UUID`), avoiding Android `BD_ADDR` GATT handle cache staleness immediately after pairing.
4. **QR Code URL**:
   ```text
   tapauth://pair?v=2&sid=<16B-hex>&pk=<32B-x25519-hex>&p=<udp_port>&ip4=<ipv4>&ip6=<ipv6>
   ```
   * `v=2`: Protocol v2 pairing version.
   * `sid`: 16-byte random session identifier (hex).
   * `pk`: Client's 32-byte ephemeral X25519 public key $X_C$ (hex).
   * `p`, `ip4`, `ip6`: Ephemeral UDP pairing port and Client IPv4/IPv6 addresses (optional when BLE-only pairing is used; the Server must allow proceeding without IPs when BLE is available).

### Step 2: Server Initiates Unified UDP + BLE Transport Race (`PairingInit`)

Upon scanning the QR code, the Server (Android):
1. Parses `v`, `sid`, `pk` ($X_C$), and optional `p` / `ip4` / `ip6`.
2. Generates its own ephemeral X25519 keypair $(x_S, X_S)$.
3. Constructs a single `PairingPacket { version: 2, session_id, msg: PairingInit(...) }` containing:
   * `server_x25519_public_key` ($X_S$)
   * `server_ed25519_public_key` ($Ed_S$, the phone's long-term signing key)
   * `server_device_name` (truncated to max 64 UTF-8 bytes)
   * `supported_symmetric_algorithms`, `supported_hash_algorithms`, `supported_signature_algorithms` — always listing baseline v1/v2 mandatory algorithms first (e.g., `[AES_256_GCM, CHACHA20_POLY1305]`, `[SHA256, BLAKE3]`, `[ED25519]`) so older Clients continue to select compatible algorithms.
4. Races the transports:
   * **UDP**: If IP & port are present, sends `PairingInit` every **500ms** (up to 15s) until `PairingResponse` arrives.
   * **BLE**: Computes `pairing_adv_id` from `(sid, pk)` and (after a **250ms** head start for LAN UDP, or immediately if no IP/UDP is available) runs a foreground hardware-filtered `ScanFilter` matching the exact 10-byte `pairing_adv_id`, connects GATT, requests `MTU 517`, subscribes to notifications on `PAIRING_CHAR_UUID`, and writes `PairingInit`.
   * Whichever transport delivers a valid `PairingResponse` first wins and locks the transport for Steps 3–6; the other transport attempt is cancelled.

### Step 3: Client Algorithm Negotiation, Transcript Hash & Signed `PairingResponse`

Upon receiving `PairingInit` matching `session_id`:
1. The Client intersects each `supported_*` list from `PairingInit` with its own supported algorithms (preferring the active CSK's `SymmetricAlgorithm` and `HashAlgorithm` if a `CSK` already exists so all paired Servers remain compatible with multicast packets). If any intersection is empty, the Client sends `PairingAbort(UNSUPPORTED_ALGORITHM)` and aborts.
2. The Client computes the canonical **Handshake Transcript Hash** $H$ over all security-relevant parameters (`version`, `session_id`, $X_C$, $X_S$, $Ed_C$, $Ed_S$, normalized device names, the full `supported_*` lists, and the selected algorithms — see [`cryptography-specification.md`](cryptography-specification.md)).
3. The Client signs `"tapauth-pair-client-sig-v2" || H` using its static Ed25519 private key ($Ed_{C,\text{priv}}$) to prove possession of $Ed_C$ and bind it to the transcript.
4. The Client computes $Z = \text{X25519}(x_C, X_S)$ (aborting on all-zero low-order output) and derives:
   $$\text{PRK} = \text{HKDF-Extract}_{\text{SHA256}}(\text{salt} = H,\; \text{IKM} = Z)$$
   * $K_{\text{c2s}} = \text{HKDF-Expand}(\text{PRK},\; \texttt{"tapauth-pair-v2-c2s"},\; 32)$
   * $K_{\text{s2c}} = \text{HKDF-Expand}(\text{PRK},\; \texttt{"tapauth-pair-v2-s2c"},\; 32)$
   * $\text{SAS\_bytes} = \text{HKDF-Expand}(\text{PRK},\; \texttt{"tapauth-pair-v2-sas"},\; 8)$
5. The Client sends `PairingResponse` on the winning transport (and over UDP caches it so duplicate `PairingInit` retries update `peer_addr` and receive the cached `PairingResponse`).

### Step 4: Server QR Key Verification, Signature Check & Mutual SAS Comparison

Before displaying the SAS to the user, the Server **must**:
1. Perform a **constant-time equality check**: `response.client_x25519_public_key == qr.pk`. If they differ, send `PairingAbort(KEY_MISMATCH)` and abort immediately — an active attacker cannot substitute $X_C$ even before SAS verification.
2. Compute $H$ from its own view of the handshake fields and verify `response.client_signature` over `"tapauth-pair-client-sig-v2" || H` using `response.client_ed25519_public_key`. If invalid, send `PairingAbort(PROTOCOL_ERROR)` and abort.
3. Verify the selected algorithms are in its own supported sets.
4. Compute $Z = \text{X25519}(x_S, X_C)$ (rejecting all-zero output), $\text{PRK}$, $K_{\text{c2s}}$, $K_{\text{s2c}}$, and the 6-digit SAS:
   $$\text{SAS} = \text{format!}(\text{"\{:06\}"},\; \text{u64::from\_be\_bytes}(\text{SAS\_bytes}) \bmod 1{,}000{,}000)$$
   formatted visually as `"123-456"`.

Because **both** $K_{\text{c2s}}/K_{\text{s2c}}$ and $\text{SAS}$ are derived from $\text{HKDF-Extract}(\text{salt}=H, \text{ikm}=Z)$, tampering with **any** field — $X_C, X_S, Ed_C, Ed_S$, device names, or negotiated algorithms — produces a completely different $H$ and causes an overwhelming SAS mismatch (1 in $10^6$).

**The user MUST visually confirm that the SAS displayed on both screens is identical before confirming.**
* If the user cancels/rejects on either screen, that side sends an authenticated `PairingAbort(USER_REJECTED_SAS)` (`auth_tag = HMAC-SHA256(K_dir, "tapauth-pair-v2-abort" || H || be32(reason))`), via `CancelPairing` IPC from the GUI on Linux or directly from the Phone.

### Step 5: Authenticated Provisioning (`PairingConfirmClient`)

Once the user approves the SAS on the Desktop (`CompletePairing` IPC):
1. The Client constructs `PairingProvisionPayload { csk, username, client_hostname }` (so `username` and `client_hostname` are **authenticated and encrypted**, never sent in cleartext).
2. The Client encrypts `PairingProvisionPayload` using **AEAD** under $K_{\text{c2s}}$ with a random 12-byte nonce and:
   $$\text{AAD} = \texttt{"tapauth-pair-v2-provision"} \parallel H$$
3. Over UDP, the Client sends `PairingConfirmClient` to the latest `peer_addr` and retransmits every **500ms** until `PairingConfirmServer` (or `PairingAbort`) arrives or the session expires. Meanwhile, once the Phone has entered the awaiting-confirm state, it sends `PairingKeepalive` every **1000ms** over UDP so home NATs and QEMU SLIRP's ~4-second UDP NAT mapping do not expire during human SAS inspection. Over BLE, the Client notifies `PAIRING_CHAR_UUID`.

### Step 6: Mutual Confirmation & Persistence (`PairingConfirmServer`)

Once the user confirms the SAS on the Phone **and** `PairingConfirmClient` arrives:
1. The Server decrypts `PairingConfirmClient.encrypted_payload` under $K_{\text{c2s}}$ with $\text{AAD} = \texttt{"tapauth-pair-v2-provision"} \parallel H$, extracting `csk`, `username`, and `client_hostname`.
2. The Server signs `"tapauth-pair-server-sig-v2" || H || csk` with its static Ed25519 private key ($Ed_{S,\text{priv}}$), proving possession of $Ed_S$ and confirming exact receipt of `csk`.
3. The Server encrypts `PairingCompletePayload { server_signature }` under $K_{\text{s2c}}$ with $\text{AAD} = \texttt{"tapauth-pair-v2-complete"} \parallel H$, persists `(Ed_C, client_hostname, csk, selected_symmetric_algorithm, selected_hash_algorithm, selected_signature_algorithm, allowed_users += username)`, and sends `PairingConfirmServer` (3 times at `0ms, 100ms, 250ms` over UDP, and also in response to duplicate `PairingConfirmClient` retries during a brief linger window; or via GATT Write on `PAIRING_CHAR_UUID` over BLE).
4. The Client decrypts `PairingConfirmServer` under $K_{\text{s2c}}$ with $\text{AAD} = \texttt{"tapauth-pair-v2-complete"} \parallel H$, verifies `server_signature` under $Ed_S$, persists `PairedServer` (including `Ed_S`, `selected_signature_algorithm`, `allowed_users += username`) and the active CSK algorithm metadata, and closes the pairing socket / stops BLE pairing advertisement.
5. Both devices securely zeroize ephemeral X25519 secrets ($x_C, x_S, Z, \text{PRK}, K_{\text{c2s}}, K_{\text{s2c}}$).
