# Authentication Flow Protocol

## 1. Overview

This document specifies the network protocol for authenticating a user on a **Client** (e.g., a Linux desktop) using a paired **Server** (e.g., an Android phone). The protocol is designed for the lowest possible latency and high privacy by default.

The core design is a **parallel discovery model**:
* The Client initiates the process by simultaneously attempting discovery over both the **Local IP Network (IPv4 & IPv6 Multicast)** and **Bluetooth Low Energy (BLE)**.
* The first successful discovery path triggers the authentication flow. All subsequent communication for that session continues over the successful transport.
* This "race" approach ensures the fastest possible connection without waiting for timeouts, providing a seamless and highly responsive user experience.

```mermaid
sequenceDiagram
    participant Client (Desktop)
    participant Server A (Phone 1)
    participant Server B (Phone 2)

    par
        Client (Desktop)->>Server A (Phone 1): EncryptedPacket (IP Multicast)
        Client (Desktop)->>Server B (Phone 2): EncryptedPacket (IP Multicast)
    and
        Client (Desktop)->>Server A (Phone 1): BLE Discovery (Advertising Ping)
        Client (Desktop)->>Server B (Phone 2): BLE Discovery (Advertising Ping)
    end

    Note over Server A (Phone 1): Server A receives packet, checks Temporal ID, and decrypts.
    
    alt User on Server A Approves
        Server A (Phone 1)-->>Client (Desktop): EncryptedPacket (Unicast)
    end
    
    Note over Client (Desktop), Server A (Phone 1): Client accepts the grant from Server A and logs in.
    Client (Desktop)->>Server B (Phone 2): EncryptedPacket (IP Multicast Cancel) & BLE Cancel
    Note over Server B (Phone 2): Server B receives cancelation and dismisses its prompt.
```

## 2. Technical Specifications

### 2.1. Message Encryption & Packet Structure

To ensure confidentiality and privacy, all post-pairing communication is encrypted and wrapped in a final packet structure that prevents passive tracking.

* **Packet Structure**: The final message sent over the network **must** be an `EncryptedPacket`.
* **Temporal Identifier Generation**:
    1.  Both Client and Server define a **time window** of 60 seconds. The current window is calculated as `floor(unix_timestamp / 60)`.
    2.  The identifier is the first 16 bytes of an HMAC-SHA256 of the time window, keyed with the shared `CSK`.
    3.  This creates a rotating identifier that is verifiable by the Server but appears random to an outside observer, preventing metadata tracking.
    4.  **BLE Advertisement Exception**: For BLE advertisements only, a shortened 10-byte temporal identifier (first 10 bytes of the HMAC-SHA256) is used to fit within the 31-byte BLE advertisement size limit. See `ble-gatt-specification.md` for details.
* **Process**:
    1.  Construct the full `WrapperMessage` with the desired payload (e.g., `AuthenticationRequest`).
    2.  Serialize the `WrapperMessage` to a byte array.
    3.  Construct the `EncryptedPacket`.
    4.  Set the `encryption_algorithm` field to `AES_256_GCM` — the only value `SymmetricAlgorithm` defines, and the value every shipped path writes (`create_encrypted_packet` / `create_encrypted_packet_with_csk_nonce` in `shared/src/protocol/packet.rs`); the algorithm negotiated at pairing is not consulted at transmission time.
    5.  Encrypt the serialized `WrapperMessage` using the specified algorithm and the shared `CSK`. The result is placed in the `ciphertext` field.
    6.  Serialize and transmit the `EncryptedPacket`.

### 2.2. Timings and Retransmission Strategy

To ensure responsiveness, the protocol employs an aggressive retransmission strategy.

* **Client `AuthenticationRequest` Retransmission**:
    * **Strategy**: Exponential backoff.
    * **Intervals**: 200ms, 400ms, 800ms, 1600ms, 3200ms, 6400ms — `200 ms × 2^attempt`, capped at 6400 ms from the sixth interval onwards (`get_client_retry_interval`, `shared/src/network/discovery.rs`).
    * **Rationale**: This ensures that a single dropped packet has a minimal impact on the initial notification time, while avoiding excessive network traffic.

* **Server `AuthenticationGrant`/`Denial` Retransmission**:
    * **Strategy**: Fixed interval.
    * **Interval**: **500ms**.
    * **Timeout**: **10 seconds** (maximum 20 retransmission attempts).
    * **Rationale**: After user interaction, the Server persistently delivers the result to ensure the login completes promptly even with network packet loss. The 10-second timeout with 20 attempts is sufficient for reliable delivery on local networks while conserving battery and network resources. Retransmission continues until a `GrantConfirmation` is received from the Client or the retransmission timeout expires.

* **Session Timeouts**:
    * The daemon's authentication session (from initial request to user interaction) times out after **120 seconds**, a fixed constant (`get_session_timeout()`, `shared/src/network/discovery.rs`). The user prompt on the Server and the PAM module's wait are bounded by that same session, and the PAM-side wait is additionally the configurable `pam_operation_timeout_secs` (default 120).
    * Server response retransmission has a separate timeout of **10 seconds** as described above.

* **Daemon-side duplicate suppression**: before opening a session, `tapauthd` checks a map of recent requests keyed on the **username alone** and answers a repeat for the same user arriving within **1 second** with `PamOutcome::Ignore` (`handle_pam_authenticate`, `DEDUP_WINDOW`, `tapauthd/src/main.rs`), so no second request is sent to the phone. The map lives on `ServerState`, so it spans every IPC connection the daemon serves and ignores the PAM service, the caller's UID and the request id; entries are pruned only by a later request, once they are 2 seconds old. The test is the timestamp, not whether the first session is still running, so a request is suppressed even after that session has concluded. This is the daemon's own deduplication, distinct from the PAM module's `(username, service)` reuse window (`ConclusionCache::replay_for`, the reuse lookup in `transaction::run`; see [`../pam-module.md`](../pam-module.md)). Two different authentication contexts for the same user inside that second — a `sudo` prompt and a lock-screen unlock — can therefore have the second answered `Ignore` by the daemon instead of rung on the phone.

### 2.3. Signature Generation

All signed messages must use a canonical format to guarantee verifiability *before encryption*. Signatures are placed on the `WrapperMessage`, not on individual inner messages — with the one exception noted at the end of this section.

* **Data-To-Be-Signed**: The **binary-serialized `WrapperMessage`** with its `signature` field set to empty bytes. The `WrapperMessage` contains the inner payload (e.g., `AuthenticationRequest`) in its `payload` field.
* **Process**:
    1.  Construct the inner message object (e.g., `AuthenticationRequest`).
    2.  Place the inner message into a `WrapperMessage` using the appropriate `payload` variant.
    3.  Set the `signature_algorithm` field on the `WrapperMessage` to `ED25519` — the only value `SignatureAlgorithm` defines, and the value `sign_wrapper_message` always writes.
    4.  Leave the `signature` field empty and serialize the `WrapperMessage` to a byte array. This is the data to be signed.
    5.  Sign the byte array using the sender's private key and the specified algorithm.
    6.  Place the resulting signature into the `signature` field of the `WrapperMessage`.
    7.  The completed `WrapperMessage` is then serialized, encrypted, and placed into an `EncryptedPacket` for transmission.

* **Inner signature on grants**: `AuthenticationGrant.signed_challenge` carries an additional Server Ed25519 signature over the raw 32-byte `challenge`, so on a grant the challenge is signed twice — once inside the payload and once through the wrapper. `verify_auth_grant` checks both signatures (`shared/src/protocol/messages.rs`).

### 2.4. Transport Layer Considerations

The protocol is transport-agnostic, but relies on specific behaviors for discovery.

* **IP Network (Wired Ethernet or Wi-Fi)**:
    * **Port**: Uses UDP on port **`36692`**. This default port **must** be user-configurable.
    * **IPv4**: The Client sends to the multicast group **`239.255.26.44`** (inside the IPv4 Local Scope `239.255.0.0/16`, RFC 2365). Servers join this group on every multicast-capable interface; the address is not an IANA assignment.
    * **IPv6**: The Client sends to the link-local multicast group **`ff12::fdec:fc27`** on every IPv6-capable interface. The group is transient (not an IANA permanent assignment) and its low 32-bit group ID lies in the IANA "Reserved for Private Use" dynamic range `0xFD000000`-`0xFDFFFFFF` (RFC 10028).
    * **Response**: The Server responds via UDP unicast to the source IP of the request packet.
    * **Source port**: Request, confirmation and cancel datagrams are sent from an **ephemeral** source port — the client opens one socket per outgoing interface so it can pin the IPv4/IPv6 multicast interface. Servers **must** therefore reply to the configured UDP port (`udp_port`), never to the observed source port.

* **Bluetooth Low Energy (BLE)**:
    * The Client acts in the **Advertiser/Peripheral** role.
    * The Server acts in the **Scanner/Central** role.
    * **Advertisement**: Uses a 10-byte shortened temporal identifier in service data for discovery.
    * **GATT Transfer**: Once connected, uses standard `EncryptedPacket` with 16-byte temporal identifier via GATT characteristics.

## 3. Protocol Flow

### Step 1: Parallel Discovery (Client)

* When the PAM module requests authentication, it forwards the request to `tapauthd` over the daemon's Unix socket, and the daemon immediately begins multicasting/advertising the `EncryptedPacket` containing the `AuthenticationRequest` on all available channels. Hosts the module classifies as display managers, or as hosts whose conversation it cannot drive, never reach this step — the phone is not rung at all (see [`../pam-module.md`](../pam-module.md)).

### Step 2: Request Handling (Server)

* The Server listens for discovery messages. Upon receiving an `EncryptedPacket`:
    1.  It reads the `temporal_identifier`.
    2.  For each `CSK` of its paired clients, it independently calculates the expected identifier for the **current time window** and the **previous time window**. To avoid re-computation, these two valid identifiers for each client **should** be cached and only re-calculated when the time window changes.
    3.  It compares the received identifier against its cached valid identifiers.
    4.  If no match is found, the packet is silently discarded.
    5.  If a match is found, it attempts a single decryption of the `ciphertext` using the corresponding `CSK`.
* Once successfully decrypted and deserialized, it verifies the signature on the inner `WrapperMessage` payload and performs replay mitigation checks.

#### Replay Attack Mitigation
An incoming `AuthenticationRequest` **must** be validated against two independent mechanisms to prevent replay attacks. Both checks must pass for the request to be considered valid.

1.  **Nonce Check (Primary Defense)**: The `challenge` field in the request acts as a unique nonce for the authentication session. The Server **must** maintain a cache of all received `challenge` nonces for the duration of the session timeout (120 seconds). If a request is received with a `challenge` that is already in the cache, it is a replay and **must** be silently discarded.

2.  **Timestamp Check (Secondary Defense)**: The `timestamp_unix_seconds` in the request is compared against the Server's current UTC time. If the timestamp is more than a **60-second** window away from the Server's clock in either direction (stale or ahead), it is considered invalid and **must** be silently discarded. This prevents the replay of very old packets that may have been captured from a previous session and are no longer in the nonce cache. The window is symmetric (`ReplayMitigationCache.isReplay`; `is_request_timestamp_valid` in `shared/src/protocol/messages.rs`).

### Step 3: Response (Server)

* The Server constructs and signs an `AuthenticationGrant` or `AuthenticationDenial` message.
* It wraps and encrypts this into an `EncryptedPacket` and sends it back to the Client using the **same transport layer** that the initial discovery message arrived on, retransmitting until a confirmation is received or timeout.

### Step 4: Finalization (Client)

* The Client accepts the first valid `EncryptedPacket` containing an `AuthenticationGrant` or `AuthenticationDenial` that it can successfully decrypt.
* Upon successful decryption of either message type, it **must** send a final `EncryptedPacket` containing a `GrantConfirmation` back to the granting Server to halt retransmissions. If further retransmissions are received after this point, the `GrantConfirmation` must be resent up to three times.

### Step 5: Cancelation (All Transports)

* If the client is unlocked (e.g., through a successful `AuthenticationGrant`), it multicasts a final `EncryptedPacket` containing an `AuthenticationCancel` message to ensure all other Servers dismiss their pending user prompts.