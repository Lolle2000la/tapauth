# BLE GATT Service Specification

This document specifies the GATT (Generic Attribute Profile) service and characteristics required for the Bluetooth Low Energy transport layer of the authentication protocol.

* **Service UUID**: `b4ad84c0-2adb-4876-8315-b39d983b2bde`
  * This unique UUID identifies the TapAuth service.

## Advertisement Packet

For discovery, the Client (desktop) **must** broadcast a BLE advertisement packet containing the following data to allow for private and secure pre-connection identification:

* **Service Data**: A 10-byte **shortened temporal identifier** as service data with the TapAuth Service UUID (`b4ad84c0-2adb-4876-8315-b39d983b2bde`) as the key.

The BLE advertisement uses the service data format where:
- **Key**: The TapAuth Service UUID (`b4ad84c0-2adb-4876-8315-b39d983b2bde`)
- **Value**: The 10-byte shortened temporal identifier

This structure allows the Server (phone) to identify TapAuth advertisements by scanning for service data with the known TapAuth Service UUID, while keeping the advertisement packet small enough to fit within the 31-byte standard advertisement size limit.

The shortened temporal identifier is derived using the same HMAC-SHA256 process as the standard temporal identifier (see `authentication-flow.md`), but truncated to the first **10 bytes** instead of 16 bytes. This optimization ensures the BLE advertisement fits within size constraints while still providing sufficient entropy for secure device matching.

This rotating identifier allows the Server (phone) to recognize a trusted Client is advertising without revealing any static information that could be used for tracking. The Server will scan for advertisements containing service data with the TapAuth Service UUID and match the temporal identifier against its paired clients, at which point it will initiate a connection.

**Important**: The shortened 10-byte temporal identifier is used **only** for BLE advertisement discovery. Once the GATT connection is established, all subsequent communication uses the standard `EncryptedPacket` format with the full 16-byte temporal identifier as specified in `auth_protocol.proto`.

### Characteristics

Once a BLE connection is established, the TapAuth service shall expose three characteristics for the exchange of the full, encrypted protocol messages.

1. **Client Command Characteristic**
   * **UUID**: `caf54438-9d78-4697-8886-0a4cfa87ba8d`
   * **Properties**: `READ`
   * **Purpose**: This is the primary channel for the Client (desktop) to deliver the authentication request to the Server (phone). The Client stores the `EncryptedPacket` containing the `AuthenticationRequest` as the value of this characteristic. The Server reads it to receive the request.

2. **Server Response Characteristic**
   * **UUID**: `ca6238be-c194-49b7-855b-58f41d3da626`
   * **Properties**: `WRITE` (Write without response)
   * **Purpose**: The Server (phone) writes the `EncryptedPacket` containing the `AuthenticationGrant` or `AuthenticationDenial` message to this characteristic on the Client. Per the authentication flow specification, the Server will retransmit the response every 500ms until a confirmation is received or timeout occurs.

3. **Client Confirmation Characteristic**
   * **UUID**: `ace3e9ad-5f0d-48bf-825a-5b7f4dc49cdf`
   * **Properties**: `READ`
   * **Purpose**: The Client (desktop) stores the `EncryptedPacket` containing a `GrantConfirmation` as the value of this characteristic after successfully processing an `AuthenticationGrant` or `AuthenticationDenial`. The Server reads this characteristic to detect when the Client has received the response, allowing it to stop retransmitting. This implements the confirmation mechanism required by the authentication flow specification for both UDP and BLE transports.

## BLE Transport Flow

The BLE transport implements the same retransmission and confirmation protocol as the UDP transport:

1. **Client provides request**: The Client stores an `EncryptedPacket` containing an `AuthenticationRequest` as the value of the **Client Command Characteristic**. The Server discovers the device via the advertisement, connects, and reads this characteristic to obtain the request.
2. **Server responds**: The Server writes an `EncryptedPacket` containing an `AuthenticationGrant` or `AuthenticationDenial` to the **Server Response Characteristic**.
3. **Retransmission**: The Server retransmits the response every 500ms by re-writing to the Server Response Characteristic.
4. **Confirmation**: Upon receiving the response, the Client stores an `EncryptedPacket` containing a `GrantConfirmation` as the value of the **Client Confirmation Characteristic**.
5. **Stop retransmission**: The Server periodically reads the **Client Confirmation Characteristic** during retransmission. When it detects the confirmation, it stops retransmitting.

This design ensures reliable delivery of authentication results over BLE while maintaining consistency with the UDP transport behavior specified in `authentication-flow.md`.

## BLE Security Best Practices

To protect the confidentiality and integrity of the communication at the transport layer, the following BLE security practice is **strongly recommended** if your implementation has low-level control over BLE security parameters.

* **LE Secure Connections**: If your BLE stack allows configuration of security requirements, the connection between the Client and Server **should** be established using **LE Secure Connections**. Legacy pairing should be disabled where possible. LE Secure Connections provides strong, ECDH-based key exchange and protects against passive eavesdropping and Man-in-the-Middle attacks at the link layer.

**Note**: Many high-level BLE APIs (such as those provided by Android and Linux BlueZ) do not expose direct control over LE Secure Connections enforcement. In such cases, the OS-level BLE stack will negotiate the strongest available security mode automatically. The application-layer encryption provided by the `EncryptedPacket` structure ensures security even when BLE link-layer security cannot be explicitly controlled.