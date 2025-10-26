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

Once a BLE connection is established, the TapAuth service shall expose two characteristics for the exchange of the full, encrypted protocol messages.

1. **Client Command Characteristic**
   * **UUID**: `caf54438-9d78-4697-8886-0a4cfa87ba8d`
   * **Properties**: `WRITE` (Write without response)
   * **Purpose**: This is the primary channel for the Client (desktop) to send encrypted commands to the Server (phone). It is used to write the `EncryptedPacket` containing the `AuthenticationRequest` or `AuthenticationCancel` messages.

2. **Server Response Characteristic**
   * **UUID**: `ca6238be-c194-49b7-855b-58f41d3da626`
   * **Properties**: `NOTIFY`
   * **Purpose**: The Server (phone) sends the `EncryptedPacket` containing the `AuthenticationGrant` or `AuthenticationDenial` message to the Client via a notification on this characteristic.

## BLE Security Best Practices

To protect the confidentiality and integrity of the communication at the transport layer, the following BLE security practice **must** be implemented.

* **LE Secure Connections**: The connection between the Client and Server **must** be established using **LE Secure Connections**. Legacy pairing is not sufficient and must be disabled. This provides strong, ECDH-based key exchange and protects against passive eavesdropping and Man-in-the-Middle attacks at the link layer.