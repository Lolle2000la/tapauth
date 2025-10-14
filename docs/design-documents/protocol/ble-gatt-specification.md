# BLE GATT Service Specification

This document specifies the GATT (Generic Attribute Profile) service and characteristics required for the Bluetooth Low Energy transport layer of the authentication protocol.

* **Service UUID**: `b4ad84c0-2adb-4876-8315-b39d983b2bde`
    * This unique UUID identifies the TapAuth service.

## Advertisement Packet

For discovery, the Client (desktop) **must** broadcast a BLE advertisement packet containing the following data to allow for pre-connection identification:

* **Service UUID**: The full 128-bit TapAuth Service UUID (`b4ad84c0-2adb-4876-8315-b39d983b2bde`).
* **Service Data**: A short, unique identifier for the Client. This **must** be a truncated hash (e.g., the first 8 bytes) of the Client's public key.

This Service Data is critical for the Server (phone) to identify which specific Client is advertising before initiating a connection, which is essential for both efficiency and a clear user experience when multiple Clients are present.

### Characteristics

The TapAuth service shall expose two characteristics:

1.  **Client Command Characteristic**
    * **UUID**: `caf54438-9d78-4697-8886-0a4cfa87ba8d`
    * **Properties**: `WRITE` (Write without response)
    * **Purpose**: This is the primary channel for the Client (desktop) to send commands to the Server (phone). It is used to write both the `AuthenticationRequest` and the `AuthenticationCancel` messages.

2.  **Server Response Characteristic**
    * **UUID**: `ca6238be-c194-49b7-855b-58f41d3da626`
    * **Properties**: `NOTIFY`
    * **Purpose**: The Server (phone) sends the encrypted `AuthenticationGrant` or `AuthenticationDenial` message to the Client via a notification on this characteristic.