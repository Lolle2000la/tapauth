# BLE GATT Service Specification (v2)

This document specifies the Bluetooth Low Energy (BLE) advertisement format and GATT (Generic Attribute Profile) service for both **Authentication** and **Pairing** in TapAuth v2.

* **Service UUID**: `b4ad84c0-2adb-4876-8315-b39d983b2bde`

## 1. Legacy 31-Byte Advertisement Budget

Every TapAuth BLE advertisement uses the **exact 31-byte legacy BLE advertising budget** so all Linux controllers and BlueZ versions advertise reliably without requiring BLE 5.0 Extended Advertising:

| AD Structure | Byte Breakdown | Bytes |
| :--- | :--- | :--- |
| Flags (`0x01`) | `len(1) + type(1) + flags(1)` (set by BlueZ `discoverable: true`) | **3** |
| Service Data 128-bit UUID (`0x21`) | `len(1) + type(1) + UUID(16) + payload(10)` | **28** |
| Local Name | Empty (`local_name: Some("")`) | **0** |
| **Total** | | **31** (exact maximum; `service_uuids` must NOT be set) |

### Service Data Payload (10 Bytes)

The 10-byte `ServiceData[SERVICE_UUID]` value distinguishes the mode without revealing static device identity:

1. **Authentication Discovery**:
   * **Value**: First **10 bytes** of `HMAC(hash_alg, CSK, u64_be(floor(unix_time / 60)))`.
   * Matched by paired Servers' background scanner against their cached `(current_window, previous_window)` 10-byte temporal ID table.
2. **Pairing Discovery**:
   * **Value**:
     $$\text{pairing\_adv\_id} = \text{SHA-256}(\texttt{"tapauth-ble-pair-v2"} \parallel \text{session\_id} \parallel X_C)[0..10]$$
   * Advertised only while a QR-initiated pairing session is open.
   * Only the Server that just scanned the QR code knows `(sid, pk)` and configures an exact 10-byte hardware `ScanFilter` (`mask = 0xFF * 10`). Other phones see an unrecognized 10-byte value and ignore it completely (zero unsolicited pairing spam).

Once a GATT connection is established, all encrypted messages use standard `EncryptedPacket` with full **16-byte** `temporal_identifier`, and all pairing messages use `PairingPacket` with full 16-byte `session_id`.

## 2. Static 4-Characteristic GATT Service

The daemon exposes a **single static GATT service layout** under `SERVICE_UUID` (`b4ad84c0-2adb-4876-8315-b39d983b2bde`) containing all four characteristics (both authentication and pairing) whenever GATT is registered. Keeping the attribute table invariant ensures Android's per-`BD_ADDR` GATT cache is never stale when transitioning from Pairing directly into Authentication.

1. **Client Command Characteristic**
   * **UUID**: `caf54438-9d78-4697-8886-0a4cfa87ba8d`
   * **Properties**: `READ | NOTIFY`
   * **Purpose**: Delivers `EncryptedPacket(AuthenticationRequest)` (initially read by the Server upon connecting) and **real-time `EncryptedPacket(AuthenticationCancel)`** via GATT **Notification** (as well as updated value for fallback read). Subscribing to notifications eliminates the 5-second disconnect grace delay when another transport or local password cancels a session.

2. **Server Response Characteristic**
   * **UUID**: `ca6238be-c194-49b7-855b-58f41d3da626`
   * **Properties**: `WRITE` (Write With Response, acknowledged)
   * **Purpose**: The Server writes `EncryptedPacket(AuthenticationGrant)` or `EncryptedPacket(AuthenticationDenial)` to the Client, retransmitting every 500ms until confirmed or timed out.

3. **Client Confirmation Characteristic**
   * **UUID**: `ace3e9ad-5f0d-48bf-825a-5b7f4dc49cdf`
   * **Properties**: `READ | NOTIFY`
   * **Purpose**: The Client writes and **immediately notifies** `EncryptedPacket(GrantConfirmation)` after verifying the Server's grant/denial and authorizing `allowed_users`. Supporting `NOTIFY` lets the Server receive confirmation in ~15ms instead of waiting 500ms to poll `READ` (eliminating the race where Linux tore down GATT at ~410ms before Android's 500ms read poll). Linux keeps the GATT link up until confirmation delivery succeeds or times out, rather than invoking `send_cancel` on the winning BLE transport.

4. **Pairing Channel Characteristic**
   * **UUID**: `d9e8f1a2-3b4c-4d5e-8f60-7a8b9c0d1e2f`
   * **Properties**: `WRITE | NOTIFY | READ`
   * **Purpose**: Unified bidirectional channel for v2 `PairingPacket` frames:
     * **Phone $\to$ Desktop**: Server writes `PairingInit`, `PairingConfirmServer`, or `PairingAbort` via `WRITE` (Write With Response).
     * **Desktop $\to$ Phone**: Client pushes `PairingResponse`, `PairingConfirmClient`, or `PairingAbort` via GATT **Notification** (plus updates readable value as fallback).

## 3. Transport & Android/BlueZ Implementation Rules

1. **MTU 517 Negotiation**: Immediately after `STATE_CONNECTED`, the Server (Android) **must** call `gatt.requestMtu(517)` and wait for `onMtuChanged` *before* calling `gatt.discoverServices()`. Since both `EncryptedPacket` ($\le 470\text{ B}$) and `PairingPacket` ($\le 300\text{ B}$) fit under 512 bytes, negotiating MTU 517 ensures single-PDU reads, single-PDU writes, and **untruncated GATT notifications** (ATT notifications cannot be long-fragmented when payload exceeds `MTU - 3`).
2. **Event-Driven Async Reception**: On Linux (`tapauthd/src/transport/ble.rs`), incoming writes from BlueZ D-Bus handlers **must** push directly into an async `tokio::sync::mpsc` channel rather than polling a mutex queue on a 20ms sleep timer.
3. **Serialized Single In-Flight GATT Operation**: Android's `BluetoothGatt` drops concurrent operations (`readCharacteristic`, `writeCharacteristic`, `writeDescriptor`, `requestMtu`, `discoverServices`). All GATT operations on Android **must** execute sequentially through a serialized coroutine channel/mutex awaiting each callback (`onMtuChanged`, `onServicesDiscovered`, `onDescriptorWrite`, `onCharacteristicRead`, `onCharacteristicWrite`).
4. **Connection Lifecycle**:
   * **Authentication**: Held open until `GrantConfirmation` is notified/read (or 10s retransmission expires). If the BLE link drops while a prompt is pending, a **5-second** reconnect grace period applies before cancelling an unanswered prompt, unless an explicit verified `AuthenticationCancel` was already received.
   * **Pairing**: Phone subscribes to CCCD (`0x2902`) on `PAIRING_CHAR_UUID` right after `discoverServices()`, then writes `PairingInit`. The GATT link stays open across user SAS review until `PairingConfirmServer` completes or `PairingAbort` / timeout occurs.

## 4. BLE Security Best Practices

* Prefer **LE Secure Connections** when platform APIs permit, while relying unconditionally on application-layer AEAD + Ed25519 signatures (`EncryptedPacket` / `PairingPacket`) since neither Android nor Linux BlueZ exposes strict LE-SC enforcement across all adapters without OS pairing dialogs.
