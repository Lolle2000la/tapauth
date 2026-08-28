# TapAuth End-to-End (E2E) Testing Guide

This document describes the automated end-to-end (E2E) test harness for TapAuth, which tests the complete system lifecycle against a real Android device/emulator without mocks.

---

## 1. Overview & Test Architecture

The E2E test stack validates the real cryptographic protocols, daemon state machine, IPC boundary, PAM module, network transports (TCP/UDP), and Bluetooth Low Energy (BLE) GATT stack.

```
┌─────────────────────────────────────────────────────────────┐
│                       Linux Desktop                         │
│                                                             │
│  ┌──────────────────┐    IPC Socket     ┌────────────────┐  │
│  │ tapauth-ipc-cli  │ ◄───────────────► │    tapauthd    │  │
│  │ (or pamtester)   │                   │    (Daemon)    │  │
│  └──────────────────┘                   └───────┬───┬────┘  │
│                                                 │   │       │
│                             UDP Broadcast (36692)   │ BLE   │
│                             TCP Pairing (Dynamic)   │ GATT  │
│                                                 │   │       │
└─────────────────────────────────────────────────┼───┼───────┘
                                                  │   │
                          Local Network / NetSim  │   │ /dev/vhci + Bumble
                                                  ▼   ▼
┌─────────────────────────────────────────────────────────────┐
│                      Android Emulator                       │
│                                                             │
│  ┌───────────────────────┐        ┌──────────────────────┐  │
│  │  PairingClient (TCP)  │        │ AuthenticationService│  │
│  │  PairingE2eTest       │        │ BleGattService       │  │
│  └───────────┬───────────┘        └──────────┬───────────┘  │
│              ▼                               ▼              │
│  ┌───────────────────────┐        ┌──────────────────────┐  │
│  │   DeviceRepository    │        │  Android Biometrics  │  │
│  │ (Encrypted / Keystore)│        │  (Fingerprint touch) │  │
│  └───────────────────────┘        └──────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Test Lifecycle Phases

The master test runner (`scripts/test-e2e.sh`) executes 6 comprehensive test phases:

### Phase 1: Real TCP Pairing & SAS Anti-MITM Verification
1. `tapauthd` generates a dynamic TCP listener port and ephemeral X25519 pairing keypair.
2. Android emulator runs `PairingE2eTest` (`adb shell am instrument ...`) connecting to host `10.0.2.2:<port>`.
3. Handshake executes:
   - `PairingHello` with Android public keys.
   - `PairingResponse` with Desktop public keys.
   - Both derive ephemeral PSK via ECDH and compute 6-digit Short Authentication String (SAS).
4. Desktop and Android assert identical SAS codes (`XXX-XXX`).
5. Desktop transmits AES-256-GCM encrypted Client Symmetric Key (CSK).
6. Android stores paired desktop in `DeviceRepository`.

### Phase 2: Local Network (UDP) End-to-End Authentication
1. Desktop enables UDP transport and disables BLE via admin IPC (`set-transports --network true --ble false`).
2. PAM authentication is requested for the test user via `tapauth-ipc-cli pam-auth <user> 20`.
3. `tapauthd` broadcasts `EncryptedPacket` with rotating 60s temporal ID on UDP port 36692.
4. `AuthenticationService` on Android receives packet, validates temporal ID, decrypts `AuthRequest`, and triggers BiometricPrompt.
5. Automated test helper touches enrolled fingerprint (`adb emu finger touch 1`).
6. Android replies with `AuthenticationGrant` signed by its Ed25519 key.
7. `tapauthd` verifies signature, returns `SUCCESS` (0) to PAM client.

### Phase 3: Bluetooth Low Energy (BLE) Authentication
1. Desktop enables BLE transport and disables UDP (`set-transports --network false --ble true`).
2. Authentication is requested over virtual BLE via Google Bumble + Netsim.
3. `tapauthd` GATT client connects to Android GATT peripheral (`dev.rourunisen.tapauth.ble.BleGattService`).
4. Exchanging `AuthRequest` and `AuthenticationGrant` characteristics.
5. Verified successful authentication over BLE.

### Phase 4: Parallel Discovery Race (UDP + BLE Simultaneous)
1. Both transports enabled (`set-transports --network true --ble true`).
2. Desktop fires simultaneous discovery on UDP and BLE.
3. First responding transport wins and completes authentication cleanly without duplicate grant conflicts.

### Phase 5: Explicit User Denial
1. Authentication is requested while auto-grant helper is paused.
2. Android triggers negative biometric rejection (`finger touch 2` or back/cancel event).
3. Android sends signed `AuthenticationDenial`.
4. `tapauthd` returns `DENIED` outcome to PAM module.

### Phase 6: Device Removal / Un-pairing
1. Desktop invokes `remove-device <server_public_key>` via admin IPC.
2. `tapauthd` purges keys and refreshes in-memory state.
3. Subsequent auth requests properly return `IGNORE` ("No paired devices configured").

---

## 3. Transport Virtualization Details

### UDP Network Bridge
Android emulators run on a virtual NAT subnet (`10.0.2.15`), where `10.0.2.2` represents the host.
- **Inbound (Host $\to$ Emulator)**: `adb emu redir add udp:36692:36692` maps host localhost to guest port 36692. A background reflector on the host (`/tmp/udp_reflector.py`) listens on `0.0.0.0:36692` (with `SO_REUSEPORT`) and forwards broadcast packets to `127.0.0.1:36692`.
- **Outbound (Emulator $\to$ Host)**: Android replies directly to `packet.address` (`10.0.2.2:36692`), reaching `tapauthd` directly.

### Virtual BLE Bridge (Google Bumble + Netsim)
Android emulators provide an internal Bluetooth simulation service called **Netsim** on gRPC port 8554.
- `bumble-hci-bridge` connects to `android-netsim:localhost:8554` and bridges HCI packets to Linux `/dev/vhci`.
- BlueZ on Linux discovers the virtual controller and exposes it as a standard Bluetooth adapter (e.g. `hci1`).
- `tapauthd`'s native BLE stack discovers and communicates with the emulator using standard Linux BlueZ APIs.

---

## 4. Running the Tests

### In CI (GitHub Actions)
E2E testing runs automatically in `.github/workflows/ci-android.yml` on every pull request and push to `main`.

### Locally (Unprivileged / No `sudo`)
The test runner is designed to run completely unprivileged without `sudo` by using isolated sandbox directories:
- `TAPAUTH_STATE_DIR`: Isolated state directory (`/tmp/tapauth-e2e.XXXXXX/state`).
- `TAPAUTHD_SOCK`: Isolated Unix socket (`/tmp/tapauth-e2e.XXXXXX/tapauthd.sock`).
- `TAPAUTH_DEV_MODE=1`: Bypasses system PolKit daemon and authorizes the process owner.

#### Prerequisites
1. Have an Android emulator running (API 33+ or 34):
   ```bash
   emulator @<your_avd_name>
   ```
2. Build Android debug APKs:
   ```bash
   cd server-android && ./gradlew assembleDebug assembleDebugAndroidTest
   ```

#### Run Test Suite
```bash
./scripts/test-e2e.sh
```

---

## 5. One-Time Setup for Local Virtual BLE (`/dev/vhci`)

To allow non-root access to `/dev/vhci` for virtual Bluetooth controller creation, configure this once:

```bash
# Ensure kernel module is loaded
sudo modprobe hci_vhci

# Add udev rule for persistent non-root access
echo 'KERNEL=="vhci", MODE="0666"' | sudo tee /etc/udev/rules.d/99-vhci.rules
sudo udevadm control --reload-rules && sudo udevadm trigger

# Immediate permissions for current boot session:
sudo chmod 666 /dev/vhci
```

If `/dev/vhci` is not writable, `test-e2e.sh` will automatically log a notice and run the complete TCP pairing, UDP authentication, Denial, and Unpairing test phases while gracefully skipping virtual BLE.
