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
2. Authentication is requested for the test user via `tapauth-ipc-cli pam-auth <user> 20`.
3. `tapauthd` broadcasts `EncryptedPacket` on UDP port 36692 (and forwards a copy to emulator redirection port `36695` in dev mode).
4. `AuthenticationService` on Android receives packet, validates temporal ID, decrypts `AuthRequest`, and triggers authentication.
5. Android verifies credentials and replies with `AuthenticationGrant` signed by its Ed25519 key to `10.0.2.2:36692`.
6. `tapauthd` verifies signature, confirms grant, and returns `SUCCESS` (0) to PAM client.

### Phase 2b: Real PAM Module Authentication (`pamtester`)
1. Test suite creates temporary PAM service definition at `/etc/pam.d/tapauth-test-e2e` pointing to `libclient_pam.so`.
2. `pamtester` invokes `pam_sm_authenticate` against the real PAM C ABI.
3. `client-pam` connects to `tapauthd` over Unix socket and completes full PAM authentication returning `PAM_SUCCESS`.

### Phase 3: Bluetooth Low Energy (BLE) Authentication
1. Desktop enables BLE transport and disables UDP (`set-transports --network false --ble true`).
2. Authentication is requested over virtual BLE via Google Bumble + Netsim.
3. `tapauthd` acts as GATT Server and Peripheral advertiser (`b4ad84c0-2adb-4876-8315-b39d983b2bde`).
4. Android `BleGattService` acts as GATT Client and Central scanner, connecting to `tapauthd`'s GATT server and exchanging `AuthRequest` and `AuthenticationGrant` characteristics.
5. Verified successful authentication over BLE.

### Phase 4: Parallel Discovery Race (UDP + BLE Simultaneous)
1. Both transports enabled (`set-transports --network true --ble true`).
2. Desktop fires simultaneous discovery on UDP and BLE.
3. First responding transport wins and completes authentication cleanly without duplicate grant conflicts.

### Phase 5: Explicit User Denial
1. Authentication is requested while auto-grant helper is paused.
2. Simulated biometric rejection / `dev.rourunisen.tapauth.ACTION_DEV_DENY` broadcast is triggered.
3. Android sends signed `AuthenticationDenial`.
4. `tapauthd` returns `DENIED` outcome to PAM module.

### Phase 5b: Authentication Timeout Verification
1. Android app is paused/stopped so no device responds to the auth broadcast.
2. Authentication is requested with a 2-second timeout.
3. `tapauthd` detects deadline expiry, broadcasts `AuthenticationCancel`, and returns `TIMEOUT` outcome.

### Phase 6: Device Removal / Un-pairing
1. Desktop invokes `remove-device <server_public_key>` via admin IPC.
2. `tapauthd` purges keys and refreshes in-memory state.
3. Subsequent auth requests properly return `IGNORE` ("No paired devices configured").

---

## 3. Transport Virtualization Details

### UDP Network Bridge
Android emulators run on a virtual NAT subnet (`10.0.2.15`), where `10.0.2.2` represents the host.
- **Inbound (Host $\to$ Emulator)**: in dev mode (`TAPAUTH_DEV_MODE`, feature `dev-state-override`) the daemon additionally unicasts every request to `127.0.0.1:36695` (configurable via `TAPAUTH_DEV_UDP_TARGET`), which `adb emu redir add udp:36695:36692` forwards directly into the guest emulator.
- **Outbound (Emulator $\to$ Host)**: Android replies directly to `senderAddress.hostAddress:appConfig.udpPort` (`10.0.2.2:36692`), which SLIRP delivers to the daemon's `[::]:36692` socket. The dev-mode loopback filter exception allows the daemon to accept loopback packets.

### Virtual BLE Bridge (Google Bumble + Netsim)
Android emulators provide an internal Bluetooth simulation service called **Netsim** on gRPC port 8554.
- `bumble-hci-bridge` connects to `android-netsim:localhost:8554` and bridges HCI packets to Linux `/dev/vhci`.
- BlueZ on Linux discovers the virtual controller and exposes it as a standard Bluetooth adapter (e.g. `hci1`).
- `tapauthd` publishes its GATT service and BLE advertisements via BlueZ, and the Android emulator scans and connects.

---

## 4. Running the Tests

### In CI (GitHub Actions)
E2E testing runs automatically in `.github/workflows/ci-android.yml` on every pull request and push to `main`.

### Locally (Unprivileged / No `sudo`)
The test runner is designed to run completely unprivileged without `sudo` by using isolated sandbox directories:
- `TAPAUTH_STATE_DIR`: Isolated state directory (`/tmp/tapauth-e2e.XXXXXX/state`).
- `TAPAUTHD_SOCK`: Isolated Unix socket (`/tmp/tapauth-e2e.XXXXXX/tapauthd.sock`).
- `TAPAUTH_DEV_MODE=1`: Bypasses system PolKit daemon for same-UID/root callers on the isolated dev socket, authorizing the process owner for test automation. (Note: Production daemon runs with full PolKit authorization enforcement).

#### Prerequisites
1. Have an Android emulator running (API 33 to 36):
   ```bash
   emulator @<your_avd_name>
   ```
2. Build Android E2E APKs:
   ```bash
   cd server-android && ./gradlew assembleE2e assembleDebugAndroidTest
   ```
   *(Note: The `e2e` build variant enables automated headless auto-approval and denial simulation; standard `debug` and `release` builds require real physical/biometric user interaction).*

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

> [!NOTE]
> Standard Linux developer workstations (running generic Linux kernels with `hci_vhci` module support) execute all phases including Phase 3 (BLE) and Phase 4 (Parallel Race).
> Cloud CI runners (such as GitHub Actions Ubuntu Azure VM runners) run cloud-optimized kernels (`linux-azure`) without Bluetooth subsystem drivers (`CONFIG_BT=n`, `hci_vhci` not compiled), where `test-e2e.sh` automatically detects kernel capabilities and runs all TCP pairing, SAS verification, UDP authentication, PAM module, Denial, Timeout, and Lifecycle phases.
