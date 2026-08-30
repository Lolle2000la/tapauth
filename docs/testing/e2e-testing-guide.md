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

The master test runner (`scripts/test-e2e.sh`) executes the following test phases (2c/2d run whenever a UDP grant packet could be captured, 2e/2e' whenever `pamtester` is available, and 7 in systemd mode):

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

### Phase 2e: Mixed-Stack PAM Semantics
1. A "real world" PAM stack is installed: `auth [success=1 default=ignore] pam_tapauth.so` followed by `pam_unix.so`.
2. **Grant path**: with the device still paired, `pamtester` authenticates while feeding a deliberately wrong password on stdin — `pam_sm_authenticate` must return `PAM_SUCCESS` and the `[success=1]` jump must skip the password module entirely.
3. **Fallback path** (Phase 6b, after un-pairing): `TapAuth` returns `PAM_IGNORE`, so `pam_unix` decides — a correct password must succeed and a wrong password must be rejected.

### Phase 2c: Adversarial UDP — Replay & Cancel
1. The legitimate `AuthenticationGrant` from Phase 2 is captured with `tcpdump` and re-injected (via `scripts/ci/udp_attack.py`) while a **fresh** auth session is pending.
2. The daemon must reject the stale-session grant (challenge mismatch audit log) and detect the immediate duplicate via its per-session nonce cache ("Replayed packet detected").
3. The pending session is then cancelled via the `pam-cancel` IPC command; the blocked PAM client must exit promptly with `OUTCOME=IGNORE` (never `SUCCESS`).

### Phase 2d: Adversarial UDP — Tampered Ciphertext
1. The captured grant is re-injected with one flipped bit inside the AES-256-GCM tag (protobuf framing and temporal identifier stay intact).
2. The daemon must fail AEAD verification, abort the session fail-closed (`OUTCOME=IGNORE` → PAM password fallback, never a grant), and log the decryption failure.

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
4. Phase 6b proves the mixed-stack password fallback end-to-end (see Phase 2e).

### Phase 7: Admin IPC Authorization Enforcement (systemd mode)
1. An unprivileged user **in** the `tapauthd-clients` group (i.e. past the socket permission gate) sends an admin request — the daemon must deny it via PolKit (`auth_admin`, no interactive agent) and log the attempt.
2. A user **outside** `tapauthd-clients` must not even be able to connect to `/run/tapauthd/tapauthd.sock`.
3. Together with the on-disk assertions (`/var/lib/tapauth` mode 700 `tapauthd:tapauthd`, key files 600, IPC socket 660 `root:tapauthd-clients`, `/etc/tapauth/config.toml` 644 `tapauthd:tapauthd`) this covers the daemon's core security properties.

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
CI runs in **systemd mode**: the daemon is the production-style build (systemd socket activation, no `fallback-socket`), installed as the real `tapauthd.service`/`tapauthd.socket` units, running as the unprivileged `tapauthd` user with state in `/var/lib/tapauth` and config in `/etc/tapauth/config.toml`. The only E2E-specific knob is the `TAPAUTH_DEV_UDP_TARGET` emulator delivery shim (enabled via the `TAPAUTH_DEV_MODE` environment on the unit), because a hosted runner cannot deliver LAN broadcasts into the Android emulator.

CI artifacts: `tapauth-debug-apk` contains the safe debug build; the E2E variant is uploaded separately as `tapauth-e2e-apk-UNSAFE-auto-approves` — **never install that one**, it auto-approves authentication requests when no biometrics are enrolled.

### Locally (Unprivileged / No `sudo`)
The test runner falls back to **dev mode** when not running as root under systemd, using isolated sandbox directories:
- `TAPAUTH_STATE_DIR`: Isolated state directory (`/tmp/tapauth-e2e.XXXXXX/state`).
- `TAPAUTHD_SOCK`: Isolated Unix socket (`/tmp/tapauth-e2e.XXXXXX/tapauthd.sock`).
- `TAPAUTH_DEV_MODE=1`: Bypasses system PolKit daemon for same-UID/root callers on the isolated dev socket, authorizing the process owner for test automation. (Note: Production daemon runs with full PolKit authorization enforcement).

Running locally **as root under systemd** (or with `TAPAUTH_E2E_DAEMON_MODE=systemd`) exercises the full production wiring instead — including the Phase 7 authorization checks — but mutates real system paths (`/usr/bin/tapauthd`, `/etc/tapauth`, `/var/lib/tapauth`, systemd units).

#### Prerequisites
1. Have an Android emulator running (API 33 to 36):
   ```bash
   emulator @<your_avd_name>
   ```
2. Build Android E2E APKs:
   ```bash
   cd server-android && ./gradlew assembleE2e assembleE2eAndroidTest
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
> - **In GitHub Actions CI**: The workflow dynamically builds and loads the `hci_vhci` kernel module directly against the runner's exact kernel headers, launching Google Bumble to bridge Android Netsim with BlueZ so all 8 phases (including Phase 3 BLE and Phase 4 Parallel Race) run for real.
> - **Local Workstations**: Running standard Linux distribution kernels (`linux-generic`, `linux-zen`, `arch`, etc.) already include `hci_vhci` out of the box. Running `./scripts/test-e2e.sh` executes the full suite.
