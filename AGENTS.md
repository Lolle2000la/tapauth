# AGENTS.md - TapAuth

## Overview
**TapAuth** is a local-first authentication system: a Linux desktop (**Client**) unlocks via a paired Android device (**Server**) over UDP multicast or BLE.

| Term | Role | Path | Stack |
| :--- | :--- | :--- | :--- |
| **Client** | Linux desktop requesting auth | `tapauthd`, `client-pam`, `client-config-gui` | Rust |
| **Server** | Android device verifying biometrics | `server-android` | Kotlin / Compose |
| **Daemon** | Background service managing transport & crypto | `tapauthd` | Rust (Tokio) |
| **PAM** | Pluggable Authentication Module hooking into login/sudo | `client-pam` | Rust (FFI cdylib) |
| **Shared** | Protocol, crypto, networking, JNI bridge | `shared` | Rust |

## Workspace & Build Commands

### Rust crates (workspace members)
```
shared/          # lib (cdylib + rlib), build.rs generates protobuf
client-pam/      # cdylib -> installed as pam_tapauth.so
client-config-gui/ # bin "tapauth-config" (iced GUI)
tapauthd/        # bin, the systemd daemon
```

### Exact CI commands (verified)
```bash
# Build & test per crate (run from workspace root):
cargo build --manifest-path shared/Cargo.toml
cargo build --manifest-path shared/Cargo.toml --features jni
cargo build --manifest-path client-pam/Cargo.toml
cargo build --manifest-path client-config-gui/Cargo.toml
cargo build --workspace

cargo test --manifest-path shared/Cargo.toml
cargo test --manifest-path shared/Cargo.toml --features jni
cargo test --manifest-path client-pam/Cargo.toml
cargo test --manifest-path client-config-gui/Cargo.toml
cargo test --workspace

# Lint/format:
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
# ^ NOTE: --all-features may fail locally (pulls in jni, which needs libjvm/JDK headers).
#    Use per-crate feature combos from CI (see feature table below).
```

### Android
```bash
# Format Kotlin:
cd server-android && ./gradlew spotlessApply

# Check formatting:
cd server-android && ./gradlew spotlessCheck

# Unit tests (JVM):
cd server-android && ./gradlew test

# Instrumentation tests (requires emulator + native libs built; the e2e build
# variant is used for instrumented tests, see testBuildType in build.gradle.kts):
cd server-android && ./gradlew connectedE2eAndroidTest
```

## Feature Flags (critical)

| Crate | Default | Features |
|-------|---------|----------|
| `shared` | `[]` | `jni`, `tpm`, `firewall`, `dev-state-override`, `dev-udp-loopback` |
| `tapauthd` | `["ble", "firewall"]` | `ble`, `tpm`, `firewall`, `fallback-socket`, `dev-state-override`, `dev-udp-loopback`, `dev-polkit-bypass`, `dev-firewall-bypass`, `dev-socket-override` |
| `client-pam` | `[]` | `tpm`, `dev-socket-override` |
| `client-config-gui` | `[]` | `tpm`, `dev-socket-override` |

Each dev knob is **separately** feature-gated so a test build can enable exactly one
of them. The UDP shim, its receive-filter bypass and the PolKit bypass additionally
require `TAPAUTH_DEV_MODE=1` at runtime, so a shipped binary cannot be toggled by the
environment alone:

| Dev feature | Env var it honours | What it does |
| :--- | :--- | :--- |
| `dev-state-override` (`shared`, `tapauthd`) | `TAPAUTH_STATE_DIR` | Relocates the state dir (and `config.toml` inside it) |
| `dev-udp-loopback` (`shared`, `tapauthd`) | `TAPAUTH_DEV_UDP_TARGET` | Unicasts packets to a local peer and accepts locally-sourced replies (emulator) |
| `dev-polkit-bypass` (`tapauthd`) | `TAPAUTH_DEV_MODE` | Skips the PolKit check for same-UID/root callers so headless harnesses need no agent |
| `dev-firewall-bypass` (`tapauthd`) | — (compile-time only) | Continues pairing when the firewall port cannot be opened (containers without usable `iptables`). Production builds abort pairing instead. Covered by the binary-string scanners via its cfg'd warning literal |
| `dev-socket-override` (`client-pam`, `client-config-gui`, `tapauthd`) | `TAPAUTHD_SOCK` | Redirects the IPC client to another socket. On `tapauthd` the feature only affects the `tapauth-ipc-cli` admin tool; the daemon itself always uses the systemd-activated socket in production |

**Gotchas:**
- `--all-features` **may not work locally** — it pulls in `jni` which requires `libjvm`/JDK headers. If you have a JDK installed, it should compile; otherwise use per-crate feature combos from CI.
- **`client-pam` has NO `ble` feature** (it's a thin IPC client that talks to tapauthd via Unix socket). Do not pass `--features ble` to it.
- **`fallback-socket`** on `tapauthd`: production uses systemd socket activation (FD#3). For dev/testing, rebuild tapauthd with `--features fallback-socket` to bind the Unix socket manually. Pulls in all five daemon dev knobs above (`dev-state-override`, `dev-udp-loopback`, `dev-polkit-bypass`, `dev-firewall-bypass`, `dev-socket-override`) — i.e. it is a full local sandbox build.
- The **E2E suite's systemd mode** runs against the installed packages: the Ubuntu pass on the host, and the Fedora/Arch passes inside containers that boot real systemd (PID 1) and run their own D-Bus, polkitd and bluetoothd. All three enable only `dev-udp-loopback,dev-polkit-bypass` (NOT `dev-state-override`), so state/config/socket paths stay production while the emulator transport shim works; the Fedora/Arch containers additionally enable `dev-firewall-bypass` (containers lack usable `iptables`). BLE runs everywhere (the host owns the Bumble bridge; each container's own bluetoothd owns the resulting vhci adapter), and Phase 7 exercises the package's installed PolKit action under the container's polkitd.
- `tpm` propagates through all crates via `shared/tpm`. Requires `tpm2-tools` on the system.
- **Production builds must NOT enable any `dev-*` feature** (nor `fallback-socket`/`dev-socket-override`): they would allow environment-controlled socket/state redirection. `scripts/ci/check-production-build.sh` (run in CI) enforces this by building the shipped artifacts per crate and failing if a dev env-var name survives into them; `packaging/tapauth.spec` `%build` and `packaging/debian/rules` `override_dh_auto_build` both refuse `dev-*`/`fallback-socket` unless the explicit `allow_test_features=1` / `ALLOW_TEST_FEATURES=1` test opt-in is set, so a plain local `rpmbuild`/`dpkg-buildpackage` cannot inject them. Beware that Cargo unifies features **per package across a workspace build**: `cargo build --workspace --features tapauthd/fallback-socket` compiles `shared/dev-state-override` into the GUI and PAM module too, even though neither asks for it — build shipped artifacts per crate (as `install.sh` does).

## Development Quick Start
```bash
# Create system users/groups and /var/lib/tapauth (needs root):
sudo ./create-dev-users.sh

# Run daemon in dev mode:
cargo run --manifest-path tapauthd/Cargo.toml --features fallback-socket --no-default-features

# Run GUI for pairing:
cargo run --manifest-path client-config-gui/Cargo.toml

# PAM module (built as libclient_pam.so, installed as pam_tapauth.so):
cargo build --manifest-path client-pam/Cargo.toml
```

## Protobuf Codegen
- Proto definitions: `proto/auth_protocol.proto`, `proto/ipc.proto`
- Generated by `shared/build.rs` into `shared::protocol::pb` and `shared::ipc::pb`
- **After editing a `.proto` file**, at minimum rebuild `shared` and `tapauthd`. If the Android JNI surface changed, also rebuild native libs for Android.

## Architecture Notes

### Daemon IPC protocol (Unix socket)
- `tapauthd` listens on `/run/tapauthd/tapauthd.sock` (systemd socket activation, FD#3, or manual bind with `fallback-socket`)
- Length-prefixed framing: 4-byte BE u32 length + protobuf body
- **All messages are wrapped in `IpcEnvelope`** (`oneof msg`) for unambiguous dispatch:
  - **PAM ops**: `PamAuthenticateRequest` / `PamCancelRequest` / `PamAuthenticateResponse`
  - **Admin ops**: `AdminRequest` / `AdminResponse` with multiple request/response variants
- Admin request variants: `GetServers`, `StartPairing`, `WaitForPairing`, `CompletePairing`, `RemoveDevice`, `RotateCsk`, `SaveConfig`, `RecoverTpm`, `GetConfig`, `GetDaemonStatus`
- `PamAuthenticateResponse` outcome: `Granted`/`Denied`/`Ignore`/`Error`

### Admin IPC Authorization (PolKit)
- The daemon is the **single writer** of all config files (`/var/lib/tapauth/`, `/etc/tapauth/config.toml`).  The GUI and PAM module never write config files directly.
- After admin mutations (pairing, device removal, CSK rotation), the daemon calls `DaemonState::reload()` to refresh in-memory state from disk without restarting.
- The daemon resolves the caller's identity via `SO_PEERCRED` (PID, UID → username + `/proc/PID/stat` start-time)
- Authorization is enforced daemon-side via `PolicyKit1.Authority.CheckAuthorization` with `unix-process` subject
- The `tapauthd` user is registered as an action owner (`org.freedesktop.policykit.owner`) via `tapauthd/dev.rourunisen.tapauth.config.admin.policy` to permit cross-identity queries
- Falls back to UID==0 check when D-Bus/PolKit is unavailable
- Socket permissions serve as an additional access gate: `root:tapauthd-clients 0660`

### PAM Module (`client-pam`)
- Built as `libclient_pam.so`, installed to distro-specific PAM dir as `pam_tapauth.so`
- Never returns `PAM_IGNORE`: Linux-PAM records no failure for it, so on a `required` stack like `auth required pam_tapauth.so` + `auth optional pam_permit.so` + `auth required pam_env.so` the whole stack would succeed. Failures map to `PAM_AUTHINFO_UNAVAIL` (no paired device, skip, timeout, daemon unreachable), `PAM_AUTH_ERR` (processing failure), `PAM_PERM_DENIED` (explicit denial on the phone) or `PAM_USER_UNKNOWN` (username lookup failed). What that buys is the `required` shape: there `PAM_IGNORE` is explicitly `ignore` while `PAM_AUTHINFO_UNAVAIL` is `bad`. On a `sufficient` line (`[success=done … default=ignore]`) both codes are `ignore`, so a following `optional pam_permit` grants either way and only the stack's configuration prevents it — the `bypass` E2E covers that `required` shape, not the `sufficient` one. Two `pam_tapauth.so` lines in one stack are now one check: the second line's transaction is answered from the recorded verdict instead of ringing the phone again.
- Wraps all IPC messages in `IpcEnvelope`, unwraps `PamResponse` from envelope
- Custom PAM FFI bindings in `pam_sys.rs` (not `pam-bindings` crate — known issues with pamtester)
- A per-process, per-`(username, service)` 500 ms verdict-reuse window returns the just-concluded code (success **or** failure) without contacting the daemon, absorbing a duplicate `pam_authenticate` some lock screens issue right after a transaction concludes (kscreenlocker ≥ 6.8 re-enters 0.37 ms later); a different user or a different PAM service always takes the normal path and rings the phone, and a new process always misses because `pam_end` unloads the module. The remaining scope is an **assumption, not a property**: no legitimate host performs an independent authentication for the same user and PAM service within 500 ms of a concluded one, and a human-initiated retry takes seconds — the `(username, service)` key cannot tell such a request apart from a duplicate
- **GUI (no-TTY) contexts use one of three flows**, chosen by *process name* (`/proc/self/exe`'s basename, falling back to `/proc/self/comm`) in `conversation_mode()`, with two service-driven branches: GDM decides from the service name (`gdm-password`) plus `GDM_SESSION_FOR_REAUTH` in the environment, and when `/proc` cannot be read the `polkit-1` service keeps the historic threaded behaviour. The display-manager bypass runs before either:
  - **Threaded** (`polkit-agent-helper-1`, `kscreenlocker_worker` ≥ 6.8, `hyprlock`, `authproto_pam` for xsecurelock, and `gdm-session-worker` during a `gdm-password` *reauthentication*): password is collected on a worker thread while the main thread waits for the phone. Each host is listed only because its conversation stays answerable while that thread is blocked — polkit's is a plain fd fed by a separate process, kscreenlocker ≥ 6.8 answers on Qt's D-Bus daemon thread, xsecurelock answers from its own thread pool, and `hyprlock` answers concurrently with a known accepted residual risk (`resetConversation`/`checkWaiting` unsynchronised). xsecurelock's `CallPAMWithRetries` re-runs `pam_authenticate` up to 3× for every status except `ABORT`, `MAXTRIES`, `NEW_AUTHTOK_REQD` and `SUCCESS`, so an explicit denial can ring the phone up to three times too — except for retries that land inside the 500 ms verdict-reuse window, which are answered from the recorded denial without ringing (see the bullet above). This is a deadlock heuristic, not a trust boundary
  - **PreCollected** (`swaylock`, `gtklock`, `i3lock`): these read the password *before* calling `pam_authenticate` (swaylock `pam.c:51`, gtklock `auth.c:61`, i3lock `i3lock.c:836`) and their conversation is a synchronous replay of it. The module calls `pam_get_authtok` directly on the calling thread — which caches `PAM_AUTHTOK` for the next module (`pam_unix` with `try_first_pass`/`use_first_pass`) — and returns `PAM_AUTHINFO_UNAVAIL` immediately. The daemon is deliberately never contacted: the user already chose the password route, so ringing the phone could only be misleading and time out. On these hosts the phone is therefore not a credential at all — it is never rung and nothing is verified — so a stack with no password module after `pam_tapauth.so` cannot unlock
  - **Sequential** (everything else — `kscreenlocker_greet` deliberately, kscreenlocker ≤ 6.7, and `xfce4-screensaver-dialog`/`mate-screensaver-dialog` among them; on kscreenlocker ≤ 6.7 the answer is posted back to the thread that called `pam_authenticate`, and the screen savers park in GLib's `g_cond_wait`, a bare futex with no cancellation point, so a threaded reply could never be abandoned and the lock screen would freeze): the conversation is **never** driven while waiting; the module waits for the daemon on the calling thread for `pam_gui_timeout_secs` (default 30s, clamped to `pam_operation_timeout_secs`), then falls through to password. Driving the conversation from a thread on those hosts deadlocks their event loop (see `run_sequential_event_loop` docs in `pam_logic.rs`)
  - **Display-manager bypass**: the module returns `PAM_AUTHINFO_UNAVAIL` unexamined for DM services (`gdm-…`, `sddm…`, `lightdm`, …) so the login manager still populates `PAM_AUTHTOK` and the keyring unlocks. A GDM **reauthentication** is exempt (`is_gdm_reauth`: `gdm-password` + `GDM_SESSION_FOR_REAUTH`): unlock runs no session/setcred phase, so the keyring reason does not apply. A missing or renamed variable degrades to the bypass/sequential default, never to a deadlock

### Authentication "Race" Flow
1. `client-pam` sends IPC request to `tapauthd`
2. `tapauthd` multicasts via UDP (port 36692) **and** starts BLE advertising simultaneously
3. Android device replies on the same transport
4. First valid `Grant` wins; `tapauthd` signals `client-pam`

### JNI Boundary (Android)
- **Kotlin never parses Protobuf.** Raw `ByteArray` messages are passed to Rust JNI (`jni_api.rs`) for validation, decryption, and parsing.
- JNI crypto tests (`TapAuthCryptoTest.kt`) are **instrumentation tests** requiring an emulator/device.
- Native build for Android is handled by the `org.mozilla.rust-android-gradle` plugin in `app/build.gradle.kts` (the `cargo` block), not by a standalone script.

### GUI Framework
- `client-config-gui` uses **iced** (Rust GUI framework), not GTK. Requires X11 or Wayland.
- Runs **unprivileged** — all privileged operations (pairing, device management, config changes) are delegated to `tapauthd` via admin IPC.
- Authorization is enforced daemon-side via PolKit; socket permissions gate access.

### Transport Details
- **UDP port 36692** (default, user-configurable). IPv4 multicast **`239.255.26.44`** (IPv4 Local Scope, RFC 2365) + IPv6 multicast **`ff12::fdec:fc27`** (transient link-local; low 32 bits in the IANA private-use group-ID range, RFC 10028). The daemon sends on every suitable interface; paired Android devices join both groups.
- **BLE**: Service UUID `b4ad84c0-2adb-4876-8315-b39d983b2bde`. GATT characteristic UUIDs are in `docs/design-documents/protocol/ble-gatt-specification.md`.
- **Pairing uses TCP** (not UDP). QR code URL format: `tapauth://pair?v=1&pk=<hex>&p=<port>&ip4=<ipv4>&ip6=<ipv6>`.

### Cryptography Quick Reference
- **X25519** for key exchange, **Ed25519** for signatures, **AES-256-GCM** for symmetric encryption.
- **AES-GCM nonces**: 12-byte cryptographically random, prepended to ciphertext. **NEVER reuse** a nonce with the same key.
- **PSK** (Pairing Symmetric Key): ephemeral, derived from ECDH, **must be discarded after pairing**.
- **CSK** (Client Symmetric Key): one per Client, shared with all paired Servers. Stored long-term.

### Key Storage
- **Android**: Android Keystore System (hardware-backed where available).
- **Linux**: TPM 2.0 preferred (`tpm` feature). Fallback: root-owned `/var/lib/tapauth/` with mode 700/600.

### Replay & DoS Protections
- **Two replay checks**: nonce cache (primary, 120s TTL) + timestamp window (secondary, 60s).
- **Pre-authentication DoS**: temporal IDs are pre-computed per 60s window into a hash set for O(1) checks before crypto.
- **Post-authentication rate limiting**: escalating backoff (1s → 2s → 4s → max 5s) per Client public key.

### Retransmission
- **Client** (`AuthenticationRequest`): exponential backoff (200ms → 400ms → 800ms → ...).
- **Server** (`AuthenticationGrant`/`Denial`): fixed 500ms, up to 10s. Stops when `GrantConfirmation` received.
- Client **must** resend `GrantConfirmation` up to 3 times if further retransmissions arrive.

### Design Documents
- Full protocol specs live in `docs/design-documents/protocol/`. Key files:
  - `authentication-flow.md` — message sequencing, retransmission, replay protection
  - `ble-gatt-specification.md` — BLE UUIDs and characteristic definitions
  - `cryptography-specification.md` — algorithm choices, nonce management
  - `initial-key-exchange.md` — pairing QR format, SAS verification
  - `security-hardening.md` — key storage, rate limiting, DoS mitigation
  - `device-lifecycle.md` — un-pairing, key rotation

## Security Constraints
- **Rust is the source of truth** for protocol logic, crypto, and packet structure.
- **No static identifiers** in cleartext during authentication (use rotating temporal IDs, HMAC-SHA256 of 60s time window).
- **Replay protection**: challenge nonces + 60-second timestamp window. Do not remove these checks.
- **Config files**: mode 600 for files, 700 for directories under `/var/lib/tapauth/`, owned by `tapauthd` user.

## Distribution Packaging
- `packaging/arch/PKGBUILD` is the **release** package (`tapauth`): `release-arch.yml`
  substitutes the release `pkgver` and the tagged tarball checksum.
- `packaging/arch-git/PKGBUILD` is the **VCS** package (`tapauth-git`): it sources
  `main` and `release-arch-git.yml` rewrites `pkgver` on every push to `main` (and
  regenerates `.SRCINFO`), so AUR helpers see each new commit.
- **The two PKGBUILDs intentionally duplicate the package payload. Whenever you add,
  remove, or rename an installed file, change `depends`/`optdepends`/`makedepends`,
  or change a build flag, edit BOTH `packaging/arch/PKGBUILD` and
  `packaging/arch-git/PKGBUILD`.** For the same reason,
  `packaging/arch/tapauth.install` and `packaging/arch-git/tapauth-git.install` are
  kept byte-identical and must be updated together.

## CI & Merge Queue
- **Merge queue (payload written, not applied).** `scripts/ci/merge-queue-ruleset.json` is the
  payload that would make `main` require a merge queue (ruleset `16779046`); it is never applied
  by CI, an admin PUTs it by hand in the documented order. Setup, the path-filter rule, and the
  apply/verify/rollback commands: `docs/ci/merge-queue.md`.
- **Required-check job names are load-bearing.** The payload matches eight `name:` strings exactly
  — the three jobs in `ci.yml` and all five in `ci-android.yml`, E2E included. Renaming a required
  job silently stalls the queue (nothing reports the new name, so every entry waits out
  `check_response_timeout_minutes`); `scripts/ci/check-required-checks.sh` is the guard and runs
  in CI.
- **Both workflows must stay unfiltered on `pull_request:`.** A required check cannot be
  path-filtered: a skipped run leaves it `Pending` forever and the PR can be neither merged nor
  queued. The `push:` filters stay on purpose (the merge group already validated the change), and
  no `merge_group` trigger may carry `paths:` — GitHub supports none on that event.

## Configuration
- Default config at `/etc/tapauth/config.toml` (see `config.toml.example`)
- Key settings: `udp_port` (default 36692), `pam_operation_timeout_secs` (default 120), `use_tpm` (default false), `enable_network` (default true, Local Network/UDP transport), `enable_ble` (default true, BLE transport). The transport toggles take effect on the next authentication attempt without a daemon restart and can be changed via admin IPC (Settings screen in the GUI; requires PolKit admin authorization).
- **`/etc/tapauth` posture** (all packages): the directory is `root:root 0755`; `config.toml` is created at install time by `packaging/tmpfiles.conf` owned `tapauthd:tapauthd 0644` (no secrets in it; keys live under `/var/lib/tapauth`, 0700). The daemon is the single writer, so a root-owned file would make the first `SaveConfig` fail with `EACCES`. `install.sh` establishes the same posture. tmpfiles `f` preserves the file's content on upgrades but re-asserts that owner/mode on every `systemd-tmpfiles --create`, so config edits survive while a manually changed mode/owner does not. Debian `purge` removes the generated `config.toml` along with the pairing state; `remove` preserves it.

## Docker Dev Environment
```bash
docker compose -f docker-compose.dev.yml up -d
docker exec -it tapauth-dev bash
# Inside container: build-tapauth, test-tapauth, test-pam-auth, run-gui
```
