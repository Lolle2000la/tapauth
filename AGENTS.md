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
fuzz/            # cargo-fuzz crate (nightly) - excluded from the workspace, `exclude = ["fuzz"]`
```

That list is the workspace; `fuzz/` is not a member and nothing here builds it (its own
`fuzz/Cargo.lock` pins its dependencies).

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
# The one CI step that *runs* the dev-udp-loopback wire test
# (transport::udp::tests::a_spoofed_source_on_the_wire_is_not_recorded). The test
# is behind `#[cfg(feature = "dev-udp-loopback")]` in
# tapauthd/src/transport/udp.rs, so a default-feature `cargo test` does not
# even compile it; only the clippy steps that enable that feature do (the
# receive-filter bypass it needs lives behind it in `shared`), which is why this
# step is the only place it runs:
cargo test -p tapauthd --no-default-features --features dev-udp-loopback
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

## Rust Conventions
- **Module layout**: a module is `foo.rs`, plus a `foo/` directory for its children — not `foo/mod.rs`. No crate in the workspace has one today and that is the intended state; the only exception is a test setup that genuinely requires `mod.rs`, and then the commit message must say why.
- **Moving or renaming a module**: use `git mv` so history follows, and update the module lists in `client-pam/src/source_guards.rs` in the same commit. The scans cover exactly what those lists name, so a stale entry silently narrows them; the walker resolves only the flat `NAME.rs` form, so a module left at `NAME/mod.rs` drops out of every scan. `the_walker_separates_test_modules_from_production` asserts the lists match the tree.
- **Naming**: name code after the thing it describes, not a design document's numbering — hence the `RuleId` variants are `RemoteRefuse`, `DmLoginBypass`, `PreCollectedLocks`.

## Feature Flags (critical)

| Crate | Default | Features |
|-------|---------|----------|
| `shared` | `[]` | `jni`, `cli`, `tpm`, `firewall`, `dev-state-override`, `dev-udp-loopback`, `fuzz-api` |
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
- **`fuzz-api`** exists only for the `fuzz/` crate (two `#[doc(hidden)]` delegates to crate-private predicates) and no shipped build enables it. `fuzz/` is a `cargo-fuzz` crate excluded from the workspace, so `cargo test/clippy --workspace` never compiles it.
- `shared`'s `uniffi` dependency is pulled in only by its `jni` and `cli` features (`jni` for the exported Kotlin surface, `cli` for the `uniffi-bindgen` bin), so no other workspace crate gains it.
- `--all-features` **is not a substitute for the per-crate feature combos CI uses** — it additionally builds the `uniffi-bindgen` binary (`cli`) and enables the entire FFI surface (`jni`), neither of which the shipped artifacts want; build the crate you are checking with its own feature set instead.
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
- Length-prefixed framing: 4-byte BE u32 length + protobuf body, written and read by one implementation (`shared::ipc::framing`) that every endpoint uses, with one 10 MiB cap (`MAX_FRAME_LEN`) enforced on **both** directions (`encode_len` and `decode_len`), so a producer cannot put a frame on the wire that a reader would refuse. The cap bounds what a peer may make us allocate, not what the protocol may carry: the daemon is the trusted writer and the only reader whose socket a privileged peer can reach (root-owned, `0660 root:tapauthd-clients`), and no message in `proto/ipc.proto` comes near either bound.
- **All messages are wrapped in `IpcEnvelope`** (`oneof msg`) for unambiguous dispatch:
  - **PAM ops**: `PamAuthenticateRequest` / `PamCancelRequest` / `PamAuthenticateResponse`
  - **Admin ops**: `AdminRequest` / `AdminResponse` with multiple request/response variants. The pairing `port` (`WaitForPairing`/`CompletePairing`/`CancelPairing` requests, `StartPairing`/`WaitForPairing` responses) is `optional uint32`: absence means a BLE-only session and is the only spelling for it, while a present value must be a real port — `Some(0)` and anything above `65535` are refused, not read back as absence (`check_requested_port` / `advertised_port`, `tapauthd/src/admin_handler/pairing.rs`)
- Admin request variants: `GetServers`, `StartPairing`, `WaitForPairing`, `CompletePairing`, `RemoveDevice`, `RotateCsk`, `SaveConfig`, `RecoverTpm`, `GetConfig`, `GetDaemonStatus`, `CancelPairing`
- `PamAuthenticateResponse` outcome (`PamOutcome` in `proto/ipc.proto:20-26`): `Success`/`Denied`/`Timeout`/`Ignore`/`Error`

### Admin IPC Authorization (PolKit)
- The daemon is the **single writer** of all config files (`/var/lib/tapauth/`, `/etc/tapauth/config.toml`).  The GUI and PAM module never write config files directly.
- After admin mutations (pairing, device removal, CSK rotation), the daemon calls `DaemonState::reload()` to refresh in-memory state from disk without restarting.
- The daemon resolves the caller's identity via `SO_PEERCRED` (PID, UID → username + `/proc/PID/stat` start-time)
- Authorization is enforced daemon-side via `PolicyKit1.Authority.CheckAuthorization` with `unix-process` subject
- The `tapauthd` user is registered as an action owner (`org.freedesktop.policykit.owner`) via `tapauthd/dev.rourunisen.tapauth.config.admin.policy` to permit cross-identity queries
- Falls back to UID==0 check when D-Bus/PolKit is unavailable
- Socket permissions serve as an additional access gate: `root:tapauthd-clients 0660`

### Caller Context Shown on the Phone
The prompt's `pam_service`, `process_name` and `command_preview` are built in `tapauthd/src/caller_context.rs`. The kernel is asked first and the request's self-reported fields are only a fallback, because a compromised `client-pam` can claim to be any process.
- **`/proc/<pid>/exe` is EACCES across UIDs by design.** `read_link` goes through `ptrace_may_access` and the unit runs without `CAP_SYS_PTRACE`, so every other-UID caller hits it. That failure is logged at `debug` as the normal path; a failure of the world-readable `cmdline` (0444) or `comm` (0644) is logged at `warn` as the anomaly it is. Do not add the capability to silence it: a missing `cmdline` only costs the name, and the capability would let the daemon inspect any process on the host.
- **Process-name fallback order**: `/proc/<pid>/exe` basename → `cmdline` `argv[0]` basename → `/proc/<pid>/comm` → the caller's self-reported name. `command_preview` comes from the kernel `cmdline` only (the request has no command field), so an unreadable `cmdline` leaves no preview rather than a caller-supplied one.
- **`is_polkit_helper` is gated on the kernel-visible identity only** (`exe`, `argv[0]`, or `comm` against the kernel's 15-byte truncation `polkit-agent-he`); the IPC request's self-reported `process_name`/`pam_service` are never consulted. It is a display heuristic, not an authorization boundary: `argv[0]` is the caller's own `execve` argument and `comm` is settable via `prctl(PR_SET_NAME)`, so a local caller can still name its binary like the helper — authorization stays with `allowed_users`.
- **The sanitizer's canonical rules are implemented twice** — Rust `sanitize_context_string` (`shared/src/protocol/messages/context.rs`) and Kotlin `ContextSanitizer` (a mirror, because `./gradlew test` cannot load `libshared.so`) — and pinned together by ONE checked-in vector file, `shared/testdata/context_sanitizer_vectors.json`, read by `test_context_sanitizer_vectors_are_honoured` and by `ContextSanitizerTest`. Add a case there first, never in one side only. The rules: (1) ANSI CSI/OSC are removed as a unit first, an unterminated one to end of input, a lone `ESC` being just a forbidden character; (2) then per code point a fixed whitespace set collapses to one ASCII space and is trimmed — whitespace is tested before the forbidden set, so `sudo\tapt` cannot become `sudoapt` — and a fixed forbidden set (controls, bidi formatters, zero-width) is dropped; (3) fixed-width truncation on a UTF-8 boundary, with a single `…` only when the budget exceeds 3 bytes.

### PAM Module (`client-pam`)
- Built as `libclient_pam.so`, installed to distro-specific PAM dir as `pam_tapauth.so`
- Never returns `PAM_IGNORE`: Linux-PAM records no failure for it, so on a `required` stack like `auth required pam_tapauth.so` + `auth optional pam_permit.so` + `auth required pam_env.so` the whole stack would succeed. Failures map to `PAM_AUTHINFO_UNAVAIL` (no paired device, skip, timeout, daemon unreachable), `PAM_AUTH_ERR` (processing failure), `PAM_PERM_DENIED` (explicit denial on the phone) or `PAM_USER_UNKNOWN` (username lookup failed). What that buys is the `required` shape: there `PAM_IGNORE` is explicitly `ignore` while `PAM_AUTHINFO_UNAVAIL` is `bad`. On a `sufficient` line (`[success=done … default=ignore]`) both codes are `ignore`, so a following `optional pam_permit` grants either way and only the stack's configuration prevents it — the `bypass` E2E covers that `required` shape, not the `sufficient` one. Two `pam_tapauth.so` lines in one stack are now one check: the second line's transaction is answered from the recorded verdict instead of ringing the phone again.
- Wraps all IPC messages in `IpcEnvelope`, unwraps `PamResponse` from envelope
- Custom PAM FFI bindings in `pam_sys.rs` (not `pam-bindings` crate — known issues with pamtester)
- A per-process, per-`(username, service)` 500 ms verdict-reuse window returns the just-concluded code (success **or** failure) without contacting the daemon, absorbing a duplicate `pam_authenticate` some lock screens issue right after a transaction concludes (kscreenlocker re-enters 0.37 ms later); the window is anchored to the module's return to the host, not to the moment the transaction concluded. A conclusion is recorded only once the request reached the daemon: a skip (a refused service, a display manager), the pre-collected handoff and any failure before the request reached the daemon record nothing, and a call whose `PAM_SERVICE` did not resolve neither consults nor populates the record. A different user or a different PAM service always takes the normal path and rings the phone, and a new process always misses because `pam_end` unloads the module. The remaining scope is an **assumption, not a property**: no legitimate host performs an independent authentication for the same user and PAM service within 500 ms of a concluded one, and a human-initiated retry takes seconds — the `(username, service)` key cannot tell such a request apart from a duplicate
- **GUI (no-TTY) contexts use one of three flows**, chosen by `classify` from the caller facts — the PAM service, the process name (`/proc/self/exe`'s basename, falling back to `/proc/self/comm`) and `GDM_SESSION_FOR_REAUTH` in the environment. Hosts are classified by the ordered rows (`RemoteRefuse`–`DefaultSequential`, first match wins) of the rule table in `client-pam/src/policy/table.rs`: a row carries its id, its `FailureDirection`, its predicate and its `Decision`; the reason a row is answered that way and its `file:line` evidence live in the test-only `audit` record beside the table, not in the shipped row. `RemoteRefuse` and `DmLoginBypass` key on the service name rather than the process, so the table is not one row per host. The three flows, plus the two skips that precede them all (`RemoteRefuse` refuses a remote-authentication service, `DmLoginBypass` bypasses the display manager):
  - **Threaded**: password is collected on a worker thread while the main thread waits for the phone. A host is in this class only because its conversation stays answerable while that thread is blocked; a host that retries `pam_authenticate` (as the phone-side helper of one of them does) can therefore ring the phone more than once for a single call, except for retries that land inside the 500 ms verdict-reuse window (see the bullet above). This is a deadlock heuristic, not a trust boundary
  - **PreCollected**: the host read the password *before* calling `pam_authenticate` and its conversation is a synchronous replay of it. The module calls `pam_get_authtok` directly on the calling thread — which caches `PAM_AUTHTOK` for the next module (`pam_unix` with `try_first_pass`/`use_first_pass`) — and returns `PAM_AUTHINFO_UNAVAIL` immediately. The daemon is deliberately never contacted: the user already chose the password route, so ringing the phone could only be misleading and time out. On these hosts the phone is therefore not a credential at all — it is never rung and nothing is verified — so a stack with no password module after `pam_tapauth.so` cannot unlock
  - **Sequential** (everything the table does not name, which includes hosts that post the conversation answer back to the thread that called `pam_authenticate` and hosts that park in a condition variable with no cancellation point, so a threaded reply could never be abandoned and the lock screen would freeze): the conversation is **never** driven while waiting; the module waits for the daemon on the calling thread, then falls through to password. The wait is `pam_gui_timeout_secs` (default 30s) clamped to `pam_operation_timeout_secs` **only for a `Sequential` host without a tty**; a sequential host with a terminal (the `sudo`/`su` case) is bounded by `pam_operation_timeout_secs` alone. Driving the conversation from a thread on these hosts deadlocks their event loop (see `mechanism/sequential.rs`)
  - **Display-manager bypass**: the module returns `PAM_AUTHINFO_UNAVAIL` unexamined for the services the table marks as display managers, so the login manager still populates `PAM_AUTHTOK` and the keyring unlocks. A GDM **reauthentication** is exempt (`gdm-password` + `GDM_SESSION_FOR_REAUTH`): unlock runs no session/setcred phase, so the keyring reason does not apply. A missing or renamed variable degrades to the bypass/sequential default, never to a deadlock
  - **Remote refusal** (`RemoteRefuse`, `FailureDirection::RefuseRemote`): `SkipPolicy::RemoteAuthentication` skips the call as `PAM_AUTHINFO_UNAVAIL` for a service in the built-in list (`sshd`, `sshd-session`) or one a deployment added to `pam_refused_services`, whatever the process. `classify` runs before the config read and sees only the built-ins, so the configured names are applied by the second decision phase (`client-pam/src/policy/refine.rs`), which can only add a skip — never remove one, reclassify one, or change the mechanism or deadline
- PAM module reference (`client-pam`: components, request lifecycle, flow selection, the three flows, deadlines, return codes, reuse, configuration, known gaps): docs/design-documents/pam-module.md

### Authentication "Race" Flow
1. `client-pam` sends IPC request to `tapauthd`
2. `tapauthd` multicasts via UDP (port 36692) **and** starts BLE advertising simultaneously
3. Android device replies on the same transport
4. First valid `Grant` wins; `tapauthd` signals `client-pam`

### JNI Boundary (Android)
- **Kotlin never parses Protobuf.** Raw `ByteArray` messages are passed to Rust (`shared/src/ffi.rs`, via UniFFI) for validation, decryption, and parsing.
- JNI crypto tests (`TapAuthCryptoTest.kt`) are **instrumentation tests** requiring an emulator/device.
- Native build for Android is handled by the `net.mullvad.rust-android` plugin's `cargo` block in `server-android/app/build.gradle.kts` (version pinned in `server-android/build.gradle.kts`), not by a standalone script: `preBuild` depends on its `cargoBuild` task, so every assemble/deploy builds `libshared.so` into `app/build/rustJniLibs/android/<abi>/`, which is registered as the app's `jniLibs` source dir.

### Rust ↔ Kotlin boundary (UniFFI)
The boundary is generated by UniFFI from the proc-macro declarations in `shared` — `#[uniffi::export]` functions plus `uniffi::Record`, `uniffi::Error` and `uniffi::Object` types, gated behind the `jni` feature — and the Kotlin bindings are produced during the Gradle build by `generateUniffiBindings` instead of being committed, so those declarations are the single source of truth and no separate contract document exists. The pairing session is a reference-counted UniFFI object rather than a `jlong` handle, which makes stale-handle and double-free unrepresentable. The former name, signature and constructor-descriptor guards are gone with the hand-written surface: they compared two sides that are now one, so nothing is left to reconcile at CI time. The pairing session has exactly one terminal transition, `conclude()` (exported on the `PairingSession` object in `shared/src/ffi.rs`, and also run from its `Drop` impl): `create_confirm_server` only records that the proof went out — a second proof is refused with `ConfirmationAlreadySent` (surfaced as `TapauthError::State`), and so is a late `create_init` — while `process_confirm_client` stays valid and idempotent, so the responder keeps decrypting the desktop's provisioning retransmissions from the same keys; after `conclude()` every entry point of the object fails with `SessionConcluded` (`State`). The desktop side gained the same liveness check, so a concluded session reports `SessionConcluded` from `verify_confirm_server` instead of a `MissingField` that crossed the FFI as a `Security` error, indistinguishable from a tampered message (`ClientPairingState::verify_confirm_server`, `shared/src/protocol/pairing/client.rs`). `create_abort` remains terminal on its own. Kotlin calls the generated API directly — do not reintroduce a hand-written facade over it.

### GUI Framework
- `client-config-gui` uses **iced** (Rust GUI framework), not GTK. Requires X11 or Wayland.
- Runs **unprivileged** — all privileged operations (pairing, device management, config changes) are delegated to `tapauthd` via admin IPC.
- Authorization is enforced daemon-side via PolKit; socket permissions gate access.

### Transport Details
- **UDP port 36692** (default, user-configurable). IPv4 multicast **`239.255.26.44`** (IPv4 Local Scope, RFC 2365) + IPv6 multicast **`ff12::fdec:fc27`** (transient link-local; low 32 bits in the IANA private-use group-ID range, RFC 10028). The daemon sends on every suitable interface; paired Android devices join both groups.
- **BLE**: Service UUID `b4ad84c0-2adb-4876-8315-b39d983b2bde`. GATT characteristic UUIDs are in `docs/design-documents/protocol/ble-gatt-specification.md`.
- **Pairing uses the same two transports as authentication; there is no TCP listener.** The desktop binds an ephemeral UDP port (no multicast, firewall rule opened for `Protocol::Udp`) and advertises a 10-byte `pairing_adv_id` over BLE GATT at the same time; the phone races both and the first acceptable `PairingResponse` wins. QR code URL format (`generate_pairing_url_v2` and the matching `PairingInfo::parse`, `shared/src/models.rs`): `tapauth://pair?v=2&sid=<32 hex>&pk=<x25519 hex>[&p=<port>][&ip4=<ipv4>][&ip6=<ipv6>]`, with `p`/`ip4`/`ip6` omitted for a BLE-only session. One grammar, enforced on both sides and mirrored by Kotlin's `PairingUrl.parse`: the whole URL is capped at 512 bytes (`MAX_PAIRING_URL_LEN`, checked before anything else), every query key may appear at most once (a duplicate is refused rather than resolved, because the two parsers disagreed about which one wins), `v` must be `2`, `sid` is exactly 32 hex characters, `pk` exactly 64 hex characters and not the all-zero key (the phone reads an all-zero `pk` as its "skip the QR comparison" sentinel, so an accepted one would turn that check off), `p` is ASCII digits in `1..=65535` (`0` is not an endpoint), and values are percent-encoded by the generator and percent-decoded by both parsers under the same byte-for-byte rules.

### Pairing Completion on the Phone (linger & commit window)
The last leg of pairing is the phone's, and it outlives the completion proof: `PairingConfirmPhase.finish` (`server-android/app/src/main/java/dev/rourunisen/tapauth/network/PairingCompletion.kt:544`) builds the `PairingConfirmServer`, persists the device, sends the burst (UDP `0/100/250 ms`; one acknowledged GATT write over BLE), then lingers for `DEFAULT_LINGER_MS` = 1.25 s in 200 ms receive slices (`:47`, `:50`) and only afterwards calls `conclude()` — from a `finally`, so a burst that throws half-way is still concluded, and the Rust `Drop` stays the backstop for a session that never reaches that line. The linger is what the desktop is waiting on: `tapauthd` re-sends the same cached `PairingConfirmClient` every 500 ms (`RETRANSMIT_INTERVAL` in `tapauthd/src/pairing.rs`) until the proof verifies, so each arrival is decrypted again (that is how it is told apart from a keepalive or an abort) and answered with the **same** `PairingConfirmServer` bytes — calling `create_confirm_server` a second time would draw a fresh nonce and produce a different message. A `PairingAbort` during the linger is ignored: the pairing is already durable, so it is neither un-persisted nor turned into a failure.
Once persisting has begun, `PairingCommitLatch` makes the commit and a release mutually exclusive: a configuration change releases nothing at all (`PairingExit.ScreenDisposed` returns without touching the session), and a leave or a destroyed ViewModel is deferred (`PairingSession.close()` returns `CloseOutcome.Deferred`, so `releaseSession` leaves the attempt scope running) instead of cancelling the coroutine inside `persist()`, while a close that wins the latch refuses the persist outright, so nothing is written and nothing is sent. That deferral is bounded by the confirmation and not by the pairing: `completeCommit()` runs from the `finally` of `PairingSessionLifecycle.finish` (`PairingCompletion.kt:451-474`, the call at `:472`), the wrapper that runs a whole phase — not from `PairingConfirmPhase.finish`'s own `finally` (`:579-585`, which is where `crypto.conclude()` runs, `:585`) — so once the burst and linger are over a close releases normally — otherwise a close arriving after a finished pairing would answer "deferred" forever and never cancel the coroutine that owns the transports. An explicit user abort is untouched by that deferral — a SAS reject, or a back press while the SAS is still awaiting, is a decision and is still written as `PairingAbort(USER_REJECTED_SAS)`; a back press once the commit window is open takes the release path instead (`PairingViewModel.kt:194-211` checks `AwaitingSas`, and `Confirming` does not match), which the latch defers only while the confirmation is in flight and lets through once `completeCommit()` has run.

### Cryptography Quick Reference
- **X25519** for key exchange, **Ed25519** for signatures, **AES-256-GCM** for symmetric encryption and **HMAC-SHA256** for the temporal-identifier MAC. Those are the only implementations v2 ships — one active primitive per slot (`SymmetricAlgorithm`: `AES_256_GCM`, `HashAlgorithm`: `SHA256`, `SignatureAlgorithm`: `ED25519`) — and the agility is in the enums, the `supported_*`/`selected_*` negotiation fields and the cleartext header tag, not in a second shipped implementation. Tag `2` is `reserved` in both enums (it was `CHACHA20_POLY1305` / `BLAKE3` in pre-release builds, which is why the refused-id tests name it). Dispatch: `shared/src/crypto/encryption.rs:60`/`:74`; the advertised slices: `SUPPORTED_*` in `shared/src/protocol/pairing/negotiation.rs`; the persisted defaults: `CskMetadata::default` and its `default_symmetric_algorithm` / `default_hash_algorithm` serde defaults (`shared/src/config.rs`). Adding a future algorithm is an enum value with the next free tag (never `2`) plus an entry at the head of the Client's `SUPPORTED_*` — see `docs/design-documents/protocol/cryptography-specification.md` §1.
- **AEAD nonces**: 12-byte cryptographically random, prepended to ciphertext, identical for whatever `SymmetricAlgorithm` is negotiated. **NEVER reuse** a nonce with the same key.
- **Pairing session keys** (`K_c2s`, `K_s2c`, `SAS`): derived per pairing — HKDF-SHA256 salted with the transcript hash `H` over `Z = X25519(x, Y)` (`derive_pairing_keys_and_sas`, `shared/src/crypto/kdf.rs`). They are session-scoped: `K_c2s`/`K_s2c` live in zeroizing buffers and, with the transcript hash `H`, are dropped only by `conclude()` — `ClientPairingState::conclude` in `shared/src/protocol/pairing/client.rs` on the desktop, `ServerPairingSession::conclude` in `shared/src/protocol/pairing/server.rs` on the phone — reached explicitly or through the FFI session's `Drop`, while `Z`, the HKDF PRK and the ephemeral X25519 secret are zeroized at derivation (`derive_pairing_keys_and_sas` in `shared/src/crypto/kdf.rs`, and its call sites in `shared/src/protocol/pairing/client.rs` and `shared/src/protocol/pairing/server.rs`); sending the completion proof is **not** the moment the session keys go, because the phone keeps them for the linger that answers the desktop's retransmissions. The only long-term material a pairing provisions is the CSK (with `username`/`client_hostname`), AEAD-encrypted under `K_c2s`; the per-server state on the Client is just `Ed_S` and the negotiated `signature_algorithm` (the `PairedServer` struct's `public_key` and `signature_algorithm` fields, `shared/src/config.rs`), while the Client-wide symmetric/hash pair it shares with every Server lives only in `CskMetadata` (`shared/src/config.rs`).
- **Algorithm negotiation is asymmetric on purpose**: an advertised `supported_*` list is a compatibility surface, so `symmetric_algorithms` / `hash_algorithms` / `signature_algorithms` drop the ids this build cannot name and `negotiate` intersects the survivors with `SUPPORTED_*` (`shared/src/protocol/pairing/negotiation.rs`) — an older Client and a newer Server still agree on the baseline instead of failing over an id neither has to use; a `selected_*` value is instead a claim, so an id this build cannot name or never advertised is refused rather than defaulted (`ServerPairingSession::verify_response`, `shared/src/protocol/pairing/server.rs`).
- **What the transcript hashes**: the three `supported_*` lists enter `H` as the **raw advertised ids**, in wire order and including ids this build cannot decode, so both peers hash the same bytes for the same advertisement (`PairingTranscript::supported_*`, `shared/src/crypto/kdf.rs`); the `selected_*` fields enter as the validated variants, framed `be32`.
- **CSK** (Client Symmetric Key): one per Client, shared with all paired Servers. Stored long-term.

### Key Storage
- **Android**: Android Keystore System (hardware-backed where available).
- **Linux**: TPM 2.0 preferred (`tpm` feature). Fallback: `/var/lib/tapauth/` owned `tapauthd:tapauthd`, mode 700 for the directory and 0600 for the files.

### Replay & DoS Protections
- **Two replay checks**: nonce cache (primary, 120s TTL) + timestamp window (secondary, 60s).
- **Pre-authentication DoS**: temporal IDs are pre-computed per 60s window into a hash set for O(1) checks before crypto.
- **Post-authentication rate limiting**: escalating backoff (1s → 2s → 4s → max 5s) per Client public key.

### Retransmission
- **Client** (`AuthenticationRequest`): exponential backoff (200ms → 400ms → 800ms → ...).
- **Server** (`AuthenticationGrant`/`Denial`): fixed 500ms, up to 10s. Stops when `GrantConfirmation` received.
- Client **must** resend `GrantConfirmation` up to 3 times if further retransmissions arrive.
- **Pairing** is the same rule on the completion side: the phone's `PairingConfirmServer` is re-sent byte-identically (same nonce, cached frame) while it answers `PairingConfirmClient` retries during the linger — see *Pairing Completion on the Phone* above.

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
- **No static identifiers** in cleartext during authentication (use rotating temporal IDs: HMAC-SHA256 of the 60s time window, keyed by the CSK — `HashAlgorithm::SHA256`, the only hash v2 implements. The pre-release `BLAKE3` tag `2` is `reserved` and refused rather than derived).
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
- **Required-check job names are load-bearing.** The eight required contexts are listed
  authoritatively in `scripts/ci/check-required-checks.sh`, which runs in
  `Code Quality & Format Checks` — the three jobs in `ci.yml` and all five in `ci-android.yml`,
  E2E included. Renaming a required job silently stalls the queue (nothing reports the new name,
  so every entry waits out `check_response_timeout_minutes`); the payload live in GitHub must be
  edited alongside it.
- **Both workflows must stay unfiltered on `pull_request:`.** A required check cannot be
  path-filtered: a skipped run leaves it `Pending` forever, so the PR can be neither merged nor
  queued. The `paths:` filters on `push:` stay deliberately — the PR and the merge group already
  ran the change, so the filtered push run is only a safety net for bypass pushes.
- **No `merge_group` trigger may carry `paths:`** — GitHub supports none on that event.
- **The merge queue is not enabled yet.** Enabling it means editing ruleset `16779046` in the
  GitHub UI or via the API; until then `main` requires no merge queue.

## Configuration
- Default config at `/etc/tapauth/config.toml` (see `config.toml.example`)
- Key settings: `udp_port` (default 36692), `pam_operation_timeout_secs` (default 120), `pam_gui_timeout_secs` (default 30, clamped to `pam_operation_timeout_secs` for a sequential host without a terminal), `pam_refused_services` (default `["sshd", "sshd-session"]`; entries are *added* to those built-ins and never replace them), `use_tpm` (default false), `tpm_pcr_policy` (`"standard"` or `"paranoid"`, default `"standard"`, `tpm` feature only), `enable_network` (default true, Local Network/UDP transport), `enable_ble` (default true, BLE transport). The transport toggles take effect on the next authentication attempt without a daemon restart and can be changed via admin IPC (Settings screen in the GUI; requires PolKit admin authorization).
- **`/etc/tapauth` posture** (all packages): the directory is `root:root 0755`; `config.toml` is created at install time by `packaging/tmpfiles.conf` owned `tapauthd:tapauthd 0644` (no secrets in it; keys live under `/var/lib/tapauth`, 0700). The daemon is the single writer, so a root-owned file would make the first `SaveConfig` fail with `EACCES`. `install.sh` establishes the same posture. tmpfiles `f` preserves the file's content on upgrades but re-asserts that owner/mode on every `systemd-tmpfiles --create`, so config edits survive while a manually changed mode/owner does not. Debian `purge` removes the generated `config.toml` along with the pairing state; `remove` preserves it.

## Docker Dev Environment
```bash
docker compose -f docker-compose.dev.yml up -d
docker exec -it tapauth-dev bash
# Inside container: build-tapauth, test-tapauth, test-pam-auth, run-gui
```
