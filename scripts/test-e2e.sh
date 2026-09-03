#!/bin/bash
# Master End-to-End (E2E) Test Suite for TapAuth (Pairing + UDP + BLE)
# Runs the real production Android app against the real Linux daemon.
#
# Daemon modes (select via TAPAUTH_E2E_DAEMON_MODE=systemd|dev|auto):
#
#   systemd (default when running as root under systemd, e.g. CI):
#     Installs the real systemd/tapauthd.socket + tapauthd.service units and the
#     production PolKit policy. The daemon runs as the unprivileged `tapauthd`
#     user, is socket-activated on the real /run/tapauthd/tapauthd.sock, keeps
#     state in /var/lib/tapauth and writes /etc/tapauth/config.toml. The PAM
#     module and CLI are built WITHOUT dev socket overrides and talk through
#     the production socket. File/socket permission properties are asserted.
#
#   dev (fallback for unprivileged local development):
#     Builds the feature-gated daemon (fallback-socket) and redirects state via
#     TAPAUTH_STATE_DIR / TAPAUTHD_SOCK into a temporary sandbox directory.
#
# NOTE on the systemd-mode build: it enables ONLY `dev-udp-loopback` (the
# emulator UDP delivery shim, TAPAUTH_DEV_UDP_TARGET) and `dev-polkit-bypass`
# (so headless runners need no authentication agent). A hosted CI runner has no
# LAN broadcast path into the Android emulator, hence the shim. `dev-state-override`
# stays OFF in this mode, so no TAPAUTH_STATE_DIR/TAPAUTHD_SOCK redirection is
# compiled in at all: every state and config path is the real production path.
# PolKit is still evaluated for every non-root caller (Phase 7 asserts this).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║      TapAuth Full Real-Android End-to-End Test Suite          ║"
echo "║      (TCP Pairing + UDP Network + BLE GATT Authentication)   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

PYTHON_BIN="${PYTHON_BIN:-python3}"

# ── Ports ─────────────────────────────────────────────────────────────────────
# UDP_PORT      the daemon's port (written to the config file, used for packet
#               capture and for injecting adversarial packets).
# DEV_HOST_PORT host-side port of the emulator UDP redirection
#               (adb emu redir add udp:$DEV_HOST_PORT:$UDP_PORT); the daemon
#               unicasts to it when the dev-udp-loopback feature is compiled in.
UDP_PORT="${TAPAUTH_E2E_UDP_PORT:-36692}"
DEV_HOST_PORT="${TAPAUTH_E2E_DEV_HOST_PORT:-36695}"
# Exported so the bridge helpers stay in sync with this suite's port choices.
export TAPAUTH_E2E_UDP_PORT="$UDP_PORT"
export TAPAUTH_E2E_DEV_HOST_PORT="$DEV_HOST_PORT"

# Ensure adb is in PATH
if ! command -v adb &> /dev/null; then
    for p in "/usr/local/lib/android/sdk/platform-tools" "$ANDROID_HOME/platform-tools" "$ANDROID_SDK_ROOT/platform-tools" "$HOME/Android/Sdk/platform-tools"; do
        if [ -x "$p/adb" ]; then
            export PATH="$PATH:$p"
            break
        fi
    done
fi

# Check for running Android emulator
if ! adb devices | grep -q 'emulator-[0-9]*'; then
    echo "❌ ERROR: No active Android emulator detected."
    echo "   Please start an emulator (e.g. via Android Studio or 'emulator @<avd_name>') before running this test."
    exit 1
fi

echo "✅ Android emulator detected."

# ── Daemon mode detection ─────────────────────────────────────────────────────
E2E_DAEMON_MODE="${TAPAUTH_E2E_DAEMON_MODE:-auto}"
if [ "$E2E_DAEMON_MODE" = "auto" ]; then
    if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1 && [ "$(ps -p 1 -o comm=)" = "systemd" ] && [ -d /run/systemd/system ]; then
        E2E_DAEMON_MODE="systemd"
    else
        E2E_DAEMON_MODE="dev"
    fi
fi
if [ "$E2E_DAEMON_MODE" != "systemd" ] && [ "$E2E_DAEMON_MODE" != "dev" ]; then
    echo "❌ ERROR: invalid TAPAUTH_E2E_DAEMON_MODE '$E2E_DAEMON_MODE' (expected systemd|dev|auto)"
    exit 1
fi

# Sandbox directory for logs, captures and (dev mode) state redirection
TEST_DIR=$(mktemp -d -t tapauth-e2e.XXXXXX)
DAEMON_LOG="${TEST_DIR}/tapauthd.log"

PAM_SERVICE_NAME="tapauth-test-e2e"
PAM_MIXED_SERVICE_NAME="tapauth-mixed-stack"
PAM_CONFIG_PATH="/etc/pam.d/${PAM_SERVICE_NAME}"
PAM_MIXED_CONFIG_PATH="/etc/pam.d/${PAM_MIXED_SERVICE_NAME}"
PAM_FALLBACK_USER="tapauth-e2e-pam"
PAM_FALLBACK_PASS="TapAuth-E2E-Fallback-$(date +%s)!"
ADMIN_DENY_USER="tapauth-e2e-deny"
USE_INSTALLED_PACKAGE="${TAPAUTH_E2E_USE_INSTALLED_PACKAGE:-0}"

if [ "$E2E_DAEMON_MODE" = "dev" ]; then
    # Dev-mode sandbox: feature-gated daemon + env redirection.
    if [ "$USE_INSTALLED_PACKAGE" = "1" ]; then
        export TAPAUTHD_SOCK="/run/tapauthd/tapauthd.sock"
        unset TAPAUTH_STATE_DIR
        export TAPAUTH_DEV_MODE=1
        CONFIG_ASSERT_FILE="/etc/tapauth/config.toml"
    else
        export TAPAUTHD_SOCK="${TEST_DIR}/tapauthd.sock"
        export TAPAUTH_STATE_DIR="${TEST_DIR}/state"
        export TAPAUTH_DEV_MODE=1
        mkdir -p "$TAPAUTH_STATE_DIR"
        chmod 700 "$TAPAUTH_STATE_DIR"
        CONFIG_ASSERT_FILE="${TAPAUTH_STATE_DIR}/config.toml"
        chown -R tapauthd:tapauthd "$TEST_DIR" 2>/dev/null || true
    fi
else
    CONFIG_ASSERT_FILE="/etc/tapauth/config.toml"
fi

# Detect test username (matches caller UID for daemon IPC authorization)
TEST_USER="$(whoami)"

echo "ℹ️  Daemon mode:    $E2E_DAEMON_MODE"
echo "ℹ️  Test User:      $TEST_USER"
echo "ℹ️  UDP port:       $UDP_PORT (emulator shim: 127.0.0.1:$DEV_HOST_PORT)"
if [ "$E2E_DAEMON_MODE" = "dev" ]; then
    echo "ℹ️  Isolated Socket: $TAPAUTHD_SOCK"
    echo "ℹ️  State Directory: $TAPAUTH_STATE_DIR"
fi
echo "ℹ️  Sandbox Dir:    $TEST_DIR"
echo ""

# Background processes this suite owns directly; the BLE/biometric helpers track
# their own PIDs in /tmp and are torn down through their own subcommands.
DAEMON_PID=""
JOURNAL_PID=""
CAPTURE_PID=""

# systemd-mode teardown bookkeeping: only undo what this run actually installed.
# (Set for real in the systemd setup block below; defaults keep cleanup() safe if
# the suite aborts earlier.)
E2E_OWNED_STATE=false
CREATED_CONFIG=false
UNITS_PREEXISTED=false
BINARY_PREEXISTED=false

# Env prefix for pamtester invocations: dev mode points the PAM module (and the
# CLI, whose TAPAUTHD_SOCK override is compiled in via fallback-socket ->
# dev-socket-override) at the sandbox socket; systemd mode must NOT set the
# variable so the production socket path is used.
# TAPAUTH_LOG_LEVEL=debug makes the module's tracing visible in the CI log so
# PAM-phase failures are diagnosable.
if [ "$E2E_DAEMON_MODE" = "dev" ]; then
    PAM_ENV=(env "TAPAUTHD_SOCK=${TAPAUTHD_SOCK}" TAPAUTH_LOG_LEVEL=debug)
else
    PAM_ENV=(env -u TAPAUTHD_SOCK TAPAUTH_LOG_LEVEL=debug)
fi

cleanup() {
    EXIT_CODE=$?
    echo ""
    echo "==> Cleaning up test environment (exit code: $EXIT_CODE)..."
    if [ "$EXIT_CODE" -ne 0 ] && [ -n "$DAEMON_LOG" ] && [ -f "$DAEMON_LOG" ]; then
        echo "=== DAEMON LOG DUMP ==="
        cat "$DAEMON_LOG"
        echo "======================="
    fi
    if [ "$EXIT_CODE" -ne 0 ] && [ -f /tmp/bumble-bridge.log ]; then
        echo "=== BUMBLE LOG DUMP ==="
        cat /tmp/bumble-bridge.log
        echo "======================="
    fi
    if [ "$EXIT_CODE" -ne 0 ] && [ -f /tmp/bluetoothd.log ]; then
        echo "=== BLUETOOTH DAEMON LOG DUMP ==="
        cat /tmp/bluetoothd.log
        echo "=================================="
    fi
    if [ "$EXIT_CODE" -ne 0 ]; then
        echo "=== ANDROID LOGCAT DUMP ==="
        adb logcat -d -v time -s AuthenticationService:* BleGattService:* AuthRequestManager:* TapAuthApplication:* PairingClient:* BiometricPromptActivity:* TapAuthCrypto:* 2>/dev/null || true
        echo "==========================="
    fi
    if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
        systemctl stop tapauthd.service 2>/dev/null || true
        systemctl stop tapauthd.socket 2>/dev/null || true
        systemctl disable tapauthd.socket 2>/dev/null || true
    fi
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    if [ -n "$JOURNAL_PID" ]; then
        kill "$JOURNAL_PID" 2>/dev/null || true
        wait "$JOURNAL_PID" 2>/dev/null || true
    fi
    if [ -n "$CAPTURE_PID" ]; then
        kill "$CAPTURE_PID" 2>/dev/null || true
        wait "$CAPTURE_PID" 2>/dev/null || true
    fi
    "$SCRIPT_DIR/ci/emulator-bio-helper.sh" stop-auto-grant 2>/dev/null || true
    if [ "${E2E_KEEP_BLE_BRIDGE:-0}" != "1" ]; then
        if [ -f /tmp/bumble-bridge.pid ]; then
            kill "$(cat /tmp/bumble-bridge.pid)" 2>/dev/null || true
            rm -f /tmp/bumble-bridge.pid
        fi
    fi
    if [ "$INSTALLED_POLKIT" = true ]; then
        sudo rm -f "$POLKIT_POLICY_DEST" 2>/dev/null || true
    fi
    if [ "$INSTALLED_FPRINT_POLICY" = true ]; then
        sudo rm -f "$FPRINT_POLICY_DEST" 2>/dev/null || true
        if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet dbus 2>/dev/null; then
            systemctl reload dbus 2>/dev/null || true
        fi
    fi
    # systemd mode installed a real daemon on this host; put the machine back the
    # way we found it. Without this, `sudo ./scripts/test-e2e.sh` would leave a
    # debug binary plus an E2E drop-in (TAPAUTH_DEV_MODE=1 + UDP shim) enabled on
    # the developer's machine. Files that already existed are never deleted.
    if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
        rm -f /etc/systemd/system/tapauthd.service.d/e2e.conf 2>/dev/null || true
        rmdir /etc/systemd/system/tapauthd.service.d 2>/dev/null || true
        if [ "$UNITS_PREEXISTED" != true ]; then
            rm -f /etc/systemd/system/tapauthd.service /etc/systemd/system/tapauthd.socket 2>/dev/null || true
        fi
        if [ "$BINARY_PREEXISTED" != true ]; then
            rm -f /usr/bin/tapauthd /usr/local/bin/tapauth-ipc-cli 2>/dev/null || true
        fi
        systemctl daemon-reload 2>/dev/null || true
        if [ "$CREATED_CONFIG" = true ]; then
            rm -f "$CONFIG_ASSERT_FILE" 2>/dev/null || true
        fi
        if [ "$E2E_OWNED_STATE" = true ]; then
            find /var/lib/tapauth -mindepth 1 -delete 2>/dev/null || true
        fi
        if [ "$USE_INSTALLED_PACKAGE" != "1" ] && { [ "$UNITS_PREEXISTED" = true ] || [ "$BINARY_PREEXISTED" = true ]; }; then
            echo "⚠️  WARNING: this run replaced pre-existing TapAuth units/binaries with"
            echo "   the E2E debug build and left them in place. Reinstall (e.g."
            echo "   ./install.sh or your distro package) before using TapAuth again."
        fi
    fi
    if [ -w "$PAM_CONFIG_PATH" ]; then
        rm -f "$PAM_CONFIG_PATH" 2>/dev/null || true
    fi
    if [ -w "$PAM_MIXED_CONFIG_PATH" ]; then
        rm -f "$PAM_MIXED_CONFIG_PATH" 2>/dev/null || true
    fi
    if id "$PAM_FALLBACK_USER" >/dev/null 2>&1; then
        passwd -l "$PAM_FALLBACK_USER" >/dev/null 2>&1 || true
        userdel -r "$PAM_FALLBACK_USER" >/dev/null 2>&1 || true
    fi
    if id "$ADMIN_DENY_USER" >/dev/null 2>&1; then
        userdel -r "$ADMIN_DENY_USER" >/dev/null 2>&1 || true
    fi
    rm -rf "$TEST_DIR" 2>/dev/null || true
    echo "✅ Teardown complete."
}
trap cleanup EXIT INT TERM

# Helper: assert a path's mode/owner/group via stat(1)
assert_stat() {
    local path=$1 expected=$2 label=$3
    local actual
    actual="$(stat -c '%a %U %G' "$path" 2>/dev/null || echo "missing")"
    if [ "$actual" = "$expected" ]; then
        echo "✅ ${label}: $(basename "$path") -> $actual"
    else
        echo "❌ ERROR (${label}): expected '$path' to be '$expected' but got '$actual'"
        exit 1
    fi
}

# Helper: wait for a background process to exit, with a timeout (seconds).
# Returns the process' exit status, or 99 on timeout (after SIGKILL).
wait_pid_with_timeout() {
    local pid=$1 timeout_secs=$2
    for _ in $(seq 1 $((timeout_secs * 10))); do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            return $?
        fi
        sleep 0.1
    done
    echo "❌ ERROR: process $pid did not exit within ${timeout_secs}s" >&2
    kill -9 "$pid" 2>/dev/null || true
    return 99
}

# PolKit policy bookkeeping: the policy itself is only ever installed by the
# systemd-mode setup block below (the dev sandbox's dev-polkit-bypass makes an
# installed policy unnecessary, and Phase 7 runs in systemd mode only). These
# defaults keep cleanup() safe if the suite aborts before that block runs.
POLKIT_POLICY_DEST="/usr/share/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy"
INSTALLED_POLKIT=false

# Ensure Android app is in a clean state (wiping any previous pairing keys)
if command -v adb >/dev/null 2>&1; then
    adb shell pm clear dev.rourunisen.tapauth.e2e >/dev/null 2>&1 || true
fi

# Step 1: Build necessary Linux binaries or resolve installed packages
if [ "$USE_INSTALLED_PACKAGE" = "1" ]; then
    echo "==> Step 1: Using pre-installed distro packages for E2E tests..."
    TAPAUTHD_BIN="/usr/bin/tapauthd"
    CLI_BIN="$(command -v tapauth-ipc-cli || true)"
    if [ -z "$CLI_BIN" ] && [ -x /usr/bin/tapauth-ipc-cli ]; then
        CLI_BIN="/usr/bin/tapauth-ipc-cli"
    elif [ -z "$CLI_BIN" ] && [ -x /usr/local/bin/tapauth-ipc-cli ]; then
        CLI_BIN="/usr/local/bin/tapauth-ipc-cli"
    fi

    PAM_LIB=""
    for candidate in \
        "/lib/x86_64-linux-gnu/security/pam_tapauth.so" \
        "/usr/lib/security/pam_tapauth.so" \
        "/lib/security/pam_tapauth.so" \
        "/usr/lib64/security/pam_tapauth.so"; do
        if [ -f "$candidate" ]; then
            PAM_LIB="$candidate"
            break
        fi
    done
    if [ -z "$PAM_LIB" ]; then
        PAM_LIB="pam_tapauth.so"
    fi

    if [ ! -x "$TAPAUTHD_BIN" ]; then
        echo "❌ ERROR: tapauthd binary not found at $TAPAUTHD_BIN"
        exit 1
    fi
    if [ ! -x "$CLI_BIN" ]; then
        echo "❌ ERROR: tapauth-ipc-cli binary not found"
        exit 1
    fi
    echo "    Found installed tapauthd:       $TAPAUTHD_BIN"
    echo "    Found installed tapauth-ipc-cli: $CLI_BIN"
    echo "    Found installed pam_tapauth.so:  $PAM_LIB"
else
    echo "==> Step 1: Building Linux components (tapauthd, tapauth-ipc-cli, client-pam)..."
    # Pin the cargo target directory so the artifact paths below are deterministic
    # regardless of any user-level CARGO_TARGET_DIR override (~/.cargo/config.toml).
    export CARGO_TARGET_DIR="${PROJECT_ROOT}/target"
    if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
        # Production-style build: systemd socket activation (fallback-socket OFF) and
        # no dev-state-override, so state/config/socket paths are production. Only the
        # emulator UDP shim and the headless PolKit bypass are compiled in, both still
        # requiring TAPAUTH_DEV_MODE at runtime.
        cargo build -p tapauthd --no-default-features --features ble,dev-udp-loopback,dev-polkit-bypass --bin tapauthd --bin tapauth-ipc-cli
        cargo build -p client-pam
    else
        cargo build -p tapauthd --features fallback-socket,ble --bin tapauthd --bin tapauth-ipc-cli
        cargo build -p client-pam --features dev-socket-override
    fi

    TAPAUTHD_BIN="${PROJECT_ROOT}/target/debug/tapauthd"
    CLI_BIN="${PROJECT_ROOT}/target/debug/tapauth-ipc-cli"
    PAM_LIB="${PROJECT_ROOT}/target/debug/libclient_pam.so"
fi

# ── systemd-mode environment setup ────────────────────────────────────────────
if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
    echo ""
    echo "==> Step 1b: Setting up production systemd environment (units, users, config)..."

    if [ "$USE_INSTALLED_PACKAGE" = "1" ]; then
        echo "    Verifying pre-installed package systemd environment..."
        UNITS_PREEXISTED=true
        BINARY_PREEXISTED=true
        E2E_OWNED_STATE=false
        CREATED_CONFIG=false

        id tapauthd >/dev/null 2>&1 || "$PROJECT_ROOT/create-dev-users.sh"
        systemd-tmpfiles --create "$PROJECT_ROOT/packaging/tmpfiles.conf" 2>/dev/null || true

        mkdir -p /etc/tapauth
        chown tapauthd:tapauthd /etc/tapauth 2>/dev/null || true
        chmod 755 /etc/tapauth 2>/dev/null || true
        if [ ! -f "$CONFIG_ASSERT_FILE" ]; then
            CREATED_CONFIG=true
            cat > "$CONFIG_ASSERT_FILE" <<EOF
# TapAuth Configuration (created by the E2E suite)
pam_operation_timeout_secs = 120
udp_port = ${UDP_PORT}
use_tpm = false
enable_fprintd_bridge = true
EOF
            chown tapauthd:tapauthd "$CONFIG_ASSERT_FILE" 2>/dev/null || true
            chmod 644 "$CONFIG_ASSERT_FILE" 2>/dev/null || true
        else
            if ! grep -q "^[[:space:]]*enable_fprintd_bridge[[:space:]]*=[[:space:]]*true" "$CONFIG_ASSERT_FILE"; then
                sed -i 's/^[#[:space:]]*enable_fprintd_bridge[[:space:]]*=.*/enable_fprintd_bridge = true/' "$CONFIG_ASSERT_FILE" 2>/dev/null || true
            fi
        fi
    else
        # This mode installs over a REAL system installation (/usr/bin/tapauthd, the
        # systemd units, /etc/tapauth, /var/lib/tapauth). On CI the runner is
        # disposable; on a developer workstation that is someone's live pairing state,
        # so refuse unless the caller opts in explicitly.
        PREEXISTING=""
        if [ -x /usr/bin/tapauthd ]; then
            PREEXISTING="/usr/bin/tapauthd"
        fi
        if [ -n "$(find /var/lib/tapauth -maxdepth 1 -type f 2>/dev/null | head -1)" ]; then
            PREEXISTING="${PREEXISTING:+$PREEXISTING, }/var/lib/tapauth (non-empty)"
        fi
        if [ -n "$PREEXISTING" ] && [ "${TAPAUTH_E2E_ALLOW_DESTRUCTIVE:-0}" != "1" ]; then
            echo "❌ ERROR: systemd mode would overwrite an existing TapAuth installation: $PREEXISTING"
            echo "   Run as root inside a disposable VM/container, or set"
            echo "   TAPAUTH_E2E_ALLOW_DESTRUCTIVE=1 to accept that pairing state and"
            echo "   binaries under /var/lib/tapauth, /etc/tapauth and /usr/bin are replaced."
            exit 1
        fi
        # We only remove state/config files that we know were absent before this run.
        E2E_OWNED_STATE=false
        if [ ! -d /var/lib/tapauth ] || [ -z "$(find /var/lib/tapauth -maxdepth 1 -type f 2>/dev/null | head -1)" ]; then
            E2E_OWNED_STATE=true
        fi
        CREATED_CONFIG=false
        # Same for the units and binaries: with TAPAUTH_E2E_ALLOW_DESTRUCTIVE=1 on a
        # host that already has TapAuth installed, overwrite them for the duration of
        # the run but never delete the pre-existing files afterwards.
        UNITS_PREEXISTED=false
        if [ -e /etc/systemd/system/tapauthd.service ] || [ -e /etc/systemd/system/tapauthd.socket ]; then
            UNITS_PREEXISTED=true
        fi
        BINARY_PREEXISTED=false
        if [ -e /usr/bin/tapauthd ] || [ -e /usr/local/bin/tapauth-ipc-cli ]; then
            BINARY_PREEXISTED=true
        fi

        # 1. System users/groups exactly as install.sh creates them
        "$PROJECT_ROOT/create-dev-users.sh"

        # 2. Install binaries + units + PolKit policy as the packages would
        install -Dm0755 "$TAPAUTHD_BIN" /usr/bin/tapauthd
        install -Dm0755 "$CLI_BIN" /usr/local/bin/tapauth-ipc-cli
        install -Dm0644 "$PROJECT_ROOT/systemd/tapauthd.service" /etc/systemd/system/tapauthd.service
        install -Dm0644 "$PROJECT_ROOT/systemd/tapauthd.socket" /etc/systemd/system/tapauthd.socket
        # Only register the policy if it is not already installed: cleanup() deletes
        # what it registered, and removing a pre-existing production policy would
        # break the host's real installation.
        if [ ! -f "$POLKIT_POLICY_DEST" ]; then
            install -Dm0644 "${PROJECT_ROOT}/tapauthd/dev.rourunisen.tapauth.config.admin.policy" "$POLKIT_POLICY_DEST"
            INSTALLED_POLKIT=true
        fi

        # Install virtual fprintd D-Bus policy if not present
        FPRINT_POLICY_DEST="/etc/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf"
        if [ ! -f "$FPRINT_POLICY_DEST" ]; then
            install -Dm0644 "${PROJECT_ROOT}/packaging/net.reactivated.Fprint.tapauth.conf" "$FPRINT_POLICY_DEST"
            INSTALLED_FPRINT_POLICY=true
            if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet dbus 2>/dev/null; then
                systemctl reload dbus 2>/dev/null || true
            fi
        fi

        # 3. Runtime/state/config directories exactly as packaging does
        systemd-tmpfiles --create "$PROJECT_ROOT/packaging/tmpfiles.conf"
        mkdir -p /etc/tapauth
        chown tapauthd:tapauthd /etc/tapauth
        chmod 755 /etc/tapauth
        if [ ! -f "$CONFIG_ASSERT_FILE" ]; then
            CREATED_CONFIG=true
            cat > "$CONFIG_ASSERT_FILE" <<EOF
# TapAuth Configuration (created by the E2E suite, mirrors install.sh)
pam_operation_timeout_secs = 120
udp_port = ${UDP_PORT}
use_tpm = false
EOF
            chown tapauthd:tapauthd "$CONFIG_ASSERT_FILE"
            chmod 644 "$CONFIG_ASSERT_FILE"
        fi
    fi

    # 4. E2E-only unit override. These are the ONLY non-production knobs: the
    #    emulator UDP delivery shim (a CI runner cannot deliver LAN broadcasts
    #    into the Android emulator), the headless PolKit bypass, and debug logs.
    #    State/config paths and socket activation stay production; the binary is
    #    built WITHOUT dev-state-override, so TAPAUTH_STATE_DIR cannot redirect
    #    anything even if it were set in the environment.
    mkdir -p /etc/systemd/system/tapauthd.service.d
    cat > /etc/systemd/system/tapauthd.service.d/e2e.conf <<EOF
# E2E-only override (not shipped in production packages)
[Service]
Environment=TAPAUTH_DEV_MODE=1
Environment=TAPAUTH_DEV_UDP_TARGET=127.0.0.1:${DEV_HOST_PORT}
Environment=TAPAUTH_LOG_LEVEL=debug
Environment=RUST_LOG=debug
EOF

    # 5. Enable the real socket unit; the service is activated on first IPC
    systemctl daemon-reload
    systemctl stop tapauthd.service 2>/dev/null || true
    systemctl enable --now tapauthd.socket

    if ! systemctl is-active --quiet tapauthd.socket; then
        echo "❌ ERROR: tapauthd.socket failed to start:"
        systemctl status tapauthd.socket --no-pager || true
        exit 1
    fi
    echo "✅ tapauthd.socket enabled (socket-activated service)."

    # 6. Real socket activation: this CLI call starts the daemon via FD#3
    if ! "$CLI_BIN" get-config > "${TEST_DIR}/activation.log" 2>&1; then
        echo "❌ ERROR: socket-activated daemon did not answer. Log:"
        cat "${TEST_DIR}/activation.log"
        systemctl status tapauthd.service --no-pager || true
        exit 1
    fi
    if ! systemctl is-active --quiet tapauthd.service; then
        echo "❌ ERROR: tapauthd.service was not activated by IPC connect:"
        systemctl status tapauthd.service --no-pager || true
        exit 1
    fi
    cat "${TEST_DIR}/activation.log"
    echo "✅ tapauthd.service socket-activated and answering IPC."

    # 7. Follow the daemon's journald output into DAEMON_LOG for assertions
    stdbuf -oL journalctl -u tapauthd.service -f -n 0 --no-pager > "$DAEMON_LOG" 2>&1 &
    JOURNAL_PID=$!
fi

# Step 2: Install Android App and Test Runner on Emulator
echo "==> Step 2: Ensuring Android App and Instrumentation Tests are installed..."
APP_PKG="dev.rourunisen.tapauth.e2e"
TEST_PKG="dev.rourunisen.tapauth.e2e.test"

if [ -f "server-android/app/build/outputs/apk/e2e/app-e2e.apk" ]; then
    adb install -r -t server-android/app/build/outputs/apk/e2e/app-e2e.apk || true
elif [ -f "server-android/app/build/outputs/apk/debug/app-debug.apk" ]; then
    APP_PKG="dev.rourunisen.tapauth.debug"
    adb install -r -t server-android/app/build/outputs/apk/debug/app-debug.apk || true
fi

if [ -f "server-android/app/build/outputs/apk/androidTest/e2e/app-e2e-androidTest.apk" ]; then
    adb install -r -t server-android/app/build/outputs/apk/androidTest/e2e/app-e2e-androidTest.apk || true
elif [ -f "server-android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk" ]; then
    TEST_PKG="dev.rourunisen.tapauth.debug.test"
    adb install -r -t server-android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk || true
fi

echo "==> Granting runtime permissions to Android app ($APP_PKG)..."
adb shell pm grant "$APP_PKG" android.permission.POST_NOTIFICATIONS 2>/dev/null || true
adb shell pm grant "$APP_PKG" android.permission.ACCESS_FINE_LOCATION 2>/dev/null || true
adb shell pm grant "$APP_PKG" android.permission.BLUETOOTH_CONNECT 2>/dev/null || true
adb shell pm grant "$APP_PKG" android.permission.BLUETOOTH_ADVERTISE 2>/dev/null || true
adb shell pm grant "$APP_PKG" android.permission.BLUETOOTH_SCAN 2>/dev/null || true

# Step 3: Setup Bridges and Virtual Transport Layers
echo "==> Step 3: Setting up Transport Bridges (BLE + UDP)..."
"$SCRIPT_DIR/ci/setup-emulator-ble-bridge.sh"
"$SCRIPT_DIR/ci/setup-emulator-udp-bridge.sh"
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" setup

# Step 4: Launch tapauthd daemon
echo "==> Step 4: Launching tapauthd daemon..."
if [ "$E2E_DAEMON_MODE" = "dev" ]; then
    env TAPAUTH_DEV_MODE="1" TAPAUTH_DEV_UDP_TARGET="127.0.0.1:${DEV_HOST_PORT}" TAPAUTH_LOG_LEVEL="debug" RUST_LOG="debug" TAPAUTHD_SOCK="$TAPAUTHD_SOCK" ${TAPAUTH_STATE_DIR:+TAPAUTH_STATE_DIR="$TAPAUTH_STATE_DIR"} "$TAPAUTHD_BIN" > "$DAEMON_LOG" 2>&1 &
    DAEMON_PID=$!

    echo -n "    Waiting for daemon socket"
    for _ in {1..50}; do
        if [ -S "$TAPAUTHD_SOCK" ]; then break; fi
        echo -n "."; sleep 0.1
    done
    echo ""

    if [ ! -S "$TAPAUTHD_SOCK" ]; then
        echo "❌ ERROR: tapauthd socket failed to initialize. Daemon log:"
        cat "$DAEMON_LOG"
        exit 1
    fi
    echo "✅ tapauthd daemon is active (dev sandbox)."
else
    echo "✅ tapauthd daemon is active (systemd socket activation)."
fi

# Step 5: Phase 1 - Real TCP Device Pairing
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 1: Real TCP Pairing & SAS Anti-MITM Verification       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

echo "==> Step 1a: Negative pairing test (SAS mismatch / user rejection)..."
START_NEG_OUTPUT=$("$CLI_BIN" start-pairing)
PORT_NEG=$(echo "$START_NEG_OUTPUT" | grep 'PORT=' | cut -d'=' -f2)
WAIT_NEG_LOG="${TEST_DIR}/wait_neg_pairing.log"
"$CLI_BIN" wait-for-pairing "$PORT_NEG" > "$WAIT_NEG_LOG" 2>&1 &
WAIT_NEG_PID=$!

AM_NEG_LOG="${TEST_DIR}/am_neg_pairing.log"
adb shell am instrument -w \
    -e class dev.rourunisen.tapauth.e2e.PairingE2eTest \
    -e pairing_host 10.0.2.2 \
    -e pairing_port "$PORT_NEG" \
    -e reject_sas true \
    "$TEST_PKG/dev.rourunisen.tapauth.crypto.TapAuthTestRunner" > "$AM_NEG_LOG" 2>&1 || true

wait "$WAIT_NEG_PID" || true

set +e
"$CLI_BIN" complete-pairing "$PORT_NEG" > "${TEST_DIR}/complete_neg_pairing.log" 2>&1
COMPLETE_NEG_EXIT=$?
set -e

NEG_SERVERS_COUNT=$("$CLI_BIN" get-servers | grep 'COUNT=' | cut -d'=' -f2)
if [ "$COMPLETE_NEG_EXIT" -ne 0 ] && [ "$NEG_SERVERS_COUNT" -eq 0 ]; then
    echo "✅ Negative pairing test PASSED: SAS rejection aborted the handshake (complete-pairing exit $COMPLETE_NEG_EXIT), 0 paired devices stored."
else
    echo "❌ ERROR: negative pairing did not abort cleanly (complete-pairing exit=$COMPLETE_NEG_EXIT, devices=$NEG_SERVERS_COUNT)!"
    cat "${TEST_DIR}/complete_neg_pairing.log" || true
    exit 1
fi

echo "==> Step 1b: Legitimate pairing handshake..."
START_OUTPUT=$("$CLI_BIN" start-pairing)
PORT=$(echo "$START_OUTPUT" | grep 'PORT=' | cut -d'=' -f2)
PAIR_URL=$(echo "$START_OUTPUT" | grep 'URL=' | cut -d'=' -f2)

echo "    Pairing Port: $PORT"
echo "    Pairing URL:  $PAIR_URL"

# Wait for pairing in background
WAIT_LOG="${TEST_DIR}/wait_pairing.log"
"$CLI_BIN" wait-for-pairing "$PORT" > "$WAIT_LOG" 2>&1 &
WAIT_PID=$!

# Trigger Android PairingClient via Instrumentation Test in background
echo "==> Triggering PairingClient inside Android Emulator..."
AM_LOG="${TEST_DIR}/am_pairing.log"
adb shell am instrument -w \
    -e class dev.rourunisen.tapauth.e2e.PairingE2eTest \
    -e pairing_host 10.0.2.2 \
    -e pairing_port "$PORT" \
    "$TEST_PKG/dev.rourunisen.tapauth.crypto.TapAuthTestRunner" > "$AM_LOG" 2>&1 &
AM_PID=$!

wait "$WAIT_PID" || {
    echo "❌ wait-for-pairing failed. Log:"
    cat "$WAIT_LOG"
    exit 1
}

SAS_CODE=$(grep 'SAS=' "$WAIT_LOG" | cut -d'=' -f2)
echo "    Desktop Derived SAS: $SAS_CODE"

echo "==> Completing pairing handshake..."
COMPLETE_OUTPUT=$("$CLI_BIN" complete-pairing "$PORT")
SERVER_HEX=$(echo "$COMPLETE_OUTPUT" | grep 'SERVER_HEX=' | cut -d'=' -f2)
echo "✅ Device pairing finalized successfully! Server Key: $SERVER_HEX"

# Wait for Android pairing test to finish successfully
wait "$AM_PID" || {
    echo "❌ Android pairing instrumentation test failed. Log:"
    cat "$AM_LOG"
    exit 1
}
cat "$AM_LOG"

# Verify SAS matching between Desktop and Android
ANDROID_SAS=$(grep -o 'ANDROID_DERIVED_SAS=[0-9-]*' "$AM_LOG" | head -n1 | cut -d'=' -f2 || true)
if [ -z "$ANDROID_SAS" ]; then
    ANDROID_SAS=$(adb shell run-as "$APP_PKG" cat files/derived_sas.txt 2>/dev/null | tr -d '\r\n' || true)
fi
if [ -z "$ANDROID_SAS" ]; then
    ANDROID_SAS=$(adb logcat -d | grep -o 'Derived SAS: [0-9-]*' | tail -n1 | cut -d':' -f2 | tr -d ' \r\n' || true)
fi
echo "    Android Derived SAS: $ANDROID_SAS"

if [ -n "$SAS_CODE" ] && [ -n "$ANDROID_SAS" ] && [ "$ANDROID_SAS" = "$SAS_CODE" ]; then
    echo "✅ SAS Anti-MITM Verification PASSED! Both sides derived identical code: $SAS_CODE"
else
    echo "❌ ERROR: SAS Anti-MITM verification mismatch! Desktop=$SAS_CODE, Android=$ANDROID_SAS"
    exit 1
fi

# Verify paired servers in daemon
SERVERS_COUNT=$("$CLI_BIN" get-servers | grep 'COUNT=' | cut -d'=' -f2)
if [ "$SERVERS_COUNT" -lt 1 ]; then
    echo "❌ ERROR: No paired servers recorded in daemon state."
    exit 1
fi
echo "✅ Verified 1 paired Android device registered."

# Verify on-disk security properties of the real state directory (systemd mode)
if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
    echo "==> Verifying state directory security properties..."
    assert_stat /var/lib/tapauth "700 tapauthd tapauthd" "state dir mode/owner"
    assert_stat /run/tapauthd/tapauthd.sock "660 root tapauthd-clients" "IPC socket mode/owner"
    SECURE_FILES=$(find /var/lib/tapauth -maxdepth 1 -type f -perm 600 | wc -l)
    if [ "$SECURE_FILES" -ge 1 ]; then
        echo "✅ Keystore files present with owner-only (600) permissions: $SECURE_FILES file(s)"
    else
        echo "❌ ERROR: expected at least one 600-permission key file under /var/lib/tapauth"
        ls -la /var/lib/tapauth || true
        exit 1
    fi
    LOOSE_FILES=$(find /var/lib/tapauth -type f -perm /go+w 2>/dev/null | wc -l)
    if [ "$LOOSE_FILES" -eq 0 ]; then
        echo "✅ No group/world-writable files in state directory."
    else
        echo "❌ ERROR: found $LOOSE_FILES group/world-writable file(s) in /var/lib/tapauth:"
        find /var/lib/tapauth -type f -perm /go+w
        exit 1
    fi
fi

# Step 5b: Ensure runtime permissions and start Android app/background services
echo "==> Starting Android foreground services for authentication..."
adb shell am force-stop "$APP_PKG" 2>/dev/null || true
adb shell am start -n "$APP_PKG/dev.rourunisen.tapauth.MainActivity"
sleep 2

# Start background biometric auto-grant listener for auth tests
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" start-auto-grant
sleep 1

# Step 6: Phase 2 - Local Network (UDP) Authentication
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2: Local Network (UDP) End-to-End Authentication       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

echo "==> Setting transport config: UDP enabled, BLE disabled..."
"$CLI_BIN" set-transports --ble false --network true

# Verify the daemon persisted the toggle to the REAL config file and that the
# file has the production mode/ownership (systemd mode).
echo "==> Verifying persisted config file..."
if grep -q 'enable_network = true' "$CONFIG_ASSERT_FILE" && grep -q 'enable_ble = false' "$CONFIG_ASSERT_FILE"; then
    echo "✅ Transport toggles persisted to ${CONFIG_ASSERT_FILE}."
else
    echo "❌ ERROR: transport toggles not found in ${CONFIG_ASSERT_FILE}:"
    cat "$CONFIG_ASSERT_FILE" || true
    exit 1
fi
if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
    assert_stat "$CONFIG_ASSERT_FILE" "644 tapauthd tapauthd" "config file mode/owner"
fi

# Capture UDP traffic while the legitimate grant is exchanged; the adversarial
# phases (2c/2d) replay/tamper this captured grant against a fresh session.
# The capture is a passive AF_PACKET sniffer (root-only) — see udp_attack.py
# sniff for why this replaces tcpdump.
CAPTURE_MANDATORY=0
if [ "$(id -u)" -eq 0 ]; then
    CAPTURE_MANDATORY=1
    echo "==> Starting UDP packet capture (AF_PACKET sniffer)..."
    "$PYTHON_BIN" "$SCRIPT_DIR/ci/udp_attack.py" sniff --port "$UDP_PORT" --duration 30 \
        > "$TEST_DIR/grants.hex" 2> "$TEST_DIR/sniff.err" &
    CAPTURE_PID=$!
fi

echo "==> Requesting authentication for user '$TEST_USER'..."
UDP_AUTH_OUTPUT=$("$CLI_BIN" pam-auth "$TEST_USER" 20 || true)
echo "$UDP_AUTH_OUTPUT"

if echo "$UDP_AUTH_OUTPUT" | grep -q 'OUTCOME=SUCCESS'; then
    echo "✅ Local Network (UDP) Authentication PASSED!"
else
    echo "❌ Local Network (UDP) Authentication FAILED."
    if [ -f "$DAEMON_LOG" ]; then
        echo "=== DAEMON LOG DUMP ==="
        cat "$DAEMON_LOG"
        echo "======================="
    fi
    exit 1
fi

# Stop capture and take the first captured server grant packet
CAPTURE_OK=0
GRANT_HEX=""
if [ -n "$CAPTURE_PID" ]; then
    kill "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" 2>/dev/null || true
    CAPTURE_PID=""
    GRANT_HEX=$(head -n1 "$TEST_DIR/grants.hex" 2>/dev/null || true)
    [ -n "$GRANT_HEX" ] && CAPTURE_OK=1
fi

if [ "$CAPTURE_OK" = "1" ]; then
    echo "✅ Captured a server grant packet (${#GRANT_HEX} hex chars) for adversarial phases."
elif [ "$CAPTURE_MANDATORY" = "1" ]; then
    echo "❌ ERROR: packet capture produced no server grant packet — cannot run adversarial phases."
    echo "   (This is mandatory when running as root, e.g. CI.)"
    echo "--- sniffer stderr:"; cat "$TEST_DIR/sniff.err" 2>/dev/null || true
    echo "--- captured lines: $(wc -l < "$TEST_DIR/grants.hex" 2>/dev/null || echo 0)"
    exit 1
else
    echo "ℹ️  Adversarial UDP phases will be skipped (not running as root)."
fi

# Step 6b: Phase 2b - Real PAM Module Authentication (pamtester)
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2b: Real PAM Module Authentication (pamtester)         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

sleep 2

PAM_TESTABLE="false"
if command -v pamtester >/dev/null 2>&1 && [ -w /etc/pam.d ] && [ -f "$PAM_LIB" ]; then
    PAM_TESTABLE="true"
fi
PAM_GRANT_STACK_OK=0
PAM_FALLBACK_OK=0

if [ "$PAM_TESTABLE" = "true" ]; then
    echo "==> Configuring temporary PAM service at ${PAM_CONFIG_PATH}..."
    printf 'auth required %s\naccount required pam_permit.so\n' "$PAM_LIB" > "$PAM_CONFIG_PATH"

    echo "==> Executing pamtester for user '$TEST_USER'..."
    set +e
    # stdin = an open pipe that never delivers data: the module's credential
    # dialog must stay ALIVE for the phone-grant path to run. An EOF (e.g.
    # /dev/null) dismisses the dialog and cancels the transaction by design.
    "${PAM_ENV[@]}" pamtester "$PAM_SERVICE_NAME" "$TEST_USER" authenticate < <(sleep 30)
    PAM_EXIT=$?
    set -e

    rm -f "$PAM_CONFIG_PATH"

    if [ "$PAM_EXIT" -eq 0 ]; then
        echo "✅ Real PAM Module Authentication PASSED (exit code: $PAM_EXIT)!"
    else
        echo "❌ Real PAM Module Authentication FAILED (exit code: $PAM_EXIT)."
        exit 1
    fi

    # Phase 2e: mixed-stack semantics — a REAL PAM stack where TapAuth's
    # PAM_IGNORE must fall through to pam_unix, and a grant must skip it.
    #
    # NOTE 1: the module deliberately yields as soon as an authtok is available
    # ("password submission takes absolute precedence over any concurrent
    # daemon response"), so the grant path below holds stdin open WITHOUT data.
    # NOTE 2: the [success=1] jump MUST land on the trailing pam_permit line —
    # a jump that overshoots the end of the stack makes Linux-PAM return
    # PAM_PERM_DENIED even though the module succeeded.
    echo ""
    echo "==> Phase 2e: Mixed-stack PAM semantics (grant skips password, IGNORE falls back)..."
    printf 'auth [success=1 default=ignore] %s\nauth required pam_unix.so\nauth required pam_permit.so\naccount required pam_permit.so\n' "$PAM_LIB" > "$PAM_MIXED_CONFIG_PATH"

    set +e
    "${PAM_ENV[@]}" pamtester "$PAM_MIXED_SERVICE_NAME" "$TEST_USER" authenticate < <(sleep 30)
    MIXED_GRANT_EXIT=$?
    set -e

    if [ "$MIXED_GRANT_EXIT" -eq 0 ]; then
        echo "✅ Grant path: TapAuth SUCCESS bypassed the password module in a mixed stack."
        PAM_GRANT_STACK_OK=1
    else
        echo "❌ ERROR: mixed-stack grant path failed (exit $MIXED_GRANT_EXIT)."
        exit 1
    fi
else
    echo "ℹ️  Real PAM module testing skipped (/etc/pam.d not writable or pamtester missing)."
fi

# Helper: assert a pattern is present in the daemon log AFTER a given line
# offset (window-scoped, so stale matches from earlier phases don't count).
assert_log_since() {
    local base=$1 pattern=$2 label=$3
    if tail -n +"$((base + 1))" "$DAEMON_LOG" 2>/dev/null | grep -q "$pattern"; then
        echo "✅ ${label}"
    else
        echo "❌ ERROR (${label}): pattern '$pattern' not found in the daemon log for this phase."
        exit 1
    fi
}

# Step 6c: Phase 2c - Adversarial UDP: Replay of a captured grant + PamCancel
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2c: Adversarial UDP (Replay) & PamCancel IPC           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

if [ "$CAPTURE_OK" = "1" ]; then
    "$SCRIPT_DIR/ci/emulator-bio-helper.sh" stop-auto-grant
    sleep 1

    # Timing note: with no biometrics enrolled, the E2E app build auto-approves a
    # request after AuthRequestManager.DEBUG_AUTO_APPROVE_DELAY_MS (1s) plus prompt
    # overhead. Injections and the cancel below deliberately land inside that
    # window while the session is still pending.
    LOG_BASE=$(wc -l < "$DAEMON_LOG" 2>/dev/null || echo 0)
    REPLAY_REQUEST_ID="e2e-replay-$$"
    echo "==> Starting auth session (request id $REPLAY_REQUEST_ID) with no grant expected..."
    REPLAY_LOG="${TEST_DIR}/replay-cli.log"
    "$CLI_BIN" pam-auth "$TEST_USER" 30 "$REPLAY_REQUEST_ID" > "$REPLAY_LOG" 2>&1 &
    REPLAY_CLI_PID=$!
    sleep 0.3

    echo "==> Injecting captured grant from an OLD session (challenge mismatch expected)..."
    "$PYTHON_BIN" "$SCRIPT_DIR/ci/udp_attack.py" send "$GRANT_HEX" --port "$UDP_PORT"
    sleep 0.2
    echo "==> Re-injecting the SAME grant (same-session nonce cache expected)..."
    "$PYTHON_BIN" "$SCRIPT_DIR/ci/udp_attack.py" send "$GRANT_HEX" --port "$UDP_PORT"
    sleep 0.1

    echo "==> Cancelling the pending session via IPC before the app's auto-approval fires..."
    "$CLI_BIN" pam-cancel "$REPLAY_REQUEST_ID" "e2e-test" | tee "${TEST_DIR}/cancel.log"
    if ! grep -q "DETAIL=Cancel forwarded" "${TEST_DIR}/cancel.log"; then
        echo "❌ ERROR: daemon did not accept the cancel (no matching pending request)."
        exit 1
    fi
    # Give the journal follower time to deliver the daemon's audit lines.
    sleep 1

    assert_log_since "$LOG_BASE" "Grant challenge verification failed" \
        "Daemon rejected a grant whose challenge belongs to another session"
    assert_log_since "$LOG_BASE" "Replayed packet detected" \
        "Daemon nonce cache detected the duplicate packet"

    CANCEL_START=$SECONDS
    set +e
    wait_pid_with_timeout "$REPLAY_CLI_PID" 15
    REPLAY_EXIT=$?
    set -e
    CANCEL_ELAPSED=$(( SECONDS - CANCEL_START ))

    cat "$REPLAY_LOG"
    if [ "$REPLAY_EXIT" -ne 0 ] && grep -q "OUTCOME=IGNORE" "$REPLAY_LOG"; then
        echo "✅ Pending authentication was cancelled via IPC (OUTCOME=IGNORE, waited ${CANCEL_ELAPSED}s for the process)."
    else
        echo "❌ ERROR: expected cancelled session to exit with OUTCOME=IGNORE (rc=$REPLAY_EXIT)."
        exit 1
    fi

    # Restore auto-grant for the following positive phases
    "$SCRIPT_DIR/ci/emulator-bio-helper.sh" start-auto-grant
    sleep 1
else
    echo "ℹ️  SKIPPED (no captured grant packet available)."
fi

# Step 6d: Phase 2d - Adversarial UDP: Tampered packet must never authenticate
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2d: Adversarial UDP (Tampered Ciphertext)              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

if [ "$CAPTURE_OK" = "1" ]; then
    "$SCRIPT_DIR/ci/emulator-bio-helper.sh" stop-auto-grant
    sleep 1

    LOG_BASE=$(wc -l < "$DAEMON_LOG" 2>/dev/null || echo 0)
    TAMPER_REQUEST_ID="e2e-tamper-$$"
    echo "==> Starting auth session (request id $TAMPER_REQUEST_ID) with no grant expected..."
    TAMPER_LOG="${TEST_DIR}/tamper-cli.log"
    "$CLI_BIN" pam-auth "$TEST_USER" 30 "$TAMPER_REQUEST_ID" > "$TAMPER_LOG" 2>&1 &
    TAMPER_CLI_PID=$!
    # Inject inside the pre-grant window (DEBUG_AUTO_APPROVE_DELAY_MS is 1s).
    sleep 0.4

    echo "==> Injecting grant with a flipped AES-GCM tag byte..."
    "$PYTHON_BIN" "$SCRIPT_DIR/ci/udp_attack.py" send "$GRANT_HEX" --port "$UDP_PORT" --corrupt

    set +e
    wait_pid_with_timeout "$TAMPER_CLI_PID" 15
    TAMPER_EXIT=$?
    set -e
    # Give the journal follower time to deliver the daemon's audit lines.
    sleep 1
    cat "$TAMPER_LOG"

    # The daemon maps any authentication error to OUTCOME=IGNORE so that PAM
    # falls back to password authentication (fail-closed). The important
    # property: the tampered packet must abort the session IMMEDIATELY with a
    # crypto error instead of being accepted, and must be visible in the audit
    # log. A session that silently continued to timeout would still pass the
    # exit-code check below, so the DETAIL and log assertions are mandatory.
    if grep -q "OUTCOME=IGNORE" "$TAMPER_LOG"; then
        echo "✅ Tampered packet rejected; session ended fail-closed (OUTCOME=IGNORE → PAM password fallback)."
    else
        echo "❌ ERROR: expected fail-closed OUTCOME=IGNORE after tampered packet injection."
        exit 1
    fi
    if grep -q "DETAIL=Authentication failed" "$TAMPER_LOG"; then
        echo "✅ Session ended with the crypto error, not a silent timeout."
    else
        echo "❌ ERROR: expected DETAIL=Authentication failed... (got the output above)."
        exit 1
    fi
    assert_log_since "$LOG_BASE" "Failed to decrypt response packet" \
        "Daemon logged the decryption failure (audit trail present)"
    if [ "$TAMPER_EXIT" -ne 0 ]; then
        echo "✅ Exit code non-zero ($TAMPER_EXIT) — no successful authentication."
    else
        echo "❌ ERROR: tampered injection must not produce a successful exit code."
        exit 1
    fi

    # Restore auto-grant for the following positive phases
    "$SCRIPT_DIR/ci/emulator-bio-helper.sh" start-auto-grant
    sleep 1
else
    echo "ℹ️  SKIPPED (no captured grant packet available)."
fi

# Step 6f: Phase 2f - Hard cancellation on IPC client disconnect
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2f: Hard Cancellation on IPC Disconnect                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

"$SCRIPT_DIR/ci/emulator-bio-helper.sh" stop-auto-grant
sleep 1

LOG_BASE=$(wc -l < "$DAEMON_LOG" 2>/dev/null || echo 0)
DISCONNECT_REQ_ID="e2e-disconnect-$$"
echo "==> Spawning pam-auth in background then abruptly killing client process (simulating lockscreen password entry)..."
"$CLI_BIN" pam-auth "$TEST_USER" 60 "$DISCONNECT_REQ_ID" > /dev/null 2>&1 &
CLI_KILL_PID=$!
sleep 0.5

echo "==> Killing IPC client process (PID $CLI_KILL_PID)..."
kill -9 "$CLI_KILL_PID" || true
wait "$CLI_KILL_PID" 2>/dev/null || true
sleep 1.5

assert_log_since "$LOG_BASE" "IPC client disconnected while authentication" \
    "Daemon detected socket EOF/disconnect and cancelled in-flight auth"

# Restore auto-grant
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" start-auto-grant
sleep 1

# Step 6g: Phase 2g - Dual-Stack Secondary PAM stack
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2g: Dual-Stack Secondary PAM Return Code & Behavior    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

if [ "$PAM_TESTABLE" = "true" ]; then
    DUAL_STACK_SERVICE="kde-fingerprint"
    DUAL_STACK_PAM_PATH="/etc/pam.d/${DUAL_STACK_SERVICE}"
    
    # Backup pre-existing PAM file if present
    ORIG_PAM_BACKUP=""
    if [ -f "$DUAL_STACK_PAM_PATH" ]; then
        ORIG_PAM_BACKUP=$(cat "$DUAL_STACK_PAM_PATH")
    fi

    restore_dual_stack_pam() {
        if [ -n "$ORIG_PAM_BACKUP" ]; then
            printf "%s\n" "$ORIG_PAM_BACKUP" > "$DUAL_STACK_PAM_PATH"
        else
            rm -f "$DUAL_STACK_PAM_PATH"
        fi
    }
    trap restore_dual_stack_pam EXIT INT TERM

    # Distro-aware include
    INCLUDES="account include common-account\npassword include common-password\nsession include common-session"
    if [ -f /etc/pam.d/system-local-login ]; then
        INCLUDES="account include system-local-login\npassword include system-local-login\nsession include system-local-login"
    elif [ -f /etc/pam.d/system-auth ]; then
        INCLUDES="account include system-auth\npassword include system-auth\nsession include system-auth"
    fi
    
    echo "==> Configuring temporary decisive PAM service for ${DUAL_STACK_SERVICE}..."
    printf "#%%PAM-1.0\nauth        [success=done default=bad]    %s\n%b\n" "$PAM_LIB" "$INCLUDES" > "$DUAL_STACK_PAM_PATH"

    echo "==> Testing successful dual-stack authentication via pamtester..."
    "$SCRIPT_DIR/ci/emulator-bio-helper.sh" start-auto-grant
    sleep 1

    if "${PAM_ENV[@]}" pamtester -v "$DUAL_STACK_SERVICE" "$TEST_USER" authenticate < <(sleep 30); then
        echo "✅ Dual-stack secondary service returned PAM_SUCCESS on phone approval."
    else
        echo "❌ ERROR: expected PAM_SUCCESS on dual-stack authentication."
        restore_dual_stack_pam
        exit 1
    fi

    restore_dual_stack_pam
    # Reset exit trap back to general cleanup if cleanup() is defined
    trap cleanup EXIT INT TERM
else
    echo "ℹ️  SKIPPED (pamtester not available, PAM library missing, or /etc/pam.d not writable)."
fi

# Step 6h: Phase 2h - Virtual fprintd D-Bus verification
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2h: Virtual fprintd D-Bus Interface Verification       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

if command -v dbus-send >/dev/null 2>&1; then
    echo "==> Enabling virtual fprintd bridge via admin IPC..."
    "$CLI_BIN" set-transports --fprintd-bridge true

    echo "==> Querying net.reactivated.Fprint.Manager.GetDefaultDevice..."
    if dbus-send --system --print-reply --dest=net.reactivated.Fprint /net/reactivated/Fprint/Manager net.reactivated.Fprint.Manager.GetDefaultDevice > "${TEST_DIR}/fprint_dev.log" 2>&1; then
        echo "✅ Virtual fprintd responded to GetDefaultDevice on system bus"
        DEV_PATH=$(grep -o 'object path "[^"]*"' "${TEST_DIR}/fprint_dev.log" | cut -d'"' -f2 || true)
        if [ -n "$DEV_PATH" ]; then
            echo "==> Querying ListEnrolledFingers on device $DEV_PATH..."
            if dbus-send --system --print-reply --dest=net.reactivated.Fprint "$DEV_PATH" net.reactivated.Fprint.Device.ListEnrolledFingers string:"$TEST_USER" > "${TEST_DIR}/fprint_fingers.log" 2>&1; then
                if grep -q 'string "right-index-finger"' "${TEST_DIR}/fprint_fingers.log"; then
                    echo "✅ Virtual fprintd ListEnrolledFingers returned ['right-index-finger'] for user '$TEST_USER'"
                else
                    echo "❌ ERROR: ListEnrolledFingers did not return ['right-index-finger']:"
                    cat "${TEST_DIR}/fprint_fingers.log"
                    exit 1
                fi
            else
                echo "❌ ERROR: Virtual fprintd ListEnrolledFingers call failed:"
                cat "${TEST_DIR}/fprint_fingers.log"
                exit 1
            fi
        else
            echo "❌ ERROR: Could not parse device path from GetDefaultDevice output:"
            cat "${TEST_DIR}/fprint_dev.log"
            exit 1
        fi
    else
        if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
            echo "❌ ERROR: Virtual fprintd GetDefaultDevice call failed on system bus in systemd mode:"
            cat "${TEST_DIR}/fprint_dev.log"
            exit 1
        else
            echo "ℹ️  Virtual fprintd D-Bus call returned error (system bus permission or not running in test sandbox):"
            cat "${TEST_DIR}/fprint_dev.log"
        fi
    fi
else
    echo "ℹ️  SKIPPED (dbus-send not found)."
fi

# Step 7: Phase 3 - Bluetooth Low Energy (BLE) Authentication
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 3: Bluetooth Low Energy (BLE) Authentication           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

sleep 2

# Check if system D-Bus is accessible (e.g., host environment with BlueZ).
# In container environments, host D-Bus rejects cross-container Unix socket connections
# (REJECTED EXTERNAL), making BlueZ inaccessible; BLE is strictly verified on the host.
BLE_AVAILABLE=true
if ! dbus-send --system --dest=org.freedesktop.DBus / org.freedesktop.DBus.Peer.Ping >/dev/null 2>&1; then
    BLE_AVAILABLE=false
fi

BLE_OK=0
if [ "$BLE_AVAILABLE" = false ]; then
    echo "ℹ️  SKIPPED: System D-Bus / BlueZ not accessible in this environment (verified on host)."
else
    echo "==> Setting transport config: BLE enabled, UDP disabled..."
    "$CLI_BIN" set-transports --ble true --network false

    echo "==> Requesting authentication for user '$TEST_USER' over virtual BLE..."
    BLE_AUTH_OUTPUT=$("$CLI_BIN" pam-auth "$TEST_USER" 30 || true)
    echo "$BLE_AUTH_OUTPUT"

    if echo "$BLE_AUTH_OUTPUT" | grep -q 'OUTCOME=SUCCESS'; then
        echo "✅ Bluetooth Low Energy (BLE) Authentication PASSED!"
        BLE_OK=1
    else
        echo "❌ Bluetooth Low Energy (BLE) Authentication FAILED."
        if [ -f "$DAEMON_LOG" ]; then
            echo "=== DAEMON LOG DUMP ==="
            cat "$DAEMON_LOG"
            echo "======================="
        fi
        exit 1
    fi
fi

# Step 8: Phase 4 - Parallel Discovery Race (Both Enabled)
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 4: Parallel Discovery Race (UDP + BLE Simultaneous)    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

sleep 2

if [ "$BLE_AVAILABLE" = false ]; then
    echo "ℹ️  SKIPPED: System D-Bus / BlueZ not accessible in this environment (verified on host)."
else
    echo "==> Setting transport config: Both BLE and UDP enabled..."
    "$CLI_BIN" set-transports --ble true --network true

    PARALLEL_OUTPUT=$("$CLI_BIN" pam-auth "$TEST_USER" 30 || true)
    echo "$PARALLEL_OUTPUT"

    if echo "$PARALLEL_OUTPUT" | grep -q 'OUTCOME=SUCCESS'; then
        echo "✅ Parallel Discovery Race Authentication PASSED!"
    else
        echo "❌ Parallel Discovery Race Authentication FAILED."
        exit 1
    fi
fi

# Step 9: Phase 5 - Denial Testing
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 5: Explicit User Denial & Rejection Verification       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Stop auto-grant watcher
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" stop-auto-grant
sleep 2

echo "==> Setting transport config: UDP enabled, BLE disabled..."
"$CLI_BIN" set-transports --ble false --network true

echo "==> Initiating auth and simulating biometric rejection..."
DENIAL_OUT_LOG="${TEST_DIR}/denial-cli.log"
"$CLI_BIN" pam-auth "$TEST_USER" 10 > "$DENIAL_OUT_LOG" 2>&1 &
DENIAL_CLI_PID=$!

sleep 0.5
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" deny "$APP_PKG"

set +e
wait "$DENIAL_CLI_PID"
DENIAL_EXIT=$?
set -e

cat "$DENIAL_OUT_LOG"

if [ "$DENIAL_EXIT" -ne 0 ] && grep -q "OUTCOME=DENIED" "$DENIAL_OUT_LOG"; then
    echo "✅ Explicit Denial correctly rejected with OUTCOME=DENIED (exit code: $DENIAL_EXIT)."
else
    echo "❌ ERROR: Expected explicit denial with OUTCOME=DENIED, but got exit code $DENIAL_EXIT."
    if [ -f "$DAEMON_LOG" ]; then
        echo "=== DAEMON LOG DUMP ==="
        cat "$DAEMON_LOG"
        echo "======================="
    fi
    exit 1
fi

# Step 9b: Phase 5b - Authentication Timeout Verification
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 5b: Authentication Timeout Verification                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

sleep 1
# Stop the Android app so that no server responds to the broadcast, verifying daemon timeout handling
adb shell am force-stop "$APP_PKG" 2>/dev/null || true
sleep 1

echo "==> Requesting authentication with 2s timeout and no response..."
TIMEOUT_OUT_LOG="${TEST_DIR}/timeout-cli.log"
"$CLI_BIN" pam-auth "$TEST_USER" 2 > "$TIMEOUT_OUT_LOG" 2>&1 || true

cat "$TIMEOUT_OUT_LOG"

if grep -q "OUTCOME=TIMEOUT" "$TIMEOUT_OUT_LOG"; then
    echo "✅ Authentication Timeout correctly detected OUTCOME=TIMEOUT!"
else
    echo "❌ ERROR: Expected OUTCOME=TIMEOUT, but got:"
    cat "$TIMEOUT_OUT_LOG"
    exit 1
fi

# Step 10: Phase 6 - Device Removal / Un-pairing (+ mixed-stack password fallback)
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 6: Device Removal / Un-pairing Lifecycle               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

echo "==> Removing paired device $SERVER_HEX..."
"$CLI_BIN" remove-device "$SERVER_HEX"

REMAINING=$("$CLI_BIN" get-servers | grep 'COUNT=' | cut -d'=' -f2)
if [ "$REMAINING" -eq 0 ]; then
    echo "✅ Device successfully removed. Remaining paired devices: 0"
else
    echo "❌ ERROR: Device removal failed, count=$REMAINING."
    exit 1
fi

sleep 2
echo "==> Verifying authentication returns PAM_IGNORE when no devices are configured..."
UNPAIRED_AUTH_LOG="${TEST_DIR}/unpaired-cli.log"
"$CLI_BIN" pam-auth "$TEST_USER" 5 > "$UNPAIRED_AUTH_LOG" 2>&1 || true
cat "$UNPAIRED_AUTH_LOG"

if grep -q "OUTCOME=IGNORE" "$UNPAIRED_AUTH_LOG"; then
    echo "✅ Un-paired authentication correctly returns OUTCOME=IGNORE (password fallback enabled)!"
else
    echo "❌ ERROR: Expected OUTCOME=IGNORE after device removal, but got:"
    cat "$UNPAIRED_AUTH_LOG"
    exit 1
fi

# Mixed-stack password fallback with the real PAM module: with no paired
# devices TapAuth yields PAM_IGNORE, so the stack must fall through to
# pam_unix and the LOCAL PASSWORD decides.
if [ "$PAM_TESTABLE" = "true" ] && [ "$(id -u)" -eq 0 ]; then
    echo ""
    echo "==> Phase 6b: Mixed-stack password fallback after un-pairing..."
    if ! id "$PAM_FALLBACK_USER" >/dev/null 2>&1; then
        useradd -m "$PAM_FALLBACK_USER"
    fi
    echo "${PAM_FALLBACK_USER}:${PAM_FALLBACK_PASS}" | chpasswd

    if [ ! -f "$PAM_MIXED_CONFIG_PATH" ]; then
        # Same stack shape as Phase 2e (trailing pam_permit so the
        # [success=1] jump can never overshoot the stack).
        printf 'auth [success=1 default=ignore] %s\nauth required pam_unix.so\nauth required pam_permit.so\naccount required pam_permit.so\n' "$PAM_LIB" > "$PAM_MIXED_CONFIG_PATH"
    fi

    set +e
    echo "$PAM_FALLBACK_PASS" | "${PAM_ENV[@]}" pamtester "$PAM_MIXED_SERVICE_NAME" "$PAM_FALLBACK_USER" authenticate
    FALLBACK_OK_EXIT=$?
    echo "definitely-not-the-password" | "${PAM_ENV[@]}" pamtester "$PAM_MIXED_SERVICE_NAME" "$PAM_FALLBACK_USER" authenticate
    FALLBACK_BAD_EXIT=$?
    set -e

    if [ "$FALLBACK_OK_EXIT" -eq 0 ]; then
        echo "✅ PAM_IGNORE fell through to pam_unix; correct password authenticated."
        PAM_FALLBACK_OK=1
    else
        echo "❌ ERROR: password fallback did not work after TapAuth IGNORE (rc=$FALLBACK_OK_EXIT)."
        exit 1
    fi
    if [ "$FALLBACK_BAD_EXIT" -ne 0 ]; then
        echo "✅ Wrong password correctly rejected after TapAuth IGNORE."
    else
        echo "❌ ERROR: wrong password was accepted — password module did not enforce!"
        exit 1
    fi
    passwd -l "$PAM_FALLBACK_USER" >/dev/null 2>&1 || true
fi

# Step 11: Phase 7 - IPC Authorization (PolKit) Enforcement
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 7: Admin IPC Authorization Enforcement (PolKit)        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
    echo "==> Creating unprivileged probe user (member of tapauthd-clients)..."
    if ! id "$ADMIN_DENY_USER" >/dev/null 2>&1; then
        useradd -m "$ADMIN_DENY_USER"
    fi
    usermod -aG tapauthd-clients "$ADMIN_DENY_USER"

    LOG_BASE=$(wc -l < "$DAEMON_LOG" 2>/dev/null || echo 0)
    echo "==> Admin request as unprivileged user (must be denied by the daemon)..."
    set +e
    runuser -u "$ADMIN_DENY_USER" -- "$CLI_BIN" get-servers > "${TEST_DIR}/deny-admin.log" 2>&1
    DENY_EXIT=$?
    set -e
    cat "${TEST_DIR}/deny-admin.log"

    if [ "$DENY_EXIT" -ne 0 ] && grep -q "ERROR" "${TEST_DIR}/deny-admin.log"; then
        echo "✅ Unprivileged admin request denied (exit code: $DENY_EXIT)."
    else
        echo "❌ ERROR: unprivileged admin request was NOT denied (exit code: $DENY_EXIT)!"
        exit 1
    fi
    sleep 1
    assert_log_since "$LOG_BASE" "Unauthorized admin request" \
        "Daemon logged the unauthorized attempt (audit trail present)"

    echo "==> Socket access gate: user outside 'tapauthd-clients' must not connect..."
    set +e
    runuser -u nobody -- "$CLI_BIN" get-servers > "${TEST_DIR}/deny-socket.log" 2>&1
    SOCKET_DENY_EXIT=$?
    set -e
    cat "${TEST_DIR}/deny-socket.log"
    if [ "$SOCKET_DENY_EXIT" -ne 0 ]; then
        echo "✅ Unprivileged non-group member could not reach the IPC socket (exit code: $SOCKET_DENY_EXIT)."
    else
        echo "❌ ERROR: 'nobody' unexpectedly reached the IPC socket!"
        exit 1
    fi
else
    echo "ℹ️  SKIPPED (systemd mode only — dev-mode sandbox does not model production authz)."
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  E2E TEST MATRIX SUMMARY                                      ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║  Phase 1: Real TCP Pairing & SAS Anti-MITM:      PASSED       ║"
echo "║  Phase 2: Local Network (UDP) Authentication:    PASSED       ║"
if [ "$PAM_TESTABLE" = "true" ]; then
echo "║  Phase 2b: Real PAM Module (pamtester):          PASSED       ║"
if [ "$PAM_GRANT_STACK_OK" = "1" ]; then
echo "║  Phase 2e: Mixed-stack PAM (grant path):         PASSED       ║"
else
echo "║  Phase 2e: Mixed-stack PAM (grant path):         SKIPPED      ║"
fi
else
echo "║  Phase 2b: Real PAM Module (pamtester):          SKIPPED      ║"
echo "║  Phase 2e: Mixed-stack PAM (grant path):         SKIPPED      ║"
fi
if [ "$CAPTURE_OK" = "1" ]; then
echo "║  Phase 2c: Adversarial Replay + PamCancel:       PASSED       ║"
echo "║  Phase 2d: Adversarial Tampered Ciphertext:      PASSED       ║"
else
echo "║  Phase 2c: Adversarial Replay + PamCancel:       SKIPPED      ║"
echo "║  Phase 2d: Adversarial Tampered Ciphertext:      SKIPPED      ║"
fi
if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
echo "║  Phase 7: Admin IPC Authorization (PolKit):      PASSED       ║"
echo "║  Daemon mode: systemd socket activation (prod)   ✔            ║"
else
echo "║  Daemon mode: dev sandbox (fallback-socket)      ✔            ║"
fi
# Phase 6b runs whenever the PAM stack is testable and the suite is root —
# which includes a root-forced dev-mode run — so report it mode-independently.
if [ "$PAM_FALLBACK_OK" = "1" ]; then
echo "║  Phase 6b: Mixed-stack PAM password fallback:    PASSED       ║"
else
echo "║  Phase 6b: Mixed-stack PAM password fallback:    SKIPPED      ║"
fi
if [ "${BLE_OK:-0}" = "1" ]; then
echo "║  Phase 3: Bluetooth Low Energy (BLE):            PASSED       ║"
echo "║  Phase 4: Parallel Race (UDP + BLE):             PASSED       ║"
else
echo "║  Phase 3: Bluetooth Low Energy (BLE):            SKIPPED      ║"
echo "║  Phase 4: Parallel Race (UDP + BLE):             SKIPPED      ║"
fi
echo "║  Phase 5: Explicit Denial & Rejection:           PASSED       ║"
echo "║  Phase 5b: Authentication Timeout:               PASSED       ║"
echo "║  Phase 6: Device Removal & PAM_IGNORE:           PASSED       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "🎉 ALL MANDATORY END-TO-END TESTS PASSED SUCCESSFULLY!"
