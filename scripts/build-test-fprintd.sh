#!/bin/bash
# Build and test the TapAuth mock fprintd D-Bus service integration
#
# Starts tapauthd with the mock fprintd provider, verifies the D-Bus
# name registration, then runs fprintd-verify against the virtual device.
#
# Intentionally avoid `set -e` to keep logs visible on failure; check critical steps manually

ORIGINAL_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges. Please re-run with: sudo $0"
    cd "$ORIGINAL_DIR"
    exit 1
fi

# ── Argument parsing ──

NO_BLE=0
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            echo "Usage: sudo $0 [--no-ble] [username]"
            echo ""
            echo "Build and test the TapAuth mock fprintd D-Bus service."
            echo "Starts tapauthd with fallback-socket, registers on net.reactivated.Fprint,"
            echo "then invokes fprintd-verify to exercise the virtual biometric device."
            echo ""
            echo "Options:"
            echo "  --no-ble     Build tapauthd without BLE support"
            echo ""
            echo "Arguments:"
            echo "  username     Optional. The user to verify fingerprints for."
            echo "               Defaults to the user who invoked sudo."
            cd "$ORIGINAL_DIR"
            exit 0
            ;;
        --no-ble)
            NO_BLE=1
            shift
            ;;
        *)
            POSITIONAL+=("$1"); shift
            ;;
    esac
done
set -- "${POSITIONAL[@]}"

if [ -n "$SUDO_USER" ]; then
    DEFAULT_TEST_USER="$SUDO_USER"
else
    DEFAULT_TEST_USER="$(whoami)"
fi
TEST_USER="${1:-$DEFAULT_TEST_USER}"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║      TapAuth fprintd Mock Interface — Production Test         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Target verification user : $TEST_USER"
echo "  BLE support              : $([ "$NO_BLE" -eq 1 ] && echo 'disabled' || echo 'enabled')"
echo ""

# ── Configuration constants ──

TAPAUTHD_BIN="target/release/tapauthd"
DBUS_POLICY_SRC="packaging/net.reactivated.Fprint.tapauth.conf"
DBUS_POLICY_DEST="/etc/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf"
CONFIG_DIR="/var/lib/tapauth"
SOCK_PATH="/run/tapauthd/tapauthd.sock"
DAEMON_PID=""

# ── Pre-flight validations ──

if ! id "$TEST_USER" &>/dev/null; then
    echo "User '$TEST_USER' does not exist on this system."
    cd "$ORIGINAL_DIR"; exit 1
fi

if ! command -v fprintd-verify &>/dev/null; then
    echo "'fprintd-verify' not found. Install the fprintd package for the test utility:"
    echo "  sudo pacman -S fprintd    # Arch / CachyOS"
    echo "  sudo apt install fprintd  # Debian / Ubuntu"
    echo "  sudo dnf install fprintd  # Fedora"
    cd "$ORIGINAL_DIR"; exit 1
fi

# ── Capture prior system state for teardown ──

WAS_FPRINTD_ACTIVE=0
WAS_FPRINTD_MASKED=0
HAS_OLD_POLICY=0

if systemctl is-active --quiet fprintd 2>/dev/null; then WAS_FPRINTD_ACTIVE=1; fi
if systemctl is-enabled fprintd 2>/dev/null | grep -q "masked"; then WAS_FPRINTD_MASKED=1; fi

if [ -f "$DBUS_POLICY_DEST" ]; then
    HAS_OLD_POLICY=1
    cp "$DBUS_POLICY_DEST" "${DBUS_POLICY_DEST}.bak"
fi

# ── Cleanup engine ──

cleanup() {
    echo ""
    echo "==> Cleaning up environment and restoring prior state..."

    local GRACE_SECONDS="1"
    if [ -n "$TAPAUTHD_GRACE_MS" ]; then
        GRACE_SECONDS=$(awk -v ms="$TAPAUTHD_GRACE_MS" 'BEGIN{ printf "%.3f", ms/1000 }')
    elif [ -n "$TAPAUTHD_GRACE_SECONDS" ]; then
        GRACE_SECONDS="$TAPAUTHD_GRACE_SECONDS"
    fi
    echo "    Granting daemon grace period: ${GRACE_SECONDS}s before teardown"
    sleep "$GRACE_SECONDS"

    if [ -n "$DAEMON_PID" ]; then
        echo "    Terminating tapauthd (PID=$DAEMON_PID)..."
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi

    if [ "$HAS_OLD_POLICY" -eq 1 ]; then
        mv "${DBUS_POLICY_DEST}.bak" "$DBUS_POLICY_DEST"
    else
        rm -f "$DBUS_POLICY_DEST"
    fi
    if systemctl is-active --quiet dbus-broker 2>/dev/null; then
        systemctl reload dbus-broker 2>/dev/null || true
    elif systemctl is-active --quiet dbus 2>/dev/null; then
        systemctl reload dbus 2>/dev/null || true
    elif command -v killall &>/dev/null; then
        killall -HUP dbus-daemon 2>/dev/null || true
    fi

    systemctl unmask fprintd 2>/dev/null || true
    if [ "$WAS_FPRINTD_MASKED" -eq 1 ]; then systemctl mask fprintd 2>/dev/null || true; fi
    if [ "$WAS_FPRINTD_ACTIVE" -eq 1 ]; then systemctl start fprintd 2>/dev/null || true; fi

    echo "Teardown completed."
    cd "$ORIGINAL_DIR"
}
trap cleanup EXIT

# ── Kill any lingering tapauthd from a previous broken run ──

pkill -x "tapauthd" 2>/dev/null || true
sleep 0.2

# ── Workspace & state initialization ──

echo "==> Initializing workspace and state directories..."

if ! id tapauthd >/dev/null 2>&1; then
    useradd --system --home /nonexistent --shell /usr/sbin/nologin tapauthd || true
fi

mkdir -p "$CONFIG_DIR"
chown tapauthd:tapauthd "$CONFIG_DIR" 2>/dev/null || true
chmod 700 "$CONFIG_DIR"

mkdir -p /run/tapauthd
chmod 755 /run/tapauthd

# ── Install D-Bus policy ──

echo "==> Installing D-Bus policy for net.reactivated.Fprint..."
cp "$DBUS_POLICY_SRC" "$DBUS_POLICY_DEST"
# Reload D-Bus config so the policy takes effect.
# dbus-broker watches /etc/dbus-1/system.d via inotify, but may
# not have picked up the file yet. Force a reload where possible.
if systemctl is-active --quiet dbus-broker 2>/dev/null; then
    systemctl reload dbus-broker 2>/dev/null || true
elif systemctl is-active --quiet dbus 2>/dev/null; then
    systemctl reload dbus 2>/dev/null || true
elif command -v killall &>/dev/null; then
    killall -HUP dbus-daemon 2>/dev/null || true
fi
sleep 0.3

# ── Suppress the real fprintd service ──

systemctl stop fprintd 2>/dev/null || true
systemctl mask fprintd 2>/dev/null || true

# ── Build ──

echo ""
echo "==> Building tapauthd (release)..."

if [ -n "$SUDO_USER" ]; then
    ORIGINAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [ -z "$ORIGINAL_HOME" ]; then
        ORIGINAL_HOME="/home/$SUDO_USER"
    fi
    CARGO_PATH=""
    for candidate in \
        "${ORIGINAL_HOME}/.cargo/bin/cargo" \
        "/usr/bin/cargo" \
        "/usr/local/bin/cargo" \
        "/opt/cargo/bin/cargo"; do
        if [ -x "$candidate" ]; then
            CARGO_PATH="$candidate"
            break
        fi
    done
    if [ -z "$CARGO_PATH" ]; then
        echo "Cargo executable not found. Ensure Rust is installed (rustup or system package)."
        echo "Checked: ~/.cargo/bin/cargo, /usr/bin/cargo, /usr/local/bin/cargo"
        cd "$ORIGINAL_DIR"; exit 1
    fi
    echo "    Building as $SUDO_USER (NO_BLE=$NO_BLE, fallback-socket enabled, cargo at $CARGO_PATH)..."
    if [ "$NO_BLE" -eq 1 ]; then
        sudo -u "$SUDO_USER" "$CARGO_PATH" build --release -p tapauthd \
            --no-default-features --features firewall,fallback-socket \
            || { echo "tapauthd build failed"; cd "$ORIGINAL_DIR"; exit 1; }
    else
        sudo -u "$SUDO_USER" "$CARGO_PATH" build --release -p tapauthd \
            --features fallback-socket \
            || { echo "tapauthd build failed"; cd "$ORIGINAL_DIR"; exit 1; }
    fi
else
    if ! command -v cargo &>/dev/null; then
        echo "cargo command not found in PATH."
        cd "$ORIGINAL_DIR"; exit 1
    fi
    echo "    Building as $(whoami) (NO_BLE=$NO_BLE, fallback-socket enabled)..."
    if [ "$NO_BLE" -eq 1 ]; then
        cargo build --release -p tapauthd \
            --no-default-features --features firewall,fallback-socket \
            || { echo "tapauthd build failed"; cd "$ORIGINAL_DIR"; exit 1; }
    else
        cargo build --release -p tapauthd \
            --features fallback-socket \
            || { echo "tapauthd build failed"; cd "$ORIGINAL_DIR"; exit 1; }
    fi
fi

if [ ! -f "$TAPAUTHD_BIN" ] || [ ! -x "$TAPAUTHD_BIN" ]; then
    echo "Build failed: tapauthd binary not found at $TAPAUTHD_BIN"
    cd "$ORIGINAL_DIR"; exit 1
fi
echo "    Build successful: $TAPAUTHD_BIN"

# ── Launch daemon ──

echo ""
echo "==> Spawning tapauthd with mock fprintd provider..."
env RUST_LOG="debug" TAPAUTHD_SOCK="$SOCK_PATH" ./"$TAPAUTHD_BIN" &
DAEMON_PID=$!

# ── Wait for D-Bus name registration ──

echo -n "    Awaiting net.reactivated.Fprint on the system bus"
for i in $(seq 1 50); do
    if busctl status net.reactivated.Fprint &>/dev/null; then
        echo ""
        echo "    Well-known bus name claimed successfully."
        break
    fi
    echo -n "."
    sleep 0.1
done

if ! busctl status net.reactivated.Fprint &>/dev/null; then
    echo ""
    echo "Timeout: Daemon failed to claim net.reactivated.Fprint on the system bus."
    echo "Check daemon logs above for details (missing D-Bus policy, permissions, etc.)."
    exit 1
fi

# ── Run fprintd-verify ──

echo ""
echo "==> Running fprintd-verify for user '$TEST_USER'..."
echo "----------------------------------------------------------------------"
echo "  fprintd-verify will call Claim → VerifyStart on the virtual device."
echo "  If you have a paired Android device, approve the prompt there."
echo "  Otherwise the mock will time out and report verify-unknown-error."
echo "----------------------------------------------------------------------"
echo ""

set +e
fprintd-verify "$TEST_USER"
VERIFY_EXIT_CODE=$?

echo ""
if [ "$VERIFY_EXIT_CODE" -eq 0 ]; then
    echo "fprintd-verify: PASS (exit 0)"
else
    echo "fprintd-verify: exit code $VERIFY_EXIT_CODE (expected with no paired device)"
fi

exit $VERIFY_EXIT_CODE
