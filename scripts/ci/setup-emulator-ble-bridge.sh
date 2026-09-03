#!/bin/bash
# Sets up Google Bumble Virtual HCI bridge connecting Android Emulator Netsim to Linux host /dev/vhci
#
# Virtual BLE is a hard requirement of the E2E suite: when no virtual HCI adapter
# can be created this script exits non-zero, and test-e2e.sh (running under
# `set -e`) aborts before any phase executes. There is intentionally no
# "skip BLE" path.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Configuring Virtual Bluetooth Bridge (Bumble <-> Netsim)..."

# CI runners are unprivileged-but-sudoable; a root shell needs no prefix.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

# If Bumble is already running (e.g. started on host), don't restart or reinstall
if [ -f /tmp/bumble-bridge.pid ]; then
    echo "    bumble-hci-bridge is already running (PID $(cat /tmp/bumble-bridge.pid 2>/dev/null || echo unknown))."
    exit 0
fi

# Ensure the vhci module is loaded and /dev/vhci is writable by us.
if [ ! -w /dev/vhci ]; then
    if [ -f "$SCRIPT_DIR/build-kernel-vhci.sh" ]; then
        bash "$SCRIPT_DIR/build-kernel-vhci.sh"
    fi
fi

if [ ! -w /dev/vhci ]; then
    echo "❌ ERROR: Virtual HCI (/dev/vhci) is not writable by the current user."
    echo "   Load hci_vhci (or run scripts/ci/build-kernel-vhci.sh) and grant access first."
    exit 1
fi

# BlueZ userspace (hciconfig/btmgmt) — installed here only when missing, so a
# local first run works without re-running apt on every CI invocation.
if ! command -v hciconfig >/dev/null 2>&1 || ! command -v btmgmt >/dev/null 2>&1; then
    echo "    Installing BlueZ tools..."
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq bluez bluez-tools
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y bluez bluez-deprecated 2>/dev/null || true
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Sy --noconfirm bluez bluez-utils 2>/dev/null || true
    fi
fi

if ! pgrep -x bluetoothd > /dev/null; then
    $SUDO systemctl start bluetooth 2>/dev/null \
        || { $SUDO sh -c 'bluetoothd -n -d > /tmp/bluetoothd.log 2>&1' & sleep 2; }
fi

# Bumble provides the netsim <-> vhci bridge. Install into the invoking user's
# site-packages: this runner's system Python owns a typing-extensions copy that
# pip is not allowed to replace, and --user sidesteps that (and needs no sudo).
# The second form is for pip releases older than 23.0, which lack the flag.
if ! python3 -c "import bumble" 2>/dev/null; then
    echo "    Installing Bumble (android-netsim extra)..."
    python3 -m pip install --user --break-system-packages "bumble[android-netsim]" grpcio protobuf \
        || python3 -m pip install "bumble[android-netsim]" grpcio protobuf \
        || {
            echo "❌ ERROR: could not install Bumble (both pip forms failed)."
            exit 1
        }
fi

# Capture existing hci devices to detect the newly created one
EXISTING_HCI=$(hciconfig 2>/dev/null | grep -o '^hci[0-9]*' || true)

# Launch bumble-hci-bridge connecting emulator netsim to /dev/vhci
echo "    Starting bumble-hci-bridge (android-netsim <-> vhci)..."
BUMBLE_LOG="/tmp/bumble-bridge.log"

if command -v bumble-hci-bridge >/dev/null 2>&1; then
    bumble-hci-bridge android-netsim "vhci:" > "$BUMBLE_LOG" 2>&1 &
else
    python3 -m bumble.apps.hci_bridge android-netsim "vhci:" > "$BUMBLE_LOG" 2>&1 &
fi
BUMBLE_PID=$!

echo "$BUMBLE_PID" > /tmp/bumble-bridge.pid
echo "    bumble-hci-bridge running with PID $BUMBLE_PID (logs: $BUMBLE_LOG)"

# Give Bumble and kernel time to perform the initial vendor handshake and register the adapter
sleep 5

# Wait for new virtual HCI adapter to appear (up to 10s)
NEW_HCI=""
for _ in {1..50}; do
    CURRENT_HCI=$(hciconfig 2>/dev/null | grep -o '^hci[0-9]*' || true)
    for dev in $CURRENT_HCI; do
        if ! echo "$EXISTING_HCI" | grep -qw "$dev"; then
            NEW_HCI="$dev"
            break 2
        fi
    done
    # If no previous adapters existed and one appeared, use the first one
    if [ -z "$EXISTING_HCI" ] && [ -n "$CURRENT_HCI" ]; then
        NEW_HCI=$(echo "$CURRENT_HCI" | head -n 1)
        break
    fi
    sleep 0.2
done

if [ -z "$NEW_HCI" ]; then
    echo "❌ ERROR: No virtual Bluetooth adapter (HCI) detected after bridge launch."
    if [ -f "$BUMBLE_LOG" ]; then
        echo "=== BUMBLE BRIDGE LOG ==="
        cat "$BUMBLE_LOG"
        echo "========================="
    fi
    exit 1
fi

echo "✅ Virtual Bluetooth adapter detected: $NEW_HCI"
INDEX=$(echo "$NEW_HCI" | sed 's/hci//')

# Power on adapter with retries
for _ in {1..10}; do
    $SUDO btmgmt --index "$INDEX" power on 2>/dev/null || $SUDO btmgmt power on 2>/dev/null || bluetoothctl power on 2>/dev/null || true
    $SUDO hciconfig "$NEW_HCI" up 2>/dev/null || true
    if $SUDO btmgmt info 2>/dev/null | grep -q "current settings:.*powered"; then
        echo "✅ $NEW_HCI powered on successfully."
        break
    fi
    sleep 1
done

echo "--- Adapter details ---"
$SUDO btmgmt info 2>/dev/null || true
bluetoothctl show 2>/dev/null || true

echo "✅ Virtual BLE bridge setup completed."
