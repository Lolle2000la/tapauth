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

# Bridge-only mode: ensure the Bumble bridge is up but leave the Bluetooth
# daemon alone. Used on the host before the Fedora/Arch systemd containers,
# which run their own bluetoothd and must own the vhci adapter.
BRIDGE_ONLY="${TAPAUTH_E2E_BLE_BRIDGE_ONLY:-0}"

# Shared record of the vhci adapter the host bridge created, so the systemd
# containers pick the Bumble adapter rather than an unrelated real controller.
VHCI_DEV_FILE="/tmp/tapauth-vhci-dev"

# External-bridge mode: the Bumble bridge runs on the host (it needs Netsim on
# the host network and /dev/vhci); this environment's job is only to run its
# own bluetoothd and own the resulting adapter. Used inside the systemd
# containers, which cannot see the host Bumble PID because they do not use
# --pid=host.
if [ "${TAPAUTH_E2E_EXTERNAL_BLE_BRIDGE:-0}" = "1" ]; then
    echo "==> External BLE bridge: verifying adapter + bluetoothd (bridge is host-managed)..."
    if ! pgrep -x bluetoothd >/dev/null; then
        $SUDO systemctl start bluetooth 2>/dev/null \
            || { $SUDO sh -c 'bluetoothd -n -d > /tmp/bluetoothd.log 2>&1' & sleep 2; }
    fi
    if ! pgrep -x bluetoothd >/dev/null; then
        echo "❌ ERROR: bluetoothd is not running in this container."
        exit 1
    fi

    NEW_HCI=""
    RECORDED=""
    [ -s "$VHCI_DEV_FILE" ] && RECORDED="$(cat "$VHCI_DEV_FILE" 2>/dev/null || true)"
    for _ in {1..50}; do
        if [ -n "$RECORDED" ] && [ -e "/sys/class/bluetooth/$RECORDED" ]; then
            NEW_HCI="$RECORDED"
            break
        fi
        if [ -z "$RECORDED" ]; then
            for dev in /sys/class/bluetooth/hci*; do
                [ -e "$dev" ] || continue
                NEW_HCI="$(basename "$dev")"
                break
            done
            [ -n "$NEW_HCI" ] && break
        fi
        sleep 0.2
    done
    if [ -z "$NEW_HCI" ]; then
        # The recorded adapter never appeared; fall back to any adapter.
        for dev in /sys/class/bluetooth/hci*; do
            [ -e "$dev" ] || continue
            NEW_HCI="$(basename "$dev")"
            break
        done
    fi
    if [ -z "$NEW_HCI" ]; then
        echo "❌ ERROR: no virtual HCI adapter found; the host Bumble bridge must be running."
        exit 1
    fi
    INDEX="${NEW_HCI#hci}"
    for _ in {1..10}; do
        $SUDO btmgmt --index "$INDEX" power on 2>/dev/null || $SUDO btmgmt power on 2>/dev/null || true
        if $SUDO btmgmt info 2>/dev/null | grep -q "current settings:.*powered"; then
            break
        fi
        sleep 1
    done
    echo "✅ External BLE bridge verified: $NEW_HCI (owned by this environment's bluetoothd)"
    exit 0
fi

# If Bumble is already running (e.g. started on host), don't restart Bumble,
# but verify that bluetoothd is active and the virtual adapter is powered on.
if [ -f /tmp/bumble-bridge.pid ]; then
    EXISTING_PID=$(cat /tmp/bumble-bridge.pid 2>/dev/null || true)
    if [ -n "$EXISTING_PID" ] && kill -0 "$EXISTING_PID" 2>/dev/null; then
        echo "    bumble-hci-bridge is already running (PID $EXISTING_PID)."
        if [ "$BRIDGE_ONLY" != "1" ] && ! pgrep -x bluetoothd > /dev/null; then
            $SUDO systemctl start bluetooth 2>/dev/null \
                || { $SUDO sh -c 'bluetoothd -n -d > /tmp/bluetoothd.log 2>&1' & sleep 2; }
        fi
        $SUDO btmgmt power on 2>/dev/null || bluetoothctl power on 2>/dev/null || true
        # Record which adapter the bridge owns for the systemd containers, if the
        # initial (fresh-start) invocation has not already done so.
        if [ ! -s "$VHCI_DEV_FILE" ]; then
            for dev in /sys/class/bluetooth/hci*; do
                [ -e "$dev" ] || continue
                basename "$dev" > "$VHCI_DEV_FILE"
                break
            done
        fi
        exit 0
    fi
    # A stale pid file (interrupted run, crashed bridge) must not make us skip
    # setup: the bridge is gone, so btmgmt would "succeed" against nothing and
    # the run would fail later with no hint. Fall through to a fresh start.
    echo "    Removing stale /tmp/bumble-bridge.pid (PID ${EXISTING_PID:-unknown} not running)."
    rm -f /tmp/bumble-bridge.pid
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

if [ "$BRIDGE_ONLY" != "1" ] && ! pgrep -x bluetoothd > /dev/null; then
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
echo "$NEW_HCI" > "$VHCI_DEV_FILE"
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
