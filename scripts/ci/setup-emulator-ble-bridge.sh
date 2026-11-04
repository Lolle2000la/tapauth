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

# `btmgmt` goes through the kernel mgmt API and is satisfied by *any*
# bluetoothd (or by none at all), so it cannot tell "this environment's BlueZ
# owns the adapter" from "another bluetoothd claimed it". The daemon under test
# enumerates adapters over D-Bus (`session.adapter_names()` in
# tapauthd/src/transport/ble.rs), so ask the local bluetoothd through
# `bluetoothctl list`: that fails exactly when tapauthd would log
# "No Bluetooth adapter found" and silently fall back to UDP-only.
#
# Every `bluetoothctl` call must go through here. bluetoothctl talks to the
# local bluetoothd over D-Bus and blocks *indefinitely* waiting for the
# `org.bluez` bus name when none is running — which is the normal state of the
# host while the containers own the adapter (that is the whole point of the
# mask in run-all-e2e.sh). An unbounded call here once hung the E2E job for 60
# minutes. Callers that poll may tighten BTCTL_TIMEOUT with a `local`.
BTCTL_TIMEOUT="${BTCTL_TIMEOUT:-10}"
btctl() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$BTCTL_TIMEOUT" bluetoothctl "$@" 2>&1 || true
    else
        bluetoothctl "$@" 2>&1 || true
    fi
}

# BlueZ-side "power on" is only meaningful for a bluetoothd this environment
# owns: under BRIDGE_ONLY the adapter belongs to the containers' bluetoothd and
# the host daemon is masked, so there is no bus name to talk to.
bluez_power_on() {
    [ "$BRIDGE_ONLY" != "1" ] || return 0
    btctl power on
}

show_bluetooth_diagnostics() {
    echo "--- pgrep -a bluetoothd ---"
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -a bluetoothd || echo "(no bluetoothd process)"
    else
        echo "(pgrep not available)"
    fi
    echo "--- systemctl status bluetooth (tail) ---"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl status bluetooth --no-pager 2>&1 | tail -30 || true
    else
        echo "(systemctl not available)"
    fi
    echo "--- journalctl -u bluetooth (this boot, tail) ---"
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u bluetooth --no-pager -b 2>&1 | tail -40 || true
    else
        echo "(journalctl not available)"
    fi
    echo "--- bluetoothctl list ---"
    btctl list
}

# Waits briefly: bluetoothd registers a freshly created vhci controller over
# D-Bus a moment after the kernel adapter appears. Worst case is bounded:
# 12 polls x (5s helper timeout + 0.5s sleep) + one 5s diagnostic call < 75s.
assert_bluez_adapter() {
    local label="$1"
    local out=""
    local BTCTL_TIMEOUT=5
    if ! command -v bluetoothctl >/dev/null 2>&1; then
        echo "    ⚠️  bluetoothctl is not installed; skipping the BlueZ adapter assertion."
        return 0
    fi
    for _ in {1..12}; do
        out="$(btctl list)"
        if printf '%s\n' "$out" | grep -q '^Controller '; then
            echo "✅ BlueZ exposes an adapter over D-Bus: $(printf '%s\n' "$out" | grep -m1 '^Controller ')"
            return 0
        fi
        sleep 0.5
    done
    echo "❌ ERROR: BlueZ in this environment exposes no Bluetooth adapter over D-Bus."
    echo "   The kernel adapter ($label) exists, but the daemon enumerates adapters through"
    echo "   bluetoothd; it would run BLE-less and only report 'No Bluetooth adapter found' later."
    show_bluetooth_diagnostics
    exit 1
}

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
    assert_bluez_adapter "$NEW_HCI"
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
        $SUDO btmgmt power on 2>/dev/null || bluez_power_on || true
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
    $SUDO btmgmt --index "$INDEX" power on 2>/dev/null || $SUDO btmgmt power on 2>/dev/null || bluez_power_on || true
    $SUDO hciconfig "$NEW_HCI" up 2>/dev/null || true
    if $SUDO btmgmt info 2>/dev/null | grep -q "current settings:.*powered"; then
        echo "✅ $NEW_HCI powered on successfully."
        break
    fi
    sleep 1
done

echo "--- Adapter details ---"
$SUDO btmgmt info 2>/dev/null || true
# BRIDGE_ONLY means another environment's bluetoothd owns this adapter and no
# local BlueZ is running, so `bluetoothctl show` would only block on a bus name
# that is not going to appear. btmgmt above is safe: it is the kernel mgmt API,
# which is exactly what is alive on this side.
if [ "$BRIDGE_ONLY" != "1" ]; then
    btctl show
fi

# Bridge-only mode deliberately leaves bluetoothd stopped (the containers own the
# adapter), so the BlueZ assertion only applies to the full host setup that the
# Ubuntu host pass needs.
if [ "$BRIDGE_ONLY" != "1" ]; then
    assert_bluez_adapter "$NEW_HCI"
fi

echo "✅ Virtual BLE bridge setup completed."
