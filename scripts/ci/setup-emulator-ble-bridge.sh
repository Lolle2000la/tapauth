#!/bin/bash
# Sets up Google Bumble Virtual HCI bridge connecting Android Emulator Netsim to Linux host /dev/vhci
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> Configuring Virtual Bluetooth Bridge (Bumble <-> Netsim)..."

# Ensure vhci module is loaded and /dev/vhci node exists with write permissions
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    sudo modprobe hci_vhci 2>/dev/null || true
    if [ ! -c /dev/vhci ]; then
        sudo mknod /dev/vhci c 10 137 2>/dev/null || true
    fi
    sudo chmod 666 /dev/vhci 2>/dev/null || true
else
    modprobe hci_vhci 2>/dev/null || true
    if [ ! -c /dev/vhci ]; then
        mknod /dev/vhci c 10 137 2>/dev/null || true
    fi
    chmod 666 /dev/vhci 2>/dev/null || true
fi

# Check if /dev/vhci is actually accessible
VHCI_SUPPORTED=false
if [ -w /dev/vhci ] && python3 -c "import os; fd = os.open('/dev/vhci', os.O_RDWR); os.close(fd)" 2>/dev/null; then
    VHCI_SUPPORTED=true
fi

if [ "$VHCI_SUPPORTED" != "true" ]; then
    echo "ℹ️  Virtual HCI (/dev/vhci) is not writable by current user."
    echo "    To enable BLE testing locally, run once: sudo chmod 666 /dev/vhci"
    echo "    (Continuing test suite with BLE disabled...)"
    echo "false" > /tmp/ble-available.txt
    exit 0
fi

echo "true" > /tmp/ble-available.txt

# Ensure D-Bus system bus is running
if ! pgrep -x dbus-daemon > /dev/null && ! pgrep -x dbus-broker > /dev/null; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo mkdir -p /var/run/dbus
        sudo dbus-daemon --system --fork 2>/dev/null || sudo systemctl start dbus || true
    fi
fi

# Ensure bluetoothd is running
if ! pgrep -x bluetoothd > /dev/null; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo bluetoothd --experimental &
        sleep 1
    fi
fi

# Verify bumble is available
if ! python3 -c "import bumble" 2>/dev/null; then
    echo "    Installing Bumble Python package..."
    pip install --break-system-packages "bumble[android-netsim]" grpcio protobuf 2>/dev/null || pip install "bumble[android-netsim]" grpcio protobuf || true
fi

# Capture existing hci devices to detect the newly created one
EXISTING_HCI=$(hciconfig 2>/dev/null | grep -o '^hci[0-9]*' || true)

# Launch bumble-hci-bridge connecting emulator netsim gRPC (default port 8554) to /dev/vhci
echo "    Starting bumble-hci-bridge (android-netsim:localhost:8554 <-> vhci)..."
BUMBLE_LOG="/tmp/bumble-bridge.log"

USER_SITE=$(python3 -c 'import site; print(":".join(site.getsitepackages() + [site.getusersitepackages()]))' 2>/dev/null || true)

if [ -w /dev/vhci ]; then
    if command -v bumble-hci-bridge &> /dev/null; then
        bumble-hci-bridge "android-netsim:localhost:8554,mode=controller" "vhci:" > "$BUMBLE_LOG" 2>&1 &
        BUMBLE_PID=$!
    else
        python3 -m bumble.apps.hci_bridge "android-netsim:localhost:8554,mode=controller" "vhci:" > "$BUMBLE_LOG" 2>&1 &
        BUMBLE_PID=$!
    fi
else
    if command -v bumble-hci-bridge &> /dev/null; then
        sudo env PATH="$PATH" PYTHONPATH="$PYTHONPATH:$USER_SITE" bumble-hci-bridge "android-netsim:localhost:8554,mode=controller" "vhci:" > "$BUMBLE_LOG" 2>&1 &
        BUMBLE_PID=$!
    else
        sudo env PATH="$PATH" PYTHONPATH="$PYTHONPATH:$USER_SITE" python3 -m bumble.apps.hci_bridge "android-netsim:localhost:8554,mode=controller" "vhci:" > "$BUMBLE_LOG" 2>&1 &
        BUMBLE_PID=$!
    fi
fi

echo "$BUMBLE_PID" > /tmp/bumble-bridge.pid
echo "    bumble-hci-bridge running with PID $BUMBLE_PID (logs: $BUMBLE_LOG)"

# Wait for new virtual HCI adapter to appear (up to 10s)
NEW_HCI=""
for i in {1..50}; do
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

if [ -n "$NEW_HCI" ]; then
    echo "✅ Virtual Bluetooth adapter detected: $NEW_HCI"
    hciconfig "$NEW_HCI" up 2>/dev/null || (command -v sudo >/dev/null 2>&1 && sudo -n hciconfig "$NEW_HCI" up 2>/dev/null) || true
    bluetoothctl --adapter "$NEW_HCI" power on 2>/dev/null || true
else
    echo "⚠️  No new HCI adapter detected yet. BlueZ will automatically bind when emulator Netsim connects."
fi

echo "✅ Virtual BLE bridge setup completed."
