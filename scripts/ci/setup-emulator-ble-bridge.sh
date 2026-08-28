#!/bin/bash
# Sets up Google Bumble Virtual HCI bridge connecting Android Emulator Netsim to Linux host /dev/vhci
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> Configuring Virtual Bluetooth Bridge (Bumble <-> Netsim)..."

# Ensure vhci module is loaded and /dev/vhci node exists
if ! lsmod | grep -q hci_vhci; then
    echo "    Loading hci_vhci kernel module..."
    sudo modprobe hci_vhci 2>/dev/null || {
        echo "⚠️ Warning: Failed to modprobe hci_vhci."
    }
fi

if [ ! -c /dev/vhci ]; then
    echo "    Creating /dev/vhci character device node..."
    sudo mknod /dev/vhci c 10 137 2>/dev/null || true
    sudo chmod 666 /dev/vhci 2>/dev/null || true
fi

# Ensure D-Bus system bus is running
if ! pgrep -x dbus-daemon > /dev/null && ! pgrep -x dbus-broker > /dev/null; then
    echo "    Starting D-Bus..."
    sudo mkdir -p /var/run/dbus
    sudo dbus-daemon --system --fork 2>/dev/null || sudo systemctl start dbus || true
fi

# Ensure bluetoothd is running with experimental flag (required for BLE GATT peripheral mode)
if ! pgrep -x bluetoothd > /dev/null; then
    echo "    Starting BlueZ bluetoothd..."
    sudo bluetoothd --experimental &
    sleep 1
fi

# Verify bumble is available
if ! python3 -c "import bumble" 2>/dev/null && ! sudo python3 -c "import bumble" 2>/dev/null; then
    echo "    Installing Bumble Python package..."
    sudo pip install --break-system-packages bumble || sudo pip3 install --break-system-packages bumble || pip install --break-system-packages bumble || true
fi

# Capture existing hci devices to detect the newly created one
EXISTING_HCI=$(hciconfig 2>/dev/null | grep -o '^hci[0-9]*' || true)

# Launch bumble-hci-bridge connecting emulator netsim gRPC (default port 8554) to /dev/vhci
echo "    Starting bumble-hci-bridge (android-netsim:localhost:8554 <-> vhci)..."
BUMBLE_LOG="/tmp/bumble-bridge.log"

USER_SITE=$(python3 -c 'import site; print(":".join(site.getsitepackages() + [site.getusersitepackages()]))' 2>/dev/null || true)

if command -v bumble-hci-bridge &> /dev/null; then
    sudo env PATH="$PATH" PYTHONPATH="$PYTHONPATH:$USER_SITE" bumble-hci-bridge "android-netsim:localhost:8554,mode=controller" "vhci:" > "$BUMBLE_LOG" 2>&1 &
    BUMBLE_PID=$!
else
    sudo env PATH="$PATH" PYTHONPATH="$PYTHONPATH:$USER_SITE" python3 -m bumble.apps.hci_bridge "android-netsim:localhost:8554,mode=controller" "vhci:" > "$BUMBLE_LOG" 2>&1 &
    BUMBLE_PID=$!
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
    sudo hciconfig "$NEW_HCI" up || true
    sudo bluetoothctl --adapter "$NEW_HCI" power on || true
else
    echo "⚠️  No new HCI adapter detected yet. BlueZ will automatically bind when emulator Netsim connects."
fi

echo "✅ Virtual BLE bridge setup completed."
