#!/bin/bash
# Sets up Google Bumble Virtual HCI bridge connecting Android Emulator Netsim to Linux host /dev/vhci
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> Configuring Virtual Bluetooth Bridge (Bumble <-> Netsim)..."

# Ensure vhci module is loaded and /dev/vhci node exists with write permissions
if [ ! -w /dev/vhci ] || ! python3 -c "import os; fd = os.open('/dev/vhci', os.O_RDWR); os.close(fd)" 2>/dev/null; then
    if [ -f "$SCRIPT_DIR/build-kernel-vhci.sh" ]; then
        bash "$SCRIPT_DIR/build-kernel-vhci.sh"
    fi
fi

# Check if /dev/vhci is actually accessible
VHCI_SUPPORTED=false
if [ -w /dev/vhci ] && python3 -c "import os; fd = os.open('/dev/vhci', os.O_RDWR); os.close(fd)" 2>/dev/null; then
    VHCI_SUPPORTED=true
fi

if [ "$VHCI_SUPPORTED" != "true" ]; then
    echo "❌ ERROR: Virtual HCI (/dev/vhci) is not writable by current user."
    exit 1
fi

# Ensure BlueZ packages are installed and bluetoothd is running
sudo apt-get update -qq
sudo apt-get install -y -qq bluez bluez-tools

if ! pgrep -x bluetoothd > /dev/null; then
    sudo systemctl start bluetooth 2>/dev/null || { sudo bluetoothd -n -d >/tmp/bluetoothd.log 2>&1 & sleep 2; }
fi

# Verify bumble is available
if ! python3 -c "import bumble" 2>/dev/null; then
    echo "    Installing Bumble Python package..."
    pip install --break-system-packages "bumble[android-netsim]" grpcio protobuf || pip install "bumble[android-netsim]" grpcio protobuf
fi

# Capture existing hci devices to detect the newly created one
EXISTING_HCI=$(hciconfig 2>/dev/null | grep -o '^hci[0-9]*' || true)

# Launch bumble-hci-bridge connecting emulator netsim to /dev/vhci
echo "    Starting bumble-hci-bridge (android-netsim <-> vhci)..."
BUMBLE_LOG="/tmp/bumble-bridge.log"

USER_SITE=$(python3 -c 'import site; print(":".join(site.getsitepackages() + [site.getusersitepackages()]))' 2>/dev/null || true)

if [ -w /dev/vhci ]; then
    if command -v bumble-hci-bridge &> /dev/null; then
        bumble-hci-bridge "android-netsim" "vhci:" > "$BUMBLE_LOG" 2>&1 &
        BUMBLE_PID=$!
    else
        python3 -m bumble.apps.hci_bridge "android-netsim" "vhci:" > "$BUMBLE_LOG" 2>&1 &
        BUMBLE_PID=$!
    fi
else
    if command -v bumble-hci-bridge &> /dev/null; then
        sudo env PATH="$PATH" PYTHONPATH="$PYTHONPATH:$USER_SITE" sh -c "bumble-hci-bridge 'android-netsim' 'vhci:' > '$BUMBLE_LOG' 2>&1" &
        BUMBLE_PID=$!
    else
        sudo env PATH="$PATH" PYTHONPATH="$PYTHONPATH:$USER_SITE" sh -c "python3 -m bumble.apps.hci_bridge 'android-netsim' 'vhci:' > '$BUMBLE_LOG' 2>&1" &
        BUMBLE_PID=$!
    fi
fi

echo "$BUMBLE_PID" > /tmp/bumble-bridge.pid
echo "    bumble-hci-bridge running with PID $BUMBLE_PID (logs: $BUMBLE_LOG)"

# Give Bumble and kernel time to perform the initial vendor handshake and register the adapter
sleep 5

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
    INDEX=$(echo "$NEW_HCI" | sed 's/hci//')
    
    # Power on adapter with retries
    for attempt in {1..10}; do
        sudo btmgmt --index "$INDEX" power on 2>/dev/null || sudo btmgmt power on 2>/dev/null || bluetoothctl power on 2>/dev/null || true
        sudo hciconfig "$NEW_HCI" up 2>/dev/null || true
        if sudo btmgmt info 2>/dev/null | grep -q "current settings:.*powered"; then
            echo "✅ $NEW_HCI powered on successfully."
            break
        fi
        sleep 1
    done

    echo "--- Adapter details ---"
    sudo btmgmt info 2>/dev/null || true
    bluetoothctl show 2>/dev/null || true
    echo "true" > /tmp/ble-available.txt
else
    echo "❌ ERROR: No virtual Bluetooth adapter (HCI) detected after bridge launch."
    echo "false" > /tmp/ble-available.txt
    if [ -f "$BUMBLE_LOG" ]; then
        echo "=== BUMBLE BRIDGE LOG ==="
        cat "$BUMBLE_LOG"
        echo "========================="
    fi
    exit 1
fi

echo "✅ Virtual BLE bridge setup completed."
