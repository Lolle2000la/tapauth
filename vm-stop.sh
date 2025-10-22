#!/bin/bash
# TapAuth VM Stop Script
# This script stops the VM and cleans up network configuration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root (using sudo) to manage network devices."
  exit 1
fi

# Fix paths when run with sudo
if [ -n "$SUDO_USER" ]; then
    ORIGINAL_HOME=$(eval echo ~$SUDO_USER)
    VM_IMAGE_DIR="${ORIGINAL_HOME}/.tapauth-vm"
    VM_DISK_IMAGE="${VM_IMAGE_DIR}/${VM_NAME}.qcow2"
    VM_CLOUD_INIT_ISO="${VM_IMAGE_DIR}/${VM_NAME}-cloud-init.iso"
    SSH_KEY_FILE="${VM_IMAGE_DIR}/id_rsa"
fi

# Auto-detect HOST ETHERNET interface
HOST_OUT_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$HOST_OUT_IFACE" ]; then
    HOST_OUT_IFACE=$(ip link | grep -E 'enp|eth' | awk '{print $2}' | sed 's/://' | head -1)
fi
if [ -z "$HOST_OUT_IFACE" ]; then
    echo "⚠️  Could not auto-detect host internet interface for cleanup."
fi

echo "Stopping TapAuth VM..."
echo ""

if [ ! -f "${VM_IMAGE_DIR}/${VM_NAME}.pid" ]; then
    echo "⚠️  VM is not running (no PID file)"
else
    VM_PID=$(cat "${VM_IMAGE_DIR}/${VM_NAME}.pid")
    
    if ps -p "$VM_PID" > /dev/null 2>&1; then
        echo "==> Shutting down VM gracefully..."
        
        echo "   Cannot guess VM IP, skipping SSH shutdown."
        
        if ps -p "$VM_PID" > /dev/null 2>&1; then
            echo "   Sending ACPI shutdown via QEMU monitor..."
            echo "system_powerdown" | socat - "UNIX-CONNECT:${VM_IMAGE_DIR}/${VM_NAME}.monitor" 2>/dev/null || true
            
            for i in {1..15}; do
                if ! ps -p "$VM_PID" > /dev/null 2>&1; then
                    echo "✅ VM shut down via ACPI"
                    break
                fi
                sleep 1
            done
        fi
        
        if ps -p "$VM_PID" > /dev/null 2>&1; then
            echo "   Forcing shutdown..."
            kill "$VM_PID"
            sleep 2
            
            if ps -p "$VM_PID" > /dev/null 2>&1; then
                kill -9 "$VM_PID"
            fi
            echo "✅ VM terminated"
        fi
    else
        echo "⚠️  VM is not running (stale PID file)"
    fi
    
    rm -f "${VM_IMAGE_DIR}/${VM_NAME}.pid"
fi

# Function to tear down the bridge
teardown_bridge() {
    echo "==> Tearing down network bridge..."
    echo "⚠️  This will temporarily disrupt host networking."

    if ip link show "$VM_TAP_DEVICE" > /dev/null 2>&1; then
        echo "   Removing TAP device '$VM_TAP_DEVICE'..."
        ip link set "$VM_TAP_DEVICE" down
        ip link del "$VM_TAP_DEVICE"
    else
        echo "   TAP device '$VM_TAP_DEVICE' already gone."
    fi

    if ip link show "$VM_BRIDGE" > /dev/null 2>&1; then
        
        if [ -n "$HOST_OUT_IFACE" ] && ip link show "$HOST_OUT_IFACE" | grep -q "master $VM_BRIDGE"; then
            echo "   Removing $HOST_OUT_IFACE from bridge..."
            ip link set "$HOST_OUT_IFACE" nomaster
        fi
        
        echo "   Removing bridge '$VM_BRIDGE'..."
        ip link set "$VM_BRIDGE" down
        ip link del "$VM_BRIDGE"
    else
        echo "   Bridge '$VM_BRIDGE' already gone."
    fi
    
    if [ -n "$HOST_OUT_IFACE" ]; then
        # --- MODIFIED: Make DHCP request more robust ---
        echo "   Releasing any old DHCP leases..."
        dhclient -r "$VM_BRIDGE" &> /dev/null || true
        dhclient -r "$HOST_OUT_IFACE" &> /dev/null || true
        # --- END MODIFICATION ---
        echo "   Requesting DHCP for host on '$HOST_OUT_IFACE'..."
        dhclient "$HOST_OUT_IFACE"
    fi
    
    echo "✅ Network bridge teardown complete."
}

# Call teardown function
teardown_bridge
echo ""

# Restore host Bluetooth
echo ""
echo "==> Restoring host Bluetooth service..."
if command -v systemctl &> /dev/null; then
    if ! systemctl is-active --quiet bluetooth 2>/dev/null; then
        sudo systemctl start bluetooth 2>/dev/null || true
        echo "✅ Host Bluetooth service started"
    else
        echo "✅ Host Bluetooth already running"
    fi
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         VM Stopped                                            ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Option to delete VM
echo ""
read -p "Do you want to delete the VM disk? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -f "$VM_DISK_IMAGE" ]; then
        rm -f "$VM_DISK_IMAGE"
        echo "✅ VM disk deleted: $VM_DISK_IMAGE"
    fi
    
    if [ -f "$VM_CLOUD_INIT_ISO" ]; then
        rm -f "$VM_CLOUD_INIT_ISO"
        echo "✅ Cloud-init ISO deleted"
    fi
    
    echo ""
    echo "To create a fresh VM, run: ./vm-setup.sh"
fi