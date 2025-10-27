#!/bin/bash
# TapAuth VM Start Script
# This script starts the VM with proper network and USB passthrough

set -e

# Save original working directory
ORIGINAL_DIR="$(pwd)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root (using sudo) to manage network devices."
  cd "$ORIGINAL_DIR"
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
    echo "❌ Could not auto-detect host internet interface."
    cd "$ORIGINAL_DIR"
    exit 1
fi
if [[ "$HOST_OUT_IFACE" == "wlan"* ]]; then
    echo "❌ Host interface '$HOST_OUT_IFACE' appears to be Wi-Fi."
    echo "   Bridging is not supported on most Wi-Fi adapters."
    echo "   Please connect via Ethernet."
    cd "$ORIGINAL_DIR"
    exit 1
fi
echo "==> Using host internet interface: $HOST_OUT_IFACE"


echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth VM - Start                                    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if VM is already running
if [ -f "${VM_IMAGE_DIR}/${VM_NAME}.pid" ]; then
    VM_PID=$(cat "${VM_IMAGE_DIR}/${VM_NAME}.pid")
    if ps -p "$VM_PID" > /dev/null 2>&1; then
        echo "⚠️  VM is already running (PID: $VM_PID)"
        echo ""
        echo "To connect: ./scripts/vm-shell.sh (must be updated for new IP)"
        echo "To stop:    sudo ./scripts/vm-stop.sh"
        cd "$ORIGINAL_DIR"
        exit 0
    else
        rm -f "${VM_IMAGE_DIR}/${VM_NAME}.pid"
    fi
fi

# Check if VM image exists
if [ ! -f "$VM_DISK_IMAGE" ]; then
    echo "❌ VM disk image not found at: $VM_DISK_IMAGE"
    echo "   Please run './scripts/vm-setup.sh' (without sudo) first to create it."
    cd "$ORIGINAL_DIR"
    exit 1
fi

# Function to tear down the bridge (for cleanup on failure)
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

# Function to set up the bridge
setup_bridge() {
    echo "==> Setting up true network bridge..."
    echo "⚠️  This will temporarily disrupt host networking."

    if ! ip link show "$VM_BRIDGE" > /dev/null 2>&1; then
        echo "   Creating bridge '$VM_BRIDGE'..."
        ip link add name "$VM_BRIDGE" type bridge
    fi

    if ! ip link show "$VM_TAP_DEVICE" > /dev/null 2>&1; then
        echo "   Creating TAP device '$VM_TAP_DEVICE'..."
        ip tuntap add dev "$VM_TAP_DEVICE" mode tap
    fi

    if ! ip link show "$VM_TAP_DEVICE" | grep -q "master $VM_BRIDGE"; then
        echo "   Attaching '$VM_TAP_DEVICE' to '$VM_BRIDGE'..."
        ip link set "$VM_TAP_DEVICE" master "$VM_BRIDGE"
    fi

    if ! ip link show "$VM_TAP_DEVICE" | grep -q "state UP"; then
        ip link set "$VM_TAP_DEVICE" up
    fi
    
    if ! ip link show "$HOST_OUT_IFACE" | grep -q "master $VM_BRIDGE"; then
        echo "   Flushing IP from $HOST_OUT_IFACE and adding it to bridge..."
        ip addr flush dev "$HOST_OUT_IFACE"
        ip link set "$HOST_OUT_IFACE" master "$VM_BRIDGE"
    fi
    
    ip link set "$HOST_OUT_IFACE" up
    ip link set "$VM_BRIDGE" up

    # --- MODIFIED: Make DHCP request more robust ---
    echo "   Releasing any old DHCP leases..."
    dhclient -r "$VM_BRIDGE" &> /dev/null || true
    dhclient -r "$HOST_OUT_IFACE" &> /dev/null || true
    # --- END MODIFICATION ---
    
    echo "   Requesting DHCP for host on '$VM_BRIDGE'..."
    dhclient "$VM_BRIDGE"
    
    echo "✅ Network bridge setup complete."
}

# Call the function
setup_bridge
echo ""

# Detect Bluetooth device
echo "==> Detecting Bluetooth device..."
BT_DEVICE=$(get_bluetooth_device)

if [ -n "$BT_DEVICE" ]; then
    echo "✅ Bluetooth device found: $BT_DEVICE"
    
    echo "==> Stopping host Bluetooth service..."
    if systemctl is-active --quiet bluetooth 2>/dev/null; then
        sudo systemctl stop bluetooth
        echo "✅ Host Bluetooth stopped (will be restored on VM shutdown)"
    fi
    
    echo "==> Unbinding Bluetooth device from host..."
    BT_VENDOR=$(echo "$BT_DEVICE" | cut -d: -f1)
    BT_PRODUCT=$(echo "$BT_DEVICE" | cut -d: -f2)
    
    BT_DEV_PATH=$(lsusb -d "${BT_DEVICE}" -v 2>/dev/null | grep -o "Bus [0-9]\+ Device [0-9]\+" | head -1)
    if [ -n "$BT_DEV_PATH" ]; then
        echo "   Found at: $BT_DEV_PATH"
    fi
    
    USB_PASSTHROUGH_ARGS="-device usb-host,vendorid=0x${BT_VENDOR},productid=0x${BT_PRODUCT}"
else
    echo "⚠️  No Bluetooth device detected"
    echo "   VM will start without Bluetooth passthrough"
    echo "   BLE features will not work"
    USB_PASSTHROUGH_ARGS=""
fi
echo ""

# Enable X11 forwarding
echo "==> Setting up X11 forwarding..."
if command -v xhost &> /dev/null; then
    xhost +local: > /dev/null 2>&1 || true
    echo "✅ X11 forwarding enabled"
else
    echo "⚠️  xhost not found, GUI may not work"
fi
echo ""

# Start VM
echo "==> Starting VM..."
echo ""

# Build QEMU command
QEMU_CMD=(
    qemu-system-x86_64
    
    # Machine type and acceleration
    -machine q35,accel=kvm
    -cpu host
    -smp "$VM_CPUS"
    -m "$VM_MEMORY"
    
    # Disks
    -drive "file=${VM_DISK_IMAGE},format=qcow2,if=virtio"
    -drive "file=${VM_CLOUD_INIT_ISO},format=raw,if=virtio,readonly=on"
    
    # Network
    -netdev tap,id=net0,ifname=${VM_TAP_DEVICE},script=no,downscript=no
    -device virtio-net-pci,netdev=net0,mac=${VM_MAC_ADDRESS}
    
    # Shared folder
    -virtfs "local,path=${VM_SHARED_FOLDER},mount_tag=tapauth,security_model=mapped-xattr,id=tapauth"
    
    # USB
    -device qemu-xhci,id=xhci
    
    # Serial
    -serial "file:${VM_IMAGE_DIR}/${VM_NAME}-serial.log"
    
    # Display
    -display gtk,gl=on
    
    # VGA
    -vga virtio
    
    # RNG
    -device virtio-rng-pci
    
    # KVM
    -enable-kvm
    
    # PID file
    -pidfile "${VM_IMAGE_DIR}/${VM_NAME}.pid"
    
    # Monitor
    -monitor "unix:${VM_IMAGE_DIR}/${VM_NAME}.monitor,server,nowait"
    
    # Daemonize
    -daemonize
)

if [ -n "$USB_PASSTHROUGH_ARGS" ]; then
    QEMU_CMD+=($USB_PASSTHROUGH_ARGS)
fi

"${QEMU_CMD[@]}"

sleep 2

if [ -f "${VM_IMAGE_DIR}/${VM_NAME}.pid" ]; then
    VM_PID=$(cat "${VM_IMAGE_DIR}/${VM_NAME}.pid")
    if ps -p "$VM_PID" > /dev/null 2>&1; then
        echo ""
        echo "╔═══════════════════════════════════════════════════════════════╗"
        echo "║         VM Started Successfully!                              ║"
        echo "╚═══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "VM is running (PID: $VM_PID)"
        echo ""
        
        echo "Network Configuration:"
        echo "  Type:       True Bridge (LAN DHCP)"
        echo "  Bridge:     $VM_BRIDGE (slaved to $HOST_OUT_IFACE)"
        echo "  Host IP:    (via DHCP on $VM_BRIDGE)"
        echo "  Guest IP:   (via DHCP from your router)"
        echo "  Internet:   Enabled (via router)"
        
        echo ""
        if [ -n "$BT_DEVICE" ]; then
            echo "Bluetooth: Passthrough enabled ($BT_DEVICE)"
        else
            echo "Bluetooth: Not available"
        fi
        echo ""
        echo "Shared Folder:"
        echo "  Host:       $VM_SHARED_FOLDER"
        echo "  Guest:      /tapauth (auto-mounted)"
        echo ""
        echo "Logs:"
        echo "  Serial console: ${VM_IMAGE_DIR}/${VM_NAME}-serial.log"
        echo "  Monitor: tail -f ${VM_IMAGE_DIR}/${VM_NAME}-serial.log"
        echo ""
        echo "First boot will take 5-10 minutes to install packages and setup."
        echo "Watch the VM window for progress."
        echo ""
        
        echo "To connect via SSH (IP will be assigned by your router):"
        echo "  1. Find the VM's IP from your router's DHCP list"
        echo "  2. Or, check VM console: sudo ip addr show"
        echo "  3. ssh -i ${ORIGINAL_HOME:-$HOME}/.tapauth-vm/id_rsa ${VM_SSH_USER}@[VM_IP_ADDRESS]"
        echo ""
        echo "To check initialization status (replace IP):"
        echo "  ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ${ORIGINAL_HOME:-$HOME}/.tapauth-vm/id_rsa ${VM_SSH_USER}@[VM_IP_ADDRESS] \"cloud-init status\""
        
        echo ""
        echo "  Status meanings:"
        echo "    'status: running'  → Still initializing (installing packages, Rust, etc.)"
        echo "    'status: done'     → Ready to use! All scripts and tools installed."
        echo "    'status: error'    → Check logs with: cloud-init status --long"
        echo ""
        echo "To stop the VM:"
        echo "  sudo ./scripts/vm-stop.sh"
        echo ""
        cd "$ORIGINAL_DIR"
    else
        echo "❌ VM failed to start"
        teardown_bridge
        cd "$ORIGINAL_DIR"
        exit 1
    fi
else
    echo "❌ VM PID file not created"
    teardown_bridge
    cd "$ORIGINAL_DIR"
    exit 1
fi