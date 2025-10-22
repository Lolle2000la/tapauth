#!/bin/bash
# TapAuth VM Start Script
# This script starts the VM with proper network and USB passthrough

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

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
        echo "To connect: ./dev-shell.sh"
        echo "To stop:    ./dev-stop.sh"
        exit 0
    else
        # Stale PID file
        rm -f "${VM_IMAGE_DIR}/${VM_NAME}.pid"
    fi
fi

# Check if VM image exists
if [ ! -f "$VM_DISK_IMAGE" ]; then
    echo "❌ VM disk image not found: $VM_DISK_IMAGE"
    echo ""
    echo "Run VM setup first: ./vm-setup.sh"
    exit 1
fi

# Detect Bluetooth device
echo "==> Detecting Bluetooth device..."
BT_DEVICE=$(get_bluetooth_device)

if [ -n "$BT_DEVICE" ]; then
    echo "✅ Bluetooth device found: $BT_DEVICE"
    
    # Stop host Bluetooth service
    echo "==> Stopping host Bluetooth service..."
    if systemctl is-active --quiet bluetooth 2>/dev/null; then
        sudo systemctl stop bluetooth
        echo "✅ Host Bluetooth stopped (will be restored on VM shutdown)"
    fi
    
    # Unbind from host
    echo "==> Unbinding Bluetooth device from host..."
    BT_VENDOR=$(echo "$BT_DEVICE" | cut -d: -f1)
    BT_PRODUCT=$(echo "$BT_DEVICE" | cut -d: -f2)
    
    # Find the device path
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
    
    # Network - Use user-mode networking (simpler, no root needed for most operations)
    # This provides NAT and port forwarding automatically
    -netdev "user,id=net0,hostfwd=tcp::${VM_SSH_PORT}-:22"
    -device "virtio-net-pci,netdev=net0"
    
    # Shared folder - virtio-9p for host filesystem sharing
    -virtfs "local,path=${VM_SHARED_FOLDER},mount_tag=tapauth,security_model=mapped-xattr,id=tapauth"
    
    # USB controller for Bluetooth passthrough
    -device qemu-xhci,id=xhci
    
    # Serial console for debugging (write to file since we're daemonizing)
    -serial "file:${VM_IMAGE_DIR}/${VM_NAME}-serial.log"
    
    # Display - Use GTK for better X11 integration
    -display gtk,gl=on
    
    # VGA
    -vga virtio
    
    # RNG for better entropy
    -device virtio-rng-pci
    
    # Enable KVM
    -enable-kvm
    
    # PID file
    -pidfile "${VM_IMAGE_DIR}/${VM_NAME}.pid"
    
    # Monitor socket for control
    -monitor "unix:${VM_IMAGE_DIR}/${VM_NAME}.monitor,server,nowait"
    
    # Daemonize
    -daemonize
)

# Add USB passthrough if Bluetooth detected
if [ -n "$USB_PASSTHROUGH_ARGS" ]; then
    QEMU_CMD+=($USB_PASSTHROUGH_ARGS)
fi

# Execute QEMU
"${QEMU_CMD[@]}"

# Wait a moment for VM to start
sleep 2

# Check if VM is running
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
        echo "  Type:       User-mode (SLIRP NAT)"
        echo "  SSH:        localhost:$VM_SSH_PORT"
        echo "  VM gets internet via NAT automatically"
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
        echo "To connect via SSH:"
        echo "  ./dev-shell.sh"
        echo ""
        echo "To check initialization status:"
        echo "  ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.tapauth-vm/id_rsa -p 2222 tapauth@localhost \"cloud-init status\""
        echo ""
        echo "  Status meanings:"
        echo "    'status: running'  → Still initializing (installing packages, Rust, etc.)"
        echo "    'status: done'     → Ready to use! All scripts and tools installed."
        echo "    'status: error'    → Check logs with: cloud-init status --long"
        echo ""
        echo "To stop the VM:"
        echo "  ./dev-stop.sh"
        echo ""
    else
        echo "❌ VM failed to start"
        exit 1
    fi
else
    echo "❌ VM PID file not created"
    exit 1
fi
