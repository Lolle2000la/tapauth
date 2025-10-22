#!/bin/bash
# TapAuth VM Stop Script
# This script stops the VM and cleans up network configuration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

echo "Stopping TapAuth VM..."
echo ""

# Check if VM is running
if [ ! -f "${VM_IMAGE_DIR}/${VM_NAME}.pid" ]; then
    echo "⚠️  VM is not running (no PID file)"
else
    VM_PID=$(cat "${VM_IMAGE_DIR}/${VM_NAME}.pid")
    
    if ps -p "$VM_PID" > /dev/null 2>&1; then
        echo "==> Shutting down VM gracefully..."
        
        # Try graceful shutdown via SSH
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
               -o IdentitiesOnly=yes -o ConnectTimeout=2 -i "${VM_IMAGE_DIR}/id_rsa" \
               -p "$VM_SSH_PORT" "${VM_SSH_USER}@localhost" "sudo poweroff" 2>/dev/null; then
            echo "   Sent shutdown command, waiting..."
            
            # Wait up to 30 seconds for graceful shutdown
            for i in {1..30}; do
                if ! ps -p "$VM_PID" > /dev/null 2>&1; then
                    echo "✅ VM shut down gracefully"
                    break
                fi
                sleep 1
            done
        fi
        
        # If still running, use QEMU monitor
        if ps -p "$VM_PID" > /dev/null 2>&1; then
            echo "   Sending ACPI shutdown via QEMU monitor..."
            echo "system_powerdown" | socat - "UNIX-CONNECT:${VM_IMAGE_DIR}/${VM_NAME}.monitor" 2>/dev/null || true
            
            # Wait up to 15 seconds
            for i in {1..15}; do
                if ! ps -p "$VM_PID" > /dev/null 2>&1; then
                    echo "✅ VM shut down via ACPI"
                    break
                fi
                sleep 1
            done
        fi
        
        # Last resort: kill the process
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
    
    # Remove PID file
    rm -f "${VM_IMAGE_DIR}/${VM_NAME}.pid"
fi

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
