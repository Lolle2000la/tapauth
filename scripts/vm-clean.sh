#!/bin/bash
# Clean up VM files while preserving the Ubuntu base image

set -e

# Save original working directory
ORIGINAL_DIR="$(pwd)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth VM Cleanup                                    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if VM is running
if [ -f "${VM_IMAGE_DIR}/${VM_NAME}.pid" ]; then
    VM_PID=$(cat "${VM_IMAGE_DIR}/${VM_NAME}.pid")
    if ps -p "$VM_PID" > /dev/null 2>&1; then
        echo "❌ VM is still running (PID: $VM_PID)"
        echo ""
        echo "Please stop it first with: ./vm-stop.sh"
        exit 1
    fi
fi

echo "This will delete:"
echo "  • VM disk image (${VM_NAME}.qcow2)"
echo "  • Cloud-init ISO and configuration"
echo "  • SSH keys"
echo "  • Log files"
echo ""
echo "This will keep:"
echo "  • Ubuntu base image (ubuntu-24.04-cloud.img)"
echo ""
read -p "Continue? (y/N): " -n 1 -r
echo

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled"
    exit 0
fi

echo ""
echo "==> Cleaning up VM files..."

cd "${VM_IMAGE_DIR}"

# Delete VM-specific files
rm -f "${VM_NAME}.qcow2"
rm -f "${VM_NAME}-cloud-init.iso"
rm -f "${VM_NAME}.pid"
rm -f "${VM_NAME}.monitor"
rm -f "${VM_NAME}-serial.log"
rm -f user-data
rm -f meta-data
rm -f id_rsa id_rsa.pub

echo "✅ VM files deleted"
echo ""
echo "Remaining files:"
ls -lh

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         Cleanup Complete                                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "To create a fresh VM, run: ./scripts/vm-setup.sh"
echo ""

# Restore original working directory
cd "$ORIGINAL_DIR"
