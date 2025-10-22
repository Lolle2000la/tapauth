#!/bin/bash
# TapAuth VM Build Helper
# This script rebuilds TapAuth components inside the VM

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

# Check if VM is running
if [ ! -f "${VM_IMAGE_DIR}/${VM_NAME}.pid" ]; then
    echo "❌ ERROR: VM is not running"
    echo ""
    echo "Start it with: ./vm-start.sh"
    exit 1
fi

VM_PID=$(cat "${VM_IMAGE_DIR}/${VM_NAME}.pid")
if ! ps -p "$VM_PID" > /dev/null 2>&1; then
    echo "❌ ERROR: VM is not running (stale PID file)"
    rm -f "${VM_IMAGE_DIR}/${VM_NAME}.pid"
    echo ""
    echo "Start it with: ./vm-start.sh"
    exit 1
fi

echo "Rebuilding TapAuth components in VM..."
echo ""

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -i "${VM_IMAGE_DIR}/id_rsa" \
    -p "$VM_SSH_PORT" "${VM_SSH_USER}@localhost" "build-tapauth"

echo ""
echo "✅ Rebuild complete!"
echo ""
echo "You can now test with: ./vm-test.sh"
