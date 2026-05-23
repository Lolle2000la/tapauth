#!/bin/bash
# TapAuth VM Test Helper
# This script runs tests in the VM

set -e

# Save original working directory
ORIGINAL_DIR="$(pwd)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

# Check if VM is running
if [ ! -f "${VM_IMAGE_DIR}/${VM_NAME}.pid" ]; then
    echo "❌ ERROR: VM is not running"
    echo ""
    echo "Start it with: ./scripts/vm-start.sh"
    cd "$ORIGINAL_DIR"
    exit 1
fi

VM_PID=$(cat "${VM_IMAGE_DIR}/${VM_NAME}.pid")
if ! ps -p "$VM_PID" > /dev/null 2>&1; then
    echo "❌ ERROR: VM is not running (stale PID file)"
    rm -f "${VM_IMAGE_DIR}/${VM_NAME}.pid"
    echo ""
    echo "Start it with: ./scripts/vm-start.sh"
    cd "$ORIGINAL_DIR"
    exit 1
fi

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         Running TapAuth Tests                                 ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Run unit tests
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -i "${VM_IMAGE_DIR}/id_rsa" \
    -p "$VM_SSH_PORT" "${VM_SSH_USER}@localhost" "test-tapauth"

echo ""
echo "✅ All tests passed!"
echo ""
echo "To test PAM authentication:"
echo "  ./scripts/vm-shell.sh"
echo "  test-pam-auth root"

# Restore original working directory
cd "$ORIGINAL_DIR"
