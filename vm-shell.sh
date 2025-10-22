#!/bin/bash
# TapAuth VM Shell Access
# This script opens a shell in the running VM via SSH

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

# Check if VM is running
if [ ! -f "${VM_IMAGE_DIR}/${VM_NAME}.pid" ]; then
    echo "❌ VM is not running"
    echo ""
    echo "Start it with: ./vm-start.sh"
    exit 1
fi

VM_PID=$(cat "${VM_IMAGE_DIR}/${VM_NAME}.pid")
if ! ps -p "$VM_PID" > /dev/null 2>&1; then
    echo "❌ VM is not running (stale PID file)"
    rm -f "${VM_IMAGE_DIR}/${VM_NAME}.pid"
    echo ""
    echo "Start it with: ./vm-start.sh"
    exit 1
fi

# Wait for SSH to be available
echo "Connecting to VM..."
echo "(SSH Port: localhost:$VM_SSH_PORT, User: $VM_SSH_USER)"
echo ""

MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           -o IdentitiesOnly=yes -o ConnectTimeout=2 -i "${VM_IMAGE_DIR}/id_rsa" \
           -p "$VM_SSH_PORT" "${VM_SSH_USER}@localhost" "exit 0" 2>/dev/null; then
        break
    fi
    
    RETRY_COUNT=$((RETRY_COUNT + 1))
    
    if [ $RETRY_COUNT -eq 1 ]; then
        echo "Waiting for VM to be ready..."
    fi
    
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "❌ Failed to connect to VM"
        echo ""
        echo "Troubleshooting:"
        echo "  1. Check if VM is running: ps aux | grep qemu"
        echo "  2. Check VM console output in the QEMU window"
        echo "  3. Try SSH manually: ssh -p $VM_SSH_PORT -i ~/.tapauth-vm/id_rsa $VM_SSH_USER@localhost"
        echo "  4. Check VM serial log: tail -f ~/.tapauth-vm/tapauth-dev-serial.log"
        echo ""
        echo "On first boot, the VM needs 5-10 minutes to install packages."
        exit 1
    fi
    
    sleep 2
done

# Check initialization status before connecting
INIT_STATUS=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o ConnectTimeout=2 -i "${VM_IMAGE_DIR}/id_rsa" \
    -p "$VM_SSH_PORT" "${VM_SSH_USER}@localhost" "cloud-init status 2>/dev/null | grep 'status:' | awk '{print \$2}'" 2>/dev/null)

if [ "$INIT_STATUS" = "running" ]; then
    echo "⚠️  Note: VM initialization is still in progress"
    echo "   Run 'init-status' inside the VM to check progress"
    echo ""
fi

# SSH with X11 forwarding
echo "Entering TapAuth VM..."
echo "(Type 'exit' to leave)"
echo ""

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -X -i "${VM_IMAGE_DIR}/id_rsa" \
    -p "$VM_SSH_PORT" "${VM_SSH_USER}@localhost"
