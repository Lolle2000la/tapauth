#!/bin/bash
# TapAuth VM Shell Access
# This script scans the network for the VM's MAC, then opens a shell via SSH

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

# --- MODIFIED: ADDED SUDO CHECK ---
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root (using sudo) to scan the network."
  exit 1
fi

# --- MODIFIED: Fix paths when run with sudo ---
if [ -n "$SUDO_USER" ]; then
    ORIGINAL_HOME=$(eval echo ~$SUDO_USER)
    VM_IMAGE_DIR="${ORIGINAL_HOME}/.tapauth-vm"
    SSH_KEY_FILE="${VM_IMAGE_DIR}/id_rsa"
else
    # Fallback if not using sudo (though it will likely fail)
    SSH_KEY_FILE="${VM_IMAGE_DIR}/id_rsa"
fi

# --- MODIFIED: Check for arp-scan dependency ---
if ! command -v arp-scan &> /dev/null; then
    echo "❌ 'arp-scan' tool not found. This is required to find the VM's IP."
    echo "   Please install it (e.g., 'sudo apt install arp-scan' or 'sudo dnf install arp-scan')"
    exit 1
fi

# Check if VM is running
if [ ! -f "${VM_IMAGE_DIR}/${VM_NAME}.pid" ]; then
    echo "❌ VM is not running"
    echo ""
    echo "Start it with: sudo -E ./vm-start.sh"
    exit 1
fi

VM_PID=$(cat "${VM_IMAGE_DIR}/${VM_NAME}.pid")
if ! ps -p "$VM_PID" > /dev/null 2>&1; then
    echo "❌ VM is not running (stale PID file)"
    rm -f "${VM_IMAGE_DIR}/${VM_NAME}.pid"
    echo ""
    echo "Start it with: sudo -E ./vm-start.sh"
    exit 1
fi

# --- MODIFIED: Find VM IP by scanning for its MAC address ---
echo "==> Scanning for VM on bridge '$VM_BRIDGE'..."
echo "    (Looking for MAC: $VM_MAC_ADDRESS)"

VM_IP=""
MAX_RETRIES=10
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    # Scan the local network using the bridge interface
    # We grep for the MAC address and use awk to get the first column (the IP)
    VM_IP=$(arp-scan --interface="$VM_BRIDGE" --localnet 2>/dev/null | grep -i "$VM_MAC_ADDRESS" | awk '{print $1}')
    
    if [ -n "$VM_IP" ]; then
        echo "✅ VM found at: $VM_IP"
        break
    fi
    
    RETRY_COUNT=$((RETRY_COUNT + 1))
    
    if [ $RETRY_COUNT -eq 1 ]; then
        echo "    VM not found yet, retrying... (This can take a moment after boot)"
    fi
    
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "❌ Failed to find VM IP on the network."
        echo ""
        echo "Troubleshooting:"
        echo "  1. Is the VM fully booted? Check the QEMU window."
        echo "  2. Is the bridge '$VM_BRIDGE' up? (check 'ip addr')"
        echo "  3. Try scanning manually: sudo arp-scan --interface=$VM_BRIDGE --localnet"
        exit 1
    fi
    
    sleep 2
done

# Wait for SSH to be available on the new IP
echo ""
echo "Connecting to VM at $VM_IP..."
echo "User: $VM_SSH_USER"
echo ""

MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           -o IdentitiesOnly=yes -o ConnectTimeout=2 -i "${SSH_KEY_FILE}" \
           "${VM_SSH_USER}@${VM_IP}" "exit 0" 2>/dev/null; then
        break
    fi
    
    RETRY_COUNT=$((RETRY_COUNT + 1))
    
    if [ $RETRY_COUNT -eq 1 ]; then
        echo "Waiting for SSH service to be ready..."
    fi
    
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "❌ Failed to connect to VM via SSH at $VM_IP"
        echo ""
        echo "Troubleshooting:"
        echo "  1. Check VM console output in the QEMU window"
        echo "  2. Check VM serial log: tail -f ${VM_IMAGE_DIR}/${VM_NAME}-serial.log"
        echo "  3. Check cloud-init status (it may still be running):"
        echo "     ssh -i $SSH_KEY_FILE ${VM_SSH_USER}@${VM_IP} \"cloud-init status\""
        echo ""
        echo "On first boot, the VM needs 5-10 minutes to install packages."
        exit 1
    fi
    
    sleep 2
done

# Check initialization status before connecting
INIT_STATUS=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o ConnectTimeout=2 -i "${SSH_KEY_FILE}" \
    "${VM_SSH_USER}@${VM_IP}" "cloud-init status 2>/dev/null | grep 'status:' | awk '{print \$2}'" 2>/dev/null)

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
    -o IdentitiesOnly=yes -X -i "${SSH_KEY_FILE}" \
    "${VM_SSH_USER}@${VM_IP}"