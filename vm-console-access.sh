#!/bin/bash
# Access VM console via QEMU monitor to check/configure network

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

source ./vm-config.sh

if [ ! -f "${VM_IMAGE_DIR}/${VM_NAME}.pid" ]; then
    echo "VM is not running"
    exit 1
fi

echo "This will send commands to the VM via the QEMU monitor."
echo ""
echo "Sending Ctrl-Alt-F2 to switch to a text console..."

# Send keystrokes to switch to console
echo "sendkey ctrl-alt-f2" | socat - "UNIX-CONNECT:${VM_IMAGE_DIR}/${VM_NAME}.monitor"

sleep 1

echo ""
echo "Now click on the QEMU window and try to login:"
echo "  Username: $VM_SSH_USER"
echo "  Password: $VM_SSH_PASSWORD"
echo ""
echo "Once logged in, check network with:"
echo "  ip addr"
echo "  sudo netplan apply"
echo "  ping 192.168.100.1"
echo ""
