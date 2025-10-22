#!/bin/bash
# TapAuth VM Configuration
# This file contains configuration variables for the VM

# VM Settings
VM_NAME="tapauth-dev"
VM_MEMORY="4096"  # MB
VM_CPUS="4"
VM_DISK_SIZE="20G"

# VM Image Settings
VM_IMAGE_DIR="${HOME}/.tapauth-vm"
VM_DISK_IMAGE="${VM_IMAGE_DIR}/${VM_NAME}.qcow2"
VM_CLOUD_INIT_ISO="${VM_IMAGE_DIR}/${VM_NAME}-cloud-init.iso"

# Ubuntu Cloud Image (24.04 LTS)
UBUNTU_VERSION="24.04"
UBUNTU_IMAGE_URL="https://cloud-images.ubuntu.com/releases/${UBUNTU_VERSION}/release/ubuntu-${UBUNTU_VERSION}-server-cloudimg-amd64.img"
UBUNTU_IMAGE_FILE="${VM_IMAGE_DIR}/ubuntu-${UBUNTU_VERSION}-cloud.img"

# Network Settings
# Bridge interface for VM networking
VM_BRIDGE="tapauth-br0"
VM_TAP_DEVICE="tapauth-tap0"
VM_HOST_IP="192.168.100.1"
VM_GUEST_IP="192.168.100.10"
VM_NETWORK_CIDR="192.168.100.0/24"

# SSH Settings
VM_SSH_PORT="2222"
VM_SSH_USER="tapauth"
VM_SSH_PASSWORD="tapauth"  # Will prompt to change on first login

# X11 Forwarding
VM_X11_DISPLAY="${DISPLAY:-:0}"

# Shared Folder
VM_SHARED_FOLDER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Bluetooth USB Device
# Leave empty to auto-detect, or set to specific device
# Format: vendorid:productid (e.g., "8087:0a2a" for Intel Bluetooth)
BT_USB_DEVICE=""

# Auto-detect Bluetooth device
auto_detect_bluetooth() {
    # Try to find Bluetooth device
    local bt_device=$(lsusb | grep -i bluetooth | head -n1)
    
    if [ -n "$bt_device" ]; then
        # Extract vendor:product ID
        local vendor=$(echo "$bt_device" | sed -n 's/.*ID \([0-9a-f]\{4\}\):\([0-9a-f]\{4\}\).*/\1/p')
        local product=$(echo "$bt_device" | sed -n 's/.*ID \([0-9a-f]\{4\}\):\([0-9a-f]\{4\}\).*/\2/p')
        
        if [ -n "$vendor" ] && [ -n "$product" ]; then
            echo "${vendor}:${product}"
        fi
    fi
}

# Get Bluetooth device ID
get_bluetooth_device() {
    if [ -n "$BT_USB_DEVICE" ]; then
        echo "$BT_USB_DEVICE"
    else
        auto_detect_bluetooth
    fi
}
