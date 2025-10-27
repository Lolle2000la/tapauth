#!/bin/bash
# TapAuth VM - USB Passthrough Setup
# This script sets up udev rules for USB passthrough without requiring root

set -e

# Save original working directory
ORIGINAL_DIR="$(pwd)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth VM - USB Passthrough Setup                    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Detect Bluetooth device
BT_DEVICE=$(get_bluetooth_device)

if [ -z "$BT_DEVICE" ]; then
    echo "❌ No Bluetooth device detected"
    echo ""
    echo "Please ensure your Bluetooth adapter is connected and try again."
    exit 1
fi

echo "Detected Bluetooth device: $BT_DEVICE"
BT_VENDOR=$(echo "$BT_DEVICE" | cut -d: -f1)
BT_PRODUCT=$(echo "$BT_DEVICE" | cut -d: -f2)

echo ""
echo "Setting up udev rules for automatic USB passthrough..."
echo ""

# Create udev rule
UDEV_RULE_FILE="/etc/udev/rules.d/99-tapauth-usb.rules"

cat << EOF | sudo tee "$UDEV_RULE_FILE" > /dev/null
# TapAuth VM - Bluetooth USB Passthrough
# Allow user access to Bluetooth device for QEMU passthrough
SUBSYSTEM=="usb", ATTRS{idVendor}=="${BT_VENDOR}", ATTRS{idProduct}=="${BT_PRODUCT}", MODE="0666", GROUP="plugdev"

# Alternative: Allow all users in plugdev group to access USB devices
# SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", MODE="0664", GROUP="plugdev"
EOF

echo "✅ Created udev rule: $UDEV_RULE_FILE"

# Add user to plugdev group if not already a member
if ! groups "$USER" | grep -q plugdev; then
    echo ""
    echo "Adding user $USER to plugdev group..."
    sudo usermod -a -G plugdev "$USER"
    echo "✅ User added to plugdev group"
    echo ""
    echo "⚠️  NOTE: You need to log out and log back in for group changes to take effect"
    echo "   Or run: newgrp plugdev"
else
    echo "✅ User $USER is already in plugdev group"
fi

# Reload udev rules
echo ""
echo "Reloading udev rules..."
sudo udevadm control --reload-rules
sudo udevadm trigger

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         Setup Complete!                                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "The following udev rule has been created:"
echo ""
cat "$UDEV_RULE_FILE"
echo ""
echo "Next steps:"
echo "  1. If you were added to plugdev group, log out and back in"
echo "  2. Restart the VM: ./scripts/vm-stop.sh && ./scripts/vm-start.sh"
echo ""

# Restore original working directory
cd "$ORIGINAL_DIR"
