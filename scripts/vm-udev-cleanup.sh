#!/bin/bash
# TapAuth VM - USB Passthrough Cleanup
# This script removes udev rules for USB passthrough

set -e

# Save original working directory
ORIGINAL_DIR="$(pwd)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth VM - USB Passthrough Cleanup                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

UDEV_RULE_FILE="/etc/udev/rules.d/99-tapauth-usb.rules"

# Check if udev rule exists
if [ ! -f "$UDEV_RULE_FILE" ]; then
    echo "✅ No udev rules found - nothing to clean up"
    echo ""
    echo "Rule file not found: $UDEV_RULE_FILE"
    exit 0
fi

echo "Found udev rule file: $UDEV_RULE_FILE"
echo ""
echo "Current rule contents:"
echo "----------------------------------------"
cat "$UDEV_RULE_FILE"
echo "----------------------------------------"
echo ""

# Confirm deletion
read -p "Remove this udev rule? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled - no changes made"
    exit 0
fi

# Remove the udev rule
echo ""
echo "Removing udev rule..."
sudo rm -f "$UDEV_RULE_FILE"
echo "✅ Removed: $UDEV_RULE_FILE"

# Reload udev rules
echo ""
echo "Reloading udev rules..."
sudo udevadm control --reload-rules
sudo udevadm trigger
echo "✅ Udev rules reloaded"

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         Cleanup Complete!                                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "The udev rule has been removed."
echo ""
echo "Note: You are still a member of the 'plugdev' group."
echo "To remove yourself from the group, run:"
echo "  sudo gpasswd -d $USER plugdev"
echo ""
echo "After removing from plugdev group, you'll need to log out and back in."
echo ""

# Restore original working directory
cd "$ORIGINAL_DIR"
