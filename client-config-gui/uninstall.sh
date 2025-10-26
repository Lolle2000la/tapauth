#!/bin/bash
set -e

# Script to uninstall TapAuth Configuration GUI

echo "Uninstalling TapAuth Configuration GUI..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (sudo ./uninstall.sh)"
    exit 1
fi

# Remove binary
if [ -f /usr/bin/tapauth-config ]; then
    echo "Removing binary..."
    rm /usr/bin/tapauth-config
fi

# Remove polkit policy
if [ -f /usr/share/polkit-1/actions/dev.rourunisen.tapauth.policy ]; then
    echo "Removing polkit policy..."
    rm /usr/share/polkit-1/actions/dev.rourunisen.tapauth.policy
fi

# Remove desktop file
if [ -f /usr/share/applications/tapauth-config.desktop ]; then
    echo "Removing desktop file..."
    rm /usr/share/applications/tapauth-config.desktop
fi

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    echo "Updating desktop database..."
    update-desktop-database /usr/share/applications
fi

echo ""
echo "✓ Uninstallation complete!"
echo ""
echo "Note: User pairing data in /etc/tapauth/ was not removed."
echo "To completely remove all data, run: sudo rm -rf /etc/tapauth/"
