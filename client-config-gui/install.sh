#!/bin/bash
set -e

# Script to install TapAuth Configuration GUI

echo "Installing TapAuth Configuration GUI..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (sudo ./install.sh)"
    exit 1
fi

# Build release binary
echo "Building release binary..."
cargo build --release

# Install binary (workspace target is at root level)
echo "Installing binary to /usr/bin/tapauth-config..."
install -Dm755 ../target/release/tapauth-config /usr/bin/tapauth-config

# Install polkit policy
echo "Installing polkit policy..."
install -Dm644 ../tapauthd/org.tapauth.config.admin.policy \
    /usr/share/polkit-1/actions/org.tapauth.config.admin.policy

# Install desktop icon
echo "Installing desktop icon..."
install -Dm644 assets/tapauth-config.svg \
    /usr/share/icons/hicolor/scalable/apps/tapauth-config.svg

# Install desktop file
echo "Installing desktop file..."
install -Dm644 tapauth-config.desktop \
    /usr/share/applications/tapauth-config.desktop

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    echo "Updating desktop database..."
    update-desktop-database /usr/share/applications
fi

# Update icon cache
if command -v gtk-update-icon-cache &> /dev/null; then
    echo "Updating icon cache..."
    gtk-update-icon-cache -f /usr/share/icons/hicolor
fi

echo ""
echo "✓ Installation complete!"
echo ""
echo "You can now:"
echo "  • Run from terminal: tapauth-config"
echo "  • Run from application menu: TapAuth Configuration"
echo ""
echo "Authorization is handled via PolKit — you will be prompted for your"
echo "password when performing administrative operations."
