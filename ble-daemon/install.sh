#!/bin/bash
# Install TapAuth BLE Daemon

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║       TapAuth BLE Daemon - Build and Install                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check for cargo
if ! command -v cargo &> /dev/null; then
    echo "❌ cargo command not found in PATH."
    echo "   Ensure Rust is installed correctly."
    exit 1
fi

# Build the daemon
echo "==> Building BLE daemon..."
cargo build --release

# With workspace, build output is at root level
if [ ! -f "../target/release/tapauth-ble-daemon" ]; then
    echo "❌ Build failed: Executable not found"
    exit 1
fi
echo "✅ Build successful"

# Install binary
echo ""
echo "==> Installing binary (requires sudo)..."
echo "    Installing daemon binary to /usr/local/bin/tapauth-ble-daemon"
sudo cp ../target/release/tapauth-ble-daemon /usr/local/bin/
sudo chmod 755 /usr/local/bin/tapauth-ble-daemon
echo "✅ Binary installed"

echo "==> Installing D-Bus policy..."
echo "    Installing D-Bus policy to /etc/dbus-1/system.d/"
sudo cp dev.rourunisen.tapauth.BLE.conf /etc/dbus-1/system.d/
sudo chmod 644 /etc/dbus-1/system.d/dev.rourunisen.tapauth.BLE.conf

echo "==> Installing D-Bus service activation file..."
echo "    Installing D-Bus service activation to /usr/share/dbus-1/system-services/"
sudo cp dev.rourunisen.tapauth.BLE.service /usr/share/dbus-1/system-services/
sudo chmod 644 /usr/share/dbus-1/system-services/dev.rourunisen.tapauth.BLE.service

# Reload D-Bus configuration WITHOUT restarting the entire service
sudo dbus-send --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig
echo "✅ D-Bus policy and service activation installed and configuration reloaded"

echo "==> Installing systemd service..."

# Install systemd service
echo ""
echo "==> Installing systemd service..."
sudo cp tapauth-ble-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
echo "✅ Systemd service installed"

# Enable and start service
echo ""
echo "==> Enabling and starting service..."
sudo systemctl enable tapauth-ble-daemon.service
sudo systemctl start tapauth-ble-daemon.service
echo "✅ Service enabled and started"

# Check status
echo ""
echo "==> Service status:"
sudo systemctl status tapauth-ble-daemon.service --no-pager -l || true

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  TapAuth BLE Daemon installed successfully!                 ║"
echo "║                                                               ║"
echo "║  Commands:                                                    ║"
echo "║    sudo systemctl status tapauth-ble-daemon                  ║"
echo "║    sudo systemctl stop tapauth-ble-daemon                    ║"
echo "║    sudo systemctl restart tapauth-ble-daemon                 ║"
echo "║    sudo journalctl -u tapauth-ble-daemon -f                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
