#!/bin/bash
# Uninstall script for TapAuth BLE Daemon

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="tapauth-ble-daemon"
BINARY_PATH="/usr/local/bin/tapauth-ble-daemon"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth BLE Daemon - Uninstall                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

# Stop and disable the service if it exists
if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
    echo "==> Stopping and disabling ${SERVICE_NAME} service..."
    
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        systemctl stop "${SERVICE_NAME}"
        echo "✅ Service stopped"
    else
        echo "ℹ️  Service was not running"
    fi
    
    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl disable "${SERVICE_NAME}"
        echo "✅ Service disabled"
    else
        echo "ℹ️  Service was not enabled"
    fi
else
    echo "ℹ️  Service ${SERVICE_NAME} not found in systemd"
fi

# Remove service file
if [ -f "$SERVICE_FILE" ]; then
    echo "==> Removing service file..."
    rm -f "$SERVICE_FILE"
    echo "✅ Service file removed: $SERVICE_FILE"
    
    # Reload systemd daemon
    systemctl daemon-reload
    echo "✅ Systemd daemon reloaded"
else
    echo "ℹ️  Service file not found: $SERVICE_FILE"
fi

# Remove binary
if [ -f "$BINARY_PATH" ]; then
    echo "==> Removing daemon binary..."
    rm -f "$BINARY_PATH"
    echo "✅ Binary removed: $BINARY_PATH"
else
    echo "ℹ️  Binary not found: $BINARY_PATH"
fi

# Remove D-Bus policy
DBUS_POLICY="/etc/dbus-1/system.d/dev.rourunisen.tapauth.BLE.conf"
if [ -f "$DBUS_POLICY" ]; then
    echo "==> Removing D-Bus policy..."
    rm -f "$DBUS_POLICY"
    echo "✅ D-Bus policy removed: $DBUS_POLICY"
else
    echo "ℹ️  D-Bus policy not found: $DBUS_POLICY"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  ✅ TapAuth BLE Daemon uninstalled successfully              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
