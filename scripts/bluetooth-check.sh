#!/bin/bash
# TapAuth - Bluetooth Advertising Diagnostic Tool
# This script checks for issues that can prevent BLE advertising

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth Bluetooth Diagnostic Tool                    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if Bluetooth service is running
echo "==> Checking Bluetooth service status..."
if systemctl is-active --quiet bluetooth; then
    echo "✅ Bluetooth service is running"
else
    echo "❌ Bluetooth service is not running"
    echo "   Start it with: sudo systemctl start bluetooth"
    exit 1
fi
echo ""

# Check for Bluetooth adapters
echo "==> Checking for Bluetooth adapters..."
if command -v bluetoothctl &> /dev/null; then
    ADAPTERS=$(bluetoothctl list | grep -c "Controller" || echo "0")
    if [ "$ADAPTERS" -gt 0 ]; then
        echo "✅ Found $ADAPTERS Bluetooth adapter(s)"
        bluetoothctl list | sed 's/^/   /'
    else
        echo "❌ No Bluetooth adapters found"
        exit 1
    fi
else
    echo "⚠️  bluetoothctl not found, cannot check adapters"
fi
echo ""

# Check adapter power state
echo "==> Checking adapter power state..."
if command -v bluetoothctl &> /dev/null; then
    POWER_STATE=$(bluetoothctl show | grep "Powered:" | awk '{print $2}')
    if [ "$POWER_STATE" = "yes" ]; then
        echo "✅ Adapter is powered on"
    else
        echo "❌ Adapter is powered off"
        echo "   Turn it on with: bluetoothctl power on"
    fi
else
    echo "⚠️  Cannot check power state"
fi
echo ""

# Check for active advertisements (requires root)
echo "==> Checking for active BLE advertisements..."
if [ "$EUID" -eq 0 ]; then
    # Check bluetoothd logs for recent advertisement activity
    RECENT_ADS=$(journalctl -u bluetooth.service --since "5 minutes ago" -n 100 | grep -c "advertisement" || echo "0")
    echo "   Found $RECENT_ADS advertisement-related log entries in last 5 minutes"
    
    # Check for "Busy" errors
    BUSY_ERRORS=$(journalctl -u bluetooth.service --since "5 minutes ago" | grep -c "Busy" || echo "0")
    if [ "$BUSY_ERRORS" -gt 0 ]; then
        echo "⚠️  Found $BUSY_ERRORS 'Busy' errors in Bluetooth logs"
        echo "   This usually means:"
        echo "   - Another application is using advertising slots"
        echo "   - Previous advertisements weren't properly cleaned up"
        echo ""
        echo "   Recent Busy errors:"
        journalctl -u bluetooth.service --since "5 minutes ago" | grep "Busy" | tail -5 | sed 's/^/      /'
    else
        echo "✅ No recent 'Busy' errors"
    fi
else
    echo "⚠️  Run with sudo to check for active advertisements"
    echo "   sudo $0"
fi
echo ""

# Check for processes using Bluetooth
echo "==> Checking for processes using Bluetooth..."
if [ "$EUID" -eq 0 ]; then
    # Check for bluetoothctl sessions
    BLUETOOTHCTL_PROCS=$(pgrep -c bluetoothctl || echo "0")
    if [ "$BLUETOOTHCTL_PROCS" -gt 0 ]; then
        echo "⚠️  Found $BLUETOOTHCTL_PROCS bluetoothctl process(es)"
        echo "   Active bluetoothctl sessions can interfere with advertising"
        pgrep -a bluetoothctl | sed 's/^/   /'
    else
        echo "✅ No bluetoothctl processes found"
    fi
    
    # Check for other BLE applications
    if command -v lsof &> /dev/null; then
        BLE_USERS=$(lsof -t /dev/rfkill 2>/dev/null | wc -l || echo "0")
        if [ "$BLE_USERS" -gt 1 ]; then
            echo "⚠️  Multiple processes are using Bluetooth hardware"
        fi
    fi
else
    echo "⚠️  Run with sudo to check for interfering processes"
fi
echo ""

# Check D-Bus configuration
echo "==> Checking TapAuth D-Bus configuration..."
if [ -f "/etc/dbus-1/system.d/dev.rourunisen.tapauth.BLE.conf" ]; then
    echo "✅ TapAuth D-Bus policy found"
else
    echo "❌ TapAuth D-Bus policy not found"
    echo "   Install it with the BLE daemon installer"
fi
echo ""

# Check for TapAuth daemon
echo "==> Checking TapAuth BLE daemon..."
if systemctl list-unit-files | grep -q "tapauth-ble-daemon.service"; then
    if systemctl is-active --quiet tapauth-ble-daemon; then
        echo "✅ TapAuth BLE daemon is running"
        
        # Show recent logs
        echo ""
        echo "   Recent daemon logs:"
        journalctl -u tapauth-ble-daemon.service -n 10 --no-pager | sed 's/^/      /'
    else
        echo "⚠️  TapAuth BLE daemon is installed but not running"
        echo "   Start it with: sudo systemctl start tapauth-ble-daemon"
    fi
else
    echo "⚠️  TapAuth BLE daemon is not installed"
fi
echo ""

# Recommendations
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         Recommendations                                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "If you're experiencing 'Busy' errors:"
echo "  1. Close any bluetoothctl sessions"
echo "  2. Restart the Bluetooth service:"
echo "     sudo systemctl restart bluetooth"
echo "  3. Restart the TapAuth daemon:"
echo "     sudo systemctl restart tapauth-ble-daemon"
echo "  4. Check for other BLE applications (e.g., bluetooth managers)"
echo ""
echo "For persistent issues:"
echo "  - Reboot the system to fully reset Bluetooth state"
echo "  - Check kernel logs: dmesg | grep -i bluetooth"
echo ""
