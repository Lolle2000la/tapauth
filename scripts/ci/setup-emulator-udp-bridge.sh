#!/bin/bash
# Sets up UDP port redirection and broadcast reflection for the Android Emulator
set -e

echo "==> Configuring UDP Network Bridge for Android Emulator..."

# Ensure adb is in PATH
if ! command -v adb &> /dev/null; then
    for p in "/usr/local/lib/android/sdk/platform-tools" "$ANDROID_HOME/platform-tools" "$ANDROID_SDK_ROOT/platform-tools" "$HOME/Android/Sdk/platform-tools"; do
        if [ -x "$p/adb" ]; then
            export PATH="$PATH:$p"
            break
        fi
    done
fi

# Find running emulator serial
EMULATOR_SERIAL=$(adb devices | grep -m1 'emulator-[0-9]*' | awk '{print $1}' || true)
if [ -z "$EMULATOR_SERIAL" ]; then
    echo "❌ Error: No running Android emulator found via adb."
    exit 1
fi

# Remove any stale port redirections
adb emu redir del udp:36692 2>/dev/null || true
adb emu redir del udp:36695 2>/dev/null || true

# Map host port 36695 to guest port 36692 (syntax: redir add udp:host_port:guest_port)
echo "    Configuring UDP redirection (host:36695 -> guest:36692)..."
adb emu redir add udp:36695:36692 || true
echo "    Active port redirections:"
adb emu redir list || true

echo "✅ UDP Network bridge ready (host:36695 -> guest:36692)."
