#!/bin/bash
# Sets up the UDP port redirection the E2E suite needs to reach the Android guest.
#
# The daemon (built with dev-udp-loopback) unicasts every packet it broadcasts to
# TAPAUTH_DEV_UDP_TARGET = 127.0.0.1:$HOST_PORT; adb forwards that host port to the
# guest's $GUEST_PORT. Replies go back out directly to 10.0.2.2:<daemon port>, so no
# broadcast reflection is involved.
set -e

# Kept in sync with scripts/test-e2e.sh (which exports both).
GUEST_PORT="${TAPAUTH_E2E_UDP_PORT:-36692}"
HOST_PORT="${TAPAUTH_E2E_DEV_HOST_PORT:-36695}"

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

# Drop a stale redirection from a previous run so re-adding cannot fail.
adb emu redir del udp:"$HOST_PORT" 2>/dev/null || true

# Map host port to guest port (syntax: redir add udp:host_port:guest_port)
echo "    Configuring UDP redirection (host:${HOST_PORT} -> guest:${GUEST_PORT})..."
adb emu redir add udp:"${HOST_PORT}":"${GUEST_PORT}" || true
echo "    Active port redirections:"
adb emu redir list || true

echo "✅ UDP Network bridge ready (host:${HOST_PORT} -> guest:${GUEST_PORT})."
