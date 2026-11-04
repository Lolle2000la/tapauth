#!/bin/bash
# Sets up the UDP port redirection the E2E suite needs to reach the Android guest.
#
# The daemon (built with dev-udp-loopback) unicasts every packet it multicasts to
# TAPAUTH_DEV_UDP_TARGET = 127.0.0.1:$HOST_PORT; adb forwards that host port to the
# guest's $GUEST_PORT. Replies go back out directly to 10.0.2.2:<daemon port>, so no
# multicast reflection is involved.
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

# adb reads the emulator console auth token from $HOME. Under sudo on
# Ubuntu 26.04 (sudo-rs) HOME is /root and bare -E is ignored, so fall
# back to the invoking user's home when it holds the token.
if [ ! -r "$HOME/.emulator_console_auth_token" ] && [ -n "${SUDO_USER:-}" ]; then
    _sudo_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    if [ -r "$_sudo_home/.emulator_console_auth_token" ]; then
        export HOME="$_sudo_home"
    fi
fi

# Find running emulator serial
EMULATOR_SERIAL=$(adb devices | grep -m1 'emulator-[0-9]*' | awk '{print $1}' || true)
if [ -z "$EMULATOR_SERIAL" ]; then
    echo "❌ Error: No running Android emulator found via adb."
    exit 1
fi

# Fails loudly with the diagnostics needed to tell "no console auth" (wrong
# $HOME) from "bridge never installed". adb relays the console's "KO: ..." to
# stdout but still exits 0, so a command's status alone is not trustworthy.
fail_redirection() {
    echo "❌ Error: $1"
    echo "    adb version:"
    adb version 2>&1 | sed 's/^/      /'
    echo "    HOME=$HOME"
    echo "    'adb -s ${EMULATOR_SERIAL} emu redir list' output:"
    _redirs="$(adb -s "$EMULATOR_SERIAL" emu redir list 2>&1 || true)"
    printf '%s\n' "$_redirs" | sed 's/^/      /'
    exit 1
}

# Drop a stale redirection from a previous run so re-adding cannot fail.
# A missing redirection makes `redir del` fail, so this stays best-effort.
adb -s "$EMULATOR_SERIAL" emu redir del udp:"$HOST_PORT" 2>/dev/null || true

# Map host port to guest port (syntax: redir add udp:host_port:guest_port)
echo "    Configuring UDP redirection (host:${HOST_PORT} -> guest:${GUEST_PORT})..."
if ! adb -s "$EMULATOR_SERIAL" emu redir add udp:"${HOST_PORT}":"${GUEST_PORT}"; then
    fail_redirection "adb emu redir add udp:${HOST_PORT}:${GUEST_PORT} failed for ${EMULATOR_SERIAL}."
fi

echo "    Active port redirections:"
REDIR_LIST="$(adb -s "$EMULATOR_SERIAL" emu redir list 2>&1 || true)"
printf '%s\n' "$REDIR_LIST"
if ! printf '%s\n' "$REDIR_LIST" | grep -q "udp:${HOST_PORT}"; then
    fail_redirection "host port ${HOST_PORT} is not redirected to guest port ${GUEST_PORT} after 'redir add'."
fi

echo "✅ UDP Network bridge ready (host:${HOST_PORT} -> guest:${GUEST_PORT})."
