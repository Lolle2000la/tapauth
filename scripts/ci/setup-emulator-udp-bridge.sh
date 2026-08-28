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

# Map host port 36695 to guest port 36692 (syntax: redir add udp:guest_port:host_port)
echo "    Configuring UDP redirection (host:36695 -> guest:36692)..."
adb emu redir add udp:36692:36695 || true
echo "    Active port redirections:"
adb emu redir list || true

# Spawn background UDP broadcast reflector
# Mirrors 255.255.255.255 / local subnet broadcasts on port 36692 to 127.0.0.1:36695
echo "    Starting background UDP broadcast reflector..."

cat << 'EOF' > /tmp/udp_reflector.py
import socket, sys, time

SO_REUSEPORT = getattr(socket, 'SO_REUSEPORT', 15)

try:
    # Listener for broadcast on 0.0.0.0:36692 (shares port 36692 with tapauthd)
    sock_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock_in.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
    except Exception:
        pass
    sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock_in.bind(('', 36692))
    
    # Forwarder to emulator guest via host redirection port 36695
    sock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print("UDP broadcast reflector listening on 36692, forwarding to 127.0.0.1:36695...", flush=True)
    
    while True:
        data, addr = sock_in.recvfrom(65535)
        # Forward to emulator redirection port
        try:
            sock_out.sendto(data, ('127.0.0.1', 36695))
            print(f"Reflected {len(data)} bytes from {addr} to 127.0.0.1:36695", flush=True)
        except Exception as e:
            print(f"Forward error: {e}", flush=True)
except Exception as e:
    print(f"Reflector error: {e}", flush=True)
EOF

python3 /tmp/udp_reflector.py > /tmp/udp-reflector.log 2>&1 &
REFLECTOR_PID=$!
echo "$REFLECTOR_PID" > /tmp/udp-reflector.pid
echo "    UDP broadcast reflector running with PID $REFLECTOR_PID"

echo "✅ UDP Network bridge ready."
