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

echo "    Configuring UDP redirection (host:36692 -> guest:36692)..."
adb emu redir add udp:36692:36692 || true
echo "    Active port redirections:"
adb emu redir list || true

# Spawn background UDP broadcast reflector
# Mirrors 255.255.255.255 / local subnet broadcasts to 127.0.0.1:36692
echo "    Starting background UDP broadcast reflector..."

cat << 'EOF' > /tmp/udp_reflector.py
import socket, sys, time

SO_REUSEPORT = getattr(socket, 'SO_REUSEPORT', 15)

try:
    # Listener for broadcast on 0.0.0.0:36692
    sock_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock_in.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
    except Exception:
        pass
    sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock_in.bind(('', 36692))
    
    # Forwarder to emulator host redirection
    sock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print("UDP broadcast reflector running on port 36692...", flush=True)
    
    seen = {}
    while True:
        data, addr = sock_in.recvfrom(65535)
        now = time.time()
        # Clean expired keys
        seen = {k: v for k, v in seen.items() if now - v < 2.0}
        
        # Don't forward loopback traffic or duplicated packets
        key = (data[:32], addr[1])
        if key in seen:
            continue
        seen[key] = now
        
        try:
            sock_out.sendto(data, ('127.0.0.1', 36692))
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
