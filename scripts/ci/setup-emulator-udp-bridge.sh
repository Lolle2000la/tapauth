#!/bin/bash
# Sets up UDP port redirection and broadcast reflection for the Android Emulator
set -e

echo "==> Configuring UDP Network Bridge for Android Emulator..."

# Find running emulator serial / console port
EMULATOR_SERIAL=$(adb devices | grep -m1 'emulator-[0-9]*' | awk '{print $1}' || true)
if [ -z "$EMULATOR_SERIAL" ]; then
    echo "❌ Error: No running Android emulator found via adb."
    exit 1
fi

CONSOLE_PORT=$(echo "$EMULATOR_SERIAL" | sed 's/emulator-//')
echo "    Found emulator: $EMULATOR_SERIAL (Console Port: $CONSOLE_PORT)"

# Set up port redirection via emulator console
AUTH_TOKEN=""
if [ -f "$HOME/.emulator_console_auth_token" ]; then
    AUTH_TOKEN=$(cat "$HOME/.emulator_console_auth_token")
fi

echo "    Configuring UDP redirection on port 36692..."
python3 - << PY || {
    echo "⚠️ Failed to configure via Python telnet; trying direct netcat..."
}
import socket, time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(('127.0.0.1', int("$CONSOLE_PORT")))
    banner = s.recv(1024).decode(errors='ignore')
    if "$AUTH_TOKEN":
        s.sendall(f"auth $AUTH_TOKEN\n".encode())
        resp = s.recv(1024).decode(errors='ignore')
    
    # Add UDP redirection: redir add udp:guest_port:host_port
    s.sendall(b"redir add udp:36692:36692\n")
    resp = s.recv(1024).decode(errors='ignore')
    print(f"    Emulator console response: {resp.strip()}")
    s.sendall(b"quit\n")
    s.close()
    print("✅ Port redirect udp:36692:36692 configured.")
except Exception as e:
    print(f"⚠️ Console redirect warning: {e}")
PY

# Spawn background UDP broadcast reflector (mirrors 255.255.255.255 / local subnet broadcasts to 127.0.0.1:36692)
echo "    Starting background UDP broadcast reflector..."
python3 - << 'EOF' > /tmp/udp-reflector.log 2>&1 &
import socket, sys

try:
    # Listener for broadcast
    sock_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock_in.bind(('', 36692))
    
    # Forwarder
    sock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print("UDP broadcast reflector running on port 36692...")
    sys.stdout.flush()
    
    while True:
        data, addr = sock_in.recvfrom(4096)
        # Avoid forwarding packets that came from loopback itself to prevent loops
        if addr[0] != '127.0.0.1':
            sock_out.sendto(data, ('127.0.0.1', 36692))
except Exception as e:
    print(f"Reflector exited: {e}")
    sys.stdout.flush()
EOF
REFLECTOR_PID=$!
echo "$REFLECTOR_PID" > /tmp/udp-reflector.pid
echo "    UDP broadcast reflector running with PID $REFLECTOR_PID"

echo "✅ UDP Network bridge ready."
