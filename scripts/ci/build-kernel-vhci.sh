#!/bin/bash
# Builds and loads bluetooth.ko and hci_vhci.ko kernel modules for virtual BLE testing
# when running on cloud VM kernels (such as Azure/GitHub Actions) where CONFIG_BT is omitted.
set -e

if [ -w /dev/vhci ] && python3 -c "import os; fd = os.open('/dev/vhci', os.O_RDWR); os.close(fd)" 2>/dev/null; then
    echo "✅ /dev/vhci is already available and writable."
    exit 0
fi

# Try modprobe first
if sudo modprobe hci_vhci 2>/dev/null; then
    if [ ! -c /dev/vhci ]; then sudo mknod /dev/vhci c 10 137 2>/dev/null || true; fi
    sudo chmod 666 /dev/vhci 2>/dev/null || true
    if [ -w /dev/vhci ]; then
        echo "✅ hci_vhci module loaded via modprobe."
        exit 0
    fi
fi

echo "==> /dev/vhci not available. Attempting to build bluetooth + hci_vhci modules for $(uname -r)..."

# Ensure build essentials, kernel headers, and source are installed
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential linux-source "linux-headers-$(uname -r)" linux-headers-azure 2>/dev/null || true

BUILD_DIR="/lib/modules/$(uname -r)/build"
if [ ! -d "$BUILD_DIR" ]; then
    echo "⚠️ Kernel build headers directory not found at $BUILD_DIR. Cannot build out-of-tree module."
    exit 0
fi

WORK_DIR=$(mktemp -d /tmp/bt-vhci-build.XXXXXX)
cd "$WORK_DIR"

# Check for Ubuntu's linux-source archive in /usr/src
SOURCE_TAR=$(ls /usr/src/linux-source-*.tar.bz2 /usr/src/linux-source-*.tar.xz 2>/dev/null | head -n1 || true)
if [ -n "$SOURCE_TAR" ] && [ -f "$SOURCE_TAR" ]; then
    echo "    Extracting kernel Bluetooth sources from $SOURCE_TAR..."
    tar -xf "$SOURCE_TAR" --wildcards --strip-components=1 "*/net/bluetooth" "*/drivers/bluetooth/hci_vhci.c" 2>/dev/null || true
fi

# If linux-source was not found or failed, fallback to GitHub source fetch
if [ ! -s drivers/bluetooth/hci_vhci.c ] || [ ! -s net/bluetooth/af_bluetooth.c ]; then
    mkdir -p net/bluetooth drivers/bluetooth
    KVER=$(uname -r | cut -d'-' -f1)
    MAJOR=$(echo "$KVER" | cut -d'.' -f1)
    MINOR=$(echo "$KVER" | cut -d'.' -f2)
    BASE_VER="v${MAJOR}.${MINOR}"
    echo "    Fallback: Fetching kernel Bluetooth sources from GitHub for $BASE_VER..."

    RAW_BASE="https://raw.githubusercontent.com/torvalds/linux/${BASE_VER}"
    if ! curl -sfI "${RAW_BASE}/drivers/bluetooth/hci_vhci.c" >/dev/null; then
        RAW_BASE="https://raw.githubusercontent.com/torvalds/linux/master"
        BASE_VER="master"
    fi

    curl -sSfL "${RAW_BASE}/drivers/bluetooth/hci_vhci.c" -o drivers/bluetooth/hci_vhci.c || true

    python3 - << PYEOF
import urllib.request, json, os
net_dir = "net/bluetooth"
os.makedirs(net_dir, exist_ok=True)
api_url = "https://api.github.com/repos/torvalds/linux/contents/net/bluetooth?ref=${BASE_VER}"
headers = {"User-Agent": "curl/7.88"}
try:
    req = urllib.request.Request(api_url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        files = json.loads(resp.read().decode())
        for f in files:
            name = f["name"]
            if name.endswith((".c", ".h")):
                urllib.request.urlretrieve(f["download_url"], os.path.join(net_dir, name))
except Exception as e:
    print(f"    API fallback error: {e}")
PYEOF
fi

# Check if essential files are present
if [ ! -s drivers/bluetooth/hci_vhci.c ] || [ ! -s net/bluetooth/af_bluetooth.c ]; then
    echo "⚠️ Failed to acquire Bluetooth source files. Skipping out-of-tree build."
    rm -rf "$WORK_DIR"
    exit 0
fi

# Compatibility: redirect deprecated <asm/unaligned.h> to <linux/unaligned.h> (kernel 6.7+ transition)
mkdir -p include/asm
echo '#include <linux/unaligned.h>' > include/asm/unaligned.h
find . -type f \( -name "*.c" -o -name "*.h" \) -exec sed -i 's|<asm/unaligned.h>|<linux/unaligned.h>|g' {} + 2>/dev/null || true

# Compatibility: patch for socket UID macro across 6.8 -> 6.11+ kernel transitions
sed -i '1i#include <net/sock.h>\n#ifndef sock_i_uid\n#define sock_i_uid(sk) sock_net_uid(sock_net(sk), sk)\n#endif' net/bluetooth/af_bluetooth.c 2>/dev/null || true

# Top-level Kbuild Makefile
cat << 'EOF' > Makefile
obj-m += net/bluetooth/
obj-m += drivers/bluetooth/
EOF

# net/bluetooth Makefile (standard core modules)
cat << 'EOF' > net/bluetooth/Makefile
obj-m += bluetooth.o
bluetooth-y := af_bluetooth.o hci_core.o hci_conn.o hci_event.o mgmt.o \
	hci_sock.o hci_sysfs.o l2cap_core.o l2cap_sock.o smp.o lib.o \
	ecdh_helper.o hci_request.o mgmt_util.o mgmt_config.o hci_sync.o \
	eir.o leds.o
EXTRA_CFLAGS += -I$(src)/../include -I$(src)/../../include -Wno-error -Wno-implicit-function-declaration -Wno-incompatible-pointer-types -Wno-int-conversion -DCONFIG_BT -DCONFIG_BT_BREDR -DCONFIG_BT_LE -DCONFIG_BT_LEDS
ccflags-y += -I$(src)/../include -I$(src)/../../include -Wno-error -Wno-implicit-function-declaration -Wno-incompatible-pointer-types -Wno-int-conversion -DCONFIG_BT -DCONFIG_BT_BREDR -DCONFIG_BT_LE -DCONFIG_BT_LEDS
EOF

# drivers/bluetooth Makefile
cat << 'EOF' > drivers/bluetooth/Makefile
obj-m += hci_vhci.o
EXTRA_CFLAGS += -I$(src)/../include -I$(src)/../../include -I$(src)/../../net/bluetooth -Wno-error -Wno-implicit-function-declaration -Wno-incompatible-pointer-types -Wno-int-conversion -DCONFIG_BT -DCONFIG_BT_BREDR -DCONFIG_BT_LE
ccflags-y += -I$(src)/../include -I$(src)/../../include -I$(src)/../../net/bluetooth -Wno-error -Wno-implicit-function-declaration -Wno-incompatible-pointer-types -Wno-int-conversion -DCONFIG_BT -DCONFIG_BT_BREDR -DCONFIG_BT_LE
EOF

echo "    Compiling bluetooth.ko + hci_vhci.ko against $BUILD_DIR..."
if make -C "$BUILD_DIR" M="$WORK_DIR" modules > "$WORK_DIR/build.log" 2>&1; then
    echo "    Modules compiled successfully. Inserting modules..."
    sudo insmod "$WORK_DIR/net/bluetooth/bluetooth.ko" 2>/dev/null || true
    sudo insmod "$WORK_DIR/drivers/bluetooth/hci_vhci.ko" 2>/dev/null || true
    if [ ! -c /dev/vhci ]; then sudo mknod /dev/vhci c 10 137 2>/dev/null || true; fi
    sudo chmod 666 /dev/vhci 2>/dev/null || true
    if [ -w /dev/vhci ]; then
        echo "✅ Successfully built and loaded bluetooth + hci_vhci modules! /dev/vhci is now active."
    else
        echo "⚠️ Modules loaded but /dev/vhci is not accessible."
    fi
else
    echo "⚠️ Out-of-tree build failed. Build log:"
    tail -n 25 "$WORK_DIR/build.log" || true
fi

rm -rf "$WORK_DIR"
