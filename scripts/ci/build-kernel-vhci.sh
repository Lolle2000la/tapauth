#!/bin/bash
# Builds and loads bluetooth.ko and hci_vhci.ko kernel modules for virtual BLE testing
# when running on cloud VM kernels (such as Azure/GitHub Actions) where CONFIG_BT is omitted.
set -e

echo "==> Setting up Linux kernel virtual Bluetooth (hci_vhci)..."

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
sudo apt-get install -y -qq build-essential "linux-headers-$(uname -r)" linux-headers-azure

BUILD_DIR="/lib/modules/$(uname -r)/build"
if [ ! -d "$BUILD_DIR" ]; then
    echo "❌ ERROR: Kernel build headers directory not found at $BUILD_DIR."
    exit 1
fi

WORK_DIR=$(mktemp -d /tmp/bt-vhci-build.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR"

mkdir -p net/bluetooth drivers/bluetooth include/net/bluetooth include/asm

# Use Linux 6.11 / master consistent tree
RAW_BASE="https://raw.githubusercontent.com/torvalds/linux/master"

echo "    Downloading matching Bluetooth subsystem source and headers..."
curl -sSfL "${RAW_BASE}/drivers/bluetooth/hci_vhci.c" -o drivers/bluetooth/hci_vhci.c

python3 - << PYEOF
import urllib.request, json, os

def fetch_dir(api_path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    api_url = f"https://api.github.com/repos/torvalds/linux/contents/{api_path}?ref=master"
    headers = {"User-Agent": "curl/7.88"}
    try:
        req = urllib.request.Request(api_url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            files = json.loads(resp.read().decode())
            for f in files:
                name = f["name"]
                if name.endswith((".c", ".h")):
                    urllib.request.urlretrieve(f["download_url"], os.path.join(out_dir, name))
            return True
    except Exception as e:
        print(f"    API fallback for {api_path}: {e}")
        return False

# Fetch all files in net/bluetooth and include/net/bluetooth
fetch_dir("net/bluetooth", "net/bluetooth")
fetch_dir("include/net/bluetooth", "include/net/bluetooth")
PYEOF

# Fallback direct download if API rate limited
if [ ! -s include/net/bluetooth/hci_core.h ]; then
    echo "    Fetching essential headers directly..."
    for h in bluetooth.h hci.h hci_core.h hci_mon.h l2cap.h mgmt.h; do
        curl -sSfL "${RAW_BASE}/include/net/bluetooth/${h}" -o "include/net/bluetooth/${h}" || true
    done
fi

if [ ! -s net/bluetooth/hci_core.c ]; then
    echo "    Fetching essential source files directly..."
    for s in af_bluetooth.c hci_core.c hci_conn.c hci_event.c mgmt.c hci_sock.c hci_sysfs.c l2cap_core.c l2cap_sock.c smp.c lib.c ecdh_helper.c hci_request.c mgmt_util.c mgmt_config.c hci_sync.c eir.c leds.c leds.h smp.h mgmt_util.h hci_request.h eir.h ecdh_helper.h mgmt_config.h; do
        curl -sSfL "${RAW_BASE}/net/bluetooth/${s}" -o "net/bluetooth/${s}" || true
    done
fi

# Check if essential files are present
if [ ! -s drivers/bluetooth/hci_vhci.c ] || [ ! -s net/bluetooth/hci_core.c ] || [ ! -s include/net/bluetooth/hci_core.h ]; then
    echo "❌ ERROR: Failed to acquire Bluetooth source files and headers."
    exit 1
fi

# Compatibility: redirect deprecated <asm/unaligned.h> to <linux/unaligned.h>
echo '#include <linux/unaligned.h>' > include/asm/unaligned.h
find . -type f \( -name "*.c" -o -name "*.h" \) -exec sed -i 's|<asm/unaligned.h>|<linux/unaligned.h>|g' {} + 2>/dev/null || true

# Compatibility: patch for socket UID macro across kernel versions
sed -i 's|sock_i_uid(sk)|sock_net_uid(sock_net(sk), sk)|g' net/bluetooth/af_bluetooth.c 2>/dev/null || true

# Top-level Kbuild Makefile
cat << 'EOF' > Makefile
obj-m += net/bluetooth/
obj-m += drivers/bluetooth/
EOF

# net/bluetooth Makefile (standard core modules, excluding vendor extensions aosp/msft/iso)
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
if ! make -C "$BUILD_DIR" M="$WORK_DIR" modules > "$WORK_DIR/build.log" 2>&1; then
    echo "❌ ERROR: Out-of-tree kernel module compilation failed. Full build log:"
    cat "$WORK_DIR/build.log"
    exit 1
fi

echo "    Modules compiled successfully. Inserting modules..."
sudo insmod "$WORK_DIR/net/bluetooth/bluetooth.ko" || {
    echo "❌ ERROR: Failed to insert bluetooth.ko module."
    dmesg | tail -n 20
    exit 1
}
sudo insmod "$WORK_DIR/drivers/bluetooth/hci_vhci.ko" || {
    echo "❌ ERROR: Failed to insert hci_vhci.ko module."
    dmesg | tail -n 20
    exit 1
}

if [ ! -c /dev/vhci ]; then sudo mknod /dev/vhci c 10 137; fi
sudo chmod 666 /dev/vhci

if [ -w /dev/vhci ] && python3 -c "import os; fd = os.open('/dev/vhci', os.O_RDWR); os.close(fd)" 2>/dev/null; then
    echo "✅ Successfully built and loaded bluetooth + hci_vhci modules! /dev/vhci is now active and writable."
else
    echo "❌ ERROR: /dev/vhci exists but is not writable."
    ls -la /dev/vhci
    exit 1
fi
