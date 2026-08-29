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

# Ensure build essentials and kernel headers are installed
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential "linux-headers-$(uname -r)" linux-headers-azure 2>/dev/null || true

BUILD_DIR="/lib/modules/$(uname -r)/build"
if [ ! -d "$BUILD_DIR" ]; then
    echo "⚠️ Kernel build headers directory not found at $BUILD_DIR. Cannot build out-of-tree module."
    exit 0
fi

WORK_DIR=$(mktemp -d /tmp/bt-vhci-build.XXXXXX)
cd "$WORK_DIR"

KVER=$(uname -r | cut -d'-' -f1)
MAJOR=$(echo "$KVER" | cut -d'.' -f1)
MINOR=$(echo "$KVER" | cut -d'.' -f2)
BASE_VER="v${MAJOR}.${MINOR}"
echo "    Fetching kernel Bluetooth sources for $BASE_VER..."

mkdir -p net/bluetooth drivers/bluetooth

RAW_BASE="https://raw.githubusercontent.com/torvalds/linux/${BASE_VER}"
if ! curl -sfI "${RAW_BASE}/drivers/bluetooth/hci_vhci.c" >/dev/null; then
    RAW_BASE="https://raw.githubusercontent.com/torvalds/linux/master"
    BASE_VER="master"
fi

echo "    Downloading Bluetooth source files from ${RAW_BASE}..."
curl -sSfL "${RAW_BASE}/drivers/bluetooth/hci_vhci.c" -o drivers/bluetooth/hci_vhci.c || true

python3 - << PYEOF
import urllib.request, json, os

net_dir = "net/bluetooth"
os.makedirs(net_dir, exist_ok=True)

# Try fetching entire directory listing from GitHub API
api_url = "https://api.github.com/repos/torvalds/linux/contents/net/bluetooth?ref=${BASE_VER}"
headers = {"User-Agent": "curl/7.88"}
success = False
try:
    req = urllib.request.Request(api_url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        files = json.loads(resp.read().decode())
        for f in files:
            name = f["name"]
            if name.endswith((".c", ".h")):
                download_url = f["download_url"]
                urllib.request.urlretrieve(download_url, os.path.join(net_dir, name))
        success = True
        print("    Downloaded net/bluetooth sources via GitHub API.")
except Exception as e:
    print(f"    GitHub API unavailable ({e}), downloading known file list...")

if not success:
    known_files = [
        "af_bluetooth.c", "hci_core.c", "hci_conn.c", "hci_event.c", "mgmt.c",
        "hci_sock.c", "hci_sysfs.c", "l2cap_core.c", "l2cap_sock.c", "smp.c",
        "lib.c", "ecdh_helper.c", "hci_request.c", "mgmt_util.c", "mgmt_config.c",
        "hci_sync.c", "eir.c", "leds.c", "leds.h", "smp.h",
        "mgmt_util.h", "hci_request.h", "aosp.h", "eir.h", "ecdh_helper.h",
        "mgmt_config.h", "hci_codec.h", "selftest.h"
    ]
    for f in known_files:
        url = f"${RAW_BASE}/net/bluetooth/{f}"
        try:
            urllib.request.urlretrieve(url, os.path.join(net_dir, f))
        except Exception:
            pass
PYEOF

# Check if essential files were downloaded
if [ ! -s drivers/bluetooth/hci_vhci.c ] || [ ! -s net/bluetooth/af_bluetooth.c ]; then
    echo "⚠️ Failed to download essential Bluetooth source files. Skipping out-of-tree build."
    rm -rf "$WORK_DIR"
    exit 0
fi

# Top-level Kbuild Makefile
cat << 'EOF' > Makefile
obj-m += net/bluetooth/
obj-m += drivers/bluetooth/
EOF

# net/bluetooth Makefile (standard core modules only, excluding vendor extensions aosp/msft/iso)
cat << 'EOF' > net/bluetooth/Makefile
obj-m += bluetooth.o
bluetooth-y := af_bluetooth.o hci_core.o hci_conn.o hci_event.o mgmt.o \
	hci_sock.o hci_sysfs.o l2cap_core.o l2cap_sock.o smp.o lib.o \
	ecdh_helper.o hci_request.o mgmt_util.o mgmt_config.o hci_sync.o \
	eir.o leds.o
ccflags-y += -DCONFIG_BT -DCONFIG_BT_BREDR -DCONFIG_BT_LE -DCONFIG_BT_LEDS -Wno-error
EOF

# drivers/bluetooth Makefile
cat << 'EOF' > drivers/bluetooth/Makefile
obj-m += hci_vhci.o
ccflags-y += -I$(src)/../../net/bluetooth -DCONFIG_BT -DCONFIG_BT_BREDR -DCONFIG_BT_LE -Wno-error
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
