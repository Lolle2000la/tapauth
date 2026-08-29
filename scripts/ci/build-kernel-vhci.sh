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

mkdir -p net/bluetooth drivers/bluetooth include/net/bluetooth

RAW_BASE="https://raw.githubusercontent.com/torvalds/linux/${BASE_VER}"
if ! curl -sfI "${RAW_BASE}/drivers/bluetooth/hci_vhci.c" >/dev/null; then
    RAW_BASE="https://raw.githubusercontent.com/torvalds/linux/master"
fi

echo "    Downloading Bluetooth source files from ${RAW_BASE}..."

# List of source files for net/bluetooth and drivers/bluetooth
BT_FILES=(
    "drivers/bluetooth/hci_vhci.c"
    "net/bluetooth/af_bluetooth.c"
    "net/bluetooth/hci_core.c"
    "net/bluetooth/hci_conn.c"
    "net/bluetooth/hci_event.c"
    "net/bluetooth/mgmt.c"
    "net/bluetooth/hci_sock.c"
    "net/bluetooth/hci_sysfs.c"
    "net/bluetooth/l2cap_core.c"
    "net/bluetooth/l2cap_sock.c"
    "net/bluetooth/smp.c"
    "net/bluetooth/lib.c"
    "net/bluetooth/ecdh_helper.c"
    "net/bluetooth/hci_request.c"
    "net/bluetooth/mgmt_util.c"
    "net/bluetooth/mgmt_config.c"
    "net/bluetooth/hci_sync.c"
    "net/bluetooth/aosp.c"
    "net/bluetooth/eir.c"
    "net/bluetooth/smp.h"
    "net/bluetooth/mgmt_util.h"
    "net/bluetooth/hci_request.h"
    "net/bluetooth/aosp.h"
    "net/bluetooth/eir.h"
    "net/bluetooth/ecdh_helper.h"
    "net/bluetooth/mgmt_config.h"
)

for file in "${BT_FILES[@]}"; do
    curl -sSfL "${RAW_BASE}/${file}" -o "$file" 2>/dev/null || true
done

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

# net/bluetooth Makefile
cat << 'EOF' > net/bluetooth/Makefile
obj-m += bluetooth.o
bluetooth-y := af_bluetooth.o hci_core.o hci_conn.o hci_event.o mgmt.o \
	hci_sock.o hci_sysfs.o l2cap_core.o l2cap_sock.o smp.o lib.o \
	ecdh_helper.o hci_request.o mgmt_util.o mgmt_config.o hci_sync.o \
	aosp.o eir.o
EOF

# drivers/bluetooth Makefile
cat << 'EOF' > drivers/bluetooth/Makefile
obj-m += hci_vhci.o
ccflags-y += -I$(src)/../../net/bluetooth
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
