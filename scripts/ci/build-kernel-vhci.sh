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
# If v6.17 or custom tag doesn't exist, fallback to master
if ! curl -sfI "${RAW_BASE}/drivers/bluetooth/hci_vhci.c" >/dev/null; then
    RAW_BASE="https://raw.githubusercontent.com/torvalds/linux/master"
fi

echo "    Downloading source files from ${RAW_BASE}..."
curl -sSfL "${RAW_BASE}/drivers/bluetooth/hci_vhci.c" -o drivers/bluetooth/hci_vhci.c || true

# Check if hci_vhci was downloaded
if [ ! -s drivers/bluetooth/hci_vhci.c ]; then
    echo "⚠️ Failed to download hci_vhci.c source. Skipping out-of-tree build."
    rm -rf "$WORK_DIR"
    exit 0
fi

# Create Kbuild Makefile for hci_vhci
cat << 'EOF' > drivers/bluetooth/Makefile
obj-m += hci_vhci.o
EOF

# Build hci_vhci
echo "    Compiling hci_vhci.ko against $BUILD_DIR..."
if make -C "$BUILD_DIR" M="$WORK_DIR/drivers/bluetooth" modules > "$WORK_DIR/build.log" 2>&1; then
    echo "    Module compiled successfully. Loading module..."
    sudo insmod "$WORK_DIR/drivers/bluetooth/hci_vhci.ko" 2>/dev/null || true
    if [ ! -c /dev/vhci ]; then sudo mknod /dev/vhci c 10 137 2>/dev/null || true; fi
    sudo chmod 666 /dev/vhci 2>/dev/null || true
    if [ -w /dev/vhci ]; then
        echo "✅ Successfully built and loaded hci_vhci module! /dev/vhci is now active."
    else
        echo "⚠️ Module loaded but /dev/vhci is not accessible."
    fi
else
    echo "⚠️ Out-of-tree build failed (often due to missing bluetooth.ko in kernel core):"
    tail -n 20 "$WORK_DIR/build.log" || true
fi

rm -rf "$WORK_DIR"
