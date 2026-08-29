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

# Ensure build essentials and kernel headers are installed
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential "linux-headers-$(uname -r)" linux-headers-azure git

BUILD_DIR="/lib/modules/$(uname -r)/build"
if [ ! -d "$BUILD_DIR" ]; then
    echo "❌ ERROR: Kernel build headers directory not found at $BUILD_DIR."
    exit 1
fi

WORK_DIR=$(mktemp -d /tmp/bt-vhci-build.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "    Cloning Bluetooth subsystem for Linux v6.11..."
if ! git clone --depth 1 --branch "v6.11" --filter=blob:none --no-checkout https://github.com/torvalds/linux.git "$WORK_DIR" 2>/dev/null; then
    echo "    v6.11 not available, cloning v6.12..."
    git clone --depth 1 --branch "v6.12" --filter=blob:none --no-checkout https://github.com/torvalds/linux.git "$WORK_DIR"
fi

cd "$WORK_DIR"
git sparse-checkout set net/bluetooth drivers/bluetooth/hci_vhci.c drivers/bluetooth/Makefile include/net/bluetooth
git checkout

# Remove root Linux Makefile so Kbuild treats this purely as an out-of-tree module
rm -f Makefile

# Compatibility: redirect deprecated <asm/unaligned.h> to <linux/unaligned.h> if needed
find . -type f \( -name "*.c" -o -name "*.h" \) -exec sed -i 's|<asm/unaligned.h>|<linux/unaligned.h>|g' {} + 2>/dev/null || true

# Top-level Kbuild
cat << 'EOF' > Kbuild
obj-m += net/bluetooth/
obj-m += drivers/bluetooth/
EOF

# net/bluetooth Makefile (force obj-m instead of CONFIG_BT conditional)
cat << 'EOF' > net/bluetooth/Makefile
obj-m += bluetooth.o
bluetooth-y := af_bluetooth.o hci_core.o hci_conn.o hci_event.o mgmt.o \
	hci_sock.o hci_sysfs.o l2cap_core.o l2cap_sock.o smp.o lib.o \
	ecdh_helper.o hci_request.o mgmt_util.o mgmt_config.o hci_sync.o \
	eir.o leds.o
ccflags-y += -I$(src)/../include -I$(src)/../../include -Wno-error -Wno-implicit-function-declaration -Wno-incompatible-pointer-types -Wno-int-conversion -DCONFIG_BT -DCONFIG_BT_BREDR -DCONFIG_BT_LE -DCONFIG_BT_LEDS
EXTRA_CFLAGS += -I$(src)/../include -I$(src)/../../include -Wno-error -Wno-implicit-function-declaration -Wno-incompatible-pointer-types -Wno-int-conversion -DCONFIG_BT -DCONFIG_BT_BREDR -DCONFIG_BT_LE -DCONFIG_BT_LEDS
EOF

# Ensure drivers/bluetooth Makefile builds hci_vhci.o with proper flags
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
