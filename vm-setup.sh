#!/bin/bash
# TapAuth VM Setup Script
# This script sets up the VM image and cloud-init configuration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth VM Setup                                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check dependencies
echo "==> Checking dependencies..."

MISSING_DEPS=()

if ! command -v qemu-system-x86_64 &> /dev/null; then
    MISSING_DEPS+=("qemu-system-x86")
fi

if ! command -v qemu-img &> /dev/null; then
    MISSING_DEPS+=("qemu-utils")
fi

if ! command -v cloud-localds &> /dev/null; then
    MISSING_DEPS+=("cloud-image-utils")
fi

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "❌ Missing dependencies: ${MISSING_DEPS[*]}"
    echo ""
    echo "Install with:"
    echo "  sudo apt-get install qemu-system-x86 qemu-utils cloud-image-utils libvirt-daemon-system libvirt-clients bridge-utils"
    exit 1
fi

echo "✅ All dependencies installed"
echo ""

# Create VM directory
echo "==> Creating VM directory..."
mkdir -p "$VM_IMAGE_DIR"
echo "✅ VM directory: $VM_IMAGE_DIR"
echo ""

# Download Ubuntu cloud image if not exists
if [ ! -f "$UBUNTU_IMAGE_FILE" ]; then
    echo "==> Downloading Ubuntu ${UBUNTU_VERSION} cloud image..."
    echo "   This may take a few minutes..."
    wget -O "$UBUNTU_IMAGE_FILE" "$UBUNTU_IMAGE_URL"
    echo "✅ Ubuntu cloud image downloaded"
else
    echo "✅ Ubuntu cloud image already exists"
fi
echo ""

# Create VM disk from cloud image
if [ ! -f "$VM_DISK_IMAGE" ]; then
    echo "==> Creating VM disk image..."
    qemu-img create -f qcow2 -F qcow2 -b "$UBUNTU_IMAGE_FILE" "$VM_DISK_IMAGE" "$VM_DISK_SIZE"
    echo "✅ VM disk created: $VM_DISK_IMAGE"
else
    echo "⚠️  VM disk already exists: $VM_DISK_IMAGE"
    read -p "Do you want to recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f "$VM_DISK_IMAGE"
        qemu-img create -f qcow2 -F qcow2 -b "$UBUNTU_IMAGE_FILE" "$VM_DISK_IMAGE" "$VM_DISK_SIZE"
        echo "✅ VM disk recreated"
    fi
fi
echo ""

# Generate SSH key if not exists
SSH_KEY_FILE="${VM_IMAGE_DIR}/id_rsa"
if [ ! -f "$SSH_KEY_FILE" ]; then
    echo "==> Generating SSH key..."
    ssh-keygen -t rsa -b 4096 -f "$SSH_KEY_FILE" -N "" -C "tapauth-vm"
    echo "✅ SSH key generated"
else
    echo "✅ SSH key already exists"
fi
echo ""

# Create cloud-init configuration
echo "==> Creating cloud-init configuration..."

cat > "${VM_IMAGE_DIR}/user-data" << EOF
#cloud-config

# Hostname
hostname: ${VM_NAME}
fqdn: ${VM_NAME}.local

# Disable default ubuntu user, create custom user
disable_root: true
ssh_pwauth: true

# User configuration
users:
  - name: ${VM_SSH_USER}
    gecos: TapAuth Development User
    groups: [adm, audio, cdrom, dialout, dip, floppy, lxd, netdev, plugdev, sudo, video, bluetooth]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/bash
    lock_passwd: false
    passwd: $(openssl passwd -6 "$VM_SSH_PASSWORD")
    ssh_authorized_keys:
      - $(cat ${SSH_KEY_FILE}.pub)

# Network configuration - use DHCP for simplicity with user-mode networking
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: true
      dhcp6: false

# Package updates
package_update: true
package_upgrade: true

# Install required packages
packages:
  # Build tools
  - build-essential
  - pkg-config
  - cmake
  - git
  - curl
  - wget
  # Rust dependencies
  - libssl-dev
  - protobuf-compiler
  # PAM development
  - libpam0g-dev
  - pamtester
  # TPM libraries (optional)
  - libtss2-dev
  # GUI dependencies (iced + X11)
  - libx11-dev
  - libx11-xcb1
  - libx11-xcb-dev
  - libxcb1-dev
  - libxcb-render0-dev
  - libxcb-shape0-dev
  - libxcb-xfixes0-dev
  - libxkbcommon-dev
  - libxkbcommon-x11-0
  - libfontconfig1-dev
  - libfreetype-dev
  - libexpat1-dev
  - libxi6
  - libxi-dev
  - libxrandr2
  - libxrandr-dev
  - libxcursor1
  - libxcursor-dev
  - libxrender1
  - libxrender-dev
  - libxinerama1
  - libxinerama-dev
  - mesa-vulkan-drivers
  - mesa-utils
  - libgl1-mesa-dri
  - libgl1
  - libglx-mesa0
  - libegl-mesa0
  - libgbm1
  - libdrm2
  - libxext6
  # Bluetooth
  - bluez
  - bluez-tools
  - libbluetooth-dev
  - libdbus-1-dev
  - rfkill
  # Bluetooth kernel modules (required for USB Bluetooth adapters)
  # Note: Will be installed via runcmd after kernel is known
  - linux-generic
  # Network tools
  - iproute2
  - iputils-ping
  - net-tools
  - tcpdump
  - socat
  # Development tools
  - vim
  - nano
  - htop
  - strace
  - gdb
  - valgrind
  - qrencode
  # X11 utilities
  - x11-apps
  - xauth
  # NFS client for shared folders
  - nfs-common
  # 9p filesystem for virtio-9p
  - 9mount

# Run commands on first boot - using a single shell script to avoid syntax issues
runcmd:
  - |
    #!/bin/bash
    set -x
    
    # Disable network wait service (do this first)
    systemctl disable --now systemd-networkd-wait-online.service
    systemctl mask systemd-networkd-wait-online.service
    
    # Apply network configuration
    netplan apply
    
    # Wait for network to be ready
    sleep 5
    
    # Create and mount shared folder BEFORE reboot
    mkdir -p /tapauth
    mount -t 9p -o trans=virtio,version=9p2000.L,posixacl,msize=104857600,rw tapauth /tapauth || echo "Failed to mount shared folder"
    echo "tapauth /tapauth 9p trans=virtio,version=9p2000.L,posixacl,msize=104857600,rw 0 0" >> /etc/fstab
    
    # Test internet connectivity
    ping -c 3 8.8.8.8 || echo "Warning: No internet connectivity"
    
    # Install linux-modules-extra for current kernel (for Bluetooth support)
    apt-get update
    apt-get install -y linux-modules-extra-\$(uname -r)
    
    # Install Rust for the user
    sudo -u ${VM_SSH_USER} bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
    sudo -u ${VM_SSH_USER} bash -c 'echo "source \$HOME/.cargo/env" >> ~/.bashrc'
    
    # Install Rust components
    sudo -u ${VM_SSH_USER} bash -c 'source ~/.cargo/env && rustup component add clippy rustfmt'
    
    # Load Bluetooth kernel modules
    modprobe bluetooth
    modprobe btusb
    modprobe btintel
    
    # Persist Bluetooth kernel modules for reboot
    echo "bluetooth" >> /etc/modules
    echo "btusb" >> /etc/modules
    echo "btintel" >> /etc/modules
    
    # Enable and start Bluetooth
    systemctl enable bluetooth
    systemctl start bluetooth
    
    # Configure network
    echo "Network configured via cloud-init"
    
    # Create TapAuth directories
    mkdir -p /etc/tapauth
    chown ${VM_SSH_USER}:${VM_SSH_USER} /etc/tapauth
    
    # Create initialization status check script
    cat > /usr/local/bin/init-status << 'SCRIPT'
    #!/bin/bash
    # Check VM initialization status
    
    echo "=== TapAuth VM Initialization Status ==="
    echo ""
    
    STATUS=$(cloud-init status 2>/dev/null | grep "status:" | awk '{print $2}')
    
    echo "Cloud-init: $STATUS"
    
    if [ "$STATUS" = "running" ]; then
        echo ""
        echo "⏳ Initialization in progress..."
        echo "   This typically takes 5-10 minutes on first boot."
        echo ""
        echo "What's happening:"
        echo "  • Installing system packages"
        echo "  • Installing Rust toolchain"
        echo "  • Setting up Bluetooth"
        echo "  • Creating helper scripts"
        echo ""
        echo "To monitor progress:"
        echo "  tail -f /var/log/cloud-init-output.log"
        echo ""
        echo "To see detailed status:"
        echo "  cloud-init status --long"
    elif [ "$STATUS" = "done" ]; then
        echo ""
        echo "✅ Initialization complete!"
        echo ""
        echo "Checking components:"
        
        # Check helper scripts
        if [ -x /usr/local/bin/build-tapauth ]; then
            echo "  ✅ Helper scripts installed"
        else
            echo "  ❌ Helper scripts missing"
        fi
        
        # Check Rust
        if command -v rustc &> /dev/null; then
            echo "  ✅ Rust installed ($(rustc --version | cut -d' ' -f2))"
        else
            echo "  ❌ Rust not found"
        fi
        
        # Check Bluetooth
        if systemctl is-active --quiet bluetooth; then
            echo "  ✅ Bluetooth service running"
        else
            echo "  ⚠️  Bluetooth service not running"
        fi
        
        # Check shared folder
        if mountpoint -q /tapauth; then
            echo "  ✅ Shared folder mounted at /tapauth"
        else
            echo "  ❌ Shared folder not mounted"
        fi
        
        echo ""
        echo "System is ready for development!"
    else
        echo ""
        echo "❌ Initialization failed or status unknown"
        echo ""
        echo "Check detailed logs:"
        echo "  cloud-init status --long"
        echo "  cat /var/log/cloud-init.log"
        echo "  cat /var/log/cloud-init-output.log"
    fi
    SCRIPT
    chmod +x /usr/local/bin/init-status
    
    # Create helper scripts
    cat > /usr/local/bin/build-tapauth << 'SCRIPT'
    #!/bin/bash
    set -e
    export PATH="$HOME/.cargo/bin:$PATH"
    cd /tapauth
    echo "Building TapAuth components..."
    
    echo "==> Building shared library..."
    cd shared && cargo build --release
    
    echo "==> Building PAM module with BLE..."
    cd ../client-pam && cargo build --release --features ble
    
    echo "==> Building GUI..."
    cd ../client-config-gui && cargo build --release
    
    echo "==> Installing PAM module..."
    sudo cp ../client-pam/target/release/libclient_pam.so /lib/security/pam_tapauth.so
    
    echo "==> Installing GUI..."
    sudo cp ../client-config-gui/target/release/tapauth-config /usr/local/bin/
    
    echo "Build complete!"
    SCRIPT
    chmod +x /usr/local/bin/build-tapauth
    
    # Create test script
    cat > /usr/local/bin/test-tapauth << 'SCRIPT'
    #!/bin/bash
    set -e
    export PATH="$HOME/.cargo/bin:$PATH"
    cd /tapauth
    
    echo "Running TapAuth tests..."
    
    echo "==> Unit tests - shared library..."
    cd shared && cargo test --release
    
    echo "==> Unit tests - PAM module..."
    cd ../client-pam && cargo test --release --features ble
    
    echo "Tests complete!"
    SCRIPT
    chmod +x /usr/local/bin/test-tapauth
    
    # Create GUI runner script
    cat > /usr/local/bin/run-gui << 'SCRIPT'
    #!/bin/bash
    
    # Run TapAuth configuration GUI
    # Requires X11 forwarding to be set up
    
    echo "Starting TapAuth GUI..."
    echo "Make sure X11 forwarding is enabled:"
    echo "  - SSH with: ssh -X (already configured in dev-shell.sh)"
    echo ""
    
    # Check if GUI binary exists
    if [ ! -f /usr/local/bin/tapauth-config ]; then
        echo "ERROR: GUI not installed at /usr/local/bin/tapauth-config"
        echo "Run: build-tapauth"
        exit 1
    fi
    
    # Create /etc/tapauth directory if it doesn't exist
    mkdir -p /etc/tapauth
    
    # Run the GUI
    tapauth-config
    SCRIPT
    chmod +x /usr/local/bin/run-gui
    
    # Create PAM test script
    cat > /usr/local/bin/test-pam-auth << 'SCRIPT'
    #!/bin/bash
    
    # Test PAM authentication with pamtester
    # Usage: test-pam-auth [username]
    
    USERNAME="${1:-root}"
    
    echo "Testing PAM authentication for user: $USERNAME"
    echo "This will test the tapauth PAM module"
    echo ""
    
    # Check if PAM module is installed
    if [ ! -f /lib/security/pam_tapauth.so ]; then
        echo "ERROR: PAM module not installed at /lib/security/pam_tapauth.so"
        echo "Run: build-tapauth"
        exit 1
    fi
    
    # Check if PAM configuration exists
    if [ ! -f /etc/pam.d/tapauth-test ]; then
        echo "Creating test PAM configuration..."
        sudo bash -c 'cat > /etc/pam.d/tapauth-test << EOF
    auth sufficient pam_tapauth.so
    auth required pam_permit.so
    account required pam_permit.so
    EOF'
    fi
    
    echo "Starting PAM test..."
    echo "You should see BLE advertisement and UDP broadcasts in logs"
    echo "Use your paired Android device to authenticate"
    echo ""
    
    # Run pamtester with verbose output
    pamtester -v tapauth-test "$USERNAME" authenticate
    
    echo ""
    echo "PAM test completed"
    SCRIPT
    chmod +x /usr/local/bin/test-pam-auth
    
    # Create Bluetooth status script
    cat > /usr/local/bin/bluetooth-status << 'SCRIPT'
    #!/bin/bash
    
    echo "=== Bluetooth Status ==="
    echo ""
    
    # Check if bluetooth daemon is running
    if pgrep -x bluetoothd > /dev/null; then
        echo "✅ Bluetooth daemon: RUNNING"
    else
        echo "❌ Bluetooth daemon: NOT RUNNING"
    fi
    
    # Check D-Bus
    if pgrep -x dbus-daemon > /dev/null; then
        echo "✅ D-Bus: RUNNING"
    else
        echo "❌ D-Bus: NOT RUNNING"
    fi
    
    echo ""
    echo "=== Bluetooth Adapters ==="
    if command -v hciconfig &> /dev/null; then
        hciconfig -a 2>/dev/null || echo "⚠️  No adapters found or hciconfig not available"
    else
        echo "⚠️  hciconfig not available"
    fi
    
    echo ""
    echo "=== Bluetooth Controller Info ==="
    if command -v bluetoothctl &> /dev/null; then
        bluetoothctl show 2>/dev/null || echo "Cannot query Bluetooth controller"
    else
        echo "bluetoothctl not available"
    fi
    
    echo ""
    echo "=== Paired Devices ==="
    if command -v bluetoothctl &> /dev/null; then
        bluetoothctl devices 2>/dev/null || echo "Cannot list devices"
    else
        echo "bluetoothctl not available"
    fi
    
    echo ""
    echo "=== USB Bluetooth Devices ==="
    lsusb | grep -i bluetooth || echo "No Bluetooth USB devices found"
    
    echo ""
    echo "=== D-Bus Bluetooth Service ==="
    if dbus-send --system --print-reply --dest=org.bluez / org.freedesktop.DBus.Introspectable.Introspect 2>/dev/null | grep -q "interface"; then
        echo "✅ Bluetooth service accessible via D-Bus"
    else
        echo "❌ Cannot connect to Bluetooth via D-Bus"
    fi
    SCRIPT
    chmod +x /usr/local/bin/bluetooth-status
    
    # TODO: Welcome message - temporarily disabled due to YAML escaping issues
    # Will be added via write_files directive in next iteration
    echo "Welcome to TapAuth VM. Run 'init-status' to check setup." > /etc/motd
    
    echo "Cloud-init setup completed successfully"

# Set timezone
timezone: UTC

# Enable password authentication for emergency access
ssh_pwauth: true

# No reboot needed - runcmd will complete on first boot
# power_state:
#   mode: reboot
#   timeout: 300
#   condition: true
EOF

# Create meta-data (minimal)
cat > "${VM_IMAGE_DIR}/meta-data" << EOF
instance-id: ${VM_NAME}
local-hostname: ${VM_NAME}
EOF

# Create cloud-init ISO
echo "==> Creating cloud-init ISO..."
cloud-localds "$VM_CLOUD_INIT_ISO" "${VM_IMAGE_DIR}/user-data" "${VM_IMAGE_DIR}/meta-data"
echo "✅ Cloud-init ISO created"
echo ""

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         VM Setup Complete!                                    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "VM Configuration:"
echo "  Name:     $VM_NAME"
echo "  Memory:   ${VM_MEMORY}MB"
echo "  CPUs:     $VM_CPUS"
echo "  Disk:     $VM_DISK_SIZE"
echo "  SSH User: $VM_SSH_USER"
echo "  SSH Pass: $VM_SSH_PASSWORD (change on first login)"
echo ""
echo "Next steps:"
echo "  1. Start VM:  ./vm-start.sh"
echo "  2. Wait for VM to boot and install packages (first boot takes 5-10 minutes)"
echo "  3. Connect:   ./vm-shell.sh"
echo ""
