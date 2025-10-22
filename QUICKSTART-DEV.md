# 🚀 TapAuth Development Quick Start

**⚠️ The development environment now uses VMs instead of Docker for better network broadcast and Bluetooth support.**

Get up and running with TapAuth development in 10 minutes!

---

## Prerequisites Check

```bash
# Check if you have QEMU/KVM
qemu-system-x86_64 --version
# ✅ Should show: QEMU emulator version 6.0+

# Check KVM support
egrep -c '(vmx|svm)' /proc/cpuinfo
# ✅ Should show: > 0 (number of CPU cores)

# Check if you have X11
echo $DISPLAY
# ✅ Should show: :0 or :1

# Check your user is in kvm group
groups
# ✅ Should include: kvm libvirt
```

If any of these fail, install prerequisites:

### Ubuntu/Debian

```bash
# Install QEMU/KVM and tools
sudo apt-get install qemu-system-x86 qemu-utils cloud-image-utils \
    libvirt-daemon-system libvirt-clients bridge-utils socat \
    x11-xserver-utils

# Add yourself to required groups
sudo usermod -a -G kvm,libvirt $USER

# Log out and back in for group changes to take effect
```

### Fedora 42

```bash
# Install QEMU/KVM and tools
sudo dnf install qemu-system-x86 qemu-img libvirt libvirt-daemon \
    libvirt-client bridge-utils socat xhost cloud-utils

# Add yourself to required groups
sudo usermod -a -G kvm,libvirt $USER

# Log out and back in for group changes to take effect
```

---

## 1️⃣ Setup VM (First Time Only)

```bash
cd /home/luca/source/repos/tapauth

# Create the VM (downloads Ubuntu cloud image, ~5 minutes)
./vm-setup.sh
```

**What this does:**
- ✅ Downloads Ubuntu 24.04 cloud image (~700MB)
- ✅ Creates VM disk image (20GB)
- ✅ Generates SSH keys
- ✅ Creates cloud-init configuration

---

## 2️⃣ Start Development Environment (First Time)

```bash
# Start the VM
# ⏱️ First boot: ~10 minutes (installs packages)
./vm-start.sh
```

**What this does:**
- ✅ Starts QEMU/KVM VM
- ✅ Sets up network bridge
- ✅ Passes through Bluetooth USB device
- ✅ Mounts shared folder
- ✅ Installs all dependencies (first boot only)

**Watch the QEMU window** to see installation progress.

---

## 3️⃣ Enter the Development Environment

```bash
./vm-shell.sh
```

You're now inside the VM! 🎉

---

## 3️⃣ Pair Your Android Device

Inside the container:

```bash
run-gui
```

**Steps:**
1. GUI window opens (thanks to X11 forwarding)
2. Click "Pair New Device"
3. QR code appears
4. Open TapAuth on your Android phone (debug build)
5. Scan the QR code
6. Verify SAS matches on both devices
7. Confirm pairing
8. Done! 🎊

---

## 4️⃣ Test Authentication

Still inside the container:

```bash
test-pam-auth root
```

**What happens:**
1. PAM module starts
2. BLE advertisement begins
3. UDP broadcasts sent
4. Waits for your Android device...
5. Approve authentication on your phone
6. Authentication succeeds! ✅

---

## 5️⃣ Stop When Done

```bash
# Exit the VM
exit

# Stop the environment (on host)
./vm-stop.sh
```

---

## 🔄 Daily Development Workflow

### Start Environment
```bash
./vm-start.sh  # Start VM (auto-setup if needed)
./vm-shell.sh  # Enter VM
```

### Make Changes
- Edit code on your host (use your favorite IDE)
- Files are automatically synced to VM

### Build & Test
```bash
# Option 1: Use helper scripts from host
./vm-build.sh       # Rebuild everything
./vm-test.sh        # Run all tests

# Option 2: Run commands inside VM
build-tapauth       # Rebuild everything
test-tapauth        # Run unit tests
test-pam-auth root  # Test authentication
```

### Stop Environment
```bash
exit            # Exit VM
./vm-stop.sh    # Stop VM
```

---

## 📱 Android Development

### Build Debug Version

```bash
# On host
cd server-android
./build-native.sh  # Build Rust native libraries

# Open in Android Studio
# Select "debug" build variant
# Click Run
```

**Result:** Debug app installs alongside any release builds!
- Debug: `dev.rourunisen.tapauth.debug` (TapAuth Debug)
- Release: `dev.rourunisen.tapauth` (TapAuth)

---

## 🐛 Quick Troubleshooting

### GUI doesn't appear?
```bash
# On host
xhost +local:docker
```

### Bluetooth not working?
```bash
# Inside container
bluetooth-status

# On host (if needed)
sudo systemctl restart bluetooth
```

### Authentication times out?
```bash
# Check Android app is running
# Check both devices on same network
# Enable debug logging:
export RUST_LOG=debug
test-pam-auth root
```

---

## 📚 Learn More

- **Full Guide**: `DEVELOPMENT.md` - Complete documentation
- **Architecture**: `docs/` - Design documents

---

## 🎯 Common Tasks

### View Logs
```bash
# PAM authentication logs
journalctl -f | grep pam

# Network traffic
tcpdump -i any port 36692

# Bluetooth
btmon
```

### Run Tests
```bash
./vm-test.sh   # On host
# OR
test-tapauth   # Inside VM
```

### Rebuild After Changes
```bash
./vm-build.sh  # On host
# OR
build-tapauth  # Inside VM
```

### Check Status
```bash
# Inside VM
bluetooth-status              # Bluetooth
netstat -uln | grep 36692     # Network
ls -la /etc/tapauth/          # Config files
```

---

## ✅ You're Ready!

You now have:
- ✅ Complete VM development environment
- ✅ PAM authentication module
- ✅ GUI client (tapauth-config)
- ✅ Android app support
- ✅ Testing tools
- ✅ Network and Bluetooth access

**Happy hacking!** 🚀
