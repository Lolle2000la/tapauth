# TapAuth VM Development Environment

This development environment uses a QEMU/KVM virtual machine instead of Docker to provide:

✅ **Full network broadcast support** - VM has its own network interface on a bridge
✅ **Exclusive Bluetooth access** - USB passthrough gives the VM complete control of the Bluetooth adapter
✅ **Better isolation** - True virtualization for realistic testing
✅ **X11 forwarding** - GUI applications work seamlessly

## Prerequisites

### Required Packages

```bash
sudo apt-get install qemu-system-x86 qemu-utils cloud-image-utils \
    libvirt-daemon-system libvirt-clients bridge-utils \
    x11-xserver-utils socat
```

### Hardware Requirements

- **CPU**: x86_64 with KVM support (Intel VT-x or AMD-V)
  - Check: `egrep -c '(vmx|svm)' /proc/cpuinfo` (should be > 0)
  - Enable KVM: `sudo modprobe kvm && sudo modprobe kvm_intel` (or `kvm_amd`)
- **RAM**: At least 6GB (4GB for VM + 2GB for host)
- **Disk**: At least 25GB free space
- **Bluetooth**: USB Bluetooth adapter (for BLE testing)

### User Permissions

Add your user to required groups:

```bash
sudo usermod -a -G kvm,libvirt $USER
# Log out and log back in for changes to take effect
```

## Quick Start

> **📖 Important:** First boot takes 5-10 minutes while the VM initializes. See [VM Initialization Guide](VM-INITIALIZATION-GUIDE.md) for details on checking progress and understanding what's happening.

### 1. Initial Setup

```bash
cd /home/luca/source/repos/tapauth

# Run initial VM setup (downloads Ubuntu cloud image, creates VM disk)
# This only needs to be done once
./vm-setup.sh
```

This will:
- Download Ubuntu 24.04 cloud image (~700MB)
- Create a VM disk image (20GB, sparse allocation)
- Generate cloud-init configuration
- Create SSH keys for access

### 2. Start the VM

```bash
./dev-start.sh
```

**First boot takes 5-10 minutes** as it:
- Installs all development packages
- Installs Rust and toolchain
- Sets up Bluetooth services
- Mounts the shared folder
- Reboots after setup

Watch the QEMU window for progress.

### 3. Connect to the VM

```bash
./dev-shell.sh
```

This opens an SSH session with X11 forwarding enabled.

### 4. Build TapAuth

Inside the VM:

```bash
build-tapauth
```

Or from the host:

```bash
./dev-rebuild.sh
```

### 5. Test

Inside the VM:

```bash
# Run unit tests
test-tapauth

# Test PAM authentication
test-pam-auth root
```

Or from the host:

```bash
./dev-test.sh
```

## VM Architecture

### Network Configuration

The VM uses a **bridge network** for full broadcast support:

```
Host Machine (192.168.100.1/24)
    ↓ [tapauth-br0 bridge]
    ↓
    ↓ [tapauth-tap0 TAP device]
    ↓
VM (192.168.100.10/24)
```

- **Bridge**: `tapauth-br0` on host at `192.168.100.1`
- **VM IP**: `192.168.100.10`
- **NAT**: Host forwards traffic to internet via iptables
- **Broadcasts**: Work on the `192.168.100.0/24` subnet

The VM can send and receive UDP broadcasts on this subnet, which is perfect for testing the TapAuth discovery protocol.

### Bluetooth USB Passthrough

The VM gets exclusive access to the Bluetooth adapter via USB passthrough:

1. Host Bluetooth service is stopped
2. USB device is passed to QEMU with `-device usb-host,vendorid=...,productid=...`
3. VM sees the Bluetooth adapter as if it were directly connected
4. VM runs its own `bluetoothd` service

Auto-detection finds your Bluetooth adapter automatically. You can also manually configure it in `vm-config.sh`:

```bash
# Set to your device's vendor:product ID (from lsusb)
BT_USB_DEVICE="8087:0a2a"  # Example: Intel Bluetooth
```

### Shared Folder

The project directory is shared with the VM using **virtio-9p**:

- **Host path**: `/home/luca/source/repos/tapauth`
- **VM mount point**: `/tapauth`
- **Auto-mounted** via `/etc/fstab` in the VM

Any changes you make on the host are immediately visible in the VM and vice versa.

## Configuration

Edit `vm-config.sh` to customize:

```bash
# VM Resources
VM_MEMORY="4096"      # MB of RAM
VM_CPUS="4"           # Number of CPU cores
VM_DISK_SIZE="20G"    # Disk size

# Network
VM_BRIDGE="tapauth-br0"
VM_HOST_IP="192.168.100.1"
VM_GUEST_IP="192.168.100.10"

# SSH
VM_SSH_USER="tapauth"
VM_SSH_PASSWORD="tapauth"  # Change on first login

# Bluetooth
BT_USB_DEVICE=""  # Auto-detect if empty
```

## Common Tasks

### Access the VM GUI

The VM window opens automatically when you start it. You can also use X11 forwarding over SSH:

```bash
./dev-shell.sh
# Inside VM:
tapauth-config  # Launches the GUI
```

### Monitor Network Traffic

From the host:

```bash
# Capture all traffic on the bridge
sudo tcpdump -i tapauth-br0

# Capture only UDP port 36692 (TapAuth)
sudo tcpdump -i tapauth-br0 udp port 36692

# Capture broadcasts
sudo tcpdump -i tapauth-br0 broadcast
```

From the VM:

```bash
./dev-shell.sh
# Inside VM:
sudo tcpdump -i ens3 udp port 36692
```

### Check Bluetooth Status

Inside the VM:

```bash
# Check Bluetooth service
systemctl status bluetooth

# Check adapter
hciconfig -a

# Scan for devices
bluetoothctl scan on
```

### Rebuild the VM

If the VM becomes corrupted or you want to start fresh:

```bash
./dev-stop.sh
# Choose "yes" to delete the VM disk

# Then run setup again
./vm-setup.sh
```

### SSH Without Scripts

```bash
ssh -i ~/.tapauth-vm/id_rsa -X tapauth@192.168.100.10
```

## Troubleshooting

### VM Won't Start

1. **Check KVM support**:
   ```bash
   lsmod | grep kvm
   # Should show kvm and kvm_intel (or kvm_amd)
   ```

2. **Check permissions**:
   ```bash
   groups
   # Should include: kvm, libvirt
   ```

3. **Check if another VM is running**:
   ```bash
   ps aux | grep qemu
   ```

### Can't Connect via SSH

1. **Wait for first boot**: Initial setup takes 5-10 minutes
2. **Check VM is running**: `ps aux | grep qemu`
3. **Check network**:
   ```bash
   ping 192.168.100.10
   ip addr show tapauth-br0
   ```
4. **Check VM console**: Look at the QEMU window for errors

### Bluetooth Not Working

1. **Check host Bluetooth is stopped**:
   ```bash
   systemctl status bluetooth
   # Should be inactive
   ```

2. **Check USB device**:
   ```bash
   lsusb | grep -i bluetooth
   # Note the device ID
   ```

3. **Manually set device** in `vm-config.sh`:
   ```bash
   BT_USB_DEVICE="8087:0a2a"  # Your device ID
   ```

4. **Restart VM**:
   ```bash
   ./dev-stop.sh
   ./dev-start.sh
   ```

### Network Broadcasts Not Working

1. **Check bridge exists**:
   ```bash
   ip addr show tapauth-br0
   ```

2. **Check iptables rules**:
   ```bash
   sudo iptables -t nat -L -n -v
   ```

3. **Test ping from VM to host**:
   ```bash
   # In VM:
   ping 192.168.100.1
   ```

4. **Test broadcast**:
   ```bash
   # From host:
   sudo tcpdump -i tapauth-br0 broadcast

   # From VM:
   echo "test" | socat - UDP4-DATAGRAM:192.168.100.255:36692,broadcast
   ```

### Shared Folder Not Mounted

Inside the VM:

```bash
# Check if mounted
mount | grep tapauth

# Try manual mount
sudo mount -t 9p -o trans=virtio,version=9p2000.L tapauth /tapauth

# Check cloud-init logs
sudo cat /var/log/cloud-init.log | grep -i error
```

### Performance Issues

1. **Increase VM resources** in `vm-config.sh`:
   ```bash
   VM_MEMORY="8192"  # 8GB RAM
   VM_CPUS="8"       # More cores
   ```

2. **Enable CPU pinning** (advanced):
   Edit `vm-start.sh` and add to QEMU_CMD:
   ```bash
   -cpu host,kvm=on
   ```

3. **Use hugepages** for better memory performance (advanced)

## Comparison: VM vs Docker

| Feature | VM (Current) | Docker (Old) |
|---------|-------------|--------------|
| Network broadcasts | ✅ Full support | ⚠️ Limited (host network) |
| Bluetooth USB | ✅ Exclusive access | ⚠️ Shared access |
| Isolation | ✅ Complete | ⚠️ Namespace only |
| Resource usage | ⚠️ Higher | ✅ Lower |
| Boot time | ⚠️ Slower | ✅ Fast |
| Realism | ✅ True hardware | ⚠️ Containerized |
| PAM testing | ✅ Native | ✅ Works |

## Advanced: Manual VM Control

### Using QEMU Monitor

```bash
# Connect to monitor socket
socat - UNIX-CONNECT:~/.tapauth-vm/tapauth-dev.monitor

# Commands:
info status          # VM status
info network         # Network devices
info usb             # USB devices
system_powerdown     # Graceful shutdown
quit                 # Force quit
```

### Custom QEMU Options

Edit `vm-start.sh` and modify the `QEMU_CMD` array to add custom options.

## Files and Directories

- `vm-config.sh` - Configuration variables
- `vm-setup.sh` - Initial VM creation script
- `vm-start.sh` - Start the VM (called by dev-start.sh)
- `vm-shell.sh` - SSH into the VM (called by dev-shell.sh)
- `vm-stop.sh` - Stop the VM (called by dev-stop.sh)
- `~/.tapauth-vm/` - VM data directory
  - `tapauth-dev.qcow2` - VM disk image
  - `tapauth-dev-cloud-init.iso` - Cloud-init configuration
  - `id_rsa` - SSH private key
  - `tapauth-dev.pid` - VM process ID
  - `tapauth-dev.monitor` - QEMU monitor socket

## Migration from Docker

If you were using the Docker-based environment:

1. Stop the Docker container:
   ```bash
   # Using old method:
   docker-compose -f docker-compose.dev.yml down -v
   ```

2. The new VM scripts use the same commands:
   - `./dev-start.sh` - Now starts a VM instead of Docker
   - `./dev-shell.sh` - Now uses SSH instead of docker exec
   - `./dev-stop.sh` - Now stops the VM instead of Docker
   - `./dev-rebuild.sh` - Now runs build via SSH
   - `./dev-test.sh` - Now runs tests via SSH

3. Your workflow remains the same!

## Support

For issues specific to the VM environment, check:
- QEMU window for console output
- `/var/log/cloud-init.log` in the VM
- `dmesg` in the VM for kernel messages
- Host system logs: `journalctl -xe`
