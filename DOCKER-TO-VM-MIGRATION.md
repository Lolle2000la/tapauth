# Migration from Docker to VM

The TapAuth development environment has been migrated from Docker to QEMU/KVM virtual machines for better network broadcast support and exclusive Bluetooth access.

## Why the Change?

### Problems with Docker

1. **Network Broadcasts**: Docker's networking (even with `network_mode: host`) has limitations with UDP broadcasts and multicast
2. **Bluetooth Access**: Docker containers can't get exclusive access to USB Bluetooth adapters
3. **Kernel Features**: Some features like raw network sockets have limitations in containers

### Benefits of VM

1. **Full Network Stack**: VM has its own network interface with full broadcast/multicast support
2. **Exclusive USB Access**: VM gets complete control of the Bluetooth adapter via USB passthrough
3. **Better Testing**: More realistic environment that matches actual deployment
4. **Isolation**: Complete kernel isolation for security testing

## What Changed?

### User-Facing Changes

**None!** The same scripts work the same way:

```bash
./dev-start.sh   # Starts VM instead of Docker
./dev-shell.sh   # SSH instead of docker exec
./dev-stop.sh    # Stops VM instead of Docker
./dev-rebuild.sh # Builds via SSH
./dev-test.sh    # Tests via SSH
```

### Under the Hood

| Aspect | Docker (Old) | VM (New) |
|--------|-------------|----------|
| Technology | Docker + docker-compose | QEMU/KVM |
| Base Image | Ubuntu 24.04 container | Ubuntu 24.04 cloud image |
| Network | Host networking | Bridge + TAP + NAT |
| Bluetooth | Shared D-Bus access | USB passthrough |
| Shared Code | Docker volume | virtio-9p filesystem |
| Access | `docker exec` | SSH with key |
| Boot Time | ~2 seconds | ~30 seconds (+ 5-10 min first boot) |
| Resources | ~500MB RAM | ~4GB RAM (configurable) |

## Migration Steps

### 1. Stop Old Docker Environment

If you have the Docker environment running:

```bash
# Using old docker-compose method
docker-compose -f docker-compose.dev.yml down

# Remove volumes (optional, frees up space)
docker-compose -f docker-compose.dev.yml down -v
```

### 2. Install VM Prerequisites

```bash
sudo apt-get install qemu-system-x86 qemu-utils cloud-image-utils \
    libvirt-daemon-system libvirt-clients bridge-utils socat
```

Add your user to the required groups:

```bash
sudo usermod -a -G kvm,libvirt $USER
```

**Important**: Log out and log back in for group changes to take effect!

### 3. Run VM Setup

```bash
./vm-setup.sh
```

This downloads Ubuntu cloud image and creates the VM disk. Only needed once.

### 4. Start the VM

```bash
./dev-start.sh
```

**First boot takes 5-10 minutes** to install all packages. Watch the QEMU window.

### 5. Connect and Build

```bash
./dev-shell.sh
# Inside VM:
build-tapauth
```

### 6. Done!

Your development environment is now VM-based. Use the same commands as before.

## File Changes

### Kept (Still Used)

These Docker files are kept for reference but not used:

- `Dockerfile.dev` - Now replaced by cloud-init
- `docker-compose.dev.yml` - Now replaced by QEMU
- `bluetooth-power-on.sh` - Functionality moved to vm-start.sh

You can delete these if you want, but they're kept for documentation purposes.

### New Files

VM-specific files:

- `vm-config.sh` - VM configuration (edit this to customize)
- `vm-setup.sh` - Initial VM creation (run once)
- `vm-start.sh` - Start the VM (called by dev-start.sh)
- `vm-shell.sh` - SSH into VM (called by dev-shell.sh)
- `vm-stop.sh` - Stop the VM (called by dev-stop.sh)
- `VM-DEVELOPMENT.md` - Complete VM documentation

### Modified Files

These now use VMs instead of Docker:

- `dev-start.sh` - Calls vm-start.sh
- `dev-shell.sh` - Calls vm-shell.sh
- `dev-stop.sh` - Calls vm-stop.sh
- `dev-rebuild.sh` - Uses SSH instead of docker exec
- `dev-test.sh` - Uses SSH instead of docker exec

## Configuration Changes

### Before (Docker)

Edit `docker-compose.dev.yml`:

```yaml
services:
  tapauth-dev:
    environment:
      - DISPLAY=${DISPLAY}
    volumes:
      - ./:/tapauth:rw
```

### Now (VM)

Edit `vm-config.sh`:

```bash
VM_MEMORY="4096"     # RAM in MB
VM_CPUS="4"          # Number of cores
VM_DISK_SIZE="20G"   # Disk size
VM_GUEST_IP="192.168.100.10"
```

## Troubleshooting Migration

### "KVM not found"

Enable KVM support:

```bash
sudo modprobe kvm kvm_intel  # Or kvm_amd for AMD
sudo usermod -a -G kvm $USER
# Log out and back in
```

### "Permission denied" when starting VM

Add yourself to kvm and libvirt groups:

```bash
sudo usermod -a -G kvm,libvirt $USER
# Log out and back in
```

Check it worked:

```bash
groups
# Should show: ... kvm libvirt ...
```

### VM is slow

Increase resources in `vm-config.sh`:

```bash
VM_MEMORY="8192"  # 8GB
VM_CPUS="8"       # 8 cores
```

### Bluetooth not working

Check the Bluetooth device is detected:

```bash
lsusb | grep -i bluetooth
```

If it's not auto-detected, manually set it in `vm-config.sh`:

```bash
BT_USB_DEVICE="8087:0a2a"  # Your device ID from lsusb
```

### Can't connect to VM

First boot takes time. Wait 5-10 minutes and watch the QEMU window.

Check if VM is running:

```bash
ps aux | grep qemu
```

Try pinging:

```bash
ping 192.168.100.10
```

### Network broadcasts not working

This should work out of the box. To test:

```bash
# From host:
sudo tcpdump -i tapauth-br0 broadcast

# From VM (in another terminal):
./dev-shell.sh
echo "test" | socat - UDP4-DATAGRAM:192.168.100.255:36692,broadcast
```

You should see the broadcast packet.

## Performance Comparison

### Resource Usage

| Resource | Docker | VM |
|----------|--------|-----|
| RAM (idle) | ~500MB | ~1GB |
| RAM (building) | ~2GB | ~3GB |
| Disk | ~2GB | ~5GB |
| CPU (idle) | <1% | <5% |

### Speed

| Operation | Docker | VM |
|-----------|--------|-----|
| Start | 2s | 30s |
| First boot | 30s | 5-10min |
| Rebuild | Same | Same |
| Tests | Same | Same |

The VM is slightly slower to start but provides much better functionality for testing network broadcasts and Bluetooth.

## Rollback (If Needed)

If you need to go back to Docker:

### 1. Stop the VM

```bash
./dev-stop.sh
```

### 2. Restore Old Scripts

```bash
git checkout HEAD -- dev-start.sh dev-shell.sh dev-stop.sh dev-rebuild.sh dev-test.sh
```

### 3. Start Docker

```bash
./dev-start.sh  # Will use old Docker method
```

## FAQ

### Q: Can I use both Docker and VM?

A: Not recommended. They use the same script names. Choose one.

### Q: Why not use libvirt/virt-manager?

A: QEMU directly gives us more control for USB passthrough and custom networking. You can import the VM into virt-manager if you prefer.

### Q: Can I use Podman instead of moving to VMs?

A: Podman has the same network and USB limitations as Docker.

### Q: Will this work on macOS/Windows?

A: No, this requires Linux with KVM. For macOS/Windows, consider using the Docker setup or a Linux VM with nested virtualization.

### Q: How do I backup my VM?

Backup these files:

```bash
~/.tapauth-vm/tapauth-dev.qcow2  # VM disk
~/.tapauth-vm/id_rsa              # SSH key
```

To restore, copy them back and run `./dev-start.sh`.

### Q: Can I run multiple VMs?

Yes, but you'll need to:
1. Edit `vm-config.sh` to use different names, IPs, and bridges
2. Create a separate copy of the scripts
3. Ensure you have enough resources

## Getting Help

1. **Check VM console**: The QEMU window shows boot messages and errors
2. **Check cloud-init logs**: Inside VM: `sudo cat /var/log/cloud-init.log`
3. **Check network**: `ip addr show tapauth-br0` on host
4. **Check Bluetooth**: `lsusb | grep -i bluetooth` on host
5. **Read full docs**: See `VM-DEVELOPMENT.md`

## Summary

The migration to VMs provides:
- ✅ Full network broadcast support (critical for TapAuth)
- ✅ Exclusive Bluetooth access (better testing)
- ✅ Same workflow (dev-start.sh, dev-shell.sh, etc.)
- ✅ Better isolation and realism

The trade-off is slightly slower startup and more RAM usage, but the benefits for testing network features are worth it.
