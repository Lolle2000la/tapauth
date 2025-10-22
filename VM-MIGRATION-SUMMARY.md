# TapAuth VM Development Environment - Summary

## What Was Done

The TapAuth development environment has been completely migrated from Docker containers to QEMU/KVM virtual machines to address critical limitations with network broadcasts and Bluetooth access.

## Why This Change Was Necessary

### Problems with Docker

1. **Network Broadcasts**: Docker containers, even with `network_mode: host`, have limitations with UDP broadcasts and IPv6 multicast. The TapAuth protocol relies heavily on UDP broadcasts for device discovery (UDP port 36692 to multicast address ff02::1).

2. **Bluetooth Access**: Docker containers cannot get exclusive access to USB Bluetooth devices. They share the host's Bluetooth D-Bus service, which causes conflicts and unreliable BLE GATT advertising.

3. **Testing Realism**: Containers provide namespace isolation but share the kernel with the host, making it difficult to test kernel-level features and network behavior accurately.

### Benefits of VM Approach

1. **Full Network Stack**: The VM has its own network interface on a bridge (`tapauth-br0`), allowing it to send and receive broadcasts on its own subnet (192.168.100.0/24).

2. **Exclusive USB Access**: USB passthrough gives the VM complete control of the Bluetooth adapter. The host Bluetooth service is stopped, and the device is passed to QEMU.

3. **Better Isolation**: Complete kernel isolation provides a realistic testing environment that matches actual deployment scenarios.

## Files Created

### Core VM Scripts

1. **`vm-config.sh`** - Configuration file with all VM settings
   - VM resources (RAM, CPU, disk)
   - Network configuration (bridge, IPs)
   - Bluetooth device settings
   - SSH credentials

2. **`vm-setup.sh`** - Initial VM creation script
   - Downloads Ubuntu 24.04 cloud image
   - Creates VM disk (qcow2 format, 20GB)
   - Generates cloud-init configuration
   - Creates SSH keys for access
   - Installs all development dependencies via cloud-init

3. **`vm-start.sh`** - VM startup script
   - Detects and passes through Bluetooth USB device
   - Creates network bridge (`tapauth-br0`) and TAP device
   - Sets up NAT for internet access
   - Configures iptables for forwarding
   - Starts QEMU with appropriate flags
   - Shares project directory via virtio-9p filesystem

4. **`vm-shell.sh`** - SSH connection script
   - Connects to VM via SSH with key authentication
   - Enables X11 forwarding for GUI apps
   - Waits for SSH to be available on first boot

5. **`vm-stop.sh`** - VM shutdown script
   - Graceful shutdown via SSH
   - Falls back to QEMU monitor ACPI shutdown
   - Cleans up network devices (TAP, bridge)
   - Restores host Bluetooth service
   - Optional: Delete VM disk for fresh start

### Documentation

6. **`VM-DEVELOPMENT.md`** - Complete VM environment guide
   - Architecture explanation
   - Network topology diagram
   - Bluetooth USB passthrough details
   - Configuration options
   - Troubleshooting guide
   - Performance tuning
   - Advanced QEMU options

7. **`DOCKER-TO-VM-MIGRATION.md`** - Migration guide
   - Why we migrated
   - Step-by-step migration instructions
   - Comparison table (Docker vs VM)
   - Rollback instructions
   - FAQ

8. **`DEV-SCRIPTS-README.sh`** - Quick reference
   - Overview of all scripts
   - Quick start commands
   - Network/Bluetooth info

## Files Modified

### Development Scripts (Now Use VMs)

1. **`dev-start.sh`** - Now calls `vm-start.sh` instead of Docker Compose
2. **`dev-shell.sh`** - Now calls `vm-shell.sh` instead of `docker exec`
3. **`dev-stop.sh`** - Now calls `vm-stop.sh` instead of `docker-compose down`
4. **`dev-rebuild.sh`** - Now uses SSH to run build instead of `docker exec`
5. **`dev-test.sh`** - Now uses SSH to run tests instead of `docker exec`

### Documentation Updates

6. **`DEVELOPMENT.md`** - Updated to point to VM documentation
7. **`QUICKSTART-DEV.md`** - Updated with VM prerequisites and steps

## Files Kept (For Reference)

These Docker files are no longer used but kept for reference:

- `Dockerfile.dev` - Container build configuration (replaced by cloud-init)
- `docker-compose.dev.yml` - Docker Compose config (replaced by QEMU)
- `bluetooth-power-on.sh` - Helper script (functionality in vm-start.sh)

## Technical Architecture

### Network Setup

```
┌─────────────────────────────────────────────────┐
│ Host Machine (192.168.100.1/24)                 │
│                                                  │
│  ┌────────────────────────────────┐             │
│  │ tapauth-br0 (Bridge)           │             │
│  │ IP: 192.168.100.1              │             │
│  └───────────┬────────────────────┘             │
│              │                                   │
│  ┌───────────▼────────────────────┐             │
│  │ tapauth-tap0 (TAP Device)      │             │
│  └───────────┬────────────────────┘             │
│              │                                   │
│              │ virtio-net                        │
│              │                                   │
│  ┌───────────▼────────────────────────────────┐ │
│  │ QEMU/KVM VM                                │ │
│  │                                            │ │
│  │ ┌────────────────────────────────┐        │ │
│  │ │ Ubuntu 24.04                   │        │ │
│  │ │ IP: 192.168.100.10/24          │        │ │
│  │ │ Gateway: 192.168.100.1         │        │ │
│  │ │                                │        │ │
│  │ │ ens3 interface                 │        │ │
│  │ └────────────────────────────────┘        │ │
│  │                                            │ │
│  │ Shared Folder: /tapauth (virtio-9p)       │ │
│  │ Bluetooth: USB passthrough                │ │
│  └────────────────────────────────────────────┘ │
│                                                  │
│  iptables NAT: VM → Internet                    │
└─────────────────────────────────────────────────┘
```

### Bluetooth USB Passthrough

```
Host                          QEMU                VM
────                          ────                ──
USB Controller                                   
  │                                              
  ├─ Bluetooth Adapter                           
  │   (e.g., 8087:0a2a)                          
  │                                              
  │  Stop bluetoothd                             
  │                                              
  │  Pass via QEMU args:                         
  │  -device usb-host,                           
  │   vendorid=0x8087,                           
  │   productid=0x0a2a                           
  │                           │                  
  └───────────────────────────┼─────────────────►│
                              │                  │
                              └──────────────────┤
                                                 │
                                         USB Controller
                                                 │
                                         Bluetooth Adapter
                                                 │
                                         bluetoothd service
                                                 │
                                         BLE GATT advertising
```

### Shared Folder (virtio-9p)

```
Host                                    VM
────                                    ──
/home/luca/source/repos/tapauth        
│                                      
├─ Shared via QEMU:                    
│  -virtfs local,                      
│   path=/path/to/tapauth,             
│   mount_tag=tapauth,                 
│   security_model=passthrough         
│                                      
└──────────────────────────────────────►│
                                        │
                                  Auto-mounted via fstab:
                                  tapauth /tapauth 9p ...
                                        │
                                  /tapauth/
                                   ├─ client-pam/
                                   ├─ client-config-gui/
                                   ├─ shared/
                                   └─ ...
```

## User Workflow (Unchanged)

Despite the backend change from Docker to VMs, the user workflow remains identical:

```bash
# 1. Start environment
./dev-start.sh

# 2. Enter environment
./dev-shell.sh

# 3. Build
build-tapauth

# 4. Test
test-tapauth
test-pam-auth root

# 5. Stop
./dev-stop.sh
```

## Key Features

### Network Broadcasts ✅

The VM can now properly:
- Send UDP broadcasts to 255.255.255.255
- Send IPv6 multicast to ff02::1
- Receive broadcast responses
- Test the full TapAuth discovery protocol

### Bluetooth Control ✅

The VM has exclusive access to:
- Bluetooth USB adapter
- Complete BlueZ stack
- BLE GATT advertising
- Pairing and device management

### Development Features ✅

- **Live code editing**: Changes on host immediately visible in VM via shared folder
- **X11 forwarding**: GUI applications work over SSH
- **Build caching**: Cargo cache preserved between sessions
- **Isolated testing**: Each VM is independent
- **Reproducible**: Cloud-init ensures consistent setup

## Performance Characteristics

### Resource Usage

| Resource | Idle | Building |
|----------|------|----------|
| RAM | ~1GB | ~3GB |
| CPU | <5% | 100% (during builds) |
| Disk | ~5GB | ~8GB (with build cache) |

### Timing

| Operation | Duration |
|-----------|----------|
| VM Setup (first time) | ~5 minutes (download + create) |
| First Boot | ~10 minutes (package installation) |
| Subsequent Boots | ~30 seconds |
| SSH Connection | ~2 seconds |
| Full Rebuild | ~5 minutes (same as Docker) |
| Shutdown | ~10 seconds |

## Testing Improvements

### Before (Docker)

- ❌ Broadcasts: Limited, unreliable
- ❌ Bluetooth: Shared access, conflicts
- ⚠️  Network: Host networking, namespace issues
- ✅ PAM: Works (sufficient for basic testing)

### After (VM)

- ✅ Broadcasts: Full support, reliable
- ✅ Bluetooth: Exclusive access, no conflicts
- ✅ Network: Own network stack, realistic
- ✅ PAM: Works (same as before)
- ✅ Isolation: Complete kernel separation

## Configuration Options

All settings in `vm-config.sh`:

```bash
# VM Resources
VM_MEMORY="4096"        # RAM in MB (default: 4GB)
VM_CPUS="4"             # CPU cores (default: 4)
VM_DISK_SIZE="20G"      # Disk size (default: 20GB)

# Network (can be customized)
VM_BRIDGE="tapauth-br0"
VM_HOST_IP="192.168.100.1"
VM_GUEST_IP="192.168.100.10"

# Bluetooth (auto-detect or manual)
BT_USB_DEVICE=""        # Empty = auto-detect

# SSH
VM_SSH_USER="tapauth"
VM_SSH_PASSWORD="tapauth"
```

## Maintenance

### Regular Tasks

- **Update VM**: SSH in and run `sudo apt-get update && sudo apt-get upgrade`
- **Clean build cache**: In VM: `cd /tapauth && cargo clean`
- **Backup**: Backup `~/.tapauth-vm/tapauth-dev.qcow2` and `~/.tapauth-vm/id_rsa`

### Rebuild VM

If VM becomes corrupted:

```bash
./dev-stop.sh  # Choose 'yes' to delete disk
./vm-setup.sh  # Recreate from scratch
./dev-start.sh # Start fresh VM
```

## Security Considerations

1. **SSH Key**: Private key stored in `~/.tapauth-vm/id_rsa` - keep secure
2. **Network**: VM has NAT access to internet (can be restricted if needed)
3. **Bluetooth**: VM has complete USB control (isolated from host)
4. **Shared Folder**: Uses passthrough security model (VM can modify host files)

## Future Enhancements

Possible improvements:

1. **Multiple VMs**: Support running multiple test VMs simultaneously
2. **Snapshots**: QEMU snapshot support for quick rollback
3. **Remote Access**: VNC/SPICE for remote GUI access
4. **Automated Tests**: CI/CD integration with VM lifecycle
5. **Performance**: Hugepages, CPU pinning for better performance

## Troubleshooting Quick Reference

| Issue | Solution |
|-------|----------|
| KVM not available | `sudo modprobe kvm kvm_intel` (or kvm_amd) |
| Permission denied | Add user to kvm/libvirt groups, log out/in |
| Bluetooth not working | Check `lsusb`, manually set `BT_USB_DEVICE` |
| Network not working | Check bridge: `ip addr show tapauth-br0` |
| Can't connect via SSH | Wait 10 mins on first boot, check VM window |
| Shared folder not mounted | In VM: `sudo mount -t 9p -o trans=virtio tapauth /tapauth` |

## Conclusion

The migration from Docker to VMs provides:

1. **Critical functionality**: Network broadcasts and exclusive Bluetooth access
2. **Maintainability**: Same user workflow, just different backend
3. **Reliability**: Isolated environment, no host conflicts
4. **Testing quality**: Realistic environment matching deployment

The trade-off of slightly higher resource usage and longer boot times is justified by the significant improvements in testing capabilities, especially for the core networking and Bluetooth features of TapAuth.
