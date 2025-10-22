#!/bin/bash
# TapAuth - Development Scripts Reference
# 
# This file documents all available development scripts.
# The environment uses QEMU/KVM virtual machines for better testing.

cat << 'EOF'

╔═══════════════════════════════════════════════════════════════╗
║         TapAuth Development Scripts                                 ║
╚═══════════════════════════════════════════════════════════════╝

MAIN WORKFLOW:

  ./vm-setup.sh       - Initial VM setup (run once)
  ./vm-start.sh       - Start the VM (auto-setup if needed)
  ./vm-shell.sh       - SSH into the VM
  ./vm-build.sh       - Build TapAuth components
  ./vm-test.sh        - Run tests
  ./vm-stop.sh        - Stop the VM
  ./vm-clean.sh       - Delete VM and reset (advanced)

═══════════════════════════════════════════════════════════════

VM MANAGEMENT:

  ./vm-setup.sh
    • Creates VM disk image from Ubuntu cloud image
    • Generates SSH keys for passwordless access
    • Creates cloud-init configuration
    • Only needs to run once
    
  ./vm-start.sh
    • Starts the QEMU/KVM virtual machine
    • Auto-runs vm-setup.sh if VM is not initialized
    • Detects and passes through Bluetooth USB device
    • Sets up network bridge for broadcast support
    • On first boot: installs packages (~5-10 minutes)
    
  ./vm-shell.sh
    • Opens SSH session into running VM
    • Enables X11 forwarding for GUI applications
    • Waits for VM to be ready on first boot
    • Type 'exit' to disconnect
    
  ./vm-stop.sh
    • Gracefully shuts down the VM
    • Restores host Bluetooth service
    • Optionally deletes VM disk for fresh start
    
  ./vm-clean.sh
    • Advanced: Deletes VM disk while keeping Ubuntu base image
    • Removes cloud-init ISO, SSH keys, log files
    • Does NOT delete the Ubuntu cloud image (~700MB)

═══════════════════════════════════════════════════════════════

BUILD & TEST:

  ./vm-build.sh
    • Builds all TapAuth components inside VM
    • Equivalent to: ./vm-shell.sh → build-tapauth
    • Errors if VM is not running
    
  ./vm-test.sh
    • Runs all unit tests inside VM
    • Equivalent to: ./vm-shell.sh → test-tapauth
    • Errors if VM is not running

═══════════════════════════════════════════════════════════════

QUICK START:

  1. Setup VM (first time only):
     ./vm-setup.sh

  2. Start VM:
     ./vm-start.sh
     # ⏱️ First boot takes 5-10 minutes

  3. Connect:
     ./vm-shell.sh

  4. Inside VM:
     build-tapauth    - Build TapAuth
     test-tapauth     - Run tests
     test-pam-auth    - Test PAM authentication
     bluetooth-status - Check Bluetooth setup
     tapauth-config   - Launch GUI

═══════════════════════════════════════════════════════════════

CONFIGURATION:

  Edit vm-config.sh to customize:
    • VM_MEMORY (default: 4096 MB)
    • VM_CPUS (default: 4)
    • VM_DISK_SIZE (default: 20G)
    • VM_SSH_PORT (default: 2222)
    • BT_USB_DEVICE (auto-detected by default)

═══════════════════════════════════════════════════════════════

NETWORK:

  Host IP:    192.168.100.1
  VM IP:      192.168.100.10
  Bridge:     tapauth-br0
  Network:    192.168.100.0/24
  
  The VM can send and receive UDP broadcasts, essential for
  the TapAuth discovery protocol.

═══════════════════════════════════════════════════════════════

BLUETOOTH:

  The VM gets exclusive access to your Bluetooth adapter via
  USB passthrough. The host Bluetooth service is stopped while
  the VM is running and automatically restored when stopped.
  
  Auto-detection: The script finds your Bluetooth device
  automatically. To see what was detected:
    • Check in the QEMU window during VM startup
    • Or: lsusb | grep -i bluetooth

═══════════════════════════════════════════════════════════════

DOCUMENTATION:

  VM-DEVELOPMENT.md           - Complete VM setup & architecture
  VM-INITIALIZATION-GUIDE.md  - First-time boot details
  QUICKSTART-DEV.md           - Quick reference guide
  DOCKER-TO-VM-MIGRATION.md   - Why we migrated from Docker

═══════════════════════════════════════════════════════════════

DAILY WORKFLOW:

  Start:
    ./vm-start.sh
    ./vm-shell.sh

  Make changes (code syncs automatically)

  Build & test:
    ./vm-build.sh
    ./vm-test.sh

  Exit:
    exit                # Exit SSH
    ./vm-stop.sh        # Stop VM

═══════════════════════════════════════════════════════════════

TROUBLESHOOTING:

  VM won't start?
    • Check KVM is available: egrep -c '(vmx|svm)' /proc/cpuinfo
    • Run ./vm-setup.sh to create VM image

  SSH connection fails?
    • First boot takes 5-10 minutes to initialize
    • Check QEMU window for cloud-init progress
    • Manually SSH: ssh -p 2222 tapauth@localhost

  Bluetooth not working?
    • Check adapter: sudo lsusb | grep -i bluetooth
    • Inside VM: bluetooth-status
    • May need to manually restart: sudo systemctl restart bluetooth

  Out of disk space?
    • Delete VM: ./vm-clean.sh
    • Recreate: ./vm-setup.sh && ./vm-start.sh

EOF
