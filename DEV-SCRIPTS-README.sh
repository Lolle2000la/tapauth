#!/bin/bash
# TapAuth - Development Scripts Overview
# 
# This file documents the development scripts available.
# The environment uses QEMU/KVM virtual machines for better testing.

cat << 'EOF'

╔═══════════════════════════════════════════════════════════════╗
║         TapAuth Development Scripts                           ║
╚═══════════════════════════════════════════════════════════════╝

Main Scripts (Use These):
  ./dev-start.sh    - Start the development VM
  ./dev-shell.sh    - SSH into the running VM
  ./dev-stop.sh     - Stop the VM
  ./dev-rebuild.sh  - Rebuild TapAuth inside the VM
  ./dev-test.sh     - Run tests inside the VM

VM Management Scripts (Advanced):
  ./vm-setup.sh     - Initial VM setup (run once)
  ./vm-start.sh     - Start VM (called by dev-start.sh)
  ./vm-shell.sh     - SSH to VM (called by dev-shell.sh)
  ./vm-stop.sh      - Stop VM (called by dev-stop.sh)
  ./vm-config.sh    - Configuration variables

Configuration:
  Edit vm-config.sh to customize VM resources, network, etc.

Documentation:
  VM-DEVELOPMENT.md           - Complete VM guide
  DOCKER-TO-VM-MIGRATION.md   - Migration from Docker
  DEVELOPMENT.md              - General development info
  QUICKSTART-DEV.md           - Quick start guide

Quick Start:
  1. Install prerequisites:
     sudo apt-get install qemu-system-x86 qemu-utils cloud-image-utils \
         libvirt-daemon-system libvirt-clients bridge-utils socat
     
     sudo usermod -a -G kvm,libvirt $USER
     # Log out and back in

  2. Setup VM (first time only):
     ./vm-setup.sh

  3. Start VM:
     ./dev-start.sh

  4. Connect:
     ./dev-shell.sh

Inside the VM:
  build-tapauth    - Build all components
  test-tapauth     - Run unit tests
  test-pam-auth    - Test PAM authentication
  tapauth-config   - Launch GUI (requires X11)

Network:
  VM IP:    192.168.100.10
  Host IP:  192.168.100.1
  Bridge:   tapauth-br0
  
Shared Folder:
  Host:     $(pwd)
  VM:       /tapauth (auto-mounted)

Bluetooth:
  Exclusive USB passthrough to VM
  Auto-detected and configured

EOF
