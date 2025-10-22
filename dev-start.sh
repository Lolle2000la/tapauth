#!/bin/bash
# TapAuth Development Environment - Start Script
# This script sets up and starts the VM development environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth Development Environment Setup                 ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if VM setup has been run
if [ ! -f "$VM_DISK_IMAGE" ]; then
    echo "VM not set up yet. Running initial setup..."
    echo ""
    ./vm-setup.sh
    echo ""
fi

# Start the VM
./vm-start.sh
