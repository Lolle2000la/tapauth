#!/bin/bash
# TapAuth Development Environment - Shell Access
# This script opens a shell in the running VM via SSH

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

# Run the VM shell script
./vm-shell.sh
