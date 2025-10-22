#!/bin/bash
# TapAuth Development Environment - Stop Script
# This script stops the VM development environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load configuration
source ./vm-config.sh

# Run the VM stop script
./vm-stop.sh
