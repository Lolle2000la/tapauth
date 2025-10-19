#!/bin/bash
# TapAuth Development Environment - Shell Access
# This script opens a shell in the running development container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q '^tapauth-dev$'; then
    echo "❌ ERROR: Development container is not running"
    echo ""
    echo "Start it with: ./dev-start.sh"
    exit 1
fi

# Enter the container
echo "Entering TapAuth development environment..."
echo "(Type 'exit' to leave the container)"
echo ""

docker exec -it tapauth-dev bash
