#!/bin/bash
# TapAuth Development Environment - Rebuild Script
# This script rebuilds TapAuth components inside the container

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

echo "Rebuilding TapAuth components in container..."
echo ""

docker exec tapauth-dev build-tapauth

echo ""
echo "✅ Rebuild complete!"
echo ""
echo "You can now test with: ./dev-test.sh"
