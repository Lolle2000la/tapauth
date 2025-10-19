#!/bin/bash
# TapAuth Development Environment - Test Script
# This script runs tests in the development container

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

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         Running TapAuth Tests                                 ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Run unit tests
docker exec tapauth-dev test-tapauth

echo ""
echo "✅ All tests passed!"
echo ""
echo "To test PAM authentication:"
echo "  docker exec -it tapauth-dev test-pam-auth root"
echo ""
echo "Or enter the container and test manually:"
echo "  ./dev-shell.sh"
echo "  test-pam-auth root"
