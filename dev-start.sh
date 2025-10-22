#!/bin/bash
# TapAuth Development Environment - Start Script
# This script sets up and starts the Docker development environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth Development Environment Setup                 ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ ERROR: Docker is not installed"
    echo "   Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ ERROR: Docker Compose is not installed"
    echo "   Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

# Detect Docker Compose command
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

echo "✅ Docker is installed"
echo "✅ Docker Compose is installed"
echo ""

# Enable X11 forwarding
echo "==> Setting up X11 forwarding for GUI..."
if command -v xhost &> /dev/null; then
    xhost +local:docker > /dev/null 2>&1 || true
    echo "✅ X11 forwarding enabled"
else
    echo "⚠️  Warning: xhost not found, GUI may not work"
    echo "   Install: sudo apt-get install x11-xserver-utils"
fi
echo ""

# Stop host Bluetooth service to allow container access
echo "==> Preparing Bluetooth access..."
if command -v systemctl &> /dev/null; then
    if systemctl is-active --quiet bluetooth; then
        echo "Stopping host Bluetooth service (will be restored when container stops)..."
        if sudo systemctl stop bluetooth 2>/dev/null; then
            echo "✅ Host Bluetooth service stopped"
            echo "   (Container will run its own Bluetooth daemon)"
        else
            echo "⚠️  Could not stop host Bluetooth service"
            echo "   Container BLE features may not work properly"
        fi
    else
        echo "✅ Host Bluetooth service already stopped"
    fi
else
    echo "⚠️  systemctl not found, cannot manage Bluetooth service"
fi
echo ""

# Check if container is already running
if docker ps --format '{{.Names}}' | grep -q '^tapauth-dev$'; then
    echo "==> Container is already running"
    echo ""
    read -p "Do you want to restart it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "==> Stopping existing container..."
        $DOCKER_COMPOSE -f docker-compose.dev.yml down
    else
        echo "==> Attaching to existing container..."
        docker exec -it tapauth-dev bash
        exit 0
    fi
fi

# Build the container
echo "==> Building Docker image..."
echo "   This may take a few minutes on first run..."
$DOCKER_COMPOSE -f docker-compose.dev.yml build

echo ""
echo "==> Starting container..."
$DOCKER_COMPOSE -f docker-compose.dev.yml up -d

# Wait for container to be ready
echo "==> Waiting for container to be ready..."
sleep 2

# Build TapAuth components inside the container
echo ""
echo "==> Building TapAuth components..."
docker exec tapauth-dev build-tapauth

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         Development Environment Ready!                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Container is running in the background."
echo ""
echo "To enter the development environment:"
echo "  ./dev-shell.sh"
echo ""
echo "To view logs:"
echo "  docker logs -f tapauth-dev"
echo ""
echo "To stop the environment:"
echo "  ./dev-stop.sh"
echo ""
echo "Quick Commands Inside Container:"
echo "  - Pair device:         run-gui"
echo "  - Test authentication: test-pam-auth root"
echo "  - Check Bluetooth:     bluetooth-status"
echo ""
