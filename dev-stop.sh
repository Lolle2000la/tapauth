#!/bin/bash
# TapAuth Development Environment - Stop Script
# This script stops the Docker development environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect Docker Compose command
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

echo "Stopping TapAuth development environment..."

# Check if container is running
if docker ps --format '{{.Names}}' | grep -q '^tapauth-dev$'; then
    $DOCKER_COMPOSE -f docker-compose.dev.yml down
    echo "✅ Development environment stopped"
else
    echo "⚠️  Container was not running"
fi

# Optionally remove volumes
echo ""
read -p "Do you want to remove volumes (will delete build cache and config)? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    $DOCKER_COMPOSE -f docker-compose.dev.yml down -v
    echo "✅ Volumes removed"
fi
