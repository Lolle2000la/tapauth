#!/bin/bash
# Quick script to create tapauthd users/groups for development testing
# without running the full installer

set -e

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

echo "Creating TapAuth system users and groups..."

# Create tapauthd user if it doesn't exist
if ! id -u tapauthd >/dev/null 2>&1; then
    echo "  Creating system user 'tapauthd'"
    useradd --system --home /nonexistent --shell /usr/sbin/nologin tapauthd
else
    echo "  User 'tapauthd' already exists"
fi

# Create tapauthd-clients group if it doesn't exist
if ! getent group tapauthd-clients >/dev/null 2>&1; then
    echo "  Creating group 'tapauthd-clients'"
    groupadd --system tapauthd-clients
else
    echo "  Group 'tapauthd-clients' already exists"
fi

# Ensure /var/lib/tapauth exists with correct ownership
CONFIG_DIR="/var/lib/tapauth"
echo "  Setting up $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
chown -R tapauthd:tapauthd "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Add the calling user to tapauthd-clients group if running via sudo
if [[ -n "$SUDO_USER" ]]; then
    if ! groups "$SUDO_USER" | grep -q tapauthd-clients; then
        echo "  Adding user '$SUDO_USER' to group 'tapauthd-clients'"
        usermod -aG tapauthd-clients "$SUDO_USER"
        echo "  Note: You will need to log out and back in for group membership to take effect"
    else
        echo "  User '$SUDO_USER' is already a member of 'tapauthd-clients'"
    fi
fi

echo ""
echo "Done! You can now run the GUI for pairing."
echo ""
echo "Note: This is for development only. Run './install.sh' for full installation."
