#!/bin/bash
# Uninstall the TapAuth PAM module from the system

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth PAM Module - Uninstall                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# --- Configuration ---
INSTALL_NAME="pam_tapauth.so"
# INSTALL_PATH will be detected below
# --- End Configuration ---

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "❌ This script must be run as root (using sudo) to remove system files."
  exit 1
fi

echo "==> Detecting PAM module directory..."
PAM_MODULE_DIR=""
# Common locations for PAM modules
declare -a possible_pam_dirs=(
    "/lib/x86_64-linux-gnu/security"
    "/usr/lib/x86_64-linux-gnu/security"
    "/lib64/security"
    "/usr/lib64/security"
    "/lib/security"
    "/usr/lib/security"
)

# Use ls directly as we are already root
for dir in "${possible_pam_dirs[@]}"; do
    # Check if directory exists and we can list it
    if [ -d "$dir" ] && ls "$dir" >/dev/null 2>&1; then
         PAM_MODULE_DIR="$dir"
         echo "✅ Using PAM directory: $PAM_MODULE_DIR"
         break
    fi
done

if [ -z "$PAM_MODULE_DIR" ]; then
    echo "❌ Could not find or access a suitable PAM module directory."
    echo "   Checked: ${possible_pam_dirs[*]}"
    exit 1
fi
INSTALL_PATH="${PAM_MODULE_DIR}/${INSTALL_NAME}"

# Uninstall the module
echo ""
echo "==> Uninstalling PAM module..."

if [ -f "$INSTALL_PATH" ]; then
    echo "    Removing $INSTALL_PATH"
    rm -f "$INSTALL_PATH"
    echo "✅ Module removed."
else
    echo "⚠️  Module not found at $INSTALL_PATH. Already uninstalled?"
fi

echo ""
echo "Remember to remove '$INSTALL_NAME' from any PAM configuration files"
echo "in /etc/pam.d/ where you added it (e.g., sshd, login, gdm-password)."
echo ""
echo "✅ Uninstallation script finished."

