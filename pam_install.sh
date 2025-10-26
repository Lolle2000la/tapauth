#!/bin/bash
# Build the TapAuth PAM module and install it to the system

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth PAM Module - Build and Install              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# --- Configuration ---
PAM_CRATE_DIR="client-pam"
BUILD_OUTPUT_FILE="target/release/libclient_pam.so"  # Workspace target at root level
INSTALL_NAME="pam_tapauth.so"
# INSTALL_PATH will be detected below
# --- End Configuration ---

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

for dir in "${possible_pam_dirs[@]}"; do
    if [ -d "$dir" ]; then
        # Check if we can list files (basic read permission check)
        # Use sudo here in case the directory isn't readable by the user
        sudo ls "$dir" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
             PAM_MODULE_DIR="$dir"
             echo "✅ Found suitable PAM directory: $PAM_MODULE_DIR"
             break
        fi
    fi
done

if [ -z "$PAM_MODULE_DIR" ]; then
    echo "❌ Could not find a suitable PAM module directory."
    echo "   Checked: ${possible_pam_dirs[*]}"
    exit 1
fi
INSTALL_PATH="${PAM_MODULE_DIR}/${INSTALL_NAME}"

# 1. Build the module
echo ""
echo "==> Building PAM Module (Release)..."
cd "$PAM_CRATE_DIR"
# Run cargo build as the original user if using sudo, otherwise as current user
if [ -n "$SUDO_USER" ]; then
    ORIGINAL_HOME=$(eval echo ~$SUDO_USER)
    CARGO_PATH="${ORIGINAL_HOME}/.cargo/bin/cargo"
    if [ ! -x "$CARGO_PATH" ]; then
        echo "❌ Cargo executable not found for user $SUDO_USER at $CARGO_PATH"
        exit 1
    fi
    sudo -u "$SUDO_USER" "$CARGO_PATH" build --release --features ble
else
    if ! command -v cargo &> /dev/null; then
        echo "❌ cargo command not found in PATH."
        exit 1
    fi
    cargo build --release --features ble
fi
cd .. # Return to project root

# With workspace, build output is at root level
BUILD_OUTPUT_FULL_PATH="${BUILD_OUTPUT_FILE}"

if [ ! -f "$BUILD_OUTPUT_FULL_PATH" ]; then
    echo "❌ Build failed: Output file not found at $BUILD_OUTPUT_FULL_PATH"
    exit 1
fi
echo "✅ Build successful: $BUILD_OUTPUT_FULL_PATH"

# 2. Install the module (requires sudo)
echo ""
echo "==> Installing PAM module (requires sudo)..."
echo "    Copying build output to $INSTALL_PATH"
sudo cp "$BUILD_OUTPUT_FULL_PATH" "$INSTALL_PATH"
sudo chmod 644 "$INSTALL_PATH" # Standard permissions for PAM modules
echo "✅ Installation complete."
echo ""
echo "Next steps:"
echo "  1. Configure PAM services in /etc/pam.d/ to use '$INSTALL_NAME'"
echo "     Example for SSH:"
echo "       - Edit /etc/pam.d/sshd"
echo "       - Add 'auth sufficient $INSTALL_NAME' near the top"
echo "  2. Test the configuration (e.g., try logging in via SSH)"
echo ""
echo "To uninstall, run: sudo ./pam-uninstall.sh"
echo ""

