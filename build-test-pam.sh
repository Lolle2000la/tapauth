#!/bin/bash
# Build the TapAuth PAM module and test it locally using pamtester

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth PAM Module - Build and Test                 ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# --- Configuration ---
PAM_CRATE_DIR="client-pam"
BUILD_OUTPUT_FILE="target/release/libclient_pam.so"
# Use a temporary name to avoid conflicts during testing
TEMP_INSTALL_NAME="pam_tapauth_test.so"
# TEMP_INSTALL_PATH will be detected below
PAM_SERVICE_NAME="tapauth-test-local"
PAM_CONFIG_PATH="/etc/pam.d/${PAM_SERVICE_NAME}"
BLE_DAEMON_SERVICE="tapauth-ble-daemon"
BLE_DAEMON_DIR="ble-daemon"
# --- End Configuration ---

# --- Track daemon state for cleanup ---
DAEMON_WAS_RUNNING=false
DAEMON_WAS_INSTALLED=false

# Check for pamtester dependency
if ! command -v pamtester &> /dev/null; then
    echo "❌ 'pamtester' command not found."
    echo "   Please install it (e.g., 'sudo apt install pamtester' or 'sudo dnf install pamtester')"
    exit 1
fi
echo "✅ pamtester found."

# --- Detect PAM module directory ---
echo ""
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
TEMP_INSTALL_PATH="${PAM_MODULE_DIR}/${TEMP_INSTALL_NAME}"
# --- END MODIFICATION ---

# 1. Build the module
echo ""
echo "==> Building PAM Module (Release)..."
cd "$PAM_CRATE_DIR"

# --- MODIFIED: Use full path to cargo when using sudo ---
if [ -n "$SUDO_USER" ]; then
    ORIGINAL_HOME=$(eval echo ~$SUDO_USER)
    CARGO_PATH="${ORIGINAL_HOME}/.cargo/bin/cargo"
    # Check if cargo exists at the expected path
    if [ ! -x "$CARGO_PATH" ]; then
        echo "❌ Cargo executable not found for user $SUDO_USER at $CARGO_PATH"
        echo "   Ensure Rust is installed correctly for the user who ran sudo."
        exit 1
    fi
    echo "    Running build as user $SUDO_USER using $CARGO_PATH..."
    sudo -u "$SUDO_USER" "$CARGO_PATH" build --release --features ble
else
    # Check if cargo is in the current user's path
    if ! command -v cargo &> /dev/null; then
        echo "❌ cargo command not found in PATH."
        echo "   Ensure Rust is installed correctly."
        exit 1
    fi
    echo "    Running build as current user ($(whoami))..."
    cargo build --release --features ble
fi
# --- END MODIFICATION ---

cd .. # Return to project root

BUILD_OUTPUT_FULL_PATH="${PAM_CRATE_DIR}/${BUILD_OUTPUT_FILE}"

if [ ! -f "$BUILD_OUTPUT_FULL_PATH" ]; then
    echo "❌ Build failed: Output file not found at $BUILD_OUTPUT_FULL_PATH"
    exit 1
fi
echo "✅ Build successful: $BUILD_OUTPUT_FULL_PATH"

# --- Check and manage daemon state ---
echo ""
echo "==> Checking BLE daemon status..."

# Check if daemon is already installed (production version)
if systemctl list-unit-files | grep -q "^${BLE_DAEMON_SERVICE}.service"; then
    DAEMON_WAS_INSTALLED=true
    echo "ℹ️  Production daemon detected"
    
    # Check if it's running
    if systemctl is-active --quiet "$BLE_DAEMON_SERVICE"; then
        DAEMON_WAS_RUNNING=true
        echo "    Production daemon is running - stopping it temporarily..."
        sudo systemctl stop "$BLE_DAEMON_SERVICE"
        echo "✅ Production daemon stopped (will be restored on exit)"
    else
        echo "    Production daemon is installed but not running"
    fi
else
    echo "ℹ️  No production daemon found - will install test version"
fi

# --- Build and install test daemon ---
echo ""
echo "==> Building and installing test BLE daemon..."
cd "$BLE_DAEMON_DIR"

# Build the daemon
if [ -n "$SUDO_USER" ]; then
    ORIGINAL_HOME=$(eval echo ~$SUDO_USER)
    CARGO_PATH="${ORIGINAL_HOME}/.cargo/bin/cargo"
    if [ ! -x "$CARGO_PATH" ]; then
        echo "❌ Cargo executable not found for user $SUDO_USER at $CARGO_PATH"
        exit 1
    fi
    echo "    Building daemon as user $SUDO_USER..."
    sudo -u "$SUDO_USER" "$CARGO_PATH" build --release
else
    if ! command -v cargo &> /dev/null; then
        echo "❌ cargo command not found in PATH."
        exit 1
    fi
    echo "    Building daemon as current user..."
    cargo build --release
fi

# Install the test daemon
echo "    Installing test daemon binary..."
sudo cp target/release/tapauth-ble-daemon /usr/local/bin/tapauth-ble-daemon
sudo chmod 755 /usr/local/bin/tapauth-ble-daemon

# Install D-Bus policy
echo "    Installing D-Bus policy..."
sudo cp dev.rourunisen.tapauth.BLE.conf /etc/dbus-1/system.d/
sudo chmod 644 /etc/dbus-1/system.d/dev.rourunisen.tapauth.BLE.conf
# Reload D-Bus configuration WITHOUT restarting the entire service
sudo dbus-send --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig

# Install systemd service if not already present
if [ "$DAEMON_WAS_INSTALLED" = false ]; then
    echo "    Installing systemd service..."
    sudo cp tapauth-ble-daemon.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable "$BLE_DAEMON_SERVICE"
fi

# Start the daemon
echo "    Starting test daemon..."
sudo systemctl start "$BLE_DAEMON_SERVICE"

# Wait a moment for daemon to initialize
sleep 2

# Check daemon status
if systemctl is-active --quiet "$BLE_DAEMON_SERVICE"; then
    echo "✅ Test daemon is running"
    # Show last few log lines
    echo "    Recent daemon logs:"
    sudo journalctl -u "$BLE_DAEMON_SERVICE" -n 5 --no-pager | sed 's/^/      /'
else
    echo "❌ Test daemon failed to start"
    echo "    Error logs:"
    sudo journalctl -u "$BLE_DAEMON_SERVICE" -n 10 --no-pager | sed 's/^/      /'
    exit 1
fi

cd .. # Return to project root

# --- Cleanup function ---
# Ensures temporary files are removed even if the script exits unexpectedly
cleanup() {
    echo ""
    echo "==> Cleaning up temporary files..."
    # Use detected path for cleanup
    sudo rm -f "$PAM_CONFIG_PATH" "$TEMP_INSTALL_PATH"
    echo "✅ Cleanup complete."
    
    # Restore daemon state if needed
    if [ "$DAEMON_WAS_INSTALLED" = true ]; then
        echo ""
        echo "==> Restoring daemon state..."
        if [ "$DAEMON_WAS_RUNNING" = true ]; then
            echo "    Starting production daemon..."
            sudo systemctl start "$BLE_DAEMON_SERVICE"
            echo "✅ Production daemon restored"
        fi
    else
        # Stop and remove test daemon
        echo ""
        echo "==> Removing test daemon..."
        if systemctl is-active --quiet "$BLE_DAEMON_SERVICE" 2>/dev/null; then
            sudo systemctl stop "$BLE_DAEMON_SERVICE"
        fi
        if [ -f "/etc/systemd/system/${BLE_DAEMON_SERVICE}.service" ]; then
            sudo systemctl disable "$BLE_DAEMON_SERVICE" 2>/dev/null || true
            sudo rm -f "/etc/systemd/system/${BLE_DAEMON_SERVICE}.service"
            sudo rm -f "/usr/local/bin/tapauth-ble-daemon"
            sudo rm -f "/etc/dbus-1/system.d/dev.rourunisen.tapauth.BLE.conf"
            sudo systemctl daemon-reload
            echo "✅ Test daemon removed"
        fi
    fi
}
# Register the cleanup function to run on script exit (normal or error)
trap cleanup EXIT

# 2. Temporarily install the module and create PAM config
echo ""
echo "==> Setting up temporary test environment (requires sudo)..."
echo "    Copying build output to $TEMP_INSTALL_PATH"
sudo cp "$BUILD_OUTPUT_FULL_PATH" "$TEMP_INSTALL_PATH"

echo "    Creating temporary PAM service file at $PAM_CONFIG_PATH"
# Note: Using the temporary *name* (not full path) is correct here,
# PAM searches standard directories automatically.
#
# IMPORTANT: Using "required" instead of "sufficient" to ensure authentication
# actually fails when TapAuth denies access. The second line (pam_deny.so) is
# a safety measure that will deny access if TapAuth somehow doesn't return a result.
sudo bash -c "cat > '$PAM_CONFIG_PATH'" << EOF
# Temporary PAM config for local tapauth testing
auth required ${TEMP_INSTALL_NAME}
auth required pam_deny.so
account required pam_permit.so
EOF
echo "✅ Temporary setup complete."

# 3. Run pamtester
echo ""
echo "==> Running pamtester..."
echo "    Service: $PAM_SERVICE_NAME"
echo "    User:    root"
echo ""
echo "---------------------------------------------------------------------"
echo "  Attempting authentication. Watch for BLE/UDP activity."
echo "  Use your paired Android device if prompted."
echo "---------------------------------------------------------------------"
echo ""

# Run pamtester with verbose output, targeting the root user
# Requires running the script with sudo
set +e
sudo pamtester -v "$PAM_SERVICE_NAME" "root" authenticate
PAMTESTER_EXIT_CODE=$?
set -e # Re-enable exit on error

echo ""
echo "---------------------------------------------------------------------"
echo "  pamtester finished with exit code: $PAMTESTER_EXIT_CODE"
if [ $PAMTESTER_EXIT_CODE -eq 0 ]; then
    echo "  ✅ Authentication successful (according to pamtester)."
else
    echo "  ⚠️  Authentication failed or denied (pamtester exit code $PAMTESTER_EXIT_CODE)."
    echo "     This might be expected if you didn't approve on the device."
fi
echo "---------------------------------------------------------------------"
echo ""

# 4. Cleanup happens automatically via the 'trap' command when the script exits

echo "✅ Build and test script finished."

exit $PAMTESTER_EXIT_CODE

