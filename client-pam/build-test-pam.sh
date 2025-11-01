#!/bin/bash
# Build and test the TapAuth PAM module with the tapauthd daemon
# Starts tapauthd locally, health-checks the socket, then runs pamtester

# Intentionally avoid `set -e` to keep logs visible on failure; check critical steps manually

# Save original working directory
ORIGINAL_DIR="$(pwd)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Check for help flag
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: sudo $0 [username]"
    echo ""
    echo "Build and test the TapAuth PAM module for a specific user."
    echo "This now uses the tapauthd daemon via IPC (Unix socket). The script will start it for you."
    echo ""
    echo "Arguments:"
    echo "  username    Optional. The user to test authentication for."
    echo "              Defaults to the user who invoked sudo (currently: ${SUDO_USER:-$(whoami)})"
    echo ""
    echo "Examples:"
    echo "  sudo $0           # Test as current user (${SUDO_USER:-$(whoami)})"
    echo "  sudo $0 alice     # Test as user 'alice'"
    echo "  sudo $0 root      # Test as root user"
    echo ""
    echo "Note:"
    echo "  - This script requires root privileges (use sudo)"
    echo "  - The test user must have paired devices in /etc/tapauth/"
    echo "  - User-specific pairing: only users in allowed_users list can authenticate"
    echo "  - BLE functionality requires BlueZ (org.bluez) to be running"
    echo ""
    cd "$ORIGINAL_DIR"
    exit 0
fi

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth PAM Module - Build and Test                   ║"
echo "║         (Daemon mode: tapauthd via Unix socket)               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# --- Configuration ---
PAM_CRATE_DIR="${PROJECT_ROOT}/client-pam"
BUILD_OUTPUT_FILE="${PROJECT_ROOT}/target/release/libclient_pam.so"  # Workspace target at root level
TAPAUTHD_BIN="${PROJECT_ROOT}/target/release/tapauthd"
TAPAUTHD_SOCK_DIR="/run/tapauthd"
TAPAUTHD_DEFAULT_SOCK_PATH="${TAPAUTHD_SOCK_DIR}/tapauthd.sock"
# Test-specific socket (for temporary systemd units)
TAPAUTHD_TEST_SOCK_PATH="${TAPAUTHD_SOCK_DIR}/tapauthd-test.sock"
# Will be set based on activation mode below
TAPAUTHD_SOCK_PATH="$TAPAUTHD_DEFAULT_SOCK_PATH"
# Temporary directory for runtime systemd unit files
TEMP_UNIT_DIR=""
# Use a temporary name to avoid conflicts during testing
TEMP_INSTALL_NAME="pam_tapauth_test.so"
# TEMP_INSTALL_PATH will be detected below
PAM_SERVICE_NAME="tapauth-test-local"
PAM_CONFIG_PATH="/etc/pam.d/${PAM_SERVICE_NAME}"

# --- Determine test user ---
# Default to the user who invoked sudo, or current user if not using sudo
if [ -n "$SUDO_USER" ]; then
    DEFAULT_TEST_USER="$SUDO_USER"
else
    DEFAULT_TEST_USER="$(whoami)"
fi

# Allow user to override via command line argument
TEST_USER="${1:-$DEFAULT_TEST_USER}"

echo "ℹ️  Test user: $TEST_USER"
if [ "$TEST_USER" != "$DEFAULT_TEST_USER" ]; then
    echo "   (Overriding default user: $DEFAULT_TEST_USER)"
fi
echo ""

# Verify the test user exists
if ! id "$TEST_USER" &>/dev/null; then
    echo "❌ User '$TEST_USER' does not exist on this system"
    echo "   Usage: $0 [username]"
    echo "   Example: sudo $0 alice"
    cd "$ORIGINAL_DIR"
    exit 1
fi

# --- End Configuration ---

# Check for pamtester dependency
if ! command -v pamtester &> /dev/null; then
    echo "❌ 'pamtester' command not found."
    echo "   Please install it (e.g., 'sudo apt install pamtester' or 'sudo dnf install pamtester')"
    cd "$ORIGINAL_DIR"
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
    cd "$ORIGINAL_DIR"
    exit 1
fi
TEMP_INSTALL_PATH="${PAM_MODULE_DIR}/${TEMP_INSTALL_NAME}"
# --- END MODIFICATION ---

# 1. Build the module
echo ""
echo "==> Building PAM Module and Daemon (Release)..."
cd "$PAM_CRATE_DIR"

# --- MODIFIED: Use full path to cargo when using sudo ---
if [ -n "$SUDO_USER" ]; then
    ORIGINAL_HOME=$(eval echo ~$SUDO_USER)
    CARGO_PATH="${ORIGINAL_HOME}/.cargo/bin/cargo"
    # Check if cargo exists at the expected path
    if [ ! -x "$CARGO_PATH" ]; then
        echo "❌ Cargo executable not found for user $SUDO_USER at $CARGO_PATH"
        echo "   Ensure Rust is installed correctly for the user who ran sudo."
        cd "$ORIGINAL_DIR"
        exit 1
    fi
    echo "    Running build as user $SUDO_USER using $CARGO_PATH..."
    sudo -u "$SUDO_USER" "$CARGO_PATH" build --release --features ble -p client-pam -p tapauthd || { echo "❌ Build failed"; cd "$ORIGINAL_DIR"; exit 1; }
else
    # Check if cargo is in the current user's path
    if ! command -v cargo &> /dev/null; then
        echo "❌ cargo command not found in PATH."
        echo "   Ensure Rust is installed correctly."
        cd "$ORIGINAL_DIR"
        exit 1
    fi
    echo "    Running build as current user ($(whoami))..."
    cargo build --release --features ble -p client-pam -p tapauthd || { echo "❌ Build failed"; cd "$ORIGINAL_DIR"; exit 1; }
fi
# --- END MODIFICATION ---

# Already at project root, no need to cd

# With workspace, build output is at root level
BUILD_OUTPUT_FULL_PATH="${BUILD_OUTPUT_FILE}"

if [ ! -f "$BUILD_OUTPUT_FULL_PATH" ]; then
    echo "❌ Build failed: Output file not found at $BUILD_OUTPUT_FULL_PATH"
    cd "$ORIGINAL_DIR"
    exit 1
fi
if [ ! -x "$TAPAUTHD_BIN" ]; then
    echo "❌ Build failed: tapauthd binary not found at $TAPAUTHD_BIN"
    cd "$ORIGINAL_DIR"
    exit 1
fi
echo "✅ Build successful: $BUILD_OUTPUT_FULL_PATH"
echo "✅ Build successful: $TAPAUTHD_BIN"

# --- Cleanup function ---
# Ensures temporary files are removed even if the script exits unexpectedly
cleanup() {
    echo ""
    echo "==> Cleaning up temporary files..."
    case "$ACTIVATION_MODE" in
        systemd-temp)
            echo "    Stopping temporary systemd units..."
            sudo systemctl stop tapauthd-test.service 2>/dev/null || true
            sudo systemctl stop tapauthd-test.socket 2>/dev/null || true
            # Remove the runtime symlinks
            sudo rm -f /run/systemd/system/tapauthd-test.socket 2>/dev/null || true
            sudo rm -f /run/systemd/system/tapauthd-test.service 2>/dev/null || true
            sudo systemctl daemon-reload 2>/dev/null || true
            sudo rm -f "$TAPAUTHD_TEST_SOCK_PATH" 2>/dev/null || true
            if [ -n "$TEMP_UNIT_DIR" ] && [ -d "$TEMP_UNIT_DIR" ]; then
                sudo rm -rf "$TEMP_UNIT_DIR" 2>/dev/null || true
            fi
            if [ -n "$TEMP_BIN_DIR" ] && [ -d "$TEMP_BIN_DIR" ]; then
                sudo rm -rf "$TEMP_BIN_DIR" 2>/dev/null || true
            fi
            ;;
        manual)
            if [ -n "$DAEMON_PID" ]; then
                echo "    Stopping tapauthd (PID=$DAEMON_PID)..."
                kill "$DAEMON_PID" 2>/dev/null || true
                wait "$DAEMON_PID" 2>/dev/null || true
            fi
            sudo rm -f "$TAPAUTHD_SOCK_PATH" 2>/dev/null || true
            ;;
        systemd-existing)
            echo "    Using existing systemd socket; no socket cleanup needed."
            ;;
    esac
    # Use detected path for cleanup
    sudo rm -f "$PAM_CONFIG_PATH" "$TEMP_INSTALL_PATH"
    echo "✅ Cleanup complete."
    
    # Restore original working directory on cleanup
    cd "$ORIGINAL_DIR"
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
# IMPORTANT: Using "sufficient" means if TapAuth succeeds, authentication succeeds.
# If TapAuth fails, it falls through to pam_deny.so which denies access.
# This ensures that authentication only succeeds when TapAuth explicitly grants it.
sudo bash -c "cat > '$PAM_CONFIG_PATH'" << EOF
# Temporary PAM config for local tapauth testing
auth sufficient ${TEMP_INSTALL_NAME}
auth required pam_deny.so
account required pam_permit.so
EOF
echo "✅ Temporary setup complete."

# 2. Start tapauthd via systemd socket activation when available; fallback to manual
echo ""
echo "==> Preparing tapauthd IPC socket"

ACTIVATION_MODE="manual"
LOG_FILE="/tmp/tapauthd-test.log"

if command -v systemctl >/dev/null 2>&1 && pidof systemd >/dev/null 2>&1; then
    if sudo systemctl is-active --quiet tapauthd.socket; then
        ACTIVATION_MODE="systemd-existing"
        TAPAUTHD_SOCK_PATH="$TAPAUTHD_DEFAULT_SOCK_PATH"
        echo "    Using existing systemd socket: $TAPAUTHD_SOCK_PATH"
        echo "    View logs with: sudo journalctl -u tapauthd.service -f"
    else
        ACTIVATION_MODE="systemd-temp"
        TAPAUTHD_SOCK_PATH="$TAPAUTHD_TEST_SOCK_PATH"
        echo "    Creating temporary systemd units for testing..."

        # Ensure 'tapauthd' user exists (daemon may drop privileges)
        if ! id tapauthd >/dev/null 2>&1; then
            echo "    Creating system user 'tapauthd'"
            sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin tapauthd || true
        fi

        # Create temporary directory for unit files
        TEMP_UNIT_DIR=$(mktemp -d -t tapauthd-test-units.XXXXXX)
        echo "    Temporary units directory: $TEMP_UNIT_DIR"

        # Prepare executable in an executable temp location (avoid noexec mounts like /home or /tmp)
        # Use /run (tmpfs) which is typically mounted with exec and friendlier to SELinux/AppArmor policies
        TEMP_BIN_DIR=$(mktemp -d -p /run tapauthd-test-bin.XXXXXX)
        sudo install -m 0755 "$TAPAUTHD_BIN" "$TEMP_BIN_DIR/tapauthd"

        # Write temporary socket unit
        cat > "$TEMP_UNIT_DIR/tapauthd-test.socket" << EOF
[Unit]
Description=TapAuth daemon IPC test socket
PartOf=tapauthd-test.service

[Socket]
ListenStream=$TAPAUTHD_TEST_SOCK_PATH
SocketUser=root
SocketGroup=root
SocketMode=0666
DirectoryMode=0755
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
EOF

        # Write temporary service unit
        cat > "$TEMP_UNIT_DIR/tapauthd-test.service" << EOF
[Unit]
Description=TapAuth authentication daemon (test)
Requires=tapauthd-test.socket
After=network.target bluetooth.target

[Service]
Type=simple
User=root
Group=root
Sockets=tapauthd-test.socket
ExecStart=$TEMP_BIN_DIR/tapauthd
Restart=on-failure
Environment="RUST_LOG=${RUST_LOG:-debug}"

# Minimal hardening for test (keep it permissive)
NoNewPrivileges=yes
PrivateTmp=no
ProtectSystem=no
ProtectHome=no

[Install]
WantedBy=multi-user.target
EOF

        # If prior runtime symlinks exist from a previous run, clean them up to avoid conflicts
        sudo systemctl stop tapauthd-test.service 2>/dev/null || true
        sudo systemctl stop tapauthd-test.socket 2>/dev/null || true
        sudo rm -f /run/systemd/system/tapauthd-test.socket 2>/dev/null || true
        sudo rm -f /run/systemd/system/tapauthd-test.service 2>/dev/null || true
        sudo systemctl daemon-reload 2>/dev/null || true

        # Link units as runtime units (no persistent state in /etc)
        sudo systemctl link --runtime "$TEMP_UNIT_DIR/tapauthd-test.socket" || { echo "❌ Failed to link socket unit"; exit 1; }
        sudo systemctl link --runtime "$TEMP_UNIT_DIR/tapauthd-test.service" || { echo "❌ Failed to link service unit"; exit 1; }
        sudo systemctl daemon-reload || { echo "❌ systemd daemon-reload failed"; exit 1; }
        sudo systemctl start tapauthd-test.socket || { echo "❌ Failed to start tapauthd-test.socket"; exit 1; }
        echo "    Started temporary socket: $TAPAUTHD_SOCK_PATH"
        echo "    View logs with: sudo journalctl -u tapauthd-test.service -f"
    fi
else
    echo "    systemd not available; starting daemon manually"
    echo "    Ensuring runtime directory at $TAPAUTHD_SOCK_DIR"
    sudo mkdir -p "$TAPAUTHD_SOCK_DIR" || true
    sudo chmod 0755 "$TAPAUTHD_SOCK_DIR" || true

    # Ensure 'tapauthd' user exists (daemon drops privileges to this user)
    if ! id tapauthd >/dev/null 2>&1; then
        echo "    Creating system user 'tapauthd'"
        sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin tapauthd || true
    fi

    TAPAUTHD_SOCK_PATH="$TAPAUTHD_DEFAULT_SOCK_PATH"
    echo "    Launching daemon with TAPAUTHD_SOCK=$TAPAUTHD_SOCK_PATH"
    echo "    Daemon logs will be written to $LOG_FILE"
    sudo env RUST_LOG="${RUST_LOG:-debug}" TAPAUTHD_SOCK="$TAPAUTHD_SOCK_PATH" "$TAPAUTHD_BIN" > "$LOG_FILE" 2>&1 &
    DAEMON_PID=$!
fi

# Wait for socket readiness (up to ~5s)
echo -n "    Waiting for socket to appear"
for i in {1..50}; do
    if [ -S "$TAPAUTHD_SOCK_PATH" ]; then echo ""; echo "✅ Socket ready: $TAPAUTHD_SOCK_PATH"; break; fi
    echo -n "."; sleep 0.1
done
if [ ! -S "$TAPAUTHD_SOCK_PATH" ]; then
    echo ""; echo "❌ Socket did not appear at $TAPAUTHD_SOCK_PATH";
    if [ "$ACTIVATION_MODE" = "manual" ]; then
        echo "   ➤ Check daemon logs: tail -n +1 -f $LOG_FILE"
    else
        UNIT_NAME="tapauthd.service"
        [ "$ACTIVATION_MODE" = "systemd-temp" ] && UNIT_NAME="tapauthd-test.service"
        echo "   ➤ Check daemon logs: sudo journalctl -u $UNIT_NAME -n 200 --no-pager"
    fi
    exit 1
fi

# Health check: connect and send empty frame (length=0), expect daemon to handle and stay alive
echo "    Performing daemon health check..."
python3 - << PY || { echo "❌ Health check failed"; exit 1; }
import socket, struct
path = "$TAPAUTHD_SOCK_PATH"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1.5)
s.connect(path)
# send zero-length frame (u32 BE = 0)
s.sendall(struct.pack('>I', 0))
s.close()
print("OK")
PY
echo "✅ Daemon health check passed"
if [ "$ACTIVATION_MODE" = "manual" ]; then
    echo "    ➤ View daemon logs with: tail -f $LOG_FILE"
else
    UNIT_NAME="tapauthd.service"
    [ "$ACTIVATION_MODE" = "systemd-temp" ] && UNIT_NAME="tapauthd-test.service"
    echo "    ➤ View daemon logs with: sudo journalctl -u $UNIT_NAME -f"
fi

# 3. Run pamtester
echo ""
echo "==> Running pamtester..."
echo "    Service: $PAM_SERVICE_NAME"
echo "    User:    $TEST_USER"
echo "    Note:    PAM module talks to tapauthd over IPC"
echo ""
echo "---------------------------------------------------------------------"
echo "  Attempting authentication for user: $TEST_USER"
echo "  The module will directly communicate with BlueZ for BLE advertising."
echo "  Watch for BLE/UDP activity."
echo "  Use your paired Android device to approve the authentication."
echo "---------------------------------------------------------------------"
echo ""

# Run pamtester with verbose output, targeting the specified user
# Requires running the script with sudo; preserve env so PAM module sees TAPAUTHD_SOCK
export TAPAUTHD_SOCK="$TAPAUTHD_SOCK_PATH"
set +e
sudo -E RUST_LOG="debug" pamtester -v "$PAM_SERVICE_NAME" "$TEST_USER" authenticate
PAMTESTER_EXIT_CODE=$?
set -e # Re-enable exit on error

echo ""
echo "---------------------------------------------------------------------"
echo "  pamtester finished with exit code: $PAMTESTER_EXIT_CODE"
if [ $PAMTESTER_EXIT_CODE -eq 0 ]; then
    echo "  ✅ Authentication successful (according to pamtester)."
    echo "     User '$TEST_USER' was authenticated successfully."
else
    echo "  ⚠️  Authentication failed or denied (pamtester exit code $PAMTESTER_EXIT_CODE)."
    echo "     This might be expected if:"
    echo "       - You didn't approve on the device"
    echo "       - User '$TEST_USER' has no paired devices"
    echo "       - User '$TEST_USER' is not in the allowed_users list for any pairing"
fi
echo "---------------------------------------------------------------------"
echo ""

# 4. Cleanup happens automatically via the 'trap' command when the script exits

echo "✅ Build and test script finished."

# Restore original working directory
cd "$ORIGINAL_DIR"

exit $PAMTESTER_EXIT_CODE

