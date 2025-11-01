#!/bin/bash
set -e

# TapAuth Interactive Installation Script
# This script builds and installs all TapAuth components with optimizations

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
INTERACTIVE=true
INSTALL_PAM=true
INSTALL_CONFIG_GUI=true
CONFIGURE_PAM_LOGIN=false
CONFIGURE_PAM_SUDO=false
CONFIGURE_PAM_POLKIT=false
USE_TPM=false
USE_BLE=true
BUILD_ONLY=false
DRY_RUN=false

# Installation paths (some will be detected at runtime)
PAM_MODULE_DIR=""  # Will be detected based on distribution
PAM_SO_NAME="pam_tapauth.so"
PAM_SO_PATH=""  # Will be set after detection
CONFIG_GUI_PATH="/usr/bin/tapauth-config"
CONFIG_DESKTOP_PATH="/usr/share/applications/tapauth-config.desktop"
CONFIG_POLICY_PATH="/usr/share/polkit-1/actions/dev.rourunisen.tapauth.policy"
CONFIG_DIR="/etc/tapauth"
KEY_PATH="$CONFIG_DIR/client_key"
SOCKET_UNIT_SOURCE="systemd/tapauthd.socket"
SERVICE_UNIT_SOURCE="systemd/tapauthd.service"
SOCKET_UNIT_DEST="/etc/systemd/system/tapauthd.socket"
SERVICE_UNIT_DEST="/etc/systemd/system/tapauthd.service"

# Print functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
}

# Dry-run helper functions
show_file_creation() {
    local file="$1"
    local description="$2"
    echo -e "${BLUE}[CREATE]${NC} $file"
    [[ -n "$description" ]] && echo "  → $description"
}

show_file_copy() {
    local source="$1"
    local dest="$2"
    echo -e "${BLUE}[COPY]${NC} $source → $dest"
}

show_file_edit() {
    local file="$1"
    local description="$2"
    echo -e "${YELLOW}[EDIT]${NC} $file"
    [[ -n "$description" ]] && echo "  → $description"
}

show_command() {
    local cmd="$1"
    local description="$2"
    echo -e "${BLUE}[EXEC]${NC} $cmd"
    [[ -n "$description" ]] && echo "  → $description"
}

show_pam_diff() {
    local pam_file="$1"
    local pam_line="$2"
    local insert_after="$3"
    
    echo ""
    echo -e "${YELLOW}[DIFF]${NC} $pam_file"
    echo "  Changes to be made:"
    
    if [[ ! -f "$pam_file" ]]; then
        echo -e "  ${RED}  File does not exist - would be created${NC}"
        echo "  + $pam_line"
        return
    fi
    
    if grep -q "pam_tapauth.so" "$pam_file" 2>/dev/null; then
        echo -e "  ${GREEN}  Already configured - no changes needed${NC}"
        return
    fi
    
    echo "  ---"
    if [[ -n "$insert_after" ]] && grep -q "$insert_after" "$pam_file"; then
        # Show context around insertion point
        grep -n "$insert_after" "$pam_file" | head -1 | while IFS=: read -r linenum line; do
            echo "  $linenum: $line"
            echo -e "  ${GREEN}+${NC} $pam_line"
        done
    else
        echo -e "  ${GREEN}+${NC} $pam_line"
        if [[ -f "$pam_file" ]]; then
            echo "  $(head -1 "$pam_file")"
        fi
    fi
    echo "  ---"
    echo -e "  ${BLUE}NOTE:${NC} 'sufficient' means TapAuth is tried first, but existing"
    echo "        authentication methods (password, etc.) remain fully functional"
}

show_service_diff() {
    local service_file="$1"
    local source_file="$2"
    
    echo ""
    echo -e "${YELLOW}[DIFF]${NC} $service_file"
    
    if [[ ! -f "$service_file" ]]; then
        echo -e "  ${BLUE}New file to be created:${NC}"
        echo "  ---"
        cat "$source_file" | head -20 | sed 's/^/  /'
        local line_count=$(wc -l < "$source_file")
        if [[ $line_count -gt 20 ]]; then
            echo "  ... ($(($line_count - 20)) more lines)"
        fi
        echo "  ---"
    else
        echo -e "  ${GREEN}File already exists${NC}"
        if ! diff -q "$source_file" "$service_file" &>/dev/null; then
            echo "  Changes:"
            echo "  ---"
            diff -u "$service_file" "$source_file" | tail -n +3 | sed 's/^/  /' || true
            echo "  ---"
        else
            echo "  No changes needed"
        fi
    fi
}

# Usage information
usage() {
    cat << EOF
TapAuth Installation Script

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -n, --non-interactive   Run in non-interactive mode
    -y, --yes               Answer yes to all prompts (implies --non-interactive)
    --no-pam                Don't install PAM module
    --no-ble                Build without Bluetooth support (UDP only)
    --no-gui                Don't install configuration GUI
    --configure-login       Configure PAM for login authentication
    --configure-sudo        Configure PAM for sudo authentication
    --configure-polkit      Configure PAM for polkit authentication
    --use-tpm               Enable TPM support for key storage
    --build-only            Only build, don't install
    --dry-run               Show what would be done without doing it

EXAMPLES:
    # Interactive installation (default)
    sudo $0

    # Non-interactive with all components
    sudo $0 --non-interactive --configure-login --configure-sudo

    # Install PAM module without Bluetooth support
    sudo $0 --no-ble --configure-login

    # Build only without installing
    $0 --build-only

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -n|--non-interactive)
                INTERACTIVE=false
                shift
                ;;
            -y|--yes)
                INTERACTIVE=false
                INSTALL_PAM=true
                INSTALL_CONFIG_GUI=true
                CONFIGURE_PAM_LOGIN=true
                CONFIGURE_PAM_SUDO=true
                CONFIGURE_PAM_POLKIT=true
                USE_BLE=true
                shift
                ;;
            --no-pam)
                INSTALL_PAM=false
                shift
                ;;
            --no-ble)
                USE_BLE=false
                shift
                ;;
            --no-gui)
                INSTALL_CONFIG_GUI=false
                shift
                ;;
            --configure-login)
                CONFIGURE_PAM_LOGIN=true
                shift
                ;;
            --configure-sudo)
                CONFIGURE_PAM_SUDO=true
                shift
                ;;
            --configure-polkit)
                CONFIGURE_PAM_POLKIT=true
                shift
                ;;
            --use-tpm)
                USE_TPM=true
                shift
                ;;
            --build-only)
                BUILD_ONLY=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Interactive prompts
prompt_components() {
    print_header "Component Selection"
    
    read -p "Install PAM module? [Y/n]: " response
    [[ ! "$response" =~ ^[Nn]$ ]] && INSTALL_PAM=true || INSTALL_PAM=false
    
    read -p "Enable Bluetooth support? [Y/n]: " response
    [[ ! "$response" =~ ^[Nn]$ ]] && USE_BLE=true || USE_BLE=false
    
    read -p "Install configuration GUI? [Y/n]: " response
    [[ ! "$response" =~ ^[Nn]$ ]] && INSTALL_CONFIG_GUI=true || INSTALL_CONFIG_GUI=false
}

prompt_pam_configuration() {
    if [[ "$INSTALL_PAM" == false ]]; then
        return
    fi
    
    print_header "PAM Configuration"
    print_warning "Configuring PAM incorrectly can lock you out of your system!"
    print_info "It's recommended to have a root shell open in another terminal."
    echo ""
    
    read -p "Configure TapAuth for login authentication? [y/N]: " response
    [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_LOGIN=true || CONFIGURE_PAM_LOGIN=false
    
    read -p "Configure TapAuth for sudo authentication? [y/N]: " response
    [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_SUDO=true || CONFIGURE_PAM_SUDO=false
    
    read -p "Configure TapAuth for polkit authentication? [y/N]: " response
    [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_POLKIT=true || CONFIGURE_PAM_POLKIT=false
}

prompt_tpm() {
    print_header "TPM Configuration"
    
    if command -v tpm2_getrandom &> /dev/null; then
        print_info "TPM tools detected on system"
        read -p "Use TPM for key storage? [y/N]: " response
        [[ "$response" =~ ^[Yy]$ ]] && USE_TPM=true || USE_TPM=false
    else
        print_warning "TPM tools not detected. Skipping TPM configuration."
        USE_TPM=false
    fi
}

# Detect PAM module directory
detect_pam_directory() {
    if [[ "$INSTALL_PAM" == false ]]; then
        return
    fi
    
    print_info "Detecting PAM module directory..."
    
    # Possible PAM module directories for different distributions
    local pam_dirs=(
        "/lib/x86_64-linux-gnu/security"        # Ubuntu/Debian
        "/usr/lib/x86_64-linux-gnu/security"    # Ubuntu/Debian (alternative)
        "/lib64/security"                        # Fedora/RHEL/CentOS
        "/usr/lib64/security"                    # Fedora/RHEL (alternative)
        "/usr/lib/security"                      # Arch Linux
        "/lib/security"                          # Generic fallback
    )
    
    for dir in "${pam_dirs[@]}"; do
        if [[ -d "$dir" ]] && [[ -r "$dir" ]]; then
            # Verify it actually contains PAM modules
            if ls "$dir"/pam_*.so &> /dev/null; then
                PAM_MODULE_DIR="$dir"
                PAM_SO_PATH="$dir/$PAM_SO_NAME"
                print_success "Found PAM directory: $PAM_MODULE_DIR"
                return
            fi
        fi
    done
    
    print_error "Could not find PAM module directory"
    print_info "Searched directories:"
    for dir in "${pam_dirs[@]}"; do
        echo "  - $dir"
    done
    exit 1
}

# Detect distribution
detect_distribution() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="$ID"
        DISTRO_NAME="$NAME"
        print_info "Detected distribution: $DISTRO_NAME"
    else
        DISTRO_ID="unknown"
        DISTRO_NAME="Unknown"
        print_warning "Could not detect distribution"
    fi
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Detect distribution first
    detect_distribution
    
    # Check if running as root (unless build-only or dry-run)
    if [[ "$BUILD_ONLY" == false && "$DRY_RUN" == false && $EUID -ne 0 ]]; then
        print_error "This script must be run as root for installation"
        print_info "Run with --build-only to just build without installing"
        print_info "Run with --dry-run to simulate installation without root"
        exit 1
    fi
    
    # Check for required commands
    local missing_deps=()
    
    if ! command -v cargo &> /dev/null; then
        missing_deps+=("cargo (Rust toolchain)")
    fi
    
    if ! command -v rustc &> /dev/null; then
        missing_deps+=("rustc (Rust compiler)")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required dependencies:"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        exit 1
    fi
    
    # Detect PAM directory if needed
    if [[ "$INSTALL_PAM" == true ]]; then
        detect_pam_directory
    fi
    
    print_success "All prerequisites met"
}

# Create system users and groups for tapauthd and IPC clients
create_system_users() {
    print_header "Creating System Users/Groups"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would create system user 'tapauthd' and group 'tapauthd-clients'"
        echo "  • useradd --system --home /nonexistent --shell /usr/sbin/nologin tapauthd"
        echo "  • groupadd --system tapauthd-clients"
        echo "  • gpasswd -d tapauthd tapauthd-clients (ensure daemon not in client group)"
        echo "  • mkdir -p $CONFIG_DIR && chown -R tapauthd:tapauthd $CONFIG_DIR && chmod 700 $CONFIG_DIR"
        return
    fi

    if ! id -u tapauthd >/dev/null 2>&1; then
        print_info "Creating system user 'tapauthd'"
        useradd --system --home /nonexistent --shell /usr/sbin/nologin tapauthd || true
    else
        print_info "System user 'tapauthd' already exists"
    fi

    if ! getent group tapauthd-clients >/dev/null 2>&1; then
        print_info "Creating group 'tapauthd-clients'"
        groupadd --system tapauthd-clients || true
    else
        print_info "Group 'tapauthd-clients' already exists"
    fi

    # Ensure daemon user is not in the client group by policy
    gpasswd -d tapauthd tapauthd-clients >/dev/null 2>&1 || true

    # Ensure configuration directory ownership and permissions
    mkdir -p "$CONFIG_DIR"
    chown -R tapauthd:tapauthd "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
}

# Install and enable systemd socket/service units for tapauthd
install_systemd_units() {
    print_header "Installing systemd Units"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would install tapauthd.socket and tapauthd.service"
        show_service_diff "$SOCKET_UNIT_DEST" "$SOCKET_UNIT_SOURCE"
        show_service_diff "$SERVICE_UNIT_DEST" "$SERVICE_UNIT_SOURCE"
        show_command "systemctl daemon-reload" "Reload systemd units"
        show_command "systemctl enable --now tapauthd.socket" "Enable socket activation"
        return
    fi

    if [[ ! -f "$SOCKET_UNIT_SOURCE" || ! -f "$SERVICE_UNIT_SOURCE" ]]; then
        print_warning "Systemd unit files not found in repo; skipping unit installation"
        return
    fi

    install -m 644 "$SOCKET_UNIT_SOURCE" "$SOCKET_UNIT_DEST"
    install -m 644 "$SERVICE_UNIT_SOURCE" "$SERVICE_UNIT_DEST"
    systemctl daemon-reload
    systemctl enable --now tapauthd.socket
    print_success "Systemd units installed and socket activated"
}

# Build components
build_components() {
    print_header "Building TapAuth Components"
    
    local build_flags="--release"
    local rustflags="-Ctarget-cpu=native -Copt-level=3"
    
    # Determine features to build with
    local pam_features=""
    if [[ "$USE_BLE" == true ]]; then
        pam_features="--features ble"
        print_info "Building with Bluetooth support (direct BlueZ access)"
    else
        pam_features="--no-default-features"
        print_info "Building without Bluetooth support (UDP only)"
    fi
    
    if [[ "$USE_TPM" == true ]]; then
        if [[ "$USE_BLE" == true ]]; then
            pam_features="--features ble,tpm"
        else
            pam_features="--features tpm"
        fi
        print_info "Building with TPM support"
    fi
    
    print_info "Building with maximum optimizations for host architecture"
    print_info "RUSTFLAGS: $rustflags"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would build components"
        echo ""
        print_info "PAM module build flags: $pam_features"
        
        # Show which user would be used for building
        if [[ $EUID -eq 0 ]] && [[ -n "$SUDO_USER" ]]; then
            echo ""
            print_info "Build would run as user '$SUDO_USER' (dropped root privileges)"
        elif [[ $EUID -eq 0 ]]; then
            echo ""
            print_warning "Build would run as root (SUDO_USER not set)"
        else
            echo ""
            print_info "Build would run as current user"
        fi
        
        return
    fi
    
    # Determine if we should drop privileges for building
    local build_user=""
    local build_cmd_prefix=""
    local user_home=""
    
    if [[ $EUID -eq 0 ]]; then
        # Running as root - try to build as the original user
        if [[ -n "$SUDO_USER" ]]; then
            build_user="$SUDO_USER"
            user_home=$(eval echo ~$SUDO_USER)
            # Use sudo -E to preserve RUSTFLAGS, but set HOME to user's home
            build_cmd_prefix="sudo -u $SUDO_USER HOME=$user_home"
            print_info "Building as user '$SUDO_USER' (dropped root privileges for safety)"
        else
            print_warning "Running as root without SUDO_USER set - building as root (not recommended)"
            build_cmd_prefix=""
        fi
    else
        # Not root - build as current user
        print_info "Building as current user"
        build_cmd_prefix=""
    fi
    
    export RUSTFLAGS="$rustflags"
    
    # Build PAM module
    if [[ "$INSTALL_PAM" == true ]]; then
        print_info "Building PAM module with features: $pam_features"
        $build_cmd_prefix env RUSTFLAGS="$rustflags" cargo build $build_flags -p client-pam $pam_features
        print_success "PAM module built"
    fi
    
    # Build configuration GUI
    if [[ "$INSTALL_CONFIG_GUI" == true ]]; then
        print_info "Building configuration GUI..."
        $build_cmd_prefix env RUSTFLAGS="$rustflags" cargo build $build_flags -p client-config-gui
        print_success "Configuration GUI built"
    fi
    
    unset RUSTFLAGS
}

# Install PAM module
install_pam() {
    if [[ "$INSTALL_PAM" == false ]]; then
        return
    fi
    
    print_header "Installing PAM Module"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would install PAM module"
        echo ""
        show_file_copy "target/release/libclient_pam.so" "$PAM_SO_PATH"
        show_command "chmod 644 $PAM_SO_PATH" "Set PAM module permissions"
        show_file_creation "$CONFIG_DIR" "TapAuth configuration directory (mode 700)"
        if [[ ! -f "$KEY_PATH" ]]; then
            show_file_creation "$KEY_PATH" "Client key file (created on first pairing)"
        fi
        return
    fi
    
    # Verify PAM directory was detected
    if [[ -z "$PAM_MODULE_DIR" ]]; then
        print_error "PAM module directory not detected"
        exit 1
    fi
    
    # Copy PAM module directly to the system PAM directory
    print_info "Installing PAM module to $PAM_SO_PATH"
    
    if [[ ! -f "target/release/libclient_pam.so" ]]; then
        print_error "PAM module not built: target/release/libclient_pam.so not found"
        exit 1
    fi
    
    cp target/release/libclient_pam.so "$PAM_SO_PATH"
    chmod 644 "$PAM_SO_PATH"
    
    # Create config directory and set permissions
    print_info "Creating configuration directory $CONFIG_DIR"
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    
    # Create or preserve key file
    if [[ ! -f "$KEY_PATH" ]]; then
        print_info "Key file will be created on first pairing"
    fi
    
    print_success "PAM module installed to $PAM_SO_PATH"
}

# Configure PAM
configure_pam() {
    if [[ "$INSTALL_PAM" == false ]]; then
        return
    fi
    
    if [[ "$CONFIGURE_PAM_LOGIN" == false && "$CONFIGURE_PAM_SUDO" == false && "$CONFIGURE_PAM_POLKIT" == false ]]; then
        print_info "No PAM services selected for configuration"
        return
    fi
    
    print_header "Configuring PAM Services"
    
    local pam_line="auth    sufficient    $PAM_SO_PATH"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would configure PAM services"
        echo ""
        
        if [[ "$CONFIGURE_PAM_LOGIN" == true ]]; then
            show_pam_diff "/etc/pam.d/login" "$pam_line" "pam_env.so"
        fi
        
        if [[ "$CONFIGURE_PAM_SUDO" == true ]]; then
            show_pam_diff "/etc/pam.d/sudo" "$pam_line" ""
        fi
        
        if [[ "$CONFIGURE_PAM_POLKIT" == true ]]; then
            # Check both locations for polkit PAM config
            if [[ -f /etc/pam.d/polkit-1 ]]; then
                show_pam_diff "/etc/pam.d/polkit-1" "$pam_line" ""
            elif [[ -f /usr/lib/pam.d/polkit-1 ]]; then
                show_pam_diff "/usr/lib/pam.d/polkit-1" "$pam_line" ""
            else
                echo ""
                echo -e "${YELLOW}[SKIP]${NC} polkit PAM configuration"
                echo "  → Not found at /etc/pam.d/polkit-1 or /usr/lib/pam.d/polkit-1"
            fi
        fi
        return
    fi
    
    # Configure login
    if [[ "$CONFIGURE_PAM_LOGIN" == true ]]; then
        print_info "Configuring PAM for login..."
        if ! grep -q "pam_tapauth.so" /etc/pam.d/login 2>/dev/null; then
            # Insert after pam_env.so or at beginning of auth section
            if grep -q "pam_env.so" /etc/pam.d/login; then
                sed -i "/pam_env.so/a $pam_line" /etc/pam.d/login
            else
                sed -i "1i $pam_line" /etc/pam.d/login
            fi
            print_success "Configured PAM for login"
        else
            print_warning "PAM login already configured"
        fi
    fi
    
    # Configure sudo
    if [[ "$CONFIGURE_PAM_SUDO" == true ]]; then
        print_info "Configuring PAM for sudo..."
        if ! grep -q "pam_tapauth.so" /etc/pam.d/sudo 2>/dev/null; then
            # Insert at beginning of auth section
            sed -i "1i $pam_line" /etc/pam.d/sudo
            print_success "Configured PAM for sudo"
        else
            print_warning "PAM sudo already configured"
        fi
    fi
    
    # Configure polkit
    if [[ "$CONFIGURE_PAM_POLKIT" == true ]]; then
        print_info "Configuring PAM for polkit..."
        
        # Check both /etc/pam.d and /usr/lib/pam.d (Fedora uses the latter)
        local polkit_pam_file=""
        if [[ -f /etc/pam.d/polkit-1 ]]; then
            polkit_pam_file="/etc/pam.d/polkit-1"
        elif [[ -f /usr/lib/pam.d/polkit-1 ]]; then
            polkit_pam_file="/usr/lib/pam.d/polkit-1"
        fi
        
        if [[ -n "$polkit_pam_file" ]]; then
            if ! grep -q "pam_tapauth.so" "$polkit_pam_file"; then
                sed -i "1i $pam_line" "$polkit_pam_file"
                print_success "Configured PAM for polkit at $polkit_pam_file"
            else
                print_warning "PAM polkit already configured at $polkit_pam_file"
            fi
        else
            print_warning "polkit PAM configuration not found (checked /etc/pam.d/polkit-1 and /usr/lib/pam.d/polkit-1)"
        fi
    fi
    
    # Inform about when changes take effect
    if [[ "$CONFIGURE_PAM_LOGIN" == true || "$CONFIGURE_PAM_SUDO" == true || "$CONFIGURE_PAM_POLKIT" == true ]]; then
        echo ""
        print_info "PAM configuration updated"
        print_info "Changes take effect:"
        if [[ "$CONFIGURE_PAM_SUDO" == true ]]; then
            echo "  • sudo: Immediately (no restart needed)"
        fi
        if [[ "$CONFIGURE_PAM_POLKIT" == true ]]; then
            echo "  • polkit: Immediately (no restart needed)"
        fi
        if [[ "$CONFIGURE_PAM_LOGIN" == true ]]; then
            echo "  • login: On next login session (logout/login required)"
        fi
    fi
}

# Install configuration GUI
install_config_gui() {
    if [[ "$INSTALL_CONFIG_GUI" == false ]]; then
        return
    fi
    
    print_header "Installing Configuration GUI"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would install configuration GUI"
        echo ""
        show_file_copy "target/release/tapauth-config" "$CONFIG_GUI_PATH"
        show_command "chmod 755 $CONFIG_GUI_PATH" "Set GUI executable permissions"
        
        if [[ -d /usr/share/applications ]]; then
            show_file_copy "client-config-gui/tapauth-config.desktop" "$CONFIG_DESKTOP_PATH"
            show_command "chmod 644 $CONFIG_DESKTOP_PATH" "Set desktop entry permissions"
        else
            echo -e "${YELLOW}[SKIP]${NC} Desktop entry (directory doesn't exist)"
        fi
        
        if [[ -d /usr/share/polkit-1/actions ]]; then
            show_file_copy "client-config-gui/dev.rourunisen.tapauth.policy" "$CONFIG_POLICY_PATH"
            show_command "chmod 644 $CONFIG_POLICY_PATH" "Set polkit policy permissions"
        else
            echo -e "${YELLOW}[SKIP]${NC} Polkit policy (directory doesn't exist)"
        fi
        return
    fi
    
    # Copy binary
    print_info "Installing configuration GUI to $CONFIG_GUI_PATH"
    cp target/release/tapauth-config "$CONFIG_GUI_PATH"
    chmod 755 "$CONFIG_GUI_PATH"
    
    # Install desktop entry
    if [[ -d /usr/share/applications ]]; then
        print_info "Installing desktop entry"
        cp client-config-gui/tapauth-config.desktop "$CONFIG_DESKTOP_PATH"
        chmod 644 "$CONFIG_DESKTOP_PATH"
    fi
    
    # Install polkit policy
    if [[ -d /usr/share/polkit-1/actions ]]; then
        print_info "Installing polkit policy"
        cp client-config-gui/dev.rourunisen.tapauth.policy "$CONFIG_POLICY_PATH"
        chmod 644 "$CONFIG_POLICY_PATH"
    fi
    
    print_success "Configuration GUI installed"
}

# Create installation summary
create_summary() {
    print_header "Installation Summary"
    
    echo "Components installed:"
    [[ "$INSTALL_PAM" == true ]] && echo "  ✓ PAM module" || echo "  ✗ PAM module"
    [[ "$INSTALL_CONFIG_GUI" == true ]] && echo "  ✓ Configuration GUI" || echo "  ✗ Configuration GUI"
    
    echo ""
    echo "PAM configuration:"
    [[ "$CONFIGURE_PAM_LOGIN" == true ]] && echo "  ✓ Login" || echo "  ✗ Login"
    [[ "$CONFIGURE_PAM_SUDO" == true ]] && echo "  ✓ Sudo" || echo "  ✗ Sudo"
    [[ "$CONFIGURE_PAM_POLKIT" == true ]] && echo "  ✓ Polkit" || echo "  ✗ Polkit"
    
    echo ""
    echo "Features enabled:"
    [[ "$USE_BLE" == true ]] && echo "  ✓ Bluetooth (direct BlueZ)" || echo "  ✗ Bluetooth (UDP only)"
    [[ "$USE_TPM" == true ]] && echo "  ✓ TPM support" || echo "  ✗ TPM support"
    
    echo ""
    print_info "Installation locations:"
    if [[ "$INSTALL_PAM" == true ]]; then
        echo "  - PAM module: $PAM_SO_PATH"
    fi
    if [[ "$INSTALL_CONFIG_GUI" == true ]]; then
        echo "  - Config GUI: $CONFIG_GUI_PATH"
    fi
    echo "  - Configuration: $CONFIG_DIR"
    echo "  - Daemon socket: /run/tapauthd/tapauthd.sock (root:tapauthd-clients, 0660)"
    echo ""
    echo "Distribution: $DISTRO_NAME"
    
    echo ""
    print_success "Installation complete!"
    
    if [[ "$INSTALL_CONFIG_GUI" == true ]]; then
        echo ""
        print_info "Next steps:"
        echo "  1. Run 'tapauth-config' to pair with your phone"
        echo "  2. Test authentication in a separate terminal"
        echo "  3. Keep a root shell open until you verify it works"
    fi
    
    if [[ "$CONFIGURE_PAM_LOGIN" == true || "$CONFIGURE_PAM_SUDO" == true ]]; then
        echo ""
        print_warning "IMPORTANT: Before logging out:"
        echo "  - Verify authentication works in a separate terminal"
        echo "  - Keep a root shell open as backup"
        if [[ "$CONFIGURE_PAM_SUDO" == true ]]; then
            echo "  - Test sudo now: 'sudo -k && sudo echo test' (works immediately)"
        fi
        if [[ "$CONFIGURE_PAM_LOGIN" == true ]]; then
            echo "  - Login authentication requires logout/login to take effect"
        fi
        echo ""
        print_info "PAM Configuration:"
        echo "  - TapAuth uses 'sufficient' - existing auth methods remain functional"
        echo "  - Password authentication will still work as a fallback"
        echo "  - Both phone tap and password can be used in parallel"
        if [[ "$CONFIGURE_PAM_SUDO" == true ]]; then
            echo ""
            print_success "Sudo authentication is ready to use immediately (no restart needed)"
        fi
    fi
}

# Main installation flow
main() {
    print_header "TapAuth Installation"
    
    parse_args "$@"
    
    if [[ "$INTERACTIVE" == true ]]; then
        prompt_components
        prompt_pam_configuration
        prompt_tpm
        
        echo ""
        read -p "Proceed with installation? [y/N]: " response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            print_info "Installation cancelled"
            exit 0
        fi
    fi
    
    check_prerequisites
    build_components
    
    if [[ "$BUILD_ONLY" == true ]]; then
        print_success "Build complete (--build-only specified)"
        exit 0
    fi
    
    create_system_users
    install_pam
    configure_pam
    install_config_gui
    install_systemd_units
    
    if [[ "$DRY_RUN" == true ]]; then
        echo ""
        print_header "Dry Run Summary"
        echo "The following changes would be made:"
        echo ""
        echo "Components to install:"
        [[ "$INSTALL_PAM" == true ]] && echo "  ✓ PAM module → $PAM_SO_PATH" || echo "  ✗ PAM module (skipped)"
        [[ "$INSTALL_CONFIG_GUI" == true ]] && echo "  ✓ Configuration GUI → $CONFIG_GUI_PATH" || echo "  ✗ Configuration GUI (skipped)"
        
        echo ""
        echo "PAM services to configure:"
        [[ "$CONFIGURE_PAM_LOGIN" == true ]] && echo "  ✓ Login (/etc/pam.d/login)" || echo "  ✗ Login (skipped)"
        [[ "$CONFIGURE_PAM_SUDO" == true ]] && echo "  ✓ Sudo (/etc/pam.d/sudo)" || echo "  ✗ Sudo (skipped)"
        [[ "$CONFIGURE_PAM_POLKIT" == true ]] && echo "  ✓ Polkit (/etc/pam.d/polkit-1)" || echo "  ✗ Polkit (skipped)"
        
        echo ""
        echo "Configuration:"
        echo "  • Distribution: $DISTRO_NAME"
        echo "  • PAM directory: $PAM_MODULE_DIR"
        if [[ "$USE_BLE" == true ]]; then
            echo "  • Bluetooth support: enabled (direct BlueZ)"
        else
            echo "  • Bluetooth support: disabled (UDP only)"
        fi
        if [[ "$USE_TPM" == true ]]; then
            echo "  • TPM support: enabled"
        else
            echo "  • TPM support: disabled"
        fi
        
        echo ""
        print_info "[DRY RUN] No actual changes were made to the system"
        print_info "Run without --dry-run to perform the installation"
    else
        create_summary
    fi
}

# Run main
main "$@"
