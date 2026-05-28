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
# All components are always installed
INSTALL_PAM=true
INSTALL_CONFIG_GUI=true
INSTALL_DAEMON=true
# Only features and PAM configuration are configurable
CONFIGURE_PAM_LOGIN=false
CONFIGURE_PAM_SU=false
CONFIGURE_PAM_SUDO=false
CONFIGURE_PAM_POLKIT=false
CONFIGURE_PAM_SU_L=false
CONFIGURE_PAM_SYSTEM_AUTH=false
CONFIGURE_PAM_GDM=false
CONFIGURE_PAM_SDDM=false
CONFIGURE_PAM_LIGHTDM=false
CONFIGURE_PAM_KDE=false
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
CONFIG_ICON_PATH="/usr/share/icons/hicolor/scalable/apps/tapauth-config.svg"
CONFIG_POLICY_PATH="/usr/share/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy"
CONFIG_DIR="/var/lib/tapauth"
KEY_PATH="$CONFIG_DIR/client_key"
DAEMON_PATH="/usr/bin/tapauthd"
SOCKET_UNIT_SOURCE="systemd/tapauthd.socket"
SERVICE_UNIT_SOURCE="systemd/tapauthd.service"
SOCKET_UNIT_DEST="/etc/systemd/system/tapauthd.socket"
SERVICE_UNIT_DEST="/etc/systemd/system/tapauthd.service"
UNINSTALL_SCRIPT_SOURCE="uninstall.sh"
UNINSTALL_SCRIPT_DEST="/usr/share/tapauth/uninstall.sh"

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
    --no-ble                Build without Bluetooth support (UDP only)
    --use-tpm               Enable TPM support for key storage
    --configure-login       Configure PAM for login authentication
    --configure-su          Configure PAM for su (root shells via su)
    --configure-sudo        Configure PAM for sudo authentication
    --configure-su-l        Configure PAM for su-l (root shells via su -)
    --configure-polkit      Configure PAM for polkit authentication
    --configure-system-auth Configure PAM for system-auth (used by SDDM, lock screen, etc.)
    --configure-gdm         Configure PAM for GDM (GNOME Display Manager)
    --configure-sddm        Configure PAM for SDDM (Simple Desktop Display Manager)
    --configure-lightdm     Configure PAM for LightDM
    --configure-kde         Configure PAM for KDE (kde, kscreenlocker)
    --build-only            Only build, don't install
    --dry-run               Show what would be done without doing it

NOTES:
    All components (PAM module, daemon, configuration GUI) are always installed.
    Only feature flags (BLE, TPM) and PAM configuration locations are configurable.
    
    system-auth is a common authentication stack used by many display managers
    (especially on Arch-based systems) and lock screens. Configuring system-auth
    may be preferable to configuring individual display managers.

EXAMPLES:
    # Interactive installation (default)
    sudo $0

    # Non-interactive with all PAM services configured
    sudo $0 --yes

    # Install without Bluetooth support
    sudo $0 --no-ble --configure-login --configure-sudo

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
                CONFIGURE_PAM_LOGIN=true
                CONFIGURE_PAM_SU=true
                CONFIGURE_PAM_SUDO=true
                CONFIGURE_PAM_POLKIT=true
                CONFIGURE_PAM_SU_L=true
                CONFIGURE_PAM_SYSTEM_AUTH=true
                CONFIGURE_PAM_GDM=true
                CONFIGURE_PAM_SDDM=false
                CONFIGURE_PAM_LIGHTDM=true
                USE_BLE=true
                shift
                ;;
            --no-ble)
                USE_BLE=false
                shift
                ;;
            --configure-login)
                CONFIGURE_PAM_LOGIN=true
                shift
                ;;
            --configure-su)
                CONFIGURE_PAM_SU=true
                shift
                ;;
            --configure-sudo)
                CONFIGURE_PAM_SUDO=true
                shift
                ;;
            --configure-su-l)
                CONFIGURE_PAM_SU_L=true
                shift
                ;;
            --configure-polkit)
                CONFIGURE_PAM_POLKIT=true
                shift
                ;;
            --configure-system-auth)
                CONFIGURE_PAM_SYSTEM_AUTH=true
                shift
                ;;
            --configure-gdm)
                CONFIGURE_PAM_GDM=true
                shift
                ;;
            --configure-sddm)
                CONFIGURE_PAM_SDDM=true
                shift
                ;;
            --configure-lightdm)
                CONFIGURE_PAM_LIGHTDM=true
                shift
                ;;
            --configure-kde)
                CONFIGURE_PAM_KDE=true
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
prompt_features() {
    print_header "Feature Selection"
    
    print_info "All components (daemon, PAM module, configuration GUI) will be installed."
    echo ""
    
    read -p "Enable Bluetooth support? [Y/n]: " response
    [[ ! "$response" =~ ^[Nn]$ ]] && USE_BLE=true || USE_BLE=false
    
    if command -v tpm2_getrandom &> /dev/null; then
        print_info "TPM tools detected on system"
        read -p "Use TPM for key storage? [y/N]: " response
        [[ "$response" =~ ^[Yy]$ ]] && USE_TPM=true || USE_TPM=false
    else
        print_info "TPM tools not detected. TPM support disabled."
        USE_TPM=false
    fi
}

prompt_pam_configuration() {
    print_header "PAM Configuration"
    print_warning "Configuring PAM incorrectly can lock you out of your system!"
    print_info "It's recommended to have a root shell open in another terminal."
    echo ""
    
    # Check for system-auth (common on Arch-based and some other systems)
    local has_system_auth=false
    if [[ -f /etc/pam.d/system-auth ]]; then
        has_system_auth=true
    fi
    
    # Detect available display managers
    local has_gdm=false
    local has_sddm=false
    local has_lightdm=false
    local has_kde=false
    
    if [[ -f /etc/pam.d/gdm-password ]] || [[ -f /etc/pam.d/gdm ]]; then
        has_gdm=true
    fi
    
    # SDDM uses /etc/pam.d/sddm for user authentication
    if [[ -f /etc/pam.d/sddm ]]; then
        has_sddm=true
    fi
    
    if [[ -f /etc/pam.d/lightdm ]]; then
        has_lightdm=true
    fi
    
    # KDE uses multiple PAM files
    if [[ -f /etc/pam.d/kde ]] || [[ -f /etc/pam.d/kscreenlocker ]]; then
        has_kde=true
    fi
    
    # Check system-auth FIRST - it's mutually exclusive with login/sudo/polkit
    if [[ "$has_system_auth" == true ]]; then
        echo ""
        print_info "═══ RECOMMENDED: system-auth ═══"
        echo ""
        echo "Detected /etc/pam.d/system-auth on your system."
        echo "This is a centralized authentication stack that covers:"
        echo "  • Login (console and display manager)"
        echo "  • Sudo"
        echo "  • Polkit"
        echo ""
        echo "Configuring system-auth is usually better than configuring"
        echo "individual services (login, sudo, polkit) separately."
        echo ""
        print_warning "Note: Lock screens often need separate configuration (see below)"
        echo ""
        read -p "Configure TapAuth for system-auth? [Y/n]: " response
        if [[ ! "$response" =~ ^[Nn]$ ]]; then
            CONFIGURE_PAM_SYSTEM_AUTH=true
            print_success "system-auth selected (covers login, su, su-l, sudo, polkit)"
            echo ""
            print_info "Skipping individual login/su/su-l/sudo/polkit configuration (covered by system-auth)"
            CONFIGURE_PAM_LOGIN=false
            CONFIGURE_PAM_SU=false
            CONFIGURE_PAM_SUDO=false
            CONFIGURE_PAM_POLKIT=false
            CONFIGURE_PAM_SU_L=false
        else
            CONFIGURE_PAM_SYSTEM_AUTH=false
            echo ""
            print_info "You can configure individual services instead:"
            echo ""
            
            read -p "Configure TapAuth for login (console/TTY login)? [y/N]: " response
            [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_LOGIN=true || CONFIGURE_PAM_LOGIN=false

            read -p "Configure TapAuth for su (root shells via 'su')? [y/N]: " response
            [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_SU=true || CONFIGURE_PAM_SU=false

            read -p "Configure TapAuth for su-l (root shells via 'su -')? [y/N]: " response
            [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_SU_L=true || CONFIGURE_PAM_SU_L=false
            
            read -p "Configure TapAuth for sudo? [y/N]: " response
            [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_SUDO=true || CONFIGURE_PAM_SUDO=false
            
            read -p "Configure TapAuth for polkit (GUI privilege elevation)? [y/N]: " response
            [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_POLKIT=true || CONFIGURE_PAM_POLKIT=false
        fi
    else
        # No system-auth, configure individually
        print_info "No /etc/pam.d/system-auth found - configuring services individually"
        echo ""
        
        read -p "Configure TapAuth for login (console/TTY login)? [y/N]: " response
        [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_LOGIN=true || CONFIGURE_PAM_LOGIN=false

        read -p "Configure TapAuth for su (root shells via 'su')? [y/N]: " response
        [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_SU=true || CONFIGURE_PAM_SU=false

        read -p "Configure TapAuth for su-l (root shells via 'su -')? [y/N]: " response
        [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_SU_L=true || CONFIGURE_PAM_SU_L=false
        
        read -p "Configure TapAuth for sudo? [y/N]: " response
        [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_SUDO=true || CONFIGURE_PAM_SUDO=false
        
        read -p "Configure TapAuth for polkit (GUI privilege elevation)? [y/N]: " response
        [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_POLKIT=true || CONFIGURE_PAM_POLKIT=false
        
        CONFIGURE_PAM_SYSTEM_AUTH=false
    fi
    
    echo ""
    print_info "═══ Display Managers & Lock Screens ═══"
    echo ""
    
    if [[ "$CONFIGURE_PAM_SYSTEM_AUTH" == true ]]; then
        print_info "Even with system-auth configured, lock screens often need"
        print_info "separate PAM configuration to work properly."
        echo ""
    fi
    
    if [[ "$has_kde" == true ]]; then
        local kde_default="n"
        local kde_prompt="[y/N]"
        if [[ "$CONFIGURE_PAM_SYSTEM_AUTH" == true ]]; then
            kde_default="Y"
            kde_prompt="[Y/n]"
            print_info "KDE lock screen recommended when using system-auth"
        fi
        read -p "Configure TapAuth for KDE (lock screen unlock)? ${kde_prompt}: " response
        if [[ "$kde_default" == "Y" ]]; then
            [[ ! "$response" =~ ^[Nn]$ ]] && CONFIGURE_PAM_KDE=true || CONFIGURE_PAM_KDE=false
        else
            [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_KDE=true || CONFIGURE_PAM_KDE=false
        fi
    fi
    
    if [[ "$has_gdm" == true ]]; then
        read -p "Configure TapAuth for GDM (GNOME Display Manager - first login)? [y/N]: " response
        [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_GDM=true || CONFIGURE_PAM_GDM=false
    fi
    
    if [[ "$has_sddm" == true ]]; then
        read -p "Configure TapAuth for SDDM (KDE/LXQt Display Manager - first login)? [y/N]: " response
        [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_SDDM=true || CONFIGURE_PAM_SDDM=false
    fi
    
    if [[ "$has_lightdm" == true ]]; then
        read -p "Configure TapAuth for LightDM (first login)? [y/N]: " response
        [[ "$response" =~ ^[Yy]$ ]] && CONFIGURE_PAM_LIGHTDM=true || CONFIGURE_PAM_LIGHTDM=false
    fi
}

# Detect PAM module directory
detect_pam_directory() {
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

# Check for existing installation and offer to uninstall
check_existing_installation() {
    if [[ "$BUILD_ONLY" == true || "$DRY_RUN" == true ]]; then
        return
    fi
    
    if [[ ! -f "$UNINSTALL_SCRIPT_DEST" ]]; then
        # No existing installation
        return
    fi
    
    print_header "Existing Installation Detected"
    print_warning "An existing TapAuth installation was found."
    echo ""
    print_info "It is recommended to uninstall the old version first to ensure"
    print_info "a clean upgrade, especially if components have changed."
    echo ""
    
    if [[ "$INTERACTIVE" == true ]]; then
        read -p "Uninstall existing version before installing? [Y/n]: " response
        if [[ "$response" =~ ^[Nn]$ ]]; then
            print_info "Proceeding with installation (will upgrade in-place)"
            return
        fi
    else
        print_info "Non-interactive mode: skipping uninstallation"
        return
    fi
    
    print_info "Running existing uninstaller..."
    echo ""
    
    # Run the existing uninstaller without removing user data or system accounts
    # Pass --non-interactive and --preserve-system-accounts to avoid prompts and keep accounts
    if bash "$UNINSTALL_SCRIPT_DEST" --non-interactive --preserve-system-accounts; then
        print_success "Previous version uninstalled successfully"
        echo ""
    else
        print_error "Uninstallation failed"
        read -p "Continue with installation anyway? [y/N]: " response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            print_info "Installation cancelled"
            exit 1
        fi
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
    
    # Always detect PAM directory
    detect_pam_directory
    
    print_success "All prerequisites met"
}

# Create system users and groups for tapauthd and IPC clients
create_system_users() {
    print_header "Creating System Users/Groups"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would create system user 'tapauthd' and group 'tapauthd-clients'"
        echo "  • useradd --system --home /nonexistent --shell /usr/sbin/nologin tapauthd"
        echo "  • groupadd --system tapauthd-clients"
        
        local install_user=""
        if [[ -n "$SUDO_USER" ]]; then
            install_user="$SUDO_USER"
        elif [[ -n "$USER" && "$USER" != "root" ]]; then
            install_user="$USER"
        fi
        
        if [[ -n "$install_user" ]]; then
            echo "  • usermod -aG tapauthd-clients $install_user"
        fi
        
        echo "  • mkdir -p $CONFIG_DIR && chown -R tapauthd:tapauthd $CONFIG_DIR && chmod 700 $CONFIG_DIR"
        echo "  • mkdir -p /var/log/tapauth && chown tapauthd:tapauthd /var/log/tapauth && chmod 755 /var/log/tapauth"
        return
    fi

    if ! id -u tapauthd >/dev/null 2>&1; then
        print_info "Creating system user 'tapauthd'"
        if useradd --system --home /nonexistent --shell /usr/sbin/nologin tapauthd 2>/dev/null; then
            print_success "System user 'tapauthd' created"
        else
            print_warning "Failed to create system user 'tapauthd' (may already exist)"
        fi
    else
        print_info "System user 'tapauthd' already exists"
    fi

    if ! getent group tapauthd-clients >/dev/null 2>&1; then
        print_info "Creating group 'tapauthd-clients'"
        if groupadd --system tapauthd-clients 2>/dev/null; then
            print_success "Group 'tapauthd-clients' created"
        else
            print_warning "Failed to create group 'tapauthd-clients' (may already exist)"
        fi
    else
        print_info "Group 'tapauthd-clients' already exists"
    fi

    # Add the installing user to tapauthd-clients group (needed for screen locker access)
    # This allows user-level processes (like kscreenlocker, gnome-screensaver, etc.) to access the daemon socket
    local install_user=""
    if [[ -n "$SUDO_USER" ]]; then
        install_user="$SUDO_USER"
    elif [[ -n "$USER" && "$USER" != "root" ]]; then
        install_user="$USER"
    fi

    if [[ -n "$install_user" ]]; then
        if ! id -nG "$install_user" | grep -qw tapauthd-clients; then
            print_info "Adding user '$install_user' to group 'tapauthd-clients'"
            usermod -aG tapauthd-clients "$install_user"
            print_warning "You will need to log out and back in for group membership to take effect"
        else
            print_info "User '$install_user' is already a member of 'tapauthd-clients'"
        fi
    else
        print_warning "Could not determine installing user - you may need to manually add your user to the tapauthd-clients group:"
        print_warning "  sudo usermod -aG tapauthd-clients \$USER"
    fi

    # Ensure configuration directory ownership and permissions
    mkdir -p "$CONFIG_DIR"
    chown -R tapauthd:tapauthd "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    
    # Create log directory for daemon
    local log_dir="/var/log/tapauth"
    if [[ ! -d "$log_dir" ]]; then
        print_info "Creating log directory $log_dir"
        mkdir -p "$log_dir"
        chown tapauthd:tapauthd "$log_dir"
        chmod 755 "$log_dir"
    else
        # Ensure ownership and permissions even if directory exists
        chown tapauthd:tapauthd "$log_dir"
        chmod 755 "$log_dir"
    fi
    
    print_success "System users/groups configured"
}

# Create initial configuration file
create_initial_config() {
    print_header "Creating Initial Configuration"
    
    local config_file="/etc/tapauth/config.toml"
    local config_dir="/etc/tapauth"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would create configuration file at $config_file"
        echo "  • pam_operation_timeout_secs: 3"
        echo "  • udp_port: 36692"
        echo "  • use_tpm: $USE_TPM"
        return
    fi
    
    # Don't overwrite existing config
    if [[ -f "$config_file" ]]; then
        print_info "Configuration file already exists, skipping creation"
        print_info "To enable/disable TPM, edit $config_file manually"
        return
    fi
    
    # Create config directory if it doesn't exist
    mkdir -p "$config_dir"
    
    print_info "Creating configuration file at $config_file"
    
    # Create TOML config
    cat > "$config_file" <<EOF
# TapAuth Configuration
# See config.toml.example for more details

# PAM operation timeout in seconds
pam_operation_timeout_secs = 3

# UDP port for authentication protocol
udp_port = 36692

# Enable TPM 2.0 for secure key storage
# Requires tpm2-tools to be installed
use_tpm = $([[ "$USE_TPM" == true ]] && echo "true" || echo "false")
EOF
    
    # Set permissions (readable by all, writable only by root)
    chmod 644 "$config_file"
    
    print_success "Configuration file created"
    if [[ "$USE_TPM" == true ]]; then
        print_info "TPM support enabled in configuration"
    fi
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
    
    # Restore SELinux contexts if available
    if command -v restorecon &> /dev/null; then
        restorecon "$SOCKET_UNIT_DEST" "$SERVICE_UNIT_DEST" || true
    fi
    
    systemctl daemon-reload
    systemctl enable --now tapauthd.socket
    print_success "Systemd units installed and socket activated"
}

# Install the daemon binary
install_daemon() {
    print_header "Installing Daemon"

    local daemon_src="target/release/tapauthd"
    local daemon_dest="/usr/bin/tapauthd"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would install daemon binary"
        show_file_copy "$daemon_src" "$daemon_dest"
        show_command "chmod 755 $daemon_dest" "Set daemon executable permissions"
        if [[ -d /usr/share/polkit-1/rules.d ]]; then
            show_command "install -m 0644 packaging/50-tapauthd.rules /usr/share/polkit-1/rules.d/50-tapauthd.rules" "Install polkit rules"
            if command -v restorecon &> /dev/null; then
                show_command "restorecon /usr/share/polkit-1/rules.d/50-tapauthd.rules" "Restore SELinux context"
            fi
        fi
        return
    fi

    if [[ ! -f "$daemon_src" ]]; then
        print_error "Daemon not built: $daemon_src not found"
        print_info "Run the build step before installing"
        exit 1
    fi

    print_info "Installing daemon to $daemon_dest"
    install -m 755 "$daemon_src" "$daemon_dest"
    
    # Restore SELinux context if available
    if command -v restorecon &> /dev/null; then
        restorecon "$daemon_dest" || true
    fi

    # Install polkit authorization rules for firewalld
    if [[ -d /usr/share/polkit-1/rules.d ]]; then
        print_info "Installing polkit firewalld authorization rules"
        install -m 0644 packaging/50-tapauthd.rules /usr/share/polkit-1/rules.d/50-tapauthd.rules
        if command -v restorecon &> /dev/null; then
            restorecon /usr/share/polkit-1/rules.d/50-tapauthd.rules || true
        fi
    fi
}

# Build components
build_components() {
    print_header "Building TapAuth Components"
    
    local build_flags="--release"
    local rustflags="-Ctarget-cpu=native -Copt-level=3"
    
    # Determine daemon features to build with
    local daemon_features=""
    local feature_list=()
    
    # Add BLE if requested
    if [[ "$USE_BLE" == true ]]; then
        feature_list+=("ble")
    fi
    
    # Add TPM if requested
    if [[ "$USE_TPM" == true ]]; then
        feature_list+=("tpm")
    fi
    
    # Build features string
    if [[ ${#feature_list[@]} -gt 0 ]]; then
        daemon_features="--features $(IFS=,; echo "${feature_list[*]}")"
        print_info "Building daemon with features: ${feature_list[*]}"
    else
        daemon_features="--no-default-features"
        print_info "Building daemon without optional features (UDP only, no TPM)"
    fi
    
    print_info "Building with maximum optimizations for host architecture"
    print_info "RUSTFLAGS: $rustflags"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would build components"
        echo ""
        print_info "Daemon build flags: $daemon_features"
        
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
    
    # Build daemon first
    print_info "Building daemon with features: $daemon_features"
    $build_cmd_prefix env RUSTFLAGS="$rustflags" cargo build $build_flags -p tapauthd $daemon_features
    print_success "Daemon built"

    # Build PAM module with same TPM feature
    local pam_features=""
    if [[ "$USE_TPM" == true ]]; then
        pam_features="--features tpm"
    else
        pam_features="--no-default-features"
    fi
    print_info "Building PAM module with features: $pam_features"
    $build_cmd_prefix env RUSTFLAGS="$rustflags" cargo build $build_flags -p client-pam $pam_features
    print_success "PAM module built"
    
    # Build configuration GUI with same TPM feature
    local gui_features=""
    if [[ "$USE_TPM" == true ]]; then
        gui_features="--features tpm"
    else
        gui_features="--no-default-features"
    fi
    print_info "Building configuration GUI with features: $gui_features"
    $build_cmd_prefix env RUSTFLAGS="$rustflags" cargo build $build_flags -p client-config-gui $gui_features
    print_success "Configuration GUI built"
    
    unset RUSTFLAGS
}

# Install PAM module
install_pam() {
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
    
    # Restore SELinux context if available
    if command -v restorecon &> /dev/null; then
        restorecon "$PAM_SO_PATH" || true
    fi
    
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
        if [[ "$CONFIGURE_PAM_LOGIN" == false && "$CONFIGURE_PAM_SU" == false && "$CONFIGURE_PAM_SU_L" == false && "$CONFIGURE_PAM_SUDO" == false && "$CONFIGURE_PAM_POLKIT" == false && \
            "$CONFIGURE_PAM_SYSTEM_AUTH" == false && "$CONFIGURE_PAM_GDM" == false && "$CONFIGURE_PAM_SDDM" == false && \
          "$CONFIGURE_PAM_LIGHTDM" == false && "$CONFIGURE_PAM_KDE" == false ]]; then
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

        if [[ "$CONFIGURE_PAM_SU" == true ]]; then
            show_pam_diff "/etc/pam.d/su" "$pam_line" "pam_env.so"
        fi

        if [[ "$CONFIGURE_PAM_SU_L" == true ]]; then
            show_pam_diff "/etc/pam.d/su-l" "$pam_line" "pam_env.so"
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
        
        if [[ "$CONFIGURE_PAM_SYSTEM_AUTH" == true ]]; then
            if [[ -f /etc/pam.d/system-auth ]]; then
                show_pam_diff "/etc/pam.d/system-auth" "$pam_line" ""
            else
                echo ""
                echo -e "${YELLOW}[SKIP]${NC} system-auth PAM configuration"
                echo "  → Not found at /etc/pam.d/system-auth"
            fi
        fi
        
        if [[ "$CONFIGURE_PAM_GDM" == true ]]; then
            # GDM typically uses gdm-password
            if [[ -f /etc/pam.d/gdm-password ]]; then
                show_pam_diff "/etc/pam.d/gdm-password" "$pam_line" ""
            elif [[ -f /etc/pam.d/gdm ]]; then
                show_pam_diff "/etc/pam.d/gdm" "$pam_line" ""
            else
                echo ""
                echo -e "${YELLOW}[SKIP]${NC} GDM PAM configuration"
                echo "  → Not found at /etc/pam.d/gdm-password or /etc/pam.d/gdm"
            fi
        fi
        
        if [[ "$CONFIGURE_PAM_SDDM" == true ]]; then
            # SDDM uses /etc/pam.d/sddm for user authentication
            if [[ -f /etc/pam.d/sddm ]]; then
                show_pam_diff "/etc/pam.d/sddm" "$pam_line" ""
            else
                echo ""
                echo -e "${YELLOW}[SKIP]${NC} SDDM PAM configuration"
                echo "  → Not found at /etc/pam.d/sddm"
            fi
        fi
        
        if [[ "$CONFIGURE_PAM_LIGHTDM" == true ]]; then
            if [[ -f /etc/pam.d/lightdm ]]; then
                show_pam_diff "/etc/pam.d/lightdm" "$pam_line" ""
            else
                echo ""
                echo -e "${YELLOW}[SKIP]${NC} LightDM PAM configuration"
                echo "  → Not found at /etc/pam.d/lightdm"
            fi
        fi
        
        if [[ "$CONFIGURE_PAM_KDE" == true ]]; then
            # KDE uses multiple PAM files
            local kde_found=false
            if [[ -f /etc/pam.d/kde ]]; then
                show_pam_diff "/etc/pam.d/kde" "$pam_line" ""
                kde_found=true
            fi
            if [[ -f /etc/pam.d/kscreenlocker ]]; then
                show_pam_diff "/etc/pam.d/kscreenlocker" "$pam_line" ""
                kde_found=true
            fi
            if [[ -f /etc/pam.d/kde-fingerprint ]]; then
                show_pam_diff "/etc/pam.d/kde-fingerprint" "$pam_line" ""
                kde_found=true
            fi
            if [[ -f /etc/pam.d/kde-smartcard ]]; then
                show_pam_diff "/etc/pam.d/kde-smartcard" "$pam_line" ""
                kde_found=true
            fi
            if [[ "$kde_found" == false ]]; then
                echo ""
                echo -e "${YELLOW}[SKIP]${NC} KDE PAM configuration"
                echo "  → No KDE PAM files found (/etc/pam.d/kde, kscreenlocker, etc.)"
            fi
        fi
        return
    fi
    
    # Configure system-auth (common on Arch-based systems, used by SDDM and lock screens)
    if [[ "$CONFIGURE_PAM_SYSTEM_AUTH" == true ]]; then
        print_info "Configuring PAM for system-auth..."
        
        if [[ -f /etc/pam.d/system-auth ]]; then
            if ! grep -q "pam_tapauth.so" /etc/pam.d/system-auth; then
                # Insert at the beginning of the auth section
                sed -i "1i $pam_line" /etc/pam.d/system-auth
                print_success "Configured PAM for system-auth"
                print_info "This covers: login, su, su-l, sudo, polkit, display managers, lock screens"
            else
                print_warning "PAM system-auth already configured"
            fi
        else
            print_warning "system-auth PAM configuration not found at /etc/pam.d/system-auth"
        fi
    fi
    
    # Only configure individual services if system-auth was NOT configured
    if [[ "$CONFIGURE_PAM_SYSTEM_AUTH" == false ]]; then
        # Configure login
        if [[ "$CONFIGURE_PAM_LOGIN" == true ]]; then
            print_info "Configuring PAM for login (console/TTY)..."
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

        # Configure su (used by `su`)
        if [[ "$CONFIGURE_PAM_SU" == true ]]; then
            local su_file="/etc/pam.d/su"
            print_info "Configuring PAM for su (root shells via 'su')..."
            if [[ -f "$su_file" ]]; then
                if ! grep -q "pam_tapauth.so" "$su_file" 2>/dev/null; then
                    if grep -q "pam_env.so" "$su_file"; then
                        sed -i "/pam_env.so/a $pam_line" "$su_file"
                    else
                        sed -i "1i $pam_line" "$su_file"
                    fi
                    print_success "Configured PAM for su"
                else
                    print_warning "PAM su already configured"
                fi
            else
                print_warning "su PAM configuration not found at $su_file"
            fi
        fi

        # Configure su-l (used by `su -`)
        if [[ "$CONFIGURE_PAM_SU_L" == true ]]; then
            local su_l_file="/etc/pam.d/su-l"
            print_info "Configuring PAM for su-l (root shells via 'su -')..."
            if [[ -f "$su_l_file" ]]; then
                if ! grep -q "pam_tapauth.so" "$su_l_file" 2>/dev/null; then
                    if grep -q "pam_env.so" "$su_l_file"; then
                        sed -i "/pam_env.so/a $pam_line" "$su_l_file"
                    else
                        sed -i "1i $pam_line" "$su_l_file"
                    fi
                    print_success "Configured PAM for su-l"
                else
                    print_warning "PAM su-l already configured"
                fi
            else
                print_warning "su-l PAM configuration not found at $su_l_file"
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
            print_info "Configuring PAM for polkit (GUI privilege elevation)..."
            
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
    fi
    
    # Configure GDM (GNOME Display Manager)
    if [[ "$CONFIGURE_PAM_GDM" == true ]]; then
        print_info "Configuring PAM for GDM (GNOME - first login)..."
        
        # GDM typically uses gdm-password for authentication
        local gdm_configured=false
        if [[ -f /etc/pam.d/gdm-password ]]; then
            if ! grep -q "pam_tapauth.so" /etc/pam.d/gdm-password; then
                sed -i "1i $pam_line" /etc/pam.d/gdm-password
                print_success "Configured PAM for GDM (gdm-password)"
                gdm_configured=true
            else
                print_warning "PAM GDM already configured (gdm-password)"
                gdm_configured=true
            fi
        fi
        
        # Some systems might use just 'gdm'
        if [[ -f /etc/pam.d/gdm ]] && [[ "$gdm_configured" == false ]]; then
            if ! grep -q "pam_tapauth.so" /etc/pam.d/gdm; then
                sed -i "1i $pam_line" /etc/pam.d/gdm
                print_success "Configured PAM for GDM"
            else
                print_warning "PAM GDM already configured"
            fi
        elif [[ "$gdm_configured" == false ]]; then
            print_warning "GDM PAM configuration not found (checked /etc/pam.d/gdm-password and /etc/pam.d/gdm)"
        fi
    fi
    
    # Configure SDDM (Simple Desktop Display Manager)
    if [[ "$CONFIGURE_PAM_SDDM" == true ]]; then
        print_info "Configuring PAM for SDDM (KDE/LXQt - first login)..."
        
        # SDDM uses /etc/pam.d/sddm for user authentication
        # Note: sddm-greeter is for the greeter UI process itself, not user auth
        if [[ -f /etc/pam.d/sddm ]]; then
            if ! grep -q "pam_tapauth.so" /etc/pam.d/sddm; then
                sed -i "1i $pam_line" /etc/pam.d/sddm
                print_success "Configured PAM for SDDM"
            else
                print_warning "PAM SDDM already configured"
            fi
        else
            print_warning "SDDM PAM configuration not found at /etc/pam.d/sddm"
        fi
    fi
    
    # Configure LightDM
    if [[ "$CONFIGURE_PAM_LIGHTDM" == true ]]; then
        print_info "Configuring PAM for LightDM (first login)..."
        
        if [[ -f /etc/pam.d/lightdm ]]; then
            if ! grep -q "pam_tapauth.so" /etc/pam.d/lightdm; then
                sed -i "1i $pam_line" /etc/pam.d/lightdm
                print_success "Configured PAM for LightDM"
            else
                print_warning "PAM LightDM already configured"
            fi
        else
            print_warning "LightDM PAM configuration not found at /etc/pam.d/lightdm"
        fi
    fi
    
    # Configure KDE (multiple PAM files)
    if [[ "$CONFIGURE_PAM_KDE" == true ]]; then
        print_info "Configuring PAM for KDE (lock screen)..."
        
        local kde_configured=false
        
        # Configure /etc/pam.d/kde
        if [[ -f /etc/pam.d/kde ]]; then
            if ! grep -q "pam_tapauth.so" /etc/pam.d/kde; then
                sed -i "1i $pam_line" /etc/pam.d/kde
                print_success "Configured PAM for KDE (kde)"
                kde_configured=true
            else
                print_warning "PAM KDE already configured (kde)"
                kde_configured=true
            fi
        fi
        
        # Configure /etc/pam.d/kscreenlocker
        if [[ -f /etc/pam.d/kscreenlocker ]]; then
            if ! grep -q "pam_tapauth.so" /etc/pam.d/kscreenlocker; then
                sed -i "1i $pam_line" /etc/pam.d/kscreenlocker
                print_success "Configured PAM for KDE screen locker (kscreenlocker)"
                kde_configured=true
            else
                print_warning "PAM KDE screen locker already configured (kscreenlocker)"
                kde_configured=true
            fi
        fi
        
        # Configure /etc/pam.d/kde-fingerprint (if it exists)
        if [[ -f /etc/pam.d/kde-fingerprint ]]; then
            if ! grep -q "pam_tapauth.so" /etc/pam.d/kde-fingerprint; then
                sed -i "1i $pam_line" /etc/pam.d/kde-fingerprint
                print_success "Configured PAM for KDE fingerprint (kde-fingerprint)"
                kde_configured=true
            else
                print_warning "PAM KDE fingerprint already configured (kde-fingerprint)"
            fi
        fi
        
        # Configure /etc/pam.d/kde-smartcard (if it exists)
        if [[ -f /etc/pam.d/kde-smartcard ]]; then
            if ! grep -q "pam_tapauth.so" /etc/pam.d/kde-smartcard; then
                sed -i "1i $pam_line" /etc/pam.d/kde-smartcard
                print_success "Configured PAM for KDE smartcard (kde-smartcard)"
                kde_configured=true
            else
                print_warning "PAM KDE smartcard already configured (kde-smartcard)"
            fi
        fi
        
        if [[ "$kde_configured" == false ]]; then
            print_warning "No KDE PAM configuration files found (checked /etc/pam.d/kde, kscreenlocker, kde-fingerprint, kde-smartcard)"
        fi
    fi
    
    # Inform about when changes take effect
    if [[ "$CONFIGURE_PAM_LOGIN" == true || "$CONFIGURE_PAM_SU" == true || "$CONFIGURE_PAM_SU_L" == true || "$CONFIGURE_PAM_SUDO" == true || "$CONFIGURE_PAM_POLKIT" == true || \
          "$CONFIGURE_PAM_SYSTEM_AUTH" == true || "$CONFIGURE_PAM_GDM" == true || "$CONFIGURE_PAM_SDDM" == true || \
          "$CONFIGURE_PAM_LIGHTDM" == true || "$CONFIGURE_PAM_KDE" == true ]]; then
        echo ""
        print_info "PAM configuration updated"
        print_info "Changes take effect:"
        if [[ "$CONFIGURE_PAM_SYSTEM_AUTH" == true ]]; then
            echo "  • system-auth: On next login session (covers login, su, su-l, sudo, polkit)"
        else
            if [[ "$CONFIGURE_PAM_SUDO" == true ]]; then
                echo "  • sudo: Immediately (no restart needed)"
            fi
            if [[ "$CONFIGURE_PAM_POLKIT" == true ]]; then
                echo "  • polkit: Immediately (no restart needed)"
            fi
            if [[ "$CONFIGURE_PAM_LOGIN" == true ]]; then
                echo "  • login: On next login session (logout/login required)"
            fi
            if [[ "$CONFIGURE_PAM_SU" == true ]]; then
                echo "  • su: Immediately (new 'su' shells)"
            fi
            if [[ "$CONFIGURE_PAM_SU_L" == true ]]; then
                echo "  • su-l: Immediately (new 'su -' shells)"
            fi
        fi
        if [[ "$CONFIGURE_PAM_GDM" == true ]]; then
            echo "  • GDM: On next login session (logout/login required)"
        fi
        if [[ "$CONFIGURE_PAM_SDDM" == true ]]; then
            echo "  • SDDM: On next login session (logout/login required)"
        fi
        if [[ "$CONFIGURE_PAM_LIGHTDM" == true ]]; then
            echo "  • LightDM: On next login session (logout/login required)"
        fi
        if [[ "$CONFIGURE_PAM_KDE" == true ]]; then
            echo "  • KDE: On next screen lock"
        fi
    fi
}

# Install configuration GUI
install_config_gui() {
    print_header "Installing Configuration GUI"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would install configuration GUI"
        echo ""
        show_file_copy "target/release/tapauth-config" "$CONFIG_GUI_PATH"
        show_command "chmod 755 $CONFIG_GUI_PATH" "Set GUI executable permissions"
        
        if [[ -d /usr/share/icons/hicolor ]]; then
            show_file_copy "client-config-gui/assets/tapauth-config.svg" "$CONFIG_ICON_PATH"
            show_command "chmod 644 $CONFIG_ICON_PATH" "Set icon permissions"
        else
            echo -e "${YELLOW}[SKIP]${NC} Desktop icon (hicolor theme doesn't exist)"
        fi
        
        if [[ -d /usr/share/applications ]]; then
            show_file_copy "client-config-gui/tapauth-config.desktop" "$CONFIG_DESKTOP_PATH"
            show_command "chmod 644 $CONFIG_DESKTOP_PATH" "Set desktop entry permissions"
        else
            echo -e "${YELLOW}[SKIP]${NC} Desktop entry (directory doesn't exist)"
        fi
        
        if [[ -d /usr/share/polkit-1/actions ]]; then
            show_file_copy "tapauthd/dev.rourunisen.tapauth.config.admin.policy" "$CONFIG_POLICY_PATH"
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
    
    # Restore SELinux context if available
    if command -v restorecon &> /dev/null; then
        restorecon "$CONFIG_GUI_PATH" || true
    fi
    
    # Install desktop icon
    if [[ -d /usr/share/icons/hicolor ]]; then
        print_info "Installing desktop icon"
        cp client-config-gui/assets/tapauth-config.svg "$CONFIG_ICON_PATH"
        chmod 644 "$CONFIG_ICON_PATH"
        
        if command -v gtk-update-icon-cache &> /dev/null; then
            gtk-update-icon-cache -f /usr/share/icons/hicolor
        fi
    fi
    
    # Install desktop entry
    if [[ -d /usr/share/applications ]]; then
        print_info "Installing desktop entry"
        cp client-config-gui/tapauth-config.desktop "$CONFIG_DESKTOP_PATH"
        chmod 644 "$CONFIG_DESKTOP_PATH"
    fi
    
    # Install polkit policy
    if [[ -d /usr/share/polkit-1/actions ]]; then
        print_info "Installing polkit policy"
        cp tapauthd/dev.rourunisen.tapauth.config.admin.policy "$CONFIG_POLICY_PATH"
        chmod 644 "$CONFIG_POLICY_PATH"
    fi
    
    print_success "Configuration GUI installed"
}

# Install uninstaller script for this version
install_uninstaller() {
    print_header "Installing Uninstaller"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would install uninstaller script"
        echo ""
        show_command "mkdir -p $(dirname $UNINSTALL_SCRIPT_DEST)" "Create uninstaller directory"
        show_file_copy "$UNINSTALL_SCRIPT_SOURCE" "$UNINSTALL_SCRIPT_DEST"
        show_command "chmod 755 $UNINSTALL_SCRIPT_DEST" "Set uninstaller executable permissions"
        return
    fi
    
    if [[ ! -f "$UNINSTALL_SCRIPT_SOURCE" ]]; then
        print_warning "Uninstaller script not found at $UNINSTALL_SCRIPT_SOURCE"
        print_warning "Skipping uninstaller installation"
        return
    fi
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$UNINSTALL_SCRIPT_DEST")"
    
    print_info "Installing uninstaller to $UNINSTALL_SCRIPT_DEST"
    cp "$UNINSTALL_SCRIPT_SOURCE" "$UNINSTALL_SCRIPT_DEST"
    chmod 755 "$UNINSTALL_SCRIPT_DEST"
    
    print_success "Uninstaller installed"
    print_info "To uninstall TapAuth, run: sudo $UNINSTALL_SCRIPT_DEST"
}

# Create installation summary
create_summary() {
    print_header "Installation Summary"
    
    echo "Components installed:"
    echo "  ✓ Daemon"
    echo "  ✓ PAM module"
    echo "  ✓ Configuration GUI"
    
    echo ""
    echo "PAM configuration:"
    if [[ "$CONFIGURE_PAM_SYSTEM_AUTH" == true ]]; then
        echo "  ✓ System-auth (covers login, su, su-l, sudo, polkit)"
        echo "  ○ Login (covered by system-auth)"
        echo "  ○ su (covered by system-auth)"
        echo "  ○ su-l (covered by system-auth)"
        echo "  ○ Sudo (covered by system-auth)"
        echo "  ○ Polkit (covered by system-auth)"
    else
        echo "  ✗ System-auth"
        [[ "$CONFIGURE_PAM_LOGIN" == true ]] && echo "  ✓ Login (console/TTY)" || echo "  ✗ Login"
        [[ "$CONFIGURE_PAM_SU" == true ]] && echo "  ✓ su (root shells via su)" || echo "  ✗ su"
        [[ "$CONFIGURE_PAM_SU_L" == true ]] && echo "  ✓ su-l (root shells via su -)" || echo "  ✗ su-l"
        [[ "$CONFIGURE_PAM_SUDO" == true ]] && echo "  ✓ Sudo" || echo "  ✗ Sudo"
        [[ "$CONFIGURE_PAM_POLKIT" == true ]] && echo "  ✓ Polkit (GUI privilege elevation)" || echo "  ✗ Polkit"
    fi
    echo ""
    echo "Display managers & lock screens:"
    [[ "$CONFIGURE_PAM_GDM" == true ]] && echo "  ✓ GDM (GNOME - first login)" || echo "  ✗ GDM"
    [[ "$CONFIGURE_PAM_SDDM" == true ]] && echo "  ✓ SDDM (KDE/LXQt - first login)" || echo "  ✗ SDDM"
    [[ "$CONFIGURE_PAM_LIGHTDM" == true ]] && echo "  ✓ LightDM (first login)" || echo "  ✗ LightDM"
    [[ "$CONFIGURE_PAM_KDE" == true ]] && echo "  ✓ KDE (lock screen)" || echo "  ✗ KDE"
    
    echo ""
    echo "Features enabled:"
    [[ "$USE_BLE" == true ]] && echo "  ✓ Bluetooth (direct BlueZ)" || echo "  ✗ Bluetooth (UDP only)"
    [[ "$USE_TPM" == true ]] && echo "  ✓ TPM support" || echo "  ✗ TPM support"
    
    echo ""
    print_info "Installation locations:"
    echo "  - Daemon: /usr/bin/tapauthd"
    echo "  - PAM module: $PAM_SO_PATH"
    echo "  - Config GUI: $CONFIG_GUI_PATH"
    echo "  - Configuration: $CONFIG_DIR"
    echo "  - Daemon socket: /run/tapauthd/tapauthd.sock (root:tapauthd-clients, 0660)"
    echo ""
    echo "Distribution: $DISTRO_NAME"
    
    echo ""
    print_success "Installation complete!"
    
    echo ""
    print_info "Next steps:"
    echo "  1. Log out and back in (or run 'newgrp tapauthd-clients') for group membership to take effect"
    echo "  2. Run 'tapauth-config' to pair with your phone"
    echo "  3. Test authentication in a separate terminal"
    echo "  4. Keep a root shell open until you verify it works"
    
    echo ""
    print_info "Uninstallation:"
    echo "  To uninstall TapAuth, run: sudo $UNINSTALL_SCRIPT_DEST"
    
    # Check if SELinux is enabled and provide guidance
    if command -v getenforce &> /dev/null && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
        echo ""
        print_warning "SELinux is enabled in Enforcing mode"
        print_info "If you're using SDDM or other display managers, you may need to configure SELinux:"
        echo "  • See docs/SELINUX.md for detailed instructions"
        echo "  • Quick fix: sudo ausearch -m avc -ts recent | grep tapauthd | audit2allow -M tapauth_sddm && sudo semodule -i tapauth_sddm.pp"
    fi
    
    if [[ "$CONFIGURE_PAM_LOGIN" == true || "$CONFIGURE_PAM_SU" == true || "$CONFIGURE_PAM_SU_L" == true || "$CONFIGURE_PAM_SUDO" == true ]]; then
        echo ""
        print_warning "IMPORTANT: Before logging out:"
        echo "  - Verify authentication works in a separate terminal"
        echo "  - Keep a root shell open as backup"
        if [[ "$CONFIGURE_PAM_SUDO" == true ]]; then
            echo "  - Test sudo now: 'sudo -k && sudo echo test' (works immediately)"
        fi
        if [[ "$CONFIGURE_PAM_SU" == true ]]; then
            echo "  - Test 'su' in another terminal to confirm su works"
        fi
        if [[ "$CONFIGURE_PAM_SU_L" == true ]]; then
            echo "  - Test 'su -' in another terminal to confirm su-l works"
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
        prompt_features
        prompt_pam_configuration
        
        echo ""
        read -p "Proceed with installation? [y/N]: " response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            print_info "Installation cancelled"
            exit 0
        fi
    fi
    
    check_prerequisites
    check_existing_installation
    build_components
    
    if [[ "$BUILD_ONLY" == true ]]; then
        print_success "Build complete (--build-only specified)"
        exit 0
    fi
    
    create_system_users
    create_initial_config
    install_daemon
    install_pam
    configure_pam
    install_config_gui
    install_uninstaller
    install_systemd_units
    
    # Restore SELinux contexts if available
    if command -v restorecon &> /dev/null; then
        print_info "Restoring SELinux contexts"
        restorecon -RF /var/lib/tapauth || true
        restorecon -RF /var/log/tapauth || true
        restorecon -RF /run/tapauthd || true
        restorecon /run/tapauthd/tapauthd.sock || true
        # Also restore contexts for all installed binaries
        restorecon "$DAEMON_PATH" || true
        restorecon "$PAM_SO_PATH" || true
        restorecon "$CONFIG_GUI_PATH" || true
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        echo ""
        print_header "Dry Run Summary"
        echo "The following changes would be made:"
        echo ""
        echo "Components to install:"
        echo "  ✓ Daemon → /usr/bin/tapauthd"
        echo "  ✓ PAM module → $PAM_SO_PATH"
        echo "  ✓ Configuration GUI → $CONFIG_GUI_PATH"
        
        echo ""
        echo "PAM services to configure:"
        [[ "$CONFIGURE_PAM_LOGIN" == true ]] && echo "  ✓ Login (/etc/pam.d/login)" || echo "  ✗ Login (skipped)"
        [[ "$CONFIGURE_PAM_SUDO" == true ]] && echo "  ✓ Sudo (/etc/pam.d/sudo)" || echo "  ✗ Sudo (skipped)"
        [[ "$REMOVE_PAM_CONFIG_POLKIT" == true ]] && echo "  ✓ Polkit (/etc/pam.d/polkit-1)" || echo "  ✗ Polkit (skipped)"
        [[ "$CONFIGURE_PAM_SYSTEM_AUTH" == true ]] && echo "  ✓ System-auth (/etc/pam.d/system-auth)" || echo "  ✗ System-auth (skipped)"
        [[ "$CONFIGURE_PAM_GDM" == true ]] && echo "  ✓ GDM (/etc/pam.d/gdm-password)" || echo "  ✗ GDM (skipped)"
        [[ "$CONFIGURE_PAM_SDDM" == true ]] && echo "  ✓ SDDM (/etc/pam.d/sddm-greeter)" || echo "  ✗ SDDM (skipped)"
        [[ "$CONFIGURE_PAM_LIGHTDM" == true ]] && echo "  ✓ LightDM (/etc/pam.d/lightdm)" || echo "  ✗ LightDM (skipped)"
        
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
