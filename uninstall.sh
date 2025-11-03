#!/bin/bash
set -e

# TapAuth Interactive Uninstallation Script
# This script removes all TapAuth components and optionally their configurations

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
INTERACTIVE=true
# All components are always removed
REMOVE_PAM=true
REMOVE_CONFIG_GUI=true
REMOVE_DAEMON=true
# Only PAM configuration locations and user data are configurable
REMOVE_PAM_CONFIG_LOGIN=false
REMOVE_PAM_CONFIG_SUDO=false
REMOVE_PAM_CONFIG_POLKIT=false
REMOVE_PAM_CONFIG_SYSTEM_AUTH=false
REMOVE_PAM_CONFIG_GDM=false
REMOVE_PAM_CONFIG_SDDM=false
REMOVE_PAM_CONFIG_LIGHTDM=false
REMOVE_PAM_CONFIG_KDE=false
REMOVE_USER_DATA=false
DRY_RUN=false

# Installation paths (some will be detected at runtime)
PAM_MODULE_DIR=""  # Will be detected based on distribution
PAM_SO_NAME="pam_tapauth.so"
PAM_SO_PATH=""  # Will be set after detection
CONFIG_GUI_PATH="/usr/bin/tapauth-config"
CONFIG_DESKTOP_PATH="/usr/share/applications/tapauth-config.desktop"
CONFIG_POLICY_PATH="/usr/share/polkit-1/actions/dev.rourunisen.tapauth.policy"
CONFIG_DIR="/var/lib/tapauth"
DAEMON_PATH="/usr/bin/tapauthd"
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
show_file_removal() {
    local file="$1"
    local description="$2"
    if [[ -f "$file" ]] || [[ -d "$file" ]]; then
        echo -e "${RED}[REMOVE]${NC} $file"
        [[ -n "$description" ]] && echo "  → $description"
    else
        echo -e "${YELLOW}[SKIP]${NC} $file (does not exist)"
    fi
}

show_command() {
    local cmd="$1"
    local description="$2"
    echo -e "${BLUE}[EXEC]${NC} $cmd"
    [[ -n "$description" ]] && echo "  → $description"
}

show_pam_restore_diff() {
    local pam_file="$1"
    
    echo ""
    echo -e "${YELLOW}[DIFF]${NC} $pam_file"
    
    if [[ ! -f "$pam_file" ]]; then
        echo -e "  ${GREEN}File does not exist - no changes needed${NC}"
        return
    fi
    
    if ! grep -q "pam_tapauth.so" "$pam_file" 2>/dev/null; then
        echo -e "  ${GREEN}TapAuth not configured - no changes needed${NC}"
        return
    fi
    
    echo "  Changes to be made (remove TapAuth line):"
    echo "  ---"
    grep -n "pam_tapauth.so" "$pam_file" | while IFS=: read -r linenum line; do
        echo -e "  ${RED}-${NC} $linenum: $line"
    done
    echo "  ---"
}

# Usage information
usage() {
    cat << EOF
TapAuth Uninstallation Script

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -n, --non-interactive   Run in non-interactive mode
    -y, --yes               Answer yes to all prompts (implies --non-interactive)
    --remove-pam-login      Remove PAM login configuration
    --remove-pam-sudo       Remove PAM sudo configuration
    --remove-pam-polkit     Remove PAM polkit configuration
    --remove-pam-system-auth Remove PAM system-auth configuration
    --remove-pam-gdm        Remove PAM GDM configuration
    --remove-pam-sddm       Remove PAM SDDM configuration
    --remove-pam-lightdm    Remove PAM LightDM configuration
    --remove-pam-kde        Remove PAM KDE configuration
    --remove-user-data      Remove user configuration data (keys, pairings)
    --dry-run               Show what would be done without doing it

NOTES:
    All components (daemon, PAM module, configuration GUI) are always removed.
    Only PAM configuration locations and user data removal are configurable.

EXAMPLES:
    # Interactive uninstallation (default)
    sudo $0

    # Non-interactive removal of everything including configs
    sudo $0 --yes

    # Dry run to see what would be removed
    sudo $0 --dry-run --yes

EOF
}

# Stop and disable systemd units, then remove unit files and daemon
remove_systemd_units_and_daemon() {
    print_header "Removing Daemon and Systemd Units"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would stop and disable systemd units"
        show_command "systemctl stop tapauthd.socket tapauthd.service" "Stop daemon and socket"
        show_command "systemctl disable tapauthd.socket tapauthd.service" "Disable units"
        show_file_removal "$SOCKET_UNIT_DEST" "Socket unit file"
        show_file_removal "$SERVICE_UNIT_DEST" "Service unit file"
        show_command "systemctl daemon-reload" "Reload systemd units"
        show_file_removal "$DAEMON_PATH" "TapAuth daemon binary"
        show_file_removal "/run/tapauthd/tapauthd.sock" "Runtime socket (if present)"
        return
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop tapauthd.socket tapauthd.service >/dev/null 2>&1 || true
        systemctl disable tapauthd.socket tapauthd.service >/dev/null 2>&1 || true
    fi

    # Remove unit files if present
    [[ -f "$SOCKET_UNIT_DEST" ]] && rm -f "$SOCKET_UNIT_DEST"
    [[ -f "$SERVICE_UNIT_DEST" ]] && rm -f "$SERVICE_UNIT_DEST"

    # Reload systemd to pick up removals
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi

    # Remove daemon binary
    if [[ -f "$DAEMON_PATH" ]]; then
        print_info "Removing daemon binary at $DAEMON_PATH"
        rm -f "$DAEMON_PATH"
    fi

    # Clean up stale socket if any
    if [[ -S "/run/tapauthd/tapauthd.sock" ]]; then
        rm -f /run/tapauthd/tapauthd.sock || true
    fi

    print_success "Daemon and systemd units removed (if present)"
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
                REMOVE_PAM_CONFIG_LOGIN=true
                REMOVE_PAM_CONFIG_SUDO=true
                REMOVE_PAM_CONFIG_POLKIT=true
                REMOVE_PAM_CONFIG_SYSTEM_AUTH=true
                REMOVE_PAM_CONFIG_GDM=true
                REMOVE_PAM_CONFIG_SDDM=true
                REMOVE_PAM_CONFIG_LIGHTDM=true
                REMOVE_PAM_CONFIG_KDE=true
                REMOVE_USER_DATA=true
                shift
                ;;
            --remove-pam-login)
                REMOVE_PAM_CONFIG_LOGIN=true
                shift
                ;;
            --remove-pam-sudo)
                REMOVE_PAM_CONFIG_SUDO=true
                shift
                ;;
            --remove-pam-polkit)
                REMOVE_PAM_CONFIG_POLKIT=true
                shift
                ;;
            --remove-pam-system-auth)
                REMOVE_PAM_CONFIG_SYSTEM_AUTH=true
                shift
                ;;
            --remove-pam-gdm)
                REMOVE_PAM_CONFIG_GDM=true
                shift
                ;;
            --remove-pam-sddm)
                REMOVE_PAM_CONFIG_SDDM=true
                shift
                ;;
            --remove-pam-lightdm)
                REMOVE_PAM_CONFIG_LIGHTDM=true
                shift
                ;;
            --remove-pam-kde)
                REMOVE_PAM_CONFIG_KDE=true
                shift
                ;;
            --remove-user-data)
                REMOVE_USER_DATA=true
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
prompt_pam_configuration() {
    print_header "PAM Configuration Removal"
    
    print_info "All components (daemon, PAM module, configuration GUI) will be removed."
    echo ""
    
    # Check which PAM files have TapAuth configured
    local has_login=false
    local has_sudo=false
    local has_polkit=false
    local has_system_auth=false
    local has_gdm=false
    local has_sddm=false
    local has_lightdm=false
    local has_kde=false
    
    if [[ -f /etc/pam.d/login ]] && grep -q "pam_tapauth.so" /etc/pam.d/login 2>/dev/null; then
        has_login=true
    fi
    
    if [[ -f /etc/pam.d/sudo ]] && grep -q "pam_tapauth.so" /etc/pam.d/sudo 2>/dev/null; then
        has_sudo=true
    fi
    
    # Check both /etc/pam.d and /usr/lib/pam.d for polkit config
    if ([[ -f /etc/pam.d/polkit-1 ]] && grep -q "pam_tapauth.so" /etc/pam.d/polkit-1 2>/dev/null) || \
       ([[ -f /usr/lib/pam.d/polkit-1 ]] && grep -q "pam_tapauth.so" /usr/lib/pam.d/polkit-1 2>/dev/null); then
        has_polkit=true
    fi
    
    # Check for system-auth
    if [[ -f /etc/pam.d/system-auth ]] && grep -q "pam_tapauth.so" /etc/pam.d/system-auth 2>/dev/null; then
        has_system_auth=true
    fi
    
    # Check for GDM
    if ([[ -f /etc/pam.d/gdm-password ]] && grep -q "pam_tapauth.so" /etc/pam.d/gdm-password 2>/dev/null) || \
       ([[ -f /etc/pam.d/gdm ]] && grep -q "pam_tapauth.so" /etc/pam.d/gdm 2>/dev/null); then
        has_gdm=true
    fi
    
    # Check for SDDM (uses /etc/pam.d/sddm for user authentication)
    if [[ -f /etc/pam.d/sddm ]] && grep -q "pam_tapauth.so" /etc/pam.d/sddm 2>/dev/null; then
        has_sddm=true
    fi
    
    # Check for LightDM
    if [[ -f /etc/pam.d/lightdm ]] && grep -q "pam_tapauth.so" /etc/pam.d/lightdm 2>/dev/null; then
        has_lightdm=true
    fi
    
    # Check for KDE (multiple PAM files)
    if ([[ -f /etc/pam.d/kde ]] && grep -q "pam_tapauth.so" /etc/pam.d/kde 2>/dev/null) || \
       ([[ -f /etc/pam.d/kscreenlocker ]] && grep -q "pam_tapauth.so" /etc/pam.d/kscreenlocker 2>/dev/null) || \
       ([[ -f /etc/pam.d/kde-fingerprint ]] && grep -q "pam_tapauth.so" /etc/pam.d/kde-fingerprint 2>/dev/null) || \
       ([[ -f /etc/pam.d/kde-smartcard ]] && grep -q "pam_tapauth.so" /etc/pam.d/kde-smartcard 2>/dev/null); then
        has_kde=true
    fi
    
    if [[ "$has_login" == true ]]; then
        read -p "Remove TapAuth from login PAM configuration? [Y/n]: " response
        [[ ! "$response" =~ ^[Nn]$ ]] && REMOVE_PAM_CONFIG_LOGIN=true || REMOVE_PAM_CONFIG_LOGIN=false
    fi
    
    if [[ "$has_sudo" == true ]]; then
        read -p "Remove TapAuth from sudo PAM configuration? [Y/n]: " response
        [[ ! "$response" =~ ^[Nn]$ ]] && REMOVE_PAM_CONFIG_SUDO=true || REMOVE_PAM_CONFIG_SUDO=false
    fi
    
    if [[ "$has_polkit" == true ]]; then
        read -p "Remove TapAuth from polkit PAM configuration? [Y/n]: " response
        [[ ! "$response" =~ ^[Nn]$ ]] && REMOVE_PAM_CONFIG_POLKIT=true || REMOVE_PAM_CONFIG_POLKIT=false
    fi
    
    if [[ "$has_system_auth" == true ]]; then
        read -p "Remove TapAuth from system-auth PAM configuration? [Y/n]: " response
        [[ ! "$response" =~ ^[Nn]$ ]] && REMOVE_PAM_CONFIG_SYSTEM_AUTH=true || REMOVE_PAM_CONFIG_SYSTEM_AUTH=false
    fi
    
    if [[ "$has_gdm" == true ]]; then
        read -p "Remove TapAuth from GDM PAM configuration? [Y/n]: " response
        [[ ! "$response" =~ ^[Nn]$ ]] && REMOVE_PAM_CONFIG_GDM=true || REMOVE_PAM_CONFIG_GDM=false
    fi
    
    if [[ "$has_sddm" == true ]]; then
        read -p "Remove TapAuth from SDDM PAM configuration? [Y/n]: " response
        [[ ! "$response" =~ ^[Nn]$ ]] && REMOVE_PAM_CONFIG_SDDM=true || REMOVE_PAM_CONFIG_SDDM=false
    fi
    
    if [[ "$has_lightdm" == true ]]; then
        read -p "Remove TapAuth from LightDM PAM configuration? [Y/n]: " response
        [[ ! "$response" =~ ^[Nn]$ ]] && REMOVE_PAM_CONFIG_LIGHTDM=true || REMOVE_PAM_CONFIG_LIGHTDM=false
    fi
    
    if [[ "$has_kde" == true ]]; then
        read -p "Remove TapAuth from KDE PAM configuration? [Y/n]: " response
        [[ ! "$response" =~ ^[Nn]$ ]] && REMOVE_PAM_CONFIG_KDE=true || REMOVE_PAM_CONFIG_KDE=false
    fi
}

prompt_user_data() {
    print_header "User Data Removal"
    
    print_warning "This will remove:"
    echo "  - Encryption keys"
    echo "  - Device pairings"
    echo "  - User configuration"
    echo ""
    
    read -p "Remove all user data and configuration? [y/N]: " response
    [[ "$response" =~ ^[Yy]$ ]] && REMOVE_USER_DATA=true || REMOVE_USER_DATA=false
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
    
    # First, try to find where our PAM module is actually installed
    for dir in "${pam_dirs[@]}"; do
        if [[ -f "$dir/$PAM_SO_NAME" ]]; then
            PAM_MODULE_DIR="$dir"
            PAM_SO_PATH="$dir/$PAM_SO_NAME"
            print_success "Found TapAuth PAM module at: $PAM_SO_PATH"
            return
        fi
    done
    
    # If not found, just check for existing PAM directories for error reporting
    for dir in "${pam_dirs[@]}"; do
        if [[ -d "$dir" ]] && [[ -r "$dir" ]]; then
            if ls "$dir"/pam_*.so &> /dev/null; then
                PAM_MODULE_DIR="$dir"
                PAM_SO_PATH="$dir/$PAM_SO_NAME"
                print_warning "PAM directory found at $PAM_MODULE_DIR but TapAuth module not installed"
                return
            fi
        fi
    done
    
    print_warning "Could not find PAM module directory or TapAuth installation"
}

# Check if running as root
check_root() {
    if [[ "$DRY_RUN" == false && $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        print_info "Run with --dry-run to simulate uninstallation without root"
        exit 1
    fi
    
    # Always detect PAM directory
    detect_pam_directory
}

# Remove PAM configuration
remove_pam_config() {
    if [[ "$REMOVE_PAM_CONFIG_LOGIN" == false && "$REMOVE_PAM_CONFIG_SUDO" == false && "$REMOVE_PAM_CONFIG_POLKIT" == false && \
          "$REMOVE_PAM_CONFIG_SYSTEM_AUTH" == false && "$REMOVE_PAM_CONFIG_GDM" == false && "$REMOVE_PAM_CONFIG_SDDM" == false && \
          "$REMOVE_PAM_CONFIG_LIGHTDM" == false && "$REMOVE_PAM_CONFIG_KDE" == false ]]; then
        return
    fi
    
    print_header "Removing PAM Configuration"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would remove PAM configuration"
        echo ""
        
        if [[ "$REMOVE_PAM_CONFIG_LOGIN" == true ]]; then
            show_pam_restore_diff "/etc/pam.d/login"
        fi
        
        if [[ "$REMOVE_PAM_CONFIG_SUDO" == true ]]; then
            show_pam_restore_diff "/etc/pam.d/sudo"
        fi
        
        if [[ "$REMOVE_PAM_CONFIG_POLKIT" == true ]]; then
            # Check both possible polkit locations
            if [[ -f /etc/pam.d/polkit-1 ]]; then
                show_pam_restore_diff "/etc/pam.d/polkit-1"
            elif [[ -f /usr/lib/pam.d/polkit-1 ]]; then
                show_pam_restore_diff "/usr/lib/pam.d/polkit-1"
            fi
        fi
        
        if [[ "$REMOVE_PAM_CONFIG_SYSTEM_AUTH" == true ]]; then
            if [[ -f /etc/pam.d/system-auth ]]; then
                show_pam_restore_diff "/etc/pam.d/system-auth"
            fi
        fi
        
        if [[ "$REMOVE_PAM_CONFIG_GDM" == true ]]; then
            if [[ -f /etc/pam.d/gdm-password ]]; then
                show_pam_restore_diff "/etc/pam.d/gdm-password"
            elif [[ -f /etc/pam.d/gdm ]]; then
                show_pam_restore_diff "/etc/pam.d/gdm"
            fi
        fi
        
        if [[ "$REMOVE_PAM_CONFIG_SDDM" == true ]]; then
            # SDDM uses /etc/pam.d/sddm for user authentication
            if [[ -f /etc/pam.d/sddm ]]; then
                show_pam_restore_diff "/etc/pam.d/sddm"
            fi
        fi
        
        if [[ "$REMOVE_PAM_CONFIG_LIGHTDM" == true ]]; then
            if [[ -f /etc/pam.d/lightdm ]]; then
                show_pam_restore_diff "/etc/pam.d/lightdm"
            fi
        fi
        
        if [[ "$REMOVE_PAM_CONFIG_KDE" == true ]]; then
            # KDE uses multiple PAM files
            if [[ -f /etc/pam.d/kde ]]; then
                show_pam_restore_diff "/etc/pam.d/kde"
            fi
            if [[ -f /etc/pam.d/kscreenlocker ]]; then
                show_pam_restore_diff "/etc/pam.d/kscreenlocker"
            fi
            if [[ -f /etc/pam.d/kde-fingerprint ]]; then
                show_pam_restore_diff "/etc/pam.d/kde-fingerprint"
            fi
            if [[ -f /etc/pam.d/kde-smartcard ]]; then
                show_pam_restore_diff "/etc/pam.d/kde-smartcard"
            fi
        fi
        return
    fi
    
    # Remove from login
    if [[ "$REMOVE_PAM_CONFIG_LOGIN" == true ]]; then
        if [[ -f /etc/pam.d/login ]] && grep -q "pam_tapauth.so" /etc/pam.d/login 2>/dev/null; then
            print_info "Removing TapAuth from login PAM configuration"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/login
            print_success "Removed from login"
        fi
    fi
    
    # Remove from sudo
    if [[ "$REMOVE_PAM_CONFIG_SUDO" == true ]]; then
        if [[ -f /etc/pam.d/sudo ]] && grep -q "pam_tapauth.so" /etc/pam.d/sudo 2>/dev/null; then
            print_info "Removing TapAuth from sudo PAM configuration"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/sudo
            print_success "Removed from sudo"
        fi
    fi
    
    # Remove from polkit
    if [[ "$REMOVE_PAM_CONFIG_POLKIT" == true ]]; then
        # Check both /etc/pam.d and /usr/lib/pam.d for polkit config
        local polkit_removed=false
        
        if [[ -f /etc/pam.d/polkit-1 ]] && grep -q "pam_tapauth.so" /etc/pam.d/polkit-1 2>/dev/null; then
            print_info "Removing TapAuth from polkit PAM configuration (/etc/pam.d/polkit-1)"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/polkit-1
            polkit_removed=true
        fi
        
        if [[ -f /usr/lib/pam.d/polkit-1 ]] && grep -q "pam_tapauth.so" /usr/lib/pam.d/polkit-1 2>/dev/null; then
            print_info "Removing TapAuth from polkit PAM configuration (/usr/lib/pam.d/polkit-1)"
            sed -i '/pam_tapauth\.so/d' /usr/lib/pam.d/polkit-1
            polkit_removed=true
        fi
        
        if [[ "$polkit_removed" == true ]]; then
            print_success "Removed from polkit"
        fi
    fi
    
    # Remove from system-auth
    if [[ "$REMOVE_PAM_CONFIG_SYSTEM_AUTH" == true ]]; then
        if [[ -f /etc/pam.d/system-auth ]] && grep -q "pam_tapauth.so" /etc/pam.d/system-auth 2>/dev/null; then
            print_info "Removing TapAuth from system-auth PAM configuration"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/system-auth
            print_success "Removed from system-auth"
        fi
    fi
    
    # Remove from GDM
    if [[ "$REMOVE_PAM_CONFIG_GDM" == true ]]; then
        local gdm_removed=false
        
        if [[ -f /etc/pam.d/gdm-password ]] && grep -q "pam_tapauth.so" /etc/pam.d/gdm-password 2>/dev/null; then
            print_info "Removing TapAuth from GDM PAM configuration (/etc/pam.d/gdm-password)"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/gdm-password
            gdm_removed=true
        fi
        
        if [[ -f /etc/pam.d/gdm ]] && grep -q "pam_tapauth.so" /etc/pam.d/gdm 2>/dev/null; then
            print_info "Removing TapAuth from GDM PAM configuration (/etc/pam.d/gdm)"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/gdm
            gdm_removed=true
        fi
        
        if [[ "$gdm_removed" == true ]]; then
            print_success "Removed from GDM"
        fi
    fi
    
    # Remove from SDDM
    if [[ "$REMOVE_PAM_CONFIG_SDDM" == true ]]; then
        # SDDM uses /etc/pam.d/sddm for user authentication
        if [[ -f /etc/pam.d/sddm ]] && grep -q "pam_tapauth.so" /etc/pam.d/sddm 2>/dev/null; then
            print_info "Removing TapAuth from SDDM PAM configuration"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/sddm
            print_success "Removed from SDDM"
        fi
    fi
    
    # Remove from LightDM
    if [[ "$REMOVE_PAM_CONFIG_LIGHTDM" == true ]]; then
        if [[ -f /etc/pam.d/lightdm ]] && grep -q "pam_tapauth.so" /etc/pam.d/lightdm 2>/dev/null; then
            print_info "Removing TapAuth from LightDM PAM configuration"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/lightdm
            print_success "Removed from LightDM"
        fi
    fi
    
    # Remove from KDE (multiple PAM files)
    if [[ "$REMOVE_PAM_CONFIG_KDE" == true ]]; then
        local kde_removed=false
        
        # Remove from /etc/pam.d/kde
        if [[ -f /etc/pam.d/kde ]] && grep -q "pam_tapauth.so" /etc/pam.d/kde 2>/dev/null; then
            print_info "Removing TapAuth from KDE PAM configuration (/etc/pam.d/kde)"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/kde
            kde_removed=true
        fi
        
        # Remove from /etc/pam.d/kscreenlocker
        if [[ -f /etc/pam.d/kscreenlocker ]] && grep -q "pam_tapauth.so" /etc/pam.d/kscreenlocker 2>/dev/null; then
            print_info "Removing TapAuth from KDE screen locker PAM configuration (/etc/pam.d/kscreenlocker)"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/kscreenlocker
            kde_removed=true
        fi
        
        # Remove from /etc/pam.d/kde-fingerprint
        if [[ -f /etc/pam.d/kde-fingerprint ]] && grep -q "pam_tapauth.so" /etc/pam.d/kde-fingerprint 2>/dev/null; then
            print_info "Removing TapAuth from KDE fingerprint PAM configuration (/etc/pam.d/kde-fingerprint)"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/kde-fingerprint
            kde_removed=true
        fi
        
        # Remove from /etc/pam.d/kde-smartcard
        if [[ -f /etc/pam.d/kde-smartcard ]] && grep -q "pam_tapauth.so" /etc/pam.d/kde-smartcard 2>/dev/null; then
            print_info "Removing TapAuth from KDE smartcard PAM configuration (/etc/pam.d/kde-smartcard)"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/kde-smartcard
            kde_removed=true
        fi
        
        if [[ "$kde_removed" == true ]]; then
            print_success "Removed from KDE"
        fi
    fi
}

# Remove PAM module
remove_pam() {
    print_header "Removing PAM Module"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would remove PAM module"
        echo ""
        
        if [[ -n "$PAM_SO_PATH" ]]; then
            show_file_removal "$PAM_SO_PATH" "TapAuth PAM module"
        else
            # Check all possible locations
            local pam_dirs=(
                "/lib/x86_64-linux-gnu/security"
                "/usr/lib/x86_64-linux-gnu/security"
                "/lib64/security"
                "/usr/lib64/security"
                "/usr/lib/security"
                "/lib/security"
            )
            local found_any=false
            for dir in "${pam_dirs[@]}"; do
                if [[ -f "$dir/$PAM_SO_NAME" ]]; then
                    show_file_removal "$dir/$PAM_SO_NAME" "TapAuth PAM module"
                    found_any=true
                fi
            done
            if [[ "$found_any" == false ]]; then
                echo -e "${GREEN}[INFO]${NC} No PAM module found to remove"
            fi
        fi
        return
    fi
    
    local found=false
    
    # Try the detected path first
    if [[ -n "$PAM_SO_PATH" && -f "$PAM_SO_PATH" ]]; then
        print_info "Removing PAM module from $PAM_SO_PATH"
        rm -f "$PAM_SO_PATH"
        found=true
    fi
    
    # Also check all possible locations to be thorough
    local pam_dirs=(
        "/lib/x86_64-linux-gnu/security"
        "/usr/lib/x86_64-linux-gnu/security"
        "/lib64/security"
        "/usr/lib64/security"
        "/usr/lib/security"
        "/lib/security"
    )
    
    for dir in "${pam_dirs[@]}"; do
        if [[ -f "$dir/$PAM_SO_NAME" ]]; then
            print_info "Removing PAM module from $dir/$PAM_SO_NAME"
            rm -f "$dir/$PAM_SO_NAME"
            found=true
        fi
    done
    
    if [[ "$found" == true ]]; then
        print_success "PAM module removed"
    else
        print_warning "PAM module not found (may already be uninstalled)"
    fi
}

# Remove configuration GUI
remove_config_gui() {
    print_header "Removing Configuration GUI"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would remove configuration GUI"
        echo ""
        show_file_removal "$CONFIG_GUI_PATH" "Configuration GUI binary"
        show_file_removal "$CONFIG_DESKTOP_PATH" "Desktop entry"
        show_file_removal "$CONFIG_POLICY_PATH" "Polkit policy"
        return
    fi
    
    # Remove binary
    if [[ -f "$CONFIG_GUI_PATH" ]]; then
        print_info "Removing configuration GUI binary"
        rm -f "$CONFIG_GUI_PATH"
    fi
    
    # Remove desktop entry
    if [[ -f "$CONFIG_DESKTOP_PATH" ]]; then
        print_info "Removing desktop entry"
        rm -f "$CONFIG_DESKTOP_PATH"
    fi
    
    # Remove polkit policy
    if [[ -f "$CONFIG_POLICY_PATH" ]]; then
        print_info "Removing polkit policy"
        rm -f "$CONFIG_POLICY_PATH"
    fi
    
    print_success "Configuration GUI removed"
}

# Remove user data
remove_user_data() {
    if [[ "$REMOVE_USER_DATA" == false ]]; then
        return
    fi
    
    print_header "Removing User Data"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would remove user data"
        echo ""
        show_file_removal "$CONFIG_DIR" "System configuration directory (contains keys and config)"
        
        # Check for user-specific configs
        for home_dir in /home/*; do
            if [[ -d "$home_dir/.config/tapauth" ]]; then
                show_file_removal "$home_dir/.config/tapauth" "User-specific configuration"
            fi
        done
        return
    fi
    
    if [[ -d "$CONFIG_DIR" ]]; then
        print_warning "Removing all user data from $CONFIG_DIR"
        rm -rf "$CONFIG_DIR"
        print_success "User data removed"
    else
        print_info "No user data found"
    fi
    
    # Also check for user-specific configs in home directories
    local user_configs_found=false
    for home_dir in /home/*; do
        if [[ -d "$home_dir/.config/tapauth" ]]; then
            user_configs_found=true
            local username=$(basename "$home_dir")
            print_info "Found user configuration for $username"
            rm -rf "$home_dir/.config/tapauth"
        fi
    done
    
    if [[ "$user_configs_found" == true ]]; then
        print_success "User-specific configurations removed"
    fi
}

# Create uninstallation summary
create_summary() {
    print_header "Uninstallation Summary"
    
    echo "Components removed:"
    echo "  ✓ Daemon"
    echo "  ✓ PAM module"
    echo "  ✓ Configuration GUI"
    
    echo ""
    echo "PAM configuration removed:"
    [[ "$REMOVE_PAM_CONFIG_LOGIN" == true ]] && echo "  ✓ Login" || echo "  ✗ Login"
    [[ "$REMOVE_PAM_CONFIG_SUDO" == true ]] && echo "  ✓ Sudo" || echo "  ✗ Sudo"
    [[ "$REMOVE_PAM_CONFIG_POLKIT" == true ]] && echo "  ✓ Polkit" || echo "  ✗ Polkit"
    [[ "$REMOVE_PAM_CONFIG_SYSTEM_AUTH" == true ]] && echo "  ✓ System-auth" || echo "  ✗ System-auth"
    [[ "$REMOVE_PAM_CONFIG_GDM" == true ]] && echo "  ✓ GDM" || echo "  ✗ GDM"
    [[ "$REMOVE_PAM_CONFIG_SDDM" == true ]] && echo "  ✓ SDDM" || echo "  ✗ SDDM"
    [[ "$REMOVE_PAM_CONFIG_LIGHTDM" == true ]] && echo "  ✓ LightDM" || echo "  ✗ LightDM"
    [[ "$REMOVE_PAM_CONFIG_KDE" == true ]] && echo "  ✓ KDE" || echo "  ✗ KDE"
    
    echo ""
    echo "User data:"
    [[ "$REMOVE_USER_DATA" == true ]] && echo "  ✓ Removed" || echo "  ✗ Preserved"
    
    echo ""
    print_success "Uninstallation complete!"
    
    if [[ "$REMOVE_USER_DATA" == false && -d "$CONFIG_DIR" ]]; then
        echo ""
        print_info "User data preserved in: $CONFIG_DIR"
        print_info "To remove manually: sudo rm -rf $CONFIG_DIR"
    fi
}

# Main uninstallation flow
main() {
    print_header "TapAuth Uninstallation"
    
    parse_args "$@"
    
    if [[ "$INTERACTIVE" == true ]]; then
        print_warning "This will remove all TapAuth components from your system"
        echo ""
        
        prompt_pam_configuration
        prompt_user_data
        
        echo ""
        read -p "Proceed with uninstallation? [y/N]: " response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            print_info "Uninstallation cancelled"
            exit 0
        fi
    fi
    
    check_root
    
    # Remove in reverse order of installation
    remove_systemd_units_and_daemon
    remove_pam_config
    remove_config_gui
    remove_pam
    remove_user_data
    
    if [[ "$DRY_RUN" == true ]]; then
        echo ""
        print_header "Dry Run Summary"
        echo "The following changes would be made:"
        echo ""
        echo "Components to remove:"
        echo "  ✓ Daemon (tapauthd, tapauthd.socket/service)"
        echo "  ✓ PAM module"
        echo "  ✓ Configuration GUI"
        
        echo ""
        echo "PAM configuration to remove:"
        [[ "$REMOVE_PAM_CONFIG_LOGIN" == true ]] && echo "  ✓ Login (/etc/pam.d/login)" || echo "  ✗ Login (kept)"
        [[ "$REMOVE_PAM_CONFIG_SUDO" == true ]] && echo "  ✓ Sudo (/etc/pam.d/sudo)" || echo "  ✗ Sudo (kept)"
        if [[ "$REMOVE_PAM_CONFIG_POLKIT" == true ]]; then
            if [[ -f /etc/pam.d/polkit-1 ]]; then
                echo "  ✓ Polkit (/etc/pam.d/polkit-1)"
            elif [[ -f /usr/lib/pam.d/polkit-1 ]]; then
                echo "  ✓ Polkit (/usr/lib/pam.d/polkit-1)"
            else
                echo "  ✓ Polkit (config file not found)"
            fi
        else
            echo "  ✗ Polkit (kept)"
        fi
        [[ "$REMOVE_PAM_CONFIG_SYSTEM_AUTH" == true ]] && echo "  ✓ System-auth (/etc/pam.d/system-auth)" || echo "  ✗ System-auth (kept)"
        if [[ "$REMOVE_PAM_CONFIG_GDM" == true ]]; then
            if [[ -f /etc/pam.d/gdm-password ]]; then
                echo "  ✓ GDM (/etc/pam.d/gdm-password)"
            elif [[ -f /etc/pam.d/gdm ]]; then
                echo "  ✓ GDM (/etc/pam.d/gdm)"
            else
                echo "  ✓ GDM (config file not found)"
            fi
        else
            echo "  ✗ GDM (kept)"
        fi
        if [[ "$REMOVE_PAM_CONFIG_SDDM" == true ]]; then
            if [[ -f /etc/pam.d/sddm ]]; then
                echo "  ✓ SDDM (/etc/pam.d/sddm)"
            else
                echo "  ✓ SDDM (config file not found)"
            fi
        else
            echo "  ✗ SDDM (kept)"
        fi
        [[ "$REMOVE_PAM_CONFIG_LIGHTDM" == true ]] && echo "  ✓ LightDM (/etc/pam.d/lightdm)" || echo "  ✗ LightDM (kept)"
        
        if [[ "$REMOVE_PAM_CONFIG_KDE" == true ]]; then
            local kde_files=""
            [[ -f /etc/pam.d/kde ]] && kde_files="kde"
            [[ -f /etc/pam.d/kscreenlocker ]] && kde_files="${kde_files:+$kde_files, }kscreenlocker"
            [[ -f /etc/pam.d/kde-fingerprint ]] && kde_files="${kde_files:+$kde_files, }kde-fingerprint"
            [[ -f /etc/pam.d/kde-smartcard ]] && kde_files="${kde_files:+$kde_files, }kde-smartcard"
            
            if [[ -n "$kde_files" ]]; then
                echo "  ✓ KDE ($kde_files)"
            else
                echo "  ✓ KDE (config files not found)"
            fi
        else
            echo "  ✗ KDE (kept)"
        fi
        
        echo ""
        echo "User data:"
        if [[ "$REMOVE_USER_DATA" == true ]]; then
            echo "  ✓ Would be removed from: $CONFIG_DIR"
        else
            echo "  ✗ Would be preserved in: $CONFIG_DIR"
        fi
        
        echo ""
        print_info "[DRY RUN] No actual changes were made to the system"
        print_info "Run without --dry-run to perform the uninstallation"
    else
        create_summary
    fi
}

# Run main
main "$@"
