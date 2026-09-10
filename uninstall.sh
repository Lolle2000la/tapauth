#!/bin/bash
set -euo pipefail
FORCE=false

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
# PAM configurations are always removed to prevent inconsistent state
# Only user data removal is configurable
REMOVE_USER_DATA=false
PRESERVE_SYSTEM_ACCOUNTS=false
RESTORE_PAM_BACKUPS=false
DRY_RUN=false
FORCE=false

# Installation paths (some will be detected at runtime)
PAM_MODULE_DIR=""  # Will be detected based on distribution
PAM_SO_NAME="pam_tapauth.so"
PAM_SO_PATH=""  # Will be set after detection
CONFIG_GUI_PATH="/usr/bin/tapauth-config"
CONFIG_DESKTOP_PATH="/usr/share/applications/tapauth-config.desktop"
CONFIG_ICON_PATH="/usr/share/icons/hicolor/scalable/apps/tapauth-config.svg"
CONFIG_POLICY_PATH="/usr/share/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy"
CONFIG_DIR="/var/lib/tapauth"
DAEMON_PATH="/usr/bin/tapauthd"
SOCKET_UNIT_DEST="/etc/systemd/system/tapauthd.socket"
SERVICE_UNIT_DEST="/etc/systemd/system/tapauthd.service"
INSTALLED_UNINSTALLER="/usr/share/tapauth/uninstall.sh"

# Detect if we're running from the installed location
RUNNING_FROM_INSTALLED=false
if [[ "$(readlink -f "$0")" == "$INSTALLED_UNINSTALLER" ]]; then
    RUNNING_FROM_INSTALLED=true
fi

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
    local description="${2:-}"
    if [[ -f "$file" ]] || [[ -d "$file" ]]; then
        echo -e "${RED}[REMOVE]${NC} $file"
        if [[ -n "$description" ]]; then
            echo "  → $description"
        fi
    else
        echo -e "${YELLOW}[SKIP]${NC} $file (does not exist)"
    fi
}

show_command() {
    local cmd="$1"
    local description="${2:-}"
    echo -e "${BLUE}[EXEC]${NC} $cmd"
    if [[ -n "$description" ]]; then
        echo "  → $description"
    fi
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
    -y, --yes               Answer yes to all prompts (non-interactive; does NOT remove user data)
    -f, --force             Force uninstallation over package-managed files without prompting
    --purge, --remove-user-data Remove user data including pairing keys (use with caution)
    --restore-pam-backups   Restore original PAM configurations from .tapauth-bak files
    --preserve-system-accounts  Preserve system user and group (tapauthd, tapauthd-clients)
    --dry-run               Show what would be done without doing it

NOTES:
    All components are always removed during uninstallation:
    - Daemon (tapauthd binary, systemd units)
    - PAM module (pam_tapauth.so)
    - PAM configurations (all modified PAM files)
    - Configuration GUI
    
    By default, system users and groups are also removed.
    Use --preserve-system-accounts during upgrades to avoid recreating them.
    
    Only user data removal is optional (keys, pairings).

EXAMPLES:
    # Interactive uninstallation (default)
    sudo $0

    # Non-interactive removal of everything including configs
    sudo $0 --yes

    # Upgrade (preserve system accounts)
    sudo $0 --non-interactive --preserve-system-accounts

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
        show_file_removal "/usr/share/polkit-1/rules.d/50-tapauthd.rules" "Polkit firewalld rules"
        show_file_removal "/etc/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf" "Virtual fprintd D-Bus policy"
        show_file_removal "/usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service" "Virtual fprintd D-Bus activation service (renamed, content-guarded)"
        show_file_removal "/usr/share/dbus-1/system-services/net.reactivated.Fprint.service" "Virtual fprintd D-Bus activation service (legacy pre-rename name, content-guarded)"
        show_file_removal "/etc/dconf/db/gdm.d/10-tapauth-fingerprint" "GDM dconf override"
        show_file_removal "/etc/dconf/db/gdm.d/01-tapauth" "GDM dconf override (legacy)"
        
        local polkit_dropin="/etc/systemd/system/polkit-agent-helper@.service.d/tapauth.conf"
        if [[ -f "$polkit_dropin" ]]; then
            show_file_removal "$polkit_dropin" "Polkit agent helper sandbox override"
            show_command "rmdir $(dirname "$polkit_dropin") || true" "Remove empty drop-in directory"
        fi
        return
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop tapauthd.socket tapauthd.service >/dev/null 2>&1 || true
        systemctl disable tapauthd.socket tapauthd.service >/dev/null 2>&1 || true
    fi

    # Remove unit files if present
    [[ -f "$SOCKET_UNIT_DEST" ]] && rm -f "$SOCKET_UNIT_DEST"
    [[ -f "$SERVICE_UNIT_DEST" ]] && rm -f "$SERVICE_UNIT_DEST"

    # Clean up the Polkit helper sandboxing drop-in if it exists
    local polkit_dropin="/etc/systemd/system/polkit-agent-helper@.service.d/tapauth.conf"
    if [[ -f "$polkit_dropin" ]]; then
        print_info "Removing Polkit agent helper systemd drop-in override..."
        rm -f "$polkit_dropin"
        rmdir "/etc/systemd/system/polkit-agent-helper@.service.d" 2>/dev/null || true
    fi

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

    # Remove polkit firewalld authorization rules
    local rules_file="/usr/share/polkit-1/rules.d/50-tapauthd.rules"
    if [[ -f "$rules_file" ]]; then
        print_info "Removing polkit firewalld authorization rules"
        rm -f "$rules_file"
    fi

    # Remove virtual fprintd files
    local removed_fprint_dbus=false
    for conf_dir in /etc/dbus-1/system.d /usr/share/dbus-1/system.d; do
        if [[ -f "$conf_dir/net.reactivated.Fprint.tapauth.conf" ]]; then
            print_info "Removing virtual fprintd D-Bus configuration ($conf_dir/net.reactivated.Fprint.tapauth.conf)"
            rm -f "$conf_dir/net.reactivated.Fprint.tapauth.conf"
            removed_fprint_dbus=true
        fi
    done

    # Remove TapAuth's D-Bus activation files. The RENAMED
    # net.reactivated.Fprint.tapauth.service is what current releases ship;
    # the un-renamed net.reactivated.Fprint.service is the filename of
    # pre-rename installs (and of the real fprintd package). BOTH are
    # content-guarded (Exec must reference tapauthd) so a hypothetical
    # identically-named foreign file — above all real fprintd's own — is
    # never deleted, mirroring the .tapauth.conf handling above.
    for fprint_srv in \
        /usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service \
        /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
    do
        if [[ -f "$fprint_srv" ]] && grep -q "tapauthd" "$fprint_srv" 2>/dev/null; then
            print_info "Removing virtual fprintd D-Bus service activation file ($fprint_srv)"
            rm -f "$fprint_srv"
            removed_fprint_dbus=true
        fi
    done

    if [[ "$removed_fprint_dbus" == true ]]; then
        if command -v systemctl &>/dev/null && systemctl is-active --quiet dbus 2>/dev/null; then
            systemctl reload dbus 2>/dev/null || true
        fi
    fi

    # Note: no config.toml edit here. The virtual fprintd bridge is enabled
    # by default in the daemon; the daemon is being removed entirely, so a
    # leftover enable_fprintd_bridge key would be stale either way.

    # Remove GDM dconf override
    local updated_dconf=false
    for gdm_dconf in /etc/dconf/db/gdm.d/10-tapauth-fingerprint /etc/dconf/db/gdm.d/01-tapauth; do
        if [[ -f "$gdm_dconf" ]]; then
            print_info "Removing GDM dconf override ($gdm_dconf)"
            rm -f "$gdm_dconf"
            updated_dconf=true
        fi
    done
    if [[ "$updated_dconf" == true ]] && command -v dconf &> /dev/null; then
        dconf update || true
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
            -f|--force)
                FORCE=true
                shift
                ;;
            -y|--yes)
                INTERACTIVE=false
                # Note: --yes does NOT imply user data deletion; use --purge for that
                shift
                ;;
            --purge|--remove-user-data)
                REMOVE_USER_DATA=true
                shift
                ;;
            --restore-pam-backups)
                RESTORE_PAM_BACKUPS=true
                shift
                ;;
            --preserve-system-accounts)
                PRESERVE_SYSTEM_ACCOUNTS=true
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
    print_header "Removing PAM Configuration"
    print_info "Cleaning up all TapAuth PAM configurations..."

    # Plain stacks: remove the pam_tapauth.so line only. The synthetic /
    # special-case stacks (gdm-fingerprint, gdm3-fingerprint, kde-fingerprint,
    # fingerprint-auth) are handled separately below.
    local pam_cleanup_files=(
        /etc/pam.d/login
        /etc/pam.d/su
        /etc/pam.d/su-l
        /etc/pam.d/sudo
        /etc/pam.d/polkit-1
        /usr/lib/pam.d/polkit-1
        /etc/pam.d/system-auth
        /etc/pam.d/gdm-password
        /etc/pam.d/gdm
        /etc/pam.d/sddm
        /etc/pam.d/lightdm
        /etc/pam.d/kde
        /etc/pam.d/kscreenlocker
        /etc/pam.d/kde-smartcard
    )

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would remove TapAuth from all PAM configurations"
        echo ""

        for pam_file in "${pam_cleanup_files[@]}"; do
            if [[ -f "$pam_file" ]]; then
                show_pam_restore_diff "$pam_file"
            fi
        done

        # Synthetic/special stacks (may be deleted or restored from backup)
        for pam_file in /etc/pam.d/gdm-fingerprint /etc/pam.d/gdm3-fingerprint \
                        /etc/pam.d/kde-fingerprint /etc/pam.d/fingerprint-auth; do
            if [[ -f "$pam_file" ]]; then
                show_pam_restore_diff "$pam_file"
            fi
        done
        return
    fi

    # Always remove from all PAM files to prevent inconsistent state
    for pam_file in "${pam_cleanup_files[@]}"; do
        if [[ -f "$pam_file" ]] && grep -q "pam_tapauth.so" "$pam_file" 2>/dev/null; then
            print_info "Removing TapAuth from PAM configuration ($pam_file)"
            sed -i '/pam_tapauth\.so/d' "$pam_file"
        fi
    done

    # Synthetic GDM fingerprint stacks: remove outright when they are ours,
    # otherwise strip the TapAuth line.
    for gdm_file in /etc/pam.d/gdm-fingerprint /etc/pam.d/gdm3-fingerprint; do
        if [[ -f "$gdm_file" ]]; then
            if grep -q "Managed by TapAuth" "$gdm_file" 2>/dev/null; then
                print_info "Removing synthetic GDM fingerprint PAM configuration ($gdm_file)"
                rm -f "$gdm_file"
            elif grep -q "pam_tapauth.so" "$gdm_file" 2>/dev/null; then
                print_info "Removing TapAuth from GDM fingerprint PAM configuration ($gdm_file)"
                sed -i '/pam_tapauth\.so/d' "$gdm_file"
            fi
        fi
    done

    # Synthetic KDE fingerprint stack: remove outright when it is ours,
    # otherwise strip the TapAuth line.
    if [[ -f /etc/pam.d/kde-fingerprint ]]; then
        if grep -q "Managed by TapAuth" /etc/pam.d/kde-fingerprint 2>/dev/null; then
            print_info "Removing synthetic KDE fingerprint PAM configuration (/etc/pam.d/kde-fingerprint)"
            rm -f /etc/pam.d/kde-fingerprint
        elif grep -q "pam_tapauth.so" /etc/pam.d/kde-fingerprint 2>/dev/null; then
            print_info "Removing TapAuth from KDE fingerprint PAM configuration (/etc/pam.d/kde-fingerprint)"
            sed -i '/pam_tapauth\.so/d' /etc/pam.d/kde-fingerprint
        fi
    fi

    # Best-effort legacy cleanup: older versions patched the Fedora
    # fingerprint-auth stack directly. Restore it from its backup when one
    # exists; otherwise drop the TapAuth lines.
    if [[ -f /etc/pam.d/fingerprint-auth ]]; then
        if grep -q "Managed by TapAuth" /etc/pam.d/fingerprint-auth 2>/dev/null; then
            print_info "Removing synthetic fingerprint-auth PAM configuration (/etc/pam.d/fingerprint-auth)"
            rm -f /etc/pam.d/fingerprint-auth /etc/pam.d/fingerprint-auth.tapauth-bak
        elif grep -q "pam_tapauth.so" /etc/pam.d/fingerprint-auth 2>/dev/null; then
            if [ -s /etc/pam.d/fingerprint-auth.tapauth-bak ]; then
                print_info "Restoring original fingerprint-auth PAM configuration from backup"
                cp -p /etc/pam.d/fingerprint-auth.tapauth-bak /etc/pam.d/fingerprint-auth
                rm -f /etc/pam.d/fingerprint-auth.tapauth-bak
            else
                print_info "Removing TapAuth from fingerprint-auth PAM configuration (/etc/pam.d/fingerprint-auth)"
                sed -i '/pam_tapauth\.so/d' /etc/pam.d/fingerprint-auth
            fi
        else
            # Stack no longer references TapAuth; drop a stale backup.
            rm -f /etc/pam.d/fingerprint-auth.tapauth-bak 2>/dev/null || true
        fi
    fi
    
    # Restore PAM backups if present — warn the user since restoring may revert security updates
    local bak_files=()
    for bak in /etc/pam.d/*.tapauth-bak; do
        [[ -f "$bak" ]] && bak_files+=("$bak")
    done
    
    if [[ ${#bak_files[@]} -gt 0 ]]; then
        print_warning "Found PAM backup files from original TapAuth installation:"
        for bak in "${bak_files[@]}"; do
            echo "  - $bak"
        done
        print_warning "Restoring these may revert security updates made after TapAuth was installed."
        
        local restore="false"
        if [[ "$RESTORE_PAM_BACKUPS" == true ]]; then
            restore="true"
        elif [[ "$INTERACTIVE" == false ]]; then
            restore="false"
            print_info "Non-interactive mode: skipping PAM backup restoration (use --restore-pam-backups to restore)."
        else
            read -rp "Restore original PAM files from backups? [y/N] " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] && restore="true"
        fi
        
        if [[ "$restore" == true ]]; then
            for bak in "${bak_files[@]}"; do
                local orig="${bak%.tapauth-bak}"
                print_info "Restoring original PAM configuration for $orig"
                cp -p "$bak" "$orig"
                rm -f "$bak"
            done
        else
            for bak in "${bak_files[@]}"; do
                print_info "Leaving backup file: $bak (delete manually if not needed)"
            done
        fi
    fi
    
    print_success "PAM configurations cleaned up"
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
        show_file_removal "$CONFIG_ICON_PATH" "Desktop icon"
        show_file_removal "$CONFIG_DESKTOP_PATH" "Desktop entry"
        show_file_removal "$CONFIG_POLICY_PATH" "Polkit policy"
        return
    fi
    
    # Remove binary
    if [[ -f "$CONFIG_GUI_PATH" ]]; then
        print_info "Removing configuration GUI binary"
        rm -f "$CONFIG_GUI_PATH"
    fi
    
    # Remove desktop icon
    if [[ -f "$CONFIG_ICON_PATH" ]]; then
        print_info "Removing desktop icon"
        rm -f "$CONFIG_ICON_PATH"
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
        show_file_removal "$CONFIG_DIR" "System state directory (contains keys and paired devices)"
        show_file_removal "/etc/tapauth" "System configuration directory (/etc/tapauth)"
        
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
        print_info "No user data found in $CONFIG_DIR"
    fi

    if [[ -d "/etc/tapauth" ]]; then
        print_info "Removing system configuration directory /etc/tapauth"
        rm -rf "/etc/tapauth"
    fi
    
    # Remove log directory
    local log_dir="/var/log/tapauth"
    if [[ -d "$log_dir" ]]; then
        print_info "Removing log directory $log_dir"
        rm -rf "$log_dir"
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

# Remove system users and groups
remove_system_users() {
    if [[ "$PRESERVE_SYSTEM_ACCOUNTS" == true ]]; then
        print_info "Preserving system user and group (upgrade mode)"
        return
    fi
    
    print_header "Removing System Users and Groups"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would remove system user and groups"
        echo ""
        
        # Check if any users are in tapauthd-clients group
        if getent group tapauthd-clients >/dev/null 2>&1; then
            local members=$(getent group tapauthd-clients | cut -d: -f4)
            if [[ -n "$members" ]]; then
                show_command "Remove users from tapauthd-clients group: $members"
            fi
            show_command "groupdel tapauthd-clients" "Delete tapauthd-clients group"
        fi
        
        if id -u tapauthd >/dev/null 2>&1; then
            show_command "userdel tapauthd" "Delete tapauthd system user"
        fi
        return
    fi
    
    # Remove users from tapauthd-clients group first
    if getent group tapauthd-clients >/dev/null 2>&1; then
        local members=$(getent group tapauthd-clients | cut -d: -f4)
        if [[ -n "$members" ]]; then
            print_info "Removing users from tapauthd-clients group: $members"
            IFS=',' read -ra user_array <<< "$members"
            for user in "${user_array[@]}"; do
                user=$(echo "$user" | xargs)  # trim whitespace
                if id "$user" >/dev/null 2>&1; then
                    gpasswd -d "$user" tapauthd-clients >/dev/null 2>&1 || true
                    print_info "Removed user '$user' from tapauthd-clients group"
                fi
            done
        fi
        
        print_info "Deleting group 'tapauthd-clients'"
        groupdel tapauthd-clients >/dev/null 2>&1 || true
    fi
    
    # Remove tapauthd system user
    if id -u tapauthd >/dev/null 2>&1; then
        print_info "Deleting system user 'tapauthd'"
        userdel tapauthd >/dev/null 2>&1 || true
    fi
    
    print_success "System users and groups removed"
}

# Remove the installed uninstaller script itself (if we're running from there)
remove_self() {
    if [[ "$RUNNING_FROM_INSTALLED" == false ]]; then
        # Not running from installed location, nothing to do
        return
    fi
    
    print_header "Removing Uninstaller"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Would remove installed uninstaller"
        show_file_removal "$INSTALLED_UNINSTALLER" "Installed uninstaller script"
        show_file_removal "$(dirname "$INSTALLED_UNINSTALLER")" "Uninstaller directory (if empty)"
        return
    fi
    
    # Remove the uninstaller script
    if [[ -f "$INSTALLED_UNINSTALLER" ]]; then
        print_info "Removing installed uninstaller script"
        rm -f "$INSTALLED_UNINSTALLER"
    fi
    
    # Remove the directory if it's empty
    local uninstaller_dir="$(dirname "$INSTALLED_UNINSTALLER")"
    if [[ -d "$uninstaller_dir" ]]; then
        if rmdir "$uninstaller_dir" 2>/dev/null; then
            print_info "Removed empty uninstaller directory"
        fi
    fi
    
    print_success "Uninstaller removed"
}

# Create uninstallation summary
create_summary() {
    print_header "Uninstallation Summary"
    
    echo "Components removed:"
    echo "  ✓ Daemon"
    echo "  ✓ PAM module"
    echo "  ✓ Configuration GUI"
    if [[ "$PRESERVE_SYSTEM_ACCOUNTS" == false ]]; then
        echo "  ✓ System users and groups"
    else
        echo "  ○ System users and groups (preserved)"
    fi
    echo "  ✓ All PAM configurations"
    [[ "$RUNNING_FROM_INSTALLED" == true ]] && echo "  ✓ Uninstaller script"
    
    echo ""
    echo "User data:"
    [[ "$REMOVE_USER_DATA" == true ]] && echo "  ✓ Removed" || echo "  ✗ Preserved"
    
    echo ""
    print_success "Uninstallation complete!"
    
    echo ""
    print_warning "You may need to log out and back in for group membership changes to take effect"
    
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
    
    # If we're NOT running from the installed location, check if there's an installed uninstaller
    # and use that instead (it matches the installed version)
    if [[ "$RUNNING_FROM_INSTALLED" == false && -f "$INSTALLED_UNINSTALLER" ]]; then
        print_info "Found installed uninstaller at $INSTALLED_UNINSTALLER"
        print_info "Using installed uninstaller to ensure version compatibility"
        echo ""
        
        # Execute the installed uninstaller with all the same arguments
        exec bash "$INSTALLED_UNINSTALLER" "$@"
        # exec replaces this process, so we never reach here
        exit 1  # Should never happen
    fi
    
    if [[ "$INTERACTIVE" == true ]]; then
        print_warning "This will remove all TapAuth components from your system"
        print_info "All PAM configurations will be cleaned up automatically"
        echo ""
        
        prompt_user_data
        
        echo ""
        read -p "Proceed with uninstallation? [y/N]: " response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            print_info "Uninstallation cancelled"
            exit 0
        fi
    fi
    
    check_root

    # Check if installed via system package manager
    local pkg_manager=""
    if command -v dpkg >/dev/null 2>&1 && { dpkg -l tapauth 2>/dev/null | grep -q '^ii' || dpkg -l tapauth-fprintd 2>/dev/null | grep -q '^ii'; }; then
        pkg_manager="apt-get remove tapauth tapauth-fprintd"
    elif command -v rpm >/dev/null 2>&1 && { rpm -q tapauth >/dev/null 2>&1 || rpm -q tapauth-fprintd >/dev/null 2>&1; }; then
        pkg_manager="dnf remove tapauth tapauth-fprintd"
    elif command -v pacman >/dev/null 2>&1 && { pacman -Q tapauth >/dev/null 2>&1 || pacman -Q tapauth-fprintd >/dev/null 2>&1 || pacman -Q tapauth-git >/dev/null 2>&1 || pacman -Q tapauth-fprintd-git >/dev/null 2>&1; }; then
        pkg_manager="pacman -R tapauth tapauth-fprintd"
    fi

    if [[ -n "$pkg_manager" ]]; then
        print_warning "TapAuth appears to have been installed via your system package manager."
        print_warning "Running this standalone script will delete package-managed binaries without updating"
        print_warning "the package database, which may cause errors during package updates or removal."
        if [[ "$FORCE" == true ]]; then
            print_info "Continuing due to --force flag."
        elif [[ "$INTERACTIVE" == false ]]; then
            print_error "Cannot uninstall package-managed TapAuth ($pkg_manager) in non-interactive mode without --force."
            print_info "Use your distribution package manager to uninstall TapAuth, or pass --force."
            exit 1
        else
            read -p "Proceed with manual uninstallation anyway? [y/N]: " pkg_uninst_confirm
            if [[ ! "$pkg_uninst_confirm" =~ ^[Yy]$ ]]; then
                print_info "Uninstallation cancelled. Please use your package manager (sudo $pkg_manager)."
                exit 0
            fi
        fi
    fi
    
    # Remove in reverse order of installation
    remove_systemd_units_and_daemon
    remove_pam_config
    remove_config_gui
    remove_pam
    remove_user_data
    remove_system_users
    remove_self  # Remove the uninstaller itself (if running from installed location)
    
    if [[ "$DRY_RUN" == true ]]; then
        echo ""
        print_header "Dry Run Summary"
        echo "The following changes would be made:"
        echo ""
        echo "Components to remove:"
        echo "  ✓ Daemon (tapauthd, tapauthd.socket/service)"
        echo "  ✓ PAM module"
        echo "  ✓ Configuration GUI"
        if [[ "$PRESERVE_SYSTEM_ACCOUNTS" == false ]]; then
            echo "  ✓ System users and groups (tapauthd, tapauthd-clients)"
        else
            echo "  ○ System users and groups (preserved for upgrade)"
        fi
        
        echo ""
        echo "PAM configurations:"
        echo "  ✓ All PAM files will be cleaned (login, sudo, polkit, system-auth, display managers, etc.)"
        
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
