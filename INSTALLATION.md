# TapAuth Installation Guide

This guide covers the installation and uninstallation of TapAuth using the interactive scripts.

## Supported Distributions

The installation scripts automatically detect and support the following Linux distributions:
- **Ubuntu/Debian** (PAM modules in `/lib/x86_64-linux-gnu/security` or `/usr/lib/x86_64-linux-gnu/security`)
- **Fedora/RHEL/CentOS** (PAM modules in `/lib64/security` or `/usr/lib64/security`)
- **Arch Linux** (PAM modules in `/usr/lib/security`)
- Other systemd-based distributions with standard PAM module locations

The scripts automatically detect your distribution and adjust paths accordingly.

## Quick Start

### Preview Installation (Recommended First Step)

Before installing, you can preview all changes that will be made:

```bash
./install.sh --dry-run --yes
```

This shows detailed diffs of PAM configuration changes, files that will be created, and commands that will be executed. See [DRY_RUN_EXAMPLES.md](DRY_RUN_EXAMPLES.md) for more information.

**No root access required for dry-run mode.**

### Interactive Installation (Recommended)

```bash
sudo ./install.sh
```

This will guide you through the installation process with interactive prompts.

### Non-Interactive Installation

```bash
sudo ./install.sh --yes
```

This installs everything with default settings (including PAM configuration for login and sudo).

## Installation Script (`install.sh`)

### Features

- **Privilege Separation**: Builds run as the original user (via `$SUDO_USER`) even when script is run with `sudo`, preventing root-owned files in cargo cache
- **Optimized Build**: Builds all components in release mode with `-C target-cpu=native -C opt-level=3`
- **Component Selection**: Choose which components to install (PAM module, BLE daemon, Config GUI)
- **PAM Configuration**: Optionally configure PAM for login, sudo, and polkit
- **TPM Support**: Optional TPM integration for secure key storage
- **Interactive Mode**: User-friendly prompts for all options
- **Non-Interactive Mode**: Full automation via command-line flags
- **Dry Run**: Preview what will be installed without making changes

### Command Line Options

```
Usage: ./install.sh [OPTIONS]

OPTIONS:
    -h, --help              Show help message
    -n, --non-interactive   Run in non-interactive mode
    -y, --yes               Answer yes to all prompts
    --no-pam                Don't install PAM module
    --no-ble                Don't install BLE daemon
    --no-gui                Don't install configuration GUI
    --configure-login       Configure PAM for login authentication
    --configure-sudo        Configure PAM for sudo authentication
    --configure-polkit      Configure PAM for polkit authentication
    --use-tpm               Enable TPM support for key storage
    --build-only            Only build, don't install
    --dry-run               Show what would be done without doing it
```

### Examples

#### Install Everything Interactively
```bash
sudo ./install.sh
```

#### Install with Login and Sudo Authentication
```bash
sudo ./install.sh --non-interactive --configure-login --configure-sudo
```

#### Install Only PAM Module and BLE Daemon
```bash
sudo ./install.sh --no-gui --configure-login
```

#### Build Without Installing
```bash
./install.sh --build-only
```

#### Preview Installation (Dry Run)
```bash
./install.sh --dry-run --yes
```

This will show detailed information about what would be installed, including:
- Files that would be created or copied
- Commands that would be executed
- Diffs of PAM configuration changes
- systemd service content preview

**No root access required for dry-run mode.**

#### Install with TPM Support
```bash
sudo ./install.sh --use-tpm --configure-login --configure-sudo
```

### Installation Locations

Installation paths are automatically detected based on your distribution:

| Component | Typical Location |
|-----------|----------|
| PAM Module | `/lib64/security/pam_tapauth.so` (Fedora/RHEL)<br>`/usr/lib/security/pam_tapauth.so` (Arch)<br>`/lib/x86_64-linux-gnu/security/pam_tapauth.so` (Ubuntu/Debian) |
| BLE Daemon | `/usr/lib/tapauth/tapauth-ble-daemon` |
| Config GUI | `/usr/bin/tapauth-config` |
| Configuration | `/etc/tapauth/` |
| Desktop Entry | `/usr/share/applications/tapauth-config.desktop` |
| systemd Service | `/etc/systemd/system/tapauth-ble-daemon.service` |
| D-Bus Config | `/etc/dbus-1/system.d/dev.rourunisen.tapauth.BLE.conf` |
| Polkit Policy | `/usr/share/polkit-1/actions/dev.rourunisen.tapauth.policy` |

**Note**: The PAM module location is automatically detected during installation based on your distribution's standard PAM directory.

## Uninstallation Script (`uninstall.sh`)

### Features

- **Safe Removal**: Removes components in the correct order
- **PAM Cleanup**: Automatically removes PAM configuration from system files
- **User Data Preservation**: Option to keep or remove user data and pairings
- **Interactive Prompts**: Guides you through what to remove
- **Dry Run**: Preview what will be removed

### Command Line Options

```
Usage: ./uninstall.sh [OPTIONS]

OPTIONS:
    -h, --help              Show help message
    -n, --non-interactive   Run in non-interactive mode
    -y, --yes               Answer yes to all prompts
    --no-pam                Don't remove PAM module
    --no-ble                Don't remove BLE daemon
    --no-gui                Don't remove configuration GUI
    --remove-pam-login      Remove PAM login configuration
    --remove-pam-sudo       Remove PAM sudo configuration
    --remove-pam-polkit     Remove PAM polkit configuration
    --remove-user-data      Remove user configuration data
    --dry-run               Show what would be done without doing it
```

### Examples

#### Interactive Uninstallation
```bash
sudo ./uninstall.sh
```

#### Complete Removal (Including User Data)
```bash
sudo ./uninstall.sh --yes --remove-user-data
```

#### Remove Only BLE Daemon
```bash
sudo ./uninstall.sh --no-pam --no-gui
```

#### Preview Uninstallation (Dry Run)
```bash
./uninstall.sh --dry-run --yes
```

This will show detailed information about what would be removed, including:
- Files that would be deleted
- Commands that would be executed
- Diffs showing PAM configuration changes
- Impact on system services

**No root access required for dry-run mode.**

#### Remove Components but Keep User Data
```bash
sudo ./uninstall.sh --yes
# (Don't use --remove-user-data flag)
```

## How PAM Integration Works

### Parallel Authentication (Non-Disruptive)

TapAuth uses PAM's `sufficient` control flag, which means:

- **Existing authentication methods remain fully functional** (password, fingerprint, etc.)
- **TapAuth runs first** - if your phone is nearby and you tap "Authenticate", you're logged in immediately
- **If TapAuth is not available** - authentication falls through to your existing methods (password prompt appears)
- **Both methods work in parallel** - whichever succeeds first grants access

**Example PAM stack after installation:**
```
auth    sufficient    pam_tapauth.so      ← NEW: Try phone authentication first
auth    sufficient    pam_unix.so         ← EXISTING: Fall back to password
auth    required      pam_deny.so         ← EXISTING: Deny if all methods fail
```

This is a **safe, non-disruptive** configuration. Your system remains accessible even if:
- Your phone is off or out of range
- The BLE daemon crashes
- TapAuth is uninstalled (just remove the line from PAM config)

**For detailed information about PAM integration, security, and troubleshooting, see [PAM_INTEGRATION.md](PAM_INTEGRATION.md).**

### When Do Changes Take Effect?

PAM modules are loaded dynamically - **no system restart is required**:

- **sudo**: Changes take effect **immediately** - test right away with `sudo -k && sudo echo test`
- **polkit**: Changes take effect **immediately** - GUI privilege dialogs will use TapAuth
- **login**: Changes take effect on **next login session** - you need to logout and login again

**Important**: You can test sudo authentication immediately after installation without rebooting!

## Post-Installation

### 1. Pair Your Device

After installation, run the configuration GUI to pair with your phone:

```bash
tapauth-config
```

Or if PAM is configured, you can use:

```bash
sudo tapauth-config
```

### 2. Test Authentication

**IMPORTANT**: Before logging out, test authentication in a separate terminal:

```bash
# Test sudo
sudo -k && sudo echo "Authentication test"

# Test login (in a separate TTY - Ctrl+Alt+F2)
# Try logging in with your paired device
```

### 3. Verify BLE Daemon

Check that the BLE daemon is running:

```bash
systemctl status tapauth-ble-daemon
```

### 4. Keep a Backup Session

When first setting up PAM authentication:
- Keep a root terminal session open
- Test authentication in another terminal
- Don't close your current session until verified

## Troubleshooting

### Build Issues

If the build fails, ensure you have:
- Rust toolchain installed (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Required system packages:
  - **Fedora/RHEL**: `sudo dnf install gcc pkg-config dbus-devel systemd-devel`
  - **Ubuntu/Debian**: `sudo apt install build-essential pkg-config libdbus-1-dev libsystemd-dev`
  - **Arch Linux**: `sudo pacman -S base-devel dbus systemd`

**Note**: The build automatically runs as your user (not root) even when the script is run with `sudo`. This prevents root-owned files in `~/.cargo` and is more secure.

### Root-Owned Cargo Files

If you accidentally ran the build as root before this feature was added, clean up with:
```bash
sudo rm -rf target/
cargo clean
```

Then run the install script normally with `sudo ./install.sh` - it will now build as your user.

### Distribution-Specific Notes

#### Fedora/RHEL/CentOS
- SELinux may need to be configured to allow PAM modules
- Check: `sudo setenforce 0` (temporary) or configure SELinux policies

#### Ubuntu/Debian
- Ensure `libpam0g-dev` is installed for PAM development
- AppArmor profiles may need adjustment for the BLE daemon

#### Arch Linux
- Ensure `pam` package is installed
- May need to enable bluetooth service: `sudo systemctl enable bluetooth`

### PAM Issues

If you get locked out:
1. Boot into recovery mode or single-user mode
2. Edit `/etc/pam.d/login` and `/etc/pam.d/sudo`
3. Remove lines containing `pam_tapauth.so`
4. Reboot

### BLE Daemon Not Starting

Check the service status:
```bash
journalctl -u tapauth-ble-daemon -f
```

Common issues:
- Bluetooth not enabled: `sudo systemctl start bluetooth`
- Missing permissions: Check D-Bus configuration
- Bluetooth adapter not available

### Permission Issues

If you see permission errors:
```bash
# Check file ownership
ls -la /etc/tapauth/
ls -la /usr/lib/pam_tapauth/

# Fix if needed
sudo chmod 700 /etc/tapauth
sudo chmod 644 /usr/lib/pam_tapauth/pam_tapauth.so
```

## Advanced Usage

### Custom Installation Directory

To use a custom installation directory, modify the paths at the top of `install.sh`:

```bash
PAM_MODULE_DIR="/custom/path/pam_tapauth"
BLE_DAEMON_DIR="/custom/path/tapauth"
# ... etc
```

### Building for a Different Architecture

Edit the build flags in `install.sh`:

```bash
# Change from:
local rustflags="-C target-cpu=native -C opt-level=3"

# To (for example, generic x86_64):
local rustflags="-C target-cpu=x86-64 -C opt-level=3"
```

### TPM Configuration

If you enabled TPM support, ensure:
1. TPM is enabled in BIOS/UEFI
2. `tpm2-tools` package is installed
3. User has access to `/dev/tpm0` or `/dev/tpmrm0`

### Multiple Users

When multiple users need to use TapAuth:
1. Each user should run `tapauth-config` to pair their own devices
2. User-specific pairings are stored in `/etc/tapauth/` with appropriate permissions
3. Each user's paired devices are isolated from others

## Security Considerations

### PAM Configuration Order

The install script adds TapAuth as a `sufficient` module, which means:
- If TapAuth succeeds, authentication succeeds immediately
- If TapAuth fails, the next PAM module in the stack is tried
- Your password will still work as a fallback

### Key Storage

- Keys are stored in `/etc/tapauth/` with mode `700` (root only)
- If TPM is enabled, keys are sealed to the TPM
- Without TPM, keys are protected by filesystem permissions

### First-Time Setup

1. Always test in a separate terminal first
2. Keep a root session open during initial setup
3. Verify you can authenticate before logging out
4. Consider setting up SSH access as a backup

## Uninstallation Notes

### What Gets Removed

- **Default**: All binaries and system files
- **Optional**: PAM configuration entries
- **Optional**: User data (keys and pairings)

### What Gets Preserved

By default, the uninstall script preserves:
- User encryption keys in `/etc/tapauth/`
- User-specific configuration in `~/.config/tapauth/`
- PAM configuration (unless explicitly requested to remove)

To completely remove everything:
```bash
sudo ./uninstall.sh --yes --remove-user-data
```

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review system logs: `journalctl -xe`
3. Check service status: `systemctl status tapauth-ble-daemon`
4. Verify PAM configuration: `cat /etc/pam.d/login | grep tapauth`

## License

See the main LICENSE file in the repository root.
