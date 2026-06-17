# TapAuth Installation Guide

This guide covers the installation and uninstallation of TapAuth using the interactive scripts.

## Native Distribution Packages

You can install tapauth via native package repositories to receive automatic updates verified by your system's package manager.

### 1. Fedora Linux
Packages are built and tracked using Fedora COPR.
```bash
sudo dnf copr enable lolle2000la/tapauth
sudo dnf install tapauth
```
* **PAM Configuration:** Fedora uses `authselect` to manage the authentication stack. Do not edit files under `/etc/pam.d/` directly as `authselect` will overwrite your changes. The package ships ready-made authselect vendor profiles that you can enable with a single command:
  ```bash
  # For standard workstations (local accounts, Fedora 40+):
  sudo authselect select vendor/tapauth

  # For environments using SSSD (FreeIPA, Active Directory, LDAP):
  sudo authselect select vendor/tapauth-sssd
  ```
  You can verify the available profiles with `authselect list` after installation. To revert to the default Fedora profile, run `sudo authselect select local` (or `sssd` if that was your previous profile).

### 2. Ubuntu
Packages are published via a Launchpad Personal Package Archive (PPA).
```bash
sudo add-apt-repository ppa:lolle2000la/tapauth
sudo apt-get update
sudo apt-get install tapauth
```
* **PAM Configuration:** Installation automatically registers a module profile hook. To toggle or configure the module non-interactively, run:
```bash
sudo pam-auth-update
```

### 3. Arch Linux / CachyOS
The source package metadata configuration is available via the Arch User Repository (AUR).
```bash
paru -S tapauth
# or alternatively
yay -S tapauth
```
* **PAM Configuration:** Arch Linux avoids implicit post-install system alterations. To complete activation, append your rule manually to your chosen authentication stack configuration file (e.g., `/etc/pam.d/system-auth`):
```text
auth      sufficient      pam_tapauth.so
```

### 4. Android (via F-Droid)
A custom, unified F-Droid repository delivers the TapAuth Android companion app and update channels without requiring any third-party app store account.

**Add the repository to F-Droid:**
1. Install [F-Droid](https://f-droid.org/) on your Android device.
2. Open F-Droid, go to **Settings** → **Repositories** → tap the **+** button.
3. Scan the QR Code or enter the repository URL containing the pinned cryptographic fingerprint to establish trust automatically without security warnings:  
   [![F-Droid Repository QR Code](docs/fdroid-repo-qr.svg)](https://tapauth.rourunisen.dev/fdroid/repo?fingerprint=94084CA00DE1D7163C3105BDFBD318DE6774B239711E8DF4EFC9CD13FCE77CF4)
   ```
   https://tapauth.rourunisen.dev/fdroid/repo?fingerprint=94084CA00DE1D7163C3105BDFBD318DE6774B239711E8DF4EFC9CD13FCE77CF4
   ```
4. Tap **Add**, then refresh the repository list (pull down or use the refresh button).
5. Search for **TapAuth** and install.

Updates and pre-release testing tracks are delivered automatically through this same repository endpoint. If you wish to receive alpha or beta builds, ensure "Show unstable versions" is toggled on within your F-Droid client app settings.

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
- **Component Selection**: Choose which components to install (PAM module, Config GUI)
- **Bluetooth Support (daemon)**: Optional - build the daemon with or without Bluetooth (BLE) support
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
    -y, --yes               Answer yes to all prompts (implies --non-interactive)
    --no-pam                Don't install PAM module
    --no-ble                Build daemon without Bluetooth support (UDP only)
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

#### Install Without BLE (daemon only)
```bash
sudo ./install.sh --no-ble --configure-login
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

#### Install with TPM Support (Opt-in)
```bash
sudo ./install.sh --use-tpm --configure-login --configure-sudo
```

**Note**: TPM support is opt-in and requires:
- TPM 2.0 hardware
- `tpm2-tools` package installed
- Building with `--use-tpm` flag

See [docs/TPM_SUPPORT.md](docs/TPM_SUPPORT.md) for details.

### Installation Locations

Installation paths are automatically detected based on your distribution:

| Component | Typical Location |
|-----------|----------|
| PAM Module | `/lib64/security/pam_tapauth.so` (Fedora/RHEL)<br>`/usr/lib/security/pam_tapauth.so` (Arch)<br>`/lib/x86_64-linux-gnu/security/pam_tapauth.so` (Ubuntu/Debian) |
| Daemon | `/usr/bin/tapauthd` |
| Socket | `/run/tapauthd/tapauthd.sock` (root:tapauthd-clients, 0660) |
| Config GUI | `/usr/bin/tapauth-config` |
| Configuration | `/var/lib/tapauth/` |
| Desktop Entry | `/usr/share/applications/tapauth-config.desktop` |
| Polkit Policy | `/usr/share/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy` |

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
    -y, --yes               Answer yes to all prompts (implies --non-interactive)
    --no-pam                Don't remove PAM module
    --no-gui                Don't remove configuration GUI
    --remove-pam-login      Remove PAM login configuration
    --remove-pam-sudo       Remove PAM sudo configuration
    --remove-pam-polkit     Remove PAM polkit configuration
    --remove-user-data      Remove user configuration data (keys, pairings)
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

#### Remove Only PAM Module
```bash
sudo ./uninstall.sh --no-gui
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
- TapAuth is uninstalled (just remove the line from PAM config)
- Network connectivity is unavailable

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

### 3. Keep a Backup Session

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
- SELinux: No custom policy is shipped. The installer restores default labels on `/var/lib/tapauth` and `/run/tapauthd` (via `restorecon` if available).

#### Ubuntu/Debian
- Ensure `libpam0g-dev` is installed for PAM development
- Ensure BlueZ is installed and running for BLE support: `sudo apt install bluez`

#### Arch Linux
- Ensure `pam` package is installed
- May need to enable bluetooth service: `sudo systemctl enable bluetooth`

### PAM Issues

If you get locked out:
1. Boot into recovery mode or single-user mode
2. Edit `/etc/pam.d/login` and `/etc/pam.d/sudo`
3. Remove lines containing `pam_tapauth.so`
4. Reboot

### Bluetooth Issues

If BLE authentication is not working:

```bash
# Check Bluetooth service is running
sudo systemctl status bluetooth

# Check for Bluetooth adapters
bluetoothctl list

# Enable Bluetooth adapter
bluetoothctl power on
```

Common issues:
- Bluetooth not enabled: `sudo systemctl start bluetooth`
- Bluetooth adapter not available or powered off
- Bluetooth device conflicts (close other BLE applications)

For detailed Bluetooth diagnostics, see `scripts/bluetooth-check.sh`.

### Permission Issues

If you see permission errors:
```bash
# Check file ownership
ls -la /var/lib/tapauth/
ls -la $(find /lib* /usr/lib* -name pam_tapauth.so 2>/dev/null | head -1)

# Fix if needed
sudo chmod 700 /var/lib/tapauth
```

## Advanced Usage

### Custom Installation Directory

The PAM module directory is automatically detected. To override, set `PAM_MODULE_DIR` before running:

```bash
export PAM_MODULE_DIR="/custom/path/security"
sudo -E ./install.sh
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
1. Each user runs `tapauth-config` (it can elevate via polkit when needed) to pair their device.
2. Pairings and keys are stored system-wide under `/var/lib/tapauth/` and managed by the daemon user `tapauthd`.
3. Access is constrained by each pairing’s `allowed_users` list; each user’s username must be added during pairing.

## Security Considerations

### PAM Configuration Order

The install script adds TapAuth as a `sufficient` module, which means:
- If TapAuth succeeds, authentication succeeds immediately
- If TapAuth fails, the next PAM module in the stack is tried
- Your password will still work as a fallback

### Key Storage

- Keys and config are stored in `/var/lib/tapauth/` with directory mode `700` and files `600`, owned by `tapauthd`.
- If TPM is enabled during configuration, TPM settings are recorded in config (implementation may be limited in this version).
- Without TPM, keys are protected by filesystem permissions.

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
- User encryption keys in `/var/lib/tapauth/`
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
3. For BLE issues, run: `./scripts/bluetooth-check.sh`
4. Verify PAM configuration: `cat /etc/pam.d/login | grep tapauth`

### Socket access policy

The IPC socket `/run/tapauthd/tapauthd.sock` is created as `root:tapauthd-clients` with mode `0660`.
- The installer creates the group `tapauthd-clients` and automatically adds the installing user to it.
- A logout/login cycle is required for the new group membership to take effect.
- If you need to grant access to additional users, add them manually:
  ```bash
  sudo usermod -aG tapauthd-clients $USER
  ```
- System services with dedicated users can be added to this group if they need non-root access to the socket.

## License

See the main LICENSE file in the repository root.
