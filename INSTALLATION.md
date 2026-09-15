# TapAuth Installation Guide

This guide covers the installation and uninstallation of TapAuth using the interactive scripts.

## Native Distribution Packages

You can install tapauth via native package repositories to receive automatic updates verified by your system's package manager.

### What the packages configure

- **PAM scope: `sudo`, `su` and `polkit-1` only.** The package scriptlets insert `auth sufficient pam_tapauth.so` into those three stacks and keep a one-time `<file>.tapauth-bak` snapshot. On removal they **strip only the TapAuth line** and delete the snapshot (they never copy the snapshot back, so later admin/vendor changes survive); an explicit rollback is available via `uninstall.sh --restore-pam-backups`. Vendor-drift triggers/hooks re-apply the line after an upgrade of the owning package. In `su` the line is inserted **after** `pam_rootok.so`/`pam_wheel.so` (and after `pam_env.so` when present), because `PAM_USER` for `su` is the target user — inserting it first would let a phone grant for `root` bypass the wheel/root checks. `login` is deliberately **not** patched.
- **The virtual fprintd bridge is opt-in and off by default.** The base packages ship no marker and no D-Bus activation file — only the D-Bus **policy** file that lets `tapauthd` own `net.reactivated.Fprint` when enabled. A base install therefore leaves the bus name to a real local fprintd. Install the optional `tapauth-fprintd-emulation` package (which ships the marker `/usr/share/tapauth/fprintd-emulation.enabled`) or set `enable_fprintd_bridge = true` to enable it. (On machines with no physical fingerprint reader, the optional package can also ship `pam_fprintd.so` itself — see [No physical fingerprint reader? Optional emulation package](#no-physical-fingerprint-reader-optional-emulation-package) below.)
- **When enabled, desktop lock screens and greeters (KDE Plasma, GNOME) integrate automatically.** No manual PAM edits and no local fingerprint reader required; stock fingerprint stacks call `pam_fprintd.so`, which resolves to TapAuth's built-in virtual fprintd service. The bridge state is read at `tapauthd` startup, so it applies on the next daemon restart.
- **Daemon lifecycle:** both `tapauthd.socket` and `tapauthd.service` are enabled via the shipped systemd preset (the service must run at boot so the opt-in bridge can be claimed at startup); `tapauthd.service` is additionally started at install so the daemon answers IPC immediately.
- **Socket access for desktop users:** the `tapauthd-clients` group owns `/run/tapauthd/tapauthd.sock` (`root:tapauthd-clients`, mode `0660`). Membership is **not** granted automatically: each desktop user who needs the configuration GUI or user-session lock-screen unlock (e.g. KDE's `kscreenlocker_worker`, which runs as the logged-in user) must add themselves (see the per-distro rows below) and **log out and back in** (or otherwise re-initialise their process's group list) for it to take effect. The source `install.sh` is the sole exception — it adds only the installing user, never every interactive user. This only matters for user-session lockers / the opt-in `pam_fprintd.so` emulation path — greeters and auth helpers that run as root (GDM/SDDM/LightDM) are unaffected. The membership is **not** removed on uninstall/purge.

### 1. Fedora Linux
Packages are built and tracked using Fedora COPR.
```bash
sudo dnf copr enable lolle2000la/tapauth
sudo dnf install tapauth
```
* **Group Membership:** The `tapauthd-clients` group owns the daemon socket (`/run/tapauthd/tapauthd.sock`, mode `0660`). Membership is **not** granted automatically; add yourself to use the configuration GUI or unlock a user-session lock screen:
  ```bash
  sudo usermod -aG tapauthd-clients $USER
  ```
  *(Log out and back in — or otherwise re-initialise the process's group list — for group membership to take effect. This matters for user-session components such as a lock-screen worker reaching the daemon socket; root auth helpers/greeters (GDM/SDDM/LightDM) are unaffected.)*

* **PAM Configuration:** The package scriptlets patch `sudo`, `su` and `polkit-1` directly (one-time `.tapauth-bak` snapshots). Removal strips only the TapAuth line and deletes the snapshots; a `%triggerin` re-applies the line after an upgrade of the owning package (`polkit`, `sudo`, `util-linux`/`coreutils`). Do **not** use `authselect` vendor profiles with TapAuth — current releases ship no authselect profiles. If you previously enabled one from an older TapAuth release (≤ 0.10.x), removing/upgrading the package rolls the selection back to the stock profile automatically.

* **SELinux Integration:** On Fedora systems with SELinux in Enforcing mode, the package automatically installs the `tapauth.cil` policy module so desktop display managers (GDM, KDE Plasma) can communicate with the daemon socket. If you encounter any AVC denials after a major system update, reload the policy with:
  ```bash
  sudo semodule -i /usr/share/selinux/packages/tapauth.cil
  ```

### 2. Ubuntu / Debian
Packages are published via a Launchpad Personal Package Archive (PPA).
```bash
sudo add-apt-repository ppa:lolle2000la/tapauth
sudo apt-get update
sudo apt-get install tapauth
```
* **Group Membership:** The `tapauthd-clients` group owns the daemon socket (`/run/tapauthd/tapauthd.sock`, mode `0660`). Membership is **not** granted automatically; add yourself to use the configuration GUI or unlock a user-session lock screen:
  ```bash
  sudo usermod -aG tapauthd-clients $USER
  ```
  *(Log out and back in — or otherwise re-initialise the process's group list — for group membership to take effect. This matters for user-session components such as a lock-screen worker reaching the daemon socket; root auth helpers/greeters (GDM/SDDM/LightDM) are unaffected.)*

* **PAM Configuration:** Installation patches `sudo`, `su` and `polkit-1` directly (one-time `<file>.tapauth-bak` snapshots; removal strips only the TapAuth line and deletes the snapshots). TapAuth does **not** register a `pam-auth-update` profile anymore. Upgrading from TapAuth ≤ 0.10.x (which used `pam-auth-update`) automatically regenerates the managed stacks so the old `common-auth` line is removed — on upgrade and on plain `apt remove tapauth`.
* **Debian/Ubuntu PAM integration and policy note:** TapAuth edits PAM conffiles owned by other packages (`sudo`, `util-linux`, `policykit-1`), a deliberate, minimal deviation from Debian Policy §10.7.3/§10.7.4. It does not use `pam-auth-update` because that mechanism only manages the shared `common-*` stacks (and previously also hit `login`); the three-file scope is intentional. The reasoning, the one-time backup/removal-strip behaviour, the vendor-drift re-apply triggers and the manual `tapauthd-clients` opt-in are documented in the package's `/usr/share/doc/tapauth/README.Debian` (source: `packaging/debian/README.Debian`).

### 3. Arch Linux / CachyOS
The packages are available via the Arch User Repository (AUR).
```bash
paru -S tapauth
# or alternatively
yay -S tapauth
```
* **Service Activation:** The install scriptlet applies the shipped systemd preset (`tapauthd.socket` enabled, `tapauthd.service` started at install), so no manual `systemctl enable --now` is required.

* **Group Membership:** The `tapauthd-clients` group owns the daemon socket (`/run/tapauthd/tapauthd.sock`, mode `0660`). Membership is **not** granted automatically; add yourself to use the configuration GUI or unlock a user-session lock screen:
  ```bash
  sudo usermod -aG tapauthd-clients $USER
  ```
  *(Log out and back in — or otherwise re-initialise the process's group list — for group membership to take effect. This matters for user-session components such as a lock-screen worker reaching the daemon socket; root auth helpers/greeters (GDM/SDDM/LightDM) are unaffected.)*

* **PAM Configuration:** The install scriptlet patches `sudo`, `su` and `polkit-1` (seeding `/etc/pam.d` overrides from `/usr/lib/pam.d` vendor files where applicable, with one-time `.tapauth-bak` snapshots). Removal strips only the TapAuth line and deletes the snapshots. A libalpm hook (`tapauth-pam-vendor-drift`) re-applies the line for `sudo`, `su` and `polkit-1` when the owning package is upgraded. No manual PAM editing is required.

## Desktop Lock Screen Integration (GNOME & KDE Plasma)

Modern Linux desktop lock screens (KDE Plasma's `kscreenlocker` and GNOME's `gdm`/`gnome-shell`) support simultaneous password and biometric authentication through virtual fingerprint emulation.

### Built-in virtual fprintd bridge (opt-in)

TapAuth ships an embedded virtual `fprintd` D-Bus service (`net.reactivated.Fprint`) in the daemon — no extra package is needed. **The bridge is opt-in and off by default**: a base install ships no marker file, so the `net.reactivated.Fprint` bus name stays with a real local `fprintd` (if installed) and a physical reader is never shadowed. Enable it by installing the optional `tapauth-fprintd-emulation` package (it ships the marker `/usr/share/tapauth/fprintd-emulation.enabled`), or by setting `enable_fprintd_bridge = true` explicitly.

Once enabled, when your screen is locked, Plasma and GNOME query `net.reactivated.Fprint` on D-Bus. If paired phones exist for your user, the desktop shows biometric authentication prompts in parallel with the password prompt. Approving on your phone immediately unlocks the session; typing your password also unlocks immediately and cancels the pending phone request.

TapAuth's daemon (`tapauthd`) claims the `net.reactivated.Fprint` bus name while it runs **only when the bridge is enabled**, so a real fprintd daemon stays in charge otherwise. The base packages ship **no D-Bus activation file** (only the D-Bus policy): both `dbus-daemon` and `dbus-broker` only use activation files named exactly after the bus name, so real fprintd's own `net.reactivated.Fprint.service` keeps full control of on-demand activation and tapauthd's availability comes from systemd.

> **Note:** `enable_fprintd_bridge` is **tri-state** — unset (default) follows the emulation marker, `true` forces the bridge on, `false` forces it off. Any change takes effect at the next **daemon restart** (`sudo systemctl restart tapauthd.service`), not dynamically.

### Using a real hardware fingerprint reader

A base install already leaves a real local fingerprint reader in charge (no marker → bridge off). If you enabled the bridge and want the reader back:

1. Keep (or install) the distribution's real `fprintd` package.
2. Either remove the optional `tapauth-fprintd-emulation` package, **or** set `enable_fprintd_bridge = false` in `/etc/tapauth/config.toml`.
3. Restart the daemon: `sudo systemctl restart tapauthd.service`.

TapAuth then never claims the bus name and real fprintd handles all fingerprint requests again. PAM authentication for `sudo`, `su` and `polkit-1` via your paired phone continues to work independently. `install.sh` writes `enable_fprintd_bridge = false` automatically when it detects a real fprintd installation.

To return to phone-based lock screen unlock, install `tapauth-fprintd-emulation` (or set `enable_fprintd_bridge = true`) and restart the daemon.

### No physical fingerprint reader? Optional emulation package

On machines with **no** fingerprint reader, the built-in virtual fprintd D-Bus bridge above provides lock-screen integration once it is enabled. Some distributions, however, only offer biometric login when a PAM module named `pam_fprintd.so` is present on disk. For that case TapAuth publishes an **optional, opt-in** package that installs a second build of its PAM module under that exact name, so stock fingerprint PAM stacks route to your phone without any real fprintd hardware. The same package **also ships the bridge marker** `/usr/share/tapauth/fprintd-emulation.enabled`, so installing it enables the virtual fprintd bridge (for lock-screen discovery) as a side effect. Its package scriptlets bounce `tapauthd` so the bus name is claimed/released immediately:

| Install path | Package / flag |
| :--- | :--- |
| **Fedora Linux (COPR)** | `tapauth-fprintd-emulation` |
| **Ubuntu / Debian (PPA)** | `tapauth-fprintd-emulation` |
| **Arch Linux / CachyOS (AUR)** | `tapauth-fprintd-emulation` or `tapauth-fprintd-emulation-git` |
| **Source install (`install.sh`)** | `sudo ./install.sh --fprintd-emulation` |

For example:

```bash
# Fedora
sudo dnf install tapauth-fprintd-emulation
# Ubuntu / Debian
sudo apt-get install tapauth-fprintd-emulation
# Arch Linux / CachyOS
paru -S tapauth-fprintd-emulation
# Source install
sudo ./install.sh --fprintd-emulation
```

This package **conflicts with, replaces and provides** the distribution's own fingerprint PAM provider (`libpam-fprintd` on Debian/Ubuntu, `fprintd-pam` on Fedora/RHEL, monolithic `fprintd` on Arch), because only one package can own `pam_fprintd.so`. The base `tapauth` package is unchanged: it still deliberately does **not** conflict with fprintd, ships no bridge marker, and ships no D-Bus activation file.

> **Prefer a physical reader if you have one.** The emulation package is intended only for machines without (or not wanting to use) a real fingerprint sensor. If your hardware has one, keep the base package and the distribution's real fprintd.

To undo the emulation package, remove it and reinstall the distribution's fingerprint PAM provider (removing the package also removes the bridge marker, and its scriptlets bounce `tapauthd` so it releases the bus name):

```bash
# Fedora
sudo dnf remove tapauth-fprintd-emulation && sudo dnf install fprintd-pam
# Ubuntu / Debian
sudo apt-get remove tapauth-fprintd-emulation && sudo apt-get install libpam-fprintd
# Arch Linux / CachyOS
sudo pacman -R tapauth-fprintd-emulation && sudo pacman -S fprintd
```

For a source install, `sudo ./uninstall.sh --fprintd-emulation` removes the replacement and restores any backed-up distro `pam_fprintd.so`.

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

This shows detailed diffs of PAM configuration changes, files that will be created, and commands that will be executed.

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

This installs everything with default settings (including PAM configuration for `sudo`, `su` and `polkit-1`).

## Installation Script (`install.sh`)

### Features

- **Privilege Separation**: Builds run as the original user (via `$SUDO_USER`) even when run with `sudo`, preventing root-owned files in the cargo cache
- **Optimized Build**: Builds all components in release mode with `-C target-cpu=native -C opt-level=3`
- **Component Installation**: Builds and installs all TapAuth components (PAM module, daemon, Config GUI)
- **Bluetooth Support (daemon)**: Optional — build the daemon with or without Bluetooth (BLE) support
- **PAM Configuration**: Patches `sudo`, `su` and `polkit-1` (opt-in per service; `login` deliberately excluded)
- **TPM Support**: Optional TPM integration for secure key storage
- **Virtual fprintd Bridge**: Built-in and **opt-in** (off by default); enabled by the `tapauth-fprintd-emulation` package's marker or an explicit `enable_fprintd_bridge = true`, and automatically forced off when a real hardware fprintd installation is detected
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
    -f, --force             Force installation over existing packages/files without prompting
    --no-ble                Build daemon without Bluetooth support (UDP only)
    --use-tpm               Enable TPM support for key storage
    --configure-su          Configure PAM for su (root shells via su)
    --configure-sudo        Configure PAM for sudo authentication
    --configure-polkit      Configure PAM for polkit authentication
    --build-only            Only build, don't install
    --dry-run               Show what would be done without doing it

NOTES:
    All components (PAM module, daemon, configuration GUI) are always installed.
    Only feature flags (BLE, TPM) and PAM configuration locations are configurable.

    PAM scope is sudo, su and polkit-1 only (see "What the packages configure"
    above for the lock screen story).
```

### Examples

#### Install Everything Interactively
```bash
sudo ./install.sh
```

#### Install Non-Interactively With All PAM Services Configured
```bash
sudo ./install.sh --yes
```

#### Install Without BLE (daemon only)
```bash
sudo ./install.sh --no-ble --configure-sudo
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
sudo ./install.sh --use-tpm --configure-sudo
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
    -h, --help                  Show help message
    -n, --non-interactive       Run in non-interactive mode
    -y, --yes                   Answer yes to all prompts (non-interactive; does NOT remove user data)
    --purge, --remove-user-data Remove user configuration data (keys, pairings; use with caution)
    --restore-pam-backups       Roll PAM files back to their install-time
                                .tapauth-bak snapshots (default: strip only the
                                TapAuth-inserted lines and delete the snapshots)
    --preserve-system-accounts  Preserve system user and group (tapauthd, tapauthd-clients)
    --dry-run                   Show what would be done without doing it
```

### Examples

#### Interactive Uninstallation
```bash
sudo ./uninstall.sh
```

#### Complete Removal (Purge User Data and Pairings)
```bash
sudo ./uninstall.sh --yes --purge
```

#### Uninstall While Preserving Pairing Keys & System Accounts (e.g. for Upgrades or Switching to Packages)
```bash
sudo ./uninstall.sh --yes --preserve-system-accounts
```

#### Preview Uninstallation (Dry Run)
```bash
./uninstall.sh --dry-run
```

This will show detailed information about what would be removed, including:
- Files that would be deleted
- Commands that would be executed
- Diffs showing PAM configuration changes
- Impact on system services

**No root access required for dry-run mode.**

### Migrating Between Installation Methods

If you previously installed TapAuth using `install.sh` and wish to switch to native distribution packages (`.deb`, `.rpm`, or Arch PKGBUILD), or vice versa:

#### Switching from `install.sh` to Distribution Packages
1. **Uninstall source files while preserving keys and system accounts**:
   ```bash
   sudo ./uninstall.sh --yes --preserve-system-accounts
   ```
   This safely cleans up the source binaries and PAM files without wiping `/var/lib/tapauth/` or removing user group memberships.
2. **Install your distribution's package**:
   - **Ubuntu / Debian**: `sudo apt install tapauth`
   - **Fedora**: `sudo dnf install tapauth`
   - **Arch Linux**: `yay -S tapauth`
   The newly installed package automatically detects existing pairings in `/var/lib/tapauth/` and configuration in `/etc/tapauth/config.toml`.

#### Switching from Distribution Packages to `install.sh`
1. **Uninstall the package**:
   - **Ubuntu / Debian**: `sudo apt remove tapauth` (or `sudo apt purge` to delete configuration)
   - **Fedora**: `sudo dnf remove tapauth`
   - **Arch Linux**: `sudo pacman -R tapauth`
2. **Build and install with `install.sh`**:
   ```bash
   ./install.sh
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
#%PAM-1.0
auth    sufficient    pam_tapauth.so      ← NEW: Try phone authentication first
auth    sufficient    pam_unix.so         ← EXISTING: Fall back to password
auth    required      pam_deny.so         ← EXISTING: Deny if all methods fail
```

This is a **safe, non-disruptive** configuration. Your system remains accessible even if:
- Your phone is off or out of range
- TapAuth is uninstalled (the package scriptlets strip only the `pam_tapauth.so` lines; the `.tapauth-bak` snapshots are not copied back)
- Network connectivity is unavailable

**For detailed information about PAM integration, security, and troubleshooting, see the design document [Desktop & Lockscreen Integration Plan](docs/design-documents/desktop-and-lockscreen-integration-plan.md), the distro packaging scriptlets in `packaging/` (the source of truth for the PAM wiring), and [SELINUX.md](docs/SELINUX.md) for SELinux troubleshooting.**

### When Do Changes Take Effect?

PAM modules are loaded dynamically - **no system restart is required**:

- **sudo**: Changes take effect **immediately** - test right away with `sudo -k && sudo echo test`
- **polkit**: Changes take effect **immediately** - GUI privilege dialogs will use TapAuth
- **Lock screens / greeters**: When the bridge is enabled, it becomes live when `tapauthd` (re)starts — install `tapauth-fprintd-emulation` (its scriptlets restart the daemon) or set `enable_fprintd_bridge = true` and run `sudo systemctl restart tapauthd.service`

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
- SELinux: the package ships and installs a `tapauth.cil` policy module; `install.sh` restores default labels on `/var/lib/tapauth` and `/run/tapauthd` (via `restorecon` if available). See the SELinux note in the Fedora section above.

#### Ubuntu/Debian
- Ensure `libpam0g-dev` is installed for PAM development
- Ensure BlueZ is installed and running for BLE support: `sudo apt install bluez`

#### Arch Linux
- Ensure `pam` package is installed
- May need to enable bluetooth service: `sudo systemctl enable bluetooth`

### PAM Issues

If you get locked out:
1. Boot into recovery mode or single-user mode
2. Strip the `pam_tapauth.so` lines (this is what package removal does by default):
   ```bash
   for f in /etc/pam.d/sudo /etc/pam.d/su /etc/pam.d/polkit-1; do
       [ -f "$f" ] && sed -i '/pam_tapauth\.so/d' "$f"
   done
   ```
   Or, if a `.tapauth-bak` snapshot still exists and you explicitly want the install-time state back:
   ```bash
   for f in /etc/pam.d/sudo /etc/pam.d/su /etc/pam.d/polkit-1; do
       [ -s "$f.tapauth-bak" ] && cp -p "$f.tapauth-bak" "$f"
   done
   ```
3. Reboot

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
- Bluetooth adapter not available or powered off (fall back to the Local Network/UDP transport)

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
local rustflags="-Ctarget-cpu=native -Copt-level=3"

# To (for example, generic x86_64):
local rustflags="-Ctarget-cpu=x86-64 -Copt-level=3"
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

- **Default**: All shipped binaries (`tapauthd`, `tapauth-config`, `pam_tapauth.so`), systemd units/sockets, the D-Bus policy file, and all PAM configuration entries (all `pam_tapauth.so` references are automatically stripped to prevent system lockouts). Note: `tapauth-ipc-cli` is a testing-only admin tool, is not installed by `install.sh` or any distro package, and is left untouched.
- **Optional (`--purge` / `--remove-user-data`)**: User pairing keys and device pairings in `/var/lib/tapauth/`.

### What Gets Preserved

By default, the uninstall script preserves:
- User encryption keys and paired devices in `/var/lib/tapauth/` (retained for reinstallation unless `--purge` is passed)
- System accounts (`tapauthd`, `tapauthd-clients`) when `--preserve-system-accounts` is passed

By default it **deletes** the one-time `.tapauth-bak` snapshots after stripping the TapAuth lines; pass `--restore-pam-backups` to roll those files back to the snapshots instead.

To completely purge everything including pairing keys:
```bash
sudo ./uninstall.sh --yes --purge
```

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review system logs: `journalctl -xe`
3. For BLE issues, run: `./scripts/bluetooth-check.sh`
4. Verify PAM configuration: `grep tapauth /etc/pam.d/sudo /etc/pam.d/su /etc/pam.d/polkit-1`

### Socket access policy

The IPC socket `/run/tapauthd/tapauthd.sock` is created as `root:tapauthd-clients` with mode `0660`.
- Every install method creates the group `tapauthd-clients`, but membership is a manual, per-user opt-in: the distribution packages add nobody, and `install.sh` adds only the installing user (the one who ran it).
- A logout/login cycle (or otherwise re-initialising the process's group list) is required for the new group membership to take effect.
- Membership is intentionally **not** removed on uninstall/purge (only the group itself is removed on purge), so a reinstall does not have to re-add every user.
- If you need to grant access to additional users, add them manually:
  ```bash
  sudo usermod -aG tapauthd-clients $USER
  ```
- System services with dedicated users can be added to this group if they need non-root access to the socket.

## License

See the main LICENSE file in the repository root.
