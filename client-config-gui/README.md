# TapAuth Configuration GUI

A graphical user interface for managing TapAuth authentication pairings on Linux desktop systems.

## Features

- Pair new authentication devices
- View and manage existing pairings
- Automatic privilege escalation (runs as root when needed)
- User-specific pairing management (preserves original username)

## Installation

### From Source

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt install libdbus-1-dev pkg-config libssl-dev

# Build and install
cd client-config-gui
sudo ./install.sh
```

The install script will:
- Build the release binary
- Install to `/usr/bin/tapauth-config`
- Install polkit policy for privilege escalation
- Install desktop file for application menu

### Running

The application can be launched in several ways:

```bash
# From terminal (will auto-elevate with pkexec/sudo)
tapauth-config

# Via application menu
# Search for "TapAuth Configuration" in your application launcher

# Manually with pkexec
pkexec tapauth-config

# Manually with sudo
sudo tapauth-config
```

## Privilege Escalation

TapAuth Configuration GUI requires root privileges to manage system-wide authentication pairings in `/etc/tapauth/`.

**How it works:**

1. When you run `tapauth-config`, it detects if it's running as root
2. If not running as root, it automatically attempts privilege escalation:
   - First tries `pkexec` (recommended - shows graphical authentication dialog)
   - Falls back to `sudo` (terminal-based authentication)
3. **Your original username is preserved** for pairing management
4. All pairings are associated with the user who initiated the configuration

**Security Model:**

- The polkit policy requires administrator authentication
- Even when running as root, pairings are tied to specific usernames
- Alice's pairings can only authenticate Alice, not other users
- Prevents privilege escalation attacks

## User-Specific Pairing

Each pairing is tied to the specific user who created it:

- When **Alice** pairs a device → only Alice can authenticate with it
- When **Bob** pairs the same device → device allows both Alice and Bob
- Prevents unprivileged users from authenticating as root

This is enforced at both client and server sides for security.

## Uninstallation

```bash
cd client-config-gui
sudo ./uninstall.sh
```

This removes:
- Binary from `/usr/bin/tapauth-config`
- Polkit policy
- Desktop file

**Note:** User pairing data in `/etc/tapauth/` is NOT removed automatically. To completely remove all data:

```bash
sudo rm -rf /etc/tapauth/
```

## Development

### Building

```bash
cargo build          # Debug build
cargo build --release  # Release build
```

### Running Without Installation

```bash
# Must be run with sudo/pkexec to access /etc/tapauth/
sudo cargo run
# or
pkexec cargo run
```

### Architecture

The GUI uses:
- **iced** framework for cross-platform UI
- **shared** crate for crypto and protocol logic
- **elevation** module to handle privilege escalation
- Environment variable `TAPAUTH_ORIGINAL_USER` to preserve username

## Troubleshooting

### "Not running as root" error

If you see this error, the automatic elevation failed. Try:

```bash
pkexec tapauth-config
# or
sudo tapauth-config
```

### pkexec authentication dialog doesn't appear

Some desktop environments may not have polkit authentication agents running. Install one:

```bash
# GNOME
sudo apt install polkit-gnome

# KDE
sudo apt install polkit-kde-agent-1

# XFCE
sudo apt install xfce-polkit
```

### Permission denied accessing /etc/tapauth/

The configuration directory must be readable/writable by root. The application handles this automatically when run with proper privileges.

## Security Considerations

1. **Privilege Separation**: Application elevates only when needed
2. **Username Preservation**: Original user tracked even when running as root
3. **Per-User Pairings**: Each pairing tied to specific username(s)
4. **Audit Trail**: All operations logged for security monitoring
5. **Polkit Integration**: Standard Linux authentication mechanism

## License

See LICENSE file in repository root.
