# Privilege Escalation Implementation - Client Config GUI

## Summary

Implemented automatic privilege escalation for the TapAuth Configuration GUI to allow non-root users to manage system-wide authentication pairings while preserving their original username for user-specific pairing enforcement.

## Files Created/Modified

### New Files

1. **`src/utils/elevation.rs`**
   - `is_root()` - Checks if running as root (via `libc::geteuid()`)
   - `get_original_user()` - Retrieves original username before elevation
   - `get_username_from_uid()` - Converts UID to username using libc
   - `attempt_privilege_escalation()` - Attempts pkexec/sudo elevation

2. **`dev.rourunisen.tapauth.policy`**
   - Polkit policy file for graphical authentication
   - Defines `dev.rourunisen.tapauth.configure` action
   - Requires admin authentication

3. **`tapauth-config.desktop`**
   - Desktop entry file for application menu
   - Uses `pkexec tapauth-config` for automatic elevation
   - Categories: Settings, Security, System

4. **`install.sh`**
   - Installs binary to `/usr/bin/tapauth-config`
   - Installs polkit policy
   - Installs desktop file
   - Updates desktop database

5. **`uninstall.sh`**
   - Removes all installed files
   - Preserves user data in `/etc/tapauth/`

6. **`README.md`**
   - Complete documentation
   - Installation instructions
   - Troubleshooting guide
   - Security model explanation

### Modified Files

1. **`src/main.rs`**
   - Added privilege escalation check on startup
   - Preserves original username in `TAPAUTH_ORIGINAL_USER` env var
   - Logs username for debugging

2. **`src/utils/mod.rs`**
   - Added `pub mod elevation;` to expose elevation utilities

3. **`Cargo.toml`**
   - Added `libc = "0.2"` dependency for UID/username lookups

## How It Works

### Username Preservation Flow

1. **User runs `tapauth-config`** as normal user "alice"
2. **`get_original_user()`** is called immediately:
   - Checks `TAPAUTH_ORIGINAL_USER` env var (set during elevation)
   - Checks `PKEXEC_UID` (set by pkexec) and converts to username
   - Checks `SUDO_USER` (set by sudo)
   - Falls back to current `USER` env var
3. **Not running as root?** → Call `attempt_privilege_escalation("alice")`
4. **Elevation attempt**:
   - Try: `pkexec` with `TAPAUTH_ORIGINAL_USER=alice` env var
   - Fallback: `sudo` with `TAPAUTH_ORIGINAL_USER=alice` env var
   - Both preserve the original username
5. **Re-executed process** runs with root privileges but knows original user
6. **Username stored** in environment: `TAPAUTH_ORIGINAL_USER=alice`
7. **Pairing operations** use "alice" for user-specific enforcement

### Privilege Escalation Methods

**Primary: pkexec (Polkit)**
- Graphical authentication dialog
- User-friendly on modern Linux desktops
- Respects polkit policies
- Preserves environment variables we set

**Fallback: sudo**
- Terminal-based authentication
- Works on systems without graphical polkit agents
- Standard on all Linux systems
- Also preserves environment variables

**Error Handling**
- If both fail, shows user-friendly error message
- Explains how to run manually with proper privileges

## Security Model

### Multi-Layer Security

1. **Privilege Separation**
   - App starts as normal user
   - Only elevates when actually needed
   - Environment variables track original user

2. **Polkit Integration**
   - Standard Linux authentication mechanism
   - Respects system policies
   - Configurable per-distribution

3. **Username Preservation**
   - Original user tracked throughout execution
   - Used for pairing enforcement
   - Prevents privilege escalation attacks

4. **User-Specific Pairings**
   - Alice pairs device → only Alice can use it
   - Bob pairs same device → device allows both
   - Root cannot use Alice's pairing without re-pairing

### Attack Prevention

**Scenario**: Unprivileged user tries to use root's pairing
- ❌ **Blocked**: Pairing has `allowed_users: ["root"]`
- ❌ User "alice" is not in list
- ❌ Authentication silently rejected

**Scenario**: Alice runs config GUI as root via sudo
- ✅ **Safe**: `SUDO_USER=alice` detected
- ✅ Original username preserved
- ✅ Pairing created with `allowed_users: ["alice"]`
- ✅ Only Alice can use this pairing

## Installation

### System Installation

```bash
cd client-config-gui
sudo ./install.sh
```

Installs to:
- `/usr/bin/tapauth-config` - Binary
- `/usr/share/polkit-1/actions/dev.rourunisen.tapauth.policy` - Policy
- `/usr/share/applications/tapauth-config.desktop` - Desktop entry

### Running

```bash
# From terminal (auto-elevates)
tapauth-config

# From app menu
# Search: "TapAuth Configuration"

# Manual elevation
pkexec tapauth-config
sudo tapauth-config
```

## Testing

### Test Privilege Escalation

```bash
# As normal user
cd client-config-gui
./target/release/tapauth-config

# Should automatically prompt for authentication
# After authentication, should run with root privileges
# Should log: "Running as root for user: <your-username>"
```

### Test Username Preservation

```bash
# Run with pkexec
pkexec ./target/release/tapauth-config
# Check logs for: "Running as root for user: <original-username>"

# Run with sudo
sudo ./target/release/tapauth-config
# Check logs for: "Running as root for user: <SUDO_USER>"

# Run directly as root (su -)
su -
./target/release/tapauth-config
# Should show: "Running as root for user: root"
```

### Test Pairing with Preserved Username

1. Run as user "alice": `tapauth-config`
2. Pair a device
3. Check `/etc/tapauth/paired_servers.json`
4. Should show: `"allowed_users": ["alice"]`
5. Try authenticating as "bob" → should fail
6. Try authenticating as "alice" → should succeed

## Dependencies

### Runtime
- `pkexec` (polkit) - Recommended for graphical auth
- `sudo` - Fallback for terminal auth
- Polkit authentication agent (desktop-dependent)

### Build
- `libc` crate - For UID/username lookups

### System
- Linux with polkit support
- `/etc/tapauth/` directory for configuration

## Troubleshooting

### No polkit agent installed
```bash
# GNOME
sudo apt install polkit-gnome

# KDE  
sudo apt install polkit-kde-agent-1

# XFCE
sudo apt install xfce-polkit
```

### pkexec fails
- Use sudo fallback: `sudo tapauth-config`
- Check polkit installation: `which pkexec`
- Check polkit agent: `ps aux | grep polkit`

### Username not preserved
- Check environment: `echo $TAPAUTH_ORIGINAL_USER`
- Check logs for username detection
- Verify elevation method sets environment correctly

## Future Enhancements

1. **Better Error Messages**
   - Detect missing polkit agents
   - Suggest installation commands

2. **Additional Elevation Methods**
   - `gksu`/`kdesu` support (legacy systems)
   - `doas` support (OpenBSD-style)

3. **Configuration**
   - Allow user to choose elevation method
   - Remember preferred method

4. **Wayland Support**
   - Test with Wayland compositors
   - Verify polkit integration works

## References

- [Polkit Documentation](https://www.freedesktop.org/software/polkit/docs/latest/)
- [Desktop Entry Specification](https://specifications.freedesktop.org/desktop-entry-spec/latest/)
- User-Specific Pairing Implementation (see `USER_SPECIFIC_PAIRING_IMPLEMENTATION.md`)
