# SELinux Configuration for TapAuth

TapAuth requires SELinux policy adjustments to allow display managers (like SDDM) and screen lockers to connect to the tapauthd socket.

## Problem

By default, SELinux blocks `xdm_t` (display managers like SDDM) from writing to the tapauthd socket, `/run/tapauthd/tapauthd.sock` (`root:tapauthd-clients 0660`, `systemd/tapauthd.socket`), which has the `var_run_t` context. This prevents authentication from working at the login screen and lock screen.

## Solution

Generate and install a custom SELinux policy module to allow the necessary socket access.

### Automatic Policy Generation

The easiest method is to let `audit2allow` generate the policy from actual denials:

```bash
# 1. Attempt to log in (this will be denied and logged)
# 2. Generate policy from the denial
sudo ausearch -m avc -ts recent | grep tapauthd | audit2allow -M tapauth_sddm

# 3. Install the policy module
sudo semodule -i tapauth_sddm.pp
```

### Manual Policy (Alternative)

If you prefer to create the policy manually, create a file `tapauth_sddm.te`:

```
module tapauth_sddm 1.0;

require {
        type var_run_t;
        type xdm_t;
        class sock_file write;
}

#============= xdm_t ==============
allow xdm_t var_run_t:sock_file write;
```

Then compile and install:

```bash
checkmodule -M -m -o tapauth_sddm.mod tapauth_sddm.te
semodule_package -o tapauth_sddm.pp -m tapauth_sddm.mod
sudo semodule -i tapauth_sddm.pp
```

## Verification

After installing the policy, verify it's loaded:

```bash
sudo semodule -l | grep tapauth
```

You should see `tapauth_sddm` in the list.

## Troubleshooting

### Check for SELinux Denials

```bash
sudo ausearch -m avc -ts recent | grep tapauthd
```

### Check SELinux Mode

```bash
getenforce
```

Should show `Enforcing`. If it shows `Permissive` or `Disabled`, SELinux is not actively blocking.

### Temporarily Disable (for testing only)

**Warning: Only for debugging. Do not use in production.**

```bash
sudo setenforce 0  # Set to permissive mode
# Test TapAuth
sudo setenforce 1  # Re-enable enforcing mode
```

## Integration with Install Script

The install script does not automatically configure SELinux. This must be done manually after installation, as it requires:
1. Attempting authentication to generate denials
2. Using those denials to create the policy

What the installer *does* do is label restoration, not policy: it runs
`restorecon` (when available) on the installed daemon, PAM module and GUI, on the
systemd units and the PolKit drop-in, and `restorecon -RF` over
`/var/lib/tapauth`, `/var/log/tapauth` and `/run/tapauthd` including the socket
(`install.sh`). That only re-applies the distribution's default labels, so the
`sock_file` access rule above is still something you have to add. At the end of a
run the installer also notices `getenforce` reporting `Enforcing` and prints the
`ausearch … | audit2allow -M tapauth_sddm && sudo semodule -i tapauth_sddm.pp`
quick fix from the section above.

Consider running the automatic policy generation as part of your first-time setup after installing TapAuth.
