# TPM 2.0 Support in TapAuth

## Overview

TapAuth supports TPM (Trusted Platform Module) 2.0 hardware for **hardware-backed key security**. When enabled, Ed25519 private keys are sealed with the TPM's Storage Root Key (SRK), so no usable copy exists on disk — not even for root.

**Key Security Model:**
- **TPM Enabled**: Keys sealed in TPM hardware only - no plaintext on disk ✓
- **TPM Disabled**: Keys stored as files with 600 permissions - readable by root ⚠️

One narrowing belongs with the first bullet: the seal carries **no authorisation
policy** — TapAuth passes only a PCR list to `tpm2_create` (no `-p` auth value,
no signed policy), so the PCR values are the sole gate. Anyone who can run
`tpm2_load`/`tpm2_unseal` against the sealed files *and* whose boot state matches
the PCRs unseals the key; what root cannot do without the TPM is read it off the
disk.

## How It Works

Since TPM 2.0 doesn't natively support Ed25519 signatures, TapAuth uses `tpm2-tools` CLI for sealing:

1. **TPM Sealing**: The TPM creates an encrypted blob bound to the Storage Root Key (SRK)
2. **Key Protection**: The Ed25519 private key (32 bytes) is sealed using `tpm2_create`
3. **Machine Binding**: Sealed keys can only be unsealed by the same TPM chip
4. **No Plaintext Backup**: Maximum security - key exists only sealed or in daemon memory

## Architecture

```
TPM 2.0 Enabled (Secure Mode):
  
  Ed25519 Key → TPM Seal (SRK) → Encrypted Blob
  (32 bytes)                      └─→ client_key.pub / client_key.priv
                                      /var/lib/tapauth/
  
  ✓ Hardware-protected
  ✓ No usable key file (not even for root)
  ✓ Machine-bound (cannot unseal on different TPM)
  ⚠ TPM failure = Recovery via GUI required


TPM 2.0 Disabled (File Mode):

  Ed25519 Key → File (600 perms) → client_key
  (32 bytes)                        /var/lib/tapauth/
  
  ⚠ Protected only by Unix permissions
  ⚠ Root can read/copy key
  ✓ No hardware dependency
  ✓ Works on any system
```

## Security Properties

| Feature | TPM Enabled (Standard) | TPM Enabled (Paranoid) | TPM Disabled |
|---------|------------------------|------------------------|--------------|
| **Root Protection** | ⚠️ No usable file; root can still unseal via this TPM | ⚠️ No usable file; root can still unseal via this TPM | ⚠️ No - file readable |
| **Key Extraction** | ⚠️ Only through this machine's TPM | ⚠️ Only through this machine's TPM | ⚠️ Possible (by root) |
| **Machine Binding** | ✅ Yes - TPM locked | ✅ Yes - TPM locked | ⚠️ No - portable file |
| **Boot Tampering** | ✅ PCR 7+14 protected | ✅ PCR 0+2+7+14 protected | ⚠️ No protection |
| **BIOS Updates** | ✅ Still works | ⚠️ Breaks (regenerate keys) | ✅ N/A |
| **Offline Attacks** | ✅ Protected | ✅ Protected | ⚠️ Vulnerable |
| **Hardware Required** | ⚠️ TPM 2.0 + Secure Boot | ⚠️ TPM 2.0 + Secure Boot | ✅ None |
| **Recovery Frequency** | ⚠️ Rare (only major changes) | ⚠️ Frequent (firmware updates) | ✅ Simple restore |

### Attack Scenarios

**Attacker with root access (system running):**
- TPM Mode: ❌ Cannot read the key off the disk; ⚠️ can unseal it through this machine's TPM while the boot state matches
- File Mode: ✅ Can copy `/var/lib/tapauth/client_key`

**Attacker modifies bootloader (evil maid attack):**
- TPM Mode: ❌ PCR-7 mismatch prevents unseal, attack detected
- File Mode: ✅ Keys work normally, attack succeeds

**Attacker with disk access (system off, disk encrypted):**
- TPM Mode: ❌ Cannot unseal without booting original system + TPM
- File Mode: ❌ Cannot decrypt disk (protected by disk encryption)

**Attacker with disk access (system off, disk NOT encrypted):**
- TPM Mode: ❌ Cannot unseal - requires TPM chip + correct boot state
- File Mode: ✅ Can copy key file and use on different machine

## Installation

### Prerequisites

TPM support requires `tpm2-tools` to be installed:

```bash
# Fedora/RHEL
sudo dnf install tpm2-tools

# Ubuntu/Debian  
sudo apt install tpm2-tools

# Arch
sudo pacman -S tpm2-tools
```

Verify TPM is available:
```bash
tpm2_getrandom 8 --hex
```

**Note**: TPM support is **opt-in** and must be explicitly enabled during build.
The workspace root is a virtual manifest, so name the crates:

```bash
# Build WITH TPM support (the daemon, and the PAM module + GUI it pairs with)
cargo build --release --manifest-path tapauthd/Cargo.toml --features tpm
cargo build --release --manifest-path client-pam/Cargo.toml --features tpm
cargo build --release --manifest-path client-config-gui/Cargo.toml --features tpm

# Or via install script (does all three)
./install.sh --use-tpm

# Default build (no TPM)
cargo build --release --manifest-path tapauthd/Cargo.toml  # ble + firewall, no TPM
```

### Enabling TPM Support

Use the `--use-tpm` flag during installation:

```bash
sudo ./install.sh --use-tpm
```

This will:
1. Check if `tpm2-tools` is installed (with no `--use-tpm` the installer asks, and
   silently disables TPM when the tools are missing)
2. Set `use_tpm = true` in `/etc/tapauth/config.toml`
3. Seal the Ed25519 keypair the first time a device is paired — `StartPairing`
   generates and seals one when no keypair can be loaded yet
4. **Not create** plaintext backup files

## Configuration

TPM support is controlled in `/etc/tapauth/config.toml`:

```toml
# Enable TPM 2.0 for secure key storage
# Requires tpm2-tools to be installed
# Default: false
use_tpm = true

# TPM PCR Sealing Policy - determines boot integrity checks
# Options: "standard" (recommended) or "paranoid"
# Default: "standard"
tpm_pcr_policy = "standard"
```

Both keys exist in the schema only when TapAuth was built with the `tpm`
feature (`shared/src/config/toml_config.rs`, both fields are `#[cfg(feature =
"tpm")]`); a build without the feature ignores them, so `tpm_pcr_policy` is also
left commented out in `config.toml.example`.

### PCR Sealing Policies

TapAuth supports two security levels for TPM key sealing:

#### Standard (Recommended)
- **PCRs**: 7 (Secure Boot state) + 14 (MOK keys)
- **Security**: Prevents evil maid attacks (modified bootloader/kernel)
- **Reliability**: ✅ Won't break on kernel or BIOS updates
- **Requirements**: Secure Boot must be enabled
- **Use case**: Most users - balanced security without maintenance burden

#### Paranoid
- **PCRs**: 0 (BIOS) + 2 (Option ROMs) + 7 (Secure Boot) + 14 (MOK)
- **Security**: Maximum - detects ANY boot chain modification
- **Reliability**: ⚠️ WILL break on BIOS updates and some hardware changes
- **Recovery**: Frequent key regeneration required (re-pair all devices)
- **Use case**: High-security environments where you control firmware updates

**Choosing a Policy:**
```toml
# For most users (stable, secure)
tpm_pcr_policy = "standard"

# For maximum security (high maintenance)
tpm_pcr_policy = "paranoid"
```

**What gets measured:**
- **PCR 0**: BIOS/UEFI firmware code
- **PCR 2**: Option ROM code (device firmware)
- **PCR 7**: Secure Boot state and keys
- **PCR 14**: MokList and MokListX (Machine Owner Keys)

### Enabling TPM After Installation

1. Install `tpm2-tools` (if not already installed)
2. Edit `/etc/tapauth/config.toml`:
   ```bash
   sudo nano /etc/tapauth/config.toml
   ```
3. Set `use_tpm = true`
4. Run the configuration GUI to regenerate keys:
   ```bash
   tapauth-config
   ```
   Click "Recover Keys" if prompted about keypair errors
5. Restart the daemon:
   ```bash
   sudo systemctl restart tapauthd
   ```
6. Re-pair all devices (old keys are invalidated)

### Disabling TPM

1. Edit `/etc/tapauth/config.toml`:
   ```bash
   sudo nano /etc/tapauth/config.toml
   ```
2. Set `use_tpm = false`
3. Run the configuration GUI to regenerate keys:
   ```bash
   tapauth-config
   ```
4. Restart the daemon:
   ```bash
   sudo systemctl restart tapauthd
   ```
5. Re-pair all devices

## File Layout

### With TPM Enabled

```
/etc/tapauth/
└── config.toml                  # use_tpm = true

/var/lib/tapauth/                # 0700 tapauthd:tapauthd
├── client_config.json           # Hostname only (mode 600)
├── client_key.pub               # TPM sealed public portion (tpm2_create output)
├── client_key.priv              # TPM sealed private portion (tpm2_create output)
├── client_symmetric_key         # CSK (mode 600)
└── paired_servers.json          # Server pairings (mode 600)

NO PLAINTEXT KEY FILE EXISTS
```

The sealed pair is written by `tpm2_create` itself, so its mode is whatever the
daemon's umask gives; the enclosing directory is 0700, which is what keeps it
private. (TapAuth's own files — `client_config.json`, `client_key`,
`client_symmetric_key`, `paired_servers.json` — are written through
`write_secure_file`, which forces 0600.)

### With TPM Disabled

```
/etc/tapauth/
└── config.toml                  # use_tpm = false

/var/lib/tapauth/
├── client_config.json           # Hostname only (mode 600)
├── client_key                   # Ed25519 private key PLAINTEXT (mode 600)
├── client_symmetric_key         # CSK (mode 600)
└── paired_servers.json          # Server pairings (mode 600)
```

## Recovery Scenarios

### TPM Failure / Hardware Replacement

If the TPM chip fails or you replace the motherboard:

1. **Symptom**: The daemon starts in **degraded mode** — it stays alive
   (`DaemonState::new` keeps the load error and leaves the keypair `None`) and
   every authentication answers with an error; the PAM module prints
   ```
   TapAuth: Error - Failed to load keypair: <TPM error>. Please open tapauth-config GUI to regenerate keys.
   ```

2. **Login**: Use your password (PAM fallback works)

3. **Open GUI**: Run configuration tool:
   ```bash
   tapauth-config
   ```

4. **Recover**: Click the red "Recover Keys (Will Clear Pairings)" button
   - This deletes old TPM-sealed keys
   - Generates fresh Ed25519 keypair
   - Generates new CSK  
   - Clears all paired servers (they had old public key)

5. **Restart Daemon**:
   ```bash
   sudo systemctl restart tapauthd
   ```

6. **Re-pair Devices**: All phones/tablets must re-pair

### Cannot Unseal Keys

If TPM unsealing fails but hardware is functional:

**Possible causes (vary by PCR policy):**

**Standard policy (PCR 7+14):**
- **Secure Boot was disabled** - PCR-7 value changed
- **Secure Boot keys changed** - New signing keys enrolled
- **MOK keys changed** - Enrolled/removed Machine Owner Keys
- **TPM was cleared/reset** - Firmware settings changed

**Paranoid policy (PCR 0+2+7+14) - additionally:**
- **BIOS/UEFI firmware update** - PCR-0 value changed
- **Hardware changes** - New devices affecting PCR-2 (Option ROMs)
- **Boot order changes** - Different device firmware loaded

**Symptoms:**
- The daemon logs `Failed to load keypair: Failed to unseal key from TPM: <error>. Use tapauth-config GUI to recover.` at startup and stays up in degraded mode
- PAM authentication answers with `PAM_AUTH_ERR`: on a `sufficient` line the stack falls through to password, on a `required` line it fails the stack
- The GUI's main menu shows that error text in red above a "Recover Keys (Will Clear Pairings)" button (`get_daemon_status` reports it while the daemon has no keypair)

**Recovery:** 
1. Check if Secure Boot is still enabled: `mokutil --sb-state`
2. If Secure Boot is disabled, re-enable it in BIOS
3. If using paranoid policy and BIOS was updated, this is expected behavior
4. Use GUI to regenerate keys (all devices must re-pair)

**Note**: If you frequently update BIOS firmware, use `tpm_pcr_policy = "standard"` to avoid constant key regeneration.

### Secure Boot Not Enabled

TPM-sealed keys require **Secure Boot to be enabled** for PCR-7 binding.

**Check Secure Boot status:**
```bash
mokutil --sb-state
# Should show: "SecureBoot enabled"
```

**If Secure Boot is disabled:**
- Enable it in your BIOS/UEFI settings
- Existing TPM-sealed keys won't unseal (PCR-7 value is different)
- Use GUI recovery to regenerate keys with new PCR-7 state

### System Migration / Backup

**TPM keys are NOT portable** - they are bound to the specific TPM chip.

If you need to migrate to new hardware:
1. Run `tapauth-config` on the NEW system
2. Click "Recover Keys" to generate new keys
3. Re-pair all devices

**Cannot** restore TPM-sealed keys from backup. This is by design for security.

## Implementation Details

### TPM Operations

TapAuth shells out to `tpm2-tools`; these are the argv it actually runs
(`shared/src/tpm.rs`), not a paraphrase:

**Sealing (`save_keypair` → `seal_data_with_tpm`):**
```bash
# The private key is written to a temp file next to the target and passed with -i;
# the two output halves are the target path with its extension replaced.

# Standard policy (PCR 7+14):
tpm2_create -C 0x81000001 -l sha256:7,14 -g sha384 -G keyedseal \
    -i /var/lib/tapauth/client_key.tmp_in \
    -u /var/lib/tapauth/client_key.pub \
    -r /var/lib/tapauth/client_key.priv

# Paranoid policy (PCR 0+2+7+14): the same command with -l sha256:0,2,7,14
```

The `-l` value is `sha256:` followed by `TpmPcrPolicy::pcr_list()`, i.e. the
`tpm_pcr_policy` setting in config.toml; `-C 0x81000001` is the SRK handle and
`-g sha384 -G keyedseal` describe the sealed object.

**Unsealing (`load_keypair` → `unseal_data_with_tpm`):**
```bash
# Load the sealed object into a transient context, then unseal that context
tpm2_load -C 0x81000001 \
    -u /var/lib/tapauth/client_key.pub \
    -r /var/lib/tapauth/client_key.priv \
    -c /var/lib/tapauth/client_key.ctx

tpm2_unseal -c /var/lib/tapauth/client_key.ctx \
    -o /var/lib/tapauth/client_key.tmp_out
```

The unsealed bytes must be exactly 32 (`InvalidKeyFormat` otherwise) and are
then rebuilt into an Ed25519 signing key; the temp files are removed afterwards.

### Storage Root Key (SRK)

- **Handle**: 0x81000001 (TPM persistent handle)
- **Type**: RSA 2048 primary key
- **Purpose**: Parent key for sealing/unsealing operations
- **Creation**: **Not created by TapAuth.** Every command names the handle
  directly (`-C 0x81000001`) and nothing in the repository runs
  `tpm2_createprimary`, so the SRK must already exist at that handle (as
  provisioned by the distribution's `systemd-creds`/`tpm2` tooling). A system
  without it fails sealing with `tpm2_create failed: …`

The SRK lives in the TPM's endorsement hierarchy and is unique to each TPM chip.

### Error Handling

**Daemon Behavior:**
- If TPM unsealing fails during startup, daemon enters **degraded mode**
- Daemon stays alive but cannot perform authentication
- PAM requests return error with helpful message
- User must use GUI to recover

**PAM Module Behavior:**
- Receives error response from daemon
- Displays: "TapAuth: Error - Failed to load keypair: <details>. Please open tapauth-config GUI to regenerate keys."
- Returns `PAM_AUTH_ERR` (never `PAM_IGNORE`) so the attempt fails closed; on a
  `sufficient` line the stack still falls through to password

## Troubleshooting

### TPM Not Available

**Symptom**: 
```
TPM enabled in config but tpm2-tools not available
```

**Solution**:
```bash
# Install tpm2-tools
sudo apt install tpm2-tools  # Debian/Ubuntu
sudo dnf install tpm2-tools  # Fedora/RHEL
sudo pacman -S tpm2-tools    # Arch

# Verify TPM works
tpm2_getrandom 8 --hex
```

### Permission Denied

**Symptom**:
```
Failed to seal key with TPM: permission denied
```

**Solution**:
- The daemon runs as the unprivileged `tapauthd` user (`systemd/tapauthd.service`,
  `User=tapauthd`), not as root — so the TPM device node must be accessible to
  *that* user. Nothing in the repository adds `tapauthd` to the `tss` group, so
  a stock `crw-rw---- tss tss` `/dev/tpmrm0` is not enough on its own; grant it
  explicitly (group membership plus a `tss`-owned device node, or a matching
  udev rule).
- Check `/dev/tpmrm0` permissions: `ls -l /dev/tpmrm0`
- Should be readable/writable by the daemon's user

### Keys Won't Unseal After Update

**Symptom**:
```
Failed to load TPM-sealed key
```

**Possible Causes**:
- BIOS/firmware update changed TPM state
- TPM was cleared in BIOS
- Secure Boot state changed (PCR 7, which both sealing policies bind to)

**Solution**:
Run `tapauth-config` and click "Recover Keys"

### Daemon Runs But Won't Authenticate

**Check logs**:
```bash
sudo journalctl -u tapauthd -n 50
```

**Look for**:
- "Failed to load keypair"
- "Failed to unseal key from TPM"

**Fix**: Run `tapauth-config` to regenerate keys

## Performance Impact

TPM operations are slower than file I/O:

| Operation | File Mode | TPM Mode | Overhead |
|-----------|-----------|----------|----------|
| **Key Load (daemon start)** | <1ms | 50-100ms | +50-100ms |
| **Key Save (pairing/regen)** | <1ms | 100-200ms | +100-200ms |
| **Authentication** | No impact | No impact | None |

**Impact**: Daemon startup is slightly slower (~100ms), but authentication performance is unaffected since keys are loaded once at startup.

## Security Considerations

### What TPM Protects Against

✅ **Root-level key copying** (running system — there is no usable file to copy)  
✅ **Cold boot attacks** (key not in memory when system off)  
✅ **Disk forensics** (key cannot be unsealed without TPM)  
✅ **Key reuse on different hardware** (machine-bound)  

### What TPM Does NOT Protect Against

❌ **Memory dumps while daemon running** (key in RAM)  
❌ **Physical TPM attacks** (advanced hardware attacks)  
❌ **Evil maid attacks on the kernel/initramfs** (the sealed PCRs are 7+14 by
default, or 0+2+7+14 under `paranoid`; none of them measures the kernel image.
A modified kernel is caught only indirectly, by Secure Boot refusing to boot it)  

### Best Practices

1. **Enable TPM** if your system has TPM 2.0 hardware
2. **Use disk encryption** (LUKS) in combination with TPM
3. **Regular key rotation** (manually via GUI as needed)
4. **Monitor daemon logs** for unsealing failures
5. **Test recovery procedure** before relying on it

## Future Enhancements

### PCR-Based Sealing (implemented)

PCR sealing is not planned — it is what TPM mode does today. `tpm_pcr_policy =
"standard"` seals to PCR 7 (Secure Boot state) and PCR 14 (MOK keys);
`"paranoid"` adds PCR 0 (BIOS/UEFI firmware code) and PCR 2 (Option ROM code).
Unsealing then fails whenever a measured value changes, which is why the
recovery paths in "Recovery Scenarios" above exist. What is still not measured
is the kernel image and the initramfs: neither policy binds to them, so a
modified kernel is caught only indirectly, by Secure Boot refusing to boot it.

### Remote Attestation (Planned)

Android app could verify:
- Key comes from genuine TPM
- System is in trusted boot state
- Key has not been extracted/copied

## References

- [TCG TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [tpm2-tools Documentation](https://github.com/tpm2-software/tpm2-tools)
- [NIST SP 800-147B: BIOS Protection Guidelines for Servers](https://csrc.nist.gov/publications/detail/sp/800-147b/final)
