# TapAuth VM Initialization Guide

## Understanding VM Initialization

When you first start the TapAuth VM, it goes through an initialization process that takes **5-10 minutes**. This is **normal** and only happens on the first boot (or after recreating the VM).

## What Happens During Initialization?

Cloud-init is installing and configuring:

1. **System packages** (~2 minutes)
   - Build tools, libraries, Bluetooth packages
   - X11 dependencies for GUI
   - Development tools

2. **Rust toolchain** (~3-4 minutes)
   - Downloads and installs Rust
   - Installs clippy and rustfmt
   - Configures cargo

3. **Bluetooth setup** (~1 minute)
   - Installs kernel modules
   - Configures Bluetooth service
   - Sets up USB passthrough

4. **Helper scripts** (< 1 minute)
   - Creates build-tapauth, test-tapauth, etc.
   - Sets up welcome message

5. **Shared folder** (< 1 minute)
   - Mounts /tapauth with read-write access
   - Adds to fstab for persistence

## How to Check Initialization Status

### Method 1: From Host (before connecting)

```bash
ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes \
    -i ~/.tapauth-vm/id_rsa -p 2222 tapauth@localhost \
    "cloud-init status"
```

**Output meanings:**
- `status: running` → Still initializing, wait a few more minutes
- `status: done` → Ready to use!
- `status: error` → Something went wrong, check logs

### Method 2: Inside VM

After connecting with `./dev-shell.sh`, run:

```bash
init-status
```

This will show:
- Current initialization state
- What components are installed
- Any issues that need attention

### Method 3: Check Welcome Message

The welcome message shown when you log in automatically detects initialization status:

- **If still initializing:** Shows progress message with monitoring tips
- **If complete:** Shows full list of available commands and tools

## What You Can Do While Waiting

### ✅ You CAN:
- Connect via SSH (`./dev-shell.sh`)
- Check status (`init-status`)
- View logs (`tail -f /var/log/cloud-init-output.log`)
- Use basic system commands

### ❌ You CANNOT (yet):
- Use helper scripts (build-tapauth, test-tapauth, etc.) - not created yet
- Use Rust/cargo - still installing
- Build TapAuth components - Rust not ready

## Monitoring Progress

### Watch cloud-init in real-time:

```bash
# Inside the VM
tail -f /var/log/cloud-init-output.log
```

You'll see output like:
```
Get:1 http://archive.ubuntu.com/ubuntu noble/main amd64 rustc ...
Unpacking rustc ...
Setting up rustc ...
```

### Check detailed status:

```bash
# Inside the VM
cloud-init status --long
```

Shows:
- Current stage
- Time elapsed
- Any errors

### Check specific logs:

```bash
# General cloud-init log
cat /var/log/cloud-init.log

# Command output (runcmd)
cat /var/log/cloud-init-output.log

# Errors only
grep -i error /var/log/cloud-init.log
```

## Common Scenarios

### Scenario 1: Just started VM, connected immediately

```bash
$ ./dev-shell.sh
⚠️  Note: VM initialization is still in progress
   Run 'init-status' inside the VM to check progress

Entering TapAuth VM...

╔═══════════════════════════════════════════════════════════════╗
║         TapAuth Development VM                                ║
╚═══════════════════════════════════════════════════════════════╝

⚠️  INITIALIZATION IN PROGRESS ⚠️

Cloud-init is still setting up the environment.
...
```

**Action:** Wait a few minutes, then log out and back in.

### Scenario 2: Waited 10 minutes, still not done

```bash
$ ssh ... "cloud-init status"
status: running
```

**Action:** Check logs for issues:

```bash
$ ssh ... "tail -50 /var/log/cloud-init-output.log"
```

Look for:
- Network issues (can't download packages)
- Package installation errors
- Rust installation hanging

### Scenario 3: Initialization complete

```bash
$ init-status

=== TapAuth VM Initialization Status ===

Cloud-init: done

✅ Initialization complete!

Checking components:
  ✅ Helper scripts installed
  ✅ Rust installed (1.90.0)
  ✅ Bluetooth service running
  ✅ Shared folder mounted at /tapauth

System is ready for development!
```

**Action:** Start developing! All tools are ready.

### Scenario 4: Initialization failed

```bash
$ init-status

=== TapAuth VM Initialization Status ===

Cloud-init: error

❌ Initialization failed or status unknown
...
```

**Action:** Check detailed logs and report the issue:

```bash
cloud-init status --long
cat /var/log/cloud-init.log | grep -i error
```

## After Initialization is Complete

Once `cloud-init status` shows `done`, you have access to:

### Helper Scripts
- `build-tapauth` - Build all components
- `test-tapauth` - Run unit tests  
- `test-pam-auth` - Test PAM authentication
- `run-gui` - Launch configuration GUI
- `bluetooth-status` - Check Bluetooth adapter
- `init-status` - Check initialization status (always available)

### Development Tools
- Rust toolchain (`rustc`, `cargo`, `clippy`, `rustfmt`)
- All system libraries and build tools
- Bluetooth utilities (`bluetoothctl`, `hciconfig`)
- Debugging tools (`gdb`, `valgrind`, `strace`)

### Shared Folder
- `/tapauth` mounted with read-write access
- All source code accessible
- Build artifacts can be written

## Subsequent Boots

After the first boot, subsequent VM starts are **much faster** (30-60 seconds):

1. VM boots
2. Services start
3. Shared folder auto-mounts
4. Bluetooth modules auto-load
5. Ready to use!

No re-initialization is needed unless you:
- Delete the VM disk (`./vm-stop.sh` → answer 'y')
- Recreate the VM (`./vm-setup.sh`)

## Quick Reference

| Command | Purpose |
|---------|---------|
| `./dev-start.sh` | Start VM (shows status instructions) |
| `./dev-shell.sh` | Connect to VM (warns if still initializing) |
| `init-status` | Check setup status (inside VM) |
| `cloud-init status` | Raw cloud-init status |
| `tail -f /var/log/cloud-init-output.log` | Watch progress |

## Tips

1. **First boot?** Grab a coffee ☕ - initialization takes 5-10 minutes
2. **Not sure if done?** Run `init-status` inside the VM
3. **Want to see progress?** Watch `/var/log/cloud-init-output.log`
4. **Subsequent boots** are fast (< 1 minute)
5. **Welcome message** adapts based on initialization state

## Troubleshooting

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| Scripts not found | Still initializing | Wait, check `init-status` |
| `rustc: command not found` | Rust still installing | Wait, check logs |
| Can't write to /tapauth | Mount failed | Check `mount \| grep tapauth` |
| Stuck at "running" for 20+ min | Network/package issue | Check logs, may need to recreate VM |

---

**Remember:** The initialization delay only happens once. After that, your VM is ready instantly!
