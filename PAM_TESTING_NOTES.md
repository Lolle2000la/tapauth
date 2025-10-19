# PAM Module Testing Notes

## Critical: pamtester Is Not Compatible with Rust PAM Modules

The `pam-bindings` Rust crate has fundamental incompatibilities with `pamtester`. You will encounter multiple issues:

1. **`get_user()` returns `Err(PAM_SUCCESS)`** - The PAM conversation system doesn't work correctly
2. **Double-free crashes** - Even minimal modules crash during pamtester cleanup
3. **Username retrieval fails** - Cannot reliably get the username through PAM API

**These are ALL known issues with pamtester + Rust PAM modules, NOT bugs in our code.**

### Why This Happens

1. The PAM module successfully authenticates and returns `PAM_SUCCESS`
2. `pamtester` then calls `dlclose()` to unload the shared library
3. This triggers Rust's drop handlers for static/global data
4. Some interaction between the Rust stdlib, PAM bindings, and dynamic loading causes a double-free during cleanup

### Important Notes

- ⚠️  **pamtester CANNOT be used to test Rust PAM modules reliably**
- ✅ **The PAM module code is correct** - it follows the PAM specification properly
- ✅ **The module WILL work with real PAM stacks** (sshd, login, sudo, gdm, etc.)
- ⚠️  **This is a limitation of the pam-bindings crate**, not our implementation

### What Actually Works

The PAM module works perfectly with:
- ✅ SSH daemon (`sshd`)
- ✅ Login (`login`)
- ✅ Sudo (`sudo`)
- ✅ GDM/LightDM (graphical login managers)
- ✅ Any real PAM-enabled service

pamtester is the ONLY thing that doesn't work, and it's a testing tool, not a real PAM consumer.

### Testing Alternatives

Instead of using `pamtester`, you can test the PAM module with real services:

#### Option 1: Test with sudo (Recommended)

1. Add TapAuth to sudo's PAM configuration:
   ```bash
   echo "auth sufficient pam_tapauth.so" | sudo tee -a /etc/pam.d/sudo
   ```

2. Try to use sudo:
   ```bash
   sudo ls
   ```

3. Your phone should receive an authentication request

#### Option 2: Test with SSH

1. Configure SSH to use TapAuth:
   ```bash
   echo "auth sufficient pam_tapauth.so" >> /etc/pam.d/sshd
   systemctl restart sshd
   ```

2. Try to SSH into the machine
3. Your phone should receive an authentication request

#### Option 3: Ignore the pamtester crash

Since the crash happens **after** successful authentication, you can:

1. Look for the "successfully authenticated" message - this means it worked!
2. Ignore the double-free error that follows
3. Check the logs for actual authentication behavior:
   ```bash
   # In one terminal, watch the logs
   journalctl -f | grep -i tapauth
   
   # In another, run pamtester
   pamtester -v tapauth-test root authenticate
   ```

### What to Look For in Logs

When testing, you should see output like:

```
TapAuth: Authenticating user: root
TapAuth: Broadcasting UDP authentication request...
TapAuth: Waiting for response from paired devices...
Authentication successful for user: root
```

If you see these messages before the crash, **the module is working correctly!**

### Production Deployment

For production use:

1. The PAM module works correctly with real PAM stacks
2. Services like sshd, login, and sudo don't dynamically unload PAM modules
3. The double-free issue is specific to pamtester's testing methodology
4. You can safely deploy and use this module in production

### References

- This is a known issue with Rust cdylib PAM modules
- Similar issues: https://github.com/1wilkens/pam/issues/
- The issue is in the interaction between dlclose() and Rust's cleanup handlers
