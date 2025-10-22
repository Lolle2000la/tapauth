# Bluetooth Setup for TapAuth Development Container

## Overview

The TapAuth development container runs its own D-Bus and Bluez (Bluetooth) services to enable BLE testing without interfering with your host system's Bluetooth.

## How It Works

### Container Services

The container automatically starts:
1. **D-Bus system daemon** - Required for Bluetooth IPC
2. **bluetoothd** - The Bluetooth daemon that manages BLE adapters
3. **Bluetooth adapter initialization** - Powers on available adapters

### Host Bluetooth Management

To avoid conflicts between the host and container Bluetooth services:

- **On container start** (`./dev-start.sh`):
  - The host's Bluetooth service is stopped
  - This allows the container exclusive access to the Bluetooth hardware
  
- **On container stop** (`./dev-stop.sh`):
  - The host's Bluetooth service is automatically restored
  - Your normal Bluetooth functionality returns

## Requirements

### Privileged Mode

The container runs in privileged mode to access Bluetooth hardware. This is configured in `docker-compose.dev.yml`:

```yaml
privileged: true
```

### Network Mode

The container uses host networking (`network_mode: "host"`) to:
- Access Bluetooth hardware directly
- Enable UDP broadcast/multicast for the authentication protocol
- Simplify network testing

### Device Access

The container has access to:
- `/dev/bus/usb` - For USB Bluetooth adapters
- `/sys/class/bluetooth` - For Bluetooth sysfs information (read-only)

## Checking Bluetooth Status

Inside the container, use:

```bash
bluetooth-status
```

This will show:
- ✅ D-Bus daemon status
- ✅ Bluetooth daemon status  
- 📡 Available Bluetooth adapters
- 📱 Paired devices
- 🔌 D-Bus service connectivity

## Troubleshooting

### "No Bluetooth adapter found"

**Cause**: The host Bluetooth service might still be running, or your system has no Bluetooth hardware.

**Solutions**:
1. Stop the container: `./dev-stop.sh`
2. Manually stop host Bluetooth: `sudo systemctl stop bluetooth`
3. Restart the container: `./dev-start.sh`
4. Check status inside container: `bluetooth-status`

### "Cannot connect to D-Bus"

**Cause**: D-Bus daemon didn't start properly in the container.

**Solution**:
```bash
# Inside container
mkdir -p /var/run/dbus
rm -f /var/run/dbus/pid
dbus-daemon --system --fork
```

### "Bluetooth daemon not running"

**Cause**: bluetoothd failed to start.

**Solution**:
```bash
# Inside container
bluetoothd &
sleep 2
hciconfig hci0 up
```

### Permission Issues

**Cause**: Container needs privileged access for Bluetooth hardware.

**Solution**: Make sure `docker-compose.dev.yml` has `privileged: true`.

## Manual Testing

### Test BLE Scanning

```bash
# Inside container
hcitool lescan
```

### Test BLE Advertising

```bash
# Inside container
hciconfig hci0 leadv 3  # Enable advertising
hciconfig hci0 noleadv  # Disable advertising
```

### Monitor Bluetooth Traffic

```bash
# Inside container (if btmon is available)
btmon

# Or use D-Bus monitoring
dbus-monitor --system "type='signal',interface='org.bluez.Device1'"
```

## BLE Service Testing

The TapAuth BLE implementation:

### Server (Android)
- Acts as **Scanner/Central**
- Scans for client advertisements
- Connects to client's GATT server
- Reads authentication requests
- Writes authentication responses

### Client (Linux)
- Acts as **Advertiser/Peripheral**  
- Advertises with temporal identifier
- Runs GATT server
- Exposes authentication characteristics
- Waits for server connections

### Test Flow

1. **Build everything**:
   ```bash
   build-tapauth
   ```

2. **Check Bluetooth**:
   ```bash
   bluetooth-status
   ```

3. **Start BLE advertising** (manual test):
   ```bash
   # This will be automated by the PAM module
   # For now, you can test the advertiser code
   cd /tapauth/client-pam
   cargo test --features ble -- --nocapture
   ```

4. **Monitor with Android app**:
   - The Android server should scan and detect the advertisement
   - Check Android logs for temporal ID matches

## Architecture Notes

### Why Container-based Bluetooth?

1. **Isolation**: Keep development separate from host system
2. **Reproducibility**: Same environment across different host systems
3. **Testing**: Easier to test BLE protocol changes
4. **Debugging**: Container can run debug tools without affecting host

### Trade-offs

**Advantages**:
- ✅ No interference with host Bluetooth usage
- ✅ Easy cleanup (just stop container)
- ✅ Consistent environment
- ✅ Can run debugging tools freely

**Disadvantages**:
- ❌ Requires stopping host Bluetooth temporarily
- ❌ Needs privileged container mode
- ❌ Slightly more complex setup

## Restoring Normal Bluetooth

If something goes wrong and your host Bluetooth doesn't automatically restart:

```bash
# On host (outside container)
sudo systemctl start bluetooth
sudo systemctl status bluetooth
```

## Next Steps

After confirming Bluetooth works in the container:

1. Test the client BLE advertiser implementation
2. Connect Android device to same network
3. Run Android server app in scanner mode
4. Test authentication flow over BLE
5. Compare with UDP authentication performance

## References

- Container startup: `/usr/local/bin/container-start` (in Dockerfile)
- Bluetooth config: `/etc/bluetooth/main.conf` (in container)
- Status checker: `/usr/local/bin/bluetooth-status` (in container)
