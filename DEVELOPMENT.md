# TapAuth Development Environment

Complete Docker-based development environment for testing and developing TapAuth authentication system.

---

## 🎯 Features

- ✅ **Complete Linux client environment** (PAM module + GUI)
- ✅ **X11 forwarding** for GUI testing
- ✅ **Bluetooth support** via host passthrough
- ✅ **Full network access** (host networking)
- ✅ **PAM testing** with `pamtester`
- ✅ **Live code editing** (source mounted as volume)
- ✅ **Build caching** (fast rebuilds)
- ✅ **Side-by-side Android** debug builds

---

## 📋 Prerequisites

### Host System Requirements

1. **Docker** (20.10+ recommended)
   ```bash
   # Ubuntu/Debian
   sudo apt-get install docker.io docker-compose
   
   # Or install Docker Desktop
   # https://docs.docker.com/get-docker/
   ```

2. **X11 Server** (for GUI)
   ```bash
   # Ubuntu/Debian
   sudo apt-get install x11-xserver-utils
   ```

3. **Bluetooth** (optional, for BLE GATT testing)
   - Bluetooth adapter on host
   - BlueZ installed on host

4. **Android Studio** (for Android server testing)
   - Download from: https://developer.android.com/studio

---

## 🚀 Quick Start

### 1. Start Development Environment

```bash
# From the tapauth repository root
./dev-start.sh
```

This will:
- Build the Docker image (first run takes ~5-10 minutes)
- Start the container in the background
- Build all TapAuth components
- Display welcome message

### 2. Enter the Container

```bash
./dev-shell.sh
```

You're now inside the development environment!

### 3. Pair a Device

Inside the container:
```bash
run-gui
```

This opens the TapAuth GUI where you can:
- Pair your Android device (QR code)
- Manage paired devices
- Configure settings

### 4. Test Authentication

Inside the container:
```bash
test-pam-auth root
```

This will:
- Start BLE advertisement
- Broadcast UDP discovery packets
- Wait for authentication from your Android device
- Show authentication result

---

## 📱 Android Development Setup

### Configure Android Studio for Side-by-Side Installation

The Android app is configured to allow **debug and release builds** to be installed simultaneously on the same device.

**Debug Build**:
- Package ID: `dev.rourunisen.tapauth.debug`
- App Name: "TapAuth (Debug)"
- Different icon (optional - can be configured)

**Release Build**:
- Package ID: `dev.rourunisen.tapauth`
- App Name: "TapAuth"

### Building and Installing

1. **Open in Android Studio**:
   ```bash
   cd server-android
   # Open this directory in Android Studio
   ```

2. **Select Build Variant**:
   - Click "Build Variants" (bottom left in Android Studio)
   - Select "debug" for development
   - Select "release" for production testing

3. **Run on Device**:
   - Connect your Android device via USB
   - Enable Developer Options and USB Debugging
   - Click "Run" (green play button) or Shift+F10
   - Both debug and release can coexist on your phone!

### Native Library Build

The Android app uses Rust native libraries. To rebuild them:

```bash
cd server-android
./build-native.sh
```

This compiles the shared Rust library for all Android architectures.

---

## 🔧 Development Workflow

### Typical Development Session

```bash
# 1. Start environment
./dev-start.sh

# 2. Enter container
./dev-shell.sh

# 3. Make code changes on host (your favorite editor)
# Files are mounted as volumes, changes are immediate

# 4. Rebuild inside container
build-tapauth

# 5. Test
test-pam-auth root

# 6. Check logs
journalctl -f | grep pam

# 7. Exit container
exit

# 8. Stop environment when done
./dev-stop.sh
```

### Available Commands Inside Container

| Command | Description |
|---------|-------------|
| `build-tapauth` | Build all TapAuth components |
| `test-tapauth` | Run unit tests |
| `test-pam-auth [user]` | Test PAM authentication |
| `run-gui` | Launch configuration GUI |
| `bluetooth-status` | Show Bluetooth adapter status |
| `tapauth-welcome` | Show welcome message again |

### Helper Scripts on Host

| Script | Description |
|--------|-------------|
| `./dev-start.sh` | Start the development environment |
| `./dev-shell.sh` | Open a shell in the container |
| `./dev-stop.sh` | Stop the development environment |
| `./dev-rebuild.sh` | Rebuild TapAuth components |
| `./dev-test.sh` | Run all tests |

---

## 🌐 Network Configuration

### UDP Port

- **Default**: 36692
- **Protocol**: UDP broadcast/multicast
- **IPv6 Multicast**: `ff02::1` (all nodes on local network segment)

The container uses **host networking**, so it can communicate directly with your Android device on the same network.

### Testing Network Connectivity

Inside the container:
```bash
# Check if UDP port is accessible
netstat -uln | grep 36692

# Capture UDP traffic
tcpdump -i any port 36692

# Ping Android device (if you know its IP)
ping <android-device-ip>
```

---

## 📡 Bluetooth Configuration

### Bluetooth Passthrough

The container has access to the host's Bluetooth adapter via:
- D-Bus socket: `/var/run/dbus`
- Bluetooth sysfs: `/sys/class/bluetooth`
- USB devices: `/dev/bus/usb`

### Checking Bluetooth Status

Inside the container:
```bash
bluetooth-status
```

This shows:
- Bluetooth service status
- Available adapters
- Paired devices
- D-Bus connection status

### Troubleshooting Bluetooth

**Issue**: Bluetooth adapter not found

```bash
# On host: Check if Bluetooth is working
hciconfig -a
systemctl status bluetooth

# Restart Bluetooth on host
sudo systemctl restart bluetooth

# In container: Check again
bluetooth-status
```

**Issue**: Cannot start advertising

```bash
# Check BlueZ version (needs 5.50+)
bluetoothctl --version

# Check D-Bus connection
dbus-send --system --print-reply --dest=org.bluez / org.freedesktop.DBus.Introspectable.Introspect
```

---

## 🖥️ X11 GUI Testing

### Prerequisites

1. X11 server running on host
2. X11 forwarding enabled

The `dev-start.sh` script automatically enables X11 forwarding with:
```bash
xhost +local:docker
```

### Testing the GUI

Inside the container:
```bash
run-gui
```

The GUI should appear on your host display!

### Troubleshooting X11

**Issue**: GUI doesn't appear

```bash
# On host: Check DISPLAY variable
echo $DISPLAY  # Usually :0 or :1

# On host: Re-enable X11 forwarding
xhost +local:docker

# In container: Check X11 connection
echo $DISPLAY
xeyes  # Test X11 (should show eyes following cursor)
```

**Issue**: Permission denied

```bash
# On host: Grant access to X11 socket
chmod 777 /tmp/.X11-unix

# Or use more secure method
xhost +SI:localuser:$(whoami)
```

---

## 🧪 Testing Scenarios

### Scenario 1: End-to-End Authentication

**Goal**: Test complete authentication flow

**Steps**:
1. Start environment: `./dev-start.sh`
2. Enter container: `./dev-shell.sh`
3. Pair device: `run-gui` → Click "Pair New Device"
4. Scan QR code with Android app (debug build)
5. Verify SAS on both devices
6. Complete pairing
7. Test authentication: `test-pam-auth root`
8. Approve authentication on Android device
9. Verify authentication succeeds

**Expected Result**: PAM authentication succeeds ✅

### Scenario 2: UDP Transport Testing

**Goal**: Test UDP broadcast/multicast discovery

**Steps**:
1. Start environment
2. In container: `tcpdump -i any port 36692` (terminal 1)
3. In container: `test-pam-auth root` (terminal 2)
4. Observe UDP packets in tcpdump
5. Approve on Android device
6. Verify grant received

**Expected Result**: 
- UDP packets visible in tcpdump
- Authentication succeeds

### Scenario 3: BLE GATT Transport Testing

**Goal**: Test BLE GATT characteristics

**Steps**:
1. Ensure Bluetooth working: `bluetooth-status`
2. Start authentication: `test-pam-auth root`
3. Observe BLE advertisement: `btmon` (separate terminal)
4. Android should scan and connect
5. Authentication messages over GATT
6. Approve on Android device

**Expected Result**:
- BLE advertisement visible
- GATT connection established
- Authentication succeeds

### Scenario 4: Multiple Authentication Attempts

**Goal**: Test replay attack mitigation

**Steps**:
1. Authenticate once: `test-pam-auth root`
2. Immediately authenticate again: `test-pam-auth root`
3. Verify both succeed (different challenges)
4. Try replaying captured packet (should fail)

**Expected Result**:
- Multiple authentications work
- Replayed packets rejected

### Scenario 5: Configuration Changes

**Goal**: Test configuration persistence

**Steps**:
1. Open GUI: `run-gui`
2. Go to Settings
3. Change hostname and UDP port
4. Save configuration
5. Exit GUI
6. Check config: `cat /etc/tapauth/client_config.json`
7. Restart PAM test: `test-pam-auth root`
8. Verify new settings used

**Expected Result**:
- Configuration saved
- New settings active

---

## 📂 File Locations

### Inside Container

| Path | Description |
|------|-------------|
| `/tapauth/` | Source code (mounted from host) |
| `/etc/tapauth/` | Configuration directory |
| `/lib/security/pam_tapauth.so` | PAM module library |
| `/usr/local/bin/tapauth-config` | GUI binary |
| `/root/.cargo/` | Rust build cache |

### Configuration Files

- **Client Config**: `/etc/tapauth/client_config.json`
- **Client Keys**: `/etc/tapauth/client_keypair.json`
- **Client CSK**: `/etc/tapauth/client_symmetric_key.bin`
- **Paired Servers**: `/etc/tapauth/paired_servers.json`

### Volumes

The following Docker volumes persist data:
- `tapauth-cargo-cache`: Rust build cache (~500MB)
- `tapauth-target-cache`: Compiled binaries (~2GB)
- `tapauth-config`: Configuration files

To reset everything:
```bash
./dev-stop.sh
# Answer "y" when asked to remove volumes
```

---

## 🐛 Debugging

### Enable Debug Logging

Inside the container:
```bash
# Set RUST_LOG environment variable
export RUST_LOG=debug

# Run with verbose output
test-pam-auth root
```

### View System Logs

```bash
# PAM logs
journalctl -f | grep pam

# Bluetooth logs
journalctl -f -u bluetooth

# All system logs
journalctl -f
```

### Network Debugging

```bash
# Capture all network traffic
tcpdump -i any -w /tmp/capture.pcap

# View captured traffic (on host)
wireshark /tmp/capture.pcap

# Check open ports
netstat -tuln

# Check routing
ip route show
```

### Bluetooth Debugging

```bash
# Monitor Bluetooth HCI
btmon

# Scan for devices
bluetoothctl scan on

# Show adapter info
hciconfig -a

# Check D-Bus messages
dbus-monitor --system
```

### Attach Debugger (GDB)

```bash
# Install gdb (already in container)
# Build with debug symbols
cd /tapauth/client-pam
cargo build --features ble

# Run under gdb
gdb --args pamtester tapauth-test root authenticate
```

---

## 🔍 Common Issues

### Issue: Container won't start

**Symptoms**: `docker-compose up` fails

**Solutions**:
```bash
# Check Docker is running
sudo systemctl status docker

# Check for port conflicts
docker ps -a

# Remove old containers
docker rm tapauth-dev

# Rebuild from scratch
docker-compose -f docker-compose.dev.yml build --no-cache
```

### Issue: Build fails inside container

**Symptoms**: `build-tapauth` errors

**Solutions**:
```bash
# Clear Rust build cache
cd /tapauth && cargo clean

# Update Rust
rustup update

# Check disk space
df -h

# Rebuild
build-tapauth
```

### Issue: GUI doesn't appear

**Symptoms**: `run-gui` runs but no window

**Solutions**:
```bash
# On host: Enable X11 forwarding
xhost +local:docker

# Check DISPLAY variable
echo $DISPLAY

# Test X11 connection
xeyes

# Check X11 socket permissions
ls -la /tmp/.X11-unix
```

### Issue: Bluetooth not working

**Symptoms**: `bluetooth-status` shows no adapters

**Solutions**:
```bash
# On host: Restart Bluetooth
sudo systemctl restart bluetooth

# Check adapter is powered
hciconfig hci0 up

# Grant D-Bus permissions
# (May need to add user to bluetooth group on host)
```

### Issue: Authentication times out

**Symptoms**: `test-pam-auth` times out after 180 seconds

**Solutions**:
```bash
# Check Android app is running
# Check network connectivity
ping <android-device-ip>

# Check UDP port is open
netstat -uln | grep 36692

# Check Bluetooth is advertising
btmon

# Enable debug logging
export RUST_LOG=debug
test-pam-auth root
```

---

## 🏗️ Advanced Usage

### Custom Docker Build

```bash
# Build with custom tags
docker build -f Dockerfile.dev -t tapauth-dev:custom .

# Run with custom options
docker run -it --rm \
  --privileged \
  --network host \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -v $(pwd):/tapauth \
  tapauth-dev:custom
```

### Mount Additional Volumes

Edit `docker-compose.dev.yml`:
```yaml
volumes:
  # Add custom mount
  - /path/on/host:/path/in/container:rw
```

### Use Different Rust Version

Edit `Dockerfile.dev`:
```dockerfile
# After rustup installation
RUN rustup install nightly
RUN rustup default nightly
```

### Network Isolation Testing

```bash
# Create custom network
docker network create tapauth-net

# Run container on custom network
docker run -it --rm \
  --network tapauth-net \
  tapauth-dev
```

---

## 📊 Performance Tips

### Speed Up Builds

1. **Use build cache volumes** (already configured)
2. **Build in release mode** (already default)
3. **Use `cargo check`** for faster iteration:
   ```bash
   cd /tapauth/client-pam
   cargo check --features ble
   ```

### Reduce Container Size

```bash
# Clean build artifacts
docker exec tapauth-dev cargo clean

# Prune Docker
docker system prune -a
```

### Monitor Resource Usage

```bash
# Container stats
docker stats tapauth-dev

# Inside container
htop
```

---

## 🤝 Contributing

When developing new features:

1. **Edit code on host** (use your favorite IDE)
2. **Build in container** (`build-tapauth`)
3. **Test in container** (`test-pam-auth`)
4. **Commit from host** (git commands)

The container is **ephemeral** - your code changes are on the host!

---

## 📚 Additional Resources

- **Project Documentation**: `/tapauth/docs/`
- **Compliance Reports**: `/tapauth/CLIENT_COMPLIANCE_REPORT.md`
- **Feature Status**: `/tapauth/FEATURE_COMPLETE_STATUS.md`
- **Android Build**: `/tapauth/server-android/BUILD_NATIVE.md`

---

## 📝 Quick Reference

### Frequently Used Commands

```bash
# Host - Start environment
./dev-start.sh && ./dev-shell.sh

# Container - Build and test
build-tapauth && test-pam-auth root

# Container - Check status
bluetooth-status && netstat -uln | grep 36692

# Container - View logs
journalctl -f | grep tapauth

# Host - Stop environment
./dev-stop.sh
```

### Port Reference

| Port | Protocol | Purpose |
|------|----------|---------|
| 36692 | UDP | Authentication broadcast |
| Dynamic | TCP | Pairing handshake |

### Service UUIDs

| Service | UUID |
|---------|------|
| BLE Service | `b4ad84c0-2adb-4876-8315-b39d983b2bde` |
| Client Command | `caf54438-9d78-4697-8886-0a4cfa87ba8d` |
| Server Response | `ca6238be-c194-49b7-855b-58f41d3da626` |

---

## 🎉 Happy Development!

You now have a complete, isolated development environment for TapAuth! 

For questions or issues, check the documentation or open an issue on GitHub.

**Status**: ✅ Development environment ready!
