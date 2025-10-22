# 🚀 TapAuth Development Quick Start

Get up and running with TapAuth development in 5 minutes!

---

## Prerequisites Check

```bash
# Check if you have Docker
docker --version
# ✅ Should show: Docker version 20.10+

# Check if you have Docker Compose
docker-compose --version
# ✅ Should show: docker-compose version 1.29+

# Check if you have X11
echo $DISPLAY
# ✅ Should show: :0 or :1
```

If any of these fail, see [`DEVELOPMENT.md`](DEVELOPMENT.md) for installation instructions.

---

## 1️⃣ Start Development Environment (First Time)

```bash
cd /home/luca/source/repos/tapauth

# Start the environment (builds Docker image + compiles everything)
# ⏱️ First run: ~5-10 minutes
./dev-start.sh
```

**What this does:**
- ✅ Builds Docker container with all dependencies
- ✅ Compiles TapAuth (shared, PAM, GUI)
- ✅ Installs PAM module and GUI
- ✅ Starts container in background

---

## 2️⃣ Enter the Development Environment

```bash
./dev-shell.sh
```

You're now inside the container! 🎉

---

## 3️⃣ Pair Your Android Device

Inside the container:

```bash
run-gui
```

**Steps:**
1. GUI window opens (thanks to X11 forwarding)
2. Click "Pair New Device"
3. QR code appears
4. Open TapAuth on your Android phone (debug build)
5. Scan the QR code
6. Verify SAS matches on both devices
7. Confirm pairing
8. Done! 🎊

---

## 4️⃣ Test Authentication

Still inside the container:

```bash
test-pam-auth root
```

**What happens:**
1. PAM module starts
2. BLE advertisement begins
3. UDP broadcasts sent
4. Waits for your Android device...
5. Approve authentication on your phone
6. Authentication succeeds! ✅

---

## 5️⃣ Stop When Done

```bash
# Exit the container
exit

# Stop the environment (on host)
./dev-stop.sh
```

---

## 🔄 Daily Development Workflow

### Start Environment
```bash
./dev-start.sh  # will rebuild if needed, press 'y' if prompted
./dev-shell.sh  # Enter container
```

### Make Changes
- Edit code on your host (use your favorite IDE)
- Files are automatically synced to container

### Build & Test
```bash
# Inside container
build-tapauth       # Rebuild everything
test-pam-auth root  # Test authentication
```

### Stop Environment
```bash
exit             # Exit container
./dev-stop.sh    # Stop environment
```

---

## 📱 Android Development

### Build Debug Version

```bash
# On host
cd server-android
./build-native.sh  # Build Rust native libraries

# Open in Android Studio
# Select "debug" build variant
# Click Run
```

**Result:** Debug app installs alongside any release builds!
- Debug: `dev.rourunisen.tapauth.debug` (TapAuth Debug)
- Release: `dev.rourunisen.tapauth` (TapAuth)

---

## 🐛 Quick Troubleshooting

### GUI doesn't appear?
```bash
# On host
xhost +local:docker
```

### Bluetooth not working?
```bash
# Inside container
bluetooth-status

# On host (if needed)
sudo systemctl restart bluetooth
```

### Authentication times out?
```bash
# Check Android app is running
# Check both devices on same network
# Enable debug logging:
export RUST_LOG=debug
test-pam-auth root
```

---

## 📚 Learn More

- **Full Guide**: `DEVELOPMENT.md` - Complete documentation
- **Architecture**: `docs/` - Design documents

---

## 🎯 Common Tasks

### View Logs
```bash
# PAM authentication logs
journalctl -f | grep pam

# Network traffic
tcpdump -i any port 36692

# Bluetooth
btmon
```

### Run Tests
```bash
./dev-test.sh  # On host
# OR
test-tapauth   # Inside container
```

### Rebuild After Changes
```bash
./dev-rebuild.sh  # On host
# OR
build-tapauth     # Inside container
```

### Check Status
```bash
# Inside container
bluetooth-status              # Bluetooth
netstat -uln | grep 36692     # Network
ls -la /etc/tapauth/          # Config files
```

---

## ✅ You're Ready!

You now have:
- ✅ Complete development environment
- ✅ Docker container with PAM + GUI
- ✅ Android debug build capability
- ✅ Testing tools (pamtester)
- ✅ Network and Bluetooth access

**Happy hacking!** 🚀
