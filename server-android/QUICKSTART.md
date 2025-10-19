# TapAuth Android - Quick Start Guide

## Prerequisites

1. **Android Device**: Android 7.0 (API 24) or higher
2. **Biometric Hardware**: Fingerprint sensor or face unlock
3. **Build Tools**:
   - Android Studio (latest version recommended)
   - Rust toolchain with Android targets
   - cargo-ndk installed (`cargo install cargo-ndk`)
   - Android NDK installed

## Building the Application

### 1. Build Native Library

```bash
cd server-android
./build-native.sh
```

This will:
- Compile the Rust shared library for all Android architectures
- Copy libraries to `app/src/main/jniLibs/`
- Output: arm64-v8a, armeabi-v7a, x86_64, x86

### 2. Build Android App

Open the project in Android Studio:
```bash
cd server-android
# Open in Android Studio or use Gradle:
./gradlew assembleDebug
```

### 3. Install on Device

```bash
./gradlew installDebug
# Or use Android Studio's Run button
```

## First Run Setup

### 1. Grant Permissions
When you first launch the app, grant the following permissions:
- **Camera**: Required for QR code scanning
- **Biometric**: Required for authentication approval
- **Nearby Devices/Bluetooth**: Required for BLE authentication (Android 12+)

### 2. Verify Biometric Setup
- Go to **Settings** screen
- Verify that "Biometric authentication is available"
- If not available, set up fingerprint/face unlock in Android system settings

## Pairing with Desktop Client

### 1. Start Desktop Client
On your desktop computer, run the TapAuth client application to generate a pairing QR code.

### 2. Scan QR Code
1. Open TapAuth Android app
2. Tap **"Scan QR Code"** on home screen
3. Point camera at the QR code displayed on desktop
4. Wait for QR code detection (usually instant)

### 3. Verify SAS
1. App will show a 6-digit code (e.g., "123-456")
2. Desktop will show the same code
3. **Verify they match!** This prevents man-in-the-middle attacks
4. Tap **"Confirm"** if codes match
5. Tap **"Cancel"** if codes don't match (indicates attack or network issue)

### 4. Pairing Complete
- App will show success checkmark
- Paired device is now stored
- You can view it in **"View Paired Devices"**

## Using Authentication

### Automatic Operation
The authentication service runs automatically in the background after app launch.

### When Authentication Request Arrives:

1. **Notification**: You'll see "TapAuth - Authentication service is running"
2. **Biometric Prompt**: Automatically appears with:
   - Title: "Authentication Request"
   - Subtitle: "Approve login for username@hostname"
   - Description: "From device: [device name]"
3. **Approve**: Touch fingerprint sensor or use face unlock
4. **Deny**: Tap "Deny" button
5. **Result**: Encrypted grant sent to desktop (if approved)

### Transport Methods
The app supports two methods:
- **UDP**: Port 8442 (requires same network or VPN)
- **BLE**: Bluetooth Low Energy (requires proximity, ~10 meters)

Both work identically - the protocol is the same.

## Viewing Paired Devices

1. Open TapAuth app
2. Tap **"View Paired Devices"**
3. See list of all paired desktop clients
4. Each device shows:
   - Device name
   - Device ID
   - Public key (truncated)
5. **Swipe to delete** a device (removes pairing)

## Settings

Access via **Settings** button on home screen:

- **CSK Information**: Explains that CSK is client-controlled
- **About**: App version, protocol version, encryption details
- **Server Keypair**: Information about Ed25519 key generation

## Troubleshooting

### Pairing Issues

**Problem**: QR code not scanning
- **Solution**: Ensure good lighting, hold phone steady
- **Solution**: Check camera permission is granted
- **Solution**: Try moving phone closer/farther from screen

**Problem**: "Connection failed"
- **Solution**: Check desktop and phone are on same network
- **Solution**: Verify port 8442 is not blocked by firewall
- **Solution**: Try using IP address instead of hostname

**Problem**: "SAS verification failed"
- **Solution**: Codes don't match - possible MITM attack or network issue
- **Solution**: Cancel and try again
- **Solution**: Check for interfering proxy or VPN

### Authentication Issues

**Problem**: Biometric prompt not appearing
- **Solution**: Check MainActivity is running (open app)
- **Solution**: Verify biometric is set up in system settings
- **Solution**: Check logs: `adb logcat | grep TapAuth`

**Problem**: "Signature verification failed"
- **Solution**: Desktop client not properly paired - re-pair device
- **Solution**: CSK may have rotated on desktop - re-pair device
- **Solution**: Check clock synchronization (temporal IDs use time)

**Problem**: "No paired devices found"
- **Solution**: You need to pair with desktop first
- **Solution**: Check paired devices list to verify pairing exists

### Service Issues

**Problem**: Authentication service not running
- **Solution**: Open app to start service
- **Solution**: Check notification permission is granted
- **Solution**: Verify service in Android Settings → Apps → TapAuth

**Problem**: BLE not working
- **Solution**: Grant Bluetooth permissions (Android 12+ requires location)
- **Solution**: Enable Bluetooth in system settings
- **Solution**: Check device supports BLE (most modern Android devices do)

## Debugging

### View Logs
```bash
adb logcat | grep -E "TapAuth|AuthenticationService|BleGattService|MainActivity"
```

### Check Services
```bash
adb shell dumpsys activity services | grep tapauth
```

### Verify Native Library
```bash
adb shell "ls -la /data/app/*/lib/*/libshared.so"
```

### Test Cryptography
The app will log cryptographic operations:
- Keypair generation
- Signature verification
- Encryption/decryption
- Temporal ID generation

Look for log entries with `TAG = "TapAuthCrypto"`

## Security Notes

### Private Keys
- Server Ed25519 private key is encrypted with Android Keystore
- CSK is stored encrypted
- Keys never leave the device
- Biometric authentication required for all auth approvals

### Network Security
- All authentication requests must be signed
- Signatures verified before processing
- Temporal identifiers prevent tracking
- Encrypted communication with AES-256-GCM

### Best Practices
1. Always verify SAS during pairing
2. Only pair with your own desktop computers
3. Remove unused paired devices
4. Keep app updated
5. Don't disable biometric authentication
6. Be cautious on public WiFi

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                  MainActivity                    │
│  - QR Scanning                                  │
│  - Biometric Prompt                             │
│  - Device Management                            │
│  - Broadcast Receiver                           │
└────────────┬────────────────────────────────────┘
             │
             ├─────────────┐
             │             │
┌────────────▼─┐    ┌──────▼───────────────┐
│AuthenticationService│BleGattService        │
│  - UDP Port 8442│    │  - BLE GATT Server   │
│  - Parse Requests│   │  - Notifications     │
│  - Verify Sigs   │   │  - Same Auth Flow    │
└────────────┬─┘    └──────┬───────────────┘
             │             │
             └─────┬───────┘
                   │
         ┌─────────▼──────────┐
         │ AuthRequestManager │
         │  - Coordinate      │
         │  - Broadcast       │
         │  - Callbacks       │
         └─────────┬──────────┘
                   │
         ┌─────────▼──────────┐
         │   Native Crypto    │
         │  (Rust + JNI)      │
         │  - Ed25519         │
         │  - X25519          │
         │  - AES-256-GCM     │
         │  - HKDF            │
         └────────────────────┘
```

## Performance

Expected behavior:
- **QR Scanning**: Instant detection (<500ms)
- **Pairing**: 1-2 seconds total
- **Auth Request Processing**: 100-200ms (before biometric)
- **Biometric Prompt**: 1-3 seconds (user dependent)
- **Grant Creation**: 50-100ms
- **Battery Impact**: Minimal (foreground service with efficient listeners)

## Support

For issues or questions:
1. Check logs with `adb logcat`
2. Review [COMPLETION_SUMMARY.md](COMPLETION_SUMMARY.md)
3. Consult protocol documentation in `docs/design-documents/`
4. Check [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)

## Next Steps

After successful pairing and testing:
1. Test authentication flow from desktop
2. Verify both UDP and BLE transports work
3. Test with multiple paired devices
4. Verify signature rejection (tamper with request)
5. Test concurrent authentication requests
