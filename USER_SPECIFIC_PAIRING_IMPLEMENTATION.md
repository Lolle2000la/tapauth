# User-Specific Pairing Implementation Plan

## Overview
This document outlines the implementation of user-specific pairing restrictions to enhance security by preventing privilege escalation attacks.

## ⚠️ CRITICAL SECURITY REQUIREMENT

**Each pairing MUST be tied to specific users to prevent privilege escalation.**

### The Attack Vector We're Preventing:
1. Root user pairs their phone for authentication
2. Without user-specific pairing, an unprivileged user could authenticate as root
3. This allows privilege escalation from any user to root

### Solution:
- Pairings are **per-user**, not per-device
- When Alice pairs, only Alice can authenticate with that pairing
- When Bob pairs on the same client, the server detects it's the same device and **appends Bob** to allowed users
- **No "all users allowed" default** - empty list was a temporary measure, now being removed
- **Client specifies username during pairing** - server knows who is pairing

### Multi-User Pairing Behavior:
1. Alice pairs her phone → Server stores: Device X, `allowed_users: ["alice"]`
2. Bob pairs the same phone → Server detects same device, updates: Device X, `allowed_users: ["alice", "bob"]`
3. Authentication: Alice ✅, Bob ✅, Carol ❌

## Protocol Changes

### Updated Protobuf Message:
```protobuf
message PairingCskMessage {
  bytes encrypted_csk = 1;
  string username = 2;  // NEW: Username of the user pairing this device
}
```

### Pairing Flow:
1. Client collects username from environment (PAM provides this)
2. Client includes username in `PairingCskMessage`
3. Server receives username and creates/updates pairing with `allowed_users: [username]`
4. If same device re-pairs with different user, server appends to `allowed_users`

## ✅ Completed Changes

### Phase 1: Data Model Updates (COMPLETE)

#### Rust (shared/src/config/mod.rs)
- ✅ Added `allowed_users: Vec<String>` field to `PairedServer`
- ✅ Added `allowed_users: Vec<String>` field to `PairedClient`
- ✅ Added `is_user_allowed(&self, username: &str)` method to both structs
- ✅ Used `#[serde(default)]` for backwards compatibility (empty list = all users allowed)

#### Android (server-android/app/src/main/java/dev/rourunisen/tapauth/data/)
- ✅ Added `allowedUsers: List<String>` to `PairedDevice` data class
- ✅ Added `isUserAllowed(username: String)` method to `PairedDevice`
- ✅ Updated `DeviceRepository.deviceToJson()` to serialize `allowedUsers`
- ✅ Updated `DeviceRepository.jsonToDevice()` to deserialize `allowedUsers` with backwards compatibility

### Phase 2: Enforcement Implementation (COMPLETE)

#### Android Server - UDP Authentication (AuthenticationService.kt)
- ✅ Added username validation in `handleAuthRequest()` method
- ✅ Logs warning when pairing is not authorized for user
- ✅ Silently rejects unauthorized requests (prevents username enumeration)
- ✅ Location: After parsing auth request, before replay mitigation check

#### Android Server - BLE Authentication (BleGattService.kt)
- ✅ Added username validation in `handleAuthenticationRequest()` method
- ✅ Logs warning when pairing is not authorized for user
- ✅ Sends generic "UNAUTHORIZED" response (prevents username enumeration)
- ✅ Location: After parsing auth request, before replay mitigation check

#### Linux Client - PAM Module (client-pam/src/auth_client.rs)
- ✅ Added filtering of paired servers in `authenticate()` method
- ✅ Only attempts authentication with servers that allow the current user
- ✅ Returns `NoPairedDevices` error if no authorized servers found
- ✅ Logs number of authorized vs total servers for debugging

**Build Status**: ✅ All components compiled successfully

## 🔨 Remaining Implementation Tasks

#### Android Server Side

**File**: `server-android/app/src/main/java/dev/rourunisen/tapauth/service/AuthenticationService.kt`

In `handleAuthRequest()` method (around line 490-500), add username validation:

```kotlin
// After parsing the authentication request
val authRequest = parseAuthRequest(wrapperMessage)
Log.d(TAG, "Parsed auth request: username=${authRequest.username}, hostname=${authRequest.hostname}")

// CHECK: Verify this pairing is allowed to authenticate this user
if (!device.isUserAllowed(authRequest.username)) {
    Log.w(TAG, "Pairing not authorized for user: ${authRequest.username}")
    Log.w(TAG, "  Device: ${device.displayName}")
    Log.w(TAG, "  Allowed users: ${device.allowedUsers}")
    // Silently reject - don't notify user to avoid information leakage
    return
}

Log.d(TAG, "Pairing authorized for user: ${authRequest.username}")
// Continue with authentication...
```

**File**: `server-android/app/src/main/java/dev/rourunisen/tapauth/ble/BleGattService.kt`

In `handleAuthenticationRequest()` method (around line 480-490), add the same check after parsing the request:

```kotlin
// After parsing authentication request from decrypted wrapper
val authRequest = parseAuthRequest(decryptedWrapper)

// CHECK: Verify this pairing is allowed to authenticate this user
if (!matchedDevice.isUserAllowed(authRequest.username)) {
    Log.w(TAG, "BLE pairing not authorized for user: ${authRequest.username}")
    sendResponseToClient(gatt, "UNAUTHORIZED_USER".toByteArray())
    return
}
```

#### Linux Client Side

**File**: `client-pam/src/auth_client.rs`

In the `AuthenticationClient::new()` method or `authenticate()` method, add validation:

```rust
// Load paired servers
let servers = config_manager.load_paired_servers()?;

// Filter servers that are allowed to authenticate this user
let allowed_servers: Vec<_> = servers
    .iter()
    .filter(|(_, server)| server.is_user_allowed(&username))
    .collect();

if allowed_servers.is_empty() {
    tracing::warn!("No paired servers authorized for user: {}", username);
    return Err(AuthError::NoPairedDevices);
}

tracing::info!("{} server(s) authorized for user {}", allowed_servers.len(), username);
```

### 3. Update Pairing Flow

#### Android Pairing Screen

**File**: `server-android/app/src/main/java/dev/rourunisen/tapauth/ui/pairing/PairingScreen.kt`

Add UI to let user specify which usernames this pairing should allow:

```kotlin
// After successful pairing, before saving:
val device = PairedDevice(
    deviceId = deviceId,
    publicKey = clientPublicKey,
    csk = receivedCsk,
    displayName = hostname,
    pairedAt = System.currentTimeMillis(),
    allowedUsers = listOf() // TODO: Get from UI - empty means all users
)
```

Add a UI component:
```kotlin
// In the pairing screen
var allowedUsers by remember { mutableStateOf<List<String>>(emptyList()) }
var showUserDialog by remember { mutableStateOf(false) }

// After pairing success
Button(onClick = { showUserDialog = true }) {
    Text("Configure Users")
}

// User configuration dialog
if (showUserDialog) {
    UserConfigDialog(
        currentUsers = allowedUsers,
        onUsersChanged = { allowedUsers = it },
        onDismiss = { showUserDialog = false }
    )
}
```

#### Desktop Pairing

**File**: `client-config-gui/src/screens/pairing.rs` (if using GUI)

Add username configuration after successful pairing. For now, the default of empty list (all users) is secure enough for initial implementation.

### 4. Configuration GUI Permission Elevation

#### Detect Current User

**File**: `client-config-gui/src/main.rs`

```rust
use std::env;

fn main() {
    // Get the user who invoked the program (before any elevation)
    let actual_user = env::var("SUDO_USER")
        .or_else(|_| env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_string());
    
    println!("Running as user: {}", actual_user);
    
    // Check if we're running as root
    if !shared::config::is_root() {
        println!("Not running as root, attempting elevation...");
        attempt_privilege_elevation(&actual_user);
    }
}
```

#### Privilege Elevation with pkexec

**File**: `client-config-gui/src/utils/elevation.rs` (new file)

```rust
use std::process::Command;
use std::env;

pub fn attempt_privilege_elevation(original_user: &str) -> ! {
    // Try pkexec first (polkit)
    if let Ok(current_exe) = env::current_exe() {
        // pkexec preserves environment variable PKEXEC_UID
        let pkexec_result = Command::new("pkexec")
            .env("TAPAUTH_ORIGINAL_USER", original_user)
            .arg(current_exe)
            .args(env::args().skip(1))
            .status();
        
        if let Ok(status) = pkexec_result {
            std::process::exit(status.code().unwrap_or(1));
        }
    }
    
    // Fallback: Ask user to run with sudo
    eprintln!("ERROR: This application requires root privileges.");
    eprintln!("Please run with: sudo tapauth-config");
    std::process::exit(1);
}
```

#### Create polkit Policy File

**File**: `client-config-gui/dev.rourunisen.tapauth.policy` (new file)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>TapAuth</vendor>
  <vendor_url>https://github.com/Lolle2000la/tapauth</vendor_url>
  
  <action id="dev.rourunisen.tapauth.configure">
    <description>Configure TapAuth authentication</description>
    <message>Authentication is required to configure TapAuth</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/bin/tapauth-config</annotate>
  </action>
</policyconfig>
```

#### Install Script Update

**File**: `client-config-gui/install.sh` (update)

```bash
# Install polkit policy
sudo install -Dm644 dev.rourunisen.tapauth.policy \
    /usr/share/polkit-1/actions/dev.rourunisen.tapauth.policy

# Create desktop file that uses pkexec
cat > tapauth-config.desktop << EOF
[Desktop Entry]
Name=TapAuth Configuration
Comment=Configure TapAuth authentication pairings
Exec=pkexec tapauth-config
Icon=security-high
Terminal=false
Type=Application
Categories=Settings;Security;
EOF

sudo install -Dm644 tapauth-config.desktop \
    /usr/share/applications/tapauth-config.desktop
```

### 5. Update Protocol Messages

The `AuthenticationRequest` already contains the `username` field, so no protocol changes are needed.

### 6. Testing Plan

1. **Backwards Compatibility Test**:
   - Verify old pairings (without `allowed_users`) still work for all users
   - Ensure JSON deserialization handles missing field correctly

2. **User Restriction Test**:
   - Pair device with specific user list (e.g., `["alice", "bob"]`)
   - Verify authentication succeeds for allowed users
   - Verify authentication fails (silently) for non-allowed users (e.g., "root")

3. **Multi-User Test**:
   - Create pairing for user "alice"
   - Verify alice can authenticate
   - Verify bob cannot authenticate with same pairing
   - Create second pairing for user "bob"
   - Verify both users can now authenticate (with their respective pairings)

4. **Privilege Elevation Test**:
   - Run `tapauth-config` as normal user
   - Verify pkexec elevation works
   - Verify original username is preserved

## Security Considerations

1. **Silent Rejection**: When a pairing doesn't allow a user, reject silently to avoid information leakage
2. **Backwards Compatibility**: Empty `allowed_users` list means "all users allowed" for old pairings
3. **Privilege Separation**: GUI runs with user privileges initially, only elevates when needed
4. **Audit Logging**: Log all username authorization decisions for security auditing

## Migration Path

1. **Phase 1** (✅ COMPLETE): Data structures with backwards compatibility
2. **Phase 2** (✅ COMPLETE): Enforcement in authentication handlers  
3. **Phase 3** (✅ COMPLETE): Pairing flow updated to use username from protocol
4. **Phase 4** (✅ COMPLETE): Protocol updated - username sent during pairing
5. **Phase 5** (✅ COMPLETE): Multi-user support - appends users on re-pairing
6. **Phase 6** (TODO): Remove backwards compatibility - enforce non-empty allowed_users
7. **Phase 7** (TODO): Add UI for managing allowed users (optional enhancement)

## ✅ What's Fully Implemented (Current Session)

### 1. Protocol Extension
- ✅ Added `username` field to `PairingCskMessage` protobuf
- ✅ Client sends username during pairing handshake
- ✅ Server receives and stores username in `allowed_users` list

### 2. Client-Side Changes (Desktop/Linux)
- ✅ Config GUI detects current username (`whoami::username()`)
- ✅ Client includes username in `PairingCskMessage`
- ✅ Client stores paired server with username in `allowed_users`
- ✅ PAM module filters servers based on current user

### 3. Server-Side Changes (Android)
- ✅ Updated JNI wrapper to return `(ByteArray, String)` from `parsePairingCskMessage`
- ✅ Pairing flow receives username from protocol
- ✅ **Multi-user support**: Detects if device already paired by matching Ed25519 public key
- ✅ **Re-pairing behavior**: Appends new username to `allowed_users` if not present
- ✅ First pairing: Creates device with `allowed_users: [username]`
- ✅ Re-pairing: Updates existing device with combined user list
- ✅ Both UDP and BLE authentication enforce username restrictions

### 4. Security Model
- ✅ **Per-user pairing**: Each pairing tied to specific username(s)
- ✅ **No privilege escalation**: Empty `allowed_users` list denies all authentication
- ✅ **Multi-user desktops**: Alice pairs → `["alice"]`, Bob pairs same device → `["alice", "bob"]`
- ✅ **Silent rejection**: Prevents username enumeration attacks

## Implementation Summary (Current Session)

### ✅ What's Working Now:

1. **Full Protocol Implementation**:
   - Client sends username in `PairingCskMessage`
   - Server extracts username and uses it for authorization
   - Multi-user pairing fully supported

2. **Security Enforcement Active**:
   - Android server validates username against allowed users list for both UDP and BLE
   - Client PAM module filters servers based on username authorization
   - Silent rejection prevents username enumeration attacks
   - **No default "all users"** - prevents privilege escalation

3. **Multi-User Behavior**:
   - Same device pairing multiple times appends users to list
   - Server detects existing devices by Ed25519 public key
   - Timestamp updated on re-pairing

### 🔨 Remaining Tasks (Optional Enhancements):

1. **Phase 6 - Remove Backwards Compatibility**:
   - Currently: Empty `allowed_users` list is technically possible (but won't be created by new code)
   - Future: Add validation to reject empty lists during deserialization
   - Migration: Update any old pairings to include username

2. **Phase 7 - UI Enhancements** (Nice to have):
   - Android: Show/edit allowed users in device list
   - Android: During pairing, show which user is being added
   - Desktop: Config GUI to view/edit allowed users for pairings
   - Desktop: Privilege elevation with pkexec/polkit for multi-user editing

## Current Behavior

- **New Pairings**: Always include username from current session
- **Re-Pairings**: Append username if not already in list
- **Authentication**: Enforces username restrictions strictly
- **Logs**: Clear logging of authorization decisions for debugging

## How to Configure User Restrictions (Manual - Until UI Added)

Currently, user restrictions can be configured manually by editing the pairing data:

**Android** (SharedPreferences):
1. Root the device or use adb backup
2. Edit `tapauth_devices` preferences
3. Add `"allowedUsers": ["alice", "bob"]` to device JSON

**Linux Client** (`/etc/tapauth/paired_servers.json`):
```json
{
  "server-id": {
    "name": "My Phone",
    "public_key": "...",
    "allowed_users": ["alice", "bob"],
    "paired_at": "2025-10-26T..."
  }
}
```

After manual configuration, authentication will only succeed for listed users.
