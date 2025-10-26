# Multi-User Pairing Removal Implementation

## Overview
This document describes how pairing removal works in multi-user scenarios for both the client (desktop) and server (Android) sides of TapAuth.

## Client-Side (Desktop/Linux) Behavior

### User-Specific Removal
When a user removes a pairing from the desktop client config GUI:

1. **Only removes the current user** from the pairing's `allowed_users` list
2. **Does NOT affect other users** on the same system
3. **Automatically removes entire pairing** if current user is the last one

### User Interface
- Shows **current username** at the top of the device list
- Only displays devices where **current user is in allowed_users**
- Shows **user count** for shared pairings (e.g., "shared with 2 other users")
- Lists **all allowed usernames** for each device

### Example Scenarios

#### Scenario 1: Single User Pairing
```
Device: "My Phone"
Allowed users: ["alice"]

When Alice clicks "Remove":
→ Entire pairing deleted
→ Device removed from list
```

#### Scenario 2: Multi-User Pairing
```
Device: "My Phone"  
Allowed users: ["alice", "bob", "carol"]

When Alice clicks "Remove":
→ Only "alice" removed from allowed_users
→ Device remains in Bob's and Carol's lists
→ Updated: allowed_users: ["bob", "carol"]
```

### Implementation Details

**Config Manager Method:**
```rust
pub fn remove_user_from_pairing(&self, id: &str, username: &str) -> Result<bool, ConfigError>
```
- Returns `true` if entire pairing was removed (last user)
- Returns `false` if only user was removed (other users remain)

**File Location:** `shared/src/config/mod.rs`

---

## Server-Side (Android) Behavior

### Flexible Removal Options
The Android app provides two types of removal:

#### 1. Remove Individual User
- **Action:** Click the 👥 (users) icon → Select user → Remove
- **Effect:** Removes only the selected user from `allowed_users`
- **Availability:** Only visible when device has multiple users
- **Auto-cleanup:** If removing the last user, entire device is removed

#### 2. Remove Entire Pairing
- **Action:** Click the 🗑️ (trash) icon
- **Effect:** Removes entire device for ALL users
- **Warning:** Shows special warning if multiple users will be affected

### User Interface

#### Single User Device Card
```
┌─────────────────────────────────┐
│ Desktop Computer            🗑️  │
│ Paired Oct 26, 2025 at 14:30    │
│ ID: 1a2b3c4d...                 │
│ Allowed users: alice            │
└─────────────────────────────────┘
```

#### Multi-User Device Card
```
┌─────────────────────────────────┐
│ Desktop Computer        👥  🗑️  │
│ Paired Oct 26, 2025 at 14:30    │
│ ID: 1a2b3c4d...                 │
│ Allowed users: alice, bob       │
│                                 │
│ [When 👥 clicked]               │
│ ─────────────────────────────   │
│ Remove individual user:         │
│  alice            [Remove]      │
│  bob              [Remove]      │
└─────────────────────────────────┘
```

### Dialog Messages

#### Remove Individual User (Not Last)
```
Remove User?

Remove user "alice" from "Desktop Computer"?

Other users (bob, carol) will still be able 
to authenticate.

[Cancel]  [Remove]
```

#### Remove Individual User (Last User)
```
Remove Device?

Remove user "alice" from "Desktop Computer"?

This is the last user, so the entire pairing 
will be removed.

[Cancel]  [Remove]
```

#### Remove Entire Pairing (Multiple Users)
```
Remove Entire Pairing?

⚠️ WARNING: This pairing is used by 3 users!

Users: alice, bob, carol

Are you sure you want to remove "Desktop Computer"? 
All users will need to pair again to authenticate 
with this device.

[Cancel]  [Remove All]
```

### Implementation Details

**Repository Methods:**
```kotlin
// Remove entire device
suspend fun removePairedDevice(deviceId: String)

// Remove specific user from device
// Returns true if entire device was removed (last user)
suspend fun removeUserFromDevice(deviceId: String, username: String): Boolean
```

**File Location:** `server-android/app/src/main/java/dev/rourunisen/tapauth/data/DeviceRepository.kt`

---

## Rationale

### Why Different Approaches?

#### Client-Side: User-Specific Only
- Each user has **separate config files** (`/etc/tapauth/`)
- Users **cannot see** other users' pairings
- **Security:** Users should only manage their own authentication
- **Simplicity:** No permission elevation needed for removal

#### Server-Side: Both Options Available
- **Single app instance** manages all pairings
- **Shared device:** Multiple users may pair the same phone
- **Flexibility:** Admin may want to revoke access for one user or all
- **Transparency:** Shows all users who have access

### Security Considerations

1. **No Privilege Escalation:**
   - Client: Users can only remove themselves
   - Server: Removing users doesn't require special permissions

2. **Auditability:**
   - Both sides log removal actions
   - Clear indication when last user is removed

3. **Data Integrity:**
   - Automatic cleanup when `allowed_users` becomes empty
   - No orphaned pairings

---

## Testing Scenarios

### Test Case 1: Desktop Multi-User Removal
```bash
# Setup: Alice and Bob both paired to "Phone A"
# As Alice:
1. Open config GUI → Device List
2. See "Phone A (shared with 1 other user)"
3. Click "Remove"
4. Verify: Alice removed, Bob still has access
5. As Bob: Can still authenticate

# As Bob:
6. Open config GUI → Device List  
7. Click "Remove" on "Phone A"
8. Verify: Entire pairing deleted (last user)
```

### Test Case 2: Android Individual User Removal
```
1. Pair device with alice, bob, carol
2. Open device list → See all 3 users
3. Click 👥 → Remove "bob"
4. Verify: Only bob removed, alice & carol remain
5. Try authentication as bob → Should fail
6. Try authentication as alice → Should succeed
```

### Test Case 3: Android Complete Removal Warning
```
1. Pair device with alice, bob
2. Click 🗑️ (trash icon)
3. Verify: Warning shows "2 users"
4. Verify: Warning lists "alice, bob"
5. Confirm removal
6. Verify: Entire device deleted
7. Try authentication as any user → Should fail
```

---

## Implementation Files

### Client-Side
- **Config Manager:** `shared/src/config/mod.rs`
  - Method: `remove_user_from_pairing()`
- **Device List Screen:** `client-config-gui/src/screens/device_list.rs`
  - Shows current username
  - Filters devices by current user
  - Displays user sharing information

### Server-Side
- **Device Repository:** `server-android/.../data/DeviceRepository.kt`
  - Method: `removeUserFromDevice()`
  - Method: `removePairedDevice()`
- **Device List Screen:** `server-android/.../ui/devices/DeviceListScreen.kt`
  - User management UI
  - Warning dialogs
  - Individual user removal

---

## Future Enhancements

### Potential Improvements
1. **Audit Log:** Track who removed which users when
2. **Undo Feature:** Allow reverting accidental removals
3. **Export/Import:** Backup and restore user lists
4. **Remote Removal:** Server could notify client when user is removed
5. **Access History:** Show last authentication time per user
