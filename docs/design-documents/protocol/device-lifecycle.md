# Device Lifecycle Management (v2)

This document outlines the procedures for managing the lifecycle of paired devices, focusing on revocation (un-pairing), key rotation, and per-device cryptographic algorithm state.

## Device Revocation (Un-pairing)

### Guiding Principles

* **User-Initiated**: Revocation must be initiated by the user on a device they physically control.
* **Local Action**: Un-pairing is a local operation deleting the cryptographic keys and user authorizations associated with the peer. No network "revocation message" is required.

### Revocation Flow

#### From the Server (Phone)

1. The Server application displays all paired Clients.
2. The user selects a Client (or user-scoped permission) to remove.
3. Upon confirmation, the Server drops the user from `allowedUsers`; when the last user is removed, it deletes the `PairedDevice` entry — including `Client_Pub` ($Ed_C$), the shared `CSK`, its negotiated `symmetricAlgorithm` / `hashAlgorithm` / `signatureAlgorithm` / `protocolVersion`, and its cached temporal identifiers.

#### From the Client (Desktop)

1. The Client GUI (`client-config-gui`) lists all paired Servers retrieved from `tapauthd` over admin IPC (`GetServers`).
2. The user selects a Server to remove; the GUI sends `RemoveDevice` (authorized via PolKit on `tapauthd`).
3. `remove_user_from_pairing` drops the calling user from `PairedServer::allowed_users`, deleting the Server entry (`Server_Pub` $Ed_S$, `signature_algorithm`) only when `allowed_users` becomes empty. Note: the Client's own `CSK` is preserved for remaining paired Servers.

## Client Key Rotation & Algorithm Upgrades

* **Procedure**: User triggers `RotateCsk` from the GUI (authorized by PolKit in `tapauthd`).
* **Effect**:
  1. Discards the existing `CSK` and clears all `PairedServer` entries (since `CSK` is shared across all Servers for multicast broadcast).
  2. **Removes** the Client's `CskMetadata` — the negotiated `csk_symmetric_algorithm` / `csk_hash_algorithm` pair described the Servers just discarded, so it is deleted rather than reset to the baseline or upgraded in place: after a rotation nothing is pinned, and the next pairing negotiates and records a suite from scratch (`rotate_csk` → `clear_csk_metadata`, `shared/src/config.rs`).
  3. Generates a fresh 32-byte `CSK` (`generate_and_save_csk`, same file); the algorithm pair is written back by the first pairing that follows, not by the rotation.
* **Recovery**: The user re-pairs any Servers they wish to continue using, provisioning the new `CSK` and negotiated algorithms cleanly via the v2 pairing handshake.
