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
  2. Generates a fresh 32-byte `CSK` and resets/upgrades the Client's active `csk_symmetric_algorithm` and `csk_hash_algorithm` to the Client's preferred defaults (e.g., `AES_256_GCM` or `CHACHA20_POLY1305` and `SHA256` or `BLAKE3`) when the next pairing occurs.
* **Recovery**: The user re-pairs any Servers they wish to continue using, provisioning the new `CSK` and negotiated algorithms cleanly via the v2 pairing handshake.
