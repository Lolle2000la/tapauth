# Device Lifecycle Management

This document outlines the procedures for managing the lifecycle of paired devices, specifically focusing on revocation (un-pairing) and key rotation.

## Device Revocation (Un-pairing)

A secure and user-friendly method for revoking trust from a previously paired device is essential.

### Guiding Principles

* **User-Initiated**: Revocation must be initiated by the user on a device they physically control.
* **Local Action**: Un-pairing is a local operation. It involves deleting the cryptographic keys associated with the other device. There is no need for a network-based "revocation message."

### Revocation Flow

#### From the Server (Phone)

1.  The Server application **must** display a list of all paired Clients.
2.  The user selects the Client they wish to remove.
3.  Upon confirmation, the Server application **must** securely delete the Client's Ed25519 public key (`Client_Pub`, the `publicKey` of its `PairedDevice`) and the shared **`Client Symmetric Key (CSK)`** associated with that specific Client from its storage.

A pairing on either side also records which usernames it may authenticate (the `allowed_users` / `allowedUsers` list), so removal can be scoped to one user: the user is dropped from that list, and the device entry — public key and `CSK` together — is deleted only when the last user is removed (`DeviceRepository.removeUserFromDevice`, `shared::config::PairedServer::allowed_users`).

#### From the Client (Desktop)

1.  The Client application **must** provide a mechanism to list all paired Servers.
2.  The user selects the Server they wish to remove.
3.  Upon confirmation, the Client application **must** securely delete the `Server_Pub` (the Ed25519 public key in the pairing's `public_key` field) associated with that specific Server from its storage. Note: The Client's own `CSK` is not deleted in this case.

Removal on the Client is likewise scoped by username, not only by device: `remove_user_from_pairing` drops the calling user from that server's `allowed_users` and deletes the server entry only when no users remain (`shared/src/config.rs`, reached through `handle_remove_device` in `tapauthd/src/admin_handler.rs`).

## Client Key Rotation

For security hygiene or in case of a suspected compromise, the Client must support rotating its master symmetric key.

* **Procedure**: The Client application **must** provide a secure, user-initiated function to discard the existing **Client Symmetric Key (`CSK`)** and generate a new one.
* **Effect**: This action immediately invalidates all existing Server pairings. The implementation drops every paired server along with the old key, so the list of paired Servers is empty afterwards (`ClientConfigManager::rotate_csk` → `clear_paired_servers` + `generate_and_save_csk` in `shared/src/config.rs`).
* **Recovery**: The user **must** re-pair the Client with any Server they wish to continue using, which will securely distribute the new `CSK`. This acts as a master "de-authorize all" function.