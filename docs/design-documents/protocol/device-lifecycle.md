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
3.  Upon confirmation, the Server application **must** securely delete the `Client_Pub` and the shared **`Client Symmetric Key (CSK)`** associated with that specific Client from its storage.

#### From the Client (Desktop)

1.  The Client application **must** provide a mechanism to list all paired Servers.
2.  The user selects the Server they wish to remove.
3.  Upon confirmation, the Client application **must** securely delete the `Server_Pub` associated with that specific Server from its storage. Note: The Client's own `CSK` is not deleted in this case.

## Client Key Rotation

For security hygiene or in case of a suspected compromise, the Client must support rotating its master symmetric key.

* **Procedure**: The Client application **must** provide a secure, user-initiated function to discard the existing **Client Symmetric Key (`CSK`)** and generate a new one.
* **Effect**: This action immediately invalidates all existing Server pairings.
* **Recovery**: The user **must** re-pair the Client with any Server they wish to continue using, which will securely distribute the new `CSK`. This acts as a master "de-authorize all" function.