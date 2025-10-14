# Device Lifecycle Management

This document outlines the procedures for managing the lifecycle of paired devices, specifically focusing on revocation (un-pairing).

## Device Revocation (Un-pairing)

A secure and user-friendly method for revoking trust from a previously paired device is essential for security and manageability.

### Guiding Principles

* **User-Initiated**: Revocation must be initiated by the user on a device they physically control.
* **Local Action**: Un-pairing is a local operation. It involves deleting the cryptographic keys associated with the other device. There is no need for a network-based "revocation message," which would add unnecessary complexity. Once the keys are gone, the trust relationship is severed.

### Revocation Flow

#### From the Server (Phone)

1.  The Server application **must** display a list of all paired Clients (desktops/laptops).
2.  The user selects the Client they wish to remove.
3.  Upon confirmation, the Server application **must** securely delete the `Client_Pub` and the `Shared Symmetric Key (SK)` associated with that specific Client from its storage.

#### From the Client (Desktop)

1.  The Client application **must** provide a mechanism (e.g., a command-line interface or a settings panel) to list all paired Servers.
2.  The user selects the Server they wish to remove.
3.  Upon confirmation, the Client application **must** securely delete the `Server_Pub` and the `Shared Symmetric Key (SK)` associated with that specific Server from its storage.