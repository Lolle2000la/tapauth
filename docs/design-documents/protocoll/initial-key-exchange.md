# Initial Key Exchange Protocol

## Overview

This document outlines a secure and byte-efficient protocol for the initial pairing of a **Client** (e.g., a Linux desktop) with a **Server** (e.g., an Android phone). The goal is to establish a mutually authenticated, secure channel for future communication. The protocol uses a QR code to bootstrap trust, a high-speed key exchange for forward secrecy, and a user-verified Short Authentication String (SAS) to prevent Man-in-the-Middle (MITM) attacks.

***

## Cryptography and Keys

* **Cryptographic Primitives**: All cryptographic algorithms used in this protocol (including the key exchange, signatures, and symmetric encryption) are explicitly defined in the [`cryptography-specification.md`](cryptography-specification.md) document.
* **Key Exchange**: An X25519 key exchange is performed to generate a shared secret.
* **Shared Symmetric Key** (`SK`): A key for the AEAD cipher derived from the key exchange result using the specified KDF.

***

## Pairing Protocol Visualization

```mermaid
sequenceDiagram
    actor User
    participant Client (Desktop)
    participant Server (Phone)

    User->>Client (Desktop): Initiate pairing
    Client (Desktop)->>Client (Desktop): Generate X25519 key pair
    Client (Desktop)-->>User: Display QR Code (IP, Port, Client_Pub)

    User->>Server (Phone): Scan QR Code
    Server (Phone)->>Server (Phone): Store Client info & Client_Pub
    Server (Phone)->>Server (Phone): Generate X25519 key pair
    
    Server (Phone)->>Client (Desktop): Connect and send Server_Pub (32 bytes)
    
    Note over Client (Desktop),Server (Phone): Both sides now compute the shared secret
    Client (Desktop)->>Client (Desktop): secret = ECDH(Client_Priv, Server_Pub)
    Server (Phone)->>Server (Phone): secret = ECDH(Server_Priv, Client_Pub)
    
    Note over Client (Desktop),Server (Phone): Both derive SAS and display it
    Client (Desktop)-->>User: Display SAS (e.g., "123-456")
    Server (Phone)-->>User: Display SAS (e.g., "123-456")

    User->>User: Visually confirm SAS matches
    User->>Server (Phone): Approve pairing
    
    Server (Phone)->>Client (Desktop): Send encrypted confirmation message
    
    Note over Client (Desktop),Server (Phone): Pairing complete. Both store keys.
```

***

## Pairing Protocol Steps

1.  **Client Presents QR Code**: The **Client (desktop)** generates its key pair and encodes its IP, port, and public key into a QR code.
2.  **Server Initiates Connection**: The **User** scans the code with the **Server (phone)**, which decodes the data, generates its own key pair, and connects to the Client, sending its public key.
3.  **Key Agreement and Derivation**: Both devices independently compute the same `Shared_Secret` using X25519 and derive a symmetric `SK`.
4.  **Anti-MITM Verification**: Both devices compute and display a **Short Authentication String (SAS)** from the secret.
5.  **User Confirmation and Finalization**: The **User visually confirms** the SAS matches and approves the pairing. The Server sends a final encrypted confirmation to the Client.