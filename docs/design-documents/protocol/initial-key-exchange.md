# Initial Key Exchange Protocol

## Overview

This document outlines a secure and byte-efficient protocol for the initial pairing of a **Client** (e.g., a Linux desktop) with a **Server** (e.g., an Android phone). The goal is to securely share the Client's long-term symmetric key with a new Server. The protocol uses a QR code to bootstrap trust, a high-speed key exchange to create a temporary secure channel, and a user-verified Short Authentication String (SAS) to prevent Man-in-the-Middle (MITM) attacks.

***

## Cryptography and Keys

* **Cryptographic Primitives**: All cryptographic algorithms used in this protocol are explicitly defined in the [`cryptography-specification.md`](cryptography-specification.md) document.
* **Key Exchange**: An X25519 key exchange is performed to generate a temporary **Pairing Symmetric Key (`PSK`)**.
* **Client Symmetric Key** (`CSK`): The Client's long-term key for encrypting all standard communication. This is the key that will be shared during this protocol.

***

## Pairing Protocol Visualization

```mermaid
sequenceDiagram
    actor User
    participant Client (Desktop)
    participant Server (Phone)

    User->>Client (Desktop): Initiate pairing
    Client (Desktop)->>Client (Desktop): Generate Key Pairs (if needed)
    Client (Desktop)->>Client (Desktop): Generate CSK (if first pairing)
    Client (Desktop)-->>User: Display QR Code (URL with pk, ip, port)

    User->>Server (Phone): Scan QR Code
    Server (Phone)->>Server (Phone): Store Client info & Client_Pub
    Server (Phone)->>Server (Phone): Generate own Key Pairs
    
    Server (Phone)->>Client (Desktop): Connect (TCP) and send PairingHandshake
    
    Note over Client (Desktop),Server (Phone): Both sides now compute the temporary PSK
    Client (Desktop)->>Client (Desktop): psk = ECDH(Client_Priv, Server_Pub)
    Server (Phone)->>Server (Phone): psk = ECDH(Server_Priv, Client_Pub)
    
    Note over Client (Desktop),Server (Phone): Both derive SAS and display it
    Client (Desktop)-->>User: Display SAS (e.g., "123-456")
    Server (Phone)-->>User: Display SAS (e.g., "123-456")

    User->>User: Visually confirm SAS matches
    User->>Client (Desktop): Approve pairing
    User->>Server (Phone): Approve pairing
    
    Client (Desktop)->>Server (Phone): Send ClientKeyDelivery (CSK encrypted with PSK)
    Server (Phone)->>Client (Desktop): Send PairingConfirmation (CSK hash encrypted with PSK)
    
    Note over Client (Desktop),Server (Phone): Pairing complete. Both discard PSK and store CSK.
```

***

## Pairing Protocol Steps

### Step 1: Client Presents QR Code

The **Client (desktop)** generates its key pair (if one doesn't exist) and its Client Symmetric Key (`CSK`) if this is its first-ever pairing. It encodes its connection information into a QR code which **must** contain a custom URL with the following format:

`tapauth://pair?v=1&pk=<hex_encoded_pubkey>&p=<port>&ip4=<ipv4_address>&ip6=<ipv6_address>`

* **`tapauth://pair`**: The scheme and action that identifies this as a TapAuth pairing request.
* **`v=1`**: The protocol version for the pairing process.
* **`pk`**: The Client's 32-byte public key, encoded as a hexadecimal string.
* **`p`**: The **TCP** port the Client is listening on for the pairing connection.
* **`ip4` / `ip6`**: The Client's IP addresses. At least one **must** be present.

> **Security Warning**: The security of this initial step relies on the user scanning the QR code directly from the trusted Client's screen. An attacker could attempt to trick a user into scanning a malicious QR code (e.g., from a photo or a different screen), which would lead to pairing with the attacker's device. The Short Authentication String (SAS) in Step 4 is the critical defense against this.

### Step 2: Server Initiates Connection

The **User** scans the code with the **Server (phone)**. The app parses the URL, extracts the Client's public key and connection details, and generates its own key pair. It then establishes a **TCP connection** to the Client.

Upon connection, the Server sends a `PairingHandshake` message. This message contains:
*   The Server's public key.
*   A list of cryptographic algorithms the Server supports (e.g., for signatures, symmetric encryption, and hashing).

The Client receives this handshake and stores the Server's public key and its list of supported algorithms for the duration of the pairing session.

### Step 3: Temporary Key Agreement

Both devices independently compute the same temporary **Pairing Symmetric Key (`PSK`)** using X25519 and the specified KDF. This key exists only for the duration of this pairing session.

### Step 4: Anti-MITM Verification

This is the most critical security step in the pairing process. Both devices compute and display a **Short Authentication String (SAS)**.

**SAS Generation:**
The SAS **must** be a 6-digit number derived as follows:
1.  Create a byte string by concatenating the Client's public key and the Server's public key: `input_material = Client_Pub | Server_Pub`.
2.  Use HKDF-SHA256 with the `PSK` as the input keying material (`IKM`), no salt, and the info string `"tapauth-sas"` to derive a 64-bit value.
3.  Take the resulting value, calculate `value mod 1,000,000`, and pad with leading zeros if necessary to create a 6-digit string. This string should be displayed to the user in a friendly format (e.g., "123-456").

**The user MUST visually confirm that the SAS displayed on the Client screen and the Server screen are identical before proceeding.**

Failure to verify the SAS could allow a Man-in-the-Middle (MITM) attacker to intercept the connection and compromise the shared key. The user interface on both devices **must** make this verification step prominent and mandatory. For example, the confirmation button could be disabled until the user actively confirms the match via a checkbox.

### Step 5: Client Sends Shared Key

After the user confirms the SAS on the Client, the Client selects a compatible set of cryptographic algorithms from the list provided by the Server. It then sends a `ClientKeyDelivery` message to the Server. This message contains the long-term `CSK`, encrypted with the temporary `PSK`.

The Client and Server will use this negotiated set of algorithms for all subsequent communication.

### Step 6: Server Confirms and Finalizes

The Server receives the message and decrypts it using the `PSK` to retrieve the `CSK`. After the user confirms the SAS on the Server, it computes a hash of the received `CSK` using the negotiated hash algorithm (e.g., SHA-256). It then sends a `PairingConfirmation` message back to the Client, containing:
*   The `hash_algorithm` used.
*   The resulting hash, encrypted with the `PSK`.

### Step 7: Completion

The Client decrypts the confirmation. If the hash matches the hash of the `CSK` it sent (calculated with the same algorithm), the pairing is successful. Both devices **must** now securely discard the ephemeral `PSK` and store the long-term `CSK` and the negotiated algorithm choices for all future communication.