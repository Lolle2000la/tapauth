# Cryptography Specification (v2)

This document specifies the cryptographic algorithms, key schedule, AEAD framing, and algorithm agility rules for TapAuth v2.

## 1. Real Cryptographic Agility

Protocol v2 replaces the nominal (unused) negotiation in v1 with **end-to-end enforced and persisted cryptographic agility**, respecting the shared-broadcast constraint of TapAuth:

1. **Client-Wide Broadcast Parameters** (associated with the Client's `CSK` because one multicast UDP / BLE advertisement targets **all** paired Servers simultaneously):
   * **`SymmetricAlgorithm`**: `AES_256_GCM` (`1`, baseline mandatory) or `CHACHA20_POLY1305` (`2`).
   * **`HashAlgorithm`**: `SHA256` (`1`, baseline mandatory, via HMAC-SHA256) or `BLAKE3` (`2`, via keyed BLAKE3 or HMAC-BLAKE3, standardized as HMAC-SHA256 for `SHA256` and BLAKE3 keyed-MAC for `BLAKE3`).
   * **Client `SignatureAlgorithm`**: `ED25519` (`1`, baseline mandatory).
2. **Per-Server Parameters** (stored individually per `PairedServer` on Linux and `PairedDevice` on Android):
   * **Server `SignatureAlgorithm`** + Server static public key ($Ed_S$).
3. **Negotiation & Persistence Rules**:
   * **Android Server** advertises `supported_*` in `PairingInit` with baseline mandatory algorithms listed **first** (`[AES_256_GCM, CHACHA20_POLY1305]`, `[SHA256, BLAKE3]`, `[ED25519]`) so legacy/older v1/v2 Linux Clients remain compatible.
   * **Linux Client** intersects `supported_*` with its own supported set (and with the active CSK's algorithm if a `CSK` already exists from a prior pairing). Rotating `CSK` (`RotateCsk`) allows upgrading the Client-wide algorithm when re-pairing.
   * Both sides **persist** the negotiated `SymmetricAlgorithm`, `HashAlgorithm`, and `SignatureAlgorithm` in config/repository storage and dispatch strictly on them at runtime, rejecting `UNSPECIFIED` or mismatched algorithms (`CryptoError::UnsupportedAlgorithm`).

## 2. Cryptographic Primitives & Key Schedule

### 2.1 Asymmetric Primitives (Curve25519)
* **Key Exchange**: **X25519** (ephemeral $(x_C, X_C)$ on Client, $(x_S, X_S)$ on Server). Both peers must reject all-zero shared secrets $Z$.
* **Digital Signatures**: **Ed25519** (`SignatureAlgorithm::ED25519`).
  * Post-pairing messages sign the raw-payload transcript (`"tapauth-sig-v2" || be32(version) || be32(sig_alg) || be32(payload_type) || raw_payload`).
  * Pairing binds static Ed25519 keys via mutual signatures over the handshake transcript $H$.

### 2.2 Pairing Transcript Hash & HKDF-SHA256 Key Schedule

All pairing handshake parameters are committed into a deterministic length-prefixed SHA-256 transcript hash $H$:

```text
H = SHA-256(
    "tapauth-pair-transcript-v2"
    || be32(version)
    || session_id (16B)
    || client_x25519_public_key (32B)
    || server_x25519_public_key (32B)
    || client_ed25519_public_key (32B)
    || server_ed25519_public_key (32B)
    || be32(client_device_name.len()) || client_device_name
    || be32(server_device_name.len()) || server_device_name
    || be32(supported_sym.len())  || [be32(a) for a in supported_sym]
    || be32(supported_hash.len()) || [be32(a) for a in supported_hash]
    || be32(supported_sig.len())  || [be32(a) for a in supported_sig]
    || be32(selected_symmetric_algorithm)
    || be32(selected_hash_algorithm)
    || be32(selected_signature_algorithm)
)
```

Using HKDF-SHA256 salted with $H$ and input keying material $Z = \text{X25519}(x, Y)$:

1. $\text{PRK} = \text{HKDF-Extract}_{\text{SHA256}}(\text{salt} = H,\; \text{IKM} = Z)$
2. $K_{\text{c2s}} = \text{HKDF-Expand}(\text{PRK},\; \texttt{"tapauth-pair-v2-c2s"},\; 32)$ — encrypts Client $\to$ Server pairing messages (`PairingConfirmClient`, Client `PairingAbort` MAC).
3. $K_{\text{s2c}} = \text{HKDF-Expand}(\text{PRK},\; \texttt{"tapauth-pair-v2-s2c"},\; 32)$ — encrypts Server $\to$ Client pairing messages (`PairingConfirmServer`, Server `PairingAbort` MAC).
4. $\text{SAS\_bytes} = \text{HKDF-Expand}(\text{PRK},\; \texttt{"tapauth-pair-v2-sas"},\; 8)$
5. $\text{SAS} = \text{u64::from\_be\_bytes}(\text{SAS\_bytes}) \bmod 1{,}000{,}000$ (6 decimal digits formatted `000-000`).

Salting HKDF with $H$ and using separate directional keys $K_{\text{c2s}} / K_{\text{s2c}}$ guarantees that **every** field in `PairingInit` and `PairingResponse` is cryptographically bound into both the SAS and the provisioning channel, and prevents reflection attacks.

### 2.3 Post-Pairing Signature Transcript

All `WrapperMessage` signatures are computed directly over `wrapper_signing_transcript` without re-serializing inner protobuf structs:

```text
"tapauth-sig-v2" || be32(version) || be32(signature_algorithm) || be32(payload_type) || payload
```

## 3. Single AEAD Nonce & Header AAD Construction

Protocol v2 **removes** all legacy challenge-derived nonce helpers (`derive_nonce`, `encrypt_with_csk`, `decrypt_with_csk`) so there is **one** unified AEAD construction across UDP, BLE, and Pairing:

* **Key Size**: 32 bytes (`AES-256-GCM` or `ChaCha20-Poly1305`).
* **Nonce**: 12-byte cryptographically random CSPRNG nonce generated per encryption, prepended directly to `ciphertext || 16-byte tag`.
* **Associated Data (AAD)**:
  * **For `EncryptedPacket`**:
    ```text
    aad = "tapauth-pkt-v2"
          || be32(encryption_algorithm as u32)
          || be16(temporal_identifier.len() as u16)
          || temporal_identifier
    ```
  * **For `PairingConfirmClient`**: `aad = "tapauth-pair-v2-provision" || H`
  * **For `PairingConfirmServer`**: `aad = "tapauth-pair-v2-complete" || H`

Empty AAD (`&[]`) is forbidden in v2: binding cleartext packet headers into the AEAD tag detects any downgrade or temporal-ID tampering before inner decryption/parsing runs.

## 4. Symmetric Key Lifecycle Summary

* **Ephemeral Pairing Keys ($x_C, x_S, Z, \text{PRK}, K_{\text{c2s}}, K_{\text{s2c}}$)**: Strictly session-scoped; zeroized immediately on completion, abort, or timeout.
* **Client Symmetric Key (`CSK`)**: 32-byte CSPRNG long-term key shared by one Client with all its paired Servers; protected at rest per [`security-hardening.md`](security-hardening.md) and rotated on demand via `RotateCsk`.
