use crate::protocol::messages::ProtocolError;
use crate::protocol::pb::*;

/// Symmetric AEAD algorithms this implementation supports, baseline mandatory first.
///
/// The negotiation keeps this order: `pick_first(SUPPORTED_*, theirs)` walks this
/// slice, so an algorithm added here is chosen ahead of any later entry while a
/// peer that only lists the baseline still intersects on it. A future upgrade
/// therefore puts the Client's newly preferred algorithm **first** (Servers list
/// every algorithm they implement, baseline included, so older Clients still
/// agree on the baseline).
///
/// With one algorithm per slot these three assertions are vacuous, so they are
/// recorded here — at the line an upgrade edits first — as work a second suite
/// brings back with it: `pinned_algorithms_win_over_the_baseline` (a pin
/// outvotes the baseline), `the_negotiated_symmetric_algorithm_reaches_the_aead`
/// (the negotiated id, not a literal at the call site, is what the AEAD
/// receives) and `the_two_selected_algorithm_ids_are_not_transposed`. Adding a
/// suite without them leaves pinning, plumbing and field mapping untested.
pub const SUPPORTED_SYMMETRIC_ALGORITHMS: &[SymmetricAlgorithm] = &[SymmetricAlgorithm::Aes256Gcm];

/// Hash algorithms this implementation supports, baseline mandatory first.
pub const SUPPORTED_HASH_ALGORITHMS: &[HashAlgorithm] = &[HashAlgorithm::Sha256];

/// Signature algorithms this implementation supports, baseline mandatory first.
pub const SUPPORTED_SIGNATURE_ALGORITHMS: &[SignatureAlgorithm] = &[SignatureAlgorithm::Ed25519];

/// The algorithms both peers agreed on for this pairing session.
///
/// Both directions persist these: the symmetric and hash algorithms become the
/// client-wide broadcast parameters (bound to the `CSK`), the signature algorithm
/// is the per-server one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedAlgorithms {
    /// AEAD algorithm for the provisioning/completion payloads (and, later, `EncryptedPacket`).
    pub symmetric_algorithm: SymmetricAlgorithm,
    /// Hash algorithm for temporal identifiers (and, later, `EncryptedPacket`).
    pub hash_algorithm: HashAlgorithm,
    /// Signature algorithm for identity proofs.
    pub signature_algorithm: SignatureAlgorithm,
}

/// The algorithms a client-wide CSK is already committed to. A client that
/// already holds a CSK must re-pair only with peers that support them,
/// because one multicast broadcast must stay decryptable by every paired server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedAlgorithms {
    pub symmetric_algorithm: SymmetricAlgorithm,
    pub hash_algorithm: HashAlgorithm,
}

/// Reject unknown enum values instead of silently dropping them: the lists enter
/// the transcript verbatim, so a value we cannot name cannot be hashed either.
pub(super) fn symmetric_algorithms(
    values: &[i32],
) -> Result<Vec<SymmetricAlgorithm>, ProtocolError> {
    values
        .iter()
        .map(|value| {
            SymmetricAlgorithm::try_from(*value).map_err(|_| ProtocolError::UnsupportedAlgorithm)
        })
        .collect()
}

pub(super) fn hash_algorithms(values: &[i32]) -> Result<Vec<HashAlgorithm>, ProtocolError> {
    values
        .iter()
        .map(|value| {
            HashAlgorithm::try_from(*value).map_err(|_| ProtocolError::UnsupportedAlgorithm)
        })
        .collect()
}

pub(super) fn signature_algorithms(
    values: &[i32],
) -> Result<Vec<SignatureAlgorithm>, ProtocolError> {
    values
        .iter()
        .map(|value| {
            SignatureAlgorithm::try_from(*value).map_err(|_| ProtocolError::UnsupportedAlgorithm)
        })
        .collect()
}

/// First of `ours` that `theirs` also lists — i.e. our preference order wins.
pub(super) fn pick_first<T: Copy + PartialEq>(ours: &[T], theirs: &[T]) -> Option<T> {
    ours.iter()
        .copied()
        .find(|candidate| theirs.contains(candidate))
}

/// Intersect all three lists, requiring a non-empty intersection for each.
///
/// A pinned (client-wide) algorithm must be present in the peer's list *and* be
/// one this build implements; otherwise negotiation fails instead of selecting a
/// pair the existing `CSK` is not using. The signature algorithm is per-server and
/// is never pinned.
pub(super) fn negotiate(
    symmetric: &[SymmetricAlgorithm],
    hash: &[HashAlgorithm],
    signature: &[SignatureAlgorithm],
    pinned: Option<PinnedAlgorithms>,
) -> Result<NegotiatedAlgorithms, ProtocolError> {
    let symmetric_algorithm = match pinned {
        Some(pinned) => {
            if !SUPPORTED_SYMMETRIC_ALGORITHMS.contains(&pinned.symmetric_algorithm)
                || !symmetric.contains(&pinned.symmetric_algorithm)
            {
                return Err(ProtocolError::UnsupportedAlgorithm);
            }
            pinned.symmetric_algorithm
        }
        None => pick_first(SUPPORTED_SYMMETRIC_ALGORITHMS, symmetric)
            .ok_or(ProtocolError::UnsupportedAlgorithm)?,
    };
    let hash_algorithm = match pinned {
        Some(pinned) => {
            if !SUPPORTED_HASH_ALGORITHMS.contains(&pinned.hash_algorithm)
                || !hash.contains(&pinned.hash_algorithm)
            {
                return Err(ProtocolError::UnsupportedAlgorithm);
            }
            pinned.hash_algorithm
        }
        None => pick_first(SUPPORTED_HASH_ALGORITHMS, hash)
            .ok_or(ProtocolError::UnsupportedAlgorithm)?,
    };
    let signature_algorithm = pick_first(SUPPORTED_SIGNATURE_ALGORITHMS, signature)
        .ok_or(ProtocolError::UnsupportedAlgorithm)?;
    Ok(NegotiatedAlgorithms {
        symmetric_algorithm,
        hash_algorithm,
        signature_algorithm,
    })
}
