//! Algorithm negotiation for pairing v2: which symmetric, hash and signature
//! algorithm both peers agree on, and what a client-wide `CSK` pin does to it.
//!
//! The Kani harnesses at the bottom of this file are `#[cfg(kani)]`, so they are
//! ungated by the default test suite: `cargo test` never compiles them and the shipped
//! build is unaffected — only `cargo kani -p shared --lib` runs them.

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

/// Decode an advertised `supported_*` list, dropping the ids this build cannot name.
///
/// An **advertisement is a compatibility surface**: a peer lists what it supports,
/// and a newer build may list an algorithm this one does not implement alongside the
/// baseline both share. Refusing the whole handshake over that extra id is what kept
/// an older Client from pairing with a newer Server at all, against
/// `cryptography-specification.md` §1.4. What survives here is the part of the peer's
/// list this build can name, and [`negotiate`] intersects exactly that with
/// `SUPPORTED_*` — so `[3, 1]` negotiates `AES_256_GCM`, while a list of nothing but
/// unknown ids decodes empty and intersects with nothing, so it is still refused.
///
/// Dropping is confined to this path. A **selection is a claim**, not an
/// advertisement: an id a peer sends as its `selected_*` is authenticated and must be
/// one we offered, so `ServerPairingSession::verify_response` still refuses an unknown
/// one (`shared/src/protocol/pairing/server.rs`) instead of defaulting.
///
/// The `Result` stays for the caller, which funnels this and the negotiation failure
/// through one type; a list that names only unknown ids is not itself an error here.
pub(super) fn symmetric_algorithms(
    values: &[i32],
) -> Result<Vec<SymmetricAlgorithm>, ProtocolError> {
    Ok(values
        .iter()
        .filter_map(|value| SymmetricAlgorithm::try_from(*value).ok())
        .collect())
}

/// Hash counterpart of [`symmetric_algorithms`], same rule (see there).
pub(super) fn hash_algorithms(values: &[i32]) -> Result<Vec<HashAlgorithm>, ProtocolError> {
    Ok(values
        .iter()
        .filter_map(|value| HashAlgorithm::try_from(*value).ok())
        .collect())
}

/// Signature counterpart of [`symmetric_algorithms`], same rule (see there).
pub(super) fn signature_algorithms(
    values: &[i32],
) -> Result<Vec<SignatureAlgorithm>, ProtocolError> {
    Ok(values
        .iter()
        .filter_map(|value| SignatureAlgorithm::try_from(*value).ok())
        .collect())
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

/// Kani bounded-model-checking harnesses for [`negotiate`] (compiled only under
/// `cfg(kani)`).
///
/// Placement is by subject: they sit beside the function they prove so that
/// `negotiate` and `pick_first` are reachable as `super::` items — both are
/// `pub(super)`, i.e. visible in `pairing` and its descendants, so a child module
/// needs **no visibility change to production code**.
///
/// **Ungated by the default test suite.** `cargo test` never compiles this module —
/// the whole module is behind `#[cfg(kani)]`, a cfg only Kani sets — so it cannot fail
/// a normal test run and nothing here gates a merge. Only `cargo kani -p shared --lib`
/// runs it; the `Kani Proofs (shared)` workflow is deliberately not one of the eight
/// required contexts in `scripts/ci/check-required-checks.sh`, so a regression here
/// produces no signal unless someone reads that job.
///
/// These harnesses pin the semantics of `negotiate` **below** the advertisement
/// decoder. That decoder now skips ids this build cannot name (see
/// [`super::symmetric_algorithms`]), so what reaches `negotiate` is the known part of
/// the peer's list and not the list as it arrived: (a) and (c) still describe it, while
/// (b) — "succeeds exactly when every slot intersects" — has to be read as "refused
/// only when the *known* intersection is empty" before the next run. The documented
/// algorithm-upgrade path likewise needs a fresh Kani run, not the assumption that
/// these still hold.
///
/// The peer slices are `[T; K]` arrays with a symbolic length, not `Vec`s, and the
/// variants are enumerated by hand (`ALL_*`) rather than derived: neither enum has
/// an `Arbitrary` impl and adding one would mean editing the enums. Each enum has
/// exactly two variants today (`proto/auth_protocol.proto:18-39` — the real
/// algorithm and `*_UNSPECIFIED`), so `K = 2` covers every distinct multiset a peer
/// could advertise. Note that tag `2` is `reserved` for `SymmetricAlgorithm` and
/// `HashAlgorithm` but **not** for `SignatureAlgorithm`, so the `.proto` reserves a
/// *tag*, never a variant: what actually catches a newly added variant is the
/// `_variants_are_all_listed` guard below, which stops compiling the moment one
/// appears.
#[cfg(kani)]
mod kani_proofs {
    use super::{
        negotiate, PinnedAlgorithms, SUPPORTED_HASH_ALGORITHMS, SUPPORTED_SIGNATURE_ALGORITHMS,
        SUPPORTED_SYMMETRIC_ALGORITHMS,
    };
    use crate::protocol::pb::{HashAlgorithm, SignatureAlgorithm, SymmetricAlgorithm};

    /// Every `SymmetricAlgorithm` variant (`proto/auth_protocol.proto:18-22`).
    ///
    /// The `_variants_are_all_listed` guard below is what makes a new variant fail
    /// the build instead of being `% 2`-ed away here.
    const ALL_SYMMETRIC: [SymmetricAlgorithm; 2] = [
        SymmetricAlgorithm::Unspecified,
        SymmetricAlgorithm::Aes256Gcm,
    ];

    /// Every `HashAlgorithm` variant (`proto/auth_protocol.proto:29-33`).
    ///
    /// Guarded by `_variants_are_all_listed` below, as above.
    const ALL_HASH: [HashAlgorithm; 2] = [HashAlgorithm::Unspecified, HashAlgorithm::Sha256];

    /// Every `SignatureAlgorithm` variant (`proto/auth_protocol.proto:36-39`).
    ///
    /// Guarded by `_variants_are_all_listed` below, as above.
    const ALL_SIGNATURE: [SignatureAlgorithm; 2] =
        [SignatureAlgorithm::Unspecified, SignatureAlgorithm::Ed25519];

    /// Longest peer slice the harnesses explore. Two is the whole domain: a third
    /// element could only repeat one of the two variants, which `contains` cannot
    /// tell apart from the two-element case — and if a third *variant* ever appears,
    /// the guard below fails the build and `K` has to be revisited with it.
    const K: usize = 2;

    // Exhaustive by construction: a new algorithm variant makes one of these matches
    // non-exhaustive, so the build fails and `ALL_*`/`K` must be revisited together
    // with the harness domain. Without this guard a third variant would be silently
    // `% len`-ed away by `*_at` and every harness below would keep reporting
    // SUCCESSFUL while the completeness claim had become false.
    const _: () = {
        fn _variants_are_all_listed(value: SymmetricAlgorithm) -> usize {
            match value {
                SymmetricAlgorithm::Unspecified => 0,
                SymmetricAlgorithm::Aes256Gcm => 1,
            }
        }

        fn _hash_variants_are_all_listed(value: HashAlgorithm) -> usize {
            match value {
                HashAlgorithm::Unspecified => 0,
                HashAlgorithm::Sha256 => 1,
            }
        }

        fn _signature_variants_are_all_listed(value: SignatureAlgorithm) -> usize {
            match value {
                SignatureAlgorithm::Unspecified => 0,
                SignatureAlgorithm::Ed25519 => 1,
            }
        }
    };

    fn symmetric_at(index: u8) -> SymmetricAlgorithm {
        let position = (index as usize) % ALL_SYMMETRIC.len();
        ALL_SYMMETRIC
            .get(position)
            .copied()
            .unwrap_or(SymmetricAlgorithm::Unspecified)
    }

    fn hash_at(index: u8) -> HashAlgorithm {
        let position = (index as usize) % ALL_HASH.len();
        ALL_HASH
            .get(position)
            .copied()
            .unwrap_or(HashAlgorithm::Unspecified)
    }

    fn signature_at(index: u8) -> SignatureAlgorithm {
        let position = (index as usize) % ALL_SIGNATURE.len();
        ALL_SIGNATURE
            .get(position)
            .copied()
            .unwrap_or(SignatureAlgorithm::Unspecified)
    }

    /// A symbolic peer slice: `K` symbolic variants plus a symbolic length.
    fn symmetric_peer() -> ([SymmetricAlgorithm; K], usize) {
        let slice = [
            symmetric_at(kani::any::<u8>()),
            symmetric_at(kani::any::<u8>()),
        ];
        let len: usize = kani::any();
        kani::assume(len <= K);
        (slice, len)
    }

    fn hash_peer() -> ([HashAlgorithm; K], usize) {
        let slice = [hash_at(kani::any::<u8>()), hash_at(kani::any::<u8>())];
        let len: usize = kani::any();
        kani::assume(len <= K);
        (slice, len)
    }

    fn signature_peer() -> ([SignatureAlgorithm; K], usize) {
        let slice = [
            signature_at(kani::any::<u8>()),
            signature_at(kani::any::<u8>()),
        ];
        let len: usize = kani::any();
        kani::assume(len <= K);
        (slice, len)
    }

    fn pinned_any() -> Option<PinnedAlgorithms> {
        if kani::any::<bool>() {
            Some(PinnedAlgorithms {
                symmetric_algorithm: symmetric_at(kani::any::<u8>()),
                hash_algorithm: hash_at(kani::any::<u8>()),
            })
        } else {
            None
        }
    }

    /// (a) **Soundness, both paths.** Whatever `negotiate` selects is an algorithm
    /// this build implements *and* one the peer advertised, in every slot.
    ///
    /// The defect this catches is a selection that reaches the transcript or the
    /// AEAD without appearing in the peer's list — i.e. two peers agreeing on an
    /// algorithm one of them never offered.
    #[kani::proof]
    #[kani::unwind(6)]
    fn a_negotiated_algorithm_is_supported_and_was_advertised() {
        let (symmetric, symmetric_len) = symmetric_peer();
        let (hash, hash_len) = hash_peer();
        let (signature, signature_len) = signature_peer();
        let symmetric = &symmetric[..symmetric_len];
        let hash = &hash[..hash_len];
        let signature = &signature[..signature_len];

        if let Ok(negotiated) = negotiate(symmetric, hash, signature, pinned_any()) {
            assert!(
                SUPPORTED_SYMMETRIC_ALGORITHMS.contains(&negotiated.symmetric_algorithm),
                "negotiated a symmetric algorithm this build does not implement"
            );
            assert!(
                symmetric.contains(&negotiated.symmetric_algorithm),
                "negotiated a symmetric algorithm the peer never advertised"
            );
            assert!(
                SUPPORTED_HASH_ALGORITHMS.contains(&negotiated.hash_algorithm),
                "negotiated a hash algorithm this build does not implement"
            );
            assert!(
                hash.contains(&negotiated.hash_algorithm),
                "negotiated a hash algorithm the peer never advertised"
            );
            assert!(
                SUPPORTED_SIGNATURE_ALGORITHMS.contains(&negotiated.signature_algorithm),
                "negotiated a signature algorithm this build does not implement"
            );
            assert!(
                signature.contains(&negotiated.signature_algorithm),
                "negotiated a signature algorithm the peer never advertised"
            );
        }
    }

    /// (b) **Completeness, unpinned path only.** With no pin, `negotiate` succeeds
    /// exactly when every slot's intersection with `SUPPORTED_*` is non-empty. It
    /// never refuses two peers that share an algorithm.
    ///
    /// `intersectable` is restated here instead of reusing `pick_first`, so the
    /// oracle is independent of the code under proof: a `pick_first` that skipped a
    /// candidate would fail this assertion rather than agree with itself.
    #[kani::proof]
    #[kani::unwind(6)]
    fn an_unpinned_negotiation_succeeds_exactly_when_every_slot_intersects() {
        let (symmetric, symmetric_len) = symmetric_peer();
        let (hash, hash_len) = hash_peer();
        let (signature, signature_len) = signature_peer();
        let symmetric = &symmetric[..symmetric_len];
        let hash = &hash[..hash_len];
        let signature = &signature[..signature_len];

        let intersectable = SUPPORTED_SYMMETRIC_ALGORITHMS
            .iter()
            .any(|algorithm| symmetric.contains(algorithm))
            && SUPPORTED_HASH_ALGORITHMS
                .iter()
                .any(|algorithm| hash.contains(algorithm))
            && SUPPORTED_SIGNATURE_ALGORITHMS
                .iter()
                .any(|algorithm| signature.contains(algorithm));

        assert_eq!(
            negotiate(symmetric, hash, signature, None).is_ok(),
            intersectable,
            "an unpinned negotiation refused or accepted a peer against the intersection"
        );
    }

    /// The **pinned path differs**: a pin that this build does not implement (the
    /// symbolic `Unspecified`) is refused even though the intersection is non-empty,
    /// so `Err` there is legitimate and (b) must not be asserted for it.
    ///
    /// This harness pins the pinned path down exactly: `Ok` iff the pin is
    /// supported *and* advertised in both pinned slots and the signature slot
    /// intersects, and on `Ok` the selected ids are the pinned ones — the pin
    /// outvotes our preference order.
    #[kani::proof]
    #[kani::unwind(6)]
    fn a_pinned_negotiation_selects_the_pin_only_when_both_sides_admit_it() {
        let (symmetric, symmetric_len) = symmetric_peer();
        let (hash, hash_len) = hash_peer();
        let (signature, signature_len) = signature_peer();
        let symmetric = &symmetric[..symmetric_len];
        let hash = &hash[..hash_len];
        let signature = &signature[..signature_len];
        let pinned = PinnedAlgorithms {
            symmetric_algorithm: symmetric_at(kani::any::<u8>()),
            hash_algorithm: hash_at(kani::any::<u8>()),
        };

        let admissible = SUPPORTED_SYMMETRIC_ALGORITHMS.contains(&pinned.symmetric_algorithm)
            && symmetric.contains(&pinned.symmetric_algorithm)
            && SUPPORTED_HASH_ALGORITHMS.contains(&pinned.hash_algorithm)
            && hash.contains(&pinned.hash_algorithm)
            && SUPPORTED_SIGNATURE_ALGORITHMS
                .iter()
                .any(|algorithm| signature.contains(algorithm));

        let result = negotiate(symmetric, hash, signature, Some(pinned));
        assert_eq!(
            result.is_ok(),
            admissible,
            "the pinned path accepted or refused a pin against its own condition"
        );
        if let Ok(negotiated) = result {
            assert_eq!(
                negotiated.symmetric_algorithm, pinned.symmetric_algorithm,
                "the pin did not outvote the preference order"
            );
            assert_eq!(
                negotiated.hash_algorithm, pinned.hash_algorithm,
                "the pin did not outvote the preference order"
            );
        }
    }
}
