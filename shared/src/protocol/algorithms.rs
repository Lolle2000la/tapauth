//! Serde support for the generated cryptographic algorithm enums.
//!
//! The three algorithm enums (`SymmetricAlgorithm`, `HashAlgorithm`,
//! `SignatureAlgorithm`) are persisted in `config.rs` (the negotiated
//! `PairedServer.signature_algorithm` and the client-wide `CskMetadata`), so
//! their JSON form is part of the on-disk contract: it is the **canonical proto
//! name** (`"AES_256_GCM"`, `"CHACHA20_POLY1305"`, `"SHA256"`, `"BLAKE3"`,
//! `"ED25519"`, `"…_UNSPECIFIED"`), not the Rust variant name.
//!
//! These impls live here rather than in `build.rs`'s blanket
//! `#[derive(serde::Serialize, serde::Deserialize)]` because a derive cannot
//! produce the proto spelling; the three enums are therefore excluded from that
//! blanket derive (see `build.rs`) and implemented by hand.
//!
//! Deserialising accepts either the canonical name string or an integer, so a
//! config written by a peer that stored the numeric value still loads.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::protocol::pb::{HashAlgorithm, SignatureAlgorithm, SymmetricAlgorithm};

/// Narrow a JSON integer into the `i32` proto enum domain and convert it.
///
/// Shared by the `visit_i64` / `visit_u64` paths of [`AlgorithmVisitor`], so all
/// three enums share one range-check implementation.
fn alg_from_i32<T>(value: i32) -> Result<T, prost::UnknownEnumValue>
where
    T: TryFrom<i32, Error = prost::UnknownEnumValue>,
{
    T::try_from(value)
}

/// Visitor accepting either a proto enum name string or an integer value.
struct AlgorithmVisitor<T> {
    /// `as_str_name`-inverse of the enum being deserialised (`from_str_name`).
    from_name: fn(&str) -> Option<T>,
    /// Human-readable enum name, used in `expecting` and error messages.
    name: &'static str,
}

impl<'de, T> Visitor<'de> for AlgorithmVisitor<T>
where
    T: TryFrom<i32, Error = prost::UnknownEnumValue>,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a {} proto name string or an integer value",
            self.name
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        (self.from_name)(value)
            .ok_or_else(|| E::custom(format_args!("unknown {}: {:?}", self.name, value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let narrowed = i32::try_from(value).map_err(|_| {
            E::custom(format_args!(
                "{} value {} does not fit in an i32",
                self.name, value
            ))
        })?;
        alg_from_i32(narrowed).map_err(E::custom)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let narrowed = i64::try_from(value).map_err(|_| {
            E::custom(format_args!(
                "{} value {} does not fit in an i32",
                self.name, value
            ))
        })?;
        self.visit_i64(narrowed)
    }
}

/// Implement `Serialize`/`Deserialize` for one generated algorithm enum.
macro_rules! impl_algorithm_serde {
    ($ty:ty, $from_name:path, $name:literal) => {
        impl Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str_name())
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_any(AlgorithmVisitor {
                    from_name: $from_name,
                    name: $name,
                })
            }
        }
    };
}

impl_algorithm_serde!(
    SymmetricAlgorithm,
    SymmetricAlgorithm::from_str_name,
    "SymmetricAlgorithm"
);
impl_algorithm_serde!(HashAlgorithm, HashAlgorithm::from_str_name, "HashAlgorithm");
impl_algorithm_serde!(
    SignatureAlgorithm,
    SignatureAlgorithm::from_str_name,
    "SignatureAlgorithm"
);
