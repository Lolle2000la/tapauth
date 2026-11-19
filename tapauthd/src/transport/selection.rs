//! Which transports a session may use, and what a refusal says when none can.
//!
//! Two features of the daemon make the same decision from the same configuration
//! toggles: the PAM authentication handler, which refuses an attempt no transport
//! could reach a phone for, and the pairing session, which refuses a session with
//! no socket and no advertisement. The rule has a trap in it — `ble` needs the
//! compile-time feature as well as the toggle — and the refusal is a sentence the
//! GUI and `pamtester` output show verbatim, so both live here rather than in
//! each caller: a second copy is the shape that drifts when someone changes one.

/// The cause a refusal reports when no transport can be used.
///
/// One string for both callers: it is the PAM response's `detail` and the admin
/// response's `error_message`, so a deployment sees the same words whichever
/// side refused.
pub(crate) const NO_TRANSPORT_AVAILABLE: &str =
    "All transports (BLE and Local Network) are disabled";

/// The transports available to one attempt or one pairing session.
///
/// The PAM side reads this to decide whether an attempt can start, and the
/// pairing side whether a session can be reached; both must agree on the rule
/// and on the sentence a refusal reports, which is why they share this type
/// instead of each computing the two booleans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EnabledTransports {
    /// Local Network (UDP multicast) transport.
    pub network: bool,
    /// Bluetooth Low Energy transport: the toggle, and nothing in a build
    /// compiled without the `ble` feature.
    pub ble: bool,
}

impl EnabledTransports {
    /// The decision for the two configuration toggles.
    ///
    /// `ble` is gated on the compile-time feature too: a daemon built without it
    /// has no advertisement to start and no BLE transport to run, so
    /// `enable_ble = true` in such a build must not count as "BLE available".
    pub(crate) fn new(enable_network: bool, enable_ble: bool) -> Self {
        Self {
            network: enable_network,
            ble: cfg!(feature = "ble") && enable_ble,
        }
    }

    /// The decision for the configuration as it is right now.
    ///
    /// Read per attempt / per request so a toggle changed in the GUI takes
    /// effect without a daemon restart.
    pub(crate) fn from_config() -> Self {
        let config = shared::config::TapAuthConfig::load();
        Self::new(config.enable_network, config.enable_ble)
    }

    /// Whether at least one transport can be used.
    ///
    /// `false` means nothing can reach the phone (no UDP endpoint, no BLE
    /// advertisement), so a session planned with it could only expire: the
    /// callers refuse it instead of running it.
    pub(crate) fn any(self) -> bool {
        self.network || self.ble
    }

    /// The sentence to refuse with, or `None` when a transport can be used.
    ///
    /// This is the one place the decision and the wording meet, so a caller
    /// cannot refuse for this reason and report something else.
    pub(crate) fn refusal(self) -> Option<&'static str> {
        (!self.any()).then_some(NO_TRANSPORT_AVAILABLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate and the rule are the same decision, and the cause is one sentence.
    ///
    /// The defect this catches: `refusal` drifting from `any` when the rule is
    /// refined (say, a transport that only counts at runtime) — a caller using
    /// `refusal` then reports "no transport" for a configuration that has one and
    /// refuses a working attempt, or starts one that nothing can reach.
    #[test]
    fn the_refusal_is_reported_only_when_no_transport_can_be_used() {
        for network in [false, true] {
            for ble in [false, true] {
                let transports = EnabledTransports::new(network, ble);
                assert_eq!(
                    transports.refusal().is_some(),
                    !transports.any(),
                    "the refusal gate and `any` disagree for network={network}, ble={ble}"
                );
                if !transports.any() {
                    assert_eq!(
                        transports.refusal(),
                        Some("All transports (BLE and Local Network) are disabled"),
                        "the refusal both callers report must keep its wording"
                    );
                }
            }
        }
    }
}
