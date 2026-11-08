//! The config-dependent second decision phase.
//!
//! `classify` decides from the caller facts alone, before the config exists, so
//! R1 can only see the built-in refused names. This module is what the config
//! read can add to that: a participating call whose service a deployment
//! declared in `pam_refused_services` gets R1's verdict. It may only ever add a
//! skip.

use crate::context::ServiceName;

use super::{Classification, SkipPolicy};

/// Whether an already-participating call's service is one of the *configured*
/// refused names.
///
/// R1 runs before the config read by design, so it can only see the built-ins.
/// This is the matcher behind the second half of the same refusal, for the names
/// a deployment added to `pam_refused_services` (a renamed `PAMServiceName`):
/// [`refine`] calls it once the config is in hand, still before the username
/// lookup, conversation, messages and transaction.
///
/// The match is ASCII case-insensitive, like R1's, and an entry that is empty
/// matches nothing — an unresolved service never matches either. Malformed
/// entries are already dropped by `PamConfig::effective_refused_services`; the
/// empty-name guard keeps a raw slice from matching a `None`/empty service.
///
/// `pub(super)` because the policy's own tests pin this table; no other module
/// can reach it, which is what keeps the configured half of R1 unsplittable.
pub(super) fn refused_service(service: Option<&ServiceName>, configured: &[String]) -> bool {
    service.is_some_and(|service| {
        configured
            .iter()
            .any(|name| !name.is_empty() && service.eq_ignore_ascii_case(name))
    })
}

/// The second decision phase: what the config read can add to `classify`.
///
/// `classify` decides from the caller facts alone, before the config exists, so
/// R1 can only see the built-in refused names. A deployment that renames
/// OpenSSH's `PAMServiceName` arrives here as a participating call, and this
/// gives that call R1's verdict. It is the *whole* of the second phase:
/// `orchestrate` calls it exactly once, immediately after the config read and
/// before the username lookup, the conversation, the messages and the
/// transaction.
///
/// The invariant is one-directional, and the body is its strongest encoding:
///
/// * it may **add** a skip — a participating call whose service is one of the
///   configured names becomes [`Classification::Skip`] with R1's own
///   [`SkipPolicy::RemoteAuthentication`];
/// * it may not remove or reclassify one: a [`Classification::Skip`] is handed
///   back untouched, before the configured list is even consulted for it;
/// * it may not change a participating call's mechanism or deadline: the
///   [`Participation`](super::Participation) is moved back out unchanged, and
///   [`Deadline`](crate::plan::Deadline) is derived from that conversation, so
///   the only value this function ever constructs is a `Skip`.
///
/// `refinement_cannot_change_a_participation` walks the whole corpus through
/// both phases with three configs and pins all three clauses.
pub(crate) fn refine(
    classification: Classification,
    service: Option<&ServiceName>,
    configured: &[String],
) -> Classification {
    match classification {
        // A skip stays a skip, unchanged: this phase only ever adds one.
        skip @ Classification::Skip(_) => skip,
        // The participation is handed back exactly as it arrived unless the
        // configured list refuses the service. The refused arm builds a skip,
        // never a `Participation`, so the mechanism cannot move.
        participate @ Classification::Participate(_) => {
            if refused_service(service, configured) {
                Classification::Skip(SkipPolicy::RemoteAuthentication)
            } else {
                participate
            }
        }
    }
}
