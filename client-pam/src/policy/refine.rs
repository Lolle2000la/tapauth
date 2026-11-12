//! The config-dependent second decision phase: the half of R1 that reads
//! `pam_refused_services`, which can only ever add a skip.

use crate::context::ServiceName;

use super::{Classification, SkipPolicy};

/// Whether an already-participating call's service is one of the *configured*
/// refused names.
///
/// R1 runs before the config read by design, so it can only see the built-ins;
/// this is the matcher for the names a deployment added to
/// `pam_refused_services`. The match is ASCII case-insensitive, like R1's, and
/// an empty entry matches nothing — which keeps a raw slice from matching a
/// `None`/empty service, since malformed entries are already dropped by
/// `PamConfig::effective_refused_services`.
pub(super) fn refused_service(service: Option<&ServiceName>, configured: &[String]) -> bool {
    service.is_some_and(|service| {
        configured
            .iter()
            .any(|name| !name.is_empty() && service.eq_ignore_ascii_case(name))
    })
}

/// The second decision phase: what the config read can add to `classify`.
///
/// It may only add a skip — a participating call whose service is configured
/// becomes [`Classification::Skip`] with R1's own [`SkipPolicy::RemoteAuthentication`]
/// — and never remove or reclassify one, move a mechanism or change a
/// [`Deadline`](crate::plan::Deadline), which is derived from the conversation it
/// passes through unchanged. `refinement_cannot_change_a_participation` pins
/// all three clauses.
pub(crate) fn refine(
    classification: Classification,
    service: Option<&ServiceName>,
    configured: &[String],
) -> Classification {
    match classification {
        skip @ Classification::Skip(_) => skip,
        participate @ Classification::Participate(_) => {
            if refused_service(service, configured) {
                Classification::Skip(SkipPolicy::RemoteAuthentication)
            } else {
                participate
            }
        }
    }
}
