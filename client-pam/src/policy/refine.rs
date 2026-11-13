//! The config-dependent second decision phase: the half of `remote_refuse` that
//! reads `pam_refused_services`, which can only ever add a skip.

use crate::context::ServiceName;

use super::{Classification, SkipPolicy};

/// Whether an already-participating call's service is one of the *configured*
/// refused names.
///
/// `remote_refuse` runs before the config read by design, so it can only see the
/// built-ins; this matches the names a deployment added to
/// `pam_refused_services`, ASCII case-insensitively like `remote_refuse`. An empty
/// entry matches nothing, so a raw slice cannot match a `None`/empty service even
/// though `effective_refused_services` already drops malformed entries.
pub(super) fn refused_service(service: Option<&ServiceName>, configured: &[String]) -> bool {
    service.is_some_and(|service| {
        configured
            .iter()
            .any(|name| !name.is_empty() && service.eq_ignore_ascii_case(name))
    })
}

/// The second decision phase: what the config read can add to `classify`.
///
/// It may only add a skip — a configured service becomes
/// [`Classification::Skip`] with `remote_refuse`'s own
/// [`SkipPolicy::RemoteAuthentication`] — never remove or reclassify one,
/// move a mechanism or change a [`Deadline`](crate::plan::Deadline), which
/// follows from the conversation it passes through unchanged.
/// `refinement_cannot_change_a_participation` pins all three clauses.
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
