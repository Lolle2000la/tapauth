//! The process's 500 ms verdict-reuse record, and the one type that owns it.
//!
//! A duplicate `pam_authenticate` some lock screens issue immediately after a
//! transaction concludes is answered here instead of starting a second
//! transaction: [`record`] stores the conclusion `authenticate` just handed
//! back, and [`replay_for`] walks that record when the same `(username,
//! service)` arrives again inside [`VERDICT_REUSE_WINDOW`].
//!
//! The state is one private static ([`LAST_CONCLUSION`]) behind a
//! [`ConclusionCache`] that exposes only `lookup`, `replay_for` and `record`
//! (`record`/`replay_for` also as the module-level forwards). No other module
//! names the lock, which is what keeps a fork fix (an `atfork` reinit, an
//! atomic cell, or dropping the cache) inside one file — a source scan asserts
//! it.
//!
//! The child half of the `pthread_atfork` registration ([`reinit_cache_in_child`])
//! replaces the slot wholesale, so a forked child starts with a fresh, unlocked
//! mutex and an **empty** record. The type is this file's only write path to
//! the cell.
//!
//! [`Concluded`] and its provenance stay in `transaction`: this module records
//! and replays them, and never constructs one.

use crate::context::ServiceName;
use crate::outcome::Outcome;
use crate::transaction::{Concluded, Via};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Window during which the verdict this process just concluded may be
/// replayed instead of starting a second authentication transaction.
///
/// What it guards: a duplicate transaction some lock screens issue right after
/// a transaction concludes.  kscreenlocker ≥ 6.8 queues the duplicate
/// `Authenticate()` about a second into the first transaction — while it is
/// still running — and dispatches it the moment the first call returns,
/// whatever its outcome, because its `PamAuthenticator::promptInternal()`
/// clears the busy guard before the heartbeat's request can be observed and
/// dropped.  The real fix is the upstream busy-guard change; until then the
/// duplicate is answered here.  Without it the second call is a full
/// transaction: a new request id, a new daemon challenge, and a second ring of
/// the phone (or a second full timeout) for a single unlock.
///
/// Why replay *any* concluded code, not just `Success`: the duplicate was
/// queued while the first transaction was still running, so no user could have
/// initiated it.  Re-asking the phone about a request the user never made is
/// wrong in both directions — a success would ring twice, and a failure
/// (`PAM_AUTHINFO_UNAVAIL` for a phone timeout or an unpaired device, or
/// `PAM_PERM_DENIED`) would ring again and wait out another full timeout for a
/// question that was just answered.
///
/// Why 500 ms: the observed duplicate gap is 0.37 ms, so 500 ms absorbs
/// scheduling jitter on a loaded host, while a human re-lock or a second login
/// as the same user takes seconds — no human-initiated retry can fall inside
/// the window, which is what keeps a genuine second attempt from being
/// answered by a cached failure.
///
/// Where the window starts: at this module's **return**.  `authenticate` records
/// the conclusion only after `orchestrate` has handed it back, so the 500 ms
/// runs from the end of the `pam_authenticate` call, not from the moment the
/// transaction concluded.  That is what matches the host behaviour it exists
/// for (the duplicate is dispatched the instant the first call returns), but it
/// also bounds the suppression: a module *after* `pam_tapauth.so` in the same
/// stack that blocks for longer than 500 ms pushes the host's duplicate outside
/// the window, and that duplicate rings the phone again.  Suppression is a
/// heuristic for a host that re-enters immediately, not a guarantee that a
/// second `pam_authenticate` in the same process is always answered locally.
const VERDICT_REUSE_WINDOW: Duration = Duration::from_millis(500);

/// The conclusion this process recorded last, with the user and service it
/// belongs to.
///
/// Process-wide because the duplicate transaction comes from the same host
/// process.  Keyed on `(username, service)` because the duplicate is the same
/// user against the same PAM service, so a different user *or* a different
/// service takes the normal path and rings the phone.  The remaining assumption
/// is that no legitimate host performs an *independent* authentication for the
/// same user and service within 500 ms of a concluded one: the key cannot tell
/// such a request apart from a duplicate.  A new process always misses, because
/// `pam_end` unloads the module and the cache dies with it.
struct LastConclusion {
    concluded_at: Instant,
    username: String,
    service: String,
    outcome: Outcome,
}

/// The lock that guards the last conclusion of this process, replayed for
/// [`VERDICT_REUSE_WINDOW`] only.
///
/// `std::sync::Mutex` is const-constructible on stable, so no lazy initializer
/// (and no `once_cell`) is needed.  The lock is an optimisation, never a
/// credential: a poisoned lock is ignored rather than fatal, so losing the
/// cache only costs one duplicate request.
///
/// The mutex sits in an [`UnsafeCell`] because a forked child has to replace it
/// wholesale: a `Mutex` a parent thread held at `fork(2)` time is permanently
/// locked in the child, since its owner does not exist there. The only write is
/// the child-side `pthread_atfork` handler, which runs when the process is
/// single-threaded again, so no reader can race it. Every other access goes
/// through the mutex itself.
///
/// The static is private to this module and is named by no other file:
/// [`record`] and [`replay_for`] are the only way to reach the record, which is
/// what keeps this representation inside the type.
struct CacheSlot {
    /// The record under its lock, replaced (never mutated through the cell) only
    /// by [`reinit_cache_in_child`].
    slot: UnsafeCell<Mutex<Option<LastConclusion>>>,
    /// Whether [`reinit_cache_in_child`] is registered for this process.
    ///
    /// A plain atomic, deliberately not a `std::sync::Once`: a `fork` taken
    /// while a sibling thread sits between `pthread_atfork` returning and the
    /// `Once` storing `COMPLETE` leaves the child's `Once` in `RUNNING` forever,
    /// so the child's first cache access would block — reintroducing the very
    /// deadlock the atfork handler exists to remove. Loading and storing an
    /// atomic never blocks. Two threads that both read [`NOT_REGISTERED`] may
    /// register the handler twice; that is harmless (the child half may run
    /// twice and replace the slot twice).
    registered: AtomicU8,
}

/// The registration states of [`CacheSlot::registered`].
const NOT_REGISTERED: u8 = 0;
const REGISTERED: u8 = 1;
/// A failed registration: remembered so the failure is logged once per process
/// rather than on every cache access, and so the cache keeps working (only the
/// fork hazard is lost).
const REGISTRATION_FAILED: u8 = 2;

// SAFETY: the `UnsafeCell` is only written by `reinit_cache_in_child`, which
// runs in a forked child where this process has exactly one thread and so no
// shared reference can exist. In the parent the cell is only ever read, and
// every read either locks the `Mutex` or hands out a `&Mutex` whose own
// synchronisation is unchanged. Neither the cell nor the record is ever sent
// between threads.
unsafe impl Sync for CacheSlot {}

impl CacheSlot {
    const fn new() -> Self {
        CacheSlot {
            slot: UnsafeCell::new(Mutex::new(None)),
            registered: AtomicU8::new(NOT_REGISTERED),
        }
    }

    /// Read the record under the lock, if the lock is not poisoned.
    ///
    /// A poisoned lock yields `None`: the cache is an optimisation, so ignoring
    /// it is always a correct answer. The guard is never named here, let alone
    /// handed out — this module may lock the slot, no one else may reach it.
    fn with_read<R>(&self, f: impl FnOnce(&Option<LastConclusion>) -> R) -> Option<R> {
        self.install_atfork_handler();
        // SAFETY: no write can happen while a shared reference is live (see the
        // `Sync` impl above).
        let mutex = unsafe { &*self.slot.get() };
        let guard = mutex.lock().ok()?;
        Some(f(&guard))
    }

    /// Replace the record under the lock, if the lock is not poisoned.
    fn with_write<R>(&self, f: impl FnOnce(&mut Option<LastConclusion>) -> R) -> Option<R> {
        self.install_atfork_handler();
        // SAFETY: as `with_read`.
        let mutex = unsafe { &*self.slot.get() };
        let mut guard = mutex.lock().ok()?;
        Some(f(&mut guard))
    }
}

/// The process's one slot. The static is the only state `CACHE` owns.
static LAST_CONCLUSION: CacheSlot = CacheSlot::new();

/// The child half of the `pthread_atfork` registration.
///
/// A fork taken while another thread holds `LAST_CONCLUSION` leaves the child
/// owning a mutex whose holder does not exist there, so the child's first
/// `pam_authenticate` would block until its host kills it. This overwrites the
/// slot with a fresh, unlocked mutex. The child is single-threaded at this
/// point (the kernel has copied only the forking thread), so there is no
/// competing reader to synchronise with, and no lock can be taken here: the
/// handler must stay async-signal-safe.
///
/// The child also starts with an **empty** record. A forked child is a new
/// process, and the module's contract is that a new process always misses
/// (`pam_end` unloads the module and the cache dies with it); inheriting a
/// parent grant would answer an authentication the child never performed, and
/// one extra ring of the phone is the cheaper error. So the record is cleared,
/// not preserved.
///
/// The replaced `Option` is leaked rather than dropped: dropping it would free
/// the record's strings on a copy of heap state the parent is still using.
extern "C" fn reinit_cache_in_child() {
    // SAFETY: see the comment above and the `Sync` impl on `CacheSlot`. Writing
    // through the cell is sound because the child has one thread and no live
    // shared reference to the slot.
    unsafe {
        std::ptr::write(LAST_CONCLUSION.slot.get(), Mutex::new(None));
    }
    // The atfork handler list is inherited by the child, so a future fork in
    // the child re-runs this handler. Recording the registration here keeps the
    // child from calling `pthread_atfork` again on its first cache access.
    LAST_CONCLUSION
        .registered
        .store(REGISTERED, Ordering::Release);
}

impl CacheSlot {
    /// Register [`reinit_cache_in_child`] if this process has not done so yet.
    ///
    /// Called before every lock, so the handler is installed before this
    /// process can hold the lock across a fork. It is a non-blocking load, not
    /// a `std::sync::Once`: a `fork` taken while a sibling thread is inside
    /// `pthread_atfork` (between the call returning and the flag being stored)
    /// copies that `Once` in its `RUNNING` state, and the child's first cache
    /// access would then wait forever — the defect this whole mechanism exists
    /// to remove, in a narrower window.
    ///
    /// `pthread_atfork` is **not** in POSIX's async-signal-safe table, so two
    /// residuals remain, and they are documented rather than claimed
    /// impossible:
    ///
    /// * a fork taken while another thread is inside `pthread_atfork` itself
    ///   copies the libc's internal atfork lock; the child's own registration
    ///   attempt could then block on it;
    /// * a child that forks before this module's first cache access ran
    ///   (`registered` still false in the parent) registers lazily on that
    ///   first access; on a libc whose child-side `malloc` is not fork-safe
    ///   (musl), that allocation is itself unsafe if the parent was mid-`malloc`
    ///   at the fork.
    ///
    /// A failed registration is logged once and remembered in
    /// [`REGISTRATION_FAILED`], so the cache keeps working and later accesses
    /// do not retry (or re-log) a call the process already knows fails. Only
    /// the fork hazard is lost.
    fn install_atfork_handler(&self) {
        if self.registered.load(Ordering::Acquire) != NOT_REGISTERED {
            return;
        }
        let res = unsafe { libc::pthread_atfork(None, None, Some(reinit_cache_in_child)) };
        if res == 0 {
            self.registered.store(REGISTERED, Ordering::Release);
        } else {
            self.registered
                .store(REGISTRATION_FAILED, Ordering::Release);
            let err = std::io::Error::from_raw_os_error(res);
            tracing::warn!("pthread_atfork registration failed: {err}");
        }
    }
}

/// The 500 ms reuse record and its lock, owned by exactly one type.
///
/// The type is zero-sized: the state is the private static above. It exists so
/// the record has an owner to hang `lookup` and `record` on, and so no other
/// module can name the lock — `mechanism/*`, `Plan` and `Outcome` cannot touch
/// it, and `pam_logic` reaches it through [`record`] and [`replay_for`] only.
pub(crate) struct ConclusionCache {
    /// No state of its own; the record lives in `LAST_CONCLUSION`.
    _private: (),
}

/// The process's one cache. Zero-sized; the state is `LAST_CONCLUSION`.
const CACHE: ConclusionCache = ConclusionCache { _private: () };

/// Whether `prev` may be replayed for `username` against `service` at `now` —
/// any code, not just a success.
///
/// Pure so the window can be tested without touching the process-wide cache.
/// `Instant` is `CLOCK_MONOTONIC` and never steps backwards, so the subtraction
/// can only be unavailable when the recorded instant came from another clock
/// origin (or is a later `Instant` constructed in a test); saturating reads
/// that as "no time passed" instead of panicking.
fn reusable_conclusion(
    prev: &LastConclusion,
    username: &str,
    service: &str,
    now: Instant,
) -> Option<Outcome> {
    if prev.username == username
        && prev.service == service
        && now.saturating_duration_since(prev.concluded_at) < VERDICT_REUSE_WINDOW
    {
        return Some(prev.outcome.clone());
    }
    None
}

/// The replayable record inside `slot` at `now`, with its age.
///
/// The age is the distance from the recorded instant to `now` — i.e. measured
/// from this module's return, which is where `authenticate` records it.
fn recorded_in(
    slot: &Option<LastConclusion>,
    username: &str,
    service: &str,
    now: Instant,
) -> Option<(Outcome, Duration)> {
    slot.as_ref().and_then(|prev| {
        reusable_conclusion(prev, username, service, now)
            .map(|outcome| (outcome, now.saturating_duration_since(prev.concluded_at)))
    })
}

impl ConclusionCache {
    /// The cached verdict for `(username, service)` at `now`, together with how
    /// long ago it was recorded, if it may be replayed.
    ///
    /// A poisoned lock returns `None`: the cache is an optimisation, so
    /// ignoring it is always a correct answer.
    fn lookup(&self, username: &str, service: &str, now: Instant) -> Option<(Outcome, Duration)> {
        LAST_CONCLUSION
            .with_read(|slot| recorded_in(slot, username, service, now))
            .flatten()
    }

    /// The cache hit for `(username, service)` as a conclusion that must not be
    /// recorded.
    ///
    /// The hit log lives here rather than at the call site: it is the cache's
    /// own event, and it carries the age the record knows.
    fn replay_for(&self, username: &str, service: &str, now: Instant) -> Option<Concluded> {
        let (recorded, age) = self.lookup(username, service, now)?;
        tracing::debug!(
            username = %username,
            service = %service,
            outcome = ?recorded,
            age_ms = age.as_millis(),
            "Replaying the concluded verdict for a duplicate transaction"
        );
        Some(Concluded::replay(
            recorded,
            username.into(),
            ServiceName::new(service),
        ))
    }

    /// Remember `concluded` as this process's last conclusion, and hand its
    /// verdict back.
    ///
    /// The token is taken **by value**, so one conclusion cannot be recorded
    /// twice, and both existing gates are inside: a conclusion whose service
    /// never resolved records nothing (it would collapse unrelated services
    /// into the empty key), and a [`Via::Replay`] one records nothing (that
    /// would refresh the timestamp and turn the fixed window into a sliding
    /// one). It is the *last* conclusion, so a non-success verdict overwrites an
    /// earlier success: a later denial must invalidate the cached grant, never
    /// sit behind it. The record holds the `Outcome`, not a code, so a replay
    /// cannot re-enter the code path.
    ///
    /// `at` is the moment the module returned to the host, which is the anchor
    /// of [`VERDICT_REUSE_WINDOW`] — not the moment the transaction concluded.
    fn record(&self, concluded: Concluded, at: Instant) -> Outcome {
        let (outcome, username, service, via) = concluded.into_parts();
        if via == Via::Daemon {
            if let Some(service) = service {
                LAST_CONCLUSION.with_write(|slot| {
                    *slot = Some(LastConclusion {
                        concluded_at: at,
                        username,
                        service: service.original().to_owned(),
                        outcome: outcome.clone(),
                    });
                });
            }
        }
        outcome
    }

    /// Today's test seam, kept so the poisoned-lock test can poison its own
    /// mutex instead of the process-wide one: a poisoned lock is a miss, not a
    /// panic.
    #[cfg(test)]
    fn lookup_in(
        lock: &Mutex<Option<LastConclusion>>,
        username: &str,
        service: &str,
        now: Instant,
    ) -> Option<(Outcome, Duration)> {
        let Ok(guard) = lock.lock() else {
            return None;
        };
        recorded_in(&guard, username, service, now)
    }
}

/// Record `concluded` as this process's last conclusion and hand its verdict
/// back — the only way to write the reuse record.
pub(crate) fn record(concluded: Concluded, at: Instant) -> Outcome {
    CACHE.record(concluded, at)
}

/// This process's replayable conclusion for `(username, service)` at `now` —
/// the only way to read the reuse record.
pub(crate) fn replay_for(username: &str, service: &str, now: Instant) -> Option<Concluded> {
    CACHE.replay_for(username, service, now)
}

/// Serialises the tests that drive the process-wide reuse slot from a record to
/// a lookup.
///
/// The record is one slot for the whole process, so two tests that each record
/// and then look up would otherwise overwrite each other between the two steps
/// and read a miss. It lives here, beside the slot it serialises, and it is
/// `#[cfg(test)]` code — the source scan that keeps the lock local exempts it
/// explicitly.
#[cfg(test)]
pub(crate) static CACHE_SLOT_LOCK: Mutex<()> = Mutex::new(());

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
pub(crate) mod tests {
    use super::*;
    use crate::transaction::tests::record_conclusion;
    use std::sync::atomic::AtomicBool;

    /// The serialising guard over [`CACHE_SLOT_LOCK`], for every test that
    /// drives the one process-wide record.
    pub(crate) fn take_slot() -> std::sync::MutexGuard<'static, ()> {
        CACHE_SLOT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The record is keyed on the service name's original bytes, so `sudo` and
    /// `SUDO` are different keys.
    ///
    /// The defect this catches: keying on an ASCII-lowercased service, which
    /// would let a conclusion recorded for `sudo` answer a `SUDO` stack —
    /// the corpus's `service_case_*` rows only prove that `classify` sees both
    /// spellings alike, not that the cache keeps them apart.
    #[test]
    fn reuse_key_is_case_sensitive() {
        let _slot = take_slot();
        let user = "case-key-user";
        let now = Instant::now();

        record_conclusion(user, "sudo", Outcome::granted_from_daemon(), now);
        assert!(
            replay_for(user, "sudo", now).is_some(),
            "the recorded spelling must hit"
        );
        assert!(
            replay_for(user, "SUDO", now).is_none(),
            "`SUDO` is a different key: folding the service would answer another \
             stack from this process's record"
        );

        // And the other direction, so neither spelling is privileged.
        record_conclusion(user, "KScreenLocker", Outcome::granted_from_daemon(), now);
        assert!(replay_for(user, "KScreenLocker", now).is_some());
        assert!(
            replay_for(user, "kscreenlocker", now).is_none(),
            "a case-folded key would answer the lowercase spelling from the \
             mixed-case entry"
        );
    }

    /// A poisoned lock reads as a cache miss.
    ///
    /// Moved here from `pam_logic::tests::reuse` when the record did: its
    /// seam (`lookup_in`, which takes the lock as a parameter) is private to the
    /// cache's module, so the test follows it. Same scenario, same assertion.
    ///
    /// The defect this catches: a poisoned lock unwrapped or panicked on, or
    /// read as a hit — either way a `PAM_SUCCESS` that is otherwise inside the
    /// window would be returned after another thread panicked.
    #[test]
    fn a_poisoned_lock_reads_as_a_cache_miss() {
        let local: Mutex<Option<LastConclusion>> = Mutex::new(Some(LastConclusion {
            concluded_at: Instant::now(),
            username: "alice".to_owned(),
            service: "tapauth-test".to_owned(),
            outcome: Outcome::granted_from_daemon(),
        }));

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = local.lock().expect("a fresh mutex is not poisoned");
            panic!("poison the local lock while holding it");
        }));
        assert!(
            poisoned.is_err(),
            "the helper closure was supposed to panic"
        );

        assert_eq!(
            ConclusionCache::lookup_in(&local, "alice", "tapauth-test", Instant::now()),
            None,
            "a poisoned lock must read as a cache miss: a `PAM_SUCCESS` that is \
             otherwise inside the window must not be returned, and the path must \
             not unwrap or panic"
        );
    }

    /// The cache survives a fork taken while another thread holds its lock, and
    /// the child starts with an empty record.
    ///
    /// The defect this catches (D4): without a registered `pthread_atfork`
    /// handler, a fork taken while another thread holds the lock leaves the
    /// child blocked forever on its first `pam_authenticate` — the lock's owner
    /// does not exist there — and, even with a reinitialised lock, a child that
    /// kept the inherited record could replay a verdict this process reached
    /// before the fork for a request the child never made. This test kills both
    /// with distinct exit codes: `SIGALRM` (a blocked child is killed by its own
    /// 5-second alarm), and `3` for an inherited record — it is visible to
    /// `lookup`, and to `replay_for`, which delegates to `lookup`. Only an
    /// unlocked slot and an empty record exit `0`.
    ///
    /// The cache is driven through its real API (`ConclusionCache::lookup` /
    /// `replay_for`) in the child, under the module's own lock, so the test
    /// exercises the atfork reinit rather than a copy of it.
    ///
    /// Platform assumption: glibc. `fork` runs the registered atfork handlers
    /// and `std::sync::Mutex` is the glibc futex mutex; no musl target is built
    /// in CI, so this gate is the whole story today.
    #[test]
    fn conclusion_cache_survives_fork() {
        // The cache is one process-wide slot, so serialise with every other
        // test that drives it. The child does not touch `CACHE_SLOT_LOCK`, so
        // holding it across the fork is safe: the child never waits on it.
        let _slot = take_slot();
        static HELD: AtomicBool = AtomicBool::new(false);
        static RELEASE: AtomicBool = AtomicBool::new(false);

        // One fixed instant for the seed, the parent's check and the child's
        // lookup: the 500 ms window can then never age out on a loaded runner,
        // so a failure means the reinit did not happen, not that time passed.
        let now = Instant::now();
        record_conclusion(
            "alice",
            "tapauth-fork-test",
            Outcome::granted_from_daemon(),
            now,
        );
        assert!(
            CACHE.lookup("alice", "tapauth-fork-test", now).is_some(),
            "the seeded conclusion must be replayable in the parent before the fork"
        );

        let holder = std::thread::spawn(|| {
            // `with_read` registers the atfork handler before locking, so the
            // child inherits the registration as well as the held lock.
            LAST_CONCLUSION.with_read(|_| {
                HELD.store(true, Ordering::SeqCst);
                // Hold until the parent has forked: the fork must happen while
                // a thread that will not exist in the child owns the lock.
                while !RELEASE.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
            });
        });

        while !HELD.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }

        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child. Keep to what a post-fork child may safely do: an `alarm`
            // so a blocked lock cannot hang the suite, the cache's real API,
            // and `_exit` — not `exit`, so no atexit handler or Rust
            // destructor runs on the forked copy of the parent's state.
            unsafe {
                libc::alarm(5);
            }
            let inherited = CACHE.lookup("alice", "tapauth-fork-test", now);
            let replayed = CACHE.replay_for("alice", "tapauth-fork-test", now);
            // `replay_for` delegates to `lookup`, so a visible inherited record
            // exits 3 whichever of the two saw it.
            let code = if inherited.is_none() && replayed.is_none() {
                0
            } else {
                3
            };
            unsafe { libc::_exit(code) };
        }
        assert!(pid > 0, "fork failed: {}", std::io::Error::last_os_error());

        RELEASE.store(true, Ordering::SeqCst);
        holder.join().expect("the lock holder must be reaped");

        let mut status: libc::c_int = 0;
        let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(reaped, pid, "waitpid must reap the child");
        assert!(
            libc::WIFEXITED(status),
            "the child was killed by signal {} after the parent forked while \
             another thread held the cache lock: a blocked child is killed by \
             its own alarm, which is the D4 deadlock (wait status {status})",
            libc::WTERMSIG(status)
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "the child must see an unlocked cache and an empty record after the \
             fork; exit 3 means it inherited the parent's conclusion"
        );
    }
}
