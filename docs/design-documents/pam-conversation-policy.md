# PAM conversation policy

`client-pam` is a PAM service module. For one `pam_authenticate` call it either asks the paired phone for a verdict through `tapauthd`, or deliberately falls through to whatever the host's stack does next. It runs unprivileged and reaches the daemon only through its Unix-socket IPC.

## What the module is

The module is one `auth` line in a service's stack. Debian/Ubuntu ship a `pam-auth-update` profile whose only auth line is `sufficient pam_tapauth.so` (`packaging/debian.pam-config`); merged into `common-auth` it sits beside the stock modules, so a fall-through reaches `pam_unix`. The `required` shape is what the `bypass` e2e covers.

| Line | On `PAM_SUCCESS` | On any other code |
| :--- | :--- | :--- |
| `auth sufficient pam_tapauth.so` | ends the stack: the phone alone completes the login | treated as a failure; the next module runs |
| `auth required pam_tapauth.so` | one required item satisfied; later modules still run | the stack fails |

It never returns `PAM_IGNORE`: Linux-PAM records no failure for that code, so on a `required` line a later `optional pam_permit` could complete the stack. Every skip therefore returns `PAM_AUTHINFO_UNAVAIL`.

The module authenticates the stack's `PAM_USER`. On `su` that is the target account, so the line must sit after `pam_wheel.so`; otherwise a phone grant for `root` replaces the wheel check.

## Components

Six roles. **Caller classification** reads the caller's own facts — service name, process identity, GDM reauthentication flag — and decides between skipping and participating; **refinement** is the second, config-dependent pass, which can only add a remote refusal. The **plan** turns the selected flow and the terminal finding into a deadline, an announcement and a terminal policy. The **transaction** owns the request and its lifecycle: handoff, reuse lookup, arming once the request is on the wire, mechanism, conclusion, and at most one message. The three **mechanisms** are the conversation shapes, and the **outcome mapping** is the single place a verdict becomes a `PAM_*` code.

Classification calls refinement, the transaction calls the plan and then exactly one mechanism, and every path ends in the outcome mapping. The `client-pam` crate documentation says where each of these lives.

## Request lifecycle

```mermaid
sequenceDiagram
    participant Host
    participant Module
    participant Daemon
    participant Phone

    Host->>Module: pam_authenticate
    Module->>Module: capture caller context
    Module->>Module: classify
    opt skip, early exit
        Module-->>Host: PAM_AUTHINFO_UNAVAIL
    end
    Module->>Module: load config, refine
    opt configured refusal, early exit
        Module-->>Host: PAM_AUTHINFO_UNAVAIL
    end
    Module->>Module: username, conversation, messages
    opt pre-collected, early exit
        Module->>Module: pam_get_authtok
        Module-->>Host: PAM_AUTHINFO_UNAVAIL
    end
    Module->>Module: reuse lookup
    opt record hit, early exit
        Module-->>Host: recorded PAM code
    end
    Module->>Module: probe tty, plan, resolve deadline
    Module->>Daemon: connect, PamAuthenticateRequest
    Module->>Module: arm
    Daemon->>Phone: ring
    Note over Module,Daemon: the selected mechanism waits for the phone
    Daemon-->>Module: PamAuthenticateResponse
    Module->>Module: conclude, emit one notice
    Module->>Module: record, map to a PAM code
    Module-->>Host: PAM_SUCCESS, PAM_PERM_DENIED, PAM_AUTHINFO_UNAVAIL, PAM_AUTH_ERR or PAM_USER_UNKNOWN
```

An `opt` marked *early exit* returns from the call; the steps after it do not run. Within a transaction, the tty probe runs after the reuse lookup, and the request is armed only once `connect` and `send` have both succeeded.

The same path as a decision graph:

```mermaid
flowchart TD
    A[pam_authenticate] --> B[capture caller context]
    B --> C{classify}
    C -- skip --> K[PAM_AUTHINFO_UNAVAIL]
    C -- participate --> D[load config]
    D --> E{refine refuses service?}
    E -- yes --> K
    E -- no --> F[username, conversation, messages]
    F -- username lookup fails --> Z[PAM_USER_UNKNOWN]
    F -- conversation lookup fails --> Y[PAM_AUTH_ERR]
    F --> G{pre-collected?}
    G -- yes --> H[pam_get_authtok]
    H --> K
    G -- no --> I{reuse hit?}
    I -- yes --> J[replay recorded code]
    J --> R[return that code]
    I -- no --> L[probe tty, plan, resolve deadline]
    L --> N2{request id ok?}
    N2 -- no --> Y
    N2 -- yes --> M[connect and send request]
    M -- connect or send fails --> K
    M --> N[arm, run mechanism]
    N --> O[conclude]
    O --> P[record]
    P --> Q[map to a PAM code]
```

The order matters and is asserted by tests, not by the type system: classification runs before the config read, refinement runs before the username, conversation and messages, and both skips return without touching any of them.

## Flow selection

Classification walks the rule table in order; the first matching row decides. The table is data, not branch logic: each row carries a name, a failure-direction class, a predicate over the caller's facts and a decision.

| Rule | Matches | Yields | Skip code |
| :--- | :--- | :--- | :--- |
| `RemoteRefuse` | `PAM_SERVICE` is `sshd` or `sshd-session`, ASCII case-insensitive; process ignored | skip | `PAM_AUTHINFO_UNAVAIL` |
| `DmLoginBypass` | `PAM_SERVICE` is a display-manager name (see the prefix list below), unless this is a GDM reauthentication | skip | `PAM_AUTHINFO_UNAVAIL` |
| `GdmReauthWorker` | process `gdm-session-worker`, service `gdm-password` (ASCII case-insensitive), `GDM_SESSION_FOR_REAUTH` set | threaded | — |
| `PolkitAgent` | process `polkit-agent-helper-1` | threaded | — |
| `KscreenlockerWorker` | process `kscreenlocker_worker` | threaded | — |
| `Hyprlock` | process `hyprlock` | threaded | — |
| `Xsecurelock` | process `authproto_pam` | threaded | — |
| `PreCollectedLocks` | process `swaylock`, `gtklock` or `i3lock` | pre-collected | — |
| `PolkitServiceWithoutProc` | process unknown, service `polkit-1` (case-sensitive) | threaded | — |
| `DefaultSequential` | anything else | sequential | — |

The display-manager prefix list is `sddm`, `gdm`, `gdm3`, `lightdm`, `lxdm`, `slim`, `xdm`, `kdm`, `greetd`, `ly`, `nodm`, `entrance`, `plasmalogin`. A service matches a prefix when it equals it or continues with `-`, after ASCII lowercasing.

Process names are the basename of `/proc/self/exe`, falling back to `/proc/self/comm`; every process rule accepts both the full name and the 15-byte `comm` truncation (`gdm-session-wor`, `polkit-agent-he`, `kscreenlocker_w`). GDM reauthentication requires both `GDM_SESSION_FOR_REAUTH` and the `gdm-password` service — `gdm3-password` is not exempt, it takes the bypass.

`sudo` and `su` match no row: they fall to `DefaultSequential`. With a controlling terminal — the usual case — the operation deadline applies; a tty-less call (`sudo -S` fed from a pipe, a cron job, a unit) finds no `/dev/tty` and takes the clamped `pam_gui_timeout_secs` deadline.

```mermaid
flowchart TD
    A[service, process, GDM flag] --> B{remote service?}
    B -- yes --> R[skip: PAM_AUTHINFO_UNAVAIL]
    B -- no --> C{display-manager service and not GDM reauth?}
    C -- yes --> S[skip: PAM_AUTHINFO_UNAVAIL]
    C -- no --> D{gdm-session-worker, gdm-password and the GDM flag?}
    D -- yes --> T[threaded]
    D -- no --> E{polkit-agent-helper-1?}
    E -- yes --> T
    E -- no --> F{kscreenlocker_worker?}
    F -- yes --> T
    F -- no --> G{hyprlock?}
    G -- yes --> T
    G -- no --> H{authproto_pam?}
    H -- yes --> T
    H -- no --> I{swaylock, gtklock or i3lock?}
    I -- yes --> P[pre-collected]
    I -- no --> J{process unknown and service polkit-1?}
    J -- yes --> T
    J -- no --> Q[sequential]
```

Config cannot reorder or replace any of this. Refinement runs once after the config read and can only turn a participation into the `RemoteRefuse` skip for a name listed in `pam_refused_services`, compared ASCII case-insensitively as a whole string; an existing skip, a selected flow and a deadline are never changed. That second phase exists because classification sees the caller's facts only, before any config is loaded.

## The three flows

All three mechanisms end the same way: with a verdict, or with the reason no verdict was reached. They differ in which thread drives the host's conversation, if any. The rule table chooses between them before any of them runs.

### Threaded

The host's conversation stays answerable while a worker thread is blocked in it, so the password is collected off the main thread while the main thread waits for the phone.

```mermaid
sequenceDiagram
    participant Host
    participant Module
    participant Worker
    participant Daemon
    participant Phone

    Host->>Module: pam_authenticate
    Module->>Daemon: PamAuthenticateRequest
    Module->>Worker: pthread_create, pam_get_authtok
    Daemon->>Phone: ring
    Note over Worker: password dialog on the worker, the main thread polls the daemon and a self-pipe
    alt phone answers first
        Phone-->>Daemon: grant or denial
        Daemon-->>Module: PamAuthenticateResponse
        Module->>Worker: cancel and join
        Module-->>Host: PAM_SUCCESS or PAM_PERM_DENIED
    else user submits a password
        Worker->>Module: self-pipe
        Module->>Daemon: PamCancelRequest gui-password-skip
        Module-->>Host: PAM_AUTHINFO_UNAVAIL
    else dialog is dismissed or fails
        Worker->>Module: self-pipe
        Module->>Daemon: PamCancelRequest gui-password-failed
        Module-->>Host: PAM_AUTHINFO_UNAVAIL
    else deadline expires
        Module->>Worker: cancel and join
        Module-->>Host: PAM_AUTHINFO_UNAVAIL
    end
```

A response that the loop reads is the verdict; the worker is cancelled and joined before the module returns.

| | |
| :--- | :--- |
| Selected by | `GdmReauthWorker`, `PolkitAgent`, `KscreenlockerWorker`, `Hyprlock`, `Xsecurelock`, `PolkitServiceWithoutProc` |
| Threads | `pam_get_authtok` on a worker pthread; the calling thread polls the daemon fd and a self-pipe |
| Daemon sees | the request; a cancel on the live connection when a password is submitted or the dialog fails; no cancel on timeout |
| User sees | the host's password dialog and the phone prompt together; a submitted password wins over a response that becomes readable at the same moment, and otherwise the first of the two ends the wait |
| Phone never answers | `pam_operation_timeout_secs` expires, the worker is cancelled and joined, `PAM_AUTHINFO_UNAVAIL`; the module does not dismiss the host's dialog, and whatever module follows in the stack drives the next prompt |

### Sequential

The host either posts the conversation answer back to the thread that called `pam_authenticate` or parks in a wait with no cancellation point, so a threaded reply could never be abandoned. The module therefore never drives the conversation while waiting: it waits on the calling thread, then falls through to the password module.

```mermaid
sequenceDiagram
    participant Host
    participant Module
    participant Daemon
    participant Phone

    Host->>Module: pam_authenticate
    Module->>Daemon: PamAuthenticateRequest
    Note over Module: waits on the calling thread, the conversation is not driven
    Daemon->>Phone: ring
    alt phone answers
        Phone-->>Daemon: grant or denial
        Daemon-->>Module: PamAuthenticateResponse
        Module-->>Host: PAM_SUCCESS or PAM_PERM_DENIED
    else user presses Enter on /dev/tty
        Module->>Daemon: PamCancelRequest tty-skip
        Module-->>Host: PAM_AUTHINFO_UNAVAIL
    else IPC fails without a terminal
        Module->>Daemon: PamCancelRequest gui-ipc-error on a fresh connection
        Module-->>Host: PAM_AUTHINFO_UNAVAIL
    else deadline expires
        Module-->>Host: PAM_AUTHINFO_UNAVAIL
    end
```

| | |
| :--- | :--- |
| Selected by | `DefaultSequential` |
| Threads | everything on the calling thread; `pam_conv` is never touched |
| Daemon sees | the request; a cancel on terminal Enter (`tty-skip`), or without a terminal on an IPC failure (`gui-ipc-error`, sent on a fresh connection); no cancel on timeout |
| User sees | a wait notice; with a terminal, Enter skips at once; without one, nothing until the deadline or an IPC failure, then the stack's password prompt |
| Phone never answers | the deadline expires, `PAM_AUTHINFO_UNAVAIL`, and the next module prompts for a password |

The terminal and no-terminal shapes are one loop driven by a profile; the profile only decides whether an IPC failure is reported as a lost connection or as an error, and whether a poll error ends the wait.

### Pre-collected

The host read the password before calling `pam_authenticate`, and its conversation is a synchronous replay of it. The module reads that password with `pam_get_authtok` on the calling thread and returns at once.

```mermaid
sequenceDiagram
    participant Host
    participant Module

    Host->>Module: pam_authenticate
    Module->>Module: pam_get_authtok on the calling thread
    Note over Module: caches PAM_AUTHTOK for the next module, no daemon contact
    Module-->>Host: PAM_AUTHINFO_UNAVAIL
```

| | |
| :--- | :--- |
| Selected by | `PreCollectedLocks` |
| Threads | the calling thread; one `pam_get_authtok`, no IPC |
| Daemon sees | nothing |
| User sees | only the password prompt the host had already shown |
| Phone never answers | it is never rung; the call returns `PAM_AUTHINFO_UNAVAIL` immediately |

On these hosts the phone is not a credential: nothing is rung and nothing is verified, so a stack with no password module after `pam_tapauth.so` cannot unlock.

## Skips

| Skip | Returns | `sufficient` stack | `required` stack | Why it is safe |
| :--- | :--- | :--- | :--- | :--- |
| Display-manager bypass (`DmLoginBypass`) | `PAM_AUTHINFO_UNAVAIL` | next module prompts for a password | the stack fails | returns before the conversation is touched, so the login manager still populates `PAM_AUTHTOK` and the keyring unlocks |
| Remote refusal (`RemoteRefuse`) | `PAM_AUTHINFO_UNAVAIL` | the next module decides, in practice a password login | the stack fails | returns before the daemon is contacted and before any credential or conversation work, so a phone grant cannot complete a remote login |
| Pre-collected handoff (`PreCollectedLocks`) | `PAM_AUTHINFO_UNAVAIL` | the next module reads the cached `PAM_AUTHTOK` | the stack fails | `pam_get_authtok` caches the token for the next module and the daemon is never contacted, so nothing is rung or verified |

The display-manager bypass exempts a GDM reauthentication (`gdm-password` plus `GDM_SESSION_FOR_REAUTH`), because an unlock runs no session or setcred phase and the keyring reason does not apply there.

The remote refusal covers the built-in names before the config read and any `pam_refused_services` entry immediately after it. A deployment that renames the service must declare the new name.

## Timeouts and deadlines

| Flow | Terminal | Deadline | Value |
| :--- | :--- | :--- | :--- |
| Threaded | either | operation | `pam_operation_timeout_secs` (120 s) |
| Sequential | present | operation | `pam_operation_timeout_secs` (120 s) |
| Sequential | absent | gui-bounded | `pam_gui_timeout_secs` (30 s), clamped to the operation timeout |
| Pre-collected | — | none | — |

The plan picks its deadline from the flow's terminal shape and from whether a terminal was found; resolving it to seconds saturates instead of overflowing, and the transaction adds those seconds to the current instant and sends the same value to the daemon, so both sides expire together.

The clamp is the gui timeout bounded by the operation timeout and applies only to a sequential host that finds no terminal. Every sequential host attempts the probe and no threaded host does — decided from the flow alone, before any terminal is known — so a host without a terminal comes back empty, and only then does its deadline become the clamped gui-bounded one.

On expiry the mechanism ends with the reason "timed out", no cancel is sent, and the module returns `PAM_AUTHINFO_UNAVAIL` after one `timed_out` message. A timeout the daemon reports itself is a separate reason, "daemon timed out": the same code, no message.

## Return codes

| Verdict | Code | What it means to a stack author |
| :--- | :--- | :--- |
| Granted | `PAM_SUCCESS` | the phone granted this call, or this process's own grant was replayed |
| Denied | `PAM_PERM_DENIED` | the user denied on the phone |
| Unavailable | `PAM_AUTHINFO_UNAVAIL` | the module could not ask: a skip, a timeout, no daemon, no paired device, or the password handoff |
| Error | `PAM_AUTH_ERR` | the host's conversation could not be set up, request-id generation failed, the daemon answered an error or a value this build does not know, the pipe or the worker thread could not be created, or a panic was caught before it could unwind into the host |
| UserUnknown | `PAM_USER_UNKNOWN` | the username lookup failed |

Only two paths produce a grant: a success this call received from the daemon (provenance: a phone tap) and a copy of this process's own record (provenance: a verdict replay). A source scan forbids constructing one any other way.

A recorded conclusion answers a further call for the same username and the same service bytes within 500 ms, returning the recorded code without contacting the daemon. The replay is marked as a replay for a grant and for a denial alike, and is never re-recorded.

## State that outlives a call

One process-wide record exists. A call either ends with a conclusion to store or ends unrecorded.

```mermaid
flowchart TD
    A[pam_authenticate] --> B{skip or handoff?}
    B -- yes --> U[unrecorded]
    B -- no --> C{reuse hit?}
    C -- yes --> D[concluded, a replay]
    D --> J[map to a PAM code]
    C -- no --> E{connect and send succeeded?}
    E -- no --> U
    E -- yes --> F[request armed]
    F --> G[mechanism]
    G --> H[concluded, from the daemon]
    H --> I{service resolved?}
    I -- yes --> K[record]
    I -- no --> U
    K --> J
    U --> J
```

| Stored | |
| :--- | :--- |
| Username | the name this call authenticated |
| Service | the service name as libpam returned it, case preserved |
| Verdict | the whole verdict, including its provenance |
| Concluded at | the instant the module records, immediately before it returns to the host |

The key is the pair of username and service, compared with plain string equality, so `sudo` and `SUDO` are distinct services. The reuse window is 500 ms, measured from the moment the module records; the anchor is the module's return path, not the moment the phone answered.

Only a conclusion the daemon produced, whose service resolved, is stored. Skips, the pre-collected handoff, a failure before the request was sent and an unresolved service store nothing, and a replay can never overwrite the record it came from. Every call that armed a request is recorded, including the module's own timeout and a pre-answer IPC failure: the record holds the verdict, not just a grant, so a later call inside the window receives the same code without ringing the phone.

A forked child inherits neither: the `pthread_atfork` child handler writes a fresh empty record over the inherited slot, so the child starts with no conclusion and no held lock.

## Configuration that affects the conversation

| Key | Default | Effect |
| :--- | :--- | :--- |
| `pam_operation_timeout_secs` | 120 | the deadline for threaded hosts and for a sequential host with a terminal; also sent to the daemon |
| `pam_gui_timeout_secs` | 30 | the deadline for a sequential host without a terminal, clamped to the operation timeout |
| `pam_refused_services` | none beyond the built-ins | adds service names to the remote refusal |

The config is read once per call; a missing or unparsable file falls back to the defaults.

`pam_refused_services` is add-only. The effective set starts from `sshd` and `sshd-session`, trims each configured name, drops invalid entries (empty, non-ASCII, over 255 bytes, containing `/`, whitespace or control characters), deduplicates case-insensitively, and can never remove a built-in.

`use_tpm` does not affect this module: it selects key storage inside `shared`.

## Adding a host or a flow

Adding a host means one new classification rule plus the coverage that pins it: a corpus row for each process spelling the host can present, and an e2e case for a host the suite exercises. Adding a flow means a new conversation shape, a plan row for every terminal shape it can meet, and a corpus row for each host that selects it. The mechanics — which pieces to edit, and the one step nothing fails loudly on — are in the `client-pam` crate documentation, which points at the in-code checklist.

A display manager is not a new rule: it is one more entry in the display-manager prefix list plus a corpus row per prefix.

A rule's failure direction decides which conversations it may select, so choose it before writing the predicate:

| Direction | Permits | Use when |
| :--- | :--- | :--- |
| Deadlock avoidance | threaded or sequential | driving the conversation from the wrong thread would deadlock the host, so the rule picks per process |
| Always ring | threaded | the host's conversation stays answerable on a worker, and the phone is always rung |
| Never ring | pre-collected | the host read the password before calling |
| Keyring | skips only | the login manager must populate `PAM_AUTHTOK` |
| Refuse remote | skips only | a remote login must never be completed by the phone |

## Known gaps

- An undeclared service rename is not detected: `PAM_RHOST` is not read, so the call falls through to `DefaultSequential` and the phone is rung for a remote login. `svc_sshd_near_miss` pins the behaviour.
- musl is only `cargo check`ed; `pthread_atfork` and the record's mutex are unverified there.
- `cache_lookup_precedes_daemon_contact` compares source byte offsets, so it passes even when the lookup sits behind a branch that never runs. The e2e duplicate shapes are the real coverage.
- The `pthread_atfork` registration-failure branch is not exercised.
- A rule missing from both the rule table and the enumeration the table is checked against is not compile-enforced: it stays green.
- A panic between `pthread_create` and the join leaks the worker; the panic guard does not close it.
- `pthread_cancel` can deadlock a host that holds an internal libc lock. Accepted: isolating the conversation would need a helper process.
- No mechanism-level test drives a daemon-reported timeout through a sequential loop; the daemon-timeout e2e uses a threaded host.
- The host-cases suite needs root to write `/etc/pam.d`; a non-root run reports one skip per case and fails.
- Nothing asserts where the `su` line sits relative to `pam_wheel.so`.
- The Debian packaged `common-auth` stack is only string-checked; no test drives it.
- No test covers a daemon-side deduplication of two identical requests.
- The Fedora/Arch shared stack (`system-auth`, `password-auth`) is not verified to reach sshd.
- No mutation or fuzz gate covers rule ordering.
