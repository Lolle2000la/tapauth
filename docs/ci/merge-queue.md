# GitHub Merge Queue

`main` is protected by the ruleset `16779046` (`name: main`); the merge queue is a
rule inside it, not a separate repository setting. The payload that adds it lives in
[`scripts/ci/merge-queue-ruleset.json`](../../scripts/ci/merge-queue-ruleset.json) and
is **not applied by CI** — someone with admin rights applies it by hand, in the order
described under [Rollout](#rollout-order).

## What the queue requires

Seven checks must be reported for a merge group before it can merge. They are the
job `name:` strings of `.github/workflows/ci.yml` and `.github/workflows/ci-android.yml`:

| Workflow | Required check |
| :--- | :--- |
| `ci.yml` | `Code Quality & Format Checks` |
| `ci.yml` | `Production Build Override Scan` |
| `ci.yml` | `Build and Test Workspace Modules` |
| `ci-android.yml` | `Build Android Native Libraries and APKs` |
| `ci-android.yml` | `Build Ubuntu Debian Package (.deb)` |
| `ci-android.yml` | `Build Fedora RPM Package (.rpm)` |
| `ci-android.yml` | `Build Arch Linux Package (.pkg.tar.zst)` |

Each entry carries `integration_id: 15368` (the GitHub Actions app), so a check with
the same name posted by anything else does not satisfy the rule.

`e2e` (`Real-Android E2E Tests (Ubuntu, Fedora, Arch)`) is deliberately **not**
required. It depends on all four Android build jobs, so it adds no independent
signal that a failure in one of them would not already give, and its suite is the
most expensive thing in CI (emulator, virtual Bluetooth kernel module, three distro
containers). `ci-android.yml` therefore skips it for queue entries with a job-level
guard:

```yaml
  e2e:
    name: Real-Android E2E Tests (Ubuntu, Fedora, Arch)
    needs: [build-android, build-pkg-ubuntu, build-pkg-fedora, build-pkg-arch]
    # Not a required check, so skip it on merge-queue entries: …
    if: github.event_name != 'merge_group'
```

The PR's own `pull_request` run still executes `e2e`, so the coverage is not lost —
it just is not repeated for every queued group.

## `merge_group` triggers

Both CI workflows additionally listen for the merge-group event, scoped to `main`:

```yaml
  merge_group:
    types: [checks_requested]
    branches: [main]
```

Without this trigger, nothing reports the required checks on the merge-group SHA and
the first queued entry stalls until `check_response_timeout_minutes` expires. Release
workflows are intentionally left alone: they are event-gated on tags/releases and
must not run for a merge group.

### Path-filter caveat

`push` and `pull_request` in both workflows filter on `paths:`. `merge_group` supports
**no** path filters (GitHub does not offer them for that event), and that is not a gap
to work around:

- a PR that touches nothing in either `paths:` list reports no CI checks on its head
  SHA at all (a docs-only PR, for example);
- the required checks are satisfied on the **merge-group SHA**, which always runs the
  full workflow set because `merge_group` is unfiltered.

So a PR may be mergeable with zero checks on its head and still be fully validated
by the queue. Do not "fix" this by adding `paths:` to `merge_group` (impossible) or by
adding an aggregate gate job (the seven names are required individually).

## Rollout order

**The workflow changes must be merged to `main` before the ruleset is applied.**
Merge-group runs use the workflow files from the merge group's base commit; if the
`merge_group` triggers are not on `main` yet, the first queued entry receives no
checks and stalls until the timeout. Order:

1. Merge the workflow change (`merge_group` triggers + the `e2e` guard).
2. Confirm it is on `main`.
3. Apply the ruleset payload.

## Applying the payload

```sh
gh api --method PUT repos/Lolle2000la/tapauth/rulesets/16779046 \
  --input scripts/ci/merge-queue-ruleset.json
```

The file is the complete body for the update, built from the live ruleset: it keeps
`name`, `target`, `enforcement: active`, `bypass_actors`, `conditions.ref_name`
(`~DEFAULT_BRANCH`), and the four existing rules (`deletion`, `required_linear_history`,
`pull_request` — including `require_extra_approval_for_unattributed_changes: true` and
`allowed_merge_methods: [squash]` — and `non_fast_forward`) verbatim, then adds
`required_status_checks` and `merge_queue`.

### Queue parameters

| Parameter | Value | Why |
| :--- | :--- | :--- |
| `merge_method` | `SQUASH` | The `pull_request` rule already allows squash only. |
| `grouping_strategy` | `ALLGREEN` | Every PR in a group must pass the full check set, so a bad entry cannot ride on the head's green. |
| `max_entries_to_build` | `5` | A Rust workspace build plus the Android native build and three package builds is the slowest sequence; five concurrent entries keeps runners from starving the PR jobs. |
| `max_entries_to_merge` | `5` | Matches the build cap, so a full group is never built and then split. |
| `min_entries_to_merge` | `1` | Merge a lone PR immediately; no batching requirement. |
| `min_entries_to_merge_wait_minutes` | `5` | Only meaningful above a minimum of 1; left short so it never delays a single entry. |
| `check_response_timeout_minutes` | `60` | Comfortably above the slowest job's wall time, and a failure to report inside an hour is worth treating as a failure. |
| `strict_required_status_checks_policy` | `false` | The queue already validates each group against the latest `main`; requiring branches to be up to date would only force needless rebases. |
| `do_not_enforce_on_create` | `false` | The ruleset targets one existing default branch; there is no branch creation to exempt. |

## Verifying after applying

```sh
# 1. The ruleset now carries both new rules, with the seven contexts.
gh api repos/Lolle2000la/tapauth/rulesets/16779046 \
  --jq '.rules[] | select(.type == "merge_queue" or .type == "required_status_checks")'

# 2. The queue is enabled on main (a PR shows "Merge when ready" instead of a plain merge).
gh pr view <number> --repo Lolle2000la/tapauth

# 3. The first queued entry produced a merge_group run reporting all seven names.
gh run list --repo Lolle2000la/tapauth --event merge_group --limit 5
```

Step 3 is the real test: the seven check names must appear on the merge-group SHA and
`Real-Android E2E Tests (Ubuntu, Fedora, Arch)` must not.

## Rolling back

Drop the `merge_queue` rule from the live ruleset — either by editing
`scripts/ci/merge-queue-ruleset.json`, deleting the `{"type": "merge_queue", …}` object,
and re-running the `PUT` above, or in the UI at
`https://github.com/Lolle2000la/tapauth/rules/16779046`.

Removing `required_status_checks` (or setting its `enforcement_level`/rule back to
"off" by deleting the rule) is the fallback if the required names turn out to be wrong
— that alone unblocks merges without the queue. Keeping the `merge_group` triggers in
the workflows after a rollback is harmless: nothing references those runs until the
rule comes back.
