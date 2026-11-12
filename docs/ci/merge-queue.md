# GitHub Merge Queue

`main` is protected by the ruleset `16779046` (`name: main`); the merge queue is a
rule inside it, not a separate repository setting. The payload that *would* make
`main` require the queue lives in
[`scripts/ci/merge-queue-ruleset.json`](../../scripts/ci/merge-queue-ruleset.json) and
is **never applied by CI** — an admin applies it by hand, in the order described under
[Rollout](#rollout-order). Until that happens `main` has no merge queue and the eight
contexts below are not required.

## The rule this design follows

`required_status_checks` gates **every PR's head SHA**, not only the merge-group SHA.
A required workflow therefore **cannot** be path-filtered: when a `paths:` filter
skips the run, nothing posts the required check, it stays `Pending` forever, and the
PR can be neither merged directly nor added to the queue. GitHub's troubleshooting
guide states it plainly — *"You should not use path or branch filtering to skip
workflow runs if the workflow is required to pass before merging"*.

An earlier revision of this document got this backwards: it assumed a PR whose filtered
workflow never ran could still be merged and would be validated by the queue instead.
That is wrong in both directions — the PR is not mergeable (its required checks never
report) and nothing validates it. **Filtering and requiring are mutually exclusive for
the same workflow.**

One related fact, because it is easy to trip over: a job skipped by a job-level `if:`
does **not** vanish from the checks list — it reports a check run with conclusion
**Success**. That makes `if:`-skipping useless as a way to avoid expensive required
work: it buys nothing except a green check that verified nothing. So no job below is
skipped on any trigger.

## Required checks — eight, from both workflows

| Workflow | Required check (job `name:`) |
| :--- | :--- |
| `ci.yml` | `Code Quality & Format Checks` |
| `ci.yml` | `Production Build Override Scan` |
| `ci.yml` | `Build and Test Workspace Modules` |
| `ci-android.yml` | `Build Android Native Libraries and APKs` |
| `ci-android.yml` | `Build Ubuntu Debian Package (.deb)` |
| `ci-android.yml` | `Build Fedora RPM Package (.rpm)` |
| `ci-android.yml` | `Build Arch Linux Package (.pkg.tar.zst)` |
| `ci-android.yml` | `Real-Android E2E Tests (Ubuntu, Fedora, Arch)` |

Each entry carries `integration_id: 15368` (the GitHub Actions app), so a check with
the same name posted by anything else does not satisfy the rule.

`scripts/ci/check-required-checks.sh` (run as a step in `Code Quality & Format Checks`,
and runnable locally as `bash scripts/ci/check-required-checks.sh`) reads these eight
contexts out of the payload and asserts each one still matches a job `name:` in
`ci.yml` or `ci-android.yml`. Renaming a required job is otherwise silent: nothing
reports the new name, so every queued entry waits out `check_response_timeout_minutes`.

### Trigger shape: filtered `push`, unfiltered `pull_request`

Because every job in both workflows is a required check:

- **`pull_request:` has no `paths:` key in either workflow.** Every PR targeting
  `main` runs all eight jobs, so the checks the PR needs are always reported. This
  includes docs-only PRs — that is the price of the jobs being required, and the
  alternative is a PR that can never merge.
- **`push:` keeps its `paths:` filters exactly as before.** This is a deliberate
  choice, not an oversight: the pull request and the merge group have already
  validated the change, so a third, unfiltered post-merge run of the Android matrix
  and the emulator suite is pure cost. The filtered `push` run stays as a safety net
  for pushes that bypass the queue (direct pushes, or a `bypass_actors` merge).

The asymmetry is safe precisely because `push` checks are not required: nothing waits
for them.

### E2E is required

`Real-Android E2E Tests (Ubuntu, Fedora, Arch)` is a required check. It therefore runs
on **every pull request** and on **every merge-group entry**; a PR cannot even be
queued until its own eight checks — including a full E2E pass across Ubuntu, Fedora and
Arch in systemd mode — are green. The `e2e` job has no job-level `if:` guard, and must
not grow one: a guarded required job would report Success without running the suite.

The two operational consequences, stated without softening:

- **E2E flakiness now blocks merges.** Before the queue, a flaky E2E run cost a red PR
  that a reviewer could overrule; now it costs a PR that cannot enter the queue, and a
  flake inside a group fails the whole group under `ALLGREEN`. If that becomes
  untenable, the lever is **removing the single `Real-Android E2E Tests (Ubuntu,
  Fedora, Arch)` context from the payload** — no workflow change is needed for that,
  and the job keeps running as an advisory PR signal.
- **Queue latency per entry is dominated by E2E.** E2E depends on all four Android
  build/package jobs (`needs: [build-android, build-pkg-ubuntu, build-pkg-fedora,
  build-pkg-arch]`), so an entry's wall time is the Android matrix plus the emulator
  suite. No job in the repository sets `timeout-minutes`, so
  `check_response_timeout_minutes` is the **only** thing that turns a hung E2E into a
  failure instead of an indefinite wait.

## `merge_group` triggers

Both workflows listen for the merge-group event, scoped to `main`:

```yaml
  merge_group:
    types: [checks_requested]
    branches: [main]
```

Without these triggers nothing reports the eight required checks on the merge-group
SHA and the first queued entry stalls until `check_response_timeout_minutes` expires.
The event supports no `paths:` filter (GitHub offers none), which is fine here because
neither workflow filters `merge_group`.

Release workflows are intentionally left alone: they are event-gated on tags/releases
and must not run for a merge group.

## Rollout order

**The workflow changes must be merged to `main` before the ruleset is applied.**
Merge-group runs use the workflow files from the merge group's base commit; if the
`merge_group` triggers and the unfiltered `pull_request` triggers are not on `main`
yet, the first queued entry receives no checks and stalls until the timeout. Order:

1. Merge the workflow change (both `merge_group` triggers, `paths:` removed from both
   `pull_request:` blocks, the guard script).
2. Confirm it is on `main` (`git log origin/main -- .github/workflows/`).
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
`allowed_merge_methods: [squash]` — and `non_fast_forward`) verbatim, then sets
`required_status_checks` to the eight contexts above and adds `merge_queue`.

### Queue parameters

| Parameter | Value | Why |
| :--- | :--- | :--- |
| `merge_method` | `SQUASH` | The `pull_request` rule already allows squash only. |
| `grouping_strategy` | `ALLGREEN` | Every PR in a group must pass the full check set, so a bad entry cannot ride on the head's green. |
| `max_entries_to_build` | `3` | E2E is now in the required set, and it spawns an emulator plus three systemd containers per workspace. Three concurrent groups keeps runner pressure survivable and multiplies flake exposure less than five; on a repo with this PR volume the throughput cost is negligible. |
| `max_entries_to_merge` | `3` | Matches the build cap, so a full group is never built and then split. |
| `min_entries_to_merge` | `1` | Merge a lone PR immediately; no batching requirement. |
| `min_entries_to_merge_wait_minutes` | `5` | Only meaningful above a minimum of 1; left short so it never delays a single entry. |
| `check_response_timeout_minutes` | `120` | Must comfortably exceed Android matrix + E2E wall time (E2E alone runs three distros in systemd mode in one session). GitHub's maximum is 360. Since no job sets `timeout-minutes`, this is the only bound on a hung E2E: too low fails healthy entries, too high parks a broken one for hours. 120 minutes is the compromise. |
| `strict_required_status_checks_policy` | `false` | The queue already validates each group against the latest `main`; requiring branches to be up to date would only force needless rebases. |
| `do_not_enforce_on_create` | `false` | The ruleset targets one existing default branch; there is no branch creation to exempt. |

## Verifying after applying

```sh
# 1. Both new rules are present in the live ruleset.
gh api repos/Lolle2000la/tapauth/rulesets/16779046 \
  --jq '.rules[] | select(.type == "merge_queue" or .type == "required_status_checks")'

# 2. Exactly the eight contexts are required.
gh api repos/Lolle2000la/tapauth/rulesets/16779046 \
  --jq '[.rules[] | select(.type == "required_status_checks")
         | .parameters.required_status_checks[].context]'

# 3. The queue is enabled on main (a PR shows "Merge when ready" instead of a plain merge).
gh pr view <number> --repo Lolle2000la/tapauth

# 4. The first queued entry produced merge_group runs reporting all eight names.
gh run list --repo Lolle2000la/tapauth --event merge_group --limit 5

# 5. The payload and the workflows still agree (also a CI step).
bash scripts/ci/check-required-checks.sh
```

Step 4 is the real test: all eight names must appear on the merge-group SHA, from
*both* workflow files. If one stays `Pending`, the ruleset name and the workflow job
`name:` have drifted — which is what step 5 catches before it reaches `main`.

## Rolling back

Removing a **rule** is the lever; `enforcement` is ruleset-scoped
(`disabled` / `active` / `evaluate`) and per-rule overrides of it do not exist.

- **Turn the queue off:** delete the `{"type": "merge_queue", …}` object from
  `scripts/ci/merge-queue-ruleset.json` and re-run the `PUT` above, or remove the
  "Require merge queue" rule in the UI at
  `https://github.com/Lolle2000la/tapauth/rules/16779046`.
- **Drop one blocking check (the E2E flake lever):** delete that single context
  object from `required_status_checks.required_status_checks` and re-run the `PUT`.
  No workflow change is required; the job keeps reporting as an advisory signal.
- **Unblock merges entirely on a wrong required name:** delete the whole
  `{"type": "required_status_checks", …}` rule. That restores direct merges without
  touching the queue rule, but it also makes `scripts/ci/check-required-checks.sh`
  exit non-zero ("declares no required_status_checks contexts"), and that guard runs
  inside `Code Quality & Format Checks`. Remove the guard step in the same change, or
  that required check is red on every run from then on.
- **Blunt lever:** setting the ruleset's top-level `enforcement` to `disabled`
  switches off *every* rule at once — `deletion`, `required_linear_history`,
  `pull_request` and `non_fast_forward` included. Use it only as an emergency stop,
  not as a way to drop one check.

Keeping the `merge_group` triggers after a rollback is harmless: nothing depends on
those runs until the rule comes back.
