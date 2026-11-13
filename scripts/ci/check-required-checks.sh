#!/usr/bin/env bash
# Guard: every required status-check context must still match a job `name:` in
# one of the CI workflows.
#
# This list is the canonical record of which checks the merge-queue ruleset
# requires. The ruleset itself is configured in GitHub (ruleset `16779046`, name
# `main`), so it cannot be read from the repository: keep this array in step with
# the ruleset and with the job `name:` values in `.github/workflows/ci.yml` and
# `.github/workflows/ci-android.yml` whenever either side changes.
#
# Renaming a required job is otherwise silent. The ruleset keeps waiting for a
# check name that nothing reports, so the required check never leaves `Pending`
# and every queued entry stalls until `check_response_timeout_minutes` expires.
#
# No third-party dependencies: bash arrays and grep -F. Runs in milliseconds.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
workflows=(
  "$repo_root/.github/workflows/ci.yml"
  "$repo_root/.github/workflows/ci-android.yml"
)

# Exactly the eight contexts the ruleset requires, in ruleset order.
contexts=(
  'Code Quality & Format Checks'
  'Production Build Override Scan'
  'Build and Test Workspace Modules'
  'Build Android Native Libraries and APKs'
  'Build Ubuntu Debian Package (.deb)'
  'Build Fedora RPM Package (.rpm)'
  'Build Arch Linux Package (.pkg.tar.zst)'
  'Real-Android E2E Tests (Ubuntu, Fedora, Arch)'
)

for f in "${workflows[@]}"; do
  if [[ ! -r $f ]]; then
    echo "error: cannot read $f" >&2
    exit 2
  fi
done

if ((${#contexts[@]} == 0)); then
  echo "error: this script declares no required status-check contexts" >&2
  exit 1
fi

missing=0
for context in "${contexts[@]}"; do
  found=false
  for wf in "${workflows[@]}"; do
    # A job-level `name:` is indented four spaces (jobs themselves two); step
    # names are deeper, so the anchored match cannot be satisfied by a step.
    if grep -qxF -- "    name: $context" "$wf"; then
      found=true
      break
    fi
  done
  if [[ $found == false ]]; then
    missing=1
    {
      echo "error: required check '$context' matches no job \`name:\` in"
      echo "       .github/workflows/ci.yml or .github/workflows/ci-android.yml."
      echo "       Fix by restoring that job name, or by updating the contexts array"
      echo "       in scripts/ci/check-required-checks.sh and the live ruleset 16779046."
      echo "       A required check that nothing reports stays Pending forever, so every"
      echo "       merge-queue entry stalls until check_response_timeout_minutes expires."
    } >&2
  fi
done

exit "$missing"
