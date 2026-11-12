#!/usr/bin/env bash
# Guard: every context the merge-queue ruleset requires must still match a job
# `name:` in one of the CI workflows.
#
# Renaming a required job is otherwise silent. The ruleset keeps waiting for a
# check name that nothing reports, so the required check never leaves `Pending`
# and every queued entry stalls until `check_response_timeout_minutes` expires.
#
# No third-party dependencies: python3 stdlib parses the JSON, grep -F does the
# match. Runs in milliseconds.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ruleset_rel='scripts/ci/merge-queue-ruleset.json'
ruleset="$repo_root/$ruleset_rel"
workflows=(
  "$repo_root/.github/workflows/ci.yml"
  "$repo_root/.github/workflows/ci-android.yml"
)

for f in "$ruleset" "${workflows[@]}"; do
  if [[ ! -r $f ]]; then
    echo "error: cannot read $f" >&2
    exit 2
  fi
done

contexts_out="$(python3 - "$ruleset" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    payload = json.load(fh)

for rule in payload.get("rules", []):
    if rule.get("type") != "required_status_checks":
        continue
    for check in rule.get("parameters", {}).get("required_status_checks", []):
        print(check["context"])
PY
)"

mapfile -t contexts <<<"$contexts_out"

if ((${#contexts[@]} == 0)) || [[ -z ${contexts[0]} ]]; then
  echo "error: $ruleset_rel declares no required_status_checks contexts" >&2
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
      echo "error: required check '$context' (from $ruleset_rel) matches no job"
      echo "       \`name:\` in .github/workflows/ci.yml or .github/workflows/ci-android.yml."
      echo "       Fix by restoring that job name, or by removing the context from"
      echo "       $ruleset_rel."
      echo "       A required check that nothing reports stays Pending forever, so every"
      echo "       merge-queue entry stalls until check_response_timeout_minutes expires."
    } >&2
  fi
done

exit "$missing"
