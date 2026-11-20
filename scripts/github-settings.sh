#!/usr/bin/env bash
# Apply the repository settings in .github/ to a GitHub repository.
# Usage: scripts/github-settings.sh OWNER/REPO [--apply]
# Without --apply it only prints the calls. Visibility is never changed.
set -euo pipefail

repo="${1:-}"
apply="${2:-}"
if [[ ! "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || [[ -n "$apply" && "$apply" != "--apply" ]]; then
  echo "usage: $0 OWNER/REPO [--apply]" >&2
  exit 2
fi

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.github" && pwd)"

call() { # METHOD PATH [JSON_FILE | -]
  local method="$1" path="$2" body="${3:-}" input
  echo "$method $path${body:+ < ${body/#$dir\//.github/}}"
  [[ "$apply" == "--apply" ]] || { [[ "$body" != "-" ]] || cat >/dev/null; return 0; }
  if [[ -n "$body" ]]; then
    input="$body"
    gh api --silent -X "$method" "$path" --input "$input"
  else
    gh api --silent -X "$method" "$path"
  fi
}

ruleset() { # FILE: create it, or update the ruleset of the same name
  local file="$1" name id
  name="$(jq -r .name "$file")"
  id="$(gh api "repos/$repo/rulesets" --jq ".[] | select(.name == \"$name\") | .id" 2>/dev/null || true)"
  if [[ "$id" =~ ^[0-9]+$ ]]; then
    call PUT "repos/$repo/rulesets/$id" "$file"
  else
    call POST "repos/$repo/rulesets" "$file"
  fi
}

private="$(gh api "repos/$repo" --jq .private)"

call PATCH "repos/$repo" "$dir/repository-settings.json"
ruleset "$dir/rulesets/main.json"
ruleset "$dir/rulesets/tags.json"

call PUT "repos/$repo/actions/permissions" - <<'J'
{ "enabled": true, "allowed_actions": "selected", "sha_pinning_required": true }
J
call PUT "repos/$repo/actions/permissions/selected-actions" - <<'J'
{
  "github_owned_allowed": true,
  "verified_allowed": false,
  "patterns_allowed": ["pnpm/action-setup@*", "ossf/scorecard-action@*"]
}
J
call PUT "repos/$repo/actions/permissions/workflow" - <<'J'
{ "default_workflow_permissions": "read", "can_approve_pull_request_reviews": false }
J
call PUT "repos/$repo/vulnerability-alerts"

if [[ "$private" == "false" ]]; then
  call PUT "repos/$repo/actions/permissions/fork-pr-contributor-approval" - <<'J'
{ "approval_policy": "all_external_contributors" }
J
  call PUT "repos/$repo/private-vulnerability-reporting"
  call PATCH "repos/$repo" - <<'J'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
J
else
  echo "private repository: fork approval, vulnerability reporting and secret scanning skipped, run this again after the switch"
fi
