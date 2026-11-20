#!/usr/bin/env bash
# Pre-commit leak guard: blocks staged changes that would publish internal content.
#   1. no staged path under docs/internal/ (or docs/intern/)
#   2. no added line containing a term from docs/internal/denylist.txt (one term per line, # comments)
#   3. gitleaks on the staged changes, if installed
#   4. no OpenPGP secret key in a staged key file (scripts/key-guard.sh)
# Bypass only after checking by hand: git commit --no-verify
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
fail=0

if git diff --cached --name-only --diff-filter=ACMRT | grep -E '^docs/intern(al)?/' >/dev/null; then
  echo "leak-guard: staged files under docs/internal/ must not be committed to this repo:" >&2
  git diff --cached --name-only --diff-filter=ACMRT | grep -E '^docs/intern(al)?/' >&2
  fail=1
fi

denylist="$root/docs/internal/denylist.txt"
if [ -f "$denylist" ]; then
  added="$(git diff --cached -U0 --no-color | grep -E '^\+' | grep -vE '^\+\+\+ ' || true)"
  while IFS= read -r term; do
    term="${term%%#*}"
    term="$(printf '%s' "$term" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [ -z "$term" ] && continue
    if printf '%s\n' "$added" | grep -iF -- "$term" >/dev/null; then
      echo "leak-guard: an added line contains a term from docs/internal/denylist.txt" >&2
      fail=1
    fi
  done < "$denylist"
fi

if command -v gitleaks >/dev/null 2>&1; then
  if ! gitleaks protect --staged --redact --no-banner >/dev/null 2>&1; then
    echo "leak-guard: gitleaks found a possible secret (run: gitleaks protect --staged -v)" >&2
    fail=1
  fi
fi

if ! "$root/scripts/key-guard.sh" --staged; then
  fail=1
fi

exit "$fail"
