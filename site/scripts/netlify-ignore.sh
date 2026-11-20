#!/usr/bin/env bash
# Netlify "ignore" command (netlify.toml): exit code 0 skips the build, any other code builds.
#
# The website is built only when something it is made of changed since the last deployed commit:
# site/, docs/ (rendered under /doku), the agent API document shown at /api, and netlify.toml.
# A push that only touches the gateway, the dashboards or the tests deploys nothing.
#
# When in doubt it builds: no earlier deploy, an unknown commit (shallow clone) or a git error.
set -u
cd "$(git rev-parse --show-toplevel)" || exit 1
from="${CACHED_COMMIT_REF:-}"
to="${COMMIT_REF:-HEAD}"
if [ -z "$from" ] || [ "$from" = "$to" ] || ! git cat-file -e "$from^{commit}" 2>/dev/null; then
  echo "netlify-ignore: no earlier deployed commit to compare with, building"
  exit 1
fi
if git diff --quiet "$from" "$to" -- site docs contract/agentapi/openapi.json netlify.toml; then
  echo "netlify-ignore: nothing of the website changed between $from and $to, skipping the build"
  exit 0
fi
echo "netlify-ignore: the website changed, building"
exit 1
