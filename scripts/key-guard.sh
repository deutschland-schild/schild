#!/usr/bin/env bash
# Refuses OpenPGP secret keys in the repository. The apt repository is signed
# with a key whose public part is checked in
# (gateway/deploy/release/apt/archive-key.asc); the secret part exists as a
# secret of the release workflow only. A wrong export into that file, or a
# backup left in the checkout, must never be committed.
#
#   scripts/key-guard.sh --staged    the files staged for a commit (pre-commit, via leak-guard.sh)
#   scripts/key-guard.sh --tracked   every tracked file (CI)
#
# It looks at files named like a key (.asc, .gpg, .pgp, .key, .sec) and finds
# an armored secret key, a binary one (gitleaks sees only the armored form)
# and, with gpg installed, anything gpg reads as a secret key.
set -euo pipefail

mode=${1:?usage: key-guard.sh --staged|--tracked}
root=$(git rev-parse --show-toplevel)
cd "$root"
archive_key=gateway/deploy/release/apt/archive-key.asc

case "$mode" in
--staged)
  list() { git diff --cached --name-only -z --diff-filter=ACMRT; }
  content() { git show ":$1"; }
  ;;
--tracked)
  list() { git ls-files -z; }
  content() { cat -- "$1"; }
  ;;
*)
  echo "usage: key-guard.sh --staged|--tracked" >&2
  exit 1
  ;;
esac

# gpg wants a home directory it can write to; nothing of the user's is read.
gpg_home=$(mktemp -d)
trap 'rm -rf "$gpg_home"' EXIT
show_keys() { gpg --batch --no-options --homedir "$gpg_home" --show-keys --with-colons 2>/dev/null || true; }

fail=0
refuse() {
  echo "key-guard: $1: $2" >&2
  fail=1
}

while IFS= read -r -d '' file; do
  case "$file" in
  *.asc | *.gpg | *.pgp | *.key | *.sec) ;;
  *) continue ;;
  esac
  [ "$mode" = --staged ] || [ -f "$file" ] || continue

  if content "$file" | grep -a -q -e '-----BEGIN PGP PRIVATE KEY BLOCK-----'; then
    refuse "$file" "an armored OpenPGP secret key"
    continue
  fi
  # A binary secret key starts with a secret-key packet: tag 5 in the old
  # (0x94 to 0x97) or the new (0xc5) packet format.
  first=$(content "$file" | head -c 1 | od -An -tx1 | tr -d ' \n')
  case "$first" in
  94 | 95 | 96 | 97 | c5)
    refuse "$file" "a binary OpenPGP secret key"
    continue
    ;;
  esac
  if command -v gpg >/dev/null 2>&1; then
    if content "$file" | show_keys | grep -q -E '^(sec|ssb):'; then
      refuse "$file" "gpg reads it as a secret key"
      continue
    fi
    if [ "$file" = "$archive_key" ] && ! content "$file" | show_keys | grep -q '^pub:'; then
      refuse "$file" "not a public key"
    fi
  fi
done < <(list)

exit "$fail"
