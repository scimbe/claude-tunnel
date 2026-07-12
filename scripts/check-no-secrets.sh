#!/usr/bin/env sh
# Committed-secrets guard (M23.3).
#
# Scans git-tracked files for credential material and verifies that real secret
# files stay untracked. Exit 0 = clean, non-zero = a likely secret is committed
# (wire into CI / a pre-commit hook). Detects only genuine credential shapes
# (PEM private keys, cloud access-key ids, tracked .env files), so ordinary test
# payloads containing the word "secret" do not trip it.
set -eu

cd "$(cd "$(dirname "$0")/.." && pwd)"
status=0

fail() { echo "SECRET-GUARD FAIL: $1"; status=1; }

# 1. No real .env files may be tracked (only *.example templates).
env_tracked=$(git ls-files | grep -E '(^|/)\.env($|\.)' | grep -v '\.example$' || true)
if [ -n "$env_tracked" ]; then
  fail "tracked .env file(s) with real values:"
  echo "$env_tracked"
fi

# 2. .gitignore must ignore .env.
if ! git check-ignore -q docker/deploy/.env 2>/dev/null; then
  fail ".env is not gitignored"
fi

# 3. Scan tracked text files for credential material.
#    - PEM private key headers
#    - AWS-style access key ids (AKIA + 16 upper/digits)
#    - Google API keys (AIza + 35 chars)
pattern='-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}'
hits=$(git ls-files | while IFS= read -r f; do
  case "$f" in
    *.example|scripts/check-no-secrets.sh) continue ;;  # templates + this scanner
  esac
  if grep -EIlq -e "$pattern" "$f" 2>/dev/null; then echo "$f"; fi
done)
if [ -n "$hits" ]; then
  fail "credential material in tracked file(s):"
  echo "$hits"
fi

[ "$status" -eq 0 ] && echo "SECRET-GUARD OK: no committed secrets"
exit "$status"
