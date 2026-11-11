#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
fail_expected() {
  if bash install.sh "$@" --dry-run >/dev/null 2>&1; then
    printf 'ERROR: should reject %s\n' "$*" >&2
    exit 1
  fi
}
out=$(bash install.sh --panel https://panel.example.org --domain sub.example.org --path /s --dry-run)
grep -Fq 'path_regexp ^(/s|/sub|/portal)/[0-9a-f]{64}$' <<< "$out"
grep -Fq 'reverse_proxy https://panel.example.org' <<< "$out"
grep -Fq 'header_up -Cookie' <<< "$out"
grep -Fq 'read_only: true' <<< "$out"
grep -Fq 'Validation successful' <<< "$out"
# Nexus mounts its public readiness route under /api/v1. A bare /health/ready is 404.
# Literal source-code signatures (not intended for shell expansion).
# shellcheck disable=SC2016
grep -Fq '"$PANEL/api/v1/health/ready"' install.sh
# shellcheck disable=SC2016
if grep -Fq '"$PANEL/health/ready"' install.sh; then
  echo 'ERROR: installer uses the old, unmounted Nexus readiness path' >&2
  exit 1
fi
out=$(bash install.sh --panel https://panel.example.org --domain sub.example.org --path /example/vpn --email ops@example.org --dry-run)
grep -Fq 'path_regexp ^(/example/vpn|/sub|/portal)/[0-9a-f]{64}$' <<< "$out"
grep -Fq 'email ops@example.org' <<< "$out"
fail_expected --panel http://panel.example.org --domain sub.example.org --path /s
fail_expected --panel https://panel.example.org/login --domain sub.example.org --path /s
fail_expected --panel https://panel.example.org:443 --domain sub.example.org --path /s
fail_expected --panel https://127.0.0.1 --domain sub.example.org --path /s
fail_expected --panel https://panel.example.org --domain panel.example.org --path /s
fail_expected --panel https://panel.example.org --domain 'evil;curl bad' --path /s
fail_expected --panel https://panel.example.org --domain sub.example.org --path /api/admin
# Literal injection payload must not expand in the test shell.
# shellcheck disable=SC2016
fail_expected --panel https://panel.example.org --domain sub.example.org --path '/s/$(whoami)'
fail_expected --panel https://panel.example.org --domain sub.example.org --path /s/../login
fail_expected --panel https://panel.example.org --domain sub.example.org --path /s/
fail_expected --panel https://panel.example.org --domain sub.example.org --path /s --email 'ops@evil.com;rm'
echo 'Installer validation tests passed'
