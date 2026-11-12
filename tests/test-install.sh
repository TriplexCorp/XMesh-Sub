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
# A real HTML portal needs its exact CSS/JS files; all other paths remain 404.
grep -Fq 'path /subscription-studio.css /subscription-surface.css /subscription-public.css /qr-code.js /subscription-experience.js /subscription-traffic.js /subscription-portal.js' <<< "$out"
grep -Fq 'handle @portal_assets {' <<< "$out"
# Ensure only one explicit public static allowlist, not a blanket /js/* or /*.
if grep -Eq 'path /\*|path /js/\*|path /styles/\*' <<< "$out"; then
  echo 'ERROR: portal static allowlist is too broad' >&2
  exit 1
fi
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
token=$(printf 'a%.0s' {1..64})
managed=$(printf '%s\n' "$token" | bash install.sh --panel https://panel.example.org --domain sub.example.org --path /s --enroll-token-stdin --dry-run)
grep -Fq 'forward_auth xmesh-sub-flood:8080' <<< "$managed"
grep -Fq 'header_up X-XMesh-Peer {remote_host}' <<< "$managed"
grep -Fq 'header_up -X-Forwarded-For' <<< "$managed"
grep -Fq 'user: "65534:65534"' <<< "$managed"
grep -Fq 'flood_guard.py:/app/flood_guard.py:ro' <<< "$managed"
if grep -Eq '(^|[[:space:]])- "[0-9]+:8080' <<< "$managed"; then
  echo 'ERROR: flood shield management port must never be exposed' >&2; exit 1
fi
if bash install.sh --panel https://panel.example.org --domain sub.example.org --path /s --enroll-token "$token" --dry-run >/dev/null 2>&1; then
  echo 'ERROR: enrollment tokens must never be accepted in argv' >&2; exit 1
fi
if printf '%s\n' invalid | bash install.sh --panel https://panel.example.org --domain sub.example.org --path /s --enroll-token-stdin --dry-run >/dev/null 2>&1; then
  echo 'ERROR: malformed stdin enrollment token was accepted' >&2; exit 1
fi
grep -Fq 'openssl pkeyutl -verify' install.sh
grep -Fq 'release.json.sig' install.sh
grep -Fq 'ProtectKernelModules=true' install.sh
grep -Fq 'NoNewPrivileges=true' install.sh
grep -Fq 'xmesh-sub-manager.service' install.sh
grep -Fq '/api/v1/sub-server/claim' install.sh
grep -Fq 'SKIP_MANAGER_RESTART' install.sh
echo 'Installer validation tests passed'
