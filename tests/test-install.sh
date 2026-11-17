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
grep -Fq 'forward_auth unix//run/xmesh-sub/rate.sock' <<< "$out"
grep -Fq 'header_up X-XMesh-Peer-IP {remote_host}' <<< "$out"
grep -Fq 'header_up -*' <<< "$out"
grep -Fq 'header_up -X-Forwarded-Uri' <<< "$out"
grep -Fq 'header_up -Authorization' <<< "$out"
grep -Fq 'header_up -Cookie' <<< "$out"
grep -Fq 'xmesh-sub-limiter:' <<< "$out"
# Even first-install dry-run receives a deterministic test-only revision.
test_sha=0000000000000000000000000000000000000000
grep -Fq "image: xmesh-sub-caddy:rev-$test_sha" <<< "$out"
grep -Fq "image: xmesh-sub-limiter:rev-$test_sha" <<< "$out"
# Distinct signed revisions must have distinct image names, and placeholders
# must never survive into a runnable Compose file.
another_sha=1111111111111111111111111111111111111111
out_alt=$(bash install.sh --panel https://panel.example.org --domain sub.example.org --path /s --release-sha "$another_sha" --dry-run)
grep -Fq "image: xmesh-sub-caddy:rev-$another_sha" <<< "$out_alt"
grep -Fq "image: xmesh-sub-limiter:rev-$another_sha" <<< "$out_alt"
if grep -Fq "@CADDY_IMAGE@" <<< "$out_alt" || grep -Fq "@LIMITER_IMAGE@" <<< "$out_alt"; then
  echo "ERROR: unresolved image names in installer output" >&2; exit 1
fi
grep -Fq 'dockerfile: Dockerfile.limiter' <<< "$out"
grep -Fq 'pull_policy: never' <<< "$out"
grep -Fq 'FROM python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89' <<< "$out"
grep -Fq 'RUN apk --no-cache upgrade krb5-libs' <<< "$out"
grep -Fq 'dockerfile: Dockerfile.caddy' <<< "$out"
grep -Fq 'FROM caddy:2.11.9-builder-alpine@sha256:646fee578e680989ca5c7fd1ce6f1de574d19fd71ef2221810cc0510a9f40c86 AS builder' <<< "$out"
grep -Fq 'RUN xcaddy build v2.11.9' <<< "$out"
grep -Fq 'github.com/smallstep/certificates@v0.30.3-0.20261105213751-6d5a251fbe01' <<< "$out"
grep -Fq 'go.step.sm/crypto@v0.92.0' <<< "$out"
grep -Fq 'golang.org/x/net@v0.62.0' <<< "$out"
grep -Fq 'FROM caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0' <<< "$out"
# The production installer must not overwrite old mutable local image tags.
# shellcheck disable=SC2016 # Literal installer source assertion, not interpolation.
grep -Fq 'docker image inspect "$limiter_image"' install.sh
# shellcheck disable=SC2016
grep -Fq 'docker image inspect "$caddy_image"' install.sh
if grep -Eq '^    image: (caddy:2|python:3[.]12-alpine)$' <<< "$out"; then
  echo 'ERROR: floating legacy image in signed installer' >&2
  exit 1
fi
grep -Fq './run:/run/xmesh-sub:ro' <<< "$out"
# The signed installer embeds the exact, audited limiter source, no unsigned
# source fetch or module download is permitted on the Sub VPS.
tmp_limiter=$(mktemp)
trap 'rm -f "$tmp_limiter"' EXIT
sed -n '/^# limiter.py$/,$p' <<< "$out" | sed '1d' >"$tmp_limiter"
cmp -s limiter.py "$tmp_limiter" || { echo 'ERROR: signed installer limiter differs from source' >&2; exit 1; }
# The standard proxy must retain origin subscription metadata, including
# profile-web-page-url and support-url. The personal webpage points to the
# same allowlisted /s/{token} route with ?view=portal.
# Caddy reverse_proxy forwards query parameters and upstream response headers
# by default. Do not introduce response-header stripping or URI rewriting.
if grep -Eq 'header_down|uri strip_prefix|rewrite \*|header -profile-web-page-url|header -support-url' <<< "$out"; then
  echo 'ERROR: gateway must not strip subscription profile metadata' >&2
  exit 1
fi
grep -Fq 'Referrer-Policy "no-referrer"' <<< "$out"
grep -Fq 'Cache-Control "private, no-store"' <<< "$out"
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
printf '%s\n' "$token" | bash install.sh --panel https://panel.example.org --domain sub.example.org --path /s --enroll-token-stdin --dry-run >/dev/null
if bash install.sh --panel https://panel.example.org --domain sub.example.org --path /s --enroll-token "$token" --dry-run >/dev/null 2>&1; then
  echo 'ERROR: enrollment tokens must never be accepted in argv' >&2; exit 1
fi
if printf '%s\n' invalid | bash install.sh --panel https://panel.example.org --domain sub.example.org --path /s --enroll-token-stdin --dry-run >/dev/null 2>&1; then
  echo 'ERROR: malformed stdin enrollment token was accepted' >&2; exit 1
fi
grep -Fq 'gh attestation verify' install.sh
# shellcheck disable=SC2016  # literal source-code assertion, not expansion
grep -Fq -- '--source-digest "$RELEASE_SHA"' install.sh
grep -Fq -- '--cert-identity' install.sh
grep -Fq 'release_verify.py' install.sh
grep -Fq 'Refusing release downgrade' install.sh
if grep -Fq 'release.json.sig' install.sh || grep -Fq 'signed_release(' manager.py; then
  echo 'ERROR: legacy offline-manifest release authentication is still enabled' >&2
  exit 1
fi
# No script may execute at root without an exact attested source commit.
grep -Fq 'Use the automatically attested installer command from Nexus' install.sh
grep -Fq 'ProtectKernelModules=true' install.sh
grep -Fq 'NoNewPrivileges=true' install.sh
grep -Fq 'xmesh-sub-manager.service' install.sh
grep -Fq 'manager.read_config(root / "manager.json")' install.sh
grep -Fq '/api/v1/sub-server/claim' install.sh
grep -Fq '"publicKey": public_key' install.sh
grep -Fq 'agent-key.pem' install.sh
if grep -Fq 'agentToken' install.sh || grep -Fq 'agentToken' manager.py; then
  echo 'ERROR: legacy bearer authentication must be removed' >&2; exit 1
fi
grep -Fq 'SKIP_MANAGER_RESTART' install.sh
# The embedded limiter must EXACTLY match the reviewed standalone source.
python3 - <<'PY'
from pathlib import Path
source=Path('install.sh').read_text().split("  cat <<'XMESH_LIMITER_SOURCE'\n",1)[1].split("\nXMESH_LIMITER_SOURCE",1)[0]
assert source.rstrip('\n')+'\n' == Path('limiter.py').read_text(), 'Limiter embedded in installer differs from tested source'
PY
echo 'Installer validation tests passed'
