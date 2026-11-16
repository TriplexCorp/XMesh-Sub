#!/usr/bin/env bash
# Disposable container integration test: generated Caddy routes + real Unix limiter.
# Runs only in CI, never on a production VPS.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
[[ $# == 1 && -s "$1/Caddyfile" ]] || { echo 'Missing generated Caddyfile' >&2; exit 1; }
source_caddyfile=$1/Caddyfile
temp=$(mktemp -d)
# Disposable non-secret fixtures must be traversable by container uid 65534.
# The socket itself remains under a uid-65534 owned, mode-0770 subdirectory.
chmod 0755 "$temp"
limiter_name="xmesh-edge-limiter-$"
caddy_name="xmesh-edge-caddy-$"
socket_volume="xmesh-edge-socket-$"
cleanup() {
  docker rm -f "$caddy_name" "$limiter_name" >/dev/null 2>&1 || true
  docker volume rm -f "$socket_volume" >/dev/null 2>&1 || true
  rm -rf "$temp"
}
trap cleanup EXIT

mkdir -p "$temp/policy"
# A Docker-managed volume is genuinely shared by sibling containers even
# when the CI runner and the Docker daemon use separate mount namespaces.
docker volume create "$socket_volume" >/dev/null
docker run --rm --user 0 --entrypoint sh \
  -v "$socket_volume:/run/xmesh-sub" \
  xmesh-sub-caddy:2.11.9-josev4r1 \
  -c 'chown 65534:65534 /run/xmesh-sub && chmod 0770 /run/xmesh-sub'
printf '%s\n' '{"enabled":true,"mode":"protect","ipPerMinute":1}' > "$temp/policy/config.json"
chmod 0644 "$temp/policy/config.json"

# Keep exact generated subscriber matcher, forward_auth and sanitization,
# replacing ONLY the TLS site address and first panel upstream for local CI.
python3 - "$source_caddyfile" "$temp/Caddyfile" <<'PY'
from pathlib import Path
import sys
raw=Path(sys.argv[1]).read_text()
upstream='''    reverse_proxy https://panel.example.org {
      header_up Host panel.example.org
      header_up -Authorization
      header_up -Cookie
    }'''
if raw.count(upstream)!=2 or raw.count('sub.example.org {')!=1:
    raise SystemExit('Unexpected production Caddy routing; cannot safely stub upstream')
if 'forward_auth unix//run/xmesh-sub/rate.sock {' not in raw:
    raise SystemExit('Production Caddyfile has lost the Unix-socket enforcement')
patched=raw.replace('sub.example.org {','http://:8080 {',1).replace(
    upstream,'    respond "allowed" 200',1)
if patched.count('forward_auth unix//run/xmesh-sub/rate.sock {')!=1:
    raise SystemExit('CI must preserve exact forward_auth rule')
Path(sys.argv[2]).write_text(patched)
PY

docker run -d --name "$limiter_name" --network none \
  --user 65534:65534 --read-only --tmpfs /tmp \
  --security-opt no-new-privileges --cap-drop ALL \
  -v "$socket_volume:/run/xmesh-sub" \
  -v "$temp/policy:/etc/xmesh-sub/policy:ro" \
  -v "$PWD/limiter.py:/opt/limiter.py:ro" \
  xmesh-sub-limiter:3.12.16-krb5r1 python3 -I /opt/limiter.py >/dev/null
for ((attempt=0; attempt<60; attempt++)); do
  docker exec "$limiter_name" test -S /run/xmesh-sub/rate.sock >/dev/null 2>&1 && break
  sleep 0.2
done
if ! docker exec "$limiter_name" test -S /run/xmesh-sub/rate.sock >/dev/null 2>&1; then
  echo 'Limiter socket failed to appear; diagnostic container status and logs:' >&2
  docker inspect --format '{{.State.Status}} {{.State.ExitCode}} {{.State.Error}}' "$limiter_name" >&2 || true
  docker logs "$limiter_name" >&2 || true
  echo 'Inspect container process, bind mounts and socket:' >&2
  docker inspect --format '{{json .Mounts}} {{json .Config.Cmd}} {{json .Config.Entrypoint}}' "$limiter_name" >&2 || true
  docker exec "$limiter_name" sh -c 'id; ls -ld /run/xmesh-sub /etc/xmesh-sub/policy; ls -al /run/xmesh-sub; ps aux' >&2 || true
  echo 'Fixture permissions:' >&2
  stat -c '%a %u:%g %n' "$temp" "$temp/policy" "$temp/policy/config.json" >&2 || true
  exit 1
fi

docker run -d --name "$caddy_name" --network bridge \
  --security-opt no-new-privileges \
  -p '127.0.0.1::8080' \
  -v "$temp/Caddyfile:/etc/caddy/Caddyfile:ro" \
  -v "$socket_volume:/run/xmesh-sub:ro" \
  xmesh-sub-caddy:2.11.9-josev4r1 caddy run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null

address=$(docker port "$caddy_name" 8080/tcp | head -n 1)
[[ "$address" =~ ^127[.]0[.]0[.]1:[0-9]+$ ]] || { echo 'Unexpected local-only Caddy binding' >&2; exit 1; }
base="http://$address"
for ((attempt=0; attempt<60; attempt++)); do
  [[ $(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$base/healthz") == 200 ]] && break
  sleep 0.2
done
status() {
  curl -sS -o /dev/null -w '%{http_code}' --max-time 6 "$@"
}
[[ $(status "$base/healthz") == 200 ]] || { echo 'Health endpoint not reachable' >&2; exit 1; }
[[ $(status "$base/api/admin") == 404 ]] || { echo 'Admin path leaked through subscription ingress' >&2; exit 1; }
[[ $(status "$base/s/not-a-token") == 404 ]] || { echo 'Invalid subscription route was accepted' >&2; exit 1; }
token=$(printf 'a%.0s' {1..64})
route="$base/s/$token"
[[ $(status "$route") == 200 ]] || { echo 'First allowed subscription request failed' >&2; exit 1; }
[[ $(status -H 'X-Forwarded-For: 198.51.100.4' "$route") == 429 ]] ||
  { echo 'Client spoofed XFF to bypass direct-peer rate limit' >&2; exit 1; }
[[ $(status -H 'X-XMesh-Peer-IP: 198.51.100.55' "$route") == 429 ]] ||
  { echo 'Client spoofed internal peer-IP header to bypass rate limit' >&2; exit 1; }
echo 'Verified: Caddy routes, private Unix gate and spoof-resistant per-peer HTTP 429'
