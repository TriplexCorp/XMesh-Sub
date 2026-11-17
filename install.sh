#!/usr/bin/env bash
# XMesh Sub: independent HTTPS subscription edge, Nexus remains authority.
set -Eeuo pipefail
umask 077
ROOT=/opt/xmesh-sub
PANEL='' DOMAIN='' SUB_PATH='' EMAIL='' DRY_RUN=0 ENROLL_TOKEN='' ENROLL_STDIN=0 SKIP_MANAGER_RESTART=0 RELEASE_SHA=''
die() { printf 'XMesh Sub: ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf 'XMesh Sub: %s\n' "$*"; }
usage() {
cat <<'HELP'
Usage (Ubuntu 22.04/24.04; run on a clean VPS with DNS + ports 80/443):
  sudo bash install.sh --panel https://panel.example.org --domain sub.example.org --path /s [--email ops@example.org]
For validation only append --dry-run. Production requires --release-sha from the automatically verified Nexus command.\nFor managed installation use --enroll-token-stdin and provide the key via stdin.
HELP
}
while (($#)); do
  case "$1" in
    --panel|--domain|--path|--email)
      (($# >= 2)) || die "Missing value for $1"
      case "$1" in --panel) PANEL=$2;; --domain) DOMAIN=$2;; --path) SUB_PATH=$2;; --email) EMAIL=$2;; esac
      shift 2;;
    --enroll-token-stdin) ENROLL_STDIN=1; shift;;
    --enroll-token) die "Enrollment secrets must use --enroll-token-stdin, not process arguments";;
    --skip-manager-restart) SKIP_MANAGER_RESTART=1; shift;;
    --release-sha) (($# >= 2)) || die 'Missing release SHA'; RELEASE_SHA=$2; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "Unknown argument: $1";;
  esac
done
if ((ENROLL_STDIN)); then
  # The secret is supplied through a here-document from the panel, not argv.
  IFS= read -r ENROLL_TOKEN || die "Missing one-time enrollment token on stdin"
fi
valid_host() {
  local hostname=$1 label
  [[ ${#hostname} -le 253 && "$hostname" == *.* ]] || return 1
  [[ "$hostname" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
  [[ "$hostname" =~ \.[A-Za-z]{2,}$ ]] || return 1
  local -a labels
  IFS='.' read -r -a labels <<< "$hostname"
  for label in "${labels[@]}"; do
    [[ ${#label} -ge 1 && ${#label} -le 63 && "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
}
valid_host "$DOMAIN" || die "Invalid subscription hostname; use a fully qualified DNS name"
[[ "$PANEL" == https://* ]] || die "Panel URL must begin with https://"
PANEL_HOST=${PANEL#https://}
valid_host "$PANEL_HOST" || die "Panel must be an HTTPS hostname without port, path or credentials"
[[ "$DOMAIN" != "$PANEL_HOST" ]] || die "Panel and subscription domains must differ"
[[ ${#SUB_PATH} -ge 2 && ${#SUB_PATH} -le 64 && "$SUB_PATH" =~ ^(/[A-Za-z0-9_-]+)+$ ]] || die "Invalid subscription path"
case "$SUB_PATH" in /api|/api/*|/login|/login/*|/dashboard|/dashboard/*) die "Subscription path collides with admin routes";; esac
if [[ -n "$EMAIL" ]]; then
  [[ "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "Invalid certificate email"
fi
if [[ -n "$ENROLL_TOKEN" ]]; then
  [[ "$ENROLL_TOKEN" =~ ^[0-9a-f]{64}$ ]] || die "Invalid or expired enrollment token format"
fi

render_caddyfile() {
  if [[ -n "$EMAIL" ]]; then printf '{\n  email %s\n}\n\n' "$EMAIL"; fi
  cat <<CONF
$DOMAIN {
  @subscriptions {
    method GET HEAD
    path_regexp ^($SUB_PATH|/sub|/portal)/[0-9a-f]{64}$
  }
  handle @subscriptions {
    # Only the direct TCP peer IP from Caddy is trusted. A private Unix socket
    # is the sole access path to the policy service. Strip all client headers
    # so subscription tokens, X-Forwarded-For and cookies never reach it.
    forward_auth unix//run/xmesh-sub/rate.sock {
      uri /check
      header_up -*
      # forward_auth may otherwise add the original URI automatically.
      header_up -X-Forwarded-Uri
      header_up -X-Forwarded-Method
      header_up -X-Forwarded-For
      header_up -Authorization
      header_up -Cookie
      header_up X-XMesh-Peer-IP {remote_host}
    }
    reverse_proxy https://$PANEL_HOST {
      header_up Host $PANEL_HOST
      header_up -Authorization
      header_up -Cookie
    }
  }
  # Exact public portal assets referenced by Nexus subscription_template.html.
  # Never forward the panel's admin bundle, secrets or arbitrary paths.
  @portal_assets {
    method GET HEAD
    path /subscription-studio.css /subscription-surface.css /subscription-public.css /qr-code.js /subscription-experience.js /subscription-traffic.js /subscription-portal.js
  }
  handle @portal_assets {
    reverse_proxy https://$PANEL_HOST {
      header_up Host $PANEL_HOST
      header_up -Authorization
      header_up -Cookie
    }
  }

  handle /healthz {
    respond "ok" 200
  }
  handle {
    respond "Not Found" 404
  }
  header {
    Referrer-Policy "no-referrer"
    Cache-Control "private, no-store"
    X-Content-Type-Options "nosniff"
  }
}
CONF
}
render_limiter_dockerfile() {
  # Build once during the signed installation, not at service startup. A
  # patched Kerberos library prevents the known krb5 1.22.2-r1 CVE inventory
  # from lingering in the Python image even if upstream tags are stale.
  cat <<'DOCKER'
FROM python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
RUN apk --no-cache upgrade krb5-libs
DOCKER
}
render_caddy_dockerfile() {
  # Caddy's official binary retains x/net 0.60.0 in this exact image.
  # Rebuild Caddy using the upstream Smallstep JOSE-v4 migration and patched
  # x/net; retain stock Caddy modules, native Caddyfile syntax and ACME.
  cat <<'DOCKER'
FROM caddy:2.11.9-builder-alpine@sha256:646fee578e680989ca5c7fd1ce6f1de574d19fd71ef2221810cc0510a9f40c86 AS builder
RUN xcaddy build v2.11.9 \
    --replace github.com/smallstep/certificates=github.com/smallstep/certificates@v0.30.3-0.20261105213751-6d5a251fbe01 \
    --replace go.step.sm/crypto=go.step.sm/crypto@v0.92.0 \
    --replace golang.org/x/net=golang.org/x/net@v0.62.0
FROM caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
DOCKER
}
# Every attested revision has immutable local image names. In particular,
# the FIRST upgrade from an old manager must never overwrite the Docker tags
# required to recover the previous running configuration.
image_release_tag() {
  local sha=${RELEASE_SHA:-0000000000000000000000000000000000000000}
  [[ "$sha" =~ ^[a-f0-9]{40}$ ]] || die "Invalid immutable image release revision"
  printf 'rev-%s' "$sha"
}
sub_limiter_image() { printf 'xmesh-sub-limiter:%s' "$(image_release_tag)"; }
sub_caddy_image() { printf 'xmesh-sub-caddy:%s' "$(image_release_tag)"; }
render_compose() {
  local limiter_image caddy_image
  limiter_image=$(sub_limiter_image)
  caddy_image=$(sub_caddy_image)
  cat <<'YAML' | sed -e "s|@LIMITER_IMAGE@|$limiter_image|g" -e "s|@CADDY_IMAGE@|$caddy_image|g"
services:
  xmesh-sub-limiter:
    image: @LIMITER_IMAGE@
    build:
      context: .
      dockerfile: Dockerfile.limiter
    pull_policy: never
    restart: unless-stopped
    user: "65534:65534"
    command: ["python3", "-I", "/opt/limiter.py"]
    volumes:
      - ./limiter.py:/opt/limiter.py:ro
      - ./edge-policy:/etc/xmesh-sub/policy:ro
      - ./run:/run/xmesh-sub
    security_opt:
      - no-new-privileges:true
    cap_drop: ["ALL"]
    read_only: true
    tmpfs:
      - /tmp
    # No published ports: Caddy is the only client, via a shared Unix socket.
  xmesh-sub:
    image: @CADDY_IMAGE@
    build:
      context: .
      dockerfile: Dockerfile.caddy
    pull_policy: never
    container_name: xmesh-sub
    restart: unless-stopped
    depends_on:
      - xmesh-sub-limiter
    ports:
      - "80:80/tcp"
      - "443:443/tcp"
      - "443:443/udp"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./data:/data
      - ./config:/config
      - ./run:/run/xmesh-sub:ro
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
YAML
}
render_limiter() {
  # Embed the audited limiter in the signed installer: old managers still
  # understand the signed schema-1 installSha256/managerSha256 manifest.
  cat <<'XMESH_LIMITER_SOURCE'
#!/usr/bin/env python3
"""A private UNIX-socket authorization gate for Caddy subscription requests.

Caddy overwrites X-XMesh-Peer-IP with the *direct TCP peer* ({remote_host})
and connects to this service only through a shared Unix-domain socket.
Never accept untrusted X-Forwarded-For, or expose this service on TCP.
Request paths and subscription bearer tokens never enter this gate.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler

SOCKET_FILE = Path("/run/xmesh-sub/rate.sock")
POLICY_FILE = Path("/etc/xmesh-sub/policy/config.json")
MAX_IPS = 50_000
IDLE_SECONDS = 120
DEFAULT_LIMIT = 120


def load_policy(path: Path | None = None) -> tuple[bool, str, int]:
    path = POLICY_FILE if path is None else path
    # Broken/missing policy must never silently disable enforcement.
    # Fresh installs create a local protected policy before starting Caddy.
    with path.open("rb") as stream:
        raw = stream.read(1025)
    if len(raw) > 1024:
        raise ValueError("Oversized edge policy")
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {"enabled", "mode", "ipPerMinute"}:
        raise ValueError("Invalid edge policy")
    enabled, mode, limit = value["enabled"], value["mode"], value["ipPerMinute"]
    if type(enabled) is not bool or mode not in ("protect", "monitor") or type(limit) is not int or not 1 <= limit <= 100000:
        raise ValueError("Invalid edge policy limits")
    return enabled, mode, limit


def normalized_address(text: str) -> bytes:
    """IPv4 remains /32. IPv4-mapped IPv6 maps to IPv4; native IPv6 to /64."""
    if not text or len(text) > 64 or any(c in text for c in ("%", "/", ",", " ")):
        raise ValueError("Invalid direct peer IP")
    addr = ipaddress.ip_address(text)
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        else:
            addr = ipaddress.IPv6Network((addr, 64), strict=False).network_address
    return addr.packed


class BucketLimiter:
    """Bounded in-memory token bucket; opaque ephemeral HMAC keys, no IP logs."""

    def __init__(self, max_ips: int = MAX_IPS):
        self._lock = threading.Lock()
        self._salt = os.urandom(32)
        self._buckets: dict[bytes, tuple[float, float]] = {}
        self._max_ips = max_ips
        self._last_prune = time.monotonic()

    def allow(self, peer: str, max_per_minute: int, now: float | None = None) -> bool:
        address = normalized_address(peer)
        key = hmac.digest(self._salt, address, "sha256")
        now = time.monotonic() if now is None else now
        with self._lock:
            if now - self._last_prune >= 30:
                self._buckets = {
                    key: entry for key, entry in self._buckets.items()
                    if now - entry[1] < IDLE_SECONDS
                }
                self._last_prune = now
            previous = self._buckets.get(key)
            if previous is None:
                if len(self._buckets) >= self._max_ips:
                    # Fail closed under cardinality abuse, never unbounded RAM.
                    raise OverflowError("Too many distinct peer networks")
                tokens = float(max_per_minute)
            else:
                tokens = min(float(max_per_minute),
                             previous[0] + max(0.0, now - previous[1]) * max_per_minute / 60.0)
            allowed = tokens >= 1
            self._buckets[key] = (tokens - 1.0 if allowed else tokens, now)
            return allowed


LIMITER = BucketLimiter()


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 128
    allow_reuse_address = True
    MAX_ACTIVE_WORKERS = 64

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(self.MAX_ACTIVE_WORKERS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        # ThreadingMixIn alone creates unlimited threads under connection floods.
        # Exhaustion denies the request (Caddy returns an upstream failure),
        # never bypasses the authentication gate.
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class PolicyHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    protocol_version = "HTTP/1.1"

    def log_message(self, format_string, *args):
        # Never log headers, client addresses, subscription URLs or tokens.
        return

    def respond(self, code: int):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if code == 429:
            self.send_header("Retry-After", "5")
        self.end_headers()

    def do_GET(self):
        if self.path != "/check":
            self.respond(404)
            return
        ips = self.headers.get_all("X-XMesh-Peer-IP", [])
        if len(ips) != 1:
            self.respond(400)
            return
        try:
            enabled, mode, max_per_minute = load_policy()
        except (OSError, ValueError):
            self.respond(503)
            return
        try:
            if enabled:
                allowed = LIMITER.allow(ips[0], max_per_minute)
                if not allowed and mode == "protect":
                    self.respond(429)
                    return
            else:
                normalized_address(ips[0])
        except ValueError:
            self.respond(400)
            return
        except OverflowError:
            self.respond(503)
            return
        self.respond(204)

    def do_POST(self):
        self.respond(405)


def main() -> None:
    SOCKET_FILE.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if os.path.lexists(SOCKET_FILE):
        if not stat.S_ISSOCK(SOCKET_FILE.lstat().st_mode):
            raise ValueError("Refusing to replace a non-socket entry")
        SOCKET_FILE.unlink()
    # Read and validate before accepting requests; a broken policy never
    # permits unlimited subscription downloads.
    load_policy()
    with UnixHTTPServer(str(SOCKET_FILE), PolicyHandler) as server:
        SOCKET_FILE.chmod(0o660)
        server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
XMESH_LIMITER_SOURCE
}
if ((DRY_RUN)); then
  info "Validation successful, no host changes made."
  info "Panel: $PANEL | Subscription: https://$DOMAIN$SUB_PATH/{token}"
  printf '\n# Dockerfile.limiter\n'; render_limiter_dockerfile
  printf '\n# Dockerfile.caddy\n'; render_caddy_dockerfile
  printf '\n# Caddyfile\n'; render_caddyfile
  printf '\n# compose.yaml\n'; render_compose
  printf '\n# limiter.py\n'; render_limiter
  exit 0
fi

((EUID == 0)) || die "Run with sudo"
[[ "$RELEASE_SHA" =~ ^[a-f0-9]{40}$ ]] || die "Use the automatically attested installer command from Nexus; --release-sha is required"
[[ -f /etc/os-release ]] || die "Unsupported OS"
# shellcheck disable=SC1091
. /etc/os-release
[[ "$ID" == ubuntu && ( "$VERSION_ID" == "22.04" || "$VERSION_ID" == "24.04" ) ]] ||
  die "Only Ubuntu 22.04/24.04 LTS supported"
command -v curl >/dev/null || { apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq curl ca-certificates; }
if [[ -n "$ENROLL_TOKEN" || -f "$ROOT/manager.json" ]]; then
  command -v openssl >/dev/null || { apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq openssl; }
fi
if [[ -n "$ENROLL_TOKEN" || -f "$ROOT/manager.json" ]]; then
  command -v python3 >/dev/null || { apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq python3; }
fi
getent ahosts "$DOMAIN" >/dev/null || die "Subscription DNS does not resolve; create A/AAAA record"
curl -fsS --connect-timeout 7 --max-time 15 --output /dev/null "$PANEL/api/v1/health/ready" ||
  die "Nexus readiness check failed at $PANEL/api/v1/health/ready; verify HTTPS, /api/v1 proxy routing and Nexus database/Redis readiness"
if [[ ! -e "$ROOT/compose.yaml" ]] && command -v ss >/dev/null; then
  for port in 80 443; do
    if ss -H -ltn "( sport = :$port )" | grep -q .; then
      die "TCP port $port is already occupied; use a clean VPS"
    fi
  done
fi
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  info "Installing official Docker Engine and Compose..."
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "$VERSION_CODENAME" >/etc/apt/sources.list.d/docker.list
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker >/dev/null
mkdir -p "$ROOT/data" "$ROOT/config"
chmod 700 "$ROOT" "$ROOT/data" "$ROOT/config"
install -d -m 0755 "$ROOT/edge-policy"
install -d -m 0770 -o 65534 -g 65534 "$ROOT/run"
if [[ ! -e "$ROOT/edge-policy/config.json" ]]; then
  printf '%s\n' '{"enabled":true,"mode":"protect","ipPerMinute":120}' > "$ROOT/edge-policy/config.json"
  chmod 644 "$ROOT/edge-policy/config.json"
fi
temp=$(mktemp -d "$ROOT/.install.XXXXXXXX")
trap 'rm -rf "$temp"' EXIT
render_caddyfile >"$temp/Caddyfile"
render_compose >"$temp/compose.yaml"
render_limiter >"$temp/limiter.py"
  render_limiter_dockerfile >"$temp/Dockerfile.limiter"
  render_caddy_dockerfile >"$temp/Dockerfile.caddy"
chmod 600 "$temp/Caddyfile" "$temp/compose.yaml" "$temp/limiter.py" "$temp/Dockerfile.limiter" "$temp/Dockerfile.caddy"
if command -v python3 >/dev/null; then
  python3 -m py_compile "$temp/limiter.py" || die "Invalid edge limiter"
fi
# Verify the installer itself BEFORE running anything other than fixed setup.
# The action's OIDC certificate binds this exact file to a reviewed workflow
# and the immutable commit, not merely to GitHub's mutable main branch.
command -v gh >/dev/null || die "Install the official GitHub CLI using the Nexus installer command"
command -v python3 >/dev/null || die "Python 3 is required for release verification"
read -r _ _ gh_version _ < <(gh version | head -n1)
[[ "$gh_version" =~ ^([0-9]+)[.]([0-9]+)[.]([0-9]+)$ ]] || die "Invalid GitHub CLI version"
gh_major=${BASH_REMATCH[1]} gh_minor=${BASH_REMATCH[2]} gh_patch=${BASH_REMATCH[3]}
(( gh_major > 2 || (gh_major == 2 && (gh_minor > 102 || (gh_minor == 102 && gh_patch >= 0))) )) ||
  die "GitHub CLI 2.102.0+ is required to verify release provenance"
verify_artifact() {
  # Fetch PUBLIC bundles, then cryptographically verify OFFLINE. No gh login,
  # GH_TOKEN, release private key, or GitHub account is needed on a VPS.
  python3 - "$1" "$temp/attestation.jsonl" <<'PY'
import hashlib,json,pathlib,ssl,sys,urllib.request,urllib.parse
file=pathlib.Path(sys.argv[1])
digest=hashlib.sha256(file.read_bytes()).hexdigest()
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,msg,headers,newurl):
        return None
opener=urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ssl.create_default_context()),NoRedirect())
def fetch(url,limit):
    with opener.open(urllib.request.Request(url,headers={
        "Accept":"application/vnd.github+json","User-Agent":"XMesh-Sub-Release/1"
    }),timeout=25) as response:
        data=response.read(limit+1)
    if len(data)>limit: raise ValueError("Attestation response oversized")
    return data
index=json.loads(fetch(
    "https://api.github.com/repos/TriplexCorp/XMesh-Sub/attestations/sha256:"+digest,256*1024))
entries=index.get("attestations") if isinstance(index,dict) else None
if not isinstance(entries,list) or not 1<=len(entries)<=30:
    raise ValueError("No public artifact attestations")
bundles=[]
for entry in entries[:12]:
    if not isinstance(entry,dict): continue
    bundle=entry.get("bundle")
    if bundle is None:
        link=entry.get("bundle_url")
        if not isinstance(link,str):continue
        url=urllib.parse.urlparse(link)
        host=(url.hostname or "").lower()
        if (url.scheme!="https" or url.username or url.password or
            url.port not in (None,443) or
            not (host.endswith(".blob.core.windows.net") or
                 host.endswith(".githubusercontent.com"))):
            raise ValueError("Untrusted attestation bundle URL")
        bundle=json.loads(fetch(link,256*1024))
    if isinstance(bundle,dict) and "verificationMaterial" in bundle and "dsseEnvelope" in bundle:
        bundles.append(bundle)
if not bundles:raise ValueError("No usable artifact attestation")
pathlib.Path(sys.argv[2]).write_text(
    "".join(json.dumps(x,separators=(",",":"))+"\n" for x in bundles))
PY
  gh attestation verify "$1" --bundle "$temp/attestation.jsonl" \
    --repo TriplexCorp/XMesh-Sub \
    --cert-identity 'https://github.com/TriplexCorp/XMesh-Sub/.github/workflows/attested-release.yml@refs/heads/main' \
    --source-ref refs/heads/main --source-digest "$RELEASE_SHA" \
    --deny-self-hosted-runners >/dev/null ||
    die "Untrusted release artifact; refused root execution"
}
verify_artifact "${BASH_SOURCE[0]}"
curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 8 --max-time 35 \
  "https://raw.githubusercontent.com/TriplexCorp/XMesh-Sub/$RELEASE_SHA/release_verify.py" \
  -o "$temp/release_verify.py" || die "Could not download provenance verifier"
verify_artifact "$temp/release_verify.py"
mkdir -m 700 "$temp/revision"
python3 "$temp/release_verify.py" stage "$RELEASE_SHA" "$temp/revision" ||
  die "Release artifacts failed OIDC provenance verification"
cp "$temp/revision/manager.py" "$temp/manager.py"
python3 -m py_compile "$temp/manager.py" "$temp/release_verify.py" ||
  die "Verified manager/verifier failed syntax validation"
# Refuse downgrade BEFORE mutating the gateway or its configuration.
python3 - "$temp/revision/VERSION" "$ROOT/VERSION" <<'PY'
import pathlib,re,sys
new=pathlib.Path(sys.argv[1]).read_text().strip()
old_file=pathlib.Path(sys.argv[2])
old=old_file.read_text().strip() if old_file.is_file() else '0.0.0'
def semver(s):
    if not re.fullmatch(r'\d+\.\d+\.\d+',s):
        raise SystemExit("Invalid release version")
    return tuple(map(int,s.split('.')))
if semver(new)<semver(old):
    raise SystemExit("Refusing release downgrade")
PY

# Resolve the patched runtime before replacing the running gateway.
# The build context contains no keys, account records or verified manager code.
mkdir -p "$temp/image-build"
cp "$temp/Dockerfile.limiter" "$temp/image-build/Dockerfile"
limiter_image=$(sub_limiter_image)
caddy_image=$(sub_caddy_image)
# A signed source revision owns its image names. Never rebuild an already
# installed revision under the same tag: a repeat installation should not
# silently replace the original image ID with a newer Alpine package set.
if ! docker image inspect "$limiter_image" >/dev/null 2>&1; then
  docker build --pull -t "$limiter_image" "$temp/image-build" ||
    die "Could not build patched limiter image; existing deployment unchanged"
fi
mkdir -p "$temp/caddy-build"
cp "$temp/Dockerfile.caddy" "$temp/caddy-build/Dockerfile"
if ! docker image inspect "$caddy_image" >/dev/null 2>&1; then
  docker build --pull -t "$caddy_image" "$temp/caddy-build" ||
    die "Could not build patched Caddy binary; existing deployment unchanged"
fi
docker run --rm -v "$temp/Caddyfile:/etc/caddy/Caddyfile:ro" "$caddy_image" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile ||
  die "Gateway configuration invalid, existing deployment unchanged"
[[ ! -f "$ROOT/Caddyfile" ]] || cp -p "$ROOT/Caddyfile" "$ROOT/Caddyfile.previous"
install -m 600 "$temp/Caddyfile" "$ROOT/Caddyfile"
install -m 600 "$temp/compose.yaml" "$ROOT/compose.yaml"
install -m 644 "$temp/Dockerfile.limiter" "$ROOT/Dockerfile.limiter"
install -m 644 "$temp/Dockerfile.caddy" "$ROOT/Dockerfile.caddy"
install -m 644 "$temp/limiter.py" "$ROOT/limiter.py"
cd "$ROOT"
docker compose pull --ignore-buildable
docker compose up -d --no-build --remove-orphans
if [[ -n "$ENROLL_TOKEN" ]]; then
  # Fresh Ed25519 identity is generated on the Sub VPS. Only the public
  # key is sent to Nexus; there is no reusable bearer credential to steal.
  openssl genpkey -algorithm Ed25519 -out "$temp/agent-key.pem" >/dev/null ||
    die "Could not generate Sub agent identity"
  chmod 600 "$temp/agent-key.pem"
  XMESH_ENROLL_TOKEN="$ENROLL_TOKEN" python3 - "$PANEL" "$DOMAIN" "$SUB_PATH" \
    "$temp/manager.json" "$temp/agent-key.pem" <<'PY'
import json, os, pathlib, ssl, subprocess, sys, urllib.request
panel, domain, sub_path, path, private_key = sys.argv[1:]
der = subprocess.run(
    ["openssl", "pkey", "-in", private_key, "-pubout", "-outform", "DER"],
    check=True, capture_output=True, timeout=10
).stdout
prefix = bytes.fromhex("302a300506032b6570032100")
if not der.startswith(prefix) or len(der) != len(prefix) + 32:
    raise SystemExit("Invalid generated Ed25519 identity")
public_key = der[len(prefix):].hex()
class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ssl.create_default_context()), RejectRedirect()
)
request = urllib.request.Request(
    panel + "/api/v1/sub-server/claim",
    data=json.dumps({
        "enrollmentToken": os.environ["XMESH_ENROLL_TOKEN"],
        "domain": domain, "publicKey": public_key
    }, separators=(",", ":")).encode("utf-8"),
    headers={"Content-Type": "application/json"}, method="POST"
)
with opener.open(request, timeout=20) as response:
    body = response.read(4097)
if len(body) > 4096 or json.loads(body) != {"ok": True}:
    raise SystemExit("Nexus rejected Ed25519 enrollment")
with open(path, "w", encoding="utf-8") as out:
    json.dump({"panel": panel, "domain": domain, "path": sub_path, "publicKey": public_key}, out)
os.chmod(path, 0o600)
PY
  chmod 600 "$temp/manager.json"
fi
if [[ -s "$temp/manager.py" ]]; then
  install -m 700 "$temp/manager.py" "$ROOT/manager.py"
  install -m 700 "$temp/revision/release_verify.py" "$ROOT/release_verify.py"
  printf "%s\\n" "$RELEASE_SHA" > "$temp/RELEASE_SHA"
  install -m 600 "$temp/RELEASE_SHA" "$ROOT/RELEASE_SHA"
  if [[ -s "$temp/manager.json" ]]; then
    install -m 600 "$temp/agent-key.pem" "$ROOT/agent-key.pem"
    install -m 600 "$temp/manager.json" "$ROOT/manager.json"
  fi
  # Fail before reporting enrollment success if the deployed manager cannot
  # parse the exact configuration schema produced by this installer.
  if [[ -s "$ROOT/manager.json" ]]; then
    python3 - "$ROOT" <<'PY' ||
import importlib.util
from pathlib import Path
import sys
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("xmesh_sub_manager", root / "manager.py")
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)
manager.read_config(root / "manager.json")
PY
      die "Management agent configuration preflight failed; service was not restarted"
  fi
  # Fixed systemd service, no inbound ports. Ed25519 identity stays in a
  # root-only PEM; the JSON file contains only non-secret connection settings.
  cat >"$temp/xmesh-sub-manager.service" <<'UNIT'
[Unit]
Description=XMesh Sub Outbound Management Agent
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/xmesh-sub/manager.py
WorkingDirectory=/opt/xmesh-sub
Restart=always
RestartSec=15
NoNewPrivileges=true
UMask=0077
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
SystemCallArchitectures=native
[Install]
WantedBy=multi-user.target
UNIT
  install -m 644 "$temp/xmesh-sub-manager.service" /etc/systemd/system/xmesh-sub-manager.service
  systemctl daemon-reload
  systemctl enable xmesh-sub-manager.service >/dev/null
  if ((SKIP_MANAGER_RESTART == 0)); then
    systemctl restart xmesh-sub-manager.service
  fi
fi
install -m 644 "$temp/revision/VERSION" "$ROOT/VERSION"
info "Started. Check HTTPS health: https://$DOMAIN/healthz"
info "Status: cd $ROOT && sudo docker compose ps"
info "Upgrade: use the signed panel update workflow; local limiter images are rebuilt by the attested installer"
info "Do not move existing users until a canary feed is verified."
if [[ -n "$ENROLL_TOKEN" ]]; then info "Management agent enrolled. Check its status in Nexus Subscription Studio."; fi
