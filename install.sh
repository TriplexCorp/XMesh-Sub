#!/usr/bin/env bash
# XMesh Sub: independent HTTPS subscription edge, Nexus remains authority.
set -Eeuo pipefail
umask 077
ROOT=/opt/xmesh-sub
PANEL='' DOMAIN='' SUB_PATH='' EMAIL='' DRY_RUN=0 ENROLL_TOKEN='' ENROLL_STDIN=0 SKIP_MANAGER_RESTART=0
die() { printf 'XMesh Sub: ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf 'XMesh Sub: %s\n' "$*"; }
usage() {
cat <<'HELP'
Usage (Ubuntu 22.04/24.04; run on a clean VPS with DNS + ports 80/443):
  sudo bash install.sh --panel https://panel.example.org --domain sub.example.org --path /s [--email ops@example.org]
For validation only append --dry-run. For managed installation use --enroll-token-stdin and provide the key via stdin.
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
  local flood_hook=''
  if [[ -n "$ENROLL_TOKEN" || -f "$ROOT/manager.json" ]]; then
    # The single trusted header is overwritten with the direct TCP peer.
    # Ignore client-supplied X-Forwarded-For / CF-Connecting-IP.
    flood_hook=$(cat <<'GUARD'
    forward_auth xmesh-sub-flood:8080 {
      uri /check
      header_up X-XMesh-Peer {remote_host}
      header_up X-Forwarded-Uri /check
      header_up -X-Forwarded-For
      header_up -CF-Connecting-IP
      header_up -Authorization
      header_up -Cookie
    }
GUARD
)
  fi
  cat <<CONF
$DOMAIN {
  @subscriptions {
    method GET HEAD
    path_regexp ^($SUB_PATH|/sub|/portal)/[0-9a-f]{64}$
  }
  handle @subscriptions {
$flood_hook
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
render_compose() {
  cat <<'YAML'
services:
  xmesh-sub:
    image: caddy:2
    container_name: xmesh-sub
    restart: unless-stopped
    ports:
      - "80:80/tcp"
      - "443:443/tcp"
      - "443:443/udp"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./data:/data
      - ./config:/config
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
YAML
  if [[ -n "$ENROLL_TOKEN" || -f "$ROOT/manager.json" ]]; then
    cat <<'YAML'
  # Private forward-auth only: no published host port or Docker socket.
  xmesh-sub-flood:
    image: python:3.13-alpine
    restart: unless-stopped
    user: "65534:65534"
    read_only: true
    pids_limit: 64
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    tmpfs: [/tmp]
    volumes:
      - ./flood_guard.py:/app/flood_guard.py:ro
      - ./flood.json:/etc/xmesh/flood.json:ro
    command: ["python3", "-u", "/app/flood_guard.py"]
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/check',timeout=2)"]
      interval: 15s
      timeout: 3s
      retries: 3
YAML
  fi
}
if ((DRY_RUN)); then
  info "Validation successful, no host changes made."
  info "Panel: $PANEL | Subscription: https://$DOMAIN$SUB_PATH/{token}"
  printf '\n# Caddyfile\n'; render_caddyfile
  printf '\n# compose.yaml\n'; render_compose
  exit 0
fi

((EUID == 0)) || die "Run with sudo"
[[ -f /etc/os-release ]] || die "Unsupported OS"
# shellcheck disable=SC1091
. /etc/os-release
[[ "$ID" == ubuntu && ( "$VERSION_ID" == "22.04" || "$VERSION_ID" == "24.04" ) ]] ||
  die "Only Ubuntu 22.04/24.04 LTS supported"
command -v curl >/dev/null || { apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates; }
if [[ -n "$ENROLL_TOKEN" || -f "$ROOT/manager.json" ]]; then
  command -v openssl >/dev/null || { apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssl; }
fi
if [[ -n "$ENROLL_TOKEN" || -f "$ROOT/manager.json" ]]; then
  command -v python3 >/dev/null || { apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3; }
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
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "$VERSION_CODENAME" >/etc/apt/sources.list.d/docker.list
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker >/dev/null
mkdir -p "$ROOT/data" "$ROOT/config"
chmod 700 "$ROOT" "$ROOT/data" "$ROOT/config"
temp=$(mktemp -d "$ROOT/.install.XXXXXXXX")
trap 'rm -rf "$temp"' EXIT
render_caddyfile >"$temp/Caddyfile"
render_compose >"$temp/compose.yaml"
chmod 600 "$temp/Caddyfile" "$temp/compose.yaml"
if [[ -n "$ENROLL_TOKEN" || -f "$ROOT/manager.json" ]]; then
  # Trust anchor: public Ed25519 key. Private signer must stay OFF the VPS and
  # outside GitHub. Do not fall back to unsigned scripts or checksums from main.
  cat >"$temp/release.pub" <<'XMESH_RELEASE_PUBLIC_KEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA67uQhBdQaaf3O9i4DisJVG74G9DJASmHOuevLlarPHw=
-----END PUBLIC KEY-----
XMESH_RELEASE_PUBLIC_KEY
  curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 8 --max-time 35 \
    https://raw.githubusercontent.com/TriplexCorp/XMesh-Sub/main/release.json -o "$temp/release.json" ||
    die "Could not download signed release metadata"
  curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 8 --max-time 35 \
    https://raw.githubusercontent.com/TriplexCorp/XMesh-Sub/main/release.json.sig -o "$temp/release.json.sig.b64" ||
    die "Could not download release signature"
  base64 -d "$temp/release.json.sig.b64" >"$temp/release.json.sig" ||
    die "Invalid release signature encoding"
  openssl pkeyutl -verify -pubin -inkey "$temp/release.pub" -rawin \
    -in "$temp/release.json" -sigfile "$temp/release.json.sig" >/dev/null 2>&1 ||
    die "Release Ed25519 signature verification failed; refusing root execution"
  curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 8 --max-time 35 \
    https://raw.githubusercontent.com/TriplexCorp/XMesh-Sub/main/manager.py -o "$temp/manager.py" ||
    die "Could not download XMesh Sub manager"
  curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 8 --max-time 35 \
    https://raw.githubusercontent.com/TriplexCorp/XMesh-Sub/main/flood_guard.py -o "$temp/flood_guard.py" ||
    die "Could not download XMesh Sub edge guard"
  # A signed, offline-approved manifest pins every executable, including the guard.
  python3 - "$temp/release.json" "$temp/manager.py" "$temp/flood_guard.py" <<'PY'
import hashlib, json, pathlib, re, sys
manifest=json.loads(pathlib.Path(sys.argv[1]).read_text())
assert set(manifest)=={"schema","version","installSha256","managerSha256"} and manifest["schema"]==1, "Invalid signed release schema"
assert isinstance(manifest["version"],str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",manifest["version"]), "Invalid release version"
for key in ("installSha256","managerSha256"):
    assert isinstance(manifest[key],str) and re.fullmatch("[a-f0-9]{64}",manifest[key]), "Invalid digest"
assert hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()==manifest["managerSha256"], "Manager SHA-256 mismatch"
# This digest is literally embedded in the signed install.sh, so old agents
# can verify the unchanged four-field manifest and still update safely.
assert hashlib.sha256(pathlib.Path(sys.argv[3]).read_bytes()).hexdigest()=="12ad8b2a901c191116a4a1e25ea33b5e431af5b3df874dbf30d45154cceae508", "Edge guard SHA-256 mismatch"
PY
  python3 -m py_compile "$temp/manager.py" "$temp/flood_guard.py" ||
    die "Agent or edge guard failed syntax validation"
fi
docker run --rm -v "$temp/Caddyfile:/etc/caddy/Caddyfile:ro" caddy:2 caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile ||
  die "Gateway configuration invalid, existing deployment unchanged"
[[ ! -f "$ROOT/Caddyfile" ]] || cp -p "$ROOT/Caddyfile" "$ROOT/Caddyfile.previous"
install -m 600 "$temp/Caddyfile" "$ROOT/Caddyfile"
install -m 600 "$temp/compose.yaml" "$ROOT/compose.yaml"
# The private sidecar's read-only bind mounts must exist BEFORE Compose starts.
if [[ -s "$temp/flood_guard.py" ]]; then
  install -m 644 "$temp/flood_guard.py" "$ROOT/flood_guard.py"
  if [[ ! -s "$ROOT/flood.json" ]]; then
    printf '%s\n' '{"enabled":true,"mode":"monitor","ipPerMinute":120}' > "$ROOT/flood.json"
  fi
  chmod 644 "$ROOT/flood.json"
fi
cd "$ROOT"
docker compose pull
docker compose up -d --remove-orphans
if [[ -n "$ENROLL_TOKEN" ]]; then
  # The one-time credential is exchanged for a long-lived service token over
  # verified TLS. Neither credential is printed in output. Only root may read it.
  XMESH_ENROLL_TOKEN="$ENROLL_TOKEN" python3 - "$PANEL" "$DOMAIN" "$SUB_PATH" "$temp/manager.json" <<'PY'
import json, os, re, ssl, sys, urllib.request
panel, domain, sub_path, path = sys.argv[1:]
request = urllib.request.Request(
  panel + "/api/v1/sub-server/claim",
  data=json.dumps({"enrollmentToken": os.environ["XMESH_ENROLL_TOKEN"], "domain": domain}).encode(),
  headers={"Content-Type": "application/json"}, method="POST"
)
with urllib.request.urlopen(request, timeout=20, context=ssl.create_default_context()) as response:
  body = response.read(4096)
token = json.loads(body)["agentToken"]
if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
  raise SystemExit("Nexus returned an invalid manager credential")
with open(path, "w", encoding="utf-8") as out:
  json.dump({"panel": panel, "domain": domain, "path": sub_path, "agentToken": token}, out)
os.chmod(path, 0o600)
PY
  chmod 600 "$temp/manager.json"
fi
if [[ -s "$temp/manager.py" ]]; then
  install -m 700 "$temp/manager.py" "$ROOT/manager.py"
  install -m 600 "$temp/release.pub" "$ROOT/release.pub"
  install -m 600 "$temp/release.json" "$ROOT/release.json"
  if [[ -s "$temp/manager.json" ]]; then
    install -m 600 "$temp/manager.json" "$ROOT/manager.json"
  fi
  # Fixed systemd service, no inbound ports, credentials live only in a
  # root-owned JSON file; no Docker socket exposed to public containers.
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
if [[ -s "$temp/release.json" ]]; then
  python3 - "$temp/release.json" "$ROOT/VERSION" "$temp/VERSION" <<'PY'
import json,pathlib,re,sys
release=json.loads(pathlib.Path(sys.argv[1]).read_text())["version"]
existing=pathlib.Path(sys.argv[2])
previous=existing.read_text().strip() if existing.is_file() else "0.0.0"
def components(version):
    match=re.match(r"^(\d+)\.(\d+)\.(\d+)",version)
    return tuple(map(int,match.groups())) if match else (0,0,0)
if components(release)<components(previous):
    raise SystemExit("Refusing signed release downgrade")
pathlib.Path(sys.argv[3]).write_text(release+"\n")
PY
else
  curl -fsSL --connect-timeout 8 --max-time 20 \
    https://raw.githubusercontent.com/TriplexCorp/XMesh-Sub/main/VERSION -o "$temp/VERSION" ||
    die "Could not download XMesh Sub version"
fi
install -m 644 "$temp/VERSION" "$ROOT/VERSION"
info "Started. Check HTTPS health: https://$DOMAIN/healthz"
info "Status: cd $ROOT && sudo docker compose ps"
info "Upgrade: cd $ROOT && sudo docker compose pull && sudo docker compose up -d"
info "Do not move existing users until a canary feed is verified."
if [[ -n "$ENROLL_TOKEN" ]]; then info "Management agent enrolled. Check its status in Nexus Subscription Studio."; fi
