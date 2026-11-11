#!/usr/bin/env bash
# XMesh Sub: independent HTTPS subscription edge, Nexus remains authority.
set -Eeuo pipefail
umask 077
ROOT=/opt/xmesh-sub
PANEL='' DOMAIN='' SUB_PATH='' EMAIL='' DRY_RUN=0
die() { printf 'XMesh Sub: ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf 'XMesh Sub: %s\n' "$*"; }
usage() {
cat <<'HELP'
Usage (Ubuntu 22.04/24.04; run on a clean VPS with DNS + ports 80/443):
  sudo bash install.sh --panel https://panel.example.org --domain sub.example.org --path /s [--email ops@example.org]
For validation only append --dry-run.
HELP
}
while (($#)); do
  case "$1" in
    --panel|--domain|--path|--email)
      (($# >= 2)) || die "Missing value for $1"
      case "$1" in --panel) PANEL=$2;; --domain) DOMAIN=$2;; --path) SUB_PATH=$2;; --email) EMAIL=$2;; esac
      shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "Unknown argument: $1";;
  esac
done
valid_host() {
  local hostname=$1 label
  [[ ${#hostname} -le 253 && "$hostname" == *.* ]] || return 1
  [[ "$hostname" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
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

render_caddyfile() {
  if [[ -n "$EMAIL" ]]; then printf '{\n  email %s\n}\n\n' "$EMAIL"; fi
  cat <<CONF
$DOMAIN {
  @subscriptions {
    method GET HEAD
    path_regexp ^($SUB_PATH|/sub|/portal)/[0-9a-f]{64}$
  }
  handle @subscriptions {
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
getent ahosts "$DOMAIN" >/dev/null || die "Subscription DNS does not resolve; create A/AAAA record"
curl -fsS --connect-timeout 7 --max-time 15 --output /dev/null "$PANEL/health/ready" ||
  die "Nexus is not reachable via verified HTTPS; fix panel connectivity first"
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
docker run --rm -v "$temp/Caddyfile:/etc/caddy/Caddyfile:ro" caddy:2 caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile ||
  die "Gateway configuration invalid, existing deployment unchanged"
[[ ! -f "$ROOT/Caddyfile" ]] || cp -p "$ROOT/Caddyfile" "$ROOT/Caddyfile.previous"
install -m 600 "$temp/Caddyfile" "$ROOT/Caddyfile"
install -m 600 "$temp/compose.yaml" "$ROOT/compose.yaml"
cd "$ROOT"
docker compose pull
docker compose up -d --remove-orphans
info "Started. Check HTTPS health: https://$DOMAIN/healthz"
info "Status: cd $ROOT && sudo docker compose ps"
info "Upgrade: cd $ROOT && sudo docker compose pull && sudo docker compose up -d"
info "Do not move existing users until a canary feed is verified."
