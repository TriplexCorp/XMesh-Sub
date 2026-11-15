#!/usr/bin/env bash
# Immutable bootstrap pinned by an XMesh Nexus release. It installs only
# attested XMesh-Sub assets; no credentials enter argv, environment or history.
set -Eeuo pipefail
umask 077
PANEL='' DOMAIN='' SUB_PATH='' DRY_RUN=0
die(){ printf 'XMesh Sub: %s\n' "$*" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --panel|--domain|--path)
      (($#>=2)) || die "Missing value for $1"
      case "$1" in --panel) PANEL=$2;; --domain) DOMAIN=$2;; --path) SUB_PATH=$2;; esac
      shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    *) die "Unknown option: $1";;
  esac
done
[[ "$PANEL" =~ ^https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die 'Invalid panel HTTPS URL'
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die 'Invalid Sub domain'
[[ "$PANEL" != "https://$DOMAIN" ]] || die 'Panel and Sub domains must differ'
[[ "${#SUB_PATH}" -le 64 && "$SUB_PATH" =~ ^(/[A-Za-z0-9_-]+)+$ ]] || die 'Invalid Sub path'
case "$SUB_PATH" in /api|/api/*|/login|/login/*|/dashboard|/dashboard/*) die 'Reserved subscription path';; esac
if ((DRY_RUN)); then
  printf 'XMesh Sub bootstrap arguments: OK\n'
  exit 0
fi
((EUID==0)) || die 'Run this bootstrap with sudo'
[[ -t 2 && -r /dev/tty ]] || die 'Interactive SSH terminal required for private enrollment code'
printf 'Paste the one-time enrollment code from Subscription Studio (input hidden): ' >/dev/tty
IFS= read -r -s ENROLL_TOKEN </dev/tty || die 'Missing enrollment code'
printf '\n' >/dev/tty
[[ "$ENROLL_TOKEN" =~ ^[0-9a-f]{64}$ ]] || die 'Invalid enrollment code; create a new code in Nexus'
tmp="$(mktemp -d)"
trap 'unset ENROLL_TOKEN; rm -rf "$tmp"' EXIT
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get -o DPkg::Lock::Timeout=600 install -y ca-certificates curl python3
# Official GitHub CLI apt trust root is pinned, never downloaded as a mutable
# unsigned installer. GitHub CLI >= 2.102.0 fixes attestation verification.
mkdir -p /etc/apt/keyrings
curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 30 \
  https://cli.github.com/packages/githubcli-archive-keyring.gpg -o "$tmp/githubcli.gpg"
printf '6084d5d7bd8e288441e0e94fc6275570895da18e6751f70f057485dc2d1a811b  %s\n' "$tmp/githubcli.gpg" |
  sha256sum --check --status || die 'GitHub CLI signing key mismatch'
install -m 644 "$tmp/githubcli.gpg" /etc/apt/keyrings/githubcli-archive-keyring.gpg
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\n' \
  "$(dpkg --print-architecture)" > /etc/apt/sources.list.d/github-cli.list
apt-get update -qq
apt-get -o DPkg::Lock::Timeout=600 install -y gh
version="$(gh version | head -n1 | awk '{print $3}')"
python3 -c 'import re,sys; m=re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)",sys.argv[1]); assert m and tuple(map(int,m.groups())) >= (2,102,0)' "$version" || die 'GitHub CLI 2.102.0+ required'
curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 30 \
  -H 'Accept: application/vnd.github+json' \
  https://api.github.com/repos/TriplexCorp/XMesh-Sub/commits/main -o "$tmp/commit.json"
sha="$(python3 -c 'import json,re,sys; s=json.load(open(sys.argv[1]))["sha"]; assert re.fullmatch(r"[0-9a-f]{40}",s); print(s)' "$tmp/commit.json")"
curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 35 \
  "https://raw.githubusercontent.com/TriplexCorp/XMesh-Sub/$sha/release_verify.py" -o "$tmp/release_verify.py"
# Before running even the verifier, fetch PUBLIC OIDC bundles and verify the
# exact SHA, signer identity and source revision offline (no GitHub login).
python3 - "$tmp/release_verify.py" "$tmp/bundles.jsonl" <<'PY'
import hashlib,json,pathlib,ssl,sys,urllib.request,urllib.parse
source=pathlib.Path(sys.argv[1])
digest=hashlib.sha256(source.read_bytes()).hexdigest()
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,request,fp,code,msg,headers,newurl): return None
opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()),NoRedirect())
def fetch(url,limit):
 with opener.open(urllib.request.Request(url,headers={"Accept":"application/vnd.github+json","User-Agent":"XMesh-Sub-Bootstrap/2"}),timeout=25) as response:
  raw=response.read(limit+1)
 if len(raw)>limit:raise ValueError("Oversized provenance response")
 return raw
index=json.loads(fetch("https://api.github.com/repos/TriplexCorp/XMesh-Sub/attestations/sha256:"+digest,256*1024))
entries=index.get("attestations") if isinstance(index,dict) else None
if not isinstance(entries,list) or not 1<=len(entries)<=30:raise ValueError("Missing public artifact attestations")
bundles=[]
for entry in entries[:12]:
 if not isinstance(entry,dict):continue
 bundle=entry.get("bundle")
 if bundle is None:
  link=entry.get("bundle_url")
  if not isinstance(link,str):continue
  url=urllib.parse.urlparse(link);host=(url.hostname or "").lower()
  if url.scheme!="https" or url.username or url.password or url.port not in (None,443) or not (host.endswith(".blob.core.windows.net") or host.endswith(".githubusercontent.com")): raise ValueError("Untrusted bundle URL")
  bundle=json.loads(fetch(link,256*1024))
 if isinstance(bundle,dict) and "verificationMaterial" in bundle and "dsseEnvelope" in bundle:bundles.append(bundle)
if not bundles:raise ValueError("Missing verified provenance bundle")
pathlib.Path(sys.argv[2]).write_text("".join(json.dumps(value,separators=(",",":"))+"\n" for value in bundles))
PY
gh attestation verify "$tmp/release_verify.py" --bundle "$tmp/bundles.jsonl" \
  --repo TriplexCorp/XMesh-Sub \
  --cert-identity 'https://github.com/TriplexCorp/XMesh-Sub/.github/workflows/attested-release.yml@refs/heads/main' \
  --source-ref refs/heads/main --source-digest "$sha" --deny-self-hosted-runners >/dev/null ||
  die 'Untrusted XMesh Sub release verifier'
mkdir -m 700 "$tmp/revision"
python3 "$tmp/release_verify.py" stage "$sha" "$tmp/revision" ||
  die 'Attested XMesh Sub release unavailable'
bash -n "$tmp/revision/install.sh" || die 'Invalid attested installer'
# One-time credential only in stdin, never shell arguments, URL or logs.
printf '%s\n' "$ENROLL_TOKEN" | bash "$tmp/revision/install.sh" \
  --release-sha "$sha" --panel "$PANEL" --domain "$DOMAIN" --path "$SUB_PATH" --enroll-token-stdin
unset ENROLL_TOKEN
printf '\nXMesh Sub: Installation finished. Agent will connect to Nexus automatically.\n'
