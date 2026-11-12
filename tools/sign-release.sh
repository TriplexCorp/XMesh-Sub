#!/usr/bin/env bash
# Run OFFLINE on a trusted maintainer workstation: tools/sign-release.sh /secure/key.pem
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/.."
[[ $# == 1 && -r "$1" ]] || { echo "Usage: tools/sign-release.sh /offline/ed25519-private.pem" >&2; exit 2; }
key=$(realpath "$1")
python3 - <<'PY'
from pathlib import Path
import hashlib,json,re
version=Path("VERSION").read_text().strip()
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
    raise SystemExit("Invalid release version")
out={"schema":1,"version":version,
     "installSha256":hashlib.sha256(Path("install.sh").read_bytes()).hexdigest(),
     "managerSha256":hashlib.sha256(Path("manager.py").read_bytes()).hexdigest(),
     "floodGuardSha256":hashlib.sha256(Path("flood_guard.py").read_bytes()).hexdigest()}
Path("release.json").write_text(json.dumps(out,separators=(",", ":"),sort_keys=True)+"\n")
PY
signature=$(mktemp)
trap 'rm -f "$signature"' EXIT
openssl pkeyutl -sign -inkey "$key" -rawin -in release.json -out "$signature"
base64 -w0 "$signature" >release.json.sig
printf '\n' >>release.json.sig
base64 -d release.json.sig >"$signature"
openssl pkeyutl -verify -pubin -inkey release.pub -rawin -in release.json -sigfile "$signature" >/dev/null
echo "Signed release.json. Commit release.json and release.json.sig; NEVER commit the private key."
