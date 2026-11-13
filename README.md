# XMesh Sub

Separate HTTPS subscription delivery gateway for [XMesh Nexus](https://github.com/TriplexCorp/XMesh-Nexus).

## Install on a clean VPS

Install XMesh Nexus first. Configure the panel domain, then save the subscription domain
and path in **Subscription Studio**. Point the subscription domain DNS A/AAAA to a separate
Ubuntu 22.04/24.04 VPS and open TCP ports 80 and 443 (optional UDP 443).

Copy the one-command managed installer from Subscription Studio after generating a
one-time enrollment token. The command downloads a vetted, immutable installer,
checks its SHA-256 before root execution and provides the enrollment token via
a stdin here-document, not via command-line arguments. Do not paste the
one-time token into shell history or support messages.

The installer installs Docker Engine and the Compose plugin if needed, validates the
Caddy configuration, creates a persistent service under `/opt/xmesh-sub`, and obtains
public TLS certificates automatically. The panel must already have valid HTTPS.

Before installing, the script probes the Nexus **public API** readiness endpoint:
`https://<panel-domain>/api/v1/health/ready`. This route checks PostgreSQL and Redis;
`/health/ready` without `/api/v1` is not a Nexus public route and returns 404.
If the probe fails, check Nexus availability and reverse-proxy routing for `/api/v1`
from the new VPS. Do not confuse the Nexus readiness URL with the XMesh Sub
`/healthz` endpoint, which only checks the HTTPS gateway.

Test the installer without root or changes to the VPS:

    bash install.sh --panel https://panel.example.org --domain sub.example.org --path /s --dry-run

Check service health after deployment:

    curl -fsSI https://sub.example.org/healthz
    cd /opt/xmesh-sub && sudo docker compose ps

Upgrade:

    cd /opt/xmesh-sub && sudo docker compose pull && sudo docker compose up -d

## Phase 1 implementation and guarantees

**This is an isolated edge gateway, not yet an independent subscription generator.**
The gateway handles GET/HEAD for the configured subscription path plus /sub/{token}
and /portal/{token}, where the token must contain exactly 64 lowercase hex characters.
It also forwards only the seven **exact public portal CSS/JS asset filenames** required
by Nexus's server-rendered subscription template (never arbitrary `/js`, `/styles`,
control API endpoints or other static files). Without these assets the portal HTML
appears as an unstyled page. To repair an existing installation, rerun the same
installer command to regenerate `/opt/xmesh-sub/Caddyfile` and restart Caddy.
Unrelated requests return 404 (including all administration and API endpoints).
Requests are passed through verified HTTPS to Nexus. Nexus still owns tokens, revocation,
expiration, quota enforcement, portal rendering, and client formats.

The edge stores no user records, admin secrets, or database credentials. It does not cache
subscription responses or configure request access logging. CDN and VPS provider logs
are external to this deployment and require separate review.

## Personal portal button in VPN applications

Nexus returns `profile-web-page-url` on authenticated subscription responses.
When XMesh Subscription Studio has no custom page URL, the header targets
the **same existing personal subscription URL** with `?view=portal`, for example:

`https://sub.example.org/s/<64-character-personal-token>?view=portal`

This parameter deliberately forces the HTML portal even when a VPN client's
embedded browser sends a VPN application User-Agent. Without the parameter,
the canonical link still serves a feed to VPN applications and an HTML portal
to normal browsers. Clients that support the metadata (including Happ) render
the personal webpage button; the app itself chooses icon artwork.

The Caddy gateway forwards the original path, query string and response headers
including `profile-web-page-url`, `profile-title`, `support-url`,
`subscription-userinfo` and `announce` without rewriting them.
The gateway does **not** store subscriber metadata, create public log files
or mint an additional portal token. The URL is a bearer credential:
do not publish it in tickets, logs, CI output or screenshots.

If the website button is missing, inspect headers locally using a
**real, private, redacted test subscription** and verify the XMesh Nexus
Subscription Studio setting **“Личный кабинет в VPN-приложениях”**.
A blank custom URL means “use the personal XMesh portal”; a configured
HTTPS URL overrides it with a shared external webpage. Disabling the setting
omits the header, but leaves the subscription itself working.

**Do not redirect production users until DNS, TLS, health, and a sample subscription are verified.**
Changing the actual hostname in issued links can require clients to re-import them.
Future work can add pairing, fleet reporting, and independent subscription rendering.

See [SECURITY.md](SECURITY.md).

## Signed managed updates

The management agent makes outbound-only HTTPS requests to Nexus. It accepts
only the fixed `update` action, not arbitrary shell commands or URLs.
The server owner generates a one-time enrollment code in Subscription Studio
and copies a single command for installation and pairing.

Every management update downloads the **offline-signed** `release.json`
manifest and verifies its Ed25519 signature against a public trust anchor
installed with the vetted initial installer. The installer SHA-256 in that
manifest must match before any root execution; the installer similarly checks
the exact SHA-256 of `manager.py`. Unsigned or modified main-branch files
are **rejected**, not executed.

To sign a new vetted release, keep the private signing key OFF GitHub and the
VPS, increment VERSION, and from a trusted signing workstation run
`tools/sign-release.sh /secure/offline-ed25519-private.pem`. Review the
manifest and commit `release.json` and `release.json.sig` with the code.
Never commit the private key. CI verifies the signature and hashes.

The agent stores recovery snapshots under `/opt/xmesh-sub/backups`
with root-only permissions and attempts to restore the old gateway configuration
if an update fails. Full OS-package rollback is not guaranteed. The root
systemd agent has additional protection flags, but still possesses root
privileges to install and update Docker/Compose. For production, keep the
VPS and panel patched and review each signed release.

To inspect the agent:

    sudo systemctl status xmesh-sub-manager
    sudo journalctl -u xmesh-sub-manager -n 50 --no-pager

Only one managed Sub server is supported per Nexus installation.
