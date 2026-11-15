# XMesh Sub

Separate HTTPS subscription delivery gateway for [XMesh Nexus](https://github.com/TriplexCorp/XMesh-Nexus).

## Install on a clean VPS

Install XMesh Nexus first. Configure the panel domain, then save the subscription domain
and path in **Subscription Studio**. Point the subscription domain DNS A/AAAA to a separate
Ubuntu 22.04/24.04 VPS and open TCP ports 80 and 443 (optional UDP 443).

Copy the one-command managed installer from Subscription Studio after generating a
one-time enrollment token. The command downloads a vetted, immutable installer,
installs the official GitHub CLI using a SHA-256-pinned APT signing keyring,
then verifies the **exact installer** using short-lived GitHub Actions OIDC
attestations (main release workflow, exact commit SHA, trusted issuer).
Only then does it execute the installer as root, passing the one-time enrollment
token through stdin rather than argv. Do not share the command: the pasted
here-document itself contains a secret, and some terminals record pasted input.

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

Upgrade: click **Update Sub server** in Nexus Subscription Studio. The local
agent fetches the immutable main commit and refuses unsigned, stale or otherwise
unauthorized artifacts. Reinstalling Ubuntu or manually signing files is not
part of the normal user workflow.

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

## Automatic, keyless attested releases (v0.4.1+)

This is a **one-command clean VPS installation**. All release publishing happens
automatically in `.github/workflows/attested-release.yml` on the protected
`main` branch, **after** installer, Python and Caddy tests pass. GitHub Actions
mints a short-lived OIDC signing certificate and publishes Sigstore attestations
for `install.sh`, `manager.py`, `release_verify.py` and `VERSION`.
There is **no static release private key** to generate, upload, or keep on the VPS.

Subscription Studio's generated command installs the official GitHub CLI (>=2.102),
validates its package-signing keyring checksum, downloads an immutable commit and
verifies the installer attestation before root execution. The installer independently
re-verifies the installer, verifier, manager and version; it rejects outdated
revisions, missing attestations, unexpected workflow identities or a failed
lookup. The manager uses the same exact-commit verification for every update.

The management agent **separately** generates its Ed25519 private identity on the
Sub VPS; this private key is never a release signing key and is never sent to
Nexus. Each poll/report is signed with timestamp, nonce, fixed route and body hash.
Legacy bearer manager authentication has been removed.

**Security prerequisite:** Protect the release workflow and `main` with branch
protection/reviews and restricted Actions permissions. Otherwise a compromised
publisher can produce attestations for malicious code; signatures alone do not
prove the code is safe. The first real VPS deployment and update must be tested
after the workflow has published attestations.

Recovery snapshots are stored under `/opt/xmesh-sub/backups` with root-only
permissions, including the installed verifier and commit SHA. A failed update
attempts a best-effort rollback (not OS package rollback). The manager requires
root to install Docker; systemd hardening reduces but cannot eliminate impact
of total host compromise.

To inspect the agent:

    sudo systemctl status xmesh-sub-manager
    sudo journalctl -u xmesh-sub-manager -n 50 --no-pager

Only one managed Sub server per Nexus installation is supported.

## Peer-IP flood defense

The attested installer embeds an audited Python limiter into the **verified installer** (never downloaded as an unsigned executable). A separate unprivileged container listens only on a private Unix-domain socket. Caddy overwrites the limiter request's peer-IP header with its own connection peer (`{remote_host}`) and strips all original request headers, URI and cookies from the authorization request. No subscriber bearer token enters the limiter. The limiter normalizes IPv4-mapped IPv6 and groups native IPv6 by /64, maintains bounded HMAC-keyed token buckets and bounds active worker threads. Protected mode returns 429 with `Retry-After` for over-budget requests; missing/invalid policy or limiter outages fail closed.

**Remaining release validation:** Confirm the authenticated release workflow has published OIDC attestations, run a clean-VPS canary and verify real peer IP from Caddy/Docker. Prevent bypass of the Sub limiter by fetching a subscription directly from the Nexus public panel origin. Neither the attestation nor the flood limiter alone solves CDN/origin bypass.
