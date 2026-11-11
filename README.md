# XMesh Sub

Separate HTTPS subscription delivery gateway for [XMesh Nexus](https://github.com/TriplexCorp/XMesh-Nexus).

## Install on a clean VPS

Install XMesh Nexus first. Configure the panel domain, then save the subscription domain
and path in **Subscription Studio**. Point the subscription domain DNS A/AAAA to a separate
Ubuntu 22.04/24.04 VPS and open TCP ports 80 and 443 (optional UDP 443).

Copy the auto-generated install command from Subscription Studio. Example:

    curl -fsSL https://raw.githubusercontent.com/TriplexCorp/XMesh-Sub/main/install.sh | sudo bash -s -- --panel https://panel.example.org --domain sub.example.org --path /s

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

**Do not redirect production users until DNS, TLS, health, and a sample subscription are verified.**
Changing the actual hostname in issued links can require clients to re-import them.
Future work can add pairing, fleet reporting, and independent subscription rendering.

See [SECURITY.md](SECURITY.md).

## Managed updates (optional, one-time enrollment)

The public HTTPS gateway can run without remote administration. To enable
**Update XMesh Sub** in Subscription Studio, click **Connect management** as
an owner. The panel issues a short-lived, single-use enrollment code, then
shows an installer command containing `--enroll-token`. Run the command on the
existing Sub VPS; the installer validates HTTPS, exchanges the enrollment code
for a service token over HTTPS and installs a systemd outbound-only agent.
The long-lived token is stored in `/opt/xmesh-sub/manager.json` with mode 0600.
It is **not** returned to panel browsers after claiming, and the short-lived
code cannot be replayed. Revoking/re-enrolling rotates the service credential.

The agent uses outbound requests to `https://<panel>/api/v1/sub-server/agent/poll`
and `.../report` every 20 seconds. The Nexus owner can enqueue **one fixed
update action**; the agent will fetch the reviewed official XMesh-Sub installer
from the project's main branch and rerun it with its existing domain and path.
It never accepts URLs, shell commands, or other executable arguments from
Nexus. **There is no inbound management port or Docker socket mounted into
Caddy.** To inspect the manager on the VPS:

    sudo systemctl status xmesh-sub-manager
    sudo journalctl -u xmesh-sub-manager -n 50 --no-pager

The agent and update code execute as root. Protect the VPS and its GitHub supply
chain, use TLS, and review changes before issuing remote updates. Updates may
briefly interrupt the public gateway. If Nexus is unreachable, the agent cannot
receive update tasks, but Caddy keeps serving subscription requests when Nexus
connectivity returns. For current versions, enrollment and management target a
**single** XMesh Sub server per Nexus installation, not a multi-server fleet.
