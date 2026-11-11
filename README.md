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
The gateway handles only GET/HEAD for the configured subscription path plus /sub/{token}
and /portal/{token}, where the token must contain exactly 64 lowercase hex characters.
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
