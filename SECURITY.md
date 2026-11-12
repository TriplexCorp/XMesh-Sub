# Security and migration

- The public XMesh Sub hostname proxies only bearer subscription paths and the exact public assets; never expose Nexus admin routes.
- Subscriber tokens are credentials. Never publish subscription links, requests, proxy logs, or tokens in monitoring.
- All gateway-to-Nexus and agent-to-Nexus connections use TLS with normal certificate validation. Agent requests reject ALL HTTP redirects, including same-origin redirects.
- The management agent has only a fixed action: **update**. There is no inbound SSH/admin listener or Docker socket mounted in Caddy.
- A one-time enrollment token is provided through **stdin**, not installer process arguments. Avoid saving the pasted install block in terminal recordings or issue comments; the code is valid for 60 minutes and can be claimed once.
- Manager credentials are root-owned, mode 0600, and never sent to browser clients after the exchange. Use full-disk encryption where appropriate and protect VPS backups.
- Every remotely triggered update **requires** an offline Ed25519-signed `release.json` and verifies SHA-256 of the installer before executing it as root. The installer verifies the same signed manifest before accepting new manager code.
- The signing key is NOT stored in the repository, VPS, or GitHub Actions. Keep its private PEM on an offline trusted machine; use `tools/sign-release.sh /secure/key.pem` to approve a new release. Release publication is deliberately fail-closed without a valid signature.
- Backups are created under `/opt/xmesh-sub/backups` (root-only) before managed updates. Failure triggers a best-effort rollback of the previous configuration and Caddy service; verify gateway health after a failure. Remote updates cannot guarantee rollback of package-manager or system-wide changes.
- The agent still needs host root privileges to operate Docker and update the installer. systemd restrictions reduce its ambient exposure but are **not** a privilege boundary against full root compromise.
- Review upstream DNS, host firewall, CDN logs, and supply-chain changes independently. Validate a canary feed before migrating customer subscriptions.

## Edge IP flood shield (pending newly signed release)

Managed XMesh Sub includes a **private** `forward_auth` sidecar. Caddy overwrites `X-XMesh-Peer` with its direct TCP peer; the sidecar ignores all forwarded headers and stores at most 6,000 temporary peer counters. IPv6 is grouped by /64. The sidecar has **no published host port**, no shell interface, and never logs raw subscription paths, secrets, or source IPs. Clients behind CDNs will share the CDN peer IP until trusted-proxy handling is explicitly configured; keep **monitor** mode while validating any CDN deployment. The Nexus agent delivers only the sanitized `enabled`, `mode`, `ipPerMinute` policy over authenticated HTTPS.

**Release gate:** Installing or updating executable code requires an offline Ed25519 signature over the exact installer, manager and edge guard SHA-256 digests. Review and sign a new release with the existing trusted private key; never bypass signature verification, ship an unsigned manifest, change the pinned public key silently, or apply this development branch to production VPSs. Reconfirm CI, Caddy validation, active-subscription compatibility and rollback on a test VPS before turning on protect mode.
