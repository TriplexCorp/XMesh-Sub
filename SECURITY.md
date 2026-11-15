# Security and migration

- The public XMesh Sub hostname proxies only bearer subscription paths and the exact public assets; never expose Nexus admin routes.
- Subscriber tokens are credentials. Never publish subscription links, requests, proxy logs, or tokens in monitoring.
- All gateway-to-Nexus and agent-to-Nexus connections use TLS with normal certificate validation. Agent and enrollment requests reject ALL HTTP redirects, including same-origin redirects.
- The management agent has only a fixed action: **update**. There is no inbound SSH/admin listener or Docker socket mounted in Caddy.
- A one-time enrollment token is provided through **stdin**, not installer process arguments. Avoid saving the pasted install block in terminal recordings or issue comments; the code is valid for 60 minutes and can be claimed once.
- The Sub VPS generates a root-owned Ed25519 private key at `/opt/xmesh-sub/agent-key.pem` (0600) during one-time enrollment. Nexus stores only its public key. Each agent poll/report signs method, exact path, timestamp, random nonce, and SHA-256 of the raw JSON; Nexus rejects replay and old Bearer authentication.
- Theft of the private key still permits agent impersonation until re-enrollment; secure its root filesystem and backups. Strong identity is not a replacement for protecting the VPS.
- Every remotely triggered update **requires** an offline Ed25519-signed `release.json` and verifies SHA-256 of the installer before executing it as root. The installer verifies the same signed manifest before accepting new manager code.
- The signing key is NOT stored in the repository, VPS, or GitHub Actions. Keep its private PEM on an offline trusted machine; use `tools/sign-release.sh /secure/key.pem` to approve a new release. Release publication is deliberately fail-closed without a valid signature.
- Backups are created under `/opt/xmesh-sub/backups` (root-only) before managed updates. Failure triggers a best-effort rollback of the previous configuration and Caddy service; verify gateway health after a failure. Remote updates cannot guarantee rollback of package-manager or system-wide changes.
- The agent still needs host root privileges to operate Docker and update the installer. systemd restrictions reduce its ambient exposure but are **not** a privilege boundary against full root compromise.
- Review upstream DNS, host firewall, CDN logs, and supply-chain changes independently. Validate a canary feed before migrating customer subscriptions.

- This **staged but unsigned** v0.4.0 source adds a private Unix-socket IP limiter with bounded concurrency. It is **not deployed** until the owner signs the exact installer and manager hashes and the matching release passes CI. The edge trusts only the direct TCP peer observed by Caddy; do not trust client-supplied `X-Forwarded-For`. Protect the Nexus public subscription origin against direct bypass and validate reverse-proxy/Docker source-IP behavior on IPv4 and IPv6. A client using a CDN will initially appear as a CDN peer unless a trusted proxy chain is independently configured.
