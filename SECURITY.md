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

## Real-IP limiter and agent proof — rollout boundary

The proposed gateway adds a private Caddy `forward_auth` connection over a
Unix socket (not publicly bound TCP) and an independent, resource-bounded
Python policy sidecar. Its only peer identity is the actual Caddy TCP peer,
not a client-controlled `X-Forwarded-For` or `X-Real-IP`. A fronting CDN
would be that peer and must not be silently treated as the visitor.
IPv6 privacy addresses are grouped to /64. Shared IPv4 NAT users share a
budget; monitor 429s in canary. Limiter absence or malformed config fails
closed rather than bypassing subscriber flood protection.

The paired manager keeps `agent-proof.pem` root-only (0600) and signs
management requests with Ed25519, while its public key is bound in Nexus
at one-time enrollment. A copied bearer token alone cannot poll or report.
Full root compromise of the Sub host still permits signing from the live
manager; hardware-backed keys and independent authorization would be an
additional protection, not a claim of total compromise resistance.

This release intentionally does **not** weaken the trusted update manifest.
After source changes, an owner must offline sign new `release.json` and
`release.json.sig` with the **same existing trusted key**. CI rejecting
the old digest is expected; never change `release.pub`, skip signature
verification or download an unsigned installer to silence that failure.
New encrypted or authenticated client subscription URLs are not introduced;
those URLs remain sensitive bearer secrets and need rotation if stolen.
