# Security and migration

- Do not deploy Nexus administrator endpoints on the public Sub hostname. Route ACLs accept only bearer subscription paths.
- Only GET and HEAD are forwarded. URL tokens are credentials; never put full URLs in monitoring, logs, or issues.
- Nexus decides authentication, user status, expiry, and quotas on every request. No stale cached subscriptions.
- Both the customer-facing edge and the upstream Nexus connection use verified TLS.
- Do not place panel database passwords, TOTP keys, subscription encryption keys, or admin tokens on the edge.
- Review upstream infrastructure, custom reverse proxies, CDN, WAF and cloud access logging independently.
- Keep existing subscription links unchanged until a canary import works. Migrate DNS only when clients can reach the new endpoint.
- Running a remote installer as root is sensitive: review and pin a vetted commit before production.
- Stage 1 is a separate HTTPS delivery boundary. It is not an autonomous generator, a node agent, or an offline cache.
