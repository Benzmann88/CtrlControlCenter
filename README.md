# CTRL Control Center

Self-hosted web gateway with local user accounts, custom remote-site tiles and a dark dashboard.

## Deployment

1. Run `sh setup.sh` to generate a local `.env` and bootstrap password.
2. Edit `.env`: set your own base domain, bind address and port.
3. Run `docker compose up -d --build`.
4. Configure DNS and an HTTPS reverse proxy for both your base domain and its wildcard subdomains. Preserve the original Host header and enable WebSockets. The certificate must cover both names.
5. Sign in using the locally generated administrator credentials.

The default backend bind is loopback. A proxy on another host/container needs an explicitly reachable backend address and appropriate firewall rules. Do not expose the plain HTTP backend directly to the internet.

## Data and security

Users, password hashes, sessions, tiles, destination approvals and branding settings are stored in the deployment database, not distributed with this source export. A fresh deployment creates its own administrator and starts without tiles.

Keep `.env`, database volumes, backups, logs, certificates and private keys out of version control. Do not delete the persistent volume during upgrades.

This is an initial implementation, not an independently audited security product. Remote device interfaces may require device-specific proxy configuration. Use network-level restrictions in addition to application authentication. Shared tiles grant all portal users access through the gateway; device authentication remains separate.

## Publishing

This repository is a source-only export. Deployment data and old Git history are intentionally excluded. Review changes and scan for secrets before each publication. No open-source license is granted by this README; choose and add an appropriate license separately if desired.
