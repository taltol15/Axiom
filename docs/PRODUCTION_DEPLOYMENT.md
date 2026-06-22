# Axiom Production Deployment Guide

This guide describes the recommended production-style deployment for Axiom.

## Recommended Topology

Axiom supports single-server lab mode, but production deployments should split
roles across at least three servers:

```text
Axiom Management Server  - Web UI, licensing, policies, reputation, node registry
Axiom SMB Proxy Node     - Inline SMB reverse proxy data plane
Axiom DNS Security Node  - DNS forwarding and filtering data plane
```

The management server should be reachable from administrator workstations and
from enrolled Axiom nodes. SMB and DNS nodes should be reachable only from the
internal networks they protect and from the management server.

## Network Flows

| Source | Destination | Port | Purpose |
| --- | --- | --- | --- |
| Admin workstation | Management server | TCP 8443 | Axiom Web UI |
| SMB node | Management server | TCP 8443 | Heartbeat, telemetry, runtime config recovery |
| DNS node | Management server | TCP 8443 | Heartbeat, telemetry, runtime config recovery |
| Management server | SMB node | TCP 9443 | Encrypted policy and reputation push |
| Management server | DNS node | TCP 9443 | Encrypted DNS policy push |
| SMB clients | SMB node | TCP 445 | Protected SMB access |
| SMB node | File server or NAS | TCP 445 | Backend SMB connection |
| DC or clients | DNS node | UDP/TCP 53 | Protected DNS queries |
| DNS node | Upstream resolver | UDP/TCP 53 | Allowed DNS forwarding |
| Operators | Any Axiom server | TCP 22 | SSH maintenance, optional |

## Internet Access

The management server does not require internet access for offline licensing.
It may need controlled outbound access for OS updates if no internal package
mirror exists.

The SMB node should not need internet access.

The DNS node needs outbound DNS access only if it forwards to public resolvers
or downloads external threat feeds. If an internal DC is the upstream resolver,
internet access should stay on the DC or the organization's DNS egress path.

## Fresh Install Sequence

1. Install the management server first.
2. Open the management UI and copy the enrollment token from Settings.
3. Install the SMB node and enroll it to the management server.
4. Install the DNS node and enroll it to the management server.
5. Confirm the Nodes page shows all nodes as online.
6. Run Support -> Built-in Smoke Tests.
7. Configure SMB and DNS policies.
8. Activate the customer license under Settings -> License Activation.

## Upgrade and Repair

For a normal source update:

```bash
cd ~/Axiom
git pull --ff-only
sudo ./install.sh --repair
```

`--repair` preserves `/etc/axiom/axiom.toml`, rebuilds the binary, refreshes the
systemd unit and helper files, and restarts the service.

## Rollback

Before overwriting configuration, the installer writes a timestamped backup:

```text
/etc/axiom/axiom.toml.bak-YYYYMMDD-HHMMSS
```

To roll back configuration:

```bash
sudo cp /etc/axiom/axiom.toml.bak-YYYYMMDD-HHMMSS /etc/axiom/axiom.toml
sudo systemctl restart axiom
```

## Uninstall

Remove service and binaries while keeping configuration, logs, and state:

```bash
sudo ./install.sh --uninstall
```

Remove service, binaries, configuration, logs, and state:

```bash
sudo ./install.sh --uninstall --purge
```

