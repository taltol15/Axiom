# Axiom Production Deployment Guide

This guide describes the recommended production-style deployment for Axiom.

## Recommended Topology

Axiom supports single-server evaluation mode, but production deployments should
split roles across at least three servers:

```text
Axiom Management Server  - Web UI, licensing, policies, reputation, node registry
Axiom SMB Proxy Node     - Inline SMB reverse proxy data plane
Axiom DNS Security Node  - DNS forwarding and filtering data plane
```

The management server should be reachable from administrator workstations and
from enrolled Axiom nodes. SMB and DNS nodes should be reachable only from the
internal networks they protect and from the management server.

## Cluster and High Availability Topology

Axiom cluster groups synchronize service templates, policy, reputation, node
identity, and health through the Management Server. The Management Server is the
control-plane source of truth; an SMB or DNS source node is used to seed the
service template and is not a permanent data-plane dependency for its replicas.

Recommended client traffic designs:

| Service | Recommended HA entry point |
| --- | --- |
| DNS | Publish two or more Axiom DNS node addresses through DHCP/DC DNS settings |
| SMB | External L4 load balancer or VIP on TCP 445 with source/session affinity |

Do not assign the same service IP directly to multiple Linux nodes unless an
approved VRRP/load-balancing design owns address failover. Axiom records the
cluster endpoint and health but does not configure external network appliances.

Each replica retains its last installed local configuration and policy if the
Management Server is temporarily unavailable. Cluster enrollment and policy
changes require Management Server reachability, while existing DNS/SMB traffic
continues on the data plane.

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

Cluster join uses the existing Management UI/API port, TCP 8443. Require HTTPS
for production enrollment and restrict TCP 8443/9443 to administrator and Axiom
node networks. No Internet connectivity is required for cluster operation.

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

For clustered deployments, create the group only after its source node is
online. Install each replica with a unique Node ID, choose cluster enrollment,
and verify `Clusters` shows `online`, `Configuration: Synced`, and a successful
policy push acknowledgement.

Use `docs/CUSTOMER_INSTALLATION_GUIDE.md` for the full installation walkthrough
and `docs/VALIDATION_TEST_PLAN.md` for acceptance testing.

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
