# Axiom Cluster and High Availability Knowledge Base

## Purpose

This document explains how Axiom clusters work, what Axiom synchronizes, what
must be supplied by the surrounding network, and how to build a production HA
deployment without creating an inspection bypass.

The most important distinction is:

> An Axiom cluster is a control-plane configuration and policy group. Client
> traffic high availability is provided by DNS client configuration, an
> external load balancer, or an external VIP mechanism.

Axiom does not silently create a floating IP, configure a third-party load
balancer, or modify customer routing.

## Architecture Layers

| Layer | Owner | Function |
| --- | --- | --- |
| Management control plane | Axiom Management Server | Enrollment, policy, credentials, inventory, audit, licensing, cluster state |
| DNS data plane | Axiom DNS Nodes | DNS filtering, cache, local DNS, upstream forwarding, block page |
| SMB data plane | Axiom SMB Nodes | TCP/445 proxy, SMB parsing, streaming inspection, policy and reputation enforcement |
| Traffic entry point | Customer network | DNS server list, load balancer, VIP, routing, firewall and health checks |
| Protected backend | Customer network | File server/NAS or upstream DNS/DC reachable only through approved paths |

## Cluster Terminology

### Source Node

The Source Node is an already enrolled and reporting `dns` or `smb_proxy` node.
It provides the shared service template when the cluster is created.

The Source Node is not a leader in the consensus-database sense. It does not
forward traffic to replicas and replicas do not depend on it to process client
traffic. If it is offline, existing replicas continue serving traffic with the
configuration and policy already installed on them.

### Replica Node

A Replica is a new node enrolled through the cluster join workflow. During
installation it receives:

- A unique per-node enrollment credential.
- The cluster role and identity.
- The shared service template captured from the Source Node.
- The current centrally managed policy.
- The current known-bad reputation feed for SMB clusters.

The installer then asks for local NIC and IP values because those settings are
specific to the new Linux machine.

### Cluster Group

A Cluster Group contains exactly one service role: `dns` or `smb_proxy`. Do not
mix DNS and SMB nodes in one group. A node ID may belong to only one group.

### Service Template

The template contains settings that should be logically equal across replicas.

For SMB clusters it contains:

| Setting | Meaning |
| --- | --- |
| Route name | Logical proxy route name |
| Client VLAN | Optional route metadata |
| Listen port | Normally TCP 445 |
| Target file server IP and port | Protected NAS/file-server backend |
| Backlog | Kernel accept queue target |

For DNS clusters it contains:

| Setting | Meaning |
| --- | --- |
| UDP/TCP ports | Normally 53 |
| Upstream resolvers | Internal DC/DNS or approved external resolvers |
| Cache TTL and maximum entries | Resolver cache behavior |
| Query timeout | Upstream timeout before failover |
| Threat-feed refresh interval | Refresh schedule, not the feed policy itself |

The template deliberately excludes local NIC names, local listener IPs,
management/control IPs, and upstream egress NICs.

## Cluster Center Options

### Cluster Name

A unique stable identifier containing letters, numbers, `-`, or `_`. Use a name
that identifies the service and environment, for example:

```text
dns-production
smb-finance
smb-dr-site
```

The name is entered again when a replica joins. Renaming is intentionally not a
normal operation because the name is part of node membership identity.

### Service Role

Choose `DNS` for resolver nodes or `SMB Proxy` for TCP/445 inspection nodes. The
selected Source Node must report the same role and a usable service template.

### Source Node

Choose a healthy reporting node whose backend/upstream settings represent the
desired baseline. The Source Node must already appear under `Nodes`.

Creating a cluster takes a snapshot of that node's current shared service
template. It does not modify or restart the Source Node.

### Join Password

The temporary shared secret used only to approve new replica enrollment.

Requirements and behavior:

- Minimum length is enforced by the Management Server.
- The Management Server stores an Argon2 password hash, never the plaintext.
- Failed join attempts are rate limited and temporarily locked out.
- A successful join returns a new unique credential for that node.
- Changing the join password affects future joins only.
- Existing nodes keep their unique credential and continue reporting.

Use HTTPS for the Management URL in production. HTTP cluster enrollment exposes
the join password to any device capable of observing that network path.

### Traffic HA Mode

This field records the intended production traffic design. It is operational
metadata and does not configure the external device.

#### External Load Balancer / VIP

Recommended for SMB. Clients connect to one stable TCP/445 address. A Layer 4
load balancer selects an available Axiom SMB node.

#### Multiple DNS Addresses

Recommended for DNS. Publish two or more Axiom DNS node addresses through DHCP,
static network configuration, or the DC forwarder configuration. Client and DC
resolver behavior decides which address is queried.

#### Direct

Clients connect directly to an individual node address. Use for labs, dedicated
segments, controlled maintenance, or an environment where another system owns
selection outside the recorded Axiom topology.

### Service Endpoint

Optional documentation of the address clients use, such as:

```text
files.company.internal
10.40.50.20
dns-security.company.internal
```

The field does not create a DNS record, VIP, listener, or load-balancer pool.

### Sync Now

`Sync now` performs two control-plane actions:

1. Refreshes the stored shared service template from the reporting Source Node.
2. Pushes the current central policy to every reachable member and records each
   acknowledgement.

For SMB it also pushes the current known-bad reputation feed.

Local network settings are never overwritten. Existing nodes whose reported
service template differs from the refreshed cluster template are shown as
configuration drift. Correct the shared service settings during an approved
maintenance window; local NIC/IP values must remain node-specific.

### Change Join Password

Replaces the Argon2 hash used for future joins. It does not rotate existing node
credentials and does not interrupt traffic.

### Remove Member

Revokes that replica's cluster credential on the Management Server. The process
already running on the node may continue serving its locally installed policy,
but it can no longer authenticate normal cluster control/reporting. Remove the
node from the LB/DNS client configuration and decommission or re-enroll it.

### Delete Cluster

Removes the group definition and member credentials from management. It does not
shut down nodes, remove them from an external LB, or delete their local config.
Drain traffic first and treat deletion as a controlled decommission operation.

## Health and Synchronization Indicators

| Indicator | Exact meaning |
| --- | --- |
| Online | Last node report received within 15 seconds |
| Degraded | Last report is 16-45 seconds old |
| Offline | Last report is more than 45 seconds old or never received |
| Synced | Node-reported shared service template equals the stored cluster template |
| Configuration drift | Shared service template differs; local NIC/IP differences are not part of this comparison |
| Push accepted | Node authenticated, decrypted, validated and applied the policy bundle |
| Push failed | Management could not reach the control listener or the node rejected the update |

Health is control-plane health. Always pair it with LB/DNS service health checks
that validate the client-facing data plane.

## SMB High Availability with an External Load Balancer

### Required LB Behavior

Use a Layer 4 TCP load balancer. Configure:

| LB setting | Recommended value |
| --- | --- |
| Frontend | Stable VIP on TCP 445 |
| Backends | Client-facing IP of every Axiom SMB node on TCP 445 |
| Protocol | Raw TCP; no HTTP mode and no TLS termination |
| Persistence | Source-IP or 5-tuple persistence for the lifetime of the SMB connection |
| Health check | TCP connect to node port 445; optionally add an external synthetic SMB check |
| Idle timeout | Long enough for persistent SMB sessions; start at 30 minutes or higher |
| Connection draining | Enabled before maintenance or removal |
| PROXY protocol | Disabled; Axiom expects the first bytes to be SMB, not a PROXY header |

SMB sessions are stateful. Never move an established TCP connection between
nodes. New connections may use any healthy node.

### Client IP Visibility

In normal SNAT load-balancer mode, Axiom sees the LB address as the TCP peer.
This reduces per-client attribution. To preserve the source IP, use a
load-balancer transparent/DSR design only after validating return routing and
anti-bypass rules in the customer's environment.

Axiom does not currently accept a PROXY-protocol header on TCP 445. Enabling it
will corrupt the SMB stream and cause connection failure.

### Anti-Bypass Firewall Rules

Production policy should enforce:

```text
Clients/VLANs -> SMB VIP or Axiom SMB nodes TCP 445: ALLOW
Clients/VLANs -> File server/NAS TCP 445: DENY
Axiom SMB nodes -> File server/NAS TCP 445: ALLOW
Management -> Axiom node control TCP 9443: ALLOW
Axiom nodes -> Management TCP 8443: ALLOW
```

The backend file server must not advertise or provide an alternate client path.
Continue blocking SMB multichannel discovery paths that could direct Windows
clients around the proxy.

### SMB Failure Scenarios

| Failure | Expected behavior |
| --- | --- |
| One SMB node fails | Existing sessions on that node fail; new sessions go to healthy nodes |
| Management fails | Existing SMB nodes continue with installed config, policy and cache |
| Source Node fails | Replicas continue; cluster template cannot refresh from source until recovery |
| File server fails | All nodes fail to reach the same backend; cluster does not replace backend HA |
| LB fails | Service endpoint fails unless the LB/VIP platform is itself redundant |

## DNS High Availability

### Preferred Design

Publish at least two Axiom DNS node IPs. Common patterns are:

```text
Endpoint DHCP option 6 -> DNS-Node-1, DNS-Node-2
DC DNS forwarders      -> DNS-Node-1, DNS-Node-2
```

Do not assume clients use the first address until it fails. Operating systems
may race, rotate, prefer, or periodically probe configured resolvers.

### DNS Health Checks

A meaningful check should send a real UDP or TCP query and validate a response.
A TCP connect to port 53 proves only that the listener accepted a connection.

Recommended checks:

- Query an approved external domain through the normal upstream path.
- Query an Axiom local DNS record.
- Query a dedicated blocked test domain and verify the expected response.
- For block-page mode, verify TCP 80 on every node from client networks.

### DNS Block Page in a Cluster

When `Block Page IPv4` is blank, the policy stores `0.0.0.0`, which means
automatic mode. Every DNS node returns its own local DNS listener IPv4 address
for a blocked A query and serves the page on TCP 80.

This makes one central policy portable across replicas.

If an external block-page VIP is used, enter that explicit IPv4 address. Axiom
will return the external address and will not bind its local TCP 80 listener for
that policy.

All client networks must be able to route to the returned block-page address.

## Policy and Configuration Propagation

### Continuously Managed Data

- DNS domain rules and actions.
- DNS threat feed URLs.
- DNS local records.
- DNS block response and branded block page.
- SMB inspection policy.
- SMB reputation action.
- Known-bad SHA-256 feed.

These are pushed after an administrator saves them. Nodes also pull periodically
as a recovery path if an active push was missed.

### Node-Local Data

- Linux NIC name.
- Listener IP.
- Control API bind IP.
- Upstream egress NIC.
- TLS trust choice for the Management Server.
- Local systemd and host firewall state.

These values cannot be copied safely because every server has a different
network identity.

## Air-Gapped Operation

Cluster control requires only internal connectivity. No internet service is
required for:

- Node enrollment.
- Policy push and recovery pull.
- Reputation feed synchronization from Management to SMB nodes.
- DNS local records.
- Embedded block-page logos.
- Offline licensing.

Internet connectivity is needed only when a DNS policy intentionally downloads
external threat feeds or forwards queries to public resolvers. In a fully
air-gapped deployment, use internal upstream DNS and import intelligence through
approved offline processes.

## Ports and Network Matrix

| Source | Destination | Port | Purpose |
| --- | --- | --- | --- |
| Administrators | Management | TCP 8443 | Web UI/API |
| DNS/SMB nodes | Management | TCP 8443 | Heartbeat, pull, enrollment and reporting |
| Management | DNS/SMB nodes | TCP 9443 | Authenticated encrypted policy push |
| DNS clients/DC | DNS nodes | UDP/TCP 53 | DNS service |
| Client networks | DNS nodes or block VIP | TCP 80 | HTTP block page |
| DNS nodes | Upstream DNS | UDP/TCP 53 | Allowed query forwarding |
| SMB clients/LB | SMB nodes | TCP 445 | Proxied SMB session |
| SMB nodes | File server/NAS | TCP 445 | Protected backend session |

Use HTTPS on Management. Restrict TCP 9443 so only Management Server addresses
can reach it.

## Five-Node Example

### Five SMB Nodes

1. Install Management and the first SMB node.
2. Confirm the first node is reporting and proxying the intended backend.
3. Create `smb-production` with that node as Source.
4. Install four additional `smb_proxy` nodes using cluster enrollment.
5. Give every replica a unique Node ID, local listener IP, and control IP.
6. Add all five client-facing TCP/445 addresses to the external LB pool.
7. Configure session persistence, health checks, idle timeout, and draining.
8. Publish only the VIP to clients.
9. Deny direct client TCP/445 access to the backend.
10. Test transfer, policy block, node drain, node loss, and restoration.

### Five DNS Nodes

1. Install the first DNS node and validate upstream resolution.
2. Create `dns-production` with that node as Source.
3. Install four replicas through cluster enrollment.
4. Assign unique DNS listener and control IPs.
5. Publish at least two addresses to each client/DC; distribute all five where
   the client platform and operational model support it.
6. Save a dedicated blocked test domain and confirm all nodes acknowledge.
7. Test allowed queries, blocked queries, local records, block page and upstream
   failover against every node.

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Source Node missing in create form | Node not reporting or wrong role | Check Nodes, token, TCP 8443 and node logs |
| Cluster join returns 401 | Wrong name/password/role or stale URL | Re-enter exact values; verify Management HTTPS trust |
| Cluster join returns 429 | Failed-attempt throttle | Wait for lockout expiry and correct credentials |
| Replica is online but drifted | Shared service template differs | Compare backend/upstream settings and plan correction |
| Policy push fails | TCP 9443 blocked, wrong control URL, credential mismatch | Test reachability and inspect last push response |
| SMB works only when one node is selected | LB is moving sessions or using HTTP mode | Use raw TCP with persistence |
| Axiom logs show LB IP only | LB SNAT mode | Accept reduced attribution or validate transparent LB design |
| DNS blocks work but page does not open | TCP 80 blocked or returned IP unreachable | Open TCP 80 and verify routing to the sinkhole IP |
| HTTPS blocked site shows certificate error | Expected TLS validation behavior | Use browser policy/approved TLS inspection or accept DNS-only block UX |
| Removing a node did not stop traffic | External LB/DNS still points to it | Drain and remove it from customer traffic infrastructure |

## Production Acceptance Checklist

- Every node has a unique Node ID and IP identity.
- Management uses a trusted HTTPS certificate.
- TCP 9443 is reachable only from Management.
- Cluster join password has been rotated after commissioning.
- Every node is Online and Synced.
- Every policy push shows an accepted acknowledgement.
- The external LB/VIP platform is redundant.
- SMB session persistence and drain behavior are verified.
- Direct client-to-file-server SMB access is denied.
- DNS clients receive multiple resolver addresses.
- DNS UDP and TCP paths are tested.
- Blocked HTTP and HTTPS behavior is documented for users.
- Offline operation has been tested if required.
- Backup and restore of Management configuration and license are validated.
