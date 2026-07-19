# Axiom Customer Installation Guide

This guide describes a fresh installation using the self-contained installer.

## Supported Operating Systems

Ubuntu/Debian family Linux distributions are supported.

The installer checks and installs required packages such as:

- Rust toolchain
- build tools
- `iproute2`
- `systemd`
- `setcap`
- `openssl`
- `pkg-config`
- `whiptail`

## Download Installer

Copy `axiom-installer.sh` to the server.

```bash
chmod +x axiom-installer.sh
```

## Install Management Server

Run:

```bash
sudo ./axiom-installer.sh
```

Choose:

```text
management
```

The installer asks for:

- Management interface
- Management IP and port
- HTTPS settings
- Optional Active Directory settings
- Initial admin username and password

When complete, open the Management UI and copy the enrollment token from
Settings.

## Create a Cluster Group

Install and verify the first SMB or DNS node normally. It becomes an available
source automatically; no reinstall or source-node cluster setting is required.

In the Management UI:

1. Open `Clusters`.
2. Enter a unique cluster name, such as `smb-production` or `dns-production`.
3. Select the service role and the reporting source node.
4. Set a join password of at least 12 characters.
5. Select the intended client traffic HA mode and optionally record the VIP or
   DNS service name.
6. Click `Create cluster`.

The join password is needed only while enrolling replicas. Existing replicas use
their own credentials and do not break when the join password is rotated.

## Install SMB Node

Run the installer on the SMB node:

```bash
sudo ./axiom-installer.sh
```

Choose:

```text
smb_proxy
```

The installer asks for:

- Management server URL
- Enrollment token
- Node ID and display name
- Node control interface and IP
- SMB listener interface and IP
- Backend file server IP

Expected result:

```text
TCP 445  listening on the SMB node client-facing IP
TCP 9443 listening for encrypted management control pushes
```

To add an SMB replica, choose `Join this node to an existing Axiom cluster` in
the installer. Enter the Management Server URL, cluster name, and join password.
The installer imports backend SMB routes and then asks only for this server's
local listener NIC/IP. Use a unique Node ID for every replica.

## Install DNS Node

Run the installer on the DNS node:

```bash
sudo ./axiom-installer.sh
```

Choose:

```text
dns
```

The installer asks for:

- Management server URL
- Enrollment token
- Node ID and display name
- DNS listener interface and IP
- Upstream resolver interface
- Upstream DNS resolvers
- Optional threat feeds

Expected result:

```text
UDP 53 listening on the DNS node IP
TCP 53 listening on the DNS node IP
TCP 80 listening after Branded block page policy is active
TCP 9443 listening for encrypted management control pushes
```

To add a DNS replica, choose the cluster enrollment path. The installer imports
upstream resolvers, ports, cache, and timeout settings and asks for this server's
local DNS listener NIC/IP and upstream egress NIC. Publish two or more DNS node
addresses to clients through DHCP or the DC's forwarder configuration.

## Verify Cluster Enrollment

Open `Clusters` in the Management UI and confirm:

- the source and replica are `online`
- configuration state is `Synced`
- `Sync now` completes and each reachable node acknowledges the policy push
- the new node also appears under `Nodes`

Rotating the join password does not rotate existing node credentials. Removing a
replica from the Cluster Center revokes that node's control-plane credential;
re-enrollment is required before it can report again.

Read `CLUSTER_AND_HIGH_AVAILABILITY_KB.md` before publishing a production SMB
VIP or multiple DNS addresses. It explains every Cluster Center option, load
balancer requirements, session persistence, client IP visibility, anti-bypass
firewall rules, failure behavior and acceptance testing.

Read `DNS_BLOCK_PAGE_KB.md` before enabling the branded DNS response. Client
networks must reach the DNS node or external block-page VIP on TCP 80, and HTTPS
certificate behavior must be included in the customer rollout plan.

## Repair Existing Installation

Use repair after pulling a new product release:

```bash
cd ~/Axiom
git pull --ff-only
sudo ./install.sh --repair
```

Repair mode preserves `/etc/axiom/axiom.toml`.

## Uninstall

Remove service and binaries, keeping configuration and logs:

```bash
sudo ./install.sh --uninstall
```

Remove service, binaries, configuration, logs, and state:

```bash
sudo ./install.sh --uninstall --purge
```
