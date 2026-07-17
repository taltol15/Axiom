# Axiom Customer Getting Started

This guide is for administrators who are installing Axiom for the first time.

## Before You Begin

Prepare three Ubuntu/Debian servers:

```text
Axiom Management Server
Axiom SMB Node
Axiom DNS Node
```

For a first production-style validation, do not combine all roles on one server.
Keeping roles separate makes routing, troubleshooting, and security boundaries
much clearer.

## Required Information

Collect the following before installation:

| Item | Needed For |
| --- | --- |
| Management server IP | Admin portal and node enrollment |
| SMB node client-facing IP | Windows clients connect here |
| Backend file server IP | SMB node forwards traffic here |
| DNS node IP | DCs or clients forward DNS queries here |
| Upstream DNS resolver IPs | DNS node forwards allowed queries here |
| Management admin username/password | Initial Web UI login |
| TLS certificate and key, optional | HTTPS for management portal |
| Axiom license file, optional at install time | Production activation |

## Install Order

Install in this order:

1. Management Server
2. SMB Node
3. DNS Node

After the Management Server is installed, log in to the Web UI and copy the
node enrollment token from Settings. Use that token when installing SMB and DNS
nodes.

## First Login

Open the Management UI:

```text
https://<management-ip>:8443/
```

If HTTPS was not enabled during installation, use:

```text
http://<management-ip>:8443/
```

Use the admin credentials you created during installation.

## First Validation

After all nodes are installed:

1. Open the Nodes page.
2. Confirm SMB and DNS nodes are `online`.
3. Open Support.
4. Run Built-in Smoke Tests.
5. Export a Support Bundle and keep it with the deployment record.
6. Open Settings -> License Activation and install the signed license.

## SMB Validation

From a Windows test workstation:

1. Browse to `\\<smb-node-ip>\<share>`.
2. Copy a normal file.
3. Confirm SMB Protected Traffic increases in the Overview page.
4. Confirm SMB Protection -> Live Inspection Proof shows the file as observed,
   hashing, and then hashed with SHA256/MD5.
5. Confirm the file appears under SMB Protection -> File transfer ledger.
6. Add the file hash as `known_bad` in Security -> Reputation Center.
7. Set SMB reputation action to `block`.
8. Copy the same file again and confirm the transfer is blocked.

## DNS Validation

From a test client or DC:

1. Configure DNS to point to the DNS node.
2. Resolve a known legitimate domain.
3. Add a test blocked domain under DNS Security -> DNS policies.
4. Resolve that domain and confirm it is blocked.
5. Confirm the DNS query appears in DNS Security and Global Audit Log.

## Daily Operations

Use the Management UI for:

- Node health
- SMB and DNS policies
- Global audit timeline
- Reputation entries
- License status
- Support bundle export
- Backup and restore

Use SSH only for OS-level maintenance or support troubleshooting.
