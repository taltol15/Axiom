# Axiom Product Overview

Axiom is an enterprise security platform for protecting file-server and DNS
traffic inside segmented networks.

## What Axiom Protects

Axiom currently provides two data-plane services:

```text
SMB Protection  - Inline SMB reverse proxy for file-server traffic
DNS Security    - DNS forwarding, policy enforcement, local records, and logging
```

Both services are managed by a central Axiom Management Server.

## Core Architecture

```text
Administrators -> Axiom Management Server
                         |
                         | policy, licensing, reputation, telemetry
                         |
             +-----------+-----------+
             |                       |
       Axiom SMB Node          Axiom DNS Node
             |                       |
 Windows clients -> SMB node   Clients/DC -> DNS node
             |                       |
        File server/NAS          Upstream DNS resolver
```

## Management Server

The Management Server is the control plane. It provides:

- Web management console
- Local and optional Active Directory login
- Node enrollment
- Central policy management
- Reputation center
- License activation
- Global audit timeline
- Support diagnostics and backup/restore

The Management Server should be reachable by administrators and by Axiom nodes.
It does not need internet access for offline license activation.

## SMB Node

The SMB Node sits in front of a protected file server or NAS. Clients connect to
the SMB Node instead of connecting directly to the file server.

The node:

- Listens on TCP 445
- Forwards valid SMB traffic to the backend file server
- Tracks live SMB connections
- Extracts file names and SMB write sizes where possible
- Calculates streaming file hashes
- Checks known-bad reputation
- Enforces SMB policies
- Sends telemetry and audit events to the Management Server

## DNS Node

The DNS Node can sit between endpoints or domain controllers and upstream DNS
resolvers.

The node:

- Listens on UDP/TCP 53
- Applies local DNS policies
- Serves local DNS records
- Caches allowed responses
- Forwards allowed queries to upstream resolvers
- Logs DNS activity and blocks

## Reputation

The Management Server maintains a central reputation database. SMB nodes receive
known-bad hashes and can enforce the configured policy action when a streamed
file hash matches.

Supported reputation states:

- `known_good`
- `known_bad`
- `unknown`

Known-bad behavior is policy-driven:

- `alert`
- `block`
- `quarantine`
- `allow`

## Licensing

Axiom supports offline activation. Customer servers do not require internet
access:

1. Download `.axact` activation request from the Management UI.
2. Upload it to the customer portal or send it to Axiom support.
3. Receive a signed `.axlic` license.
4. Upload the `.axlic` file in the Management UI.

## Recommended Production Deployment

Use three servers:

```text
1 x Axiom Management Server
1 x Axiom SMB Node
1 x Axiom DNS Node
```

Single-server mode is intended for evaluation and controlled testing only.

