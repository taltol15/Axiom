# Axiom Validation Test Plan

Use this plan for the current three-server test environment.

## Phase 1 - Management Server

Run after updating the management server.

### Commands

```bash
cd ~/Axiom
git pull --ff-only
sudo ./install.sh --repair
sudo systemctl status axiom --no-pager
sudo ss -ltnp | egrep ':8443'
```

### Expected Results

- `axiom.service` is active.
- Management UI loads.
- Login works.
- Settings -> License Activation is visible.
- Support -> Release Readiness is visible.
- Support -> Built-in Smoke Tests runs.
- Support -> Export Diagnostics downloads a JSON file.

## Phase 2 - SMB Node

Run after the Management Server is healthy.

### Commands

```bash
cd ~/Axiom
git pull --ff-only
sudo ./install.sh --repair
sudo systemctl status axiom --no-pager
sudo ss -ltnp | egrep ':445|:9443'
```

### Expected Results

- `axiom.service` is active.
- TCP 445 listens on the SMB node client-facing IP.
- TCP 9443 listens on the node control IP.
- Management UI -> Nodes shows the SMB node as `online`.
- Management UI -> Overview shows SMB Protected Traffic after a file copy.

### Functional Test

1. From Windows, browse to `\\<smb-node-ip>\<share>`.
2. Copy a normal file larger than 40 MB.
3. Confirm Overview -> SMB Protected Traffic increases by roughly that size.
4. Confirm SMB Protection -> Live Inspection Proof shows the file with:
   - `hashing` while data is flowing.
   - `hashed` after the SMB close/finalization is observed.
   - SHA256/MD5 populated for the file stream.
5. Confirm SMB Protection -> File transfer ledger shows the file.
6. Add the file SHA256 as `known_bad` in Security -> Reputation Center.
7. Set SMB reputation policy action to `block`.
8. Copy the same file again.

Expected:

- Windows copy is interrupted.
- Global Audit Log shows `REPUTATION VERDICT` with action `BLOCK`.
- SMB Protection -> Live Inspection Proof shows `blocked` for the file.
- SMB node logs include `blocked SMB frame by known bad reputation hash`.

## Phase 3 - DNS Node

Run after the Management Server is healthy.

### Commands

```bash
cd ~/Axiom
git pull --ff-only
sudo ./install.sh --repair
sudo systemctl status axiom --no-pager
sudo ss -lunp | grep ':53'
sudo ss -ltnp | egrep ':53|:9443'
```

### Expected Results

- `axiom.service` is active.
- UDP/TCP 53 listen on the DNS node IP.
- TCP 9443 listens on the node control IP.
- Management UI -> Nodes shows the DNS node as `online`.

### Functional Test

From a test endpoint or DC:

```bash
nslookup example.com <dns-node-ip>
```

Then add a blocked domain in DNS Security -> DNS policies and query it.

Expected:

- Legitimate domain resolves.
- Blocked test domain is denied according to policy.
- DNS Security -> Live DNS queries shows the queries.
- Global Audit Log shows DNS events.

## Phase 4 - Control Plane Push

Run after both nodes are online.

1. Change an SMB policy and click Save.
2. Confirm the push progress reaches success.
3. Change a DNS policy and click Save.
4. Confirm the push progress reaches success.

Expected:

- Nodes page shows latest push OK.
- No node is `degraded`.
- Policy generation changes in Runtime Enforcement.

## Phase 5 - Release Evidence

Before calling the build ready:

1. Run Support -> Built-in Smoke Tests.
2. Export Support Bundle.
3. Export Backup.
4. Save screenshots of:
   - Overview
   - Nodes
   - SMB Protection
   - DNS Security
   - Security -> Reputation Center
   - Global Audit Log
   - Support -> Release Readiness
