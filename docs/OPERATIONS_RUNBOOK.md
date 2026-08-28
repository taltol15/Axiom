# Axiom Operations Runbook

This runbook is intended for support engineers and customer operators.

## Service Health

```bash
sudo systemctl status axiom --no-pager
sudo journalctl -u axiom -n 160 -l --no-pager
sudo ss -ltnup | egrep ':8443|:9443|:445|:53'
```

Expected management listeners:

```text
TCP 8443 - Management UI
```

Expected data-plane listeners:

```text
TCP 9443 - Node control API
TCP 445  - SMB proxy node
UDP 53   - DNS node
TCP 53   - DNS node
```

## Management UI Troubleshooting

If the UI loads but freezes, navigation is sluggish, or Settings cannot show the
enrollment token / license activation file:

1. Check whether reverse DNS is enabled unintentionally:

```bash
sudo grep -n client_reverse_dns /etc/axiom/axiom.toml
```

If `client_reverse_dns = true` and the server cannot resolve client PTR records
quickly, disable it and restart:

```bash
sudo sed -i 's/client_reverse_dns = true/client_reverse_dns = false/' /etc/axiom/axiom.toml
sudo systemctl restart axiom
```

2. Confirm the status API responds quickly from the management host:

```bash
curl -sk -H "Authorization: Bearer <session-or-token>" https://127.0.0.1:8443/api/status -o /dev/null -w '%{time_total}s\n'
```

If the UI does not load:

```bash
sudo systemctl status axiom --no-pager
sudo journalctl -u axiom -n 120 -l --no-pager
sudo ss -ltnp | egrep ':8443'
```

If HTTPS was enabled and the browser fails, open the server locally over SSH and
temporarily disable HTTPS in `/etc/axiom/axiom.toml` under `[management.tls]`,
then restart:

```bash
sudo systemctl restart axiom
```

## Node Enrollment Troubleshooting

On the node:

```bash
sudo grep -nE 'role|management_url|enrollment_token|allow_invalid_management_tls|node.control|bind_ip|port' /etc/axiom/axiom.toml
sudo journalctl -u axiom -n 160 -l --no-pager | egrep -i 'node agent|heartbeat|runtime config|control|401|403|failed'
```

On the management server:

```bash
sudo journalctl -u axiom -n 160 -l --no-pager | egrep -i 'node|heartbeat|enroll|policy push|reputation'
```

Common causes:

- Enrollment token mismatch.
- Node points to `https://` while management is currently running `http://`.
- Self-signed management certificate is rejected by the node.
- Firewall blocks node -> management TCP 8443.
- Firewall blocks management -> node TCP 9443.

## SMB Troubleshooting

On the SMB node:

```bash
sudo ss -ltnp | grep ':445'
sudo ss -tnp | grep ':445'
sudo journalctl -u axiom -n 180 -l --no-pager | egrep -i 'SMB proxy|blocked SMB frame|reputation|stream blocked|hash completed'
ip -br addr
ip route
```

If counters stay at zero, verify clients connect to the SMB node IP, not the
backend NAS IP. Also check for NAT or forwarding rules that bypass the user-space
proxy.

In the management UI, use SMB Protection -> Live Inspection Proof to confirm the
proxy observed SMB CREATE/WRITE/CLOSE activity for the file. A healthy upload
should move from `observed` to `hashing` and then `hashed`. A reputation block
should show `blocked` with the matching SHA256.

## DNS Troubleshooting

On the DNS node:

```bash
sudo ss -lunp | grep ':53'
sudo ss -ltnp | grep ':53'
sudo journalctl -u axiom -n 180 -l --no-pager | egrep -i 'dns|upstream|blocked|cache|timeout'
dig @127.0.0.1 example.com
```

If browsing is slow, check upstream resolver latency and DNS policy blocks in the
management UI.

## Backup and Restore

Use Support -> Backup and Restore in the management UI for a configuration
export before major policy changes.

CLI backup:

```bash
sudo cp -a /etc/axiom/axiom.toml /etc/axiom/axiom.toml.manual-backup-$(date +%Y%m%d-%H%M%S)
```

## Support Bundle

Use Support -> Export Diagnostics from the management UI. The bundle includes
configuration path, process state, listener state, routes, recent activity, and
selected diagnostic command output.

## Repair Existing Installation

```bash
cd ~/Axiom
git pull --ff-only
sudo ./install.sh --repair
```

Use repair when the service binary, systemd unit, restart helper, or Linux
capabilities need to be refreshed while preserving customer configuration.
