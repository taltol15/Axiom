# Axiom 1.1.3

Hotfix for clean installs that still showed legacy branding or froze after SMB/DNS nodes enrolled.

## Fixes

- **Customer installer now ships a pre-built `axiom-daemon` binary** instead of compiling on the target server, so the installed UI always matches the published package.
- **Strip `active_policy` from stored node telemetry** — the 1.1.1 trim kept full policy configs in memory and `/api/status` responses, which could still freeze the dashboard after the first node heartbeat.
- **Installer verification** — `install.sh` fails fast if the installed binary is missing Trustity Axiom branding or still contains the legacy footer text.
- **Active Directory wizard** — reverse DNS for client names now defaults to **No** instead of Yes.

## Verify after install

```bash
/usr/local/bin/axiom-daemon --version   # must print 1.1.3
strings /usr/local/bin/axiom-daemon | grep -i 'Trustity Axiom - Management Console'
sudo grep client_reverse_dns /etc/axiom/axiom.toml   # should be false unless you opted in
```

Login and dashboard must show the Trustity Axiom PNG logo and the updated footer. After an SMB or DNS node enrolls, the UI must remain responsive.
