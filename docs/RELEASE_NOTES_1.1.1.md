# Axiom 1.1.1

Hotfix for management UI freezes on upgraded servers with enrolled SMB/DNS nodes.

## Fix

- Trim heavy node telemetry when it is stored on the management server, not only when `/api/status` responds.
- Serialize status refreshes so concurrent dashboard polls cannot pile up.

## Verify after upgrade

```bash
/usr/local/bin/axiom-daemon --version   # must print 1.1.1
```

Login footer and dashboard footer must show `Axiom v1.1.1` and the Trustity byline under the Axiom wordmark.
