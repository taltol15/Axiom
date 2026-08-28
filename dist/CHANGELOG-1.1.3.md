# Axiom 1.1.3 — Clean install hotfix

## Summary

Fixes two issues reported on fresh installs labeled 1.1.2: legacy Axiom logo/footer and dashboard freeze after the first enrolled node heartbeat.

## What's fixed

- Customer installer now embeds a **pre-built Axiom 1.1.3 binary** (no compile-on-target drift).
- Node telemetry trim now removes heavy **`active_policy`** payloads from stored stats and `/api/status`.
- Installer verifies Trustity Axiom branding before completing.
- AD reverse-DNS prompt defaults to **No**.

## Install (clean server)

```bash
chmod +x axiom-installer-1.1.3.sh
sudo ./axiom-installer-1.1.3.sh
```

## Verify

```bash
/usr/local/bin/axiom-daemon --version
strings /usr/local/bin/axiom-daemon | grep -i 'Trustity Axiom - Management Console'
```

- Trustity Axiom PNG logo on login + dashboard
- Footer: `Trustity Axiom - Management Console - Version 1.1.3 - Copyright © 2026 - https://trustity.co`
- UI stays responsive after SMB/DNS nodes come online

## SHA256

`22de540056aeb5d5f16657c96e60854914f4967c298061da90b9cf21d7c7b9ce`
