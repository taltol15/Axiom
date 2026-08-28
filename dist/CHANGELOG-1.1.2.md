# Axiom 1.1.2 — Management Console branding refresh

## Summary

Branding update for the Axiom Management Console. No functional or security changes beyond 1.1.1.

## What's new

- **Official Trustity Axiom logo** on the login page and dashboard header (replaces the previous inline SVG wordmark).
- **Updated footer** on login and dashboard:
  `Trustity Axiom - Management Console - Version 1.1.2 - Copyright © 2026 - https://trustity.co`

## Upgrade from 1.1.1

```bash
cd ~/Axiom && git fetch --tags && git checkout v1.1.2
sudo ./install.sh --repair
/usr/local/bin/axiom-daemon --version   # must print 1.1.2
```

Or run the customer installer on a clean server:

```bash
chmod +x axiom-installer-1.1.2.sh
sudo ./axiom-installer-1.1.2.sh
```

## Verify

- Login and dashboard show the Trustity Axiom logo.
- Footer displays version **1.1.2** and link to **https://trustity.co**.
- Management UI remains responsive after SMB/DNS nodes come online (1.1.1 fix retained).

## SHA256

`588f456ef2bc23b28a961330995c79b3e588436dee54b51ef8203a62e2844252`
