# Axiom 1.1.5 — Fix npx requirement on customer Linux servers

## Summary

Fixes 1.1.4 installs that failed with `npx is required to build embedded Tailwind CSS` during source compilation on the target server.

## What's fixed

- Installer packages already ship embedded UI assets (Tailwind CSS + Trustity Axiom logo base64).
- `install.sh` no longer tries to rebuild Tailwind on the server when those assets are present.
- Node.js/npx is **not** required on customer servers.

## Install / repair

```bash
chmod +x axiom-installer-1.1.5.sh
sudo ./axiom-installer-1.1.5.sh
```

Expected during source build:
`Embedded UI assets found in package; skipping Tailwind rebuild on target server.`

## Verify

```bash
/usr/local/bin/axiom-daemon --version
strings /usr/local/bin/axiom-daemon | grep -i 'Trustity Axiom - Management Console'
sudo systemctl restart axiom
sudo grep client_reverse_dns /etc/axiom/axiom.toml
```

SHA256: `f3d29ec3a3651128f442d72ddcc5a7bee00076feb6bcdfd5d99b60db0187b4a7`
