# Axiom 1.1.6

**Supported customer baseline** — Trustity Axiom branding, stable management UI after node enrollment, and reliable Linux installs.

## Summary

- Trustity Axiom logo and updated management console footer
- Node telemetry trim (`active_policy` removal) prevents dashboard freeze after SMB/DNS heartbeats
- Customer installs on Linux without Node.js/npx on the target server
- Install verification fixed for Ubuntu/Debian source builds

## Fixes in the 1.1.3 – 1.1.6 packaging line

| Version | Note |
| --- | --- |
| 1.1.3 | Prebuilt binary was macOS-only — do not use |
| 1.1.4 | Required `npx` on target server — do not use |
| 1.1.5 | False-negative branding verify after successful compile — do not use |
| **1.1.6** | **Supported baseline** |

## Verify after install

```bash
/usr/local/bin/axiom-daemon --version
strings -a /usr/local/bin/axiom-daemon | grep -F trustity-axiom-logo
sudo grep client_reverse_dns /etc/axiom/axiom.toml
sudo systemctl restart axiom
```

Login and dashboard must show the Trustity Axiom logo and footer with version **1.1.6**. The UI must stay responsive after SMB/DNS nodes enroll.

## Customer package

```bash
./scripts/build-customer-package.sh 1.1.6
```

Upload `dist/axiom-installer-1.1.6.sh` to Trustity Dev → Admin → Downloads.

