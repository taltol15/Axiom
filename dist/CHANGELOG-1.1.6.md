# Axiom 1.1.6 — Supported customer baseline

Trustity Axiom branding, responsive management UI, reliable Linux install.

## Install

```bash
chmod +x axiom-installer-1.1.6.sh
sudo ./axiom-installer-1.1.6.sh
```

## Verify

```bash
/usr/local/bin/axiom-daemon --version
strings -a /usr/local/bin/axiom-daemon | grep -F trustity-axiom-logo
```

SHA256: `43c1608c2d7650e93b28d79b96ed8843644a373add5a76b76b18a54c9f05ad78`

Do not publish 1.1.0–1.1.5 to customers.
