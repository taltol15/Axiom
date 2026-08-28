# Axiom 1.1.0

First customer-ready release with management UI stability fixes for lab and air-gapped deployments.

## Highlights

- Management UI no longer freezes under fleet telemetry load
- Reverse DNS disabled by default on fresh installs
- Embedded offline Tailwind CSS (no CDN dependency)
- Trustity co-branding in the management console
- Self-contained `axiom-installer.sh` for customer deployment

## Build

```bash
./scripts/build-customer-package.sh 1.1.0
```

## Upgrade

```bash
cd ~/Axiom && git pull && git checkout v1.1.0
cargo build --release -p axiom-daemon
sudo install -m 755 target/release/axiom-daemon /usr/local/bin/axiom-daemon
sudo systemctl restart axiom
```

Or reinstall with `install.sh --repair` from a fresh checkout.
