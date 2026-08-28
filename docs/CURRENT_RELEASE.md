# Axiom current release

**Supported customer baseline: 1.1.6** (`v1.1.6`)

## Customer install

Download `axiom-installer-1.1.6.sh` from **Trustity Dev → Downloads** (see
`trustity-dev-central` docs: Axiom customer installer).

```bash
chmod +x axiom-installer-1.1.6.sh
sudo ./axiom-installer-1.1.6.sh
```

SHA-256: `43c1608c2d7650e93b28d79b96ed8843644a373add5a76b76b18a54c9f05ad78`

## Build a customer package (maintainers)

```bash
git checkout v1.1.6
./scripts/build-customer-package.sh 1.1.6
```

Requires Node.js (`npx`) on the **build machine** for embedded Tailwind CSS.
Target Linux servers do not need Node.js when installing from the customer
package.

Optional: install Docker on the build machine so
`scripts/build-linux-release.sh` can embed a Linux x86_64 prebuilt binary.
Without Docker on macOS, the package compiles from source on the customer
server (supported path validated on Ubuntu 26.04 lab).

## Verify after install

```bash
/usr/local/bin/axiom-daemon --version
strings -a /usr/local/bin/axiom-daemon | grep -F trustity-axiom-logo
sudo grep client_reverse_dns /etc/axiom/axiom.toml
sudo systemctl status axiom --no-pager
```

## Do not publish to customers

Versions **1.1.0 – 1.1.5** had packaging or Linux install verification issues.
Use **1.1.6** for all new lab simulations and customer rollouts.

## Release notes

- `docs/RELEASE_NOTES_1.1.6.md` — current baseline
- `docs/RELEASE_NOTES_1.1.5.md` and earlier — historical only
