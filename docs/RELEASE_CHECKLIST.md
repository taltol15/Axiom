# Axiom Release Readiness Checklist

Use this checklist before shipping a customer build.

## Build Integrity

- `cargo fmt --all --check`
- `cargo test --workspace`
- `cargo build --release -p axiom-daemon`
- `bash -n install.sh`
- `./scripts/build-installer.sh`
- `bash -n axiom-installer.sh`
- `./scripts/build-lab-installer.sh`
- `bash -n axiom-lab-installer.sh`

## Management Server

- Management UI loads on the configured interface.
- Login works with local admin.
- HTTPS can be enabled and disabled from Settings.
- License Activation downloads `.axact`.
- Signed `.axlic` installs successfully.
- Support -> Built-in Smoke Tests passes.
- Support -> Export Diagnostics downloads a JSON bundle.
- Backup export and restore work on a lab configuration.
- Customer-facing docs are current:
  - `docs/PRODUCT_OVERVIEW.md`
  - `docs/CUSTOMER_GETTING_STARTED.md`
  - `docs/CUSTOMER_INSTALLATION_GUIDE.md`

## Node Control Plane

- SMB node appears under Nodes.
- DNS node appears under Nodes.
- Node health transitions show online/stale/offline/degraded correctly.
- SMB policy push reports successful acknowledgement.
- DNS policy push reports successful acknowledgement.
- Reputation changes push known-bad feed to SMB nodes.

## SMB Data Plane

- Windows client can browse a protected share through the SMB node.
- Large file upload counters match the transferred file size.
- ZIP/RAR policy blocks when configured to block.
- Reputation known_bad hash blocks when policy action is block.
- Known_bad alert mode logs without blocking.
- Global Audit Log shows source IP, target, file, rule, and action.

## DNS Data Plane

- UDP and TCP DNS queries are answered.
- Local DNS records resolve as configured.
- Blocked domains are blocked according to DNS policy.
- Legitimate domains are forwarded to upstream resolvers.
- Cache hits and upstream errors are visible in the dashboard.

## Packaging

- Fresh management install succeeds.
- Fresh SMB node install succeeds.
- Fresh DNS node install succeeds.
- `sudo ./install.sh --repair` preserves configuration and restarts service.
- `sudo ./install.sh --uninstall` removes service and binaries while keeping data.
- `sudo ./install.sh --uninstall --purge` removes configuration, data, and logs.
- `axiom-installer.sh` is the customer-facing installer artifact.
- `axiom-lab-installer.sh` remains available only for compatibility and controlled lab use.

## Customer Readiness

- No customer-facing page describes the product as MVP.
- No customer-facing page documents a default production password.
- The management installer requires explicit admin credentials.
- Release evidence is captured according to `docs/VALIDATION_TEST_PLAN.md`.
