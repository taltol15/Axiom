# Axiom 1.1.4 — Linux installer fix

## Summary

Fixes 1.1.3 installs that failed on Linux with `axiom-daemon did not report an Axiom version` because the bundled pre-built binary was built for macOS.

## What's fixed

- Customer package build targets **Linux x86_64 ELF** (Docker cross-build when packaging on macOS).
- `install.sh` tests the bundled binary before installing it and **falls back to source build** when it cannot execute on the target host.
- Keeps 1.1.3 fixes: Trustity Axiom branding, telemetry trim, install verification.

## Install

```bash
chmod +x axiom-installer-1.1.4.sh
sudo ./axiom-installer-1.1.4.sh
```

Expected on Linux when no compatible prebuilt is bundled:
`Pre-built package binary is not compatible with this host; building from source instead...`

## Verify

```bash
/usr/local/bin/axiom-daemon --version
file /usr/local/bin/axiom-daemon
strings /usr/local/bin/axiom-daemon | grep -i 'Trustity Axiom - Management Console'
```

## SHA256

`1670349a8dc99f78d87d6c251d28716777b8bfc3eec4d4915b7553e6d9925f79`
