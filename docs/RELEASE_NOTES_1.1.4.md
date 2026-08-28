# Axiom 1.1.4

Fix customer installer pre-built binary targeting the wrong operating system.

## Fixes

- Build customer packages with a **Linux x86_64 ELF** binary (Docker cross-build on macOS).
- If a bundled pre-built binary cannot execute on the target host, `install.sh` now **falls back to compiling from source** instead of failing after copying a bad binary to `/usr/local/bin/axiom-daemon`.

## Verify after install

```bash
/usr/local/bin/axiom-daemon --version   # must print 1.1.4
file /usr/local/bin/axiom-daemon        # must report ELF 64-bit x86-64
strings /usr/local/bin/axiom-daemon | grep -i 'Trustity Axiom - Management Console'
```

## Notes

- 1.1.3 customer packages built on macOS contained a Mach-O binary and failed on Linux with `did not report an Axiom version`.
- 1.1.4 retains the 1.1.3 telemetry trim and branding changes.
