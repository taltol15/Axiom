# Axiom 1.1.5

Fix source builds on customer Linux servers that do not have Node.js/npx installed.

## Fix

- Customer installs no longer run `npx tailwindcss` on the target server when the installer package already contains embedded UI assets.
- Keeps 1.1.4 Linux prebuilt fallback behavior and 1.1.3 telemetry/branding fixes.

## Verify after install

```bash
/usr/local/bin/axiom-daemon --version   # must print 1.1.5
strings /usr/local/bin/axiom-daemon | grep -i 'Trustity Axiom - Management Console'
sudo systemctl restart axiom
```
