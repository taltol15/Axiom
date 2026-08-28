# Axiom 1.1.6

Fix false install failures during UI branding verification on Linux.

## Fix

- Use `strings -a` and fixed-string grep markers (`trustity-axiom-logo`, `Trustity Axiom`) instead of a long footer match that failed on some Linux builds.
- Verify the freshly built release binary before copying it to `/usr/local/bin/axiom-daemon`.

## Verify after install

```bash
/usr/local/bin/axiom-daemon --version
strings -a /usr/local/bin/axiom-daemon | grep -F trustity-axiom-logo
sudo systemctl restart axiom
```
