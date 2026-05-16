# Axiom

Axiom is an enterprise SMB reverse proxy MVP for Linux deployments with a
dedicated management NIC and isolated proxy NICs.

## Run

```bash
cargo check --workspace
cargo run -p axiom-daemon -- config/axiom.toml
```

## Lab Install

For an Ubuntu/Debian lab machine, copy and run the self-contained installer:

```bash
chmod +x axiom-lab-installer.sh
./axiom-lab-installer.sh
```

The installer embeds the full Axiom source tree, extracts it to a temporary
directory, discovers NICs interactively, writes `/etc/axiom/axiom.toml`, builds
the release binary, applies Linux capabilities, and starts `axiom.service`.

The default MVP management login is:

```text
username: admin
password: axiom-admin
```

On Linux, binding to TCP/445 and enforcing `SO_BINDTODEVICE` require network
capabilities. For production-style systemd deployment, grant the daemon
`CAP_NET_BIND_SERVICE` and the capability required by the kernel for device
binding, or run as root only during early lab validation.
