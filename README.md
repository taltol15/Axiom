# Axiom

Axiom is an enterprise SMB reverse proxy and DNS security gateway MVP for Linux
deployments with a dedicated management NIC, isolated SMB proxy NICs, and an
optional DNS NIC that can sit in front of internal DC DNS resolvers.

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

During installation, the DNS Security Gateway can be enabled on a dedicated NIC.
Axiom listens on UDP/TCP 53, checks domains against local policy and configured
threat feeds, caches safe responses, and forwards allowed queries to the
configured internal DC/upstream DNS servers.

## Policies

The management UI includes runtime policy controls for SMB archive detection,
entropy detection, and custom byte signatures. Each rule can be set to
`disabled`, `monitor`, or `block`. Policy changes are applied immediately and
persisted back to `/etc/axiom/axiom.toml`.

The same dashboard also shows DNS query volume, DNS blocks, cache hits, upstream
errors, and recent DNS activity by client/domain/action.

The default MVP management login is:

```text
username: admin
password: axiom-admin
```

On Linux, binding to TCP/445 and enforcing `SO_BINDTODEVICE` require network
capabilities. For production-style systemd deployment, grant the daemon
`CAP_NET_BIND_SERVICE` and the capability required by the kernel for device
binding, or run as root only during early lab validation.
