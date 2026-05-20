# Axiom

Axiom is an enterprise SMB reverse proxy and DNS security gateway MVP for Linux
deployments with a dedicated management NIC, isolated SMB proxy NICs, and an
optional DNS NIC that can sit in front of internal DC DNS resolvers.

## Deployment Roles

The recommended production-style lab uses at least three Axiom servers:

```text
Axiom Management Server  - Web UI, policy control plane, node registry
Axiom DNS Node           - DNS Security data plane
Axiom SMB Proxy Node     - SMB reverse proxy data plane
```

During installation, choose one of these roles:

```text
management      Central dashboard and policy server
dns             DNS node enrolled to the management server
smb_proxy       SMB proxy node enrolled to the management server
standalone_lab  Single-machine lab mode
```

The management server prints an enrollment token at the end of installation.
Use that token when installing DNS and SMB nodes. Data-plane nodes post
heartbeat/statistics to the management server and also expose a small control
listener for policy push. When an admin clicks Save, the management server
actively pushes the updated policy to the relevant DNS or SMB node. Control
payloads and replies are encrypted with ChaCha20-Poly1305 and authenticated with
the enrollment token; periodic pull remains as a recovery fallback.

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
Axiom listens on UDP/TCP 53, checks domains against local policy and optional
threat feeds, serves local DNS records, caches safe responses, and forwards
allowed queries to the configured internal DC/upstream DNS servers. Threat feeds
are opt-in during installation so a new lab does not start blocking domains
before an explicit DNS policy is configured.

Organizations without internal DNS can select public recursive upstreams during
installation, including Cloudflare, Google, Quad9, or custom resolver IPs. The
installer also asks which NIC should be used for upstream resolver egress.
When `whiptail` is available, the installer uses a terminal GUI/TUI; set
`AXIOM_INSTALLER_CLI=1` to force the plain CLI wizard.

## Policies

The management UI includes runtime policy controls for SMB archive detection,
entropy detection, and custom byte signatures. Each rule can be set to
`disabled`, `monitor`, or `block`. Policy changes are applied immediately and
persisted back to `/etc/axiom/axiom.toml`.

The same dashboard also includes DNS policy controls, local DNS records, DNS
query volume, DNS blocks, cache hits, upstream errors, and recent DNS activity by
client/domain/action.

Axiom blocks SMB multichannel interface-discovery IOCTLs by default. This keeps
Windows clients on the proxy path instead of learning backend file-server NICs
and moving large file transfers around Axiom.

The default MVP management login is:

```text
username: admin
password: axiom-admin
```

On Linux, binding to TCP/445 and enforcing `SO_BINDTODEVICE` require network
capabilities. For production-style systemd deployment, grant the daemon
`CAP_NET_BIND_SERVICE` and the capability required by the kernel for device
binding, or run as root only during early lab validation.
