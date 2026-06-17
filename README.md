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

The management server exposes the node enrollment token in the Management UI
under Settings, where admins can copy it or rotate it without logging in to
Linux. Use that token when installing DNS and SMB nodes. Data-plane nodes post
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

The management role can enable HTTPS during installation. The installer can
generate a local self-signed certificate for labs, while production deployments
should replace it with an enterprise-issued certificate or trusted internal CA.
If a DNS/SMB node points to an HTTPS management URL that uses a self-signed lab
certificate, the installer asks whether that node should accept the private
certificate for management heartbeat and policy recovery.

Management login supports the local admin account and optional LDAP/Active
Directory authentication. Directory settings are written under
`[management.directory]`. When reverse DNS is enabled and the management server
uses the DC/DNS resolver, client IPs in SMB and DNS telemetry are enriched with
hostnames where PTR records exist.

## Offline Licensing

Axiom starts with a local offline trial when no license is installed. In the
management UI, admins use a simple offline file exchange:

```text
Settings -> License Activation -> Download activation file
Send the .axact file to Axiom
Upload the returned .axlic license file
```

No customer server needs internet access for offline activation.

Customer deployments should be installed with the official Axiom public
verification key. The installer accepts it without exposing any private signing
material:

```bash
AXIOM_LICENSE_PUBLIC_KEY_HEX="official_axiom_public_key_hex" ./axiom-lab-installer.sh
```

The installer writes that value to `[license].public_key_hex`. If the variable
is omitted, Axiom falls back to its built-in development verification key.

For lab issuance, generate an Ed25519 key pair on a trusted issuing workstation:

```bash
cargo run -p axiom-license --bin axiom-license-tool -- generate-key
```

Keep the private key outside git and customer systems. For lab testing only,
copy the generated `public_key_hex` into the management server config:

```toml
[license]
public_key_hex = "generated_public_key_hex"
```

Restart management after changing the public key:

```bash
sudo systemctl restart axiom
```

Then download the `.axact` activation file from the management UI and issue a
signed `.axlic` license:

```bash
export AXIOM_LICENSE_PRIVATE_KEY_HEX="generated_private_key_hex"
cargo run -p axiom-license --bin axiom-license-tool -- issue \
  --request customer.axact \
  --customer "Customer Lab" \
  --edition enterprise \
  --days 365 \
  --max-smb-nodes 5 \
  --max-dns-nodes 5 \
  --max-protected-clients 5000 \
  --max-reputation-entries 100000 \
  --output customer.axlic
```

Upload `customer.axlic` in Settings -> License Activation -> Upload license
file. Production issuance should use the official Axiom signing key, with only
the public verification key present in customer deployments.

The customer installer does not install the license issuing tool by default.
For an internal Axiom staff host or the company customer portal backend, install
the issuer explicitly:

```bash
AXIOM_INSTALL_LICENSE_TOOL=1 ./axiom-lab-installer.sh
# or, when running directly from a checked-out repository:
AXIOM_INSTALL_LICENSE_TOOL=1 ./install.sh
```

The private key must still live outside git and customer systems, preferably as
a protected secret or a `0600` file readable only by the license issuing service.

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
