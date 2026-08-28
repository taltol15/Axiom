# Axiom

Axiom is an enterprise SMB reverse proxy and DNS security gateway for Linux
deployments. It protects file-server traffic through inline SMB inspection,
centralized reputation, policy enforcement, DNS filtering, and a dedicated
management console.

Engineers joining the project should start with `DEVELOPER_HANDOFF.md`. It
documents both repositories, cross-repository contracts, runtime architecture,
security invariants, release workflow and current limitations.

**Current customer release:** 1.1.6 — see `docs/CURRENT_RELEASE.md`.

## Deployment Roles

The recommended production deployment uses at least three Axiom servers:

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
standalone_lab  Single-machine evaluation mode
```

The management server exposes the node enrollment token in the Management UI
under Settings, where admins can copy it or rotate it without logging in to
Linux. Use that token when installing DNS and SMB nodes. Data-plane nodes post
heartbeat/statistics to the management server and also expose a small control
listener for policy push. When an admin clicks Save, the management server
actively pushes the updated policy to the relevant DNS or SMB node. Control
payloads and replies are encrypted with ChaCha20-Poly1305 and authenticated with
the enrollment token; periodic pull remains as a recovery fallback.

## DNS and SMB Clusters

The Management Server can organize reporting DNS and SMB nodes into independent
cluster groups. Open `Clusters`, select an existing source node, define a unique
cluster name and join password, and then run the normal installer on each new
replica. Choose the cluster enrollment path and enter the same name and password.

The replica receives the source node's shared service template automatically:

- SMB backend targets, ports, VLAN metadata, and listener backlog
- DNS upstream resolvers, ports, cache limits, and timeout settings
- the current centrally managed policy and reputation feed

Local NIC names and listener IP addresses are deliberately not copied. The
installer asks for those values on every replica because they belong to that
specific Linux server. The join password is stored only as an Argon2 hash on the
Management Server. A successful join issues a unique node credential, so one
replica can be revoked without rotating the entire cluster.

Cluster membership provides centralized configuration and policy consistency.
Client traffic high availability is configured separately: publish several DNS
node addresses through DHCP, or place SMB nodes behind a TCP/445-aware external
load balancer/VIP with session affinity. Axiom records the intended HA mode and
service endpoint but does not take ownership of an external VIP. See
`docs/CLUSTER_AND_HIGH_AVAILABILITY_KB.md` for field-by-field behavior, exact LB
requirements, failure scenarios, firewall rules, and production acceptance
tests.

## Run

```bash
cargo check --workspace
cargo run -p axiom-daemon -- config/axiom.toml
```

## Installation

For an Ubuntu/Debian server, copy and run the self-contained installer:

```bash
chmod +x axiom-installer.sh
./axiom-installer.sh
```

The installer embeds the full Axiom source tree, extracts it to a temporary
directory, discovers NICs interactively, writes `/etc/axiom/axiom.toml`, builds
the release binary, applies Linux capabilities, and starts `axiom.service`.
During management installation, the installer prompts for the initial Web UI
administrator username and password. No default production password is created.

For existing servers, use repair mode after pulling a new release. It preserves
the installed configuration and refreshes the binary, systemd service, helper
files, Linux capabilities, and reverse-proxy sysctl settings:

```bash
cd ~/Axiom
git pull --ff-only
sudo ./install.sh --repair
```

To remove Axiom while keeping configuration, state, and logs:

```bash
sudo ./install.sh --uninstall
```

To remove service, binaries, configuration, state, and logs:

```bash
sudo ./install.sh --uninstall --purge
```

During installation, the DNS Security Gateway can be enabled on a dedicated NIC.
Axiom listens on UDP/TCP 53, checks domains against local policy and optional
threat feeds, serves local DNS records, caches safe responses, and forwards
allowed queries to the configured internal DC/upstream DNS servers. Threat feeds
are opt-in during installation so a new deployment does not start blocking
domains before an explicit DNS policy is configured.

New DNS installations use the built-in Axiom block page for blocked domains.
Administrators can customize its logo, UTF-8 text, color and support link under
DNS Security. The page is served locally on TCP 80 and works without internet
access. HTTP can display the page directly; HTTPS normally shows a certificate
warning before HTTP content because Axiom does not impersonate the blocked
domain. See `docs/DNS_BLOCK_PAGE_KB.md` for design and validation details.

Organizations without internal DNS can select public recursive upstreams during
installation, including Cloudflare, Google, Quad9, or custom resolver IPs. The
installer also asks which NIC should be used for upstream resolver egress.
When `whiptail` is available, the installer uses a terminal GUI/TUI; set
`AXIOM_INSTALLER_CLI=1` to force the plain CLI wizard.

The management role can enable HTTPS during installation. A self-signed
certificate is available for evaluation, while production deployments should use
an enterprise-issued certificate or trusted internal CA. If a DNS/SMB node points
to an HTTPS management URL that uses a private certificate, the installer asks
whether that node should trust it for management heartbeat and policy recovery.

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
AXIOM_LICENSE_PUBLIC_KEY_HEX="official_axiom_public_key_hex" ./axiom-installer.sh
```

The installer writes that value to `[license].public_key_hex`. If the variable
is omitted, Axiom uses its bundled public verification key.

For internal issuance testing, generate an Ed25519 key pair on a trusted issuing
workstation:

```bash
cargo run -p axiom-license --bin axiom-license-tool -- generate-key
```

Keep the private key outside git and customer systems. For controlled testing
only, copy the generated `public_key_hex` into the management server config:

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
  --customer "Customer Name" \
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
AXIOM_INSTALL_LICENSE_TOOL=1 ./axiom-installer.sh
# or, when running directly from a checked-out repository:
AXIOM_INSTALL_LICENSE_TOOL=1 ./install.sh
```

The private key must still live outside git and customer systems, preferably as
a protected secret or a `0600` file readable only by the license issuing service.

## Operations Docs

Production deployment, support, and release readiness documents live under
`docs/`:

```text
docs/PRODUCTION_DEPLOYMENT.md
docs/CUSTOMER_GETTING_STARTED.md
docs/CUSTOMER_INSTALLATION_GUIDE.md
docs/PRODUCT_OVERVIEW.md
docs/OPERATIONS_RUNBOOK.md
docs/RELEASE_CHECKLIST.md
docs/VALIDATION_TEST_PLAN.md
docs/CLUSTER_AND_HIGH_AVAILABILITY_KB.md
docs/DNS_BLOCK_PAGE_KB.md
```

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

On Linux, binding to TCP/445 and enforcing `SO_BINDTODEVICE` require network
capabilities. For production-style systemd deployment, grant the daemon
`CAP_NET_BIND_SERVICE` and the capability required by the kernel for device
binding, or run as root only during early controlled validation.
