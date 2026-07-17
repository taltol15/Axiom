# Axiom Customer Installation Guide

This guide describes a fresh installation using the self-contained installer.

## Supported Operating Systems

Ubuntu/Debian family Linux distributions are supported.

The installer checks and installs required packages such as:

- Rust toolchain
- build tools
- `iproute2`
- `systemd`
- `setcap`
- `openssl`
- `pkg-config`
- `whiptail`

## Download Installer

Copy `axiom-installer.sh` to the server.

```bash
chmod +x axiom-installer.sh
```

## Install Management Server

Run:

```bash
sudo ./axiom-installer.sh
```

Choose:

```text
management
```

The installer asks for:

- Management interface
- Management IP and port
- HTTPS settings
- Optional Active Directory settings
- Initial admin username and password

When complete, open the Management UI and copy the enrollment token from
Settings.

## Install SMB Node

Run the installer on the SMB node:

```bash
sudo ./axiom-installer.sh
```

Choose:

```text
smb_proxy
```

The installer asks for:

- Management server URL
- Enrollment token
- Node ID and display name
- Node control interface and IP
- SMB listener interface and IP
- Backend file server IP

Expected result:

```text
TCP 445  listening on the SMB node client-facing IP
TCP 9443 listening for encrypted management control pushes
```

## Install DNS Node

Run the installer on the DNS node:

```bash
sudo ./axiom-installer.sh
```

Choose:

```text
dns
```

The installer asks for:

- Management server URL
- Enrollment token
- Node ID and display name
- DNS listener interface and IP
- Upstream resolver interface
- Upstream DNS resolvers
- Optional threat feeds

Expected result:

```text
UDP 53 listening on the DNS node IP
TCP 53 listening on the DNS node IP
TCP 9443 listening for encrypted management control pushes
```

## Repair Existing Installation

Use repair after pulling a new product release:

```bash
cd ~/Axiom
git pull --ff-only
sudo ./install.sh --repair
```

Repair mode preserves `/etc/axiom/axiom.toml`.

## Uninstall

Remove service and binaries, keeping configuration and logs:

```bash
sudo ./install.sh --uninstall
```

Remove service, binaries, configuration, logs, and state:

```bash
sudo ./install.sh --uninstall --purge
```

