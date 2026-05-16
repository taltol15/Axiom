#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="/etc/axiom"
CONFIG_PATH="${CONFIG_DIR}/axiom.toml"
BINARY_NAME="axiom-daemon"
BINARY_SOURCE="${PROJECT_ROOT}/target/release/${BINARY_NAME}"
BINARY_PATH="/usr/local/bin/${BINARY_NAME}"
SERVICE_PATH="/etc/systemd/system/axiom.service"
SERVICE_USER="axiom"
SERVICE_GROUP="axiom"
MANAGEMENT_DEFAULT_PORT="8443"
SMB_DEFAULT_PORT="445"
LISTEN_DEFAULT_IP="0.0.0.0"
MIN_RUST_VERSION="1.88.0"

trap 'echo "Axiom installation failed. Review the error above and rerun install.sh." >&2' ERR

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

require_sudo() {
  if [[ -n "${SUDO}" ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
      echo "sudo is required when install.sh is not run as root." >&2
      exit 1
    fi
    sudo -v
  fi
}

ensure_debian_family() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This installer supports Linux only." >&2
    exit 1
  fi

  if [[ ! -f /etc/debian_version ]]; then
    echo "This installer supports Ubuntu/Debian family systems." >&2
    exit 1
  fi
}

ensure_project_root() {
  if [[ ! -f "${PROJECT_ROOT}/Cargo.toml" ]]; then
    echo "Cargo.toml was not found next to install.sh." >&2
    exit 1
  fi
}

install_missing_dependencies() {
  local missing_packages=()
  declare -A command_packages=(
    ["ip"]="iproute2"
    ["systemctl"]="systemd"
    ["setcap"]="libcap2-bin"
    ["sha256sum"]="coreutils"
    ["curl"]="curl"
    ["tar"]="tar"
    ["gzip"]="gzip"
  )

  for command_name in "${!command_packages[@]}"; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
      missing_packages+=("${command_packages[${command_name}]}")
    fi
  done

  if ((${#missing_packages[@]} > 0)); then
    if ! command -v apt-get >/dev/null 2>&1; then
      echo "Missing dependencies and apt-get is unavailable: ${missing_packages[*]}" >&2
      exit 1
    fi

    echo "Installing missing packages: ${missing_packages[*]}"
    ${SUDO} apt-get update
    ${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing_packages[@]}"
  fi

  ${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates \
    build-essential \
    pkg-config

  for command_name in ip systemctl setcap sha256sum curl tar gzip; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
      echo "Required command '${command_name}' is still unavailable after dependency installation." >&2
      exit 1
    fi
  done

  if ! systemctl list-unit-files >/dev/null 2>&1; then
    echo "systemd is installed but not operational in this environment." >&2
    exit 1
  fi
}

version_ge() {
  local current="$1"
  local required="$2"
  printf '%s\n%s\n' "${required}" "${current}" | sort -V -C
}

current_rust_version() {
  if ! command -v rustc >/dev/null 2>&1; then
    return 1
  fi
  rustc --version | awk '{ print $2 }'
}

ensure_rust_toolchain() {
  export PATH="${HOME}/.cargo/bin:${PATH}"

  local rust_version=""
  if rust_version="$(current_rust_version)" && version_ge "${rust_version}" "${MIN_RUST_VERSION}" && command -v cargo >/dev/null 2>&1; then
    echo "Rust toolchain detected: rustc ${rust_version}"
    return
  fi

  echo "Installing Rust toolchain with rustup; required rustc >= ${MIN_RUST_VERSION}"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable

  # shellcheck disable=SC1090
  source "${HOME}/.cargo/env"

  rustup update stable

  rust_version="$(current_rust_version)"
  if ! version_ge "${rust_version}" "${MIN_RUST_VERSION}"; then
    echo "Installed rustc ${rust_version}, but Axiom requires >= ${MIN_RUST_VERSION}." >&2
    exit 1
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo is unavailable after rustup installation." >&2
    exit 1
  fi
}

load_interfaces() {
  mapfile -t INTERFACES < <(find /sys/class/net -mindepth 1 -maxdepth 1 -type l -printf '%f\n' | sort)
  if ((${#INTERFACES[@]} == 0)); then
    echo "No network interfaces were discovered under /sys/class/net." >&2
    exit 1
  fi
}

get_interface_ipv4() {
  local interface_name="$1"
  ip -o -4 addr show dev "${interface_name}" scope global 2>/dev/null \
    | awk '{ split($4, address, "/"); print address[1]; exit }'
}

get_interface_state() {
  local interface_name="$1"
  if [[ -r "/sys/class/net/${interface_name}/operstate" ]]; then
    cat "/sys/class/net/${interface_name}/operstate"
  else
    printf "unknown"
  fi
}

print_interfaces() {
  echo
  echo "Available network interfaces:"
  for index in "${!INTERFACES[@]}"; do
    local interface_name="${INTERFACES[${index}]}"
    local state
    local ipv4
    state="$(get_interface_state "${interface_name}")"
    ipv4="$(get_interface_ipv4 "${interface_name}")"
    if [[ -z "${ipv4}" ]]; then
      ipv4="-"
    fi
    printf "  %2d) %-18s state=%-10s ipv4=%s\n" "$((index + 1))" "${interface_name}" "${state}" "${ipv4}"
  done
  echo
}

select_management_interface() {
  while true; do
    print_interfaces
    read -r -p "Select the interface for the Web Management UI [number]: " selection
    if [[ "${selection}" =~ ^[0-9]+$ ]] && ((selection >= 1 && selection <= ${#INTERFACES[@]})); then
      MANAGEMENT_INTERFACE="${INTERFACES[$((selection - 1))]}"
      return
    fi
    echo "Invalid interface selection."
  done
}

select_proxy_interfaces() {
  while true; do
    print_interfaces
    read -r -p "Select the interfaces for the Proxy [comma-separated numbers]: " raw_selection
    raw_selection="${raw_selection// /}"

    if [[ -z "${raw_selection}" ]]; then
      echo "At least one proxy interface is required."
      continue
    fi

    IFS=',' read -r -a selections <<< "${raw_selection}"
    SELECTED_PROXY_INTERFACES=()
    declare -A seen=()
    local valid="true"

    for selection in "${selections[@]}"; do
      if [[ ! "${selection}" =~ ^[0-9]+$ ]] || ((selection < 1 || selection > ${#INTERFACES[@]})); then
        echo "Invalid proxy interface selection: ${selection}"
        valid="false"
        break
      fi

      local interface_name="${INTERFACES[$((selection - 1))]}"
      if [[ -z "${seen[${interface_name}]+x}" ]]; then
        seen["${interface_name}"]=1
        SELECTED_PROXY_INTERFACES+=("${interface_name}")
      fi
    done

    if [[ "${valid}" == "true" ]] && ((${#SELECTED_PROXY_INTERFACES[@]} > 0)); then
      return
    fi
  done
}

is_ipv4() {
  local value="$1"
  local octets
  IFS='.' read -r -a octets <<< "${value}"

  if ((${#octets[@]} != 4)); then
    return 1
  fi

  for octet in "${octets[@]}"; do
    if [[ ! "${octet}" =~ ^[0-9]+$ ]] || ((octet < 0 || octet > 255)); then
      return 1
    fi
  done

  return 0
}

prompt_ipv4() {
  local prompt="$1"
  local default_value="${2:-}"
  local value

  while true; do
    if [[ -n "${default_value}" ]]; then
      printf "%s [%s]: " "${prompt}" "${default_value}" >&2
      read -r value
      value="${value:-${default_value}}"
    else
      printf "%s: " "${prompt}" >&2
      read -r value
    fi

    if is_ipv4 "${value}"; then
      printf "%s" "${value}"
      return
    fi
    echo "Invalid IPv4 address." >&2
  done
}

prompt_port() {
  local prompt="$1"
  local default_value="$2"
  local value

  while true; do
    printf "%s [%s]: " "${prompt}" "${default_value}" >&2
    read -r value
    value="${value:-${default_value}}"

    if [[ "${value}" =~ ^[0-9]+$ ]] && ((value >= 1 && value <= 65535)); then
      printf "%s" "${value}"
      return
    fi
    echo "Invalid TCP port." >&2
  done
}

prompt_optional_vlan() {
  local prompt="$1"
  local value

  while true; do
    printf "%s [empty for none]: " "${prompt}" >&2
    read -r value
    if [[ -z "${value}" ]]; then
      printf ""
      return
    fi

    if [[ "${value}" =~ ^[0-9]+$ ]] && ((value >= 1 && value <= 4094)); then
      printf "%s" "${value}"
      return
    fi
    echo "Invalid VLAN ID." >&2
  done
}

prompt_nonempty() {
  local prompt="$1"
  local value

  while true; do
    printf "%s: " "${prompt}" >&2
    read -r value
    if [[ -n "${value}" ]]; then
      printf "%s" "${value}"
      return
    fi
    echo "Value must not be empty." >&2
  done
}

prompt_admin_credentials() {
  ADMIN_USERNAME="$(prompt_nonempty "Set Web UI admin username")"

  local password
  local confirmation
  while true; do
    read -r -s -p "Set Web UI admin password: " password
    echo
    read -r -s -p "Confirm Web UI admin password: " confirmation
    echo

    if [[ -z "${password}" ]]; then
      echo "Password must not be empty."
      continue
    fi

    if [[ "${password}" != "${confirmation}" ]]; then
      echo "Passwords do not match."
      continue
    fi

    ADMIN_PASSWORD="${password}"
    return
  done
}

sha256_password_hash() {
  local password="$1"
  local salt
  local digest

  salt="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  digest="$(printf "%s:%s" "${salt}" "${password}" | sha256sum | awk '{ print $1 }')"
  printf "sha256\$%s\$%s" "${salt}" "${digest}"
}

toml_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf "%s" "${value}"
}

safe_route_name() {
  local interface_name="$1"
  local vlan="$2"
  local name

  name="$(printf "%s" "${interface_name}" | tr -c 'A-Za-z0-9_-' '-')"
  if [[ -n "${vlan}" ]]; then
    printf "proxy-%s-vlan%s" "${name}" "${vlan}"
  else
    printf "proxy-%s" "${name}"
  fi
}

collect_configuration() {
  select_management_interface

  local discovered_management_ip
  discovered_management_ip="$(get_interface_ipv4 "${MANAGEMENT_INTERFACE}")"
  MANAGEMENT_BIND_IP="$(prompt_ipv4 "Management UI bind IPv4 for ${MANAGEMENT_INTERFACE}" "${discovered_management_ip}")"
  MANAGEMENT_PORT="$(prompt_port "Management UI TCP port" "${MANAGEMENT_DEFAULT_PORT}")"

  select_proxy_interfaces

  PROXY_NAMES=()
  PROXY_INTERFACES=()
  PROXY_VLANS=()
  PROXY_LISTEN_IPS=()
  PROXY_LISTEN_PORTS=()
  PROXY_TARGET_IPS=()
  PROXY_TARGET_PORTS=()

  for proxy_interface in "${SELECTED_PROXY_INTERFACES[@]}"; do
    echo
    echo "Configure proxy interface: ${proxy_interface}"
    local vlan
    local listen_ip
    local listen_port
    local target_ip
    local target_port
    local route_name

    vlan="$(prompt_optional_vlan "Client VLAN ID for ${proxy_interface}")"
    listen_ip="$(prompt_ipv4 "SMB listen IPv4 for ${proxy_interface}" "${LISTEN_DEFAULT_IP}")"
    listen_port="$(prompt_port "SMB listen TCP port for ${proxy_interface}" "${SMB_DEFAULT_PORT}")"
    target_ip="$(prompt_ipv4 "Target File Server IPv4 protected by ${proxy_interface}")"
    target_port="$(prompt_port "Target File Server TCP port" "${SMB_DEFAULT_PORT}")"
    route_name="$(safe_route_name "${proxy_interface}" "${vlan}")"

    PROXY_NAMES+=("${route_name}")
    PROXY_INTERFACES+=("${proxy_interface}")
    PROXY_VLANS+=("${vlan}")
    PROXY_LISTEN_IPS+=("${listen_ip}")
    PROXY_LISTEN_PORTS+=("${listen_port}")
    PROXY_TARGET_IPS+=("${target_ip}")
    PROXY_TARGET_PORTS+=("${target_port}")
  done

  prompt_admin_credentials
  ADMIN_PASSWORD_HASH="$(sha256_password_hash "${ADMIN_PASSWORD}")"
  unset ADMIN_PASSWORD
}

ensure_service_user() {
  if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
    ${SUDO} groupadd --system "${SERVICE_GROUP}"
  fi

  if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    ${SUDO} useradd \
      --system \
      --no-create-home \
      --gid "${SERVICE_GROUP}" \
      --shell /usr/sbin/nologin \
      "${SERVICE_USER}"
  fi
}

write_config() {
  local temp_config
  temp_config="$(mktemp)"

  {
    echo "[management]"
    echo "interface = \"$(toml_escape "${MANAGEMENT_INTERFACE}")\""
    echo "bind_ip = \"$(toml_escape "${MANAGEMENT_BIND_IP}")\""
    echo "port = ${MANAGEMENT_PORT}"
    echo
    echo "[management.admin]"
    echo "username = \"$(toml_escape "${ADMIN_USERNAME}")\""
    echo "password_hash = \"$(toml_escape "${ADMIN_PASSWORD_HASH}")\""
    echo
    echo "[policy.smb]"
    echo "encrypted_payload = \"monitor\""
    echo
    echo "[policy.archive]"
    echo "rar = \"block\""
    echo "seven_zip = \"block\""
    echo "zip = \"monitor\""
    echo "encrypted_zip = \"block\""
    echo
    echo "[policy.entropy]"
    echo "mode = \"monitor\""
    echo "threshold = 7.9"
    echo "minimum_chunk_size = 8192"
    echo
    echo "[[policy.signatures]]"
    echo "name = \"Axiom synthetic test marker\""
    echo "pattern = \"AXIOM_TEST_THREAT\""
    echo "mode = \"block\""
    echo
    echo "[[policy.signatures]]"
    echo "name = \"WannaCry marker WNCRY\""
    echo "pattern = \"WNCRY\""
    echo "mode = \"block\""
    echo
    echo "[[policy.signatures]]"
    echo "name = \"WannaCry marker WANACRY\""
    echo "pattern = \"WANACRY!\""
    echo "mode = \"block\""

    for index in "${!PROXY_INTERFACES[@]}"; do
      echo
      echo "[[proxy_listeners]]"
      echo "name = \"$(toml_escape "${PROXY_NAMES[${index}]}")\""
      echo "source_interface = \"$(toml_escape "${PROXY_INTERFACES[${index}]}")\""
      if [[ -n "${PROXY_VLANS[${index}]}" ]]; then
        echo "client_vlan = ${PROXY_VLANS[${index}]}"
      fi
      echo "listen_ip = \"$(toml_escape "${PROXY_LISTEN_IPS[${index}]}")\""
      echo "listen_port = ${PROXY_LISTEN_PORTS[${index}]}"
      echo "target_file_server_ip = \"$(toml_escape "${PROXY_TARGET_IPS[${index}]}")\""
      echo "target_file_server_port = ${PROXY_TARGET_PORTS[${index}]}"
      echo "backlog = 4096"
    done
  } > "${temp_config}"

  ${SUDO} install -d -m 0770 -o root -g "${SERVICE_GROUP}" "${CONFIG_DIR}"
  ${SUDO} install -m 0660 -o root -g "${SERVICE_GROUP}" "${temp_config}" "${CONFIG_PATH}"
  rm -f "${temp_config}"
}

build_and_install_binary() {
  echo
  echo "Building Axiom release binary..."
  (cd "${PROJECT_ROOT}" && cargo build --release -p axiom-daemon)

  ${SUDO} install -m 0755 -o root -g root "${BINARY_SOURCE}" "${BINARY_PATH}"
  ${SUDO} setcap 'cap_net_bind_service,cap_net_raw+ep' "${BINARY_PATH}"
}

write_systemd_service() {
  local temp_service
  temp_service="$(mktemp)"

  cat > "${temp_service}" <<EOF
[Unit]
Description=Axiom SMB Reverse Proxy
Documentation=file:${PROJECT_ROOT}/README.md
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
ExecStart=${BINARY_PATH} ${CONFIG_PATH}
Restart=on-failure
RestartSec=2s
Environment=RUST_LOG=axiom=info,axiom_daemon=info
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/axiom /var/lib/axiom /var/log/axiom
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF

  ${SUDO} install -d -m 0755 /var/lib/axiom /var/log/axiom
  ${SUDO} chown "${SERVICE_USER}:${SERVICE_GROUP}" /var/lib/axiom /var/log/axiom
  ${SUDO} install -m 0644 -o root -g root "${temp_service}" "${SERVICE_PATH}"
  rm -f "${temp_service}"
}

enable_and_start_service() {
  ${SUDO} systemctl daemon-reload
  ${SUDO} systemctl enable axiom.service
  ${SUDO} systemctl restart axiom.service
}

print_summary() {
  echo
  echo "Axiom installation completed."
  echo "Config: ${CONFIG_PATH}"
  echo "Binary: ${BINARY_PATH}"
  echo "Service: axiom.service"
  echo "Management UI: http://${MANAGEMENT_BIND_IP}:${MANAGEMENT_PORT}/"
  echo
  ${SUDO} systemctl --no-pager --lines=12 status axiom.service || true
}

main() {
  ensure_debian_family
  ensure_project_root
  require_sudo
  install_missing_dependencies
  ensure_rust_toolchain
  load_interfaces
  collect_configuration
  ensure_service_user
  write_config
  build_and_install_binary
  write_systemd_service
  enable_and_start_service
  print_summary
}

main "$@"
