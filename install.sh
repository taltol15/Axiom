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
DNS_DEFAULT_PORT="53"
LISTEN_DEFAULT_IP="0.0.0.0"
DNS_DEFAULT_THREAT_FEED_URL="https://urlhaus.abuse.ch/downloads/hostfile/"
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
    ["sysctl"]="procps"
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
    binutils \
    pkg-config \
    whiptail

  for command_name in ip systemctl setcap sha256sum sysctl curl tar gzip cc ld.bfd; do
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

use_tui() {
  [[ "${AXIOM_INSTALLER_CLI:-0}" != "1" ]] \
    && [[ -t 0 ]] \
    && command -v whiptail >/dev/null 2>&1
}

ui_error() {
  local message="$1"
  if use_tui; then
    whiptail --title "Axiom installer" --msgbox "${message}" 10 72
  else
    echo "${message}" >&2
  fi
}

ui_input() {
  local prompt="$1"
  local default_value="${2:-}"

  if use_tui; then
    whiptail --title "Axiom installer" --inputbox "${prompt}" 10 76 "${default_value}" 3>&1 1>&2 2>&3
  else
    return 1
  fi
}

ui_password() {
  local prompt="$1"

  if use_tui; then
    whiptail --title "Axiom installer" --passwordbox "${prompt}" 10 76 3>&1 1>&2 2>&3
  else
    return 1
  fi
}

interface_summary() {
  local interface_name="$1"
  local state
  local ipv4

  state="$(get_interface_state "${interface_name}")"
  ipv4="$(get_interface_ipv4 "${interface_name}")"
  if [[ -z "${ipv4}" ]]; then
    ipv4="-"
  fi

  printf "%s  state=%s  ipv4=%s" "${interface_name}" "${state}" "${ipv4}"
}

select_interface_tui() {
  local prompt="$1"
  local choices=()
  local index
  local selection

  for index in "${!INTERFACES[@]}"; do
    choices+=("$((index + 1))" "$(interface_summary "${INTERFACES[${index}]}")")
  done

  selection="$(whiptail --title "Axiom installer" --menu "${prompt}" 22 88 12 "${choices[@]}" 3>&1 1>&2 2>&3)" || return 1
  printf "%s" "${INTERFACES[$((selection - 1))]}"
}

select_proxy_interfaces_tui() {
  local choices=()
  local index
  local raw_selection
  local selection

  for index in "${!INTERFACES[@]}"; do
    choices+=("$((index + 1))" "$(interface_summary "${INTERFACES[${index}]}")" "OFF")
  done

  raw_selection="$(whiptail --title "Axiom installer" --separate-output --checklist "Select the SMB Proxy interfaces" 22 88 12 "${choices[@]}" 3>&1 1>&2 2>&3)" || return 1
  mapfile -t selections <<< "${raw_selection}"

  SELECTED_PROXY_INTERFACES=()
  for selection in "${selections[@]}"; do
    if [[ "${selection}" =~ ^[0-9]+$ ]] && ((selection >= 1 && selection <= ${#INTERFACES[@]})); then
      SELECTED_PROXY_INTERFACES+=("${INTERFACES[$((selection - 1))]}")
    fi
  done

  ((${#SELECTED_PROXY_INTERFACES[@]} > 0))
}

select_management_interface() {
  if use_tui; then
    if MANAGEMENT_INTERFACE="$(select_interface_tui "Select the interface for the Web Management UI")"; then
      return
    fi
  fi

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
  if use_tui; then
    if select_proxy_interfaces_tui; then
      return
    fi
  fi

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

select_dns_interface() {
  if use_tui; then
    if DNS_INTERFACE="$(select_interface_tui "Select the interface for the DNS Security Gateway")"; then
      return
    fi
  fi

  while true; do
    print_interfaces
    read -r -p "Select the interface for the DNS Security Gateway [number]: " selection
    if [[ "${selection}" =~ ^[0-9]+$ ]] && ((selection >= 1 && selection <= ${#INTERFACES[@]})); then
      DNS_INTERFACE="${INTERFACES[$((selection - 1))]}"
      return
    fi
    echo "Invalid interface selection."
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
    if use_tui; then
      value="$(ui_input "${prompt}" "${default_value}")" || exit 1
      value="${value:-${default_value}}"
    elif [[ -n "${default_value}" ]]; then
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
    ui_error "Invalid IPv4 address."
  done
}

prompt_port() {
  local prompt="$1"
  local default_value="$2"
  local value

  while true; do
    if use_tui; then
      value="$(ui_input "${prompt}" "${default_value}")" || exit 1
    else
      printf "%s [%s]: " "${prompt}" "${default_value}" >&2
      read -r value
    fi
    value="${value:-${default_value}}"

    if [[ "${value}" =~ ^[0-9]+$ ]] && ((value >= 1 && value <= 65535)); then
      printf "%s" "${value}"
      return
    fi
    ui_error "Invalid TCP/UDP port."
  done
}

prompt_yes_no() {
  local prompt="$1"
  local default_value="$2"
  local value
  local suffix

  if use_tui; then
    local default_option=()
    if [[ "${default_value}" != "yes" ]]; then
      default_option=(--defaultno)
    fi
    whiptail --title "Axiom installer" "${default_option[@]}" --yesno "${prompt}" 10 76
    return $?
  elif [[ "${default_value}" == "yes" ]]; then
    suffix="Y/n"
  else
    suffix="y/N"
  fi

  while true; do
    printf "%s [%s]: " "${prompt}" "${suffix}" >&2
    read -r value
    value="${value,,}"

    if [[ -z "${value}" ]]; then
      value="${default_value}"
    fi

    case "${value}" in
      y|yes)
        return 0
        ;;
      n|no)
        return 1
        ;;
      *)
        ui_error "Please answer yes or no."
        ;;
    esac
  done
}

prompt_optional_vlan() {
  local prompt="$1"
  local value

  while true; do
    if use_tui; then
      value="$(ui_input "${prompt} (empty for none)" "")" || exit 1
    else
      printf "%s [empty for none]: " "${prompt}" >&2
      read -r value
    fi
    if [[ -z "${value}" ]]; then
      printf ""
      return
    fi

    if [[ "${value}" =~ ^[0-9]+$ ]] && ((value >= 1 && value <= 4094)); then
      printf "%s" "${value}"
      return
    fi
    ui_error "Invalid VLAN ID."
  done
}

prompt_dns_upstreams() {
  local prompt="$1"
  local default_value="${2:-}"
  local raw_value
  local upstream

  while true; do
    if use_tui; then
      raw_value="$(ui_input "${prompt} (comma-separated IPv4 or IPv4:port)" "${default_value}")" || exit 1
    else
      if [[ -n "${default_value}" ]]; then
        printf "%s [comma-separated IPv4 or IPv4:port] [%s]: " "${prompt}" "${default_value}" >&2
      else
        printf "%s [comma-separated IPv4 or IPv4:port]: " "${prompt}" >&2
      fi
      read -r raw_value
    fi
    raw_value="${raw_value:-${default_value}}"
    raw_value="${raw_value// /}"

    if [[ -z "${raw_value}" ]]; then
      ui_error "At least one upstream DNS server is required when DNS is enabled."
      continue
    fi

    IFS=',' read -r -a DNS_UPSTREAMS <<< "${raw_value}"
    local valid="true"
    local normalized=()

    for upstream in "${DNS_UPSTREAMS[@]}"; do
      local ip="${upstream}"
      local port="${DNS_DEFAULT_PORT}"

      if [[ "${upstream}" == *:* ]]; then
        ip="${upstream%:*}"
        port="${upstream##*:}"
      fi

      if ! is_ipv4 "${ip}"; then
        ui_error "Invalid upstream DNS IPv4: ${ip}"
        valid="false"
        break
      fi

      if [[ ! "${port}" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
        ui_error "Invalid upstream DNS port: ${port}"
        valid="false"
        break
      fi

      normalized+=("${ip}:${port}")
    done

    if [[ "${valid}" == "true" ]] && ((${#normalized[@]} > 0)); then
      DNS_UPSTREAMS=("${normalized[@]}")
      return
    fi
  done
}

configure_dns_upstreams() {
  local mode

  if use_tui; then
    mode="$(whiptail --title "Axiom installer" --menu "Choose DNS upstream mode" 16 82 6 \
      "internal" "Internal/DC DNS resolvers" \
      "cloudflare" "Cloudflare public DNS: 1.1.1.1, 1.0.0.1" \
      "google" "Google public DNS: 8.8.8.8, 8.8.4.4" \
      "quad9" "Quad9 security DNS: 9.9.9.9, 149.112.112.112" \
      "custom" "Custom recursive resolvers" \
      3>&1 1>&2 2>&3)" || exit 1
  else
    echo
    echo "DNS upstream mode:"
    echo "  1) Internal/DC DNS resolvers"
    echo "  2) Cloudflare public DNS (1.1.1.1, 1.0.0.1)"
    echo "  3) Google public DNS (8.8.8.8, 8.8.4.4)"
    echo "  4) Quad9 security DNS (9.9.9.9, 149.112.112.112)"
    echo "  5) Custom recursive resolvers"
    while true; do
      read -r -p "Select DNS upstream mode [1-5]: " mode
      case "${mode}" in
        1) mode="internal"; break ;;
        2) mode="cloudflare"; break ;;
        3) mode="google"; break ;;
        4) mode="quad9"; break ;;
        5) mode="custom"; break ;;
        *) echo "Invalid DNS upstream mode." ;;
      esac
    done
  fi

  case "${mode}" in
    internal)
      prompt_dns_upstreams "Internal/DC DNS servers"
      ;;
    cloudflare)
      DNS_UPSTREAMS=("1.1.1.1:53" "1.0.0.1:53")
      ;;
    google)
      DNS_UPSTREAMS=("8.8.8.8:53" "8.8.4.4:53")
      ;;
    quad9)
      DNS_UPSTREAMS=("9.9.9.9:53" "149.112.112.112:53")
      ;;
    custom)
      prompt_dns_upstreams "Custom upstream DNS servers" "8.8.8.8,1.1.1.1"
      ;;
    *)
      ui_error "Invalid DNS upstream mode."
      configure_dns_upstreams
      ;;
  esac
}

prompt_nonempty() {
  local prompt="$1"
  local value

  while true; do
    if use_tui; then
      value="$(ui_input "${prompt}" "")" || exit 1
    else
      printf "%s: " "${prompt}" >&2
      read -r value
    fi
    if [[ -n "${value}" ]]; then
      printf "%s" "${value}"
      return
    fi
    ui_error "Value must not be empty."
  done
}

prompt_admin_credentials() {
  ADMIN_USERNAME="$(prompt_nonempty "Set Web UI admin username")"

  local password
  local confirmation
  while true; do
    if use_tui; then
      password="$(ui_password "Set Web UI admin password")" || exit 1
      confirmation="$(ui_password "Confirm Web UI admin password")" || exit 1
    else
      read -r -s -p "Set Web UI admin password: " password
      echo
      read -r -s -p "Confirm Web UI admin password: " confirmation
      echo
    fi

    if [[ -z "${password}" ]]; then
      ui_error "Password must not be empty."
      continue
    fi

    if [[ "${password}" != "${confirmation}" ]]; then
      ui_error "Passwords do not match."
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
    local discovered_proxy_ip
    local listen_ip
    local listen_port
    local target_ip
    local target_port
    local route_name

    vlan="$(prompt_optional_vlan "Client VLAN ID for ${proxy_interface}")"
    discovered_proxy_ip="$(get_interface_ipv4 "${proxy_interface}")"
    if [[ -z "${discovered_proxy_ip}" ]]; then
      discovered_proxy_ip="${LISTEN_DEFAULT_IP}"
    fi
    listen_ip="$(prompt_ipv4 "SMB listen IPv4 for ${proxy_interface}" "${discovered_proxy_ip}")"
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

  DNS_ENABLED="false"
  DNS_INTERFACE=""
  DNS_BIND_IP="${LISTEN_DEFAULT_IP}"
  DNS_UDP_PORT="${DNS_DEFAULT_PORT}"
  DNS_TCP_PORT="${DNS_DEFAULT_PORT}"
  DNS_UPSTREAM_INTERFACE=""
  DNS_UPSTREAMS=()
  DNS_THREAT_FEED_URLS=()

  echo
  if prompt_yes_no "Enable Axiom DNS Security Gateway" "yes"; then
    DNS_ENABLED="true"
    select_dns_interface

    local discovered_dns_ip
    discovered_dns_ip="$(get_interface_ipv4 "${DNS_INTERFACE}")"
    if [[ -z "${discovered_dns_ip}" ]]; then
      discovered_dns_ip="${LISTEN_DEFAULT_IP}"
    fi

    DNS_BIND_IP="$(prompt_ipv4 "DNS listen IPv4 for ${DNS_INTERFACE}" "${discovered_dns_ip}")"
    DNS_UDP_PORT="$(prompt_port "DNS UDP port" "${DNS_DEFAULT_PORT}")"
    DNS_TCP_PORT="$(prompt_port "DNS TCP port" "${DNS_DEFAULT_PORT}")"
    DNS_UPSTREAM_INTERFACE="${DNS_INTERFACE}"
    configure_dns_upstreams

    if prompt_yes_no "Enable the built-in URLhaus DNS threat feed" "yes"; then
      DNS_THREAT_FEED_URLS=("${DNS_DEFAULT_THREAT_FEED_URL}")
    fi
  fi

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
    echo "[dns]"
    echo "enabled = ${DNS_ENABLED}"
    if [[ "${DNS_ENABLED}" == "true" ]]; then
      echo "interface = \"$(toml_escape "${DNS_INTERFACE}")\""
      echo "listen_ip = \"$(toml_escape "${DNS_BIND_IP}")\""
      echo "udp_port = ${DNS_UDP_PORT}"
      echo "tcp_port = ${DNS_TCP_PORT}"
      echo "upstream_interface = \"$(toml_escape "${DNS_UPSTREAM_INTERFACE}")\""
      printf "upstreams = ["
      for index in "${!DNS_UPSTREAMS[@]}"; do
        if ((index > 0)); then
          printf ", "
        fi
        printf "\"%s\"" "$(toml_escape "${DNS_UPSTREAMS[${index}]}")"
      done
      printf "]\n"
      echo "cache_ttl_seconds = 300"
      echo "cache_max_entries = 100000"
      echo "query_timeout_millis = 1500"
      echo "threat_feed_refresh_seconds = 3600"
      echo
      echo "[dns.policy]"
      echo "blocked_domain_action = \"block\""
      echo "monitored_domain_action = \"monitor\""
      echo "blocked_domains = []"
      echo "monitored_domains = []"
      printf "threat_feed_urls = ["
      for index in "${!DNS_THREAT_FEED_URLS[@]}"; do
        if ((index > 0)); then
          printf ", "
        fi
        printf "\"%s\"" "$(toml_escape "${DNS_THREAT_FEED_URLS[${index}]}")"
      done
      printf "]\n"
      echo "block_response = \"nxdomain\""
      echo "sinkhole_ipv4 = \"0.0.0.0\""
      echo
    fi
    echo "[policy.smb]"
    echo "encrypted_payload = \"monitor\""
    echo
    echo "[policy.archive]"
    echo "rar = \"block\""
    echo "seven_zip = \"block\""
    echo "zip = \"block\""
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
    echo "name = \"EICAR antivirus test string\""
    echo 'pattern = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"'
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
  local axiom_rustflags="-C linker=cc -C link-self-contained=no -C link-arg=-fuse-ld=bfd"
  if [[ -n "${RUSTFLAGS:-}" ]]; then
    axiom_rustflags="${RUSTFLAGS} ${axiom_rustflags}"
  fi

  echo "Using system linker for release build: cc with ld.bfd"
  (
    cd "${PROJECT_ROOT}"
    RUSTFLAGS="${axiom_rustflags}" cargo build --release -p axiom-daemon
  )

  ${SUDO} install -m 0755 -o root -g root "${BINARY_SOURCE}" "${BINARY_PATH}"
  ${SUDO} setcap 'cap_net_bind_service,cap_net_raw+ep' "${BINARY_PATH}"
}

warn_if_smb_nat_rules_exist() {
  local nft_matches=""
  local iptables_matches=""

  if command -v nft >/dev/null 2>&1; then
    nft_matches="$(${SUDO} nft list ruleset 2>/dev/null | grep -Ei 'tcp dport (445|microsoft-ds)|dport 445|:445' || true)"
  fi

  if command -v iptables-save >/dev/null 2>&1; then
    iptables_matches="$(${SUDO} iptables-save 2>/dev/null | grep -Ei -- '--dport 445|dpt:445|:445' || true)"
  fi

  if [[ -n "${nft_matches}${iptables_matches}" ]]; then
    echo
    echo "WARNING: Existing firewall/NAT rules reference TCP 445."
    echo "Axiom is a user-space reverse proxy. DNAT/REDIRECT/FORWARD rules for SMB can bypass inspection."
    echo "Review these rules if dashboard counters stay at zero after a client connects:"
    if [[ -n "${nft_matches}" ]]; then
      echo
      echo "nft matches:"
      echo "${nft_matches}"
    fi
    if [[ -n "${iptables_matches}" ]]; then
      echo
      echo "iptables matches:"
      echo "${iptables_matches}"
    fi
  fi
}

configure_reverse_proxy_network_mode() {
  local temp_sysctl
  temp_sysctl="$(mktemp)"

  cat > "${temp_sysctl}" <<EOF
# Managed by Axiom installer.
# Axiom is a user-space SMB reverse proxy, not a Linux L3 forwarding gateway.
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
EOF

  ${SUDO} install -m 0644 -o root -g root "${temp_sysctl}" /etc/sysctl.d/99-axiom-reverse-proxy.conf
  rm -f "${temp_sysctl}"

  echo
  echo "Disabling kernel IPv4 forwarding so SMB traffic cannot bypass Axiom inspection."
  ${SUDO} sysctl -q -p /etc/sysctl.d/99-axiom-reverse-proxy.conf
  warn_if_smb_nat_rules_exist
}

write_systemd_service() {
  local temp_service
  temp_service="$(mktemp)"

  cat > "${temp_service}" <<EOF
[Unit]
Description=Axiom SMB and DNS Security Gateway
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
Environment=RUST_LOG=axiom=info,axiom_daemon=info,axiom_dns=info
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/axiom /var/lib/axiom /var/log/axiom
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

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
  if [[ "${DNS_ENABLED}" == "true" ]]; then
    echo "DNS Gateway: ${DNS_BIND_IP}:${DNS_UDP_PORT}/udp and ${DNS_BIND_IP}:${DNS_TCP_PORT}/tcp -> ${DNS_UPSTREAMS[*]}"
  fi
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
  configure_reverse_proxy_network_mode
  write_systemd_service
  enable_and_start_service
  print_summary
}

main "$@"
