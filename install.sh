#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="/etc/axiom"
CONFIG_PATH="${CONFIG_DIR}/axiom.toml"
BINARY_NAME="axiom-daemon"
BINARY_SOURCE="${PROJECT_ROOT}/target/release/${BINARY_NAME}"
BINARY_PATH="/usr/local/bin/${BINARY_NAME}"
LICENSE_TOOL_NAME="axiom-license-tool"
LICENSE_TOOL_SOURCE="${PROJECT_ROOT}/target/release/${LICENSE_TOOL_NAME}"
LICENSE_TOOL_PATH="/usr/local/bin/${LICENSE_TOOL_NAME}"
SERVICE_PATH="/etc/systemd/system/axiom.service"
RESTART_HELPER_PATH="/usr/local/sbin/axiom-restart-service"
SUDOERS_PATH="/etc/sudoers.d/axiom-management"
SERVICE_USER="axiom"
SERVICE_GROUP="axiom"
MANAGEMENT_DEFAULT_PORT="8443"
NODE_CONTROL_DEFAULT_PORT="9443"
SMB_DEFAULT_PORT="445"
DNS_DEFAULT_PORT="53"
LISTEN_DEFAULT_IP="0.0.0.0"
DNS_DEFAULT_THREAT_FEED_URL="https://urlhaus.abuse.ch/downloads/hostfile/"
MIN_RUST_VERSION="1.88.0"
LOCAL_AGENT_MANAGEMENT_INTERFACE="lo"
LOCAL_AGENT_MANAGEMENT_IP="127.0.0.1"
AXIOM_LICENSE_PUBLIC_KEY_HEX="${AXIOM_LICENSE_PUBLIC_KEY_HEX:-}"
AXIOM_INSTALL_LICENSE_TOOL="${AXIOM_INSTALL_LICENSE_TOOL:-0}"
INSTALL_MODE="install"
PURGE_DATA_ON_UNINSTALL="false"

trap 'echo "Axiom installation failed. Review the error above and rerun install.sh." >&2' ERR

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

print_usage() {
  cat <<EOF
Usage: ./install.sh [options]

Options:
  --install       Run the interactive installer. This is the default.
  --repair        Rebuild and reinstall the binary, service, and helpers while preserving /etc/axiom/axiom.toml.
  --uninstall     Stop and remove the Axiom service and binaries. Configuration, data, and logs are kept.
  --purge         With --uninstall, also remove /etc/axiom, /var/lib/axiom, and /var/log/axiom.
  --cli           Force the plain CLI wizard instead of whiptail.
  -h, --help      Show this help message.

Environment:
  AXIOM_INSTALLER_CLI=1              Force plain CLI prompts.
  AXIOM_LICENSE_PUBLIC_KEY_HEX=...   Install the official license verification public key.
  AXIOM_INSTALL_LICENSE_TOOL=1       Install the internal license issuing tool on trusted staff systems only.
EOF
}

parse_args() {
  while (($# > 0)); do
    case "$1" in
      --install)
        INSTALL_MODE="install"
        ;;
      --repair)
        INSTALL_MODE="repair"
        ;;
      --uninstall)
        INSTALL_MODE="uninstall"
        ;;
      --purge)
        PURGE_DATA_ON_UNINSTALL="true"
        ;;
      --cli)
        export AXIOM_INSTALLER_CLI=1
        ;;
      -h | --help)
        print_usage
        exit 0
        ;;
      *)
        echo "Unknown option: $1" >&2
        print_usage >&2
        exit 1
        ;;
    esac
    shift
  done

  if [[ "${PURGE_DATA_ON_UNINSTALL}" == "true" && "${INSTALL_MODE}" != "uninstall" ]]; then
    echo "--purge can only be used with --uninstall." >&2
    exit 1
  fi
}

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
    ["cmake"]="cmake"
    ["systemctl"]="systemd"
    ["setcap"]="libcap2-bin"
    ["sha256sum"]="coreutils"
    ["sysctl"]="procps"
    ["curl"]="curl"
    ["python3"]="python3"
    ["tar"]="tar"
    ["gzip"]="gzip"
    ["sudo"]="sudo"
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
    cmake \
    openssl \
    pkg-config \
    sudo \
    whiptail

  for command_name in ip cmake systemctl setcap sha256sum sysctl curl python3 tar gzip cc ld.bfd openssl sudo visudo; do
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

validate_release_options() {
  case "${AXIOM_INSTALL_LICENSE_TOOL}" in
    1 | true | yes | on)
      AXIOM_INSTALL_LICENSE_TOOL="1"
      ;;
    0 | false | no | off | "")
      AXIOM_INSTALL_LICENSE_TOOL="0"
      ;;
    *)
      echo "AXIOM_INSTALL_LICENSE_TOOL must be 0 or 1." >&2
      exit 1
      ;;
  esac

  if [[ -n "${AXIOM_LICENSE_PUBLIC_KEY_HEX}" && ! "${AXIOM_LICENSE_PUBLIC_KEY_HEX}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    echo "AXIOM_LICENSE_PUBLIC_KEY_HEX must be a 64-character hex encoded Ed25519 public key." >&2
    exit 1
  fi
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

select_node_role() {
  if use_tui; then
    NODE_ROLE="$(whiptail --title "Axiom installer" --menu "Select this server role" 18 86 8 \
      "management" "Central Web UI, policy control plane, node registry" \
      "dns" "DNS Security data-plane node managed by a central server" \
      "smb_proxy" "SMB Reverse Proxy data-plane node managed by a central server" \
      "standalone_lab" "Single-server evaluation mode: management + optional DNS + SMB" \
      3>&1 1>&2 2>&3)" || exit 1
    return
  fi

  echo
  echo "Axiom server role:"
  echo "  1) management      Central Web UI and policy control plane"
  echo "  2) dns             DNS Security data-plane node"
  echo "  3) smb_proxy       SMB Reverse Proxy data-plane node"
  echo "  4) standalone_lab  Single-server evaluation mode"
  while true; do
    read -r -p "Select role [1-4]: " role_selection
    case "${role_selection}" in
      1) NODE_ROLE="management"; return ;;
      2) NODE_ROLE="dns"; return ;;
      3) NODE_ROLE="smb_proxy"; return ;;
      4) NODE_ROLE="standalone_lab"; return ;;
      *) echo "Invalid role selection." ;;
    esac
  done
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

select_dns_upstream_interface() {
  if use_tui; then
    if DNS_UPSTREAM_INTERFACE="$(select_interface_tui "Select the interface Axiom should use to reach upstream DNS resolvers")"; then
      return
    fi
  fi

  while true; do
    print_interfaces
    read -r -p "Select the upstream DNS egress interface [number]: " selection
    if [[ "${selection}" =~ ^[0-9]+$ ]] && ((selection >= 1 && selection <= ${#INTERFACES[@]})); then
      DNS_UPSTREAM_INTERFACE="${INTERFACES[$((selection - 1))]}"
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

prompt_optional() {
  local prompt="$1"
  local default_value="${2:-}"
  local value

  if use_tui; then
    value="$(ui_input "${prompt}" "${default_value}")" || exit 1
    printf "%s" "${value:-${default_value}}"
  else
    if [[ -n "${default_value}" ]]; then
      printf "%s [%s]: " "${prompt}" "${default_value}" >&2
    else
      printf "%s [empty to skip]: " "${prompt}" >&2
    fi
    read -r value
    printf "%s" "${value:-${default_value}}"
  fi
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

configure_management_ui() {
  select_management_interface

  local discovered_management_ip
  discovered_management_ip="$(get_interface_ipv4 "${MANAGEMENT_INTERFACE}")"
  MANAGEMENT_BIND_IP="$(prompt_ipv4 "Management UI bind IPv4 for ${MANAGEMENT_INTERFACE}" "${discovered_management_ip}")"
  MANAGEMENT_PORT="$(prompt_port "Management UI TCP port" "${MANAGEMENT_DEFAULT_PORT}")"
  configure_management_tls
  configure_directory_integration
  prompt_admin_credentials
  ADMIN_PASSWORD_HASH="$(sha256_password_hash "${ADMIN_PASSWORD}")"
  unset ADMIN_PASSWORD
}

configure_management_tls() {
  MANAGEMENT_TLS_ENABLED="false"
  MANAGEMENT_TLS_CERT_PATH="/etc/axiom/tls/axiom.crt"
  MANAGEMENT_TLS_KEY_PATH="/etc/axiom/tls/axiom.key"

  if prompt_yes_no "Enable HTTPS for the Web Management UI" "no"; then
    MANAGEMENT_TLS_ENABLED="true"
    MANAGEMENT_TLS_CERT_PATH="$(prompt_optional "TLS certificate path" "${MANAGEMENT_TLS_CERT_PATH}")"
    MANAGEMENT_TLS_KEY_PATH="$(prompt_optional "TLS private key path" "${MANAGEMENT_TLS_KEY_PATH}")"
  fi
}

configure_directory_integration() {
  DIRECTORY_ENABLED="false"
  DIRECTORY_URL=""
  DIRECTORY_USER_BIND_FORMAT="{username}"
  DIRECTORY_BIND_DN=""
  DIRECTORY_BIND_PASSWORD=""
  DIRECTORY_BASE_DN=""
  DIRECTORY_USER_FILTER="(sAMAccountName={username})"
  DIRECTORY_REQUIRED_GROUP_DN=""
  DIRECTORY_CLIENT_REVERSE_DNS="false"

  if ! prompt_yes_no "Enable Active Directory login for the Management UI" "no"; then
    return
  fi

  DIRECTORY_ENABLED="true"
  DIRECTORY_URL="$(prompt_nonempty "LDAP URL, for example ldap://192.168.0.10:389 or ldaps://dc01.domain.local:636")"
  DIRECTORY_BASE_DN="$(prompt_nonempty "LDAP base DN, for example DC=example,DC=local")"
  DIRECTORY_USER_BIND_FORMAT="$(prompt_optional "User bind format" "{username}")"
  DIRECTORY_USER_FILTER="$(prompt_optional "User search filter" "(sAMAccountName={username})")"
  DIRECTORY_REQUIRED_GROUP_DN="$(prompt_optional "Required admin group DN")"
  DIRECTORY_BIND_DN="$(prompt_optional "Service bind DN for group checks")"
  if [[ -n "${DIRECTORY_BIND_DN}" ]]; then
    if use_tui; then
      DIRECTORY_BIND_PASSWORD="$(ui_password "Service bind password")" || exit 1
    else
      read -r -s -p "Service bind password: " DIRECTORY_BIND_PASSWORD
      echo
    fi
  fi

  if prompt_yes_no "Resolve client names through reverse DNS" "yes"; then
    DIRECTORY_CLIENT_REVERSE_DNS="true"
  else
    DIRECTORY_CLIENT_REVERSE_DNS="false"
  fi
}

configure_agent_management_stub() {
  MANAGEMENT_INTERFACE="${LOCAL_AGENT_MANAGEMENT_INTERFACE}"
  MANAGEMENT_BIND_IP="${LOCAL_AGENT_MANAGEMENT_IP}"
  MANAGEMENT_PORT="${MANAGEMENT_DEFAULT_PORT}"
  MANAGEMENT_TLS_ENABLED="false"
  MANAGEMENT_TLS_CERT_PATH=""
  MANAGEMENT_TLS_KEY_PATH=""
  DIRECTORY_ENABLED="false"
  DIRECTORY_URL=""
  DIRECTORY_USER_BIND_FORMAT="{username}"
  DIRECTORY_BIND_DN=""
  DIRECTORY_BIND_PASSWORD=""
  DIRECTORY_BASE_DN=""
  DIRECTORY_USER_FILTER="(sAMAccountName={username})"
  DIRECTORY_REQUIRED_GROUP_DN=""
  DIRECTORY_CLIENT_REVERSE_DNS="false"
  ADMIN_USERNAME="local-agent-node"
  ADMIN_PASSWORD_HASH="$(sha256_password_hash "$(random_secret)")"
}

configure_agent_registration() {
  NODE_CLUSTER_ENABLED="false"
  NODE_CLUSTER_NAME=""
  CLUSTER_JOIN_RESPONSE_PATH=""

  if prompt_yes_no "Join this node to an existing Axiom cluster" "no"; then
    configure_cluster_registration
    return
  fi

  configure_direct_agent_registration
}

configure_direct_agent_registration() {
  NODE_ENROLLMENT_VALIDATED="false"

  while true; do
    NODE_MANAGEMENT_URL="$(prompt_nonempty "Management server URL, for example http://10.0.0.5:8443")"
    NODE_ENROLLMENT_TOKEN="$(prompt_nonempty "Enrollment token from the Axiom management server")"
    NODE_ALLOW_INVALID_MANAGEMENT_TLS="false"

    if [[ "${NODE_MANAGEMENT_URL}" == https://* ]]; then
      if prompt_yes_no "Allow this node to trust a self-signed Management HTTPS certificate" "no"; then
        NODE_ALLOW_INVALID_MANAGEMENT_TLS="true"
      fi
    fi

    if validate_agent_enrollment; then
      NODE_ENROLLMENT_VALIDATED="true"
      return
    fi

    if prompt_yes_no "Continue without successful Management enrollment validation" "no"; then
      return
    fi

    echo "Retrying Management enrollment settings."
  done
}

configure_cluster_registration() {
  local cluster_password
  local response_path
  local request_path
  local curl_error_path
  local http_code
  local curl_args=()
  local response_preview

  while true; do
    NODE_MANAGEMENT_URL="$(prompt_nonempty "Management server URL, for example https://10.0.0.5:8443")"
    NODE_MANAGEMENT_URL="${NODE_MANAGEMENT_URL%/}"
    NODE_ALLOW_INVALID_MANAGEMENT_TLS="false"
    if [[ "${NODE_MANAGEMENT_URL}" == https://* ]] \
      && prompt_yes_no "Allow this node to trust a self-signed Management HTTPS certificate" "no"; then
      NODE_ALLOW_INVALID_MANAGEMENT_TLS="true"
    fi
    if [[ "${NODE_MANAGEMENT_URL}" == http://* ]] \
      && ! prompt_yes_no "This will send the cluster join password over HTTP. Continue only in an isolated lab" "no"; then
      echo "Use an HTTPS Management URL for production cluster enrollment."
      continue
    fi
    NODE_CLUSTER_NAME="$(prompt_nonempty "Cluster name from Axiom Cluster Center")"
    if use_tui; then
      cluster_password="$(ui_password "Cluster join password")" || exit 1
    else
      read -r -s -p "Cluster join password: " cluster_password
      echo
    fi

    request_path="$(mktemp)"
    response_path="$(mktemp)"
    curl_error_path="$(mktemp)"
    python3 - "${NODE_CLUSTER_NAME}" "${cluster_password}" "${NODE_ID}" "${NODE_ROLE}" > "${request_path}" <<'PY'
import json
import sys

print(json.dumps({
    "name": sys.argv[1],
    "password": sys.argv[2],
    "node_id": sys.argv[3],
    "role": sys.argv[4],
}))
PY
    unset cluster_password

    curl_args=(
      -sS
      --connect-timeout 5
      --max-time 20
      -o "${response_path}"
      -w "%{http_code}"
      -H "Content-Type: application/json"
      --data-binary "@${request_path}"
      "${NODE_MANAGEMENT_URL}/api/clusters/join"
    )
    if [[ "${NODE_ALLOW_INVALID_MANAGEMENT_TLS}" == "true" ]]; then
      curl_args=(-k "${curl_args[@]}")
    fi

    if ! http_code="$(curl "${curl_args[@]}" 2>"${curl_error_path}")"; then
      response_preview="$(head -c 220 "${curl_error_path}" 2>/dev/null || true)"
      rm -f "${request_path}" "${response_path}" "${curl_error_path}"
      ui_error "Could not reach Management server at ${NODE_MANAGEMENT_URL}: ${response_preview}"
    elif [[ "${http_code}" != "200" ]]; then
      response_preview="$(python3 - "${response_path}" <<'PY'
import json
import sys
try:
    payload = json.load(open(sys.argv[1], encoding="utf-8"))
    print(payload.get("message") or payload.get("error") or "cluster join rejected")
except Exception:
    print("cluster join rejected")
PY
)"
      rm -f "${request_path}" "${response_path}" "${curl_error_path}"
      ui_error "Cluster enrollment failed with HTTP ${http_code}: ${response_preview}"
    else
      NODE_ENROLLMENT_TOKEN="$(python3 - "${response_path}" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
print(payload.get("enrollment_token", ""))
PY
)"
      if [[ ! "${NODE_ENROLLMENT_TOKEN}" =~ ^[A-Fa-f0-9]{32,128}$ ]]; then
        rm -f "${request_path}" "${response_path}" "${curl_error_path}"
        ui_error "Management returned an invalid cluster credential."
      else
        rm -f "${request_path}" "${curl_error_path}"
        NODE_CLUSTER_ENABLED="true"
        CLUSTER_JOIN_RESPONSE_PATH="${response_path}"
        NODE_ENROLLMENT_VALIDATED="true"
        echo "Cluster enrollment validated. Shared service settings will be imported from ${NODE_CLUSTER_NAME}."
        return
      fi
    fi

    if ! prompt_yes_no "Retry cluster enrollment" "yes"; then
      echo "Cluster enrollment is required for a cluster replica." >&2
      exit 1
    fi
  done
}

validate_agent_enrollment() {
  local normalized_management_url
  local response_path
  local curl_error_path
  local curl_args=()
  local http_code
  local response_preview

  normalized_management_url="${NODE_MANAGEMENT_URL%/}"
  NODE_MANAGEMENT_URL="${normalized_management_url}"

  if [[ ! "${NODE_MANAGEMENT_URL}" =~ ^https?:// ]]; then
    ui_error "Management URL must start with http:// or https://"
    return 1
  fi

  if [[ ! "${NODE_ENROLLMENT_TOKEN}" =~ ^[A-Fa-f0-9]{32,128}$ ]]; then
    ui_error "Enrollment token does not look like an Axiom token. Copy it from Management UI -> Settings -> Enrollment Token."
    return 1
  fi

  response_path="$(mktemp)"
  curl_error_path="$(mktemp)"

  if [[ "${NODE_ALLOW_INVALID_MANAGEMENT_TLS}" == "true" ]]; then
    curl_args+=("-k")
  fi

  curl_args+=(
    -sS
    --connect-timeout 4
    --max-time 10
    -o "${response_path}"
    -w "%{http_code}"
    -H "Authorization: Bearer ${NODE_ENROLLMENT_TOKEN}"
    "${NODE_MANAGEMENT_URL}/api/nodes/runtime-config"
  )

  if ! http_code="$(curl "${curl_args[@]}" 2>"${curl_error_path}")"; then
    response_preview="$(head -c 220 "${curl_error_path}" 2>/dev/null || true)"
    rm -f "${response_path}" "${curl_error_path}"
    ui_error "Could not reach Management server at ${NODE_MANAGEMENT_URL}: ${response_preview}"
    return 1
  fi

  response_preview="$(head -c 220 "${response_path}" 2>/dev/null || true)"
  rm -f "${response_path}" "${curl_error_path}"

  case "${http_code}" in
    200)
      echo "Management enrollment token validated successfully."
      return 0
      ;;
    401)
      ui_error "Management rejected the enrollment token with HTTP 401. Copy the exact token from Management UI -> Settings."
      return 1
      ;;
    000)
      ui_error "Management server did not respond at ${NODE_MANAGEMENT_URL}."
      return 1
      ;;
    *)
      ui_error "Management enrollment validation failed with HTTP ${http_code}: ${response_preview}"
      return 1
      ;;
  esac
}

select_node_control_interface() {
  if use_tui; then
    if NODE_CONTROL_INTERFACE="$(select_interface_tui "Select the interface that should accept encrypted management push requests")"; then
      return
    fi
  fi

  while true; do
    print_interfaces
    read -r -p "Select the interface for encrypted management push requests [number]: " selection
    if [[ "${selection}" =~ ^[0-9]+$ ]] && ((selection >= 1 && selection <= ${#INTERFACES[@]})); then
      NODE_CONTROL_INTERFACE="${INTERFACES[$((selection - 1))]}"
      return
    fi
    echo "Invalid interface selection."
  done
}

configure_node_control_listener() {
  NODE_CONTROL_ENABLED="true"
  select_node_control_interface

  local discovered_control_ip
  discovered_control_ip="$(get_interface_ipv4 "${NODE_CONTROL_INTERFACE}")"
  NODE_CONTROL_BIND_IP="$(prompt_ipv4 "Node control listen IPv4 for ${NODE_CONTROL_INTERFACE}" "${discovered_control_ip}")"
  NODE_CONTROL_PORT="$(prompt_port "Node control TCP port" "${NODE_CONTROL_DEFAULT_PORT}")"
}

configure_node_identity() {
  local default_id
  local default_name
  default_id="$(hostname -s 2>/dev/null || printf "axiom-node")"
  default_id="$(printf "%s-%s" "${NODE_ROLE}" "${default_id}" | tr -c 'A-Za-z0-9_-' '-')"
  default_name="Axiom ${NODE_ROLE} node"

  if use_tui; then
    NODE_ID="$(ui_input "Axiom node ID" "${default_id}")" || exit 1
    NODE_ID="${NODE_ID:-${default_id}}"
  else
    printf "Axiom node ID [%s]: " "${default_id}" >&2
    read -r NODE_ID
    NODE_ID="${NODE_ID:-${default_id}}"
  fi

  if use_tui; then
    NODE_DISPLAY_NAME="$(ui_input "Axiom node display name" "${default_name}")" || exit 1
    NODE_DISPLAY_NAME="${NODE_DISPLAY_NAME:-${default_name}}"
  else
    printf "Axiom node display name [%s]: " "${default_name}" >&2
    read -r NODE_DISPLAY_NAME
    NODE_DISPLAY_NAME="${NODE_DISPLAY_NAME:-${default_name}}"
  fi
}

configure_proxy_listeners() {
  select_proxy_interfaces

  PROXY_NAMES=()
  PROXY_INTERFACES=()
  PROXY_VLANS=()
  PROXY_LISTEN_IPS=()
  PROXY_LISTEN_PORTS=()
  PROXY_TARGET_IPS=()
  PROXY_TARGET_PORTS=()
  PROXY_BACKLOGS=()

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
    PROXY_BACKLOGS+=("4096")
  done
}

select_cluster_route_interface() {
  local route_name="$1"
  local selection

  if use_tui; then
    select_interface_tui "Select the local interface for replicated SMB route ${route_name}"
    return
  fi

  while true; do
    print_interfaces
    read -r -p "Select the local interface for SMB route ${route_name} [number]: " selection
    if [[ "${selection}" =~ ^[0-9]+$ ]] && ((selection >= 1 && selection <= ${#INTERFACES[@]})); then
      printf "%s" "${INTERFACES[$((selection - 1))]}"
      return
    fi
    echo "Invalid interface selection."
  done
}

configure_proxy_listeners_from_cluster() {
  local route_count
  local index
  local template_row
  local template_name
  local vlan
  local listen_port
  local target_ip
  local target_port
  local backlog
  local proxy_interface
  local discovered_proxy_ip
  local listen_ip

  route_count="$(python3 - "${CLUSTER_JOIN_RESPONSE_PATH}" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
print(len(payload.get("service_template", {}).get("smb_routes", [])))
PY
)"
  if [[ ! "${route_count}" =~ ^[0-9]+$ ]] || ((route_count == 0)); then
    ui_error "The selected SMB cluster does not contain a usable proxy route template."
    exit 1
  fi

  PROXY_NAMES=()
  PROXY_INTERFACES=()
  PROXY_VLANS=()
  PROXY_LISTEN_IPS=()
  PROXY_LISTEN_PORTS=()
  PROXY_TARGET_IPS=()
  PROXY_TARGET_PORTS=()
  PROXY_BACKLOGS=()

  for ((index = 0; index < route_count; index++)); do
    template_row="$(python3 - "${CLUSTER_JOIN_RESPONSE_PATH}" "${index}" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
route = payload["service_template"]["smb_routes"][int(sys.argv[2])]
values = [
    route.get("name", "cluster-route"),
    "" if route.get("client_vlan") is None else str(route["client_vlan"]),
    str(route.get("listen_port", 445)),
    str(route["target_file_server_ip"]),
    str(route.get("target_file_server_port", 445)),
    str(route.get("backlog", 4096)),
]
print("|".join(values))
PY
)"
    IFS='|' read -r template_name vlan listen_port target_ip target_port backlog <<< "${template_row}"
    proxy_interface="$(select_cluster_route_interface "${template_name}")"
    discovered_proxy_ip="$(get_interface_ipv4 "${proxy_interface}")"
    if [[ -z "${discovered_proxy_ip}" ]]; then
      discovered_proxy_ip="${LISTEN_DEFAULT_IP}"
    fi
    listen_ip="$(prompt_ipv4 "Local SMB listen IPv4 for ${proxy_interface}" "${discovered_proxy_ip}")"

    PROXY_NAMES+=("$(safe_route_name "${proxy_interface}" "${vlan}")")
    PROXY_INTERFACES+=("${proxy_interface}")
    PROXY_VLANS+=("${vlan}")
    PROXY_LISTEN_IPS+=("${listen_ip}")
    PROXY_LISTEN_PORTS+=("${listen_port}")
    PROXY_TARGET_IPS+=("${target_ip}")
    PROXY_TARGET_PORTS+=("${target_port}")
    PROXY_BACKLOGS+=("${backlog}")
    echo "Imported SMB route ${template_name}: ${listen_ip}:${listen_port} -> ${target_ip}:${target_port}"
  done
}

configure_dns_gateway() {
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
  select_dns_upstream_interface
  configure_dns_upstreams

  if prompt_yes_no "Enable the built-in URLhaus DNS threat feed (can block domains immediately)" "no"; then
    DNS_THREAT_FEED_URLS=("${DNS_DEFAULT_THREAT_FEED_URL}")
  fi
}

configure_dns_gateway_from_cluster() {
  DNS_ENABLED="true"
  select_dns_interface

  local discovered_dns_ip
  local dns_values
  discovered_dns_ip="$(get_interface_ipv4 "${DNS_INTERFACE}")"
  if [[ -z "${discovered_dns_ip}" ]]; then
    discovered_dns_ip="${LISTEN_DEFAULT_IP}"
  fi
  DNS_BIND_IP="$(prompt_ipv4 "Local DNS listen IPv4 for ${DNS_INTERFACE}" "${discovered_dns_ip}")"
  select_dns_upstream_interface

  dns_values="$(python3 - "${CLUSTER_JOIN_RESPONSE_PATH}" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
dns = payload.get("service_template", {}).get("dns")
if not dns:
    raise SystemExit("missing DNS template")
print("|".join(str(value) for value in [
    dns.get("udp_port", 53),
    dns.get("tcp_port", 53),
    dns.get("cache_ttl_seconds", 300),
    dns.get("cache_max_entries", 100000),
    dns.get("query_timeout_millis", 1500),
    dns.get("threat_feed_refresh_seconds", 3600),
]))
PY
)" || {
    ui_error "The selected DNS cluster does not contain a usable DNS service template."
    exit 1
  }
  IFS='|' read -r DNS_UDP_PORT DNS_TCP_PORT DNS_CACHE_TTL_SECONDS DNS_CACHE_MAX_ENTRIES DNS_QUERY_TIMEOUT_MILLIS DNS_THREAT_FEED_REFRESH_SECONDS <<< "${dns_values}"
  mapfile -t DNS_UPSTREAMS < <(python3 - "${CLUSTER_JOIN_RESPONSE_PATH}" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
for upstream in payload["service_template"]["dns"].get("upstreams", []):
    print(upstream)
PY
)
  if ((${#DNS_UPSTREAMS[@]} == 0)); then
    ui_error "The selected DNS cluster template does not contain upstream resolvers."
    exit 1
  fi
  DNS_THREAT_FEED_URLS=()
  echo "Imported DNS service template: UDP ${DNS_UDP_PORT}, TCP ${DNS_TCP_PORT}, upstreams ${DNS_UPSTREAMS[*]}"
}

sha256_password_hash() {
  local password="$1"
  local salt
  local digest

  salt="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  digest="$(printf "%s:%s" "${salt}" "${password}" | sha256sum | awk '{ print $1 }')"
  printf "sha256\$%s\$%s" "${salt}" "${digest}"
}

random_secret() {
  od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
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
  select_node_role
  NODE_MANAGEMENT_URL=""
  NODE_ENROLLMENT_TOKEN=""
  NODE_ID=""
  NODE_DISPLAY_NAME=""
  NODE_CONTROL_ENABLED="false"
  NODE_ALLOW_INVALID_MANAGEMENT_TLS="false"
  NODE_CLUSTER_ENABLED="false"
  NODE_CLUSTER_NAME=""
  CLUSTER_JOIN_RESPONSE_PATH=""
  NODE_CONTROL_INTERFACE=""
  NODE_CONTROL_BIND_IP=""
  NODE_CONTROL_PORT="${NODE_CONTROL_DEFAULT_PORT}"
  MANAGEMENT_TLS_ENABLED="false"
  MANAGEMENT_TLS_CERT_PATH=""
  MANAGEMENT_TLS_KEY_PATH=""
  DIRECTORY_ENABLED="false"
  DIRECTORY_URL=""
  DIRECTORY_USER_BIND_FORMAT="{username}"
  DIRECTORY_BIND_DN=""
  DIRECTORY_BIND_PASSWORD=""
  DIRECTORY_BASE_DN=""
  DIRECTORY_USER_FILTER="(sAMAccountName={username})"
  DIRECTORY_REQUIRED_GROUP_DN=""
  DIRECTORY_CLIENT_REVERSE_DNS="false"
  PROXY_NAMES=()
  PROXY_INTERFACES=()
  PROXY_VLANS=()
  PROXY_LISTEN_IPS=()
  PROXY_LISTEN_PORTS=()
  PROXY_TARGET_IPS=()
  PROXY_TARGET_PORTS=()
  PROXY_BACKLOGS=()
  DNS_ENABLED="false"
  DNS_INTERFACE=""
  DNS_BIND_IP="${LISTEN_DEFAULT_IP}"
  DNS_UDP_PORT="${DNS_DEFAULT_PORT}"
  DNS_TCP_PORT="${DNS_DEFAULT_PORT}"
  DNS_UPSTREAM_INTERFACE=""
  DNS_UPSTREAMS=()
  DNS_THREAT_FEED_URLS=()
  DNS_CACHE_TTL_SECONDS="300"
  DNS_CACHE_MAX_ENTRIES="100000"
  DNS_QUERY_TIMEOUT_MILLIS="1500"
  DNS_THREAT_FEED_REFRESH_SECONDS="3600"

  case "${NODE_ROLE}" in
    management)
      configure_management_ui
      NODE_ID="$(hostname -s 2>/dev/null || printf "axiom-management")"
      NODE_DISPLAY_NAME="Axiom Management Server"
      NODE_ENROLLMENT_TOKEN="$(random_secret)"
      ;;
    dns)
      configure_agent_management_stub
      configure_node_identity
      configure_agent_registration
      configure_node_control_listener
      if [[ "${NODE_CLUSTER_ENABLED}" == "true" ]]; then
        configure_dns_gateway_from_cluster
      else
        configure_dns_gateway
      fi
      ;;
    smb_proxy)
      configure_agent_management_stub
      configure_node_identity
      configure_agent_registration
      configure_node_control_listener
      if [[ "${NODE_CLUSTER_ENABLED}" == "true" ]]; then
        configure_proxy_listeners_from_cluster
      else
        configure_proxy_listeners
      fi
      ;;
    standalone_lab)
      configure_management_ui
      NODE_ID="$(hostname -s 2>/dev/null || printf "axiom-standalone")"
      NODE_DISPLAY_NAME="Axiom Standalone Lab"
      NODE_ENROLLMENT_TOKEN="$(random_secret)"
      configure_proxy_listeners

      echo
      if prompt_yes_no "Enable Axiom DNS Security Gateway" "yes"; then
        configure_dns_gateway
      fi
      ;;
    *)
      echo "Unsupported role: ${NODE_ROLE}" >&2
      exit 1
      ;;
  esac
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

backup_existing_config() {
  if [[ ! -f "${CONFIG_PATH}" ]]; then
    return
  fi

  local backup_path
  backup_path="${CONFIG_PATH}.bak-$(date +%Y%m%d-%H%M%S)"
  ${SUDO} cp -a "${CONFIG_PATH}" "${backup_path}"
  echo "Existing config backed up to ${backup_path}"
}

read_config_role() {
  if [[ ! -f "${CONFIG_PATH}" ]]; then
    return 1
  fi

  ${SUDO} awk -F'"' '/^[[:space:]]*role[[:space:]]*=/ { print $2; exit }' "${CONFIG_PATH}"
}

config_has_proxy_listeners() {
  [[ -f "${CONFIG_PATH}" ]] && ${SUDO} grep -Eq '^[[:space:]]*\[\[proxy_listeners\]\]' "${CONFIG_PATH}"
}

write_config() {
  local temp_config
  temp_config="$(mktemp)"

  {
    echo "[node]"
    echo "role = \"$(toml_escape "${NODE_ROLE}")\""
    echo "node_id = \"$(toml_escape "${NODE_ID}")\""
    echo "display_name = \"$(toml_escape "${NODE_DISPLAY_NAME}")\""
    if [[ -n "${NODE_MANAGEMENT_URL}" ]]; then
      echo "management_url = \"$(toml_escape "${NODE_MANAGEMENT_URL}")\""
    fi
    if [[ -n "${NODE_ENROLLMENT_TOKEN}" ]]; then
      echo "enrollment_token = \"$(toml_escape "${NODE_ENROLLMENT_TOKEN}")\""
    fi
    echo "allow_invalid_management_tls = ${NODE_ALLOW_INVALID_MANAGEMENT_TLS}"
    echo "heartbeat_interval_seconds = 5"
    echo
    echo "[node.cluster]"
    echo "enabled = ${NODE_CLUSTER_ENABLED}"
    if [[ "${NODE_CLUSTER_ENABLED}" == "true" ]]; then
      echo "name = \"$(toml_escape "${NODE_CLUSTER_NAME}")\""
    fi
    echo
    echo "[node.control]"
    echo "enabled = ${NODE_CONTROL_ENABLED}"
    if [[ "${NODE_CONTROL_ENABLED}" == "true" ]]; then
      echo "interface = \"$(toml_escape "${NODE_CONTROL_INTERFACE}")\""
      echo "bind_ip = \"$(toml_escape "${NODE_CONTROL_BIND_IP}")\""
      echo "port = ${NODE_CONTROL_PORT}"
    fi
    echo
    echo "[management]"
    echo "interface = \"$(toml_escape "${MANAGEMENT_INTERFACE}")\""
    echo "bind_ip = \"$(toml_escape "${MANAGEMENT_BIND_IP}")\""
    echo "port = ${MANAGEMENT_PORT}"
    echo
    echo "[management.admin]"
    echo "username = \"$(toml_escape "${ADMIN_USERNAME}")\""
    echo "password_hash = \"$(toml_escape "${ADMIN_PASSWORD_HASH}")\""
    echo
    echo "[management.tls]"
    echo "enabled = ${MANAGEMENT_TLS_ENABLED}"
    if [[ -n "${MANAGEMENT_TLS_CERT_PATH}" ]]; then
      echo "cert_path = \"$(toml_escape "${MANAGEMENT_TLS_CERT_PATH}")\""
    fi
    if [[ -n "${MANAGEMENT_TLS_KEY_PATH}" ]]; then
      echo "key_path = \"$(toml_escape "${MANAGEMENT_TLS_KEY_PATH}")\""
    fi
    echo
    echo "[management.directory]"
    echo "enabled = ${DIRECTORY_ENABLED}"
    echo "client_reverse_dns = ${DIRECTORY_CLIENT_REVERSE_DNS}"
    if [[ "${DIRECTORY_ENABLED}" == "true" ]]; then
      echo "url = \"$(toml_escape "${DIRECTORY_URL}")\""
      echo "user_bind_format = \"$(toml_escape "${DIRECTORY_USER_BIND_FORMAT}")\""
      if [[ -n "${DIRECTORY_BIND_DN}" ]]; then
        echo "bind_dn = \"$(toml_escape "${DIRECTORY_BIND_DN}")\""
        echo "bind_password = \"$(toml_escape "${DIRECTORY_BIND_PASSWORD}")\""
      fi
      echo "base_dn = \"$(toml_escape "${DIRECTORY_BASE_DN}")\""
      echo "user_filter = \"$(toml_escape "${DIRECTORY_USER_FILTER}")\""
      if [[ -n "${DIRECTORY_REQUIRED_GROUP_DN}" ]]; then
        echo "required_group_dn = \"$(toml_escape "${DIRECTORY_REQUIRED_GROUP_DN}")\""
      fi
    fi
    echo
    echo "[license]"
    echo "enabled = true"
    echo "license_path = \"/etc/axiom/license.json\""
    echo "state_path = \"/var/lib/axiom/license-state.json\""
    echo "trial_days = 30"
    echo "warn_before_expiry_days = 14"
    echo "public_key_hex = \"$(toml_escape "${AXIOM_LICENSE_PUBLIC_KEY_HEX}")\""
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
      echo "cache_ttl_seconds = ${DNS_CACHE_TTL_SECONDS}"
      echo "cache_max_entries = ${DNS_CACHE_MAX_ENTRIES}"
      echo "query_timeout_millis = ${DNS_QUERY_TIMEOUT_MILLIS}"
      echo "threat_feed_refresh_seconds = ${DNS_THREAT_FEED_REFRESH_SECONDS}"
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
      echo "block_response = \"sinkhole\""
      echo "sinkhole_ipv4 = \"0.0.0.0\""
      echo "local_records = []"
      echo
      echo "[dns.policy.block_page]"
      echo "enabled = true"
      echo "organization_name = \"Axiom Security\""
      echo "title = \"Access to this site has been blocked\""
      echo "message = \"This domain was blocked by your organization's DNS security policy.\""
      echo "primary_color = \"#34f5c5\""
      echo "support_text = \"Contact your IT or security team if you believe this is an error.\""
      echo "support_url = \"\""
      echo "logo_data_url = \"\""
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
    echo "[policy.reputation]"
    echo "enabled = true"
    echo "known_bad_action = \"alert\""
    echo "cache_ttl_seconds = 3600"
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
      echo "backlog = ${PROXY_BACKLOGS[${index}]}"
    done
  } > "${temp_config}"

  ${SUDO} install -d -m 0770 -o root -g "${SERVICE_GROUP}" "${CONFIG_DIR}"
  ${SUDO} install -m 0660 -o root -g "${SERVICE_GROUP}" "${temp_config}" "${CONFIG_PATH}"
  rm -f "${temp_config}"
}

prepare_tls_certificate() {
  if [[ "${NODE_ROLE}" != "management" && "${NODE_ROLE}" != "standalone_lab" ]]; then
    return
  fi

  if [[ -z "${MANAGEMENT_TLS_CERT_PATH}" || -z "${MANAGEMENT_TLS_KEY_PATH}" ]]; then
    return
  fi

  local tls_dir
  tls_dir="$(dirname "${MANAGEMENT_TLS_CERT_PATH}")"
  ${SUDO} install -d -m 0750 -o root -g "${SERVICE_GROUP}" "${tls_dir}"

  if [[ -f "${MANAGEMENT_TLS_CERT_PATH}" && -f "${MANAGEMENT_TLS_KEY_PATH}" ]]; then
    ${SUDO} chown root:"${SERVICE_GROUP}" "${MANAGEMENT_TLS_CERT_PATH}" "${MANAGEMENT_TLS_KEY_PATH}"
    ${SUDO} chmod 0644 "${MANAGEMENT_TLS_CERT_PATH}"
    ${SUDO} chmod 0640 "${MANAGEMENT_TLS_KEY_PATH}"
    validate_tls_certificate_pair
    return
  fi

  local subject_alt_name
  subject_alt_name="IP:${MANAGEMENT_BIND_IP},DNS:axiom-management"

  ${SUDO} openssl req \
    -x509 \
    -nodes \
    -newkey rsa:3072 \
    -sha256 \
    -days 825 \
    -subj "/CN=${MANAGEMENT_BIND_IP}" \
    -addext "subjectAltName=${subject_alt_name}" \
    -keyout "${MANAGEMENT_TLS_KEY_PATH}" \
    -out "${MANAGEMENT_TLS_CERT_PATH}"

  ${SUDO} chown root:"${SERVICE_GROUP}" "${MANAGEMENT_TLS_CERT_PATH}" "${MANAGEMENT_TLS_KEY_PATH}"
  ${SUDO} chmod 0644 "${MANAGEMENT_TLS_CERT_PATH}"
  ${SUDO} chmod 0640 "${MANAGEMENT_TLS_KEY_PATH}"
  validate_tls_certificate_pair
}

validate_tls_certificate_pair() {
  if [[ "${NODE_ROLE}" != "management" && "${NODE_ROLE}" != "standalone_lab" ]]; then
    return
  fi

  if [[ "${MANAGEMENT_TLS_ENABLED}" != "true" ]]; then
    return
  fi

  ${SUDO} openssl x509 -in "${MANAGEMENT_TLS_CERT_PATH}" -noout >/dev/null
  ${SUDO} openssl pkey -in "${MANAGEMENT_TLS_KEY_PATH}" -noout >/dev/null

  local cert_public_hash
  local key_public_hash
  cert_public_hash="$(
    ${SUDO} openssl x509 -in "${MANAGEMENT_TLS_CERT_PATH}" -pubkey -noout \
      | openssl pkey -pubin -outform DER 2>/dev/null \
      | sha256sum \
      | awk '{print $1}'
  )"
  key_public_hash="$(
    ${SUDO} openssl pkey -in "${MANAGEMENT_TLS_KEY_PATH}" -pubout -outform DER 2>/dev/null \
      | sha256sum \
      | awk '{print $1}'
  )"

  if [[ -z "${cert_public_hash}" || "${cert_public_hash}" != "${key_public_hash}" ]]; then
    echo "TLS certificate and private key do not match." >&2
    exit 1
  fi
}

write_service_restart_helper() {
  if [[ "${NODE_ROLE}" != "management" && "${NODE_ROLE}" != "standalone_lab" ]]; then
    return
  fi

  local systemctl_path
  local systemd_run_path
  local temp_helper
  local temp_sudoers
  systemctl_path="$(command -v systemctl)"
  systemd_run_path="$(command -v systemd-run || true)"
  temp_helper="$(mktemp)"
  temp_sudoers="$(mktemp)"

  cat > "${temp_helper}" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

SYSTEMCTL_PATH="${systemctl_path}"
SYSTEMD_RUN_PATH="${systemd_run_path}"

if [[ -n "\${SYSTEMD_RUN_PATH}" && -x "\${SYSTEMD_RUN_PATH}" ]]; then
  exec "\${SYSTEMD_RUN_PATH}" \
    --unit axiom-restart \
    --on-active=1 \
    --description "Restart Axiom service from Management UI" \
    "\${SYSTEMCTL_PATH}" restart axiom.service
fi

exec "\${SYSTEMCTL_PATH}" restart axiom.service
EOF

  cat > "${temp_sudoers}" <<EOF
${SERVICE_USER} ALL=(root) NOPASSWD: ${RESTART_HELPER_PATH}
EOF

  ${SUDO} visudo -cf "${temp_sudoers}" >/dev/null
  ${SUDO} install -d -m 0755 "$(dirname "${RESTART_HELPER_PATH}")"
  ${SUDO} install -m 0750 -o root -g "${SERVICE_GROUP}" "${temp_helper}" "${RESTART_HELPER_PATH}"
  ${SUDO} install -m 0440 -o root -g root "${temp_sudoers}" "${SUDOERS_PATH}"
  rm -f "${temp_helper}" "${temp_sudoers}"
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
    if [[ "${AXIOM_INSTALL_LICENSE_TOOL}" == "1" ]]; then
      RUSTFLAGS="${axiom_rustflags}" cargo build --release -p axiom-license --bin axiom-license-tool
    fi
  )

  ${SUDO} install -m 0755 -o root -g root "${BINARY_SOURCE}" "${BINARY_PATH}"
  ${SUDO} setcap 'cap_net_bind_service,cap_net_raw+ep' "${BINARY_PATH}"
  if [[ "${AXIOM_INSTALL_LICENSE_TOOL}" == "1" ]]; then
    ${SUDO} install -m 0755 -o root -g root "${LICENSE_TOOL_SOURCE}" "${LICENSE_TOOL_PATH}"
  fi
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
  local no_new_privileges_line
  temp_service="$(mktemp)"
  no_new_privileges_line="NoNewPrivileges=true"

  if [[ "${NODE_ROLE}" == "management" || "${NODE_ROLE}" == "standalone_lab" ]]; then
    no_new_privileges_line=""
  fi

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
${no_new_privileges_line}
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
  echo "Role: ${NODE_ROLE}"
  if [[ -n "${AXIOM_LICENSE_PUBLIC_KEY_HEX}" ]]; then
    echo "License verification key: configured from AXIOM_LICENSE_PUBLIC_KEY_HEX"
  else
    echo "License verification key: built-in default"
  fi
  if [[ "${AXIOM_INSTALL_LICENSE_TOOL}" == "1" ]]; then
    echo "License issuer tool: ${LICENSE_TOOL_PATH}"
  fi
  if [[ "${NODE_ROLE}" == "management" || "${NODE_ROLE}" == "standalone_lab" ]]; then
    if [[ "${MANAGEMENT_TLS_ENABLED}" == "true" ]]; then
      echo "Management UI: https://${MANAGEMENT_BIND_IP}:${MANAGEMENT_PORT}/"
      echo "TLS certificate: ${MANAGEMENT_TLS_CERT_PATH}"
    else
      echo "Management UI: http://${MANAGEMENT_BIND_IP}:${MANAGEMENT_PORT}/"
      echo "HTTPS can be enabled later in Settings using: ${MANAGEMENT_TLS_CERT_PATH}"
    fi
    echo "Enrollment token is available in the Management UI under Settings."
    if [[ "${DIRECTORY_ENABLED}" == "true" ]]; then
      echo "Directory login: ${DIRECTORY_URL}"
    fi
  else
    echo "Management server: ${NODE_MANAGEMENT_URL}"
    echo "Node ID: ${NODE_ID}"
    if [[ "${NODE_CLUSTER_ENABLED:-false}" == "true" ]]; then
      echo "Cluster: ${NODE_CLUSTER_NAME} (service template imported)"
    else
      echo "Cluster: standalone managed node"
    fi
    if [[ "${NODE_ENROLLMENT_VALIDATED:-false}" == "true" ]]; then
      echo "Enrollment validation: passed"
    else
      echo "Enrollment validation: not verified"
    fi
    if [[ "${NODE_CONTROL_ENABLED}" == "true" ]]; then
      echo "Node control API: http://${NODE_CONTROL_BIND_IP}:${NODE_CONTROL_PORT}/ (encrypted policy payloads)"
    fi
  fi
  if [[ "${DNS_ENABLED}" == "true" ]]; then
    echo "DNS Gateway: ${DNS_BIND_IP}:${DNS_UDP_PORT}/udp and ${DNS_BIND_IP}:${DNS_TCP_PORT}/tcp -> ${DNS_UPSTREAMS[*]}"
  fi
  echo
  ${SUDO} systemctl --no-pager --lines=12 status axiom.service || true
}

print_repair_summary() {
  echo
  echo "Axiom repair completed."
  echo "Config preserved: ${CONFIG_PATH}"
  echo "Binary: ${BINARY_PATH}"
  echo "Service: axiom.service"
  echo "Role: ${NODE_ROLE}"
  echo
  echo "Useful next checks:"
  echo "  sudo systemctl status axiom --no-pager"
  echo "  sudo journalctl -u axiom -n 120 -l --no-pager"
  echo
  ${SUDO} systemctl --no-pager --lines=12 status axiom.service || true
}

repair_existing_installation() {
  if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo "Cannot repair Axiom because ${CONFIG_PATH} does not exist." >&2
    echo "Run ./install.sh for a new installation." >&2
    exit 1
  fi

  NODE_ROLE="$(read_config_role)"
  if [[ -z "${NODE_ROLE}" ]]; then
    echo "Cannot determine node.role from ${CONFIG_PATH}." >&2
    exit 1
  fi

  echo
  echo "Repairing existing Axiom installation for role: ${NODE_ROLE}"
  backup_existing_config
  ensure_service_user
  build_and_install_binary
  if config_has_proxy_listeners; then
    configure_reverse_proxy_network_mode
  fi
  write_service_restart_helper
  write_systemd_service
  enable_and_start_service
  print_repair_summary
}

uninstall_axiom() {
  echo "Removing Axiom service and binaries."

  if command -v systemctl >/dev/null 2>&1; then
    ${SUDO} systemctl stop axiom.service >/dev/null 2>&1 || true
    ${SUDO} systemctl disable axiom.service >/dev/null 2>&1 || true
  fi

  ${SUDO} setcap -r "${BINARY_PATH}" >/dev/null 2>&1 || true
  ${SUDO} rm -f \
    "${SERVICE_PATH}" \
    "${BINARY_PATH}" \
    "${LICENSE_TOOL_PATH}" \
    "${RESTART_HELPER_PATH}" \
    "${SUDOERS_PATH}" \
    /etc/sysctl.d/99-axiom-reverse-proxy.conf

  if command -v systemctl >/dev/null 2>&1; then
    ${SUDO} systemctl daemon-reload || true
  fi

  if [[ "${PURGE_DATA_ON_UNINSTALL}" == "true" ]]; then
    echo "Purging Axiom configuration, state, and logs."
    ${SUDO} rm -rf "${CONFIG_DIR}" /var/lib/axiom /var/log/axiom
  else
    echo "Configuration and data were kept for recovery:"
    echo "  ${CONFIG_DIR}"
    echo "  /var/lib/axiom"
    echo "  /var/log/axiom"
    echo "Run ./install.sh --uninstall --purge to remove them as well."
  fi

  echo "Axiom uninstall completed."
}

main() {
  parse_args "$@"
  ensure_debian_family
  validate_release_options
  require_sudo
  if [[ "${INSTALL_MODE}" == "uninstall" ]]; then
    uninstall_axiom
    return
  fi

  ensure_project_root
  install_missing_dependencies
  ensure_rust_toolchain
  if [[ "${INSTALL_MODE}" == "repair" ]]; then
    repair_existing_installation
    return
  fi

  load_interfaces
  collect_configuration
  ensure_service_user
  prepare_tls_certificate
  write_service_restart_helper
  backup_existing_config
  write_config
  if [[ -n "${CLUSTER_JOIN_RESPONSE_PATH:-}" ]]; then
    rm -f "${CLUSTER_JOIN_RESPONSE_PATH}"
    CLUSTER_JOIN_RESPONSE_PATH=""
  fi
  build_and_install_binary
  if ((${#PROXY_INTERFACES[@]} > 0)); then
    configure_reverse_proxy_network_mode
  fi
  write_systemd_service
  enable_and_start_service
  print_summary
}

main "$@"
