#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_PATH="${1:-${PROJECT_ROOT}/axiom-installer.sh}"
ARCHIVE_MARKER="__AXIOM_SOURCE_ARCHIVE_BELOW__"

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Required command '${command_name}' is not available." >&2
    exit 1
  fi
}

for command_name in tar base64 mktemp chmod; do
  require_command "${command_name}"
done

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

ARCHIVE_PATH="${TEMP_DIR}/axiom-source.tar.gz"

(
  cd "${PROJECT_ROOT}"
  tar \
    --exclude='.git' \
    --exclude='target' \
    --exclude='axiom-installer.sh' \
    --exclude='axiom-lab-installer.sh' \
    --exclude='dist' \
    --exclude='.DS_Store' \
    -czf "${ARCHIVE_PATH}" \
    .
)

cat > "${OUTPUT_PATH}" <<'INSTALLER_HEADER'
#!/usr/bin/env bash
set -Eeuo pipefail

ARCHIVE_MARKER="__AXIOM_SOURCE_ARCHIVE_BELOW__"

fail() {
  echo "$1" >&2
  exit 1
}

for command_name in awk base64 tail tar mktemp chmod; do
  command -v "${command_name}" >/dev/null 2>&1 || fail "Required command '${command_name}' is not available."
done

PAYLOAD_LINE="$(awk "/^${ARCHIVE_MARKER}$/ { print NR + 1; exit 0 }" "$0")"
if [[ -z "${PAYLOAD_LINE}" ]]; then
  fail "Embedded Axiom source archive marker was not found."
fi

WORK_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

ARCHIVE_PATH="${WORK_DIR}/axiom-source.tar.gz"
SOURCE_DIR="${WORK_DIR}/source"
mkdir -p "${SOURCE_DIR}"

tail -n +"${PAYLOAD_LINE}" "$0" | base64 -d > "${ARCHIVE_PATH}"
tar -xzf "${ARCHIVE_PATH}" -C "${SOURCE_DIR}"
chmod +x "${SOURCE_DIR}/install.sh"

echo "Axiom self-contained installer extracted to ${SOURCE_DIR}"
cd "${SOURCE_DIR}"
exec ./install.sh "$@"

__AXIOM_SOURCE_ARCHIVE_BELOW__
INSTALLER_HEADER

base64 < "${ARCHIVE_PATH}" >> "${OUTPUT_PATH}"
printf '\n' >> "${OUTPUT_PATH}"
chmod +x "${OUTPUT_PATH}"

echo "Wrote self-contained installer: ${OUTPUT_PATH}"
