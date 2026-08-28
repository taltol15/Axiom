#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${PROJECT_ROOT}/dist"
VERSION="${1:-1.1.5}"
INSTALLER_NAME="axiom-installer-${VERSION}.sh"
PREBUILT_DIR="${PROJECT_ROOT}/packaging/prebuilt"
LINUX_TARGET="${AXIOM_LINUX_TARGET:-x86_64-unknown-linux-gnu}"

"${PROJECT_ROOT}/scripts/build-dashboard-css.sh"

PREBUILT_PATH=""
LINUX_TARGET="${AXIOM_LINUX_TARGET:-x86_64-unknown-linux-gnu}"
chmod +x "${PROJECT_ROOT}/scripts/build-linux-release.sh"
if PREBUILT_PATH="$("${PROJECT_ROOT}/scripts/build-linux-release.sh")"; then
  mkdir -p "${PREBUILT_DIR}"
  cp "${PREBUILT_PATH}" "${PREBUILT_DIR}/axiom-daemon"
  printf '%s\n' "${VERSION}" > "${PREBUILT_DIR}/VERSION"
  printf '%s\n' "${LINUX_TARGET}" > "${PREBUILT_DIR}/TARGET"
  if command -v file >/dev/null 2>&1; then
    echo "Pre-built binary: $(file -b "${PREBUILT_DIR}/axiom-daemon")"
  fi
  if [[ "$(uname -s)" == "Linux" ]]; then
    "${PREBUILT_DIR}/axiom-daemon" --version
  else
    echo "Skipping local --version check; prebuilt binary targets ${LINUX_TARGET}."
  fi
else
  echo "WARNING: Linux pre-built binary was not produced; customer installs will compile from source on the target server."
  rm -rf "${PREBUILT_DIR}"
fi

mkdir -p "${DIST_DIR}"
"${PROJECT_ROOT}/scripts/build-installer.sh" "${DIST_DIR}/${INSTALLER_NAME}"
cp "${DIST_DIR}/${INSTALLER_NAME}" "${DIST_DIR}/axiom-installer.sh"

(
  cd "${DIST_DIR}"
  shasum -a 256 "${INSTALLER_NAME}" > "${INSTALLER_NAME}.sha256"
)

cat > "${DIST_DIR}/RELEASE-${VERSION}.txt" <<EOF
Axiom ${VERSION} customer installer

File: ${INSTALLER_NAME}
SHA256: $(cut -d' ' -f1 "${DIST_DIR}/${INSTALLER_NAME}.sha256")

Install:
  chmod +x ${INSTALLER_NAME}
  sudo ./${INSTALLER_NAME}

Git tag: v${VERSION}
EOF

echo
echo "Customer package ready:"
echo "  ${DIST_DIR}/${INSTALLER_NAME}"
echo "  ${DIST_DIR}/${INSTALLER_NAME}.sha256"
echo "  ${DIST_DIR}/RELEASE-${VERSION}.txt"
echo
echo "Upload ${INSTALLER_NAME} to Trustity Dev → Admin → Downloads for customer access."
