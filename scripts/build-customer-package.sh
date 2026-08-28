#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${PROJECT_ROOT}/dist"
VERSION="${1:-1.1.0}"
INSTALLER_NAME="axiom-installer-${VERSION}.sh"

"${PROJECT_ROOT}/scripts/build-dashboard-css.sh"

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
