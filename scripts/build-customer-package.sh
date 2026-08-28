#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${PROJECT_ROOT}/dist"
VERSION="${1:-$(git -C "${PROJECT_ROOT}" describe --tags --always 2>/dev/null || date +%Y%m%d)}"
INSTALLER_NAME="axiom-installer-${VERSION}.sh"

mkdir -p "${DIST_DIR}"
"${PROJECT_ROOT}/scripts/build-installer.sh" "${DIST_DIR}/${INSTALLER_NAME}"
cp "${DIST_DIR}/${INSTALLER_NAME}" "${DIST_DIR}/axiom-installer.sh"

echo
echo "Customer package ready:"
echo "  ${DIST_DIR}/${INSTALLER_NAME}"
echo "  ${DIST_DIR}/axiom-installer.sh"
echo
echo "Send axiom-installer.sh to the customer — no git access required."
echo "Install: chmod +x axiom-installer.sh && sudo ./axiom-installer.sh"
