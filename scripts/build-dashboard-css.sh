#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="${PROJECT_ROOT}/crates/axiom-web"
INPUT="${WEB_DIR}/assets/tailwind.input.css"
OUTPUT="${WEB_DIR}/assets/embedded-tailwind.css"
LOGO_PNG="${WEB_DIR}/assets/trustity-axiom-logo.png"
LOGO_B64="${WEB_DIR}/assets/trustity-axiom-logo.base64"

if [[ -s "${OUTPUT}" && -s "${LOGO_B64}" ]]; then
  echo "Embedded UI assets already present; skipping Tailwind rebuild."
  exit 0
fi

if ! command -v npx >/dev/null 2>&1; then
  echo "npx is required to build embedded Tailwind CSS, but the UI assets are missing." >&2
  exit 1
fi

(
  cd "${WEB_DIR}"
  npx --yes tailwindcss@3.4.17 -i "${INPUT}" -o "${OUTPUT}" --minify
)

echo "Wrote embedded Tailwind CSS: ${OUTPUT}"

if [[ -f "${LOGO_PNG}" ]]; then
  base64 < "${LOGO_PNG}" | tr -d '\n' > "${LOGO_B64}"
  echo "Wrote embedded logo base64: ${LOGO_B64}"
fi
