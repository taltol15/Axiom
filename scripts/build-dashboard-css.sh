#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="${PROJECT_ROOT}/crates/axiom-web"
INPUT="${WEB_DIR}/assets/tailwind.input.css"
OUTPUT="${WEB_DIR}/assets/embedded-tailwind.css"

if ! command -v npx >/dev/null 2>&1; then
  echo "npx is required to build embedded Tailwind CSS." >&2
  exit 1
fi

(
  cd "${WEB_DIR}"
  npx --yes tailwindcss@3.4.17 -i "${INPUT}" -o "${OUTPUT}" --minify
)

echo "Wrote embedded Tailwind CSS: ${OUTPUT}"
