#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "${PROJECT_ROOT}/scripts/build-installer.sh" "${1:-${PROJECT_ROOT}/axiom-lab-installer.sh}"
