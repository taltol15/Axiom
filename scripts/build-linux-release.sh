#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${AXIOM_LINUX_TARGET:-x86_64-unknown-linux-gnu}"
RUSTFLAGS="${RUSTFLAGS:--C linker=cc -C link-self-contained=no -C link-arg=-fuse-ld=bfd}"

linux_native_build() {
  (
    cd "${PROJECT_ROOT}"
    RUSTFLAGS="${RUSTFLAGS}" cargo build --release -p axiom-daemon --target "${TARGET}"
  )
}

if [[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" && "${TARGET}" == "x86_64-unknown-linux-gnu" ]]; then
  linux_native_build
  echo "${PROJECT_ROOT}/target/${TARGET}/release/axiom-daemon"
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to build a Linux customer binary from $(uname -s)/$(uname -m)." >&2
  echo "Run this script on Linux x86_64 or install Docker." >&2
  exit 1
fi

echo "Building Linux ${TARGET} release binary in Docker..."
docker run --rm \
  -e RUSTFLAGS="${RUSTFLAGS}" \
  -v "${PROJECT_ROOT}:/work" \
  -w /work \
  rust:1.88-bookworm \
  bash -lc "
    set -Eeuo pipefail
    apt-get update -qq
    apt-get install -y -qq pkg-config libssl-dev libldap2-dev build-essential >/dev/null
    rustup target add '${TARGET}'
    cargo build --release -p axiom-daemon --target '${TARGET}'
  "

echo "${PROJECT_ROOT}/target/${TARGET}/release/axiom-daemon"
