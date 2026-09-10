#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  cat <<'EOF_USAGE'
Usage: ./scripts/ci.sh <command>

Commands:
  android   Build Android native libraries, bindings, and debug APK
  rust      Run Rust agent checks
  server    Run server tests
  docs      Build documentation with strict checks
  all       Run server, Rust, Android, and docs checks
EOF_USAGE
}

command="${1:-}"

case "${command}" in
  android)
    "${ROOT}/scripts/ci/android-build.sh"
    ;;
  rust)
    "${ROOT}/scripts/ci/rust-check.sh"
    ;;
  server)
    "${ROOT}/scripts/ci/server-tests.sh"
    ;;
  docs)
    "${ROOT}/scripts/ci/docs-build.sh"
    ;;
  all)
    "${ROOT}/scripts/ci/server-tests.sh"
    "${ROOT}/scripts/ci/rust-check.sh"
    "${ROOT}/scripts/ci/android-build.sh"
    "${ROOT}/scripts/ci/docs-build.sh"
    ;;
  *)
    usage
    exit 2
    ;;
esac
