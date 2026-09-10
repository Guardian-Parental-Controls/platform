#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SERVER_VENV_PYTHON="${ROOT}/server/.venv/bin/python"

if [[ -x "${SERVER_VENV_PYTHON}" ]]; then
  PYTHON="${SERVER_VENV_PYTHON}"
else
  PYTHON="${PYTHON:-python3}"
fi

echo "Bundling agent i18n artifacts..."
"${PYTHON}" "${ROOT}/scripts/i18n/manage.py" bundle --target agent

echo "Running Rust agent check..."
cargo check --manifest-path "${ROOT}/agent/Cargo.toml"

echo "Rust check completed successfully."
