#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SERVER_DIR="${ROOT}/server"
VENV_PYTHON="${SERVER_DIR}/.venv/bin/python"

if [[ -x "${VENV_PYTHON}" ]]; then
  PYTHON="${VENV_PYTHON}"
else
  PYTHON="${PYTHON:-python3}"
fi

echo "Running server tests..."

(
  cd "${SERVER_DIR}"
  export TESTING=True

  if "${PYTHON}" -c 'import xdist' >/dev/null 2>&1; then
    "${PYTHON}" -m pytest -q -n auto
  else
    "${PYTHON}" -m pytest -q
  fi
)

echo "Server tests completed successfully."
