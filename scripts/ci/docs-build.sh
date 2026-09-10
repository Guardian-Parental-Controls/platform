#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOCS_VENV_MKDOCS="${ROOT}/.venv-docs/bin/mkdocs"

if [[ -x "${DOCS_VENV_MKDOCS}" ]]; then
  MKDOCS="${DOCS_VENV_MKDOCS}"
else
  MKDOCS="${MKDOCS:-mkdocs}"
fi

echo "Building documentation..."

cd "${ROOT}"
export DISABLE_MKDOCS_2_WARNING=true
"${MKDOCS}" build --strict

echo "Documentation build completed successfully."
