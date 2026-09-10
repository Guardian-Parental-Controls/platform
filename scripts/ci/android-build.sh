#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ANDROID_DIR="${ROOT}/android-agent"
SERVER_VENV_PYTHON="${ROOT}/server/.venv/bin/python"

if [[ -x "${SERVER_VENV_PYTHON}" ]]; then
  PYTHON="${SERVER_VENV_PYTHON}"
else
  PYTHON="${PYTHON:-python3}"
fi

echo "Bundling agent i18n artifacts..."
"${PYTHON}" "${ROOT}/scripts/i18n/manage.py" bundle --target agent

echo "Building Android native libraries and UniFFI bindings..."
"${ROOT}/scripts/android-native-build.sh"

echo "Building Android debug APK..."
(
  cd "${ANDROID_DIR}"
  ./gradlew assembleDebug --no-daemon
)

echo "Android build completed successfully."
