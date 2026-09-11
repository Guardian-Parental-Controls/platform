#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEV_VERSIONS_FILE="${REPO_ROOT}/scripts/dev-versions.env"
[[ -f "$DEV_VERSIONS_FILE" ]] || {
    echo "ERROR: Development versions file not found: ${DEV_VERSIONS_FILE}" >&2
    exit 1
}

# shellcheck disable=SC1090
source "$DEV_VERSIONS_FILE"

SERVER_DIR="${REPO_ROOT}/server"
VENV_DIR="${SERVER_DIR}/.venv"
ENV_FILE="${REPO_ROOT}/.env"

SKIP_SYSTEM=0
SKIP_SERVER=0
SKIP_BUILD=0
WITH_DOCKER=0
RUN_TESTS=0

usage() {
    cat <<'EOF'
Set up a local development environment for the Guardian platform server.

Agent, docs, and translations live in sibling repositories. See README.md.

Usage:
  setup-dev.sh [options]

Options:
  --skip-system   Skip OS package installation (Python, build tools, etc.)
  --skip-server   Skip Python virtualenv and server dependencies
  --skip-build    Install toolchains and dependencies only
  --with-docker   Also install/verify Docker and Docker Compose
  --run-tests     Run the server pytest suite after setup
  --help          Show this help message

What this script configures:
  - server/.venv with pip requirements from server/requirements-dev.txt
  - .env with dev defaults and a generated AGENT_TOKEN

Suggested sibling checkout:

  guardian/
    platform/          (this repo)
    agent-common/
    agent-linux/
    agent-windows/
    agent-android/
    docs/
    versions/
    translations/

After setup:
  1. Terminal 1:  source .env && cd server && ./.venv/bin/python app.py
  2. Terminal 2:  source .env && cd server && ./.venv/bin/python task_worker.py

UI catalogs: checkout translations and set GUARDIAN_I18N_ROOT to its i18n/ folder
(or run Docker image builds which check out translations in CI).

Default admin login: admin / admin
Approve new devices at http://127.0.0.1:5000/admin/devices
EOF
}

log() {
    printf '==> %s\n' "$*"
}

warn() {
    printf 'Warning: %s\n' "$*" >&2
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

need_cmd() {
    has_cmd "$1" || die "Required command not found: $1"
}

version_ge() {
    local current="$1"
    local required="$2"
    python3 - "$current" "$required" <<'PY'
import sys

def parse(version):
    parts = []
    for piece in version.split(".")[:3]:
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits or "0"))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)

raise SystemExit(0 if parse(sys.argv[1]) >= parse(sys.argv[2]) else 1)
PY
}

ensure_python() {
    need_cmd python3
    local py_ver
    py_ver="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
    version_ge "$py_ver" "${PYTHON_MIN_VERSION:-3.12.0}" || \
        die "Python ${PYTHON_MIN_VERSION:-3.12}+ required (found $py_ver)"
}

install_system_packages() {
    if [[ "$SKIP_SYSTEM" -eq 1 ]]; then
        log "Skipping system package install"
        return
    fi
    if has_cmd apt-get; then
        log "Installing apt packages"
        sudo apt-get update -y
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
            python3 python3-venv python3-pip build-essential curl git
    elif has_cmd brew; then
        log "Homebrew detected; ensure Python ${PYTHON_MIN_VERSION:-3.12}+ is installed"
    else
        warn "No apt-get/brew; install Python ${PYTHON_MIN_VERSION:-3.12}+ manually"
    fi
}

setup_server_venv() {
    if [[ "$SKIP_SERVER" -eq 1 ]]; then
        log "Skipping server venv"
        return
    fi
    ensure_python
    log "Creating server virtualenv at ${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"
    python -m pip install --upgrade pip wheel
    python -m pip install -r "${SERVER_DIR}/requirements-dev.txt"
}

write_env_file() {
    if [[ -f "$ENV_FILE" ]]; then
        log ".env already exists; leaving it alone"
        return
    fi
    local token
    token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    cat >"$ENV_FILE" <<EOF
AGENT_TOKEN=${token}
DATABASE_URL=sqlite:///../instance/timekpr.db
TZ=UTC
GUARDIAN_VERSIONS_URL=https://guardian-parental-controls.github.io/versions/feed.json
EOF
    log "Wrote ${ENV_FILE}"
}

maybe_docker() {
    if [[ "$WITH_DOCKER" -ne 1 ]]; then
        return
    fi
    need_cmd docker
    docker compose version >/dev/null 2>&1 || die "Docker Compose plugin required"
    log "Docker OK"
}

maybe_tests() {
    if [[ "$RUN_TESTS" -ne 1 ]]; then
        return
    fi
    log "Running server tests"
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"
    (
        cd "${SERVER_DIR}"
        TESTING=True python -m pytest -q -n auto
    )
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-system) SKIP_SYSTEM=1 ;;
        --skip-server) SKIP_SERVER=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        --with-docker) WITH_DOCKER=1 ;;
        --run-tests) RUN_TESTS=1 ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
    shift
done

# Legacy flags kept as no-ops so old docs/scripts do not break.
# (agent toolchains live in sibling repos now)

log "Guardian platform setup"
install_system_packages
setup_server_venv
write_env_file
maybe_docker
maybe_tests
log "Done. See README.md for sibling agent repositories."
