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
AGENT_DIR="${REPO_ROOT}/agent"
ANDROID_DIR="${REPO_ROOT}/android-agent"
VENV_DIR="${SERVER_DIR}/.venv"
ENV_FILE="${REPO_ROOT}/.env"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-${REPO_ROOT}/.dev/android-sdk}}"

SKIP_SYSTEM=0
SKIP_SERVER=0
SKIP_LINUX_AGENT=0
SKIP_ANDROID=0
SKIP_BUILD=0
WITH_DOCKER=0
RUN_TESTS=0

usage() {
    cat <<'EOF'
Set up a local development environment for the TimeKpr server, Rust Linux agent,
and Android agent.

Usage:
  setup-dev.sh [options]

Options:
  --skip-system       Skip OS package installation (Python, JDK, build tools, etc.)
  --skip-server       Skip Python virtualenv and server dependencies
  --skip-linux-agent  Skip Rust toolchain and Linux agent build
  --skip-android      Skip Android SDK, JDK, and Android agent build
  --skip-build        Install toolchains and dependencies only; do not compile
  --with-docker       Also install/verify Docker and Docker Compose
  --run-tests         Run the server pytest suite after setup
  --help              Show this help message

What this script configures:
  - server/.venv with pip requirements from server/requirements-dev.txt
  - .env with dev defaults and a generated AGENT_TOKEN
  - agent/config.json for local Rust agent pairing (from config.json.example)
  - .dev/android-sdk with platform-tools, Android platform, build-tools, and NDK
  - android-agent/local.properties pointing at the local SDK
  - android-agent/app/google-services.json from the example when missing

After setup, typical workflow:
  1. Terminal 1:  source .env && cd server && ./.venv/bin/python app.py
  2. Terminal 2:  source .env && cd server && ./.venv/bin/python task_worker.py
  3. Linux agent: cd agent && ../server/.venv/bin/python -c "import json; ..."  # or run target/debug/timekpr-agent
  4. Android:     adb install -r android-agent/app/build/outputs/apk/debug/app-debug.apk

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

current, required = sys.argv[1], sys.argv[2]
raise SystemExit(0 if parse(current) >= parse(required) else 1)
PY
}

detect_package_manager() {
    if has_cmd apt-get; then
        printf 'apt-get'
    elif has_cmd pacman; then
        printf 'pacman'
    elif has_cmd dnf; then
        printf 'dnf'
    elif has_cmd zypper; then
        printf 'zypper'
    else
        return 1
    fi
}

run_as_root() {
    if [[ ${EUID} -eq 0 ]]; then
        "$@"
    elif has_cmd sudo; then
        sudo "$@"
    else
        die "Root privileges required for system packages. Re-run with sudo or use --skip-system."
    fi
}

install_system_packages() {
    local package_manager
    package_manager="$(detect_package_manager)" || {
        warn "Could not detect apt-get, pacman, dnf, or zypper; skipping system packages"
        return 0
    }

    log "Installing system packages via ${package_manager}"
    case "$package_manager" in
        apt-get)
            run_as_root env DEBIAN_FRONTEND=noninteractive apt-get update
            run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
                python3 python3-venv python3-pip python3-dev \
                build-essential pkg-config libdbus-1-dev libssl-dev \
                openjdk-17-jdk curl ca-certificates unzip wget git
            ;;
        pacman)
            run_as_root pacman -Sy --noconfirm --needed \
                python python-pip base-devel pkgconf dbus openssl \
                jdk17-openjdk curl unzip wget git
            ;;
        dnf)
            run_as_root dnf install -y \
                python3 python3-pip python3-devel \
                gcc gcc-c++ make pkgconfig dbus-devel openssl-devel \
                java-17-openjdk-devel curl unzip wget git
            ;;
        zypper)
            run_as_root zypper --non-interactive install --no-confirm \
                python3 python3-pip python3-devel \
                patterns-devel-C-C++ pkg-config libdbus-1-3 libopenssl-devel \
                java-17-openjdk-devel curl unzip wget git
            ;;
        *)
            die "Unsupported package manager: ${package_manager}"
            ;;
    esac
}

install_docker() {
    if has_cmd docker && docker compose version >/dev/null 2>&1; then
        log "Docker and Docker Compose are already available"
        return 0
    fi

    local package_manager
    package_manager="$(detect_package_manager)" || die "Cannot install Docker without a supported package manager"

    log "Installing Docker via ${package_manager}"
    case "$package_manager" in
        apt-get)
            run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2
            ;;
        pacman)
            run_as_root pacman -Sy --noconfirm --needed docker docker-compose
            ;;
        dnf)
            run_as_root dnf install -y docker docker-compose
            ;;
        zypper)
            run_as_root zypper --non-interactive install --no-confirm docker docker-compose
            ;;
    esac

    if [[ ${EUID} -ne 0 ]] && has_cmd sudo; then
        if ! groups "$USER" | grep -qw docker; then
            warn "Add your user to the docker group to run containers without sudo:"
            warn "  sudo usermod -aG docker $USER"
            warn "Then log out and back in before running docker compose."
        fi
    fi
}

ensure_python() {
    need_cmd python3
    local py_version
    py_version="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')"
    log "Using Python ${py_version}"
    if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)'; then
        warn "Python 3.12+ is recommended; older versions may still work for local dev"
    fi
}

setup_server_venv() {
    log "Creating Python virtualenv at ${VENV_DIR}"
    if [[ ! -d "$VENV_DIR" ]]; then
        python3 -m venv "$VENV_DIR"
    fi

    if ! "${VENV_DIR}/bin/python" -m pip --version >/dev/null 2>&1; then
        log "Bootstrapping pip in Python virtualenv"
        "${VENV_DIR}/bin/python" -m ensurepip --upgrade
    fi

    log "Installing server development dependencies"
    "${VENV_DIR}/bin/python" -m pip install --upgrade pip
    "${VENV_DIR}/bin/python" -m pip install -r "${SERVER_DIR}/requirements-dev.txt"
}

generate_env_file() {
    if [[ -f "$ENV_FILE" ]]; then
        log "Keeping existing ${ENV_FILE}"
        return 0
    fi

    local agent_token
    agent_token="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"

    log "Writing ${ENV_FILE}"
    cat >"$ENV_FILE" <<EOF
# Generated by scripts/setup-dev.sh
AGENT_TOKEN=${agent_token}
TZ=UTC
TIMEKPR_SERVER_VERSION=v0.0.0-dev
DEBUG=1
DATABASE_URL=sqlite:///timekpr.db
TIMEKPR_ENABLE_BACKGROUND_TASKS=1
TIMEKPR_AGENT_WS_URL=ws://127.0.0.1:5000/ws
EOF
    chmod 0600 "$ENV_FILE"
}

load_agent_token_from_env() {
    if [[ ! -f "$ENV_FILE" ]]; then
        die "Missing ${ENV_FILE}; run setup without --skip-server first"
    fi
    # shellcheck disable=SC1090
    set -a
    source "$ENV_FILE"
    set +a
    [[ -n "${AGENT_TOKEN:-}" ]] || die "AGENT_TOKEN is not set in ${ENV_FILE}"
}

write_linux_agent_config() {
    local config_path="${AGENT_DIR}/config.json"
    if [[ -f "$config_path" ]]; then
        log "Keeping existing ${config_path}"
        return 0
    fi

    load_agent_token_from_env

    log "Writing ${config_path} for local Rust agent development"
    python3 - "$config_path" "${AGENT_TOKEN}" <<'PY'
import json
import sys

path, token = sys.argv[1], sys.argv[2]
data = {
    "server_url": "ws://127.0.0.1:5000/ws",
    "system_id": None,
    "registration_token": None,
    "agent_token": token,
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2)
    handle.write("\n")
PY
    chmod 0600 "$config_path"
}

ensure_rust() {
    if ! has_cmd rustup; then
        log "Installing Rust via rustup"
        need_cmd curl
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    fi

    # shellcheck disable=SC1091
    if [[ -f "${HOME}/.cargo/env" ]]; then
        # shellcheck disable=SC1091
        source "${HOME}/.cargo/env"
    fi

    need_cmd cargo
    need_cmd rustc

    log "Updating Rust stable toolchain"
    rustup update stable >/dev/null
    rustup default stable >/dev/null

    local rust_version
    rust_version="$(rustc --version | awk '{print $2}')"
    if ! version_ge "$rust_version" "$MIN_RUST_VERSION"; then
        die "Rust ${MIN_RUST_VERSION}+ is required (found ${rust_version}). Run: rustup update stable"
    fi
    log "Using Rust ${rust_version}"
}

build_linux_agent() {
    log "Building Rust Linux agent (cargo build)"
    (
        cd "$AGENT_DIR"
        cargo build
    )
}

ensure_java() {
    configure_java_17
}

configure_java_17() {
    if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
        local java_major
        java_major="$("${JAVA_HOME}/bin/java" -version 2>&1 | sed -n 's/.* version "\([0-9]*\).*/\1/p' | head -n1)"
        if [[ "$java_major" == "17" ]]; then
            export PATH="${JAVA_HOME}/bin:${PATH}"
            log "Using JAVA_HOME=${JAVA_HOME}"
            "${JAVA_HOME}/bin/java" -version 2>&1 | head -n1
            return 0
        fi
        warn "JAVA_HOME is set but is not JDK 17 (found Java ${java_major}); searching for JDK 17"
    fi

    local candidate=""
    for candidate in \
        /usr/lib/jvm/java-17-openjdk \
        /usr/lib/jvm/java-17-openjdk-amd64 \
        /usr/lib/jvm/temurin-17-jdk \
        /usr/lib/jvm/jdk-17; do
        if [[ -x "${candidate}/bin/java" ]]; then
            export JAVA_HOME="$candidate"
            export PATH="${JAVA_HOME}/bin:${PATH}"
            log "Using JAVA_HOME=${JAVA_HOME}"
            java -version 2>&1 | head -n1
            return 0
        fi
    done

    for candidate in /usr/lib/jvm/java-17*; do
        if [[ -d "$candidate" && -x "${candidate}/bin/java" ]]; then
            export JAVA_HOME="$candidate"
            export PATH="${JAVA_HOME}/bin:${PATH}"
            log "Using JAVA_HOME=${JAVA_HOME}"
            java -version 2>&1 | head -n1
            return 0
        fi
    done

    if has_cmd java; then
        local java_major
        java_major="$(java -version 2>&1 | sed -n 's/.* version "\([0-9]*\).*/\1/p' | head -n1)"
        if [[ "$java_major" == "17" ]]; then
            log "Using Java 17 from PATH"
            java -version 2>&1 | head -n1
            return 0
        fi
        die "JDK 17 is required for Android builds (found Java ${java_major} on PATH). Install openjdk-17-jdk and re-run."
    fi

    die "Java 17 JDK not found. Install openjdk-17-jdk or re-run without --skip-system."
}

ensure_gradle_wrapper() {
    local wrapper_jar="${ANDROID_DIR}/gradle/wrapper/gradle-wrapper.jar"
    if [[ -f "$wrapper_jar" ]]; then
        log "Gradle wrapper already present"
        return 0
    fi

    log "Bootstrapping Gradle ${GRADLE_VERSION} wrapper (gradle-wrapper.jar was missing)"
    need_cmd curl
    need_cmd unzip

    local gradle_home="${REPO_ROOT}/.dev/gradle-${GRADLE_VERSION}"
    if [[ ! -x "${gradle_home}/bin/gradle" ]]; then
        local archive="${REPO_ROOT}/.dev/gradle-${GRADLE_VERSION}-bin.zip"
        mkdir -p "${REPO_ROOT}/.dev"
        curl -fsSL "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
            -o "$archive"
        rm -rf "$gradle_home"
        unzip -q "$archive" -d "${REPO_ROOT}/.dev"
    fi

    (
        cd "$ANDROID_DIR"
        "${gradle_home}/bin/gradle" wrapper --gradle-version "${GRADLE_VERSION}" --no-daemon
    )
    [[ -f "$wrapper_jar" ]] || die "Failed to generate ${wrapper_jar}"
}

install_android_sdk() {
    configure_java_17

    mkdir -p "${ANDROID_SDK_ROOT}/cmdline-tools"

    local cmdline_dir="${ANDROID_SDK_ROOT}/cmdline-tools/latest"
    if [[ ! -x "${cmdline_dir}/bin/sdkmanager" ]]; then
        log "Downloading Android command-line tools into ${ANDROID_SDK_ROOT}"
        need_cmd curl
        need_cmd unzip

        local archive="${REPO_ROOT}/.dev/cmdline-tools.zip"
        mkdir -p "${REPO_ROOT}/.dev"
        curl -fsSL \
            "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS_VERSION}_latest.zip" \
            -o "$archive"
        rm -rf "${REPO_ROOT}/.dev/cmdline-tools-extract"
        unzip -q "$archive" -d "${REPO_ROOT}/.dev/cmdline-tools-extract"
        rm -rf "$cmdline_dir"
        mkdir -p "${ANDROID_SDK_ROOT}/cmdline-tools"
        mv "${REPO_ROOT}/.dev/cmdline-tools-extract/cmdline-tools" "$cmdline_dir"
        rm -rf "${REPO_ROOT}/.dev/cmdline-tools-extract" "$archive"
    fi

    export ANDROID_SDK_ROOT
    export ANDROID_HOME="${ANDROID_SDK_ROOT}"
    export PATH="${cmdline_dir}/bin:${ANDROID_SDK_ROOT}/platform-tools:${PATH}"

    log "Accepting Android SDK licenses"
    set +o pipefail
    yes | sdkmanager --sdk_root="${ANDROID_SDK_ROOT}" --licenses >/dev/null || true
    set -o pipefail

    log "Installing Android SDK packages (platform-tools, android-${ANDROID_API_LEVEL}, build-tools ${ANDROID_BUILD_TOOLS_VERSION}, NDK ${ANDROID_NDK_VERSION})"
    sdkmanager --sdk_root="${ANDROID_SDK_ROOT}" \
        "platform-tools" \
        "platforms;android-${ANDROID_API_LEVEL}" \
        "build-tools;${ANDROID_BUILD_TOOLS_VERSION}" \
        "ndk;${ANDROID_NDK_VERSION}"

    for required_path in \
        "${ANDROID_SDK_ROOT}/platform-tools/adb" \
        "${ANDROID_SDK_ROOT}/platforms/android-${ANDROID_API_LEVEL}/android.jar" \
        "${ANDROID_SDK_ROOT}/build-tools/${ANDROID_BUILD_TOOLS_VERSION}/aapt" \
        "${ANDROID_SDK_ROOT}/ndk/${ANDROID_NDK_VERSION}"; do
        [[ -e "$required_path" ]] || die "Android SDK install incomplete: missing ${required_path}"
    done
    log "Android SDK packages verified"

    export ANDROID_NDK_HOME="${ANDROID_SDK_ROOT}/ndk/${ANDROID_NDK_VERSION}"
    export ANDROID_NDK_ROOT="${ANDROID_NDK_HOME}"
}

write_android_local_properties() {
    local props_file="${ANDROID_DIR}/local.properties"
    log "Writing ${props_file}"
    printf 'sdk.dir=%s\n' "${ANDROID_SDK_ROOT}" >"$props_file"
}

ensure_google_services_json() {
    local target="${ANDROID_DIR}/app/google-services.json"
    local example="${ANDROID_DIR}/app/google-services.json.example"
    if [[ -f "$target" ]]; then
        log "Keeping existing ${target}"
        return 0
    fi
    [[ -f "$example" ]] || die "Missing ${example}"
    log "Copying ${example} -> ${target} (replace with real Firebase config for FCM on devices)"
    cp "$example" "$target"
}

# File: scripts/setup-dev.sh
# Function: build_android_agent()

build_android_agent() {
    configure_java_17
    ensure_gradle_wrapper

    log "Building Android agent"
    "${REPO_ROOT}/scripts/ci/android-build.sh"
}

run_server_tests() {
    log "Running server test suite"
    (
        cd "$SERVER_DIR"
        # shellcheck disable=SC1091
        set -a
        source "$ENV_FILE"
        set +a
        export TESTING=True
        if "${VENV_DIR}/bin/python" -c 'import xdist' >/dev/null 2>&1; then
            log "Running server tests in parallel"
            "${VENV_DIR}/bin/python" -m pytest -q -n auto
        else
            log "pytest-xdist not available; running server tests sequentially"
            "${VENV_DIR}/bin/python" -m pytest -q
fi
    )
}

print_summary() {
    cat <<EOF

Development environment is ready.

Environment file:
  ${ENV_FILE}

Python virtualenv:
  ${VENV_DIR}

Android SDK:
  ${ANDROID_SDK_ROOT}

Android build:
  Re-run this setup script without --skip-build to build the Android agent.

Run the server (two terminals):
  source ${ENV_FILE}
  cd ${SERVER_DIR} && ./.venv/bin/python app.py
  cd ${SERVER_DIR} && ./.venv/bin/python task_worker.py

Optional Python debug agent (no TimeKpr D-Bus required):
  source ${ENV_FILE}
  cd ${SERVER_DIR} && ./.venv/bin/python debug_agent.py \\
    --server-url "ws://127.0.0.1:5000/ws" \\
    --agent-version "\${TIMEKPR_SERVER_VERSION}"

Run the Rust agent from ${AGENT_DIR}:
  cd ${AGENT_DIR} && cargo run

Install the Android debug APK:
  adb install -r ${ANDROID_DIR}/app/build/outputs/apk/debug/app-debug.apk

Docker alternative:
  docker compose -f ${REPO_ROOT}/docker-compose.yaml up -d --build

Admin UI: http://127.0.0.1:5000/  (admin / admin — change after first login)
Approve devices: http://127.0.0.1:5000/admin/devices
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-system)
            SKIP_SYSTEM=1
            shift
            ;;
        --skip-server)
            SKIP_SERVER=1
            shift
            ;;
        --skip-linux-agent)
            SKIP_LINUX_AGENT=1
            shift
            ;;
        --skip-android)
            SKIP_ANDROID=1
            shift
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        --with-docker)
            WITH_DOCKER=1
            shift
            ;;
        --run-tests)
            RUN_TESTS=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1 (try --help)"
            ;;
    esac
done

need_cmd bash
need_cmd python3

if [[ "$SKIP_SYSTEM" -eq 0 ]]; then
    install_system_packages
fi

if [[ "$WITH_DOCKER" -eq 1 ]]; then
    install_docker
fi

ensure_python

if [[ "$SKIP_SERVER" -eq 0 ]]; then
    setup_server_venv
fi

if [[ ! -f "$ENV_FILE" ]]; then
    generate_env_file
fi

if [[ "$SKIP_LINUX_AGENT" -eq 0 ]]; then
    write_linux_agent_config
    ensure_rust
    if [[ "$SKIP_BUILD" -eq 0 ]]; then
        build_linux_agent
    fi
fi

if [[ "$SKIP_ANDROID" -eq 0 ]]; then
    configure_java_17
    install_android_sdk
    write_android_local_properties
    ensure_google_services_json
    ensure_gradle_wrapper
    if [[ "$SKIP_BUILD" -eq 0 ]]; then
        build_android_agent
    fi
fi

if [[ "$RUN_TESTS" -eq 1 ]]; then
    [[ -d "$VENV_DIR" ]] || die "Server virtualenv missing; re-run without --skip-server"
    run_server_tests
fi

print_summary
