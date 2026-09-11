#!/usr/bin/env bash
set -euo pipefail

DEFAULT_REPO="Guardian-Parental-Controls/agent-linux"
DEFAULT_VERSIONS_URL="https://guardian-parental-controls.github.io/versions/feed.json"
VERSIONS_URL="${GUARDIAN_VERSIONS_URL:-$DEFAULT_VERSIONS_URL}"
REPO=""
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/guardian-agent"
CONFIG_PATH="${CONFIG_DIR}/config.json"
SERVICE_NAME="guardian-agent.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
OLD_CONFIG_DIR="/etc/timekpr-agent"
OLD_SERVICE_NAME="timekpr-agent.service"
OLD_SERVICE_PATH="/etc/systemd/system/${OLD_SERVICE_NAME}"
OLD_BINARY_NAME="timekpr-agent"
RELEASE_TAG=""
SERVER_URL="${GUARDIAN_SERVER_URL:-${TIMEKPR_SERVER_URL:-}}"
AGENT_TOKEN="${GUARDIAN_AGENT_TOKEN:-${TIMEKPR_AGENT_TOKEN:-}}"
REGISTRATION_TOKEN="${GUARDIAN_REGISTRATION_TOKEN:-${TIMEKPR_REGISTRATION_TOKEN:-}}"
AGENT_TOKEN_FILE=""
REGISTRATION_TOKEN_FILE=""
DOWNLOAD_ONLY=0
NO_START=0
REPLACE_AGENT_TOKEN=0
SECURITY_STACK_REBOOT_REQUIRED=0
SECURITY_STACK_KERNEL_BUG_DETECTED=0
WITH_OVERLAY=0

usage() {
    cat <<'EOF'
Install or update the Guardian agent from the Guardian versions feed
(or optionally from a GitHub release tag).

Usage:
  install-agent.sh [options]

Options:
  --server-url URL                 WebSocket URL for the server, preferably wss://.../ws
  --url URL                       Alias for --server-url
  --agent-token TOKEN             Initial bootstrap token (matches server AGENT_TOKEN)
  --agent-token-file PATH         Read the bootstrap token from a file
  --registration-token TOKEN      Optional pairing firewall token
  --registration-token-file PATH  Read the pairing firewall token from a file
  --repo OWNER/REPO               GitHub repository for --tag downloads
                                  (default: Guardian-Parental-Controls/agent-linux)
  --tag TAG                       Install a specific GitHub release tag instead of the versions feed
  --install-dir PATH              Directory for the agent binary
  --config-dir PATH               Directory for the agent config
  --replace-agent-token           Overwrite an existing config token
  --download-only                 Download and install the binary, but do not write config or service files
  --no-start                      Install and enable the service, but do not start/restart it
  --with-overlay                  Also download and install the CEF overlay helper when available
                                  in the versions feed (or matching GitHub release assets).
                                  The CEF runtime is installed to
                                  ${INSTALL_DIR}/guardian-overlay-cef/ and a launcher wrapper is
                                  written to ${INSTALL_DIR}/guardian-overlay-helper.
  --help                          Show this help message

Environment:
  GUARDIAN_VERSIONS_URL           Versions feed URL
                                  (default: https://guardian-parental-controls.github.io/versions/feed.json)
  GUARDIAN_SERVER_URL (or TIMEKPR_SERVER_URL)
  GUARDIAN_AGENT_TOKEN (or TIMEKPR_AGENT_TOKEN)
  GUARDIAN_REGISTRATION_TOKEN (or TIMEKPR_REGISTRATION_TOKEN)

Notes:
  - By default the script resolves agent-linux artifacts from the versions feed JSON.
  - Use --tag (and optionally --repo) to download a specific GitHub release instead.
  - On first install, the script prompts for missing secrets if they were not supplied.
  - On upgrades, an existing config token is preserved by default so you do not accidentally
    replace the per-device secret minted after pairing.
  - On full installs, the script attempts to install and enable AppArmor plus auditd so
    application monitoring works with minimal manual setup.
  - Feed artifact ids are typically linux-x86_64 / linux-aarch64; release assets are named:
      guardian-agent-x86_64-unknown-linux-gnu.tar.gz
      guardian-agent-aarch64-unknown-linux-gnu.tar.gz
      guardian-overlay-x86_64-unknown-linux-gnu.tar.gz  (CEF overlay, optional)
  - Requires agent version v1.0.0 or newer.
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

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

prompt() {
    local message="$1"
    local value
    read -r -p "$message" value
    printf '%s' "$value"
}

prompt_secret() {
    local message="$1"
    local value
    read -r -s -p "$message" value
    printf '\n' >&2
    printf '%s' "$value"
}

read_secret_file() {
    local path="$1"
    [[ -f "$path" ]] || die "Secret file not found: $path"
    python3 - "$path" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).read_text(encoding="utf-8").strip())
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

install_security_stack_packages() {
    local package_manager
    package_manager="$(detect_package_manager)" || die \
        "Could not detect a supported package manager for installing AppArmor/auditd/screenshots"

    log "Installing AppArmor, auditd, and screenshot dependencies via ${package_manager}"
    case "$package_manager" in
        apt-get)
            DEBIAN_FRONTEND=noninteractive apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                apparmor apparmor-utils auditd grim scrot
            ;;
        pacman)
            pacman -Sy --noconfirm --needed apparmor audit grim scrot
            ;;
        dnf)
            dnf install -y apparmor apparmor-utils audit grim scrot
            ;;
        zypper)
            zypper --non-interactive install --no-confirm \
                apparmor-parser apparmor-utils audit grim scrot
            ;;
        *)
            die "Unsupported package manager: ${package_manager}"
            ;;
    esac
}

systemd_unit_exists() {
    local unit_name="$1"
    local units
    units="$(systemctl list-unit-files "$unit_name" --no-legend 2>/dev/null || true)"
    [[ -n "$units" ]]
}

enable_service_now_if_possible() {
    local unit_name="$1"
    if ! systemd_unit_exists "$unit_name"; then
        warn "Systemd unit ${unit_name} was not found after package installation"
        return 1
    fi

    if [[ "$NO_START" -eq 1 ]]; then
        log "Enabling ${unit_name} (service start deferred by --no-start)"
        systemctl enable "$unit_name"
    else
        log "Enabling and starting ${unit_name}"
        systemctl enable --now "$unit_name"
    fi
}

apparmor_runtime_enabled() {
    [[ -r /sys/module/apparmor/parameters/enabled ]] || return 1
    [[ "$(< /sys/module/apparmor/parameters/enabled)" == "Y" ]]
}

ensure_security_stack() {
    install_security_stack_packages

    has_cmd apparmor_parser || die "AppArmor parser was not installed successfully"
    has_cmd aa-status || warn "aa-status is not available; AppArmor diagnostics will be limited"

    enable_service_now_if_possible apparmor.service || true
    enable_service_now_if_possible auditd.service || true

    if apparmor_runtime_enabled; then
        log "Verified that AppArmor is active in the running kernel"
    else
        SECURITY_STACK_REBOOT_REQUIRED=1
        warn "AppArmor is installed but not active in the running kernel."
        warn "Protections will not apply until the host boots with AppArmor enabled."
        if [[ -r /proc/cmdline ]]; then
            warn "Current kernel cmdline: $(< /proc/cmdline)"
        fi
        warn "Ensure your bootloader enables AppArmor (for example apparmor=1 and lsm includes apparmor), then reboot."
    fi

    if journalctl -k --no-pager -n 200 2>/dev/null | rg -q 'audit_log_(subj|object)_ctx'; then
        SECURITY_STACK_KERNEL_BUG_DETECTED=1
        warn "Detected kernel audit/AppArmor context logging errors in the kernel log."
        warn "This is usually a kernel bug, not an agent configuration problem."
        warn "Application monitoring may be noisy or unreliable until the kernel is updated."
    fi
}

detect_target() {
    case "$(uname -m)" in
        x86_64|amd64)
            printf 'x86_64-unknown-linux-gnu'
            ;;
        aarch64|arm64)
            printf 'aarch64-unknown-linux-gnu'
            ;;
        *)
            die "Unsupported architecture: $(uname -m)"
            ;;
    esac
}

detect_arch_id() {
    case "$(uname -m)" in
        x86_64|amd64)
            printf 'linux-x86_64'
            ;;
        aarch64|arm64)
            printf 'linux-aarch64'
            ;;
        *)
            die "Unsupported architecture: $(uname -m)"
            ;;
    esac
}

require_v1_or_newer() {
    local version_or_tag="$1"
    python3 - "$version_or_tag" <<'PY'
import sys

raw = sys.argv[1].strip()
if not raw:
    print("Error: Could not resolve agent version.", file=sys.stderr)
    sys.exit(1)

tag = raw
if tag.startswith("v"):
    tag = tag[1:]

parts = []
for part in tag.split("-")[0].split("+")[0].split("."):
    try:
        parts.append(int(part))
    except ValueError:
        parts.append(0)

while len(parts) < 3:
    parts.append(0)

version = tuple(parts[:3])
if version < (1, 0, 0):
    print(
        f"Error: Resolved version {raw} is below the minimum required version v1.0.0",
        file=sys.stderr,
    )
    sys.exit(1)
PY
}

verify_sha256() {
    local archive_path="$1"
    local checksum_path="$2"

    python3 - "$archive_path" "$checksum_path" <<'PY'
import hashlib
import pathlib
import sys

archive = pathlib.Path(sys.argv[1])
checksum_file = pathlib.Path(sys.argv[2])
text = checksum_file.read_text(encoding="utf-8").strip()
if not text:
    print("Error: checksum file is empty", file=sys.stderr)
    sys.exit(1)

expected = text.split()[0].lower()
actual = hashlib.sha256(archive.read_bytes()).hexdigest().lower()
if expected != actual:
    print(
        f"Error: SHA256 mismatch for {archive.name}: expected {expected}, got {actual}",
        file=sys.stderr,
    )
    sys.exit(1)
print(f"Verified SHA256 for {archive.name}")
PY
}

download_and_verify() {
    local url="$1"
    local dest="$2"
    local checksum_url="${3:-}"

    curl -fsSL "$url" -o "$dest"

    if [[ -n "$checksum_url" ]]; then
        local checksum_path="${dest}.sha256"
        log "Downloading checksum from ${checksum_url}"
        if curl -fsSL "$checksum_url" -o "$checksum_path"; then
            log "Verifying SHA256 for $(basename "$dest")"
            verify_sha256 "$dest" "$checksum_path" || die "Checksum verification failed for ${dest}"
        else
            warn "Could not download checksum from ${checksum_url}; continuing without verification"
        fi
    fi
}

get_existing_config_value() {
    local key="$1"
    python3 - "$CONFIG_PATH" "$key" <<'PY'
import json
import os
import sys

path, key = sys.argv[1], sys.argv[2]
if not os.path.exists(path):
    raise SystemExit(0)

with open(path, encoding="utf-8") as handle:
    data = json.load(handle)

value = data.get(key)
if value is None:
    raise SystemExit(0)
print(value)
PY
}

write_config() {
    local server_url="$1"
    local agent_token="$2"
    local registration_token="$3"

    install -d -m 0700 -o root -g root "$CONFIG_DIR"

    python3 - "$CONFIG_PATH" "$server_url" "$agent_token" "$registration_token" <<'PY'
import json
import os
import sys

path, server_url, agent_token, registration_token = sys.argv[1:5]
data = {}

if os.path.exists(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)

data["server_url"] = server_url
data.setdefault("system_id", None)
data["agent_token"] = agent_token
data["registration_token"] = registration_token or None

with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2)
    handle.write("\n")
PY

    chown root:root "$CONFIG_PATH"
    chmod 0600 "$CONFIG_PATH"
}

write_service() {
    cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Guardian WebSocket Client Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
UMask=0077
ExecStart=${INSTALL_DIR}/guardian-agent
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "$SERVICE_PATH"
}

resolve_from_feed() {
    local feed_json="$1"
    local arch_id="$2"
    local out_file="$3"

    python3 - "$feed_json" "$arch_id" "$out_file" <<'PY'
import json
import sys
from pathlib import Path

feed_path, arch_id, out_path = sys.argv[1:4]
with open(feed_path, encoding="utf-8") as handle:
    data = json.load(handle)

component = (data.get("components") or {}).get("agent-linux")
if not component:
    print("Error: versions feed is missing components.agent-linux", file=sys.stderr)
    sys.exit(1)

version = str(component.get("version") or "").strip()
artifacts = component.get("artifacts") or []

agent = None
for artifact in artifacts:
    if artifact.get("id") == arch_id:
        agent = artifact
        break

if agent is None or not agent.get("url"):
    print(f"Error: versions feed has no agent-linux artifact for {arch_id}", file=sys.stderr)
    sys.exit(1)

overlay = None
overlay_id = arch_id.replace("linux-", "linux-overlay-", 1)
for artifact in artifacts:
    artifact_id = str(artifact.get("id") or "")
    url = str(artifact.get("url") or "")
    if artifact_id == overlay_id or "guardian-overlay" in url:
        overlay = artifact
        break

payload = {
    "version": version,
    "download_url": agent.get("url", ""),
    "checksum_url": agent.get("checksum_url") or "",
    "overlay_url": (overlay or {}).get("url") or "",
    "overlay_checksum_url": (overlay or {}).get("checksum_url") or "",
}
Path(out_path).write_text(json.dumps(payload), encoding="utf-8")
PY
}

if [[ ${EUID} -ne 0 ]]; then
    need_cmd sudo
    exec sudo --preserve-env=GUARDIAN_VERSIONS_URL,GUARDIAN_SERVER_URL,GUARDIAN_AGENT_TOKEN,GUARDIAN_REGISTRATION_TOKEN,TIMEKPR_SERVER_URL,TIMEKPR_AGENT_TOKEN,TIMEKPR_REGISTRATION_TOKEN,GITHUB_TOKEN bash "$0" "$@"
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-url|--url)
            [[ $# -ge 2 ]] || die "Missing value for $1"
            SERVER_URL="$2"
            shift 2
            ;;
        --agent-token)
            [[ $# -ge 2 ]] || die "Missing value for --agent-token"
            AGENT_TOKEN="$2"
            shift 2
            ;;
        --agent-token-file)
            [[ $# -ge 2 ]] || die "Missing value for --agent-token-file"
            AGENT_TOKEN_FILE="$2"
            shift 2
            ;;
        --registration-token)
            [[ $# -ge 2 ]] || die "Missing value for --registration-token"
            REGISTRATION_TOKEN="$2"
            shift 2
            ;;
        --registration-token-file)
            [[ $# -ge 2 ]] || die "Missing value for --registration-token-file"
            REGISTRATION_TOKEN_FILE="$2"
            shift 2
            ;;
        --repo)
            [[ $# -ge 2 ]] || die "Missing value for --repo"
            REPO="$2"
            shift 2
            ;;
        --tag)
            [[ $# -ge 2 ]] || die "Missing value for --tag"
            RELEASE_TAG="$2"
            shift 2
            ;;
        --install-dir)
            [[ $# -ge 2 ]] || die "Missing value for --install-dir"
            INSTALL_DIR="$2"
            shift 2
            ;;
        --config-dir)
            [[ $# -ge 2 ]] || die "Missing value for --config-dir"
            CONFIG_DIR="$2"
            CONFIG_PATH="${CONFIG_DIR}/config.json"
            shift 2
            ;;
        --replace-agent-token)
            REPLACE_AGENT_TOKEN=1
            shift
            ;;
        --download-only)
            DOWNLOAD_ONLY=1
            shift
            ;;
        --no-start)
            NO_START=1
            shift
            ;;
        --with-overlay)
            WITH_OVERLAY=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
done

need_cmd bash
need_cmd curl
need_cmd install
need_cmd python3
need_cmd tar
need_cmd uname

if [[ -n "$AGENT_TOKEN_FILE" ]]; then
    AGENT_TOKEN="$(read_secret_file "$AGENT_TOKEN_FILE")"
fi

if [[ -n "$REGISTRATION_TOKEN_FILE" ]]; then
    REGISTRATION_TOKEN="$(read_secret_file "$REGISTRATION_TOKEN_FILE")"
fi

TARGET="$(detect_target)"
ARCH_ID="$(detect_arch_id)"
ASSET_NAME="guardian-agent-${TARGET}.tar.gz"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

DOWNLOAD_URL=""
CHECKSUM_URL=""
OVERLAY_DOWNLOAD_URL=""
OVERLAY_CHECKSUM_URL=""
RELEASE_TAG_RESOLVED=""

if [[ -n "$RELEASE_TAG" ]]; then
    REPO="${REPO:-$DEFAULT_REPO}"
    require_v1_or_newer "$RELEASE_TAG" || die "Version check failed. Script requires v1.0.0 or higher."
    RELEASE_TAG_RESOLVED="$RELEASE_TAG"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/${ASSET_NAME}"
    CHECKSUM_URL="${DOWNLOAD_URL}.sha256"
    OVERLAY_ASSET_NAME="guardian-overlay-${TARGET}.tar.gz"
    OVERLAY_DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/${OVERLAY_ASSET_NAME}"
    OVERLAY_CHECKSUM_URL="${OVERLAY_DOWNLOAD_URL}.sha256"
    log "Using GitHub release override ${REPO}@${RELEASE_TAG}"
else
    [[ -z "$REPO" ]] || warn "--repo is ignored unless --tag is also provided"
    FEED_JSON="${TMP_DIR}/feed.json"
    RESOLVED_JSON="${TMP_DIR}/resolved.json"

    log "Resolving agent-linux artifacts from ${VERSIONS_URL}"
    curl -fsSL "$VERSIONS_URL" -o "$FEED_JSON" \
        || die "Could not fetch versions feed from ${VERSIONS_URL}"

    resolve_from_feed "$FEED_JSON" "$ARCH_ID" "$RESOLVED_JSON" \
        || die "Could not resolve agent-linux artifacts from the versions feed"

    eval "$(python3 - "$RESOLVED_JSON" <<'PY'
import json
import shlex
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)

def emit(name, value):
    print(f"{name}={shlex.quote(value)}")

emit("RELEASE_TAG_RESOLVED", data.get("version") or "")
emit("DOWNLOAD_URL", data.get("download_url") or "")
emit("CHECKSUM_URL", data.get("checksum_url") or "")
emit("OVERLAY_DOWNLOAD_URL", data.get("overlay_url") or "")
emit("OVERLAY_CHECKSUM_URL", data.get("overlay_checksum_url") or "")
PY
)"

    [[ -n "$RELEASE_TAG_RESOLVED" ]] || die "Versions feed did not include an agent-linux version"
    [[ -n "$DOWNLOAD_URL" ]] || die "Versions feed did not include a download URL for ${ARCH_ID}"
    require_v1_or_newer "$RELEASE_TAG_RESOLVED" || die "Version check failed. Script requires v1.0.0 or higher."
    log "Resolved agent-linux version ${RELEASE_TAG_RESOLVED} (${ARCH_ID})"
fi

ARCHIVE_PATH="${TMP_DIR}/${ASSET_NAME}"
EXTRACT_DIR="${TMP_DIR}/extract"
mkdir -p "$EXTRACT_DIR"

log "Downloading ${ASSET_NAME} (version ${RELEASE_TAG_RESOLVED})"
download_and_verify "$DOWNLOAD_URL" "$ARCHIVE_PATH" "$CHECKSUM_URL"

log "Extracting release archive"
tar -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"
[[ -f "${EXTRACT_DIR}/guardian-agent" ]] || die "Archive did not contain the guardian-agent binary"

install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "${EXTRACT_DIR}/guardian-agent" "${INSTALL_DIR}/guardian-agent"
log "Installed binary to ${INSTALL_DIR}/guardian-agent"

# ---------------------------------------------------------------------------
# Optional CEF overlay helper (requires --with-overlay)
# ---------------------------------------------------------------------------
if [[ "$WITH_OVERLAY" -eq 1 ]]; then
    OVERLAY_ASSET_NAME="guardian-overlay-${TARGET}.tar.gz"

    if [[ -z "$OVERLAY_DOWNLOAD_URL" ]]; then
        warn "--with-overlay requested but no overlay artifact was found for this install source."
        warn "Overlay helper will not be installed. Build the CEF overlay on x86_64 first."
    else
        OVERLAY_ARCHIVE="${TMP_DIR}/${OVERLAY_ASSET_NAME}"
        OVERLAY_EXTRACT_DIR="${TMP_DIR}/overlay-extract"
        mkdir -p "$OVERLAY_EXTRACT_DIR"

        log "Downloading ${OVERLAY_ASSET_NAME} (version ${RELEASE_TAG_RESOLVED})"
        if ! download_and_verify "$OVERLAY_DOWNLOAD_URL" "$OVERLAY_ARCHIVE" "${OVERLAY_CHECKSUM_URL:-}"; then
            warn "--with-overlay requested but overlay download failed for ${OVERLAY_DOWNLOAD_URL}."
            warn "Overlay helper will not be installed. Build the CEF overlay on x86_64 first."
        else
            log "Extracting overlay archive"
            tar -xzf "$OVERLAY_ARCHIVE" -C "$OVERLAY_EXTRACT_DIR"

            [[ -f "${OVERLAY_EXTRACT_DIR}/guardian-overlay-helper" ]] || \
                die "Overlay archive did not contain the guardian-overlay-helper binary"

            # Install CEF runtime libraries into a dedicated subdirectory so they
            # don't pollute the system library path.
            CEF_RUNTIME_DIR="${INSTALL_DIR}/guardian-overlay-cef"
            install -d -m 0755 "$CEF_RUNTIME_DIR"

            # Copy every file from the archive except the main binary itself.
            find "$OVERLAY_EXTRACT_DIR" -maxdepth 1 ! -name 'guardian-overlay-helper' \
                -not -type d -exec install -m 0644 {} "$CEF_RUNTIME_DIR/" \;
            # Preserve subdirectories (locales/, Resources/, swiftshader/) with their contents.
            for d in "${OVERLAY_EXTRACT_DIR}"/*/; do
                [[ -d "$d" ]] || continue
                dir_name="$(basename "$d")"
                install -d -m 0755 "${CEF_RUNTIME_DIR}/${dir_name}"
                cp -r "${d}/." "${CEF_RUNTIME_DIR}/${dir_name}/"
            done

            # Write a thin launcher wrapper that sets LD_LIBRARY_PATH to the CEF
            # runtime directory before exec-ing the real binary.  guardian-agent
            # spawns this wrapper by name (guardian-overlay-helper) so find_helper()
            # picks it up from the same directory.
            install -d -m 0755 "$INSTALL_DIR"
            cat > "${INSTALL_DIR}/guardian-overlay-helper" <<WRAPPER
#!/usr/bin/env bash
export LD_LIBRARY_PATH="${CEF_RUNTIME_DIR}\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
exec "${CEF_RUNTIME_DIR}/guardian-overlay-helper-bin" "\$@"
WRAPPER
            chmod 0755 "${INSTALL_DIR}/guardian-overlay-helper"

            # Install the real binary under a private name inside the CEF dir.
            install -m 0755 "${OVERLAY_EXTRACT_DIR}/guardian-overlay-helper" \
                "${CEF_RUNTIME_DIR}/guardian-overlay-helper-bin"

            log "Installed overlay helper to ${CEF_RUNTIME_DIR}/guardian-overlay-helper-bin"
            log "Installed overlay launcher wrapper to ${INSTALL_DIR}/guardian-overlay-helper"
        fi
    fi
fi

if [[ "$DOWNLOAD_ONLY" -eq 1 ]]; then
    log "Download-only mode requested; skipping config and systemd service setup"
    exit 0
fi

need_cmd systemctl

ensure_security_stack

# Migrate existing timekpr-agent installation to guardian-agent if present
if systemd_unit_exists "${OLD_SERVICE_NAME}"; then
    log "Existing ${OLD_SERVICE_NAME} detected. Stopping and disabling it..."
    systemctl stop "${OLD_SERVICE_NAME}" || true
    systemctl disable "${OLD_SERVICE_NAME}" || true
    if [[ -f "${OLD_SERVICE_PATH}" ]]; then
        log "Removing old service file ${OLD_SERVICE_PATH}"
        rm -f "${OLD_SERVICE_PATH}"
    fi
    systemctl daemon-reload
fi

if [[ -f "${INSTALL_DIR}/${OLD_BINARY_NAME}" ]]; then
    log "Removing old ${OLD_BINARY_NAME} binary from ${INSTALL_DIR}/${OLD_BINARY_NAME}"
    rm -f "${INSTALL_DIR}/${OLD_BINARY_NAME}"
fi

# Clean up old AppArmor profiles if present
if [[ -d "/etc/apparmor.d" ]]; then
    log "Checking for old timekpr AppArmor profiles..."
    for profile in /etc/apparmor.d/timekpr-*; do
        if [[ -f "$profile" ]]; then
            log "Removing and unloading AppArmor profile: $profile"
            if has_cmd apparmor_parser; then
                apparmor_parser -R "$profile" || true
            fi
            rm -f "$profile"
        fi
    done
fi

if [[ -d "${OLD_CONFIG_DIR}" ]]; then
    if [[ ! -d "${CONFIG_DIR}" ]]; then
        log "Migrating config directory ${OLD_CONFIG_DIR} to ${CONFIG_DIR}"
        mv "${OLD_CONFIG_DIR}" "${CONFIG_DIR}"
    else
        if [[ -f "${OLD_CONFIG_DIR}/config.json" && ! -f "${CONFIG_PATH}" ]]; then
            log "Migrating config.json from ${OLD_CONFIG_DIR} to ${CONFIG_DIR}"
            mv "${OLD_CONFIG_DIR}/config.json" "${CONFIG_PATH}"
        fi
        rmdir "${OLD_CONFIG_DIR}" 2>/dev/null || true
    fi
fi

EXISTING_SERVER_URL="$(get_existing_config_value "server_url" || true)"
EXISTING_AGENT_TOKEN="$(get_existing_config_value "agent_token" || true)"
EXISTING_REGISTRATION_TOKEN="$(get_existing_config_value "registration_token" || true)"

if [[ -z "$SERVER_URL" && -n "$EXISTING_SERVER_URL" ]]; then
    SERVER_URL="$EXISTING_SERVER_URL"
fi

if [[ -z "$SERVER_URL" ]]; then
    SERVER_URL="$(prompt 'Server WebSocket URL (prefer wss://host/ws): ')"
fi

if [[ -z "$EXISTING_AGENT_TOKEN" ]]; then
    if [[ -z "$AGENT_TOKEN" ]]; then
        AGENT_TOKEN="$(prompt_secret 'Initial agent token (matches server AGENT_TOKEN): ')"
    fi
elif [[ -n "$AGENT_TOKEN" && "$AGENT_TOKEN" != "$EXISTING_AGENT_TOKEN" && "$REPLACE_AGENT_TOKEN" -ne 1 ]]; then
    warn "Preserving the existing agent token in ${CONFIG_PATH}. Use --replace-agent-token to overwrite it."
    AGENT_TOKEN="$EXISTING_AGENT_TOKEN"
elif [[ -z "$AGENT_TOKEN" ]]; then
    AGENT_TOKEN="$EXISTING_AGENT_TOKEN"
fi

if [[ -z "$AGENT_TOKEN" ]]; then
    die "Agent token is required on first install"
fi

if [[ -z "$REGISTRATION_TOKEN" && -n "$EXISTING_REGISTRATION_TOKEN" ]]; then
    REGISTRATION_TOKEN="$EXISTING_REGISTRATION_TOKEN"
fi

log "Writing ${CONFIG_PATH} with root-only permissions"
write_config "$SERVER_URL" "$AGENT_TOKEN" "$REGISTRATION_TOKEN"

log "Writing systemd unit to ${SERVICE_PATH}"
write_service

log "Reloading systemd and enabling ${SERVICE_NAME}"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

if [[ "$NO_START" -eq 1 ]]; then
    log "Skipping service start because --no-start was requested"
else
    log "Restarting ${SERVICE_NAME}"
    systemctl restart "$SERVICE_NAME"
fi

cat <<EOF

Installed Guardian agent release ${RELEASE_TAG_RESOLVED}.

Next steps:
  - Review ${CONFIG_PATH} permissions: ls -l ${CONFIG_PATH}
  - Check service status: systemctl status ${SERVICE_NAME}
  - Read recent logs: journalctl -u ${SERVICE_NAME} -n 50 --no-pager

If this is the first time the agent has run, the logs will show the generated system ID
that must be approved in the Web UI admin panel.
EOF

if [[ "$SECURITY_STACK_REBOOT_REQUIRED" -eq 1 ]]; then
    cat <<'EOF'

Important:
  - AppArmor was installed, but the running kernel does not currently have it active.
  - Reboot after enabling AppArmor in the bootloader/kernel command line, then re-run:
      aa-status
      systemctl status apparmor auditd guardian-agent
EOF
fi

if [[ "$SECURITY_STACK_KERNEL_BUG_DETECTED" -eq 1 ]]; then
    cat <<'EOF'

Important:
  - The running kernel is logging audit/AppArmor context errors such as:
      audit: error in audit_log_subj_ctx
  - This is typically a kernel bug in audit/LSM context handling, not a bad Guardian install.
  - Recommended action:
      1. Update the host to a newer kernel build.
      2. Reboot.
      3. Re-check: journalctl -k | rg 'audit_log_(subj|object)_ctx'
EOF
fi
