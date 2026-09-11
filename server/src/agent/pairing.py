"""Helpers for generating Android/Linux agent pairing payloads and QR codes."""

from __future__ import annotations

import base64
import io
import json
import logging
import os
import subprocess
import time
from urllib.parse import urlparse, urlunparse

import requests
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from src.common.settings import (
    _get_android_provisioning_leave_all_system_apps_enabled,
    _get_android_provisioning_wifi_ssid,
    _get_android_provisioning_wifi_security_type,
    _get_android_provisioning_wifi_password,
)


_LOGGER = logging.getLogger(__name__)

PAIRING_PAYLOAD_TYPE = 'timekpr_pairing'

ANDROID_DPC_COMPONENT = (
    'com.guardian.agent/com.guardian.agent.admin.GuardianDeviceAdminReceiver'
)
ANDROID_EXTRA_SERVER_URL = 'com.guardian.agent.EXTRA_SERVER_URL'
ANDROID_EXTRA_REGISTRATION_TOKEN = 'com.guardian.agent.EXTRA_REGISTRATION_TOKEN'
PROVISIONING_KEY_COMPONENT = 'android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME'
PROVISIONING_KEY_SIGNATURE = 'android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM'
PROVISIONING_KEY_DOWNLOAD = 'android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION'
PROVISIONING_KEY_EXTRAS = 'android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE'
PROVISIONING_KEY_LEAVE_ALL_SYSTEM_APPS_ENABLED = 'android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED'
PROVISIONING_KEY_SKIP_ENCRYPTION = 'android.app.extra.PROVISIONING_SKIP_ENCRYPTION'
PROVISIONING_KEY_WIFI_SSID = 'android.app.extra.PROVISIONING_WIFI_SSID'
PROVISIONING_KEY_WIFI_SECURITY_TYPE = 'android.app.extra.PROVISIONING_WIFI_SECURITY_TYPE'
PROVISIONING_KEY_WIFI_PASSWORD = 'android.app.extra.PROVISIONING_WIFI_PASSWORD'
PROVISIONING_APK_PATH = '/api/pairing/provisioning/apk'


_CHECKSUM_CACHE: dict[str, tuple[str, float]] = {}
_CHECKSUM_CACHE_TTL_SECONDS = 300
_ANDROID_APK_FILENAME = 'android-agent.apk'
_MAX_ANDROID_APK_BYTES = 250 * 1024 * 1024
_EMPTY_SIGNATURE_CHECKSUM = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU'


def _normalize_ws_path(path: str | None) -> str:
    normalized = (path or '').strip() or '/ws'
    if not normalized.startswith('/'):
        normalized = f'/{normalized}'
    return normalized


def normalize_agent_websocket_url(url: str) -> str:
    """Normalize and validate a configured agent WebSocket URL."""
    candidate = url.strip()
    if not candidate:
        return ''

    parsed = urlparse(candidate)
    if parsed.scheme not in ('ws', 'wss') or not parsed.netloc:
        raise ValueError('Agent WebSocket URL must use ws:// or wss:// with a host')

    path = _normalize_ws_path(parsed.path)
    return urlunparse((parsed.scheme, parsed.netloc, path, '', '', ''))


def build_agent_websocket_url(
    request,
    explicit_url: str | None = None,
    configured_url: str | None = None,
) -> str:
    """Build the WebSocket URL agents should connect to."""
    if explicit_url:
        candidate = explicit_url.strip()
        if candidate:
            return candidate

    if configured_url:
        candidate = configured_url.strip()
        if candidate:
            return candidate

    configured = (os.environ.get('TIMEKPR_AGENT_WS_URL') or '').strip()
    if configured:
        return configured

    scheme = 'wss' if request.is_secure else 'ws'
    host = (request.host or 'localhost').strip()
    path = _normalize_ws_path('/ws')
    return urlunparse((scheme, host, path, '', '', ''))


def build_pairing_payload(server_url: str, registration_token: str | None = None) -> dict:
    payload = {
        'type': PAIRING_PAYLOAD_TYPE,
        'server_url': server_url.strip(),
    }
    if registration_token:
        payload['registration_token'] = registration_token.strip()
    return payload


def pairing_payload_json(server_url: str, registration_token: str | None = None) -> str:
    return json.dumps(build_pairing_payload(server_url, registration_token), sort_keys=True)


def render_pairing_qr_png(payload_json: str, box_size: int = 8, border: int = 2) -> bytes:
    """Render a QR code PNG for the pairing payload."""
    import qrcode

    qr = qrcode.QRCode(box_size=box_size, border=border)
    qr.add_data(payload_json)
    qr.make(fit=True)
    image = qr.make_image(fill_color='black', back_color='white')
    buffer = io.BytesIO()
    image.save(buffer, format='PNG')
    return buffer.getvalue()


def render_pairing_qr_data_uri(payload_json: str) -> str:
    png_bytes = render_pairing_qr_png(payload_json)
    encoded = base64.b64encode(png_bytes).decode('ascii')
    return f'data:image/png;base64,{encoded}'


def get_server_version() -> str:
    """Return the configured server version string."""
    return (os.environ.get('TIMEKPR_SERVER_VERSION') or 'v1.0.0-dev').strip()


def is_dev_server_version(version: str) -> bool:
    """Return True when the server version has no published release assets."""
    normalized = (version or '').strip()
    return not normalized or normalized.endswith('-dev')


def default_android_apk_url(version: str) -> str:
    """Return the Android APK URL published in the versions feed."""
    from src.agent.releases import get_component

    component = get_component('android') or {}
    for artifact in component.get('artifacts', []):
        if isinstance(artifact, dict) and artifact.get('id') == 'android-apk':
            return str(artifact.get('url') or '')
    return ''


def default_android_checksum_url(version: str) -> str:
    """Return the Android signature checksum URL published in the feed."""
    from src.agent.releases import get_component

    component = get_component('android') or {}
    for artifact in component.get('artifacts', []):
        if isinstance(artifact, dict) and artifact.get('id') == 'android-apk':
            return str(artifact.get('checksum_url') or '')
    return ''


def get_android_apk_storage_dir() -> str:
    """Directory used to persist an uploaded Android agent APK."""
    custom_dir = (os.environ.get('TIMEKPR_ANDROID_APK_DIR') or '').strip()
    if custom_dir:
        return custom_dir
    data_dir = (os.environ.get('TIMEKPR_DATA_DIR') or '').strip()
    if data_dir:
        return data_dir
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance')


def get_android_apk_storage_path() -> str:
    """Filesystem path for the uploaded Android agent APK."""
    custom_path = (os.environ.get('TIMEKPR_ANDROID_APK_PATH') or '').strip()
    if custom_path:
        return custom_path
    return os.path.join(get_android_apk_storage_dir(), _ANDROID_APK_FILENAME)


def has_uploaded_android_apk() -> bool:
    path = get_android_apk_storage_path()
    return os.path.isfile(path) and os.path.getsize(path) > 0


def websocket_url_to_http_origin(server_url: str) -> str:
    """Convert an agent WebSocket URL to an HTTP origin for device-reachable links."""
    parsed = urlparse(server_url.strip())
    if parsed.scheme not in ('ws', 'wss') or not parsed.netloc:
        raise ValueError('Agent WebSocket URL must use ws:// or wss:// with a host')

    scheme = 'https' if parsed.scheme == 'wss' else 'http'
    return urlunparse((scheme, parsed.netloc, '', '', '', ''))


def build_uploaded_android_apk_url(server_url: str) -> str:
    """Build the device-reachable download URL for a server-hosted uploaded APK."""
    origin = websocket_url_to_http_origin(server_url)
    return f'{origin.rstrip("/")}{PROVISIONING_APK_PATH}'


def _checksum_script_path() -> str:
    server_root = os.path.dirname(os.path.dirname(__file__))
    return os.path.join(server_root, 'scripts', 'android-signature-checksum.sh')


def _find_apksigner() -> str | None:
    """Return the newest available apksigner binary from the Android SDK."""
    roots: list[str] = []
    for env_var in ('ANDROID_HOME', 'ANDROID_SDK_ROOT'):
        value = (os.environ.get(env_var) or '').strip()
        if value:
            roots.append(os.path.join(value, 'build-tools'))
    roots.append(os.path.join(os.path.expanduser('~'), 'Android', 'Sdk', 'build-tools'))

    candidates: list[str] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for entry in os.listdir(root):
            candidate = os.path.join(root, entry, 'apksigner')
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                candidates.append(candidate)

    if not candidates:
        return None
    return sorted(candidates)[-1]


def _hex_digest_to_checksum(hex_digest: str) -> str:
    normalized = hex_digest.lower().replace(':', '').strip()
    if len(normalized) != 64 or any(ch not in '0123456789abcdef' for ch in normalized):
        raise RuntimeError('Invalid certificate SHA-256 digest')
    raw = bytes.fromhex(normalized)
    encoded = base64.urlsafe_b64encode(raw).decode('ascii')
    return encoded.rstrip('=')


def _checksum_from_apksigner(apk_path: str) -> str:
    apksigner = _find_apksigner()
    if not apksigner:
        raise RuntimeError('apksigner not found')

    result = subprocess.run(
        [apksigner, 'verify', '--print-certs', apk_path],
        capture_output=True,
        text=True,
        check=False,
    )
    output = '\n'.join(part for part in (result.stdout, result.stderr) if part).strip()
    if result.returncode != 0 and 'certificate SHA-256 digest:' not in output:
        raise RuntimeError(output or 'apksigner verify failed')

    hex_digest = ''
    for line in output.splitlines():
        marker = 'certificate SHA-256 digest:'
        if marker in line:
            hex_digest = line.split(':', 1)[1].strip()
            break
    if not hex_digest:
        raise RuntimeError('apksigner did not report a signing certificate digest')
    return _hex_digest_to_checksum(hex_digest)


def _validate_signature_checksum(checksum: str) -> str:
    candidate = (checksum or '').strip()
    if not candidate:
        raise RuntimeError('APK signature checksum is empty')
    if candidate == _EMPTY_SIGNATURE_CHECKSUM:
        raise RuntimeError(
            'APK signature checksum is invalid; install Android SDK build-tools '
            'so apksigner can read v2/v3-signed APKs'
        )
    return candidate


def compute_apk_signature_checksum(apk_path: str) -> str:
    """Compute the MDM provisioning signature checksum for an APK file."""
    errors: list[str] = []
    try:
        return _validate_signature_checksum(_checksum_from_apksigner(apk_path))
    except RuntimeError as exc:
        errors.append(str(exc))

    script = _checksum_script_path()
    if os.path.isfile(script):
        result = subprocess.run(
            [script, apk_path],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            try:
                return _validate_signature_checksum(result.stdout.strip())
            except RuntimeError as exc:
                errors.append(str(exc))
        else:
            message = (result.stderr or result.stdout or '').strip()
            errors.append(message or 'Checksum script failed')

    if errors:
        raise RuntimeError(errors[-1])
    raise RuntimeError('Checksum script not found')


def _validate_android_apk_upload(file_storage: FileStorage) -> None:
    filename = secure_filename(file_storage.filename or '')
    if not filename.lower().endswith('.apk'):
        raise ValueError('Uploaded file must have a .apk extension')

    header = file_storage.stream.read(4)
    file_storage.stream.seek(0)
    if header != b'PK\x03\x04':
        raise ValueError('Uploaded file does not look like a valid APK archive')


def save_uploaded_android_apk(file_storage: FileStorage) -> tuple[str, str]:
    """Validate, persist, and checksum an uploaded Android APK."""
    _validate_android_apk_upload(file_storage)

    storage_path = get_android_apk_storage_path()
    os.makedirs(os.path.dirname(storage_path), exist_ok=True)

    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size <= 0:
        raise ValueError('Uploaded APK is empty')
    if size > _MAX_ANDROID_APK_BYTES:
        raise ValueError('Uploaded APK exceeds the 250 MB limit')

    temp_path = f'{storage_path}.upload'
    try:
        file_storage.save(temp_path)
        checksum = compute_apk_signature_checksum(temp_path)
        os.replace(temp_path, storage_path)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise

    return secure_filename(file_storage.filename or _ANDROID_APK_FILENAME), checksum


def remove_uploaded_android_apk() -> None:
    """Delete a previously uploaded Android APK from the server."""
    storage_path = get_android_apk_storage_path()
    if os.path.isfile(storage_path):
        os.remove(storage_path)


def resolve_android_apk_url(version: str, server_url: str = '') -> str:
    """Resolve the APK URL used in Android MDM provisioning QR codes."""
    explicit = (os.environ.get('TIMEKPR_ANDROID_PROVISIONING_APK_URL') or '').strip()
    if explicit:
        return explicit
    if has_uploaded_android_apk() and (server_url or '').strip():
        return build_uploaded_android_apk_url(server_url)
    if is_dev_server_version(version):
        return ''
    return default_android_apk_url(version)


def _fetch_release_signature_checksum(version: str) -> str | None:
    """Fetch the companion signature-checksum asset from a GitHub release."""
    tag = (version or '').strip()
    if not tag or is_dev_server_version(tag):
        return None

    now = time.monotonic()
    cached = _CHECKSUM_CACHE.get(tag)
    if cached and (now - cached[1]) < _CHECKSUM_CACHE_TTL_SECONDS:
        return cached[0]

    url = default_android_checksum_url(tag)
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return None
        checksum = response.text.strip()
        if not checksum or checksum == _EMPTY_SIGNATURE_CHECKSUM:
            return None
        _CHECKSUM_CACHE[tag] = (checksum, now)
        return checksum
    except requests.RequestException as exc:
        _LOGGER.debug('Failed to fetch Android signature checksum for %s: %s', tag, exc)
        return None


def resolve_android_signature_checksum(
    version: str,
    override: str | None = None,
) -> str | None:
    """Resolve the APK signing certificate checksum for MDM provisioning."""
    if has_uploaded_android_apk():
        try:
            return compute_apk_signature_checksum(get_android_apk_storage_path())
        except RuntimeError as exc:
            _LOGGER.warning('Failed to compute checksum from uploaded APK: %s', exc)
            stored = (override or '').strip()
            if stored:
                return stored
            return None

    env_checksum = (os.environ.get('TIMEKPR_ANDROID_SIGNATURE_CHECKSUM') or '').strip()
    if env_checksum:
        return env_checksum

    return _fetch_release_signature_checksum(version)


def is_https_download_url(url: str) -> bool:
    parsed = urlparse((url or '').strip())
    return parsed.scheme == 'https' and bool(parsed.netloc)


def provisioning_download_warnings(apk_url: str) -> list[str]:
    warnings: list[str] = []
    if not apk_url:
        return warnings
    if not is_https_download_url(apk_url):
        warnings.append(
            'APK download URL is not HTTPS. Many devices (including Samsung) refuse to '
            'download the DPC during setup wizard provisioning over plain HTTP.'
        )
    return warnings


def build_android_provisioning_payload(
    server_url: str,
    apk_url: str,
    signature_checksum: str,
    registration_token: str | None = None,
    leave_all_system_apps_enabled: bool = True,
    wifi_ssid: str | None = None,
    wifi_security_type: str | None = None,
    wifi_password: str | None = None,
) -> dict:
    """Build an Android Enterprise 6-tap provisioning QR payload."""
    extras = {
        ANDROID_EXTRA_SERVER_URL: server_url.strip(),
    }
    if registration_token:
        extras[ANDROID_EXTRA_REGISTRATION_TOKEN] = registration_token.strip()

    payload = {
        PROVISIONING_KEY_COMPONENT: ANDROID_DPC_COMPONENT,
        PROVISIONING_KEY_SIGNATURE: signature_checksum.strip(),
        PROVISIONING_KEY_DOWNLOAD: apk_url.strip(),
        PROVISIONING_KEY_EXTRAS: extras,
        PROVISIONING_KEY_LEAVE_ALL_SYSTEM_APPS_ENABLED: leave_all_system_apps_enabled,
        PROVISIONING_KEY_SKIP_ENCRYPTION: True,
    }

    if wifi_ssid and wifi_ssid.strip():
        payload[PROVISIONING_KEY_WIFI_SSID] = wifi_ssid.strip()
        payload[PROVISIONING_KEY_WIFI_SECURITY_TYPE] = (wifi_security_type or 'WPA').strip()
        if wifi_password and wifi_password.strip():
            payload[PROVISIONING_KEY_WIFI_PASSWORD] = wifi_password

    return payload


def provisioning_payload_json(
    server_url: str,
    apk_url: str,
    signature_checksum: str,
    registration_token: str | None = None,
    leave_all_system_apps_enabled: bool = True,
    wifi_ssid: str | None = None,
    wifi_security_type: str | None = None,
    wifi_password: str | None = None,
) -> str:
    return json.dumps(
        build_android_provisioning_payload(
            server_url,
            apk_url,
            signature_checksum,
            registration_token,
            leave_all_system_apps_enabled=leave_all_system_apps_enabled,
            wifi_ssid=wifi_ssid,
            wifi_security_type=wifi_security_type,
            wifi_password=wifi_password,
        ),
        sort_keys=True,
    )


def resolve_android_provisioning(
    server_url: str,
    version: str,
    checksum_override: str | None = None,
    registration_token: str | None = None,
) -> dict:
    """Resolve APK URL, checksum, and readiness for Android MDM provisioning."""
    apk_url = resolve_android_apk_url(version, server_url=server_url)
    signature_checksum = resolve_android_signature_checksum(version, checksum_override)
    download_warnings = provisioning_download_warnings(apk_url or '')
    provisioning_ready = bool(apk_url and signature_checksum)

    checksum_source = 'missing'
    if has_uploaded_android_apk() and signature_checksum:
        checksum_source = 'upload'
    elif (os.environ.get('TIMEKPR_ANDROID_SIGNATURE_CHECKSUM') or '').strip() and signature_checksum:
        checksum_source = 'environment'
    elif signature_checksum:
        checksum_source = 'release'

    apk_source = 'missing'
    if has_uploaded_android_apk():
        apk_source = 'upload'
    elif apk_url:
        apk_source = 'release'

    # Retrieve current provisioning configuration settings
    leave_all_system_apps_enabled = _get_android_provisioning_leave_all_system_apps_enabled()
    wifi_ssid = _get_android_provisioning_wifi_ssid()
    wifi_security_type = _get_android_provisioning_wifi_security_type()
    wifi_password = _get_android_provisioning_wifi_password()

    payload = None
    payload_json = None
    if provisioning_ready:
        payload = build_android_provisioning_payload(
            server_url,
            apk_url,
            signature_checksum,
            registration_token,
            leave_all_system_apps_enabled=leave_all_system_apps_enabled,
            wifi_ssid=wifi_ssid,
            wifi_security_type=wifi_security_type,
            wifi_password=wifi_password,
        )
        payload_json = provisioning_payload_json(
            server_url,
            apk_url,
            signature_checksum,
            registration_token,
            leave_all_system_apps_enabled=leave_all_system_apps_enabled,
            wifi_ssid=wifi_ssid,
            wifi_security_type=wifi_security_type,
            wifi_password=wifi_password,
        )

    return {
        'apk_url': apk_url,
        'apk_source': apk_source,
        'apk_download_https': is_https_download_url(apk_url or ''),
        'signature_checksum': signature_checksum,
        'checksum_source': checksum_source,
        'provisioning_ready': provisioning_ready,
        'provisioning_warnings': download_warnings,
        'payload': payload,
        'payload_json': payload_json,
        'is_dev_version': is_dev_server_version(version),
        'leave_all_system_apps_enabled': leave_all_system_apps_enabled,
        'wifi_ssid': wifi_ssid,
        'wifi_security_type': wifi_security_type,
        'has_wifi_password': bool(wifi_password),
    }



def resolve_android_update_info(version: str, server_url: str = '') -> dict:
    """Resolve APK download metadata for Android agent auto-update."""
    from src.agent.releases import resolve_android_update_info as _resolve_android_update_info

    return _resolve_android_update_info(version, server_url=server_url)
