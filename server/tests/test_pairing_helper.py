"""Tests for agent pairing QR helpers."""

import io
import json
import zipfile
from unittest.mock import patch

import pytest
from werkzeug.datastructures import FileStorage

from src.agent.pairing import (
    ANDROID_DPC_COMPONENT,
    ANDROID_EXTRA_REGISTRATION_TOKEN,
    ANDROID_EXTRA_SERVER_URL,
    PAIRING_PAYLOAD_TYPE,
    PROVISIONING_KEY_COMPONENT,
    PROVISIONING_KEY_DOWNLOAD,
    PROVISIONING_KEY_EXTRAS,
    PROVISIONING_KEY_SIGNATURE,
    PROVISIONING_KEY_SKIP_ENCRYPTION,
    build_android_provisioning_payload,
    build_pairing_payload,
    default_android_apk_url,
    is_dev_server_version,
    normalize_agent_websocket_url,
    pairing_payload_json,
    provisioning_payload_json,
    render_pairing_qr_png,
    resolve_android_apk_url,
    resolve_android_provisioning,
    resolve_android_signature_checksum,
    resolve_android_update_info,
)

ANDROID_COMPONENT = {
    'version': '1.0.0',
    'repository': 'https://github.com/Guardian-Parental-Controls/agent-android',
    'artifacts': [{
        'id': 'android-apk',
        'url': 'https://example.com/guardian-android-agent-v1.0.0.apk',
        'checksum_url': 'https://example.com/guardian-android-agent-v1.0.0.signature-checksum',
        'signature_checksum': 'release-checksum',
    }],
}


def test_build_pairing_payload_includes_registration_token():
    payload = build_pairing_payload('wss://example.com/ws', 'secret-token')
    assert payload['type'] == PAIRING_PAYLOAD_TYPE
    assert payload['server_url'] == 'wss://example.com/ws'
    assert payload['registration_token'] == 'secret-token'


def test_pairing_payload_json_roundtrip():
    raw = pairing_payload_json('ws://127.0.0.1:5000/ws')
    parsed = json.loads(raw)
    assert parsed['type'] == PAIRING_PAYLOAD_TYPE
    assert parsed['server_url'].startswith('ws://')


def test_render_pairing_qr_png():
    png = render_pairing_qr_png(pairing_payload_json('ws://localhost/ws'))
    assert png[:8] == b'\x89PNG\r\n\x1a\n'


def test_build_agent_websocket_url_from_request(app):
    with app.test_request_context('/', base_url='https://timekpr.example'):
        from flask import request

        from src.agent.pairing import build_agent_websocket_url

        assert build_agent_websocket_url(request) == 'wss://timekpr.example/ws'


def test_build_agent_websocket_url_explicit_override(app):
    with app.test_request_context('/'):
        from flask import request

        from src.agent.pairing import build_agent_websocket_url

        assert build_agent_websocket_url(request, explicit_url='wss://custom/ws') == 'wss://custom/ws'


def test_build_agent_websocket_url_configured_override(app):
    with app.test_request_context('/', base_url='https://timekpr.example'):
        from flask import request

        from src.agent.pairing import build_agent_websocket_url

        assert build_agent_websocket_url(
            request,
            configured_url='wss://public.example/ws',
        ) == 'wss://public.example/ws'


@patch('src.agent.releases.get_component')
def test_linux_install_script_redirects_to_feed_url(mock_component, app):
    mock_component.return_value = {
        'install_script': 'https://example.com/install-agent.sh',
    }
    client = app.test_client()

    response = client.get('/scripts/install-agent.sh')

    assert response.status_code == 302
    assert response.headers['Location'] == 'https://example.com/install-agent.sh'


def test_normalize_agent_websocket_url_adds_default_path():
    assert normalize_agent_websocket_url('wss://example.com') == 'wss://example.com/ws'


def test_normalize_agent_websocket_url_rejects_invalid_scheme():
    with pytest.raises(ValueError, match='ws:// or wss://'):
        normalize_agent_websocket_url('https://example.com/ws')


def test_is_dev_server_version():
    assert is_dev_server_version('v0.0.0-dev') is True
    assert is_dev_server_version('') is True
    assert is_dev_server_version('v0.10') is False


@patch('src.agent.releases.get_component', return_value=ANDROID_COMPONENT)
def test_default_android_apk_url(_mock_component):
    url = default_android_apk_url('v1.2.3')
    assert url.endswith('/guardian-android-agent-v1.0.0.apk')


def test_resolve_android_apk_url_dev_without_upload(app):
    with app.test_request_context('/'):
        assert resolve_android_apk_url('v0.0.0-dev') == ''


@patch('src.agent.releases.get_component', return_value=ANDROID_COMPONENT)
def test_resolve_android_apk_url_release_default(_mock_component, app):
    with app.test_request_context('/'):
        url = resolve_android_apk_url('1.0.0')
        assert 'guardian-android-agent-v1.0.0.apk' in url


@patch('src.agent.pairing.has_uploaded_android_apk', return_value=True)
def test_resolve_android_apk_url_uses_agent_server_host(mock_uploaded):
    url = resolve_android_apk_url('v0.0.0-dev', server_url='ws://10.10.5.25:5000/ws')
    assert url == 'http://10.10.5.25:5000/api/pairing/provisioning/apk'


def test_build_uploaded_android_apk_url_uses_wss_origin():
    from src.agent.pairing import build_uploaded_android_apk_url

    url = build_uploaded_android_apk_url('wss://timekpr.example/ws')
    assert url == 'https://timekpr.example/api/pairing/provisioning/apk'


@patch('src.agent.pairing.has_uploaded_android_apk', return_value=True)
@patch('src.agent.pairing.compute_apk_signature_checksum', return_value='computed-checksum')
def test_resolve_android_signature_checksum_computes_from_upload(mock_compute, mock_uploaded):
    assert resolve_android_signature_checksum('v0.10', 'stale-override') == 'computed-checksum'
    mock_compute.assert_called_once()


@patch('src.agent.pairing.has_uploaded_android_apk', return_value=True)
@patch('src.agent.pairing.compute_apk_signature_checksum', side_effect=RuntimeError('fail'))
def test_resolve_android_signature_checksum_falls_back_to_stored_override(mock_compute, mock_uploaded):
    assert resolve_android_signature_checksum('v0.10', 'checksum-override') == 'checksum-override'


@patch('src.agent.pairing._fetch_release_signature_checksum', return_value='release-checksum')
def test_resolve_android_signature_checksum_fetches_release(mock_fetch):
    assert resolve_android_signature_checksum('v0.10', '') == 'release-checksum'
    mock_fetch.assert_called_once_with('v0.10')


def test_android_dpc_component_matches_guardian_apk():
    assert ANDROID_DPC_COMPONENT == (
        'com.guardian.agent/com.guardian.agent.admin.GuardianDeviceAdminReceiver'
    )
    assert ANDROID_EXTRA_SERVER_URL == 'com.guardian.agent.EXTRA_SERVER_URL'
    assert ANDROID_EXTRA_REGISTRATION_TOKEN == 'com.guardian.agent.EXTRA_REGISTRATION_TOKEN'


def test_build_android_provisioning_payload_shape():
    payload = build_android_provisioning_payload(
        'wss://example.com/ws',
        'https://cdn.example/app.apk',
        'abc123checksum',
        'reg-token',
    )
    assert payload[PROVISIONING_KEY_COMPONENT] == ANDROID_DPC_COMPONENT
    assert payload[PROVISIONING_KEY_DOWNLOAD] == 'https://cdn.example/app.apk'
    assert payload[PROVISIONING_KEY_SIGNATURE] == 'abc123checksum'
    extras = payload[PROVISIONING_KEY_EXTRAS]
    assert extras[ANDROID_EXTRA_SERVER_URL] == 'wss://example.com/ws'
    assert extras[ANDROID_EXTRA_REGISTRATION_TOKEN] == 'reg-token'
    assert payload[PROVISIONING_KEY_SKIP_ENCRYPTION] is True


def test_provisioning_download_warnings_for_http_apk():
    from src.agent.pairing import provisioning_download_warnings

    warnings = provisioning_download_warnings('http://10.0.0.5:5000/api/pairing/provisioning/apk')
    assert warnings
    assert provisioning_download_warnings('https://example.com/app.apk') == []


def test_provisioning_payload_json_roundtrip():
    raw = provisioning_payload_json(
        'wss://example.com/ws',
        'https://cdn.example/app.apk',
        'abc123checksum',
    )
    parsed = json.loads(raw)
    assert parsed[PROVISIONING_KEY_COMPONENT] == ANDROID_DPC_COMPONENT


@patch('src.agent.pairing.has_uploaded_android_apk', return_value=False)
@patch('src.agent.pairing._fetch_release_signature_checksum', return_value='release-checksum')
@patch('src.agent.releases.get_component', return_value=ANDROID_COMPONENT)
def test_resolve_android_provisioning_ready_with_release_assets(
    _mock_component,
    mock_fetch,
    mock_uploaded,
):
    context = resolve_android_provisioning(
        'wss://example.com/ws',
        '1.0.0',
        registration_token='secret',
    )
    assert context['provisioning_ready'] is True
    assert context['apk_source'] == 'release'
    assert context['checksum_source'] == 'release'
    assert context['payload_json'] is not None


def test_resolve_android_provisioning_not_ready_for_dev_without_overrides():
    context = resolve_android_provisioning('wss://example.com/ws', 'v0.0.0-dev')
    assert context['provisioning_ready'] is False
    assert context['is_dev_version'] is True


@patch('src.agent.releases.fetch_versions_feed')
def test_resolve_android_update_info_with_release_assets(mock_feed):
    mock_feed.return_value = {
        'schema_version': 1,
        'components': {'agent-android': ANDROID_COMPONENT},
    }
    info = resolve_android_update_info('1.0.0', server_url='wss://example.com/ws')
    assert info['update_available'] is True
    assert info['apk_url'] == ANDROID_COMPONENT['artifacts'][0]['url']
    assert info['signature_checksum'] == 'release-checksum'


@patch('src.agent.pairing.has_uploaded_android_apk', return_value=False)
def test_resolve_android_update_info_not_available_for_dev_without_upload(mock_uploaded):
    info = resolve_android_update_info('v0.0.0-dev', server_url='wss://example.com/ws')
    assert info['update_available'] is False
    assert info['apk_url'] == ''
    assert info['signature_checksum'] == ''


@patch('src.agent.pairing.has_uploaded_android_apk', return_value=True)
def test_resolve_android_provisioning_ready_with_uploaded_apk(mock_uploaded):
    context = resolve_android_provisioning(
        'ws://10.10.5.25:5000/ws',
        'v0.0.0-dev',
        checksum_override='dev-checksum',
    )
    assert context['provisioning_ready'] is True
    assert context['apk_source'] == 'upload'
    assert context['checksum_source'] == 'upload'
    assert context['apk_url'] == 'http://10.10.5.25:5000/api/pairing/provisioning/apk'


def _make_apk_filestorage():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('AndroidManifest.xml', '<manifest />')
    buffer.seek(0)
    return FileStorage(
        stream=buffer,
        filename='app-release.apk',
        content_type='application/vnd.android.package-archive',
    )


def test_validate_android_apk_upload_rejects_non_apk():
    from src.agent.pairing import _validate_android_apk_upload

    storage = FileStorage(stream=io.BytesIO(b'plain-text'), filename='notes.txt')
    with pytest.raises(ValueError, match='.apk'):
        _validate_android_apk_upload(storage)


@patch('src.agent.pairing.compute_apk_signature_checksum', return_value='checksum-value')
def test_save_uploaded_android_apk_persists_file(mock_checksum, tmp_path, monkeypatch):
    import os

    from src.agent.pairing import get_android_apk_storage_path, save_uploaded_android_apk

    monkeypatch.setenv('TIMEKPR_ANDROID_APK_PATH', str(tmp_path / 'android-agent.apk'))
    filename, checksum = save_uploaded_android_apk(_make_apk_filestorage())
    assert filename == 'app-release.apk'
    assert checksum == 'checksum-value'
    assert os.path.isfile(get_android_apk_storage_path())


def test_validate_signature_checksum_rejects_empty_hash():
    from src.agent.pairing import _validate_signature_checksum

    with pytest.raises(RuntimeError, match='invalid'):
        _validate_signature_checksum('47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU')


@patch('src.agent.pairing._checksum_from_apksigner', return_value='real-checksum')
def test_compute_apk_signature_checksum_uses_apksigner(mock_apksigner, tmp_path):
    from src.agent.pairing import compute_apk_signature_checksum

    apk_path = tmp_path / 'agent.apk'
    apk_path.write_bytes(b'placeholder')
    assert compute_apk_signature_checksum(str(apk_path)) == 'real-checksum'
    mock_apksigner.assert_called_once_with(str(apk_path))


def test_fetch_release_signature_checksum_ignores_empty_hash():
    with patch('src.agent.pairing.requests.get') as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU'
        from src.agent.pairing import _fetch_release_signature_checksum

        assert _fetch_release_signature_checksum('v0.32') is None
