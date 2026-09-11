"""Tests for feed-based agent update metadata."""

from unittest.mock import patch

from src.agent.releases import (
    agent_version_status,
    enrich_auth_with_agent_update,
    fetch_versions_feed,
    get_versions_url,
    resolve_agent_update_info,
)


FEED = {
    'schema_version': 1,
    'generated_at': '2026-09-11T09:00:00Z',
    'components': {
        'agent-linux': {
            'version': '1.2.0',
            'minimum_supported_version': '1.0.0',
            'min_server': '1.0.0',
            'repository': 'https://github.com/Guardian-Parental-Controls/agent-linux',
            'artifacts': [
                {
                    'id': 'linux-aarch64',
                    'url': 'https://example.com/linux.tar.gz',
                    'checksum_url': 'https://example.com/linux.tar.gz.sha256',
                },
            ],
        },
        'agent-android': {
            'version': '1.1.0',
            'minimum_supported_version': '1.0.0',
            'min_server': '1.0.0',
            'repository': 'https://github.com/Guardian-Parental-Controls/agent-android',
            'artifacts': [
                {
                    'id': 'android-apk',
                    'url': 'https://example.com/agent.apk',
                    'signature_checksum': 'signature',
                },
            ],
        },
    },
}


def test_versions_url_has_org_default(monkeypatch):
    monkeypatch.delenv('GUARDIAN_VERSIONS_URL', raising=False)
    assert get_versions_url() == (
        'https://guardian-parental-controls.github.io/versions/feed.json'
    )


def test_versions_url_honours_override(monkeypatch):
    monkeypatch.setenv('GUARDIAN_VERSIONS_URL', 'https://example.com/feed.json')
    assert get_versions_url() == 'https://example.com/feed.json'


def test_fetch_versions_feed_supports_file_fixture(tmp_path, monkeypatch):
    feed_path = tmp_path / 'feed.json'
    import json
    feed_path.write_text(json.dumps(FEED), encoding='utf-8')
    monkeypatch.setenv('GUARDIAN_VERSIONS_URL', feed_path.as_uri())

    assert fetch_versions_feed(force=True) == FEED


@patch('src.agent.releases.fetch_versions_feed', return_value=FEED)
def test_resolve_linux_uses_arch_artifact(_mock_feed):
    info = resolve_agent_update_info('linux', '1.0.0', agent_arch='aarch64')
    assert info['target_version'] == '1.2.0'
    assert info['update_available'] is True
    assert info['download_url'] == 'https://example.com/linux.tar.gz'


@patch('src.agent.releases.fetch_versions_feed', return_value=FEED)
def test_resolve_android_uses_feed_signature(_mock_feed):
    info = resolve_agent_update_info('android', '1.0.0')
    assert info['update_available'] is True
    assert info['apk_url'] == 'https://example.com/agent.apk'
    assert info['signature_checksum'] == 'signature'


@patch('src.agent.releases.fetch_versions_feed', return_value=FEED)
def test_version_status_uses_support_floor_and_latest(_mock_feed):
    assert agent_version_status('linux', '1.0.0', '1.0.0') == (True, True)
    assert agent_version_status('linux', '1.2.0', '1.0.0') == (True, False)
    assert agent_version_status('linux', '0.9.0', '1.0.0') == (False, False)


@patch('src.agent.releases.fetch_versions_feed')
def test_older_server_keeps_supported_agent_but_does_not_offer_new_build(mock_feed):
    feed = {
        **FEED,
        'components': {
            **FEED['components'],
            'agent-linux': {
                **FEED['components']['agent-linux'],
                'min_server': '1.2.0',
            },
        },
    }
    mock_feed.return_value = feed
    assert agent_version_status('linux', '1.0.0', '1.0.0') == (True, False)


@patch('src.agent.releases.resolve_agent_update_info')
def test_enrich_auth_sets_required_and_feed_target(mock_resolve):
    mock_resolve.return_value = {
        'target_version': '1.2.0',
        'update_available': True,
        'download_url': 'https://example.com/linux.tar.gz',
        'checksum_url': 'https://example.com/linux.tar.gz.sha256',
    }
    payload = enrich_auth_with_agent_update(
        {'type': 'auth_result', 'success': False, 'message': 'update'},
        platform='linux',
        server_version='1.0.0',
        agent_version='0.9.0',
        server_url='wss://example.com/ws',
        agent_arch='aarch64',
        mandatory=True,
    )
    assert payload['update_required'] is True
    assert payload['target_version'] == '1.2.0'
    assert payload['update_available'] is True
