"""Resolve agent compatibility and updates from the Guardian versions feed."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import requests

from src.agent.pairing import (
    has_uploaded_android_apk,
    is_dev_server_version,
    resolve_android_apk_url,
    resolve_android_signature_checksum,
)

_LOGGER = logging.getLogger(__name__)

DEFAULT_VERSIONS_URL = 'https://guardian-parental-controls.github.io/versions/feed.json'
_FEED_CACHE: dict[str, tuple[dict[str, Any], float]] = {}
_FEED_CACHE_TTL_SECONDS = int(os.environ.get('GUARDIAN_VERSIONS_CACHE_TTL_SECONDS', '120'))


def get_versions_url() -> str:
    return (os.environ.get('GUARDIAN_VERSIONS_URL') or DEFAULT_VERSIONS_URL).strip()


def _parse_version(version: str | None) -> tuple[int, int, int] | None:
    normalized = (version or '').strip().lstrip('v').split('-', 1)[0].split('+', 1)[0]
    parts = normalized.split('.')
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def _validate_feed(feed: Any) -> dict[str, Any]:
    if not isinstance(feed, dict) or feed.get('schema_version') != 1:
        raise ValueError('unsupported Guardian versions feed')
    components = feed.get('components')
    if not isinstance(components, dict):
        raise ValueError('versions feed components must be an object')
    return feed


def fetch_versions_feed(*, force: bool = False) -> dict[str, Any] | None:
    """Fetch and cache the release catalog. Failure safely disables updates."""
    url = get_versions_url()
    now = time.monotonic()
    cached = _FEED_CACHE.get(url)
    if not force and cached and now - cached[1] < _FEED_CACHE_TTL_SECONDS:
        return cached[0]

    try:
        if url.startswith('file://'):
            with open(url[7:], encoding='utf-8') as feed_file:
                feed = json.load(feed_file)
        else:
            response = requests.get(
                url,
                timeout=10,
                headers={'Accept': 'application/json'},
            )
            response.raise_for_status()
            feed = response.json()
        validated = _validate_feed(feed)
        _FEED_CACHE[url] = (validated, now)
        return validated
    except (OSError, ValueError, requests.RequestException) as exc:
        _LOGGER.warning('Unable to load Guardian versions feed from %s: %s', url, exc)
        return cached[0] if cached else None


def _component_id(platform: str | None) -> str | None:
    normalized = normalize_platform(platform)
    return {
        'linux': 'agent-linux',
        'windows': 'agent-windows',
        'android': 'agent-android',
    }.get(normalized)


def get_component(platform: str | None) -> dict[str, Any] | None:
    component_id = _component_id(platform)
    feed = fetch_versions_feed()
    if not component_id or not feed:
        return None
    component = feed['components'].get(component_id)
    return component if isinstance(component, dict) else None


def normalize_platform(platform: str | None) -> str:
    return (platform or '').strip().lower()


def linux_artifact_id(agent_arch: str | None) -> str | None:
    arch = (agent_arch or '').strip().lower()
    if arch == 'x86_64':
        return 'linux-x86_64'
    if arch == 'aarch64':
        return 'linux-aarch64'
    return None


def _find_artifact(component: dict[str, Any], artifact_id: str) -> dict[str, Any] | None:
    for artifact in component.get('artifacts', []):
        if isinstance(artifact, dict) and artifact.get('id') == artifact_id:
            return artifact
    return None


def _empty_update_payload(target_version: str = '') -> dict[str, Any]:
    return {
        'target_version': target_version,
        'update_available': False,
        'apk_url': '',
        'signature_checksum': '',
        'download_url': '',
        'checksum_url': '',
    }


def _resolve_android_update_fields(tag: str, server_url: str) -> dict[str, str]:
    apk_url = resolve_android_apk_url(tag, server_url=server_url)
    signature_checksum = resolve_android_signature_checksum(tag) or ''
    return {
        'apk_url': apk_url or '',
        'signature_checksum': signature_checksum,
    }


def resolve_agent_update_info(
    platform: str | None,
    target_version: str = '',
    server_url: str = '',
    agent_arch: str | None = None,
) -> dict[str, Any]:
    """Resolve update metadata exclusively from the compiled versions feed."""
    component = get_component(platform)
    current_version = str(component.get('version', '')) if component else target_version
    payload = _empty_update_payload(current_version)
    normalized_platform = normalize_platform(platform)

    if is_dev_server_version(target_version):
        if normalized_platform == 'android' and has_uploaded_android_apk() and (server_url or '').strip():
            fields = _resolve_android_update_fields(target_version, server_url)
            if fields['apk_url'] and fields['signature_checksum']:
                payload.update(fields)
                payload['update_available'] = True
        return payload

    if not component:
        return payload

    if normalized_platform == 'android':
        artifact = _find_artifact(component, 'android-apk')
        if artifact and artifact.get('url') and artifact.get('signature_checksum'):
            payload['apk_url'] = str(artifact['url'])
            payload['signature_checksum'] = str(artifact['signature_checksum'])
            payload['update_available'] = True
        return payload

    if normalized_platform == 'linux':
        artifact_id = linux_artifact_id(agent_arch)
        if not artifact_id:
            return payload
        artifact = _find_artifact(component, artifact_id)
        if artifact and artifact.get('url') and artifact.get('checksum_url'):
            payload['download_url'] = str(artifact['url'])
            payload['checksum_url'] = str(artifact['checksum_url'])
            payload['update_available'] = True
        return payload

    if normalized_platform == 'windows':
        artifact = _find_artifact(component, 'windows-x86_64')
        if artifact and artifact.get('url') and artifact.get('checksum_url'):
            payload['download_url'] = str(artifact['url'])
            payload['checksum_url'] = str(artifact['checksum_url'])
            payload['update_available'] = True
        return payload

    return payload


def resolve_android_update_info(version: str, server_url: str = '') -> dict[str, Any]:
    """Backward-compatible Android update metadata helper."""
    info = resolve_agent_update_info('android', version, server_url=server_url)
    return {
        'apk_url': info.get('apk_url', ''),
        'signature_checksum': info.get('signature_checksum', ''),
        'update_available': bool(info.get('update_available')),
    }


def enrich_auth_with_agent_update(
    auth_payload: dict[str, Any],
    *,
    platform: str | None,
    server_version: str,
    agent_version: str | None,
    server_url: str,
    agent_arch: str | None = None,
    mandatory: bool = False,
) -> dict[str, Any]:
    """Attach feed-provided update metadata to an authentication result."""
    auth_payload['update_available'] = False

    if mandatory:
        auth_payload['update_required'] = True

    update_info = resolve_agent_update_info(
        platform,
        server_version,
        server_url=server_url,
        agent_arch=agent_arch,
    )
    if not update_info.get('update_available'):
        return auth_payload

    auth_payload.update(update_info)
    return auth_payload


def agent_version_status(
    platform: str | None,
    agent_version: str | None,
    server_version: str,
) -> tuple[bool, bool]:
    """Return (compatible, update_recommended) using the feed's support floor."""
    if is_dev_server_version(server_version):
        return True, False

    component = get_component(platform)
    agent = _parse_version(agent_version)
    server = _parse_version(server_version)
    if not component or not agent or not server:
        return False, False

    latest = _parse_version(str(component.get('version', '')))
    minimum = _parse_version(str(component.get('minimum_supported_version', '1.0.0')))
    min_server = _parse_version(str(component.get('min_server', '1.0.0')))
    if not latest or not minimum or not min_server:
        return False, False

    compatible = agent[0] == latest[0] and agent >= minimum
    update_recommended = compatible and server >= min_server and agent < latest
    return compatible, update_recommended
