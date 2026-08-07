"""Single-flight OIDC token refresh to avoid refresh-token rotation races."""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import threading
import time
from typing import Any

from src.common.oidc import OIDCRefreshError

_LOGGER = logging.getLogger(__name__)

_locks_guard = threading.Lock()
_locks: dict[str, threading.Lock] = {}
_memory_cache: dict[str, dict[str, Any]] = {}


def _cache_key(refresh_token: str) -> str:
    return hashlib.sha256(refresh_token.encode('utf-8')).hexdigest()


def _lock_for(key: str) -> threading.Lock:
    with _locks_guard:
        if key not in _locks:
            _locks[key] = threading.Lock()
        return _locks[key]


def _cache_ttl_seconds() -> int:
    raw = os.environ.get('OIDC_REFRESH_CACHE_SECONDS', '120').strip()
    try:
        return max(30, int(raw))
    except ValueError:
        return 120


def _cache_dir() -> str | None:
    try:
        from flask import current_app

        path = os.path.join(current_app.instance_path, 'oidc_refresh_cache')
        os.makedirs(path, exist_ok=True)
        return path
    except Exception:
        return None


def _read_file_cache(key: str) -> dict[str, Any] | None:
    cache_dir = _cache_dir()
    if not cache_dir:
        return None

    cache_path = os.path.join(cache_dir, f'{key}.json')
    if not os.path.exists(cache_path):
        return None

    try:
        with open(cache_path, 'r', encoding='utf-8') as handle:
            payload = json.load(handle)
    except (OSError, ValueError, TypeError):
        return None

    expires_at = float(payload.get('expires_at', 0))
    if expires_at <= time.time():
        try:
            os.remove(cache_path)
        except OSError:
            pass
        return None

    tokens = payload.get('tokens')
    if not isinstance(tokens, dict) or not tokens.get('access_token'):
        return None
    return tokens


def _write_file_cache(key: str, tokens: dict[str, Any]) -> None:
    cache_dir = _cache_dir()
    if not cache_dir:
        return

    cache_path = os.path.join(cache_dir, f'{key}.json')
    lock_path = os.path.join(cache_dir, f'{key}.lock')
    payload = {
        'tokens': tokens,
        'cached_at': time.time(),
        'expires_at': time.time() + _cache_ttl_seconds(),
    }

    try:
        with open(lock_path, 'w', encoding='utf-8') as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                with open(cache_path, 'w', encoding='utf-8') as handle:
                    json.dump(payload, handle)
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    except OSError as exc:
        _LOGGER.debug('Unable to persist OIDC refresh cache: %s', exc)


def _remember_tokens(key: str, tokens: dict[str, Any]) -> None:
    _memory_cache[key] = {
        'tokens': tokens,
        'expires_at': time.time() + _cache_ttl_seconds(),
    }
    _write_file_cache(key, tokens)


def _lookup_cached_tokens(key: str) -> dict[str, Any] | None:
    cached = _memory_cache.get(key)
    if cached and cached['expires_at'] > time.time():
        return cached['tokens']

    file_tokens = _read_file_cache(key)
    if file_tokens is not None:
        _memory_cache[key] = {
            'tokens': file_tokens,
            'expires_at': time.time() + _cache_ttl_seconds(),
        }
        return file_tokens
    return None


def clear_refresh_cache_for_tests() -> None:
    """Reset in-memory OIDC refresh caches between tests."""
    _memory_cache.clear()


def refresh_oidc_tokens(oidc_helper, refresh_token: str) -> dict[str, Any]:
    """Refresh OIDC tokens, deduplicating concurrent refresh attempts."""
    key = _cache_key(refresh_token)
    cached = _lookup_cached_tokens(key)
    if cached is not None:
        return cached

    lock = _lock_for(key)
    with lock:
        cached = _lookup_cached_tokens(key)
        if cached is not None:
            return cached

        try:
            tokens = oidc_helper.refresh_access_token(refresh_token)
        except OIDCRefreshError as exc:
            cached = _lookup_cached_tokens(key)
            if cached is not None:
                _LOGGER.info(
                    'Recovered OIDC refresh from cache after concurrent refresh failure '
                    '(status=%s, oauth_error=%s).',
                    exc.status_code,
                    exc.oauth_error,
                )
                return cached
            raise

        _remember_tokens(key, tokens)
        return tokens
