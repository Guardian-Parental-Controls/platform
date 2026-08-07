"""Tests for coordinated OIDC token refresh."""

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from src.auth.oidc_token_refresh import refresh_oidc_tokens
from src.common.oidc import OIDCRefreshError


def test_refresh_oidc_tokens_uses_memory_cache():
    helper = MagicMock()
    helper.refresh_access_token.return_value = {
        'access_token': 'cached-access',
        'expires_in': 3600,
    }

    first = refresh_oidc_tokens(helper, 'refresh-token-a')
    second = refresh_oidc_tokens(helper, 'refresh-token-a')

    assert first['access_token'] == 'cached-access'
    assert second['access_token'] == 'cached-access'
    helper.refresh_access_token.assert_called_once_with('refresh-token-a')


def test_refresh_oidc_tokens_recovers_after_invalid_grant_when_cache_exists():
    helper = MagicMock()
    helper.refresh_access_token.side_effect = OIDCRefreshError(
        'revoked',
        is_transient=False,
        status_code=400,
        oauth_error='invalid_grant',
    )

    from src.auth import oidc_token_refresh

    key = oidc_token_refresh._cache_key('shared-refresh-token')
    oidc_token_refresh._remember_tokens(
        key,
        {'access_token': 'winner-token', 'expires_in': 3600},
    )

    tokens = refresh_oidc_tokens(helper, 'shared-refresh-token')

    assert tokens['access_token'] == 'winner-token'
    helper.refresh_access_token.assert_not_called()


def test_refresh_oidc_tokens_deduplicates_concurrent_refresh_calls():
    helper = MagicMock()
    release = threading.Event()

    def slow_refresh(_refresh_token):
        release.wait(timeout=5)
        return {'access_token': 'fresh-token', 'expires_in': 3600}

    helper.refresh_access_token.side_effect = slow_refresh

    results = []
    barrier = threading.Barrier(2)

    def worker():
        barrier.wait()
        results.append(refresh_oidc_tokens(helper, 'same-token'))

    threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
    for thread in threads:
        thread.start()

    time.sleep(0.05)
    release.set()

    for thread in threads:
        thread.join(timeout=5)

    assert len(results) == 2
    assert all(result['access_token'] == 'fresh-token' for result in results)
    helper.refresh_access_token.assert_called_once_with('same-token')
