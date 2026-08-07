"""Session expiry helpers for the parent web console."""

from __future__ import annotations

import logging
import os
import time

from src.common.oidc import OIDCRefreshError
from src.auth.oidc_token_refresh import refresh_oidc_tokens

_LOGGER = logging.getLogger(__name__)

WARN_SECONDS_DEFAULT = 300


def session_warn_seconds() -> int:
    raw = os.environ.get('SESSION_WARN_SECONDS')
    if raw is None:
        return WARN_SECONDS_DEFAULT
    try:
        return max(60, int(raw))
    except ValueError:
        return WARN_SECONDS_DEFAULT


def get_oidc_expires_at(session) -> float | None:
    raw = session.get('oidc_token_expires_at')
    if raw is None:
        return None
    return float(raw)


def seconds_until_expiry(session) -> float | None:
    expires_at = get_oidc_expires_at(session)
    if expires_at is None:
        return None
    return expires_at - time.time()


def extend_parent_session(session, oidc_helper) -> tuple[bool, str | None]:
    """Extend an authenticated parent session.

    Returns ``(success, api_message_key)`` where the key is relative to ``api.*``.
    """
    if not session.get('logged_in'):
        return False, 'not_authenticated'

    refresh_token = session.get('oidc_refresh_token')
    if not refresh_token:
        session.modified = True
        return True, None

    try:
        new_tokens = refresh_oidc_tokens(oidc_helper, refresh_token)
        session['oidc_access_token'] = new_tokens.get('access_token')
        if new_tokens.get('refresh_token'):
            session['oidc_refresh_token'] = new_tokens.get('refresh_token')
        session['oidc_token_expires_at'] = time.time() + new_tokens.get('expires_in', 3600)
        session.pop('oidc_refresh_retry_after', None)
        _LOGGER.info('Parent session extended via OIDC token refresh.')
        return True, None
    except OIDCRefreshError as exc:
        if exc.is_transient:
            _LOGGER.warning('Transient OIDC refresh failure during session extend: %s', exc)
            return False, 'session_extend_transient'
        _LOGGER.info(
            'Definitive OIDC refresh failure during session extend '
            '(status=%s, oauth_error=%s): %s',
            exc.status_code,
            exc.oauth_error,
            exc,
        )
        return False, 'session_extend_failed'
    except Exception as exc:
        _LOGGER.warning('Unexpected error during session extend: %s', exc)
        return False, 'session_extend_transient'
