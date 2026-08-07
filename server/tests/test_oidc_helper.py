"""Tests for the OIDC helper wrapper around discovery and token exchange."""

# pylint: disable=protected-access

from unittest.mock import MagicMock, patch

import pytest
import requests

from src.common.oidc import OIDCHelper

def test_oidc_disabled():
    helper = OIDCHelper()
    assert not helper.is_enabled

    # If issuer_url is missing, discovery should raise ValueError
    with pytest.raises(ValueError, match="OIDC Issuer URL is not configured"):
        helper._fetch_discovery()

def test_oidc_enabled():
    with patch.dict('os.environ', {
        'OIDC_ISSUER_URL': 'https://auth.example.com',
        'OIDC_CLIENT_ID': 'my-client-id',
        'OIDC_CLIENT_SECRET': 'my-client-secret',
        'OIDC_VERIFY_SSL': 'false'
    }):
        helper = OIDCHelper()
        assert helper.is_enabled
        assert not helper.verify_ssl

def test_fetch_discovery_cached():
    helper = OIDCHelper()
    helper._endpoints = {'authorization_endpoint': 'https://auth.com/login'}
    assert helper._fetch_discovery() == {'authorization_endpoint': 'https://auth.com/login'}

@patch('requests.get')
def test_fetch_discovery_success(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        'authorization_endpoint': 'https://auth.com/login',
        'token_endpoint': 'https://auth.com/token',
        'userinfo_endpoint': 'https://auth.com/userinfo'
    }
    mock_response.raise_for_status.return_value = None
    mock_get.return_value = mock_response

    helper = OIDCHelper()
    helper.issuer_url = "https://auth.com"
    
    endpoints = helper._fetch_discovery()
    assert endpoints['authorization_endpoint'] == 'https://auth.com/login'
    mock_get.assert_called_once_with(
        "https://auth.com/.well-known/openid-configuration",
        verify=True,
        timeout=(5.0, 30.0),
    )

@patch('requests.get')
def test_fetch_discovery_failure(mock_get):
    mock_get.side_effect = requests.RequestException("Network Connection Refused")

    helper = OIDCHelper()
    helper.issuer_url = "https://auth.com"

    with pytest.raises(RuntimeError, match="OIDC configuration error"):
        helper._fetch_discovery()

def test_get_authorization_url():
    helper = OIDCHelper()
    helper.issuer_url = "https://auth.com"
    helper._endpoints = {'authorization_endpoint': 'https://auth.com/login'}
    helper.client_id = "test-id"

    # Dynamic redirect
    url = helper.get_authorization_url("state-xyz", "http://app.com/callback")
    assert "https://auth.com/login" in url
    assert "client_id=test-id" in url
    assert "state=state-xyz" in url
    assert "redirect_uri=http%3A%2F%2Fapp.com%2Fcallback" in url

    # Redirect override
    helper.redirect_uri_override = "http://override.com"
    url_override = helper.get_authorization_url("state-xyz", "http://app.com/callback")
    assert "redirect_uri=http%3A%2F%2Foverride.com" in url_override

    # Missing authorization endpoint
    helper._endpoints = {}
    with pytest.raises(KeyError, match="authorization_endpoint"):
        helper.get_authorization_url("state-xyz", "http://app.com/callback")

@patch('requests.post')
def test_exchange_code(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {'access_token': 'token-123'}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    helper = OIDCHelper()
    helper.issuer_url = "https://auth.com"
    helper._endpoints = {'token_endpoint': 'https://auth.com/token'}
    helper.client_id = "test-client"
    helper.client_secret = "test-secret"

    tokens = helper.exchange_code("auth-code-val", "http://app.com/callback")
    assert tokens['access_token'] == 'token-123'
    mock_post.assert_called_once()

    # Missing token endpoint
    helper._endpoints = {}
    with pytest.raises(KeyError, match="token_endpoint"):
        helper.exchange_code("code", "redirect")

    # Post failure
    helper._endpoints = {'token_endpoint': 'https://auth.com/token'}
    mock_post.side_effect = requests.RequestException("Token server offline")
    with pytest.raises(RuntimeError, match="OIDC code exchange failed"):
        helper.exchange_code("code", "redirect")

@patch('requests.get')
def test_get_user_info(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = {'sub': 'user-123', 'name': 'John Doe'}
    mock_response.raise_for_status.return_value = None
    mock_get.return_value = mock_response

    helper = OIDCHelper()
    helper.issuer_url = "https://auth.com"
    helper._endpoints = {'userinfo_endpoint': 'https://auth.com/userinfo'}

    info = helper.get_user_info("access-token-xyz")
    assert info['name'] == 'John Doe'
    mock_get.assert_called_once_with(
        'https://auth.com/userinfo',
        headers={'Authorization': 'Bearer access-token-xyz'},
        verify=True,
        timeout=(5.0, 30.0),
    )

    # Missing userinfo endpoint
    helper._endpoints = {}
    with pytest.raises(KeyError, match="userinfo_endpoint"):
        helper.get_user_info("access-token")

    # Get failure
    helper._endpoints = {'userinfo_endpoint': 'https://auth.com/userinfo'}
    mock_get.side_effect = requests.RequestException("Userinfo server error")
    with pytest.raises(RuntimeError, match="OIDC user info retrieval failed"):
        helper.get_user_info("access-token")

def test_is_authorized_admin_requires_configuration():
    helper = OIDCHelper()
    allowed, message = helper.is_authorized_admin({'email': 'child@school.edu'})
    assert not allowed
    assert 'not configured' in message.lower()


def test_is_authorized_admin_accepts_whitelisted_email():
    with patch.dict('os.environ', {'ALLOWED_OIDC_ADMINS': 'parent@example.com'}):
        helper = OIDCHelper()
        allowed, message = helper.is_authorized_admin({'email': 'parent@example.com'})
        assert allowed
        assert message == ''


def test_is_authorized_admin_accepts_matching_domain():
    with patch.dict('os.environ', {'ALLOWED_OIDC_ADMIN_DOMAINS': 'example.com'}):
        helper = OIDCHelper()
        allowed, _ = helper.is_authorized_admin({'email': 'admin@example.com'})
        assert allowed


def test_is_authorized_admin_accepts_matching_role_claim():
    with patch.dict('os.environ', {'ALLOWED_OIDC_ADMIN_ROLES': 'admin'}):
        helper = OIDCHelper()
        allowed, _ = helper.is_authorized_admin({'roles': ['viewer', 'admin']})
        assert allowed


def test_generate_state():
    state1 = OIDCHelper.generate_state()
    state2 = OIDCHelper.generate_state()
    assert len(state1) > 10
    assert state1 != state2


def test_oidc_helper_custom_scopes_and_params():
    with patch.dict('os.environ', {
        'OIDC_SCOPES': 'openid profile custom-scope',
        'OIDC_EXTRA_AUTH_PARAMS': '{"access_type": "offline", "prompt": "consent"}'
    }):
        helper = OIDCHelper()
        helper.issuer_url = "https://auth.com"
        helper.client_id = "test-client"
        helper._endpoints = {'authorization_endpoint': 'https://auth.com/login'}

        url = helper.get_authorization_url("state-xyz", "http://app.com/callback")
        assert "scope=openid+profile+custom-scope" in url
        assert "access_type=offline" in url
        assert "prompt=consent" in url


@patch('requests.post')
def test_refresh_access_token_success(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        'access_token': 'new-access-token',
        'refresh_token': 'new-refresh-token',
        'expires_in': 1800
    }
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    helper = OIDCHelper()
    helper.issuer_url = "https://auth.com"
    helper._endpoints = {'token_endpoint': 'https://auth.com/token'}
    helper.client_id = "test-client"
    helper.client_secret = "test-secret"

    tokens = helper.refresh_access_token("old-refresh-token")
    assert tokens['access_token'] == 'new-access-token'
    assert tokens['refresh_token'] == 'new-refresh-token'
    assert tokens['expires_in'] == 1800
    mock_post.assert_called_once()


@patch('requests.post')
def test_refresh_access_token_http_errors(mock_post):
    from src.common.oidc import OIDCRefreshError

    helper = OIDCHelper()
    helper.issuer_url = "https://auth.com"
    helper._endpoints = {'token_endpoint': 'https://auth.com/token'}
    helper.client_id = "test-client"
    helper.client_secret = "test-secret"

    # Test definitive HTTP 400 error (e.g. invalid grant/revoked token)
    mock_response_400 = MagicMock()
    mock_response_400.status_code = 400
    mock_response_400.json.return_value = {
        'error': 'invalid_grant',
        'error_description': 'Refresh token has expired',
    }
    http_error_400 = requests.HTTPError("Bad Request", response=mock_response_400)
    mock_post.side_effect = http_error_400

    with pytest.raises(OIDCRefreshError) as exc_info:
        helper.refresh_access_token("revoked-token")
    assert not exc_info.value.is_transient
    assert exc_info.value.status_code == 400
    assert exc_info.value.oauth_error == 'invalid_grant'

    # Test transient HTTP 400 error for provider/client configuration issues
    mock_response_400_client = MagicMock()
    mock_response_400_client.status_code = 400
    mock_response_400_client.json.return_value = {
        'error': 'invalid_client',
        'error_description': 'Client authentication failed',
    }
    http_error_400_client = requests.HTTPError("Bad Request", response=mock_response_400_client)
    mock_post.side_effect = http_error_400_client

    with pytest.raises(OIDCRefreshError) as exc_info:
        helper.refresh_access_token("any-token")
    assert exc_info.value.is_transient
    assert exc_info.value.status_code == 400
    assert exc_info.value.oauth_error == 'invalid_client'

    # Test transient HTTP 503 error
    mock_response_503 = MagicMock()
    mock_response_503.status_code = 503
    mock_response_503.json.return_value = {}
    http_error_503 = requests.HTTPError("Service Unavailable", response=mock_response_503)
    mock_post.side_effect = http_error_503

    with pytest.raises(OIDCRefreshError) as exc_info:
        helper.refresh_access_token("any-token")
    assert exc_info.value.is_transient
    assert exc_info.value.status_code == 503


@patch('requests.post')
def test_refresh_access_token_network_errors(mock_post):
    from src.common.oidc import OIDCRefreshError

    helper = OIDCHelper()
    helper.issuer_url = "https://auth.com"
    helper._endpoints = {'token_endpoint': 'https://auth.com/token'}
    helper.client_id = "test-client"
    helper.client_secret = "test-secret"

    # Test connection network error retries then fails
    mock_post.side_effect = requests.RequestException("Connection timed out")

    with pytest.raises(OIDCRefreshError) as exc_info:
        helper.refresh_access_token("any-token")
    assert exc_info.value.is_transient
    assert mock_post.call_count == 3


@patch('time.sleep')
@patch('requests.post')
def test_refresh_access_token_retries_transient_http_error(mock_post, _mock_sleep):
    from src.common.oidc import OIDCRefreshError

    helper = OIDCHelper()
    helper.issuer_url = "https://auth.com"
    helper._endpoints = {'token_endpoint': 'https://auth.com/token'}
    helper.client_id = "test-client"
    helper.client_secret = "test-secret"

    mock_response_503 = MagicMock()
    mock_response_503.status_code = 503
    http_error_503 = requests.HTTPError("Service Unavailable", response=mock_response_503)

    success_response = MagicMock()
    success_response.raise_for_status.return_value = None
    success_response.json.return_value = {'access_token': 'new-token', 'expires_in': 3600}
    mock_post.side_effect = [http_error_503, success_response]

    tokens = helper.refresh_access_token("any-token")
    assert tokens['access_token'] == 'new-token'
    assert mock_post.call_count == 2

