"""Helpers for OpenID Connect discovery and login flows."""

import json
import logging
import os
import secrets
import time

import requests

logger = logging.getLogger(__name__)


class OIDCRefreshError(RuntimeError):
    """Custom exception raised when OIDC token refresh fails."""

    def __init__(
        self,
        message,
        is_transient=False,
        status_code=None,
        oauth_error=None,
        oauth_error_description=None,
    ):
        super().__init__(message)
        self.is_transient = is_transient
        self.status_code = status_code
        self.oauth_error = oauth_error
        self.oauth_error_description = oauth_error_description


def _parse_oauth_error_response(response):
    """Return (error, error_description) from an OAuth token error response."""
    if response is None:
        return None, None
    try:
        payload = response.json()
    except ValueError:
        return None, None
    if not isinstance(payload, dict):
        return None, None
    error = payload.get('error')
    description = payload.get('error_description')
    return (
        str(error).strip() if error else None,
        str(description).strip() if description else None,
    )


def _classify_refresh_http_error(status_code, oauth_error):
    """Classify whether an HTTP refresh failure should be retried or ends the session."""
    if status_code is None:
        return True
    if status_code >= 500:
        return True
    if status_code in {401, 403}:
        return False
    if status_code == 400:
        # invalid_grant usually means the refresh token is expired/revoked/reused.
        # Other 400s are often transient provider or client configuration issues.
        if oauth_error in {None, 'invalid_grant'}:
            return False
        return True
    return status_code >= 500


class OIDCHelper:
    """Fetch and cache OIDC metadata, then drive browser-based login."""

    def __init__(self):
        """Load OIDC settings from the environment."""
        self.issuer_url = os.environ.get('OIDC_ISSUER_URL')
        self.client_id = os.environ.get('OIDC_CLIENT_ID')
        self.client_secret = os.environ.get('OIDC_CLIENT_SECRET')
        self.redirect_uri_override = os.environ.get('OIDC_REDIRECT_URI')

        self.scopes = os.environ.get('OIDC_SCOPES', 'openid profile email offline_access')

        # Load extra auth parameters from OIDC_EXTRA_AUTH_PARAMS (JSON string)
        extra_auth_params_raw = os.environ.get('OIDC_EXTRA_AUTH_PARAMS', '{}')
        try:
            self.extra_auth_params = json.loads(extra_auth_params_raw)
            if not isinstance(self.extra_auth_params, dict):
                logger.warning("OIDC_EXTRA_AUTH_PARAMS is not a valid JSON object. Defaulting to empty dict.")
                self.extra_auth_params = {}
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse OIDC_EXTRA_AUTH_PARAMS JSON: %s. Defaulting to empty dict.", exc)
            self.extra_auth_params = {}

        # Load verify SSL toggle (default to True)
        verify_ssl_str = os.environ.get('OIDC_VERIFY_SSL', 'true').lower()
        self.verify_ssl = verify_ssl_str not in ('false', '0', 'no', 'off')

        self._endpoints = None

    @staticmethod
    def _http_timeout():
        """Return (connect, read) timeouts for outbound OIDC HTTP calls."""
        raw = os.environ.get('OIDC_HTTP_TIMEOUT_SECONDS', '30').strip()
        try:
            read_timeout = max(5.0, float(raw))
        except ValueError:
            read_timeout = 30.0
        return (5.0, read_timeout)

    @staticmethod
    def _refresh_max_attempts():
        raw = os.environ.get('OIDC_REFRESH_MAX_ATTEMPTS', '3').strip()
        try:
            return max(1, int(raw))
        except ValueError:
            return 3

    @property
    def is_enabled(self):
        """Returns True if OIDC is configured with all required parameters."""
        return bool(self.issuer_url and self.client_id and self.client_secret)

    def _fetch_discovery(self):
        """Fetches OIDC discovery document and caches it."""
        if self._endpoints is not None:
            return self._endpoints

        if not self.issuer_url:
            raise ValueError("OIDC Issuer URL is not configured.")

        discovery_url = f"{self.issuer_url.rstrip('/')}/.well-known/openid-configuration"
        try:
            logger.info("Fetching OIDC configuration from: %s", discovery_url)
            response = requests.get(
                discovery_url,
                verify=self.verify_ssl,
                timeout=self._http_timeout(),
            )
            response.raise_for_status()
            self._endpoints = response.json()
            return self._endpoints
        except (requests.RequestException, ValueError) as exc:
            logger.error(
                "Failed to fetch OIDC discovery document from %s: %s",
                discovery_url,
                exc,
            )
            raise RuntimeError(f"OIDC configuration error: {exc}") from exc

    def get_authorization_url(self, state, redirect_uri):
        """Constructs the authorization URL to redirect the user to."""
        endpoints = self._fetch_discovery()
        auth_endpoint = endpoints.get('authorization_endpoint')
        if not auth_endpoint:
            raise KeyError("OIDC discovery is missing 'authorization_endpoint'")

        # Use redirect URI override if configured, otherwise use dynamic redirect_uri
        actual_redirect = self.redirect_uri_override or redirect_uri

        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': actual_redirect,
            'scope': self.scopes,
            'state': state
        }

        # Merge extra auth parameters if specified
        if self.extra_auth_params:
            params.update(self.extra_auth_params)

        # Construct full URL with query parameters
        req = requests.models.PreparedRequest()
        req.prepare_url(auth_endpoint, params)
        return req.url

    def exchange_code(self, code, redirect_uri):
        """Exchanges authorization code for access and ID tokens."""
        endpoints = self._fetch_discovery()
        token_endpoint = endpoints.get('token_endpoint')
        if not token_endpoint:
            raise KeyError("OIDC discovery is missing 'token_endpoint'")

        actual_redirect = self.redirect_uri_override or redirect_uri

        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': actual_redirect,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }

        try:
            logger.info("Exchanging code at OIDC token endpoint: %s", token_endpoint)
            response = requests.post(
                token_endpoint,
                data=data,
                verify=self.verify_ssl,
                timeout=self._http_timeout(),
            )
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            logger.error("Failed to exchange OIDC authorization code: %s", exc)
            raise RuntimeError(f"OIDC code exchange failed: {exc}") from exc

    def refresh_access_token(self, refresh_token):
        """Refreshes the access token using a refresh token."""
        endpoints = self._fetch_discovery()
        token_endpoint = endpoints.get('token_endpoint')
        if not token_endpoint:
            raise KeyError("OIDC discovery is missing 'token_endpoint'")

        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }

        max_attempts = self._refresh_max_attempts()
        logger.info("Refreshing OIDC tokens at token endpoint: %s", token_endpoint)

        for attempt in range(1, max_attempts + 1):
            try:
                response = requests.post(
                    token_endpoint,
                    data=data,
                    verify=self.verify_ssl,
                    timeout=self._http_timeout(),
                )
                response.raise_for_status()
                return response.json()
            except requests.HTTPError as exc:
                status_code = exc.response.status_code if exc.response is not None else None
                oauth_error, oauth_error_description = _parse_oauth_error_response(exc.response)
                is_transient = _classify_refresh_http_error(status_code, oauth_error)
                if is_transient and attempt < max_attempts:
                    logger.warning(
                        "OIDC token refresh attempt %s/%s failed with HTTP %s "
                        "(oauth_error=%s); retrying.",
                        attempt,
                        max_attempts,
                        status_code,
                        oauth_error,
                    )
                    time.sleep(1)
                    continue
                log = logger.warning if is_transient else logger.info
                log(
                    "HTTP error during OIDC token refresh (status %s, oauth_error=%s): %s",
                    status_code,
                    oauth_error,
                    exc,
                )
                raise OIDCRefreshError(
                    f"OIDC token refresh failed with HTTP status {status_code}: {exc}",
                    is_transient=is_transient,
                    status_code=status_code,
                    oauth_error=oauth_error,
                    oauth_error_description=oauth_error_description,
                ) from exc
            except requests.RequestException as exc:
                if attempt < max_attempts:
                    logger.warning(
                        "OIDC token refresh attempt %s/%s failed with network error; retrying: %s",
                        attempt,
                        max_attempts,
                        exc,
                    )
                    time.sleep(1)
                    continue
                logger.warning(
                    "Network error during OIDC token refresh after %s attempts: %s",
                    max_attempts,
                    exc,
                )
                raise OIDCRefreshError(
                    f"OIDC token refresh failed due to network error: {exc}",
                    is_transient=True,
                ) from exc
            except ValueError as exc:
                if attempt < max_attempts:
                    logger.warning(
                        "OIDC token refresh attempt %s/%s returned invalid JSON; retrying.",
                        attempt,
                        max_attempts,
                    )
                    time.sleep(1)
                    continue
                logger.warning("Failed to parse OIDC token response after %s attempts: %s", max_attempts, exc)
                raise OIDCRefreshError(
                    f"OIDC token refresh returned invalid response: {exc}",
                    is_transient=True,
                ) from exc

    def get_user_info(self, access_token):
        """Retrieves user profile using access token."""
        endpoints = self._fetch_discovery()
        userinfo_endpoint = endpoints.get('userinfo_endpoint')
        if not userinfo_endpoint:
            raise KeyError("OIDC discovery is missing 'userinfo_endpoint'")

        headers = {
            'Authorization': f'Bearer {access_token}',
        }

        try:
            logger.info("Fetching userinfo from: %s", userinfo_endpoint)
            response = requests.get(
                userinfo_endpoint,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self._http_timeout(),
            )
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            logger.error("Failed to fetch OIDC user info: %s", exc)
            raise RuntimeError(f"OIDC user info retrieval failed: {exc}") from exc

    @staticmethod
    def generate_state():
        """Generates a secure cryptographically random state for CSRF protection."""
        return secrets.token_urlsafe(16)

    @staticmethod
    def _parse_csv_env(name):
        value = os.environ.get(name, '')
        return [item.strip().lower() for item in value.split(',') if item.strip()]

    @staticmethod
    def _normalize_claim_values(raw_value):
        if raw_value is None:
            return []
        if isinstance(raw_value, str):
            values = [raw_value]
        elif isinstance(raw_value, (list, tuple, set)):
            values = list(raw_value)
        else:
            values = [str(raw_value)]
        return [str(value).strip().lower() for value in values if str(value).strip()]

    def is_authorized_admin(self, user_info):
        """Return whether the OIDC identity is allowed to access the admin console."""
        if not user_info:
            return False, 'Missing user information from identity provider'

        allow_any = os.environ.get('OIDC_ALLOW_ANY_AUTHENTICATED', '').strip().lower()
        if allow_any in {'true', '1', 'yes', 'on'}:
            testing = os.environ.get('TESTING', '').strip().lower() in {'true', '1', 'yes', 'on'}
            if not testing:
                logger.error(
                    'OIDC_ALLOW_ANY_AUTHENTICATED is set but refused outside TESTING mode'
                )
                return False, (
                    'OIDC_ALLOW_ANY_AUTHENTICATED is disabled in production. '
                    'Configure ALLOWED_OIDC_ADMINS or related allowlists.'
                )
            logger.warning(
                'OIDC_ALLOW_ANY_AUTHENTICATED is enabled; any authenticated identity may access the admin console'
            )
            return True, ''

        allowed_emails = self._parse_csv_env('ALLOWED_OIDC_ADMINS')
        allowed_domains = self._parse_csv_env('ALLOWED_OIDC_ADMIN_DOMAINS')
        allowed_roles = self._parse_csv_env('ALLOWED_OIDC_ADMIN_ROLES')
        allowed_groups = self._parse_csv_env('ALLOWED_OIDC_ADMIN_GROUPS')

        if not any((allowed_emails, allowed_domains, allowed_roles, allowed_groups)):
            return False, (
                'OIDC admin access is not configured. Set ALLOWED_OIDC_ADMINS, '
                'ALLOWED_OIDC_ADMIN_DOMAINS, ALLOWED_OIDC_ADMIN_ROLES, or ALLOWED_OIDC_ADMIN_GROUPS.'
            )

        email = (user_info.get('email') or '').strip().lower()
        if allowed_emails and email in allowed_emails:
            return True, ''
        if allowed_domains and '@' in email:
            domain = email.rsplit('@', 1)[-1]
            if domain in allowed_domains:
                return True, ''

        role_values = self._normalize_claim_values(
            user_info.get('roles') or user_info.get('role')
        )
        if allowed_roles and any(role in allowed_roles for role in role_values):
            return True, ''

        group_values = self._normalize_claim_values(
            user_info.get('groups') or user_info.get('group')
        )
        if allowed_groups and any(group in allowed_groups for group in group_values):
            return True, ''

        return False, 'You are not authorized to access the admin console.'
