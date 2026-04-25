"""Shared fixtures for extensive-auth tests."""
import pytest

from extensive_auth import AuthConfig


@pytest.fixture()
def cfg() -> AuthConfig:
    """A minimal AuthConfig wired with sensible test defaults."""
    return AuthConfig(
        google_client_id="test-client-id",
        google_client_secret="test-secret",
        google_redirect_uri="http://testserver/auth/google/callback",
        session_secret="0" * 64,
        allowed_emails={"alice@example.com", "bob@example.com"},
        api_key="test-api-key",
        cookie_name="test_session",
        session_salt="test-salt",
        cookie_secure=False,
    )
