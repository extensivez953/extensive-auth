"""AuthConfig construction + env-var parsing."""
import os

import pytest

from extensive_auth import AuthConfig


# ---------------------------------------------------------------------------
# Direct construction
# ---------------------------------------------------------------------------


def test_direct_construction_minimal(cfg):
    assert cfg.google_client_id == "test-client-id"
    assert cfg.allowed_emails == {"alice@example.com", "bob@example.com"}
    assert cfg.api_key == "test-api-key"


def test_is_allowed_normalises_case(cfg):
    assert cfg.is_allowed("ALICE@example.com") is True
    assert cfg.is_allowed("  alice@example.com  ") is True


def test_is_allowed_rejects_unknown(cfg):
    assert cfg.is_allowed("eve@example.com") is False
    assert cfg.is_allowed("") is False


# ---------------------------------------------------------------------------
# from_env() — required vars
# ---------------------------------------------------------------------------


_REQUIRED = (
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GOOGLE_REDIRECT_URI",
    "SESSION_SECRET",
    "ALLOWED_EMAILS",
)


def _set_required(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "id")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://localhost/cb")
    monkeypatch.setenv("SESSION_SECRET", "x" * 64)
    monkeypatch.setenv("ALLOWED_EMAILS", "alice@example.com,bob@example.com")


def test_from_env_minimum(monkeypatch):
    _set_required(monkeypatch)
    cfg = AuthConfig.from_env()
    assert cfg.google_client_id == "id"
    assert cfg.allowed_emails == {"alice@example.com", "bob@example.com"}
    assert cfg.api_key == ""
    assert cfg.cookie_name == "extensive_session"  # default


@pytest.mark.parametrize("missing_var", _REQUIRED)
def test_from_env_raises_on_missing_required(monkeypatch, missing_var):
    _set_required(monkeypatch)
    monkeypatch.delenv(missing_var, raising=False)
    with pytest.raises(RuntimeError, match=missing_var):
        AuthConfig.from_env()


def test_from_env_uses_prefix(monkeypatch):
    monkeypatch.setenv("LPC_GOOGLE_CLIENT_ID", "id")
    monkeypatch.setenv("LPC_GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("LPC_GOOGLE_REDIRECT_URI", "http://localhost/cb")
    monkeypatch.setenv("LPC_SESSION_SECRET", "x" * 64)
    monkeypatch.setenv("LPC_ALLOWED_EMAILS", "tina@example.com")
    cfg = AuthConfig.from_env(prefix="LPC_")
    assert cfg.allowed_emails == {"tina@example.com"}


def test_from_env_allowlist_strips_whitespace_and_lowercases(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("ALLOWED_EMAILS", "  Alice@Example.com ,, BOB@example.com  ,")
    cfg = AuthConfig.from_env()
    assert cfg.allowed_emails == {"alice@example.com", "bob@example.com"}


def test_from_env_optional_overrides(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("API_KEY", "secret-key")
    monkeypatch.setenv("COOKIE_NAME", "lpc_session")
    monkeypatch.setenv("SESSION_SALT", "lpc-salt")
    monkeypatch.setenv("SESSION_TTL_DAYS", "30")
    monkeypatch.setenv("ROOT_PATH", "/lpc")
    monkeypatch.setenv("COOKIE_SECURE", "false")

    cfg = AuthConfig.from_env()
    assert cfg.api_key == "secret-key"
    assert cfg.cookie_name == "lpc_session"
    assert cfg.session_salt == "lpc-salt"
    assert cfg.session_ttl.days == 30
    assert cfg.root_path == "/lpc"
    assert cfg.cookie_secure is False


def test_from_env_invalid_ttl_days_raises(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("SESSION_TTL_DAYS", "not-a-number")
    with pytest.raises(RuntimeError, match="SESSION_TTL_DAYS"):
        AuthConfig.from_env()


def test_from_env_root_path_strips_trailing_slash(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("ROOT_PATH", "/lpc/")
    cfg = AuthConfig.from_env()
    assert cfg.root_path == "/lpc"
