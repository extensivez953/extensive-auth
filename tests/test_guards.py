"""require_user / require_user_or_api_key dependency-style guards."""
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from extensive_auth import (
    create_session,
    require_user,
    require_user_or_api_key,
)


def _request(cfg, *, cookie: str | None = None, api_key: str | None = None) -> MagicMock:
    req = MagicMock()
    req.cookies = {cfg.cookie_name: cookie} if cookie else {}
    req.headers = {"X-Api-Key": api_key} if api_key else {}
    return req


# ---------------------------------------------------------------------------
# require_user — session-only path
# ---------------------------------------------------------------------------


def test_require_user_accepts_valid_session(cfg):
    cookie = create_session(cfg, email="alice@example.com", picture="pic")
    user = require_user(cfg)(_request(cfg, cookie=cookie))
    assert user["email"] == "alice@example.com"
    assert user["picture"] == "pic"
    assert user["auth_method"] == "session"


def test_require_user_rejects_no_cookie(cfg):
    with pytest.raises(HTTPException) as exc:
        require_user(cfg)(_request(cfg))
    assert exc.value.status_code == 403


def test_require_user_rejects_garbage_cookie(cfg):
    with pytest.raises(HTTPException) as exc:
        require_user(cfg)(_request(cfg, cookie="garbage"))
    assert exc.value.status_code == 403


def test_require_user_ignores_api_key(cfg):
    """require_user should NOT accept an API key — that's the other guard's job."""
    with pytest.raises(HTTPException):
        require_user(cfg)(_request(cfg, api_key="test-api-key"))


# ---------------------------------------------------------------------------
# require_user_or_api_key — dual auth path
# ---------------------------------------------------------------------------


def test_dual_guard_accepts_session(cfg):
    cookie = create_session(cfg, email="alice@example.com")
    user = require_user_or_api_key(cfg)(_request(cfg, cookie=cookie))
    assert user["email"] == "alice@example.com"
    assert user["auth_method"] == "session"


def test_dual_guard_accepts_matching_api_key(cfg):
    user = require_user_or_api_key(cfg)(_request(cfg, api_key="test-api-key"))
    assert user["auth_method"] == "api_key"
    assert user["email"] == "<api-key>"


def test_dual_guard_rejects_wrong_api_key(cfg):
    with pytest.raises(HTTPException):
        require_user_or_api_key(cfg)(_request(cfg, api_key="not-the-key"))


def test_dual_guard_rejects_no_credentials(cfg):
    with pytest.raises(HTTPException) as exc:
        require_user_or_api_key(cfg)(_request(cfg))
    assert exc.value.status_code == 403


def test_dual_guard_disables_api_key_when_unconfigured(cfg):
    """If the config has no api_key set, ANY X-Api-Key header must fail."""
    cfg.api_key = ""
    with pytest.raises(HTTPException):
        require_user_or_api_key(cfg)(_request(cfg, api_key="anything"))


def test_dual_guard_session_wins_over_api_key(cfg):
    """When both are present and valid, the session path is preferred."""
    cookie = create_session(cfg, email="alice@example.com")
    user = require_user_or_api_key(cfg)(
        _request(cfg, cookie=cookie, api_key="test-api-key"),
    )
    assert user["auth_method"] == "session"
