"""Cookie session round-trip + expiry + state-token logic."""
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from itsdangerous import URLSafeSerializer

from extensive_auth import (
    AuthConfig,
    create_session,
    delete_session,
    get_session_email,
    get_session_picture,
)
from extensive_auth.session import (
    consume_oauth_state,
    store_oauth_state,
)


def _request_with_cookie(cfg: AuthConfig, value: str | None) -> MagicMock:
    """Build a minimal fastapi.Request stand-in carrying one cookie."""
    req = MagicMock()
    req.cookies = {cfg.cookie_name: value} if value is not None else {}
    return req


# ---------------------------------------------------------------------------
# create / get round-trip
# ---------------------------------------------------------------------------


def test_create_session_and_read_email(cfg):
    cookie = create_session(cfg, email="alice@example.com", picture="http://pic")
    req = _request_with_cookie(cfg, cookie)
    assert get_session_email(cfg, req) == "alice@example.com"
    assert get_session_picture(cfg, req) == "http://pic"


def test_get_email_returns_none_when_no_cookie(cfg):
    req = _request_with_cookie(cfg, None)
    assert get_session_email(cfg, req) is None


def test_get_email_returns_none_for_garbage_cookie(cfg):
    req = _request_with_cookie(cfg, "not-a-signed-token")
    assert get_session_email(cfg, req) is None


def test_get_email_returns_none_for_cookie_signed_by_other_secret(cfg):
    other = URLSafeSerializer("different-secret", salt=cfg.session_salt)
    forged = other.dumps("attacker-controlled-sid")
    req = _request_with_cookie(cfg, forged)
    assert get_session_email(cfg, req) is None


def test_picture_empty_when_session_missing_picture(cfg):
    cookie = create_session(cfg, email="alice@example.com")  # no picture
    req = _request_with_cookie(cfg, cookie)
    assert get_session_picture(cfg, req) == ""


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


def test_expired_session_returns_none_and_evicts(cfg):
    cookie = create_session(cfg, email="alice@example.com")
    # Reach into the store and rewind the expiry to an hour ago.
    serializer = URLSafeSerializer(cfg.session_secret, salt=cfg.session_salt)
    sid = serializer.loads(cookie)
    assert sid in cfg._sessions
    cfg._sessions[sid]["expires_at"] = cfg._sessions[sid]["expires_at"] - timedelta(days=30)

    req = _request_with_cookie(cfg, cookie)
    assert get_session_email(cfg, req) is None
    assert sid not in cfg._sessions  # evicted on read


# ---------------------------------------------------------------------------
# delete_session
# ---------------------------------------------------------------------------


def test_delete_session_removes_record(cfg):
    cookie = create_session(cfg, email="alice@example.com")
    req = _request_with_cookie(cfg, cookie)
    assert get_session_email(cfg, req) == "alice@example.com"

    delete_session(cfg, req)
    assert get_session_email(cfg, req) is None


def test_delete_session_without_cookie_is_noop(cfg):
    req = _request_with_cookie(cfg, None)
    delete_session(cfg, req)  # must not raise


# ---------------------------------------------------------------------------
# OAuth state tokens
# ---------------------------------------------------------------------------


def test_oauth_state_round_trip(cfg):
    store_oauth_state(cfg, "abc123")
    assert consume_oauth_state(cfg, "abc123") is True


def test_oauth_state_is_single_use(cfg):
    store_oauth_state(cfg, "abc123")
    assert consume_oauth_state(cfg, "abc123") is True
    # Second consume must fail — state is one-shot.
    assert consume_oauth_state(cfg, "abc123") is False


def test_oauth_state_rejects_unknown(cfg):
    assert consume_oauth_state(cfg, "never-stored") is False


def test_oauth_state_rejects_expired(cfg):
    store_oauth_state(cfg, "abc123", ttl_minutes=10)
    cfg._sessions["_oauth_state:abc123"]["expires_at"] = (
        cfg._sessions["_oauth_state:abc123"]["expires_at"] - timedelta(hours=1)
    )
    assert consume_oauth_state(cfg, "abc123") is False
