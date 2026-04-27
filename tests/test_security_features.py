"""Tests for the security additions: CSP middleware, rate-limit, CSRF helpers.

OAuth state-cookie binding is exercised indirectly in router-level tests; the
unit slice here covers the building blocks.
"""
import time
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from extensive_auth import (
    build_security_headers_middleware,
    check_csrf,
    create_session,
    new_csrf,
)
from extensive_auth.rate_limit import (
    RateLimitState,
    is_rate_limited,
    record_attempt,
    reset,
)


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------


def _app_with_security_middleware(**kwargs) -> TestClient:
    app = FastAPI()
    app.add_middleware(build_security_headers_middleware(**kwargs))

    @app.get("/")
    def root():
        return {"ok": True}

    @app.get("/healthz")
    def health():
        return "ok"

    return TestClient(app)


def test_security_headers_default_set():
    client = _app_with_security_middleware()
    resp = client.get("/")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_security_headers_csp_overrides_replace_only_named_directive():
    client = _app_with_security_middleware(
        csp_overrides={"script-src": "'self' https://cdn.jsdelivr.net"},
    )
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "script-src 'self' https://cdn.jsdelivr.net" in csp
    # Other directives untouched.
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_security_headers_exempt_paths_skipped():
    client = _app_with_security_middleware(exempt_paths=["/healthz"])
    resp = client.get("/healthz")
    assert "Content-Security-Policy" not in resp.headers
    # Non-exempt routes still get headers.
    resp = client.get("/")
    assert "Content-Security-Policy" in resp.headers


# ---------------------------------------------------------------------------
# Rate-limit
# ---------------------------------------------------------------------------


def test_rate_limit_locks_out_after_threshold():
    state = RateLimitState(max_attempts=3, window_seconds=60, lockout_seconds=300)
    for _ in range(3):
        record_attempt(state, "1.2.3.4")
    assert is_rate_limited(state, "1.2.3.4") is True


def test_rate_limit_independent_per_ip():
    state = RateLimitState(max_attempts=2)
    record_attempt(state, "10.0.0.1")
    record_attempt(state, "10.0.0.1")
    assert is_rate_limited(state, "10.0.0.1") is True
    assert is_rate_limited(state, "10.0.0.2") is False


def test_rate_limit_window_expires():
    state = RateLimitState(max_attempts=2, window_seconds=1, lockout_seconds=1)
    record_attempt(state, "5.5.5.5")
    record_attempt(state, "5.5.5.5")
    assert is_rate_limited(state, "5.5.5.5") is True
    time.sleep(1.2)
    # Lockout window has passed; old attempts are out of the sliding window.
    assert is_rate_limited(state, "5.5.5.5") is False


def test_rate_limit_reset_clears_state():
    state = RateLimitState(max_attempts=1)
    record_attempt(state, "9.9.9.9")
    assert is_rate_limited(state, "9.9.9.9") is True
    reset(state)
    assert is_rate_limited(state, "9.9.9.9") is False


# ---------------------------------------------------------------------------
# CSRF helpers
# ---------------------------------------------------------------------------


def _request(cfg, cookie: str | None = None) -> MagicMock:
    req = MagicMock()
    req.cookies = {cfg.cookie_name: cookie} if cookie else {}
    req.headers = {}
    return req


def test_csrf_token_round_trip(cfg):
    cookie = create_session(cfg, email="alice@example.com")
    request = _request(cfg, cookie=cookie)
    token = new_csrf(cfg, request)
    # No exception = valid.
    check_csrf(cfg, request, token)


def test_csrf_rejects_token_from_different_session(cfg):
    cookie_a = create_session(cfg, email="alice@example.com")
    cookie_b = create_session(cfg, email="bob@example.com")
    token = new_csrf(cfg, _request(cfg, cookie=cookie_a))
    with pytest.raises(HTTPException) as exc:
        check_csrf(cfg, _request(cfg, cookie=cookie_b), token)
    assert exc.value.status_code == 403
    assert "Invalid" in exc.value.detail


def test_csrf_rejects_malformed_token(cfg):
    request = _request(cfg)
    for bad in ("", "garbage", "no-dot", "12345", ".", "abc.def"):
        with pytest.raises(HTTPException):
            check_csrf(cfg, request, bad)


def test_csrf_rejects_expired_token(cfg):
    cookie = create_session(cfg, email="alice@example.com")
    request = _request(cfg, cookie=cookie)
    token = new_csrf(cfg, request)
    with pytest.raises(HTTPException) as exc:
        check_csrf(cfg, request, token, ttl_seconds=0)
    assert exc.value.status_code == 403
    assert "expired" in exc.value.detail.lower()


def test_csrf_token_anonymous_request_round_trip(cfg):
    """Login pages render forms before the user has a session — token still works."""
    request = _request(cfg)
    token = new_csrf(cfg, request)
    check_csrf(cfg, request, token)
