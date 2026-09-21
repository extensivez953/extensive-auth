"""Fleet SSO mode: token mint/verify and the app-side router branch."""
import time

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from extensive_auth import AuthConfig, SsoError, build_auth_router, get_session_email, mint_sso_token, verify_sso_token
from extensive_auth import sso as sso_mod

SECRET = "s" * 48


@pytest.fixture(autouse=True)
def _fresh_jti_cache():
    sso_mod._seen_jti.clear()
    yield
    sso_mod._seen_jti.clear()


def _sso_cfg(**over) -> AuthConfig:
    base = dict(
        google_client_id="id", google_client_secret="secret",
        google_redirect_uri="https://games.example/auth/google/callback",
        session_secret="0" * 64, allowed_emails=set(), cookie_name="games_session",
        cookie_secure=False, sso_url="https://auth.example", sso_secret=SECRET, sso_app="games",
    )
    base.update(over)
    return AuthConfig(**base)


# ── token ───────────────────────────────────────────────────────────────────

def test_mint_and_verify_round_trip():
    tok = mint_sso_token(SECRET, email="Grayson@Example.com", app="games", name="Grayson", role="member")
    claims = verify_sso_token(SECRET, tok, app="games")
    assert claims["email"] == "grayson@example.com"
    assert claims["name"] == "Grayson" and claims["role"] == "member"


def test_verify_rejects_other_app_other_secret_and_replay():
    tok = mint_sso_token(SECRET, email="a@example.com", app="finance")
    with pytest.raises(SsoError, match="not 'games'"):
        verify_sso_token(SECRET, tok, app="games")
    with pytest.raises(SsoError, match="bad signature"):
        verify_sso_token("other" * 10, tok, app="finance")
    verify_sso_token(SECRET, tok, app="finance")
    with pytest.raises(SsoError, match="replayed"):
        verify_sso_token(SECRET, tok, app="finance")


def test_verify_rejects_expired(monkeypatch):
    tok = mint_sso_token(SECRET, email="a@example.com", app="games")
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 120)
    with pytest.raises(SsoError, match="expired"):
        verify_sso_token(SECRET, tok, app="games", max_age=60)


# ── config ──────────────────────────────────────────────────────────────────

def test_from_env_sso_mode_makes_allowlist_optional(monkeypatch):
    for k in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI", "SESSION_SECRET"):
        monkeypatch.setenv(k, "x" * 40)
    monkeypatch.delenv("ALLOWED_EMAILS", raising=False)
    monkeypatch.setenv("SSO_URL", "https://auth.example/")
    monkeypatch.setenv("SSO_SECRET", SECRET)
    monkeypatch.setenv("SSO_APP", "games")
    cfg = AuthConfig.from_env()
    assert cfg.sso_enabled and cfg.sso_url == "https://auth.example"
    assert cfg.is_allowed("anyone@example.com")  # empty allowlist + SSO => trust the grant
    monkeypatch.delenv("SSO_APP")
    with pytest.raises(RuntimeError, match="SSO_APP"):
        AuthConfig.from_env()


def test_wildcard_allowlist():
    cfg = _sso_cfg(sso_url="", allowed_emails={"*"})
    assert cfg.is_allowed("whoever@example.com")
    assert not cfg.is_allowed("")


# ── router ──────────────────────────────────────────────────────────────────

def _app(cfg: AuthConfig) -> TestClient:
    app = FastAPI()
    app.include_router(build_auth_router(cfg))

    @app.get("/whoami")
    def whoami(request: Request):
        return {"email": get_session_email(cfg, request)}

    return TestClient(app, base_url="https://games.example", follow_redirects=False)


def test_start_bounces_to_sso_with_state_and_return():
    cfg = _sso_cfg()
    client = _app(cfg)
    r = client.get("/auth/google/start")
    assert r.status_code == 307 or r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith("https://auth.example/authorize?")
    assert "app=games" in loc and "return=https%3A%2F%2Fgames.example%2Fauth%2Fsso%2Fcallback" in loc
    assert "extensive_oauth_state" in r.cookies


def test_sso_callback_opens_session_and_rejects_bad_state():
    cfg = _sso_cfg()
    client = _app(cfg)
    r = client.get("/auth/google/start")
    state = r.headers["location"].split("state=")[1].split("&")[0]
    tok = mint_sso_token(SECRET, email="grayson@example.com", app="games", name="Grayson")
    # wrong state: refused
    bad = client.get("/auth/sso/callback", params={"token": tok, "state": "nope"})
    assert bad.status_code == 400
    ok = client.get("/auth/sso/callback", params={"token": tok, "state": state})
    assert ok.status_code == 302 and ok.headers["location"] == "/"
    assert cfg.cookie_name in ok.cookies
    # the cookie is a live session
    assert client.get("/whoami").json() == {"email": "grayson@example.com"}


def test_sso_callback_honours_local_allowlist():
    cfg = _sso_cfg(allowed_emails={"mike@example.com"})
    client = _app(cfg)
    state = client.get("/auth/google/start").headers["location"].split("state=")[1].split("&")[0]
    tok = mint_sso_token(SECRET, email="grayson@example.com", app="games")
    r = client.get("/auth/sso/callback", params={"token": tok, "state": state})
    assert r.status_code == 403


def test_sso_callback_404_when_not_in_sso_mode():
    cfg = _sso_cfg(sso_url="", allowed_emails={"mike@example.com"})
    client = _app(cfg)
    assert client.get("/auth/sso/callback", params={"token": "x", "state": "y"}).status_code == 404


def test_logout_in_sso_mode_signs_out_everywhere_and_flags_signed_out():
    cfg = _sso_cfg()
    client = _app(cfg)
    r = client.get("/auth/logout")
    assert r.status_code == 302
    assert r.headers["location"] == "https://auth.example/logout?return=https%3A%2F%2Fgames.example%2Flogin%3Fsigned_out%3D1"
    plain = _app(_sso_cfg(sso_url="", allowed_emails={"a@example.com"}))
    assert plain.get("/auth/logout").headers["location"] == "/login"


def test_sso_auto_login_only_for_browsers_and_not_after_signout():
    from starlette.requests import Request as SRequest
    from extensive_auth import sso_auto_login

    def req(headers: dict, query: str = ""):
        scope = {"type": "http", "method": "GET", "path": "/login", "query_string": query.encode(),
                 "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]}
        return SRequest(scope)

    cfg = _sso_cfg(root_path="/games")
    browser = {"sec-fetch-dest": "document", "sec-fetch-mode": "navigate", "user-agent": "Mozilla/5.0", "accept": "text/html"}
    r = sso_auto_login(cfg, req(browser))
    assert r is not None and r.headers["location"] == "/games/auth/google/start"
    old_browser = {"user-agent": "Mozilla/5.0 (Android)", "accept": "text/html,*/*"}
    assert sso_auto_login(cfg, req(old_browser)) is not None
    monitor = {"user-agent": "python-httpx/0.27", "accept": "*/*"}
    assert sso_auto_login(cfg, req(monitor)) is None
    assert sso_auto_login(cfg, req(browser, "signed_out=1")) is None
    assert sso_auto_login(_sso_cfg(sso_url="", allowed_emails={"a@example.com"}), req(browser)) is None
