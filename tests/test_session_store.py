"""SESSION_STORE_PATH: sessions survive a "restart" (a fresh AuthConfig over the same file)."""
from datetime import timedelta
from unittest.mock import MagicMock

from extensive_auth import AuthConfig, create_session, delete_session, get_session_email, get_session_name
from extensive_auth.session import consume_oauth_state, store_oauth_state


def _cfg(path: str) -> AuthConfig:
    return AuthConfig(google_client_id="id", google_client_secret="s", google_redirect_uri="http://t/cb",
                      session_secret="0" * 64, allowed_emails={"alice@example.com"}, cookie_name="t",
                      cookie_secure=False, session_store_path=path)


def _req(cfg, cookie):
    r = MagicMock(); r.cookies = {cfg.cookie_name: cookie}; return r


def test_sessions_and_states_survive_a_new_config_over_the_same_file(tmp_path):
    path = str(tmp_path / "sessions.db")
    cfg1 = _cfg(path)
    cookie = create_session(cfg1, email="alice@example.com", name="Alice", picture="p")
    store_oauth_state(cfg1, "abc")

    cfg2 = _cfg(path)  # "after the rebuild"
    assert get_session_email(cfg2, _req(cfg2, cookie)) == "alice@example.com"
    assert get_session_name(cfg2, _req(cfg2, cookie)) == "Alice"
    assert consume_oauth_state(cfg2, "abc") is True
    assert consume_oauth_state(cfg2, "abc") is False  # single use
    delete_session(cfg2, _req(cfg2, cookie))
    assert get_session_email(_cfg(path), _req(cfg2, cookie)) is None


def test_expired_sqlite_session_is_evicted(tmp_path):
    path = str(tmp_path / "sessions.db")
    cfg = _cfg(path)
    cfg.session_ttl = timedelta(seconds=-1)
    cookie = create_session(cfg, email="alice@example.com")
    assert get_session_email(cfg, _req(cfg, cookie)) is None


def test_from_env_reads_session_store_path(monkeypatch, tmp_path):
    for k in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI", "SESSION_SECRET"):
        monkeypatch.setenv(k, "x" * 40)
    monkeypatch.setenv("ALLOWED_EMAILS", "a@example.com")
    monkeypatch.setenv("SESSION_STORE_PATH", str(tmp_path / "s.db"))
    assert AuthConfig.from_env().session_store_path.endswith("s.db")
