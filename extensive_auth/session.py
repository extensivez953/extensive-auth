"""Cookie-based session management.

The cookie value is the signed (itsdangerous URLSafeSerializer) session id.
Records live in a **store** chosen per AuthConfig:

- the default is a process-local dict (``cfg._sessions``) — fine for a
  single-worker uvicorn app, but a rebuild forgets every session;
- set ``session_store_path`` (env ``SESSION_STORE_PATH``, e.g.
  ``/data/extensive-sso-sessions.db``) and records live in a tiny SQLite
  table instead, so they survive restarts and redeploys. The fleet SSO uses
  this: without it every SSO rebuild put the Google chooser back in front of
  everyone.

Multi-worker setups can share the SQLite store; the public API is the same.
"""
import json
import logging
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Request
from itsdangerous import BadSignature, URLSafeSerializer

from extensive_auth.config import AuthConfig

log = logging.getLogger("extensive_auth")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _serializer(cfg: AuthConfig) -> URLSafeSerializer:
    return URLSafeSerializer(cfg.session_secret, salt=cfg.session_salt)


# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------


class _MemoryStore:
    """Wraps cfg._sessions so tests (and old code) can still reach into the dict."""

    def __init__(self, d: dict) -> None:
        self._d = d

    def get(self, key: str) -> dict | None:
        return self._d.get(key)

    def put(self, key: str, record: dict) -> None:
        self._d[key] = record

    def delete(self, key: str) -> None:
        self._d.pop(key, None)


class _SqliteStore:
    """One table, records as JSON, expiry as an epoch column for cheap pruning."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("PRAGMA journal_mode = WAL")
            c.execute("CREATE TABLE IF NOT EXISTS sessions (key TEXT PRIMARY KEY, record TEXT NOT NULL, expires_at REAL NOT NULL)")
        self._last_prune = 0.0

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def get(self, key: str) -> dict | None:
        with self._lock, self._conn() as c:
            row = c.execute("SELECT record, expires_at FROM sessions WHERE key = ?", (key,)).fetchone()
        if not row:
            return None
        record = json.loads(row[0])
        record["expires_at"] = datetime.fromtimestamp(row[1], tz=timezone.utc)
        return record

    def put(self, key: str, record: dict) -> None:
        exp: datetime = record["expires_at"]
        body = {k: v for k, v in record.items() if k != "expires_at"}
        with self._lock, self._conn() as c:
            c.execute("INSERT OR REPLACE INTO sessions (key, record, expires_at) VALUES (?, ?, ?)",
                      (key, json.dumps(body), exp.timestamp()))
            if time.time() - self._last_prune > 600:
                c.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
                self._last_prune = time.time()

    def delete(self, key: str) -> None:
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM sessions WHERE key = ?", (key,))


_sqlite_stores: dict[str, _SqliteStore] = {}


def _store(cfg: AuthConfig):
    path = getattr(cfg, "session_store_path", "") or ""
    if not path:
        return _MemoryStore(cfg._sessions)
    store = _sqlite_stores.get(path)
    if store is None:
        store = _sqlite_stores[path] = _SqliteStore(path)
        log.info("[extensive_auth] sessions persisted in %s", path)
    return store


# ---------------------------------------------------------------------------
# Reading the current request's session
# ---------------------------------------------------------------------------


def _decode_sid(cfg: AuthConfig, request: Request) -> str | None:
    raw = request.cookies.get(cfg.cookie_name)
    if not raw:
        return None
    try:
        sid = _serializer(cfg).loads(raw)
    except BadSignature:
        return None
    if not isinstance(sid, str):
        return None
    return sid


def _live_record(cfg: AuthConfig, sid: str) -> dict | None:
    store = _store(cfg)
    record = store.get(sid)
    if not record:
        return None
    if _now_utc() > record["expires_at"]:
        store.delete(sid)
        return None
    return record


def get_session_email(cfg: AuthConfig, request: Request) -> str | None:
    """Return the authenticated email for this request, or None."""
    sid = _decode_sid(cfg, request)
    if sid is None:
        return None
    record = _live_record(cfg, sid)
    return record["email"] if record else None


def get_session_name(cfg: AuthConfig, request: Request) -> str:
    """Return the display name Google (or the SSO) gave for this session, or ''."""
    sid = _decode_sid(cfg, request)
    if sid is None:
        return ""
    record = _live_record(cfg, sid)
    return (record or {}).get("name", "")


def get_session_picture(cfg: AuthConfig, request: Request) -> str:
    """Return the Google profile picture URL for this session, or ''."""
    sid = _decode_sid(cfg, request)
    if sid is None:
        return ""
    record = _live_record(cfg, sid)
    return (record or {}).get("picture", "")


# ---------------------------------------------------------------------------
# Mutating the session store
# ---------------------------------------------------------------------------


def create_session(cfg: AuthConfig, *, email: str, picture: str = "", name: str = "") -> str:
    """Insert a new session and return the *signed* cookie value."""
    sid = secrets.token_urlsafe(32)
    _store(cfg).put(sid, {
        "email": email,
        "picture": picture,
        "name": name,
        "expires_at": _now_utc() + cfg.session_ttl,
    })
    return _serializer(cfg).dumps(sid)


def delete_session(cfg: AuthConfig, request: Request) -> None:
    """Remove the session associated with the current request cookie."""
    sid = _decode_sid(cfg, request)
    if sid is not None:
        _store(cfg).delete(sid)


# ---------------------------------------------------------------------------
# OAuth state (separate namespace from session ids)
# ---------------------------------------------------------------------------
# State tokens for the OAuth /start → /callback handshake live in the same
# store but with a "_oauth_state:" prefix so they can't collide with session
# ids. Bug-fix history note: in earlier extensive-lpc code the start path
# stored under the prefixed key but the callback looked up the bare key,
# causing 100% callback failure (cf. extensive-lpc PR #6). Both helpers
# below use the prefixed key.

_STATE_PREFIX = "_oauth_state:"


def store_oauth_state(cfg: AuthConfig, state: str, *, ttl_minutes: int = 10) -> None:
    _store(cfg).put(_STATE_PREFIX + state, {
        "expires_at": _now_utc() + timedelta(minutes=ttl_minutes),
    })


def consume_oauth_state(cfg: AuthConfig, state: str) -> bool:
    """Validate + remove a state token. Returns True if it was valid."""
    key = _STATE_PREFIX + state
    store = _store(cfg)
    record = store.get(key)
    if not record:
        return False
    store.delete(key)
    return _now_utc() <= record["expires_at"]
