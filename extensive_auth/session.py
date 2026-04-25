"""Cookie-based session management.

Sessions live in a process-local dict on the AuthConfig instance. The
cookie value is the signed (itsdangerous URLSafeSerializer) session id.

This is fine for single-process deployments (uvicorn with one worker —
which is what every extensive-* app uses today). For multi-worker setups
you'd swap this for a shared store (Redis, sqlite, etc.) — the public
API stays the same.
"""
import logging
import secrets
from datetime import datetime, timezone

from fastapi import Request
from itsdangerous import BadSignature, URLSafeSerializer

from extensive_auth.config import AuthConfig

log = logging.getLogger("extensive_auth")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _serializer(cfg: AuthConfig) -> URLSafeSerializer:
    return URLSafeSerializer(cfg.session_secret, salt=cfg.session_salt)


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
    record = cfg._sessions.get(sid)
    if not record:
        return None
    if _now_utc() > record["expires_at"]:
        cfg._sessions.pop(sid, None)
        return None
    return record


def get_session_email(cfg: AuthConfig, request: Request) -> str | None:
    """Return the authenticated email for this request, or None."""
    sid = _decode_sid(cfg, request)
    if sid is None:
        return None
    record = _live_record(cfg, sid)
    return record["email"] if record else None


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


def create_session(cfg: AuthConfig, *, email: str, picture: str = "") -> str:
    """Insert a new session and return the *signed* cookie value."""
    sid = secrets.token_urlsafe(32)
    cfg._sessions[sid] = {
        "email": email,
        "picture": picture,
        "expires_at": _now_utc() + cfg.session_ttl,
    }
    return _serializer(cfg).dumps(sid)


def delete_session(cfg: AuthConfig, request: Request) -> None:
    """Remove the session associated with the current request cookie."""
    sid = _decode_sid(cfg, request)
    if sid is not None:
        cfg._sessions.pop(sid, None)


# ---------------------------------------------------------------------------
# OAuth state (separate namespace from session ids)
# ---------------------------------------------------------------------------
# State tokens for the OAuth /start → /callback handshake live in the same
# dict but with a "_oauth_state:" prefix so they can't collide with session
# ids. Bug-fix history note: in earlier extensive-lpc code the start path
# stored under the prefixed key but the callback looked up the bare key,
# causing 100% callback failure (cf. extensive-lpc PR #6). Both helpers
# below use the prefixed key.

_STATE_PREFIX = "_oauth_state:"


def store_oauth_state(cfg: AuthConfig, state: str, *, ttl_minutes: int = 10) -> None:
    from datetime import timedelta
    cfg._sessions[_STATE_PREFIX + state] = {
        "expires_at": _now_utc() + timedelta(minutes=ttl_minutes),
    }


def consume_oauth_state(cfg: AuthConfig, state: str) -> bool:
    """Validate + remove a state token. Returns True if it was valid."""
    key = _STATE_PREFIX + state
    record = cfg._sessions.get(key)
    if not record:
        return False
    cfg._sessions.pop(key, None)
    return _now_utc() <= record["expires_at"]
