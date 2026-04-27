"""CSRF token helpers bound to the current session.

Token format: ``{timestamp}.{hmac_hex}`` where the HMAC is over
``"{session_sid}:{timestamp}"`` keyed by ``cfg.session_secret``. This ties
each token to a specific signed session — a token issued for one session
is rejected when presented from another. Tokens expire after the
configured TTL (default 24 hours).

This complements ``samesite=lax`` cookies, which are NOT a complete CSRF
defense on their own (subdomain attacks, browser bugs, top-level GET
mutations, etc.). Apps protect mutating session-auth routes by:

    @app.post("/post")
    def create_post(
        request: Request,
        csrf_token: str = Form(...),
    ):
        check_csrf(cfg, request, csrf_token)
        ...

…and emit the token from a hidden form field rendered by ``new_csrf``::

    <form method="post" action="...">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        ...
    </form>

API-key callers don't need CSRF — the X-Api-Key header is itself unforgeable
from the browser cross-origin (CORS preflight blocks it).
"""
import hashlib
import hmac
import time

from fastapi import HTTPException, Request

from extensive_auth.config import AuthConfig
from extensive_auth.session import _decode_sid  # noqa: SLF001 — same package


# 24h is a reasonable balance between user friction (form left open in a
# tab) and replay window. Apps that want stricter can wrap check_csrf.
DEFAULT_TTL_SECONDS: int = 86_400


def _signing_key(cfg: AuthConfig) -> bytes:
    """Use the session secret as the CSRF signing key — same key, different
    namespace via the message format. Avoids introducing a second secret."""
    return cfg.session_secret.encode("utf-8")


def _sid_for_csrf(cfg: AuthConfig, request: Request) -> str:
    """Return the session id to bind the CSRF token to.

    For unauthenticated requests we fall back to the raw cookie value, which
    means a logged-out form (e.g. login page) gets a session-less token that
    only works for that browser tab as long as the cookie is unchanged.
    """
    sid = _decode_sid(cfg, request)
    if sid is not None:
        return sid
    raw = request.cookies.get(cfg.cookie_name, "")
    return raw or "anonymous"


def _sign(cfg: AuthConfig, sid: str, ts: str) -> str:
    msg = f"{sid}:{ts}".encode("utf-8")
    return hmac.new(_signing_key(cfg), msg, hashlib.sha256).hexdigest()


def new_csrf(cfg: AuthConfig, request: Request) -> str:
    """Generate a CSRF token bound to the current session.

    Caller is expected to render this into a hidden form field (or include
    it in JSON request bodies for fetch-based UIs).
    """
    ts = str(int(time.time()))
    sid = _sid_for_csrf(cfg, request)
    return f"{ts}.{_sign(cfg, sid, ts)}"


def check_csrf(
    cfg: AuthConfig,
    request: Request,
    token: str,
    *,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> None:
    """Validate a CSRF token. Raises HTTP 403 on failure.

    Failure modes:
      - Malformed token (no ``ts.sig`` shape, or non-numeric timestamp)
      - Signature mismatch (different session, tampered, or wrong key)
      - Expired (timestamp older than ``ttl_seconds`` ago)
    """
    if not token or "." not in token:
        raise HTTPException(status_code=403, detail="Missing or malformed CSRF token.")
    ts_str, presented_sig = token.split(".", 1)
    if not ts_str.isdigit():
        raise HTTPException(status_code=403, detail="Malformed CSRF token.")

    issued_at = int(ts_str)
    if time.time() - issued_at > ttl_seconds:
        raise HTTPException(status_code=403, detail="CSRF token expired.")

    sid = _sid_for_csrf(cfg, request)
    expected_sig = _sign(cfg, sid, ts_str)
    if not hmac.compare_digest(presented_sig, expected_sig):
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")
