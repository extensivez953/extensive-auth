"""Fleet single sign-on — the token that auth.extensive.cloud hands an app.

The SSO (extensive-sso) and every app share one secret (``SSO_SECRET``).
After a person signs in at the SSO and is found to hold a grant for the
requesting app, the SSO mints a short-lived, single-use, signed token and
redirects the browser back to the app's ``/auth/sso/callback``. The app
verifies it here and opens its ordinary local session — nothing else about
the app changes.

Token = itsdangerous ``URLSafeTimedSerializer`` over a small JSON payload::

    {"email": "...", "name": "...", "picture": "...", "app": "games",
     "role": "member", "jti": "<random>"}

Checks on the app side (``verify_sso_token``):
  - signature and age (default 60 s — the browser redirect takes well under that)
  - ``app`` equals this app's slug (a token minted for finance can't open games)
  - ``jti`` not seen before in this process (replay inside the window)

Both ends use this module so the format has exactly one definition.
"""
import secrets
import time
from urllib.parse import urlencode

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from extensive_auth.config import AuthConfig

SSO_TOKEN_SALT = "extensive-sso-token"
SSO_TOKEN_MAX_AGE = 60  # seconds

# jti -> expiry epoch. Process-local, like the session store. Pruned on use.
_seen_jti: dict[str, float] = {}


class SsoError(Exception):
    """Raised by verify_sso_token with a message safe to show in a log line."""


def _serializer(secret: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret, salt=SSO_TOKEN_SALT)


def mint_sso_token(secret: str, *, email: str, app: str, name: str = "", picture: str = "", role: str = "member") -> str:
    """SSO side: sign a login for ``app``."""
    payload = {
        "email": email.lower().strip(),
        "name": name or "",
        "picture": picture or "",
        "app": app,
        "role": role,
        "jti": secrets.token_urlsafe(16),
    }
    return _serializer(secret).dumps(payload)


def verify_sso_token(secret: str, token: str, *, app: str, max_age: int = SSO_TOKEN_MAX_AGE) -> dict:
    """App side: return the payload or raise SsoError."""
    if not secret:
        raise SsoError("SSO_SECRET is not configured")
    try:
        payload = _serializer(secret).loads(token, max_age=max_age)
    except SignatureExpired as exc:
        raise SsoError("token expired") from exc
    except BadSignature as exc:
        raise SsoError("bad signature") from exc
    if not isinstance(payload, dict) or not payload.get("email") or not payload.get("jti"):
        raise SsoError("malformed payload")
    if payload.get("app") != app:
        raise SsoError(f"token is for app {payload.get('app')!r}, not {app!r}")
    now = time.time()
    for k in [k for k, exp in _seen_jti.items() if exp < now]:
        _seen_jti.pop(k, None)
    if payload["jti"] in _seen_jti:
        raise SsoError("token replayed")
    _seen_jti[payload["jti"]] = now + max_age
    return payload


def sso_authorize_url(cfg: AuthConfig, *, state: str, return_url: str) -> str:
    """Where the app sends the browser to start an SSO login."""
    params = {"app": cfg.sso_app, "return": return_url, "state": state}
    return f"{cfg.sso_url.rstrip('/')}/authorize?{urlencode(params)}"


def sso_logout_url(cfg: AuthConfig, *, return_url: str) -> str:
    return f"{cfg.sso_url.rstrip('/')}/logout?{urlencode({'return': return_url})}"
