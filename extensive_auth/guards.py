"""FastAPI dependency-style guards.

Apps use these as `Depends(...)` arguments on protected routes. Each
guard is a *factory* — call it with the config to get a closure suitable
for `Depends()`.

    from fastapi import Depends
    from extensive_auth import require_user, require_user_or_api_key

    @app.get("/api/me")
    def me(user: dict = Depends(require_user(cfg))):
        return user

    @app.post("/api/cards")
    def add(user: dict = Depends(require_user_or_api_key(cfg))):
        ...

`require_user` rejects unauthenticated requests with 403.
`require_user_or_api_key` accepts either a valid session OR a matching
X-Api-Key header — useful for endpoints that humans AND scripts call.
"""
import hmac
from collections.abc import Callable

from fastapi import HTTPException, Request

from extensive_auth.config import AuthConfig
from extensive_auth.session import get_session_email, get_session_picture


def _user_from_session(cfg: AuthConfig, request: Request) -> dict | None:
    email = get_session_email(cfg, request)
    if not email:
        return None
    return {
        "email": email,
        "picture": get_session_picture(cfg, request),
        "auth_method": "session",
    }


def _user_from_api_key(cfg: AuthConfig, request: Request) -> dict | None:
    """Return a synthetic 'user' dict if the request carries a valid X-Api-Key.

    The api-key path doesn't identify a *human*; it identifies a *caller*.
    The synthetic user records that fact so route handlers can audit or
    behave differently for programmatic vs. human callers.
    """
    if not cfg.api_key:
        return None
    presented = request.headers.get("X-Api-Key", "")
    if not presented:
        return None
    if not hmac.compare_digest(presented, cfg.api_key):
        return None
    return {
        "email": "<api-key>",
        "picture": "",
        "auth_method": "api_key",
    }


def require_user(cfg: AuthConfig) -> Callable[[Request], dict]:
    """Dependency: requires a valid session cookie, else 403."""
    def _dep(request: Request) -> dict:
        user = _user_from_session(cfg, request)
        if user is None:
            raise HTTPException(status_code=403, detail="Authentication required.")
        return user
    return _dep


def require_user_or_api_key(cfg: AuthConfig) -> Callable[[Request], dict]:
    """Dependency: requires either a valid session cookie OR a matching X-Api-Key, else 403."""
    def _dep(request: Request) -> dict:
        user = _user_from_session(cfg, request) or _user_from_api_key(cfg, request)
        if user is None:
            raise HTTPException(
                status_code=403,
                detail="Authentication required. Provide a session cookie or X-Api-Key header.",
            )
        return user
    return _dep
