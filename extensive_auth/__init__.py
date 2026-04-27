"""extensive-auth — shared Google-OAuth + session + X-Api-Key auth.

Public API:

    from extensive_auth import (
        AuthConfig,
        build_auth_router,
        get_session_email,
        get_session_picture,
        require_user,
        require_user_or_api_key,
    )

Quick start in a FastAPI app:

    from fastapi import FastAPI, Depends
    from extensive_auth import AuthConfig, build_auth_router, require_user

    cfg = AuthConfig.from_env()             # reads ALLOWED_EMAILS, GOOGLE_*, etc.
    app = FastAPI()
    app.include_router(build_auth_router(cfg))

    @app.get("/api/secret")
    def secret(user: dict = Depends(require_user(cfg))):
        return {"email": user["email"]}

The package is intentionally small (stdlib + httpx + itsdangerous + fastapi)
and designed to be pip-installed directly from git:

    extensive-auth @ git+https://github.com/extensivez953/extensive-auth.git@main

Apps own their own login *page* (HTML/CSS); the package owns the OAuth
endpoints, session store, and guards.
"""
from extensive_auth.config import AuthConfig
from extensive_auth.csrf import check_csrf, new_csrf
from extensive_auth.guards import require_user, require_user_or_api_key
from extensive_auth.router import build_auth_router
from extensive_auth.security_headers import build_security_headers_middleware
from extensive_auth.session import (
    create_session,
    delete_session,
    get_session_email,
    get_session_picture,
)

__all__ = [
    "AuthConfig",
    "build_auth_router",
    "build_security_headers_middleware",
    "check_csrf",
    "create_session",
    "delete_session",
    "get_session_email",
    "get_session_picture",
    "new_csrf",
    "require_user",
    "require_user_or_api_key",
]

__version__ = "0.2.0"
