"""FastAPI router factory for the Google OAuth flow.

The app calls `build_auth_router(cfg)` once at startup and mounts the
returned APIRouter. Routes provided:

  GET  /auth/google/start       Begins OAuth code-flow
  GET  /auth/google/callback    Completes flow, sets session cookie
  GET  /auth/logout             Clears session cookie

The login *page* is the app's responsibility (different apps, different
brands). This router only handles the OAuth handshake.
"""
import hmac
import logging
import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from extensive_auth.config import AuthConfig
from extensive_auth.rate_limit import (
    RateLimitState,
    client_ip,
    is_rate_limited,
    record_attempt,
)
from extensive_auth.session import (
    consume_oauth_state,
    create_session,
    delete_session,
    store_oauth_state,
)

log = logging.getLogger("extensive_auth")

GOOGLE_AUTH_URL    = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL   = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

# Short-lived cookie that mirrors the OAuth state value. The server-side
# state store already prevents replay (single-use, TTL'd). Binding the
# state to a browser-set cookie additionally prevents an attacker from
# completing the OAuth flow in a different browser using a callback URL
# captured from the victim — the cookie never leaves the original browser.
_STATE_COOKIE = "extensive_oauth_state"
_STATE_TTL_SECONDS = 600  # 10 min — generous for a slow login


def build_auth_router(cfg: AuthConfig) -> APIRouter:
    """Return an APIRouter with the OAuth + logout endpoints.

    Apps mount this directly:
        app.include_router(build_auth_router(cfg))
    """
    router = APIRouter()

    # Per-AuthConfig rate-limit state. Lives for the lifetime of the
    # config (i.e. the running process). Multi-worker setups would
    # swap this for a shared store; single-worker uvicorn (the standard
    # extensive-* deployment) is fine as-is.
    rl_state = RateLimitState()

    @router.get("/auth/google/start")
    def google_start(request: Request):
        ip = client_ip(request)
        if is_rate_limited(rl_state, ip):
            log.warning("[extensive_auth] rate-limited /auth/google/start from %s", ip)
            raise HTTPException(
                status_code=429,
                detail="Too many login attempts from this address. Try again later.",
            )
        record_attempt(rl_state, ip)

        state = secrets.token_urlsafe(24)
        store_oauth_state(cfg, state)
        params = {
            "client_id": cfg.google_client_id,
            "redirect_uri": cfg.google_redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "online",
            "prompt": "select_account",
        }
        response = RedirectResponse(url=f"{GOOGLE_AUTH_URL}?{urlencode(params)}")
        # Bind state to this browser via a short-lived cookie. Callback
        # rejects any state that doesn't match this cookie.
        response.set_cookie(
            _STATE_COOKIE,
            value=state,
            max_age=_STATE_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            secure=cfg.cookie_secure,
            path="/",
        )
        return response

    @router.get("/auth/google/callback")
    async def google_callback(request: Request, code: str = "", state: str = ""):
        if not code or not state:
            raise HTTPException(status_code=400, detail="Missing code/state.")

        # Browser-binding check — short-circuits before we touch Google.
        cookie_state = request.cookies.get(_STATE_COOKIE, "")
        if not cookie_state or not hmac.compare_digest(state, cookie_state):
            log.warning(
                "[extensive_auth] OAuth state cookie mismatch from %s",
                client_ip(request),
            )
            raise HTTPException(status_code=400, detail="State cookie mismatch.")

        if not consume_oauth_state(cfg, state):
            raise HTTPException(status_code=400, detail="Expired or invalid state.")

        async with httpx.AsyncClient(timeout=10.0) as client:
            token_resp = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": cfg.google_client_id,
                    "client_secret": cfg.google_client_secret,
                    "redirect_uri": cfg.google_redirect_uri,
                    "grant_type": "authorization_code",
                },
            )
            if token_resp.status_code != 200:
                log.warning("[extensive_auth] token exchange failed: %s", token_resp.text)
                raise HTTPException(status_code=502, detail="Google token exchange failed.")
            access_token = (token_resp.json() or {}).get("access_token", "")
            if not access_token:
                raise HTTPException(status_code=502, detail="Missing access_token from Google.")

            info_resp = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if info_resp.status_code != 200:
                raise HTTPException(status_code=502, detail="Google userinfo failed.")
            info = info_resp.json() or {}

        email = (info.get("email") or "").lower().strip()
        if not email or not info.get("email_verified", False):
            raise HTTPException(status_code=403, detail="Email not verified by Google.")
        if not cfg.is_allowed(email):
            log.warning("[extensive_auth] denied non-allowlisted email: %s", email)
            raise HTTPException(status_code=403, detail="This email isn't on the allowlist.")

        picture = info.get("picture", "") or ""
        cookie_value = create_session(cfg, email=email, picture=picture)

        log.info("[extensive_auth] login: %s", email)
        response = RedirectResponse(url=(cfg.root_path or "") + "/", status_code=302)
        response.set_cookie(
            cfg.cookie_name,
            cookie_value,
            max_age=int(cfg.session_ttl.total_seconds()),
            httponly=True,
            samesite="lax",
            secure=cfg.cookie_secure,
            path="/",
        )
        # State has served its purpose; clear the bind cookie so it can't
        # leak into later requests.
        response.delete_cookie(_STATE_COOKIE, path="/")
        return response

    @router.get("/auth/logout")
    def logout(request: Request):
        delete_session(cfg, request)
        response = RedirectResponse(
            url=(cfg.root_path or "") + "/login", status_code=302,
        )
        response.delete_cookie(cfg.cookie_name, path="/")
        return response

    return router
