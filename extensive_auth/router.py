"""FastAPI router factory for the Google OAuth flow.

The app calls `build_auth_router(cfg)` once at startup and mounts the
returned APIRouter. Routes provided:

  GET  /auth/google/start       Begins OAuth code-flow (or, in SSO mode, bounces to the fleet SSO)
  GET  /auth/google/callback    Completes flow, sets session cookie
  GET  /auth/sso/callback       SSO mode: verifies the SSO token, sets session cookie
  GET  /auth/logout             Clears session cookie (?everywhere=1 also signs out of the SSO)

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
from extensive_auth.sso import (
    SsoError,
    sso_authorize_url,
    sso_logout_url,
    verify_sso_token,
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
_cfg_holder: dict = {}


def build_auth_router(cfg: AuthConfig) -> APIRouter:
    """Return an APIRouter with the OAuth + logout endpoints.

    Apps mount this directly:
        app.include_router(build_auth_router(cfg))
    """
    router = APIRouter()
    _cfg_holder["cfg"] = cfg

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
        if cfg.sso_enabled:
            # Fleet SSO: Google happens once at auth.extensive.cloud; we get a token back.
            response = RedirectResponse(url=sso_authorize_url(
                cfg, state=state, return_url=_sso_return_url(request)))
            response.set_cookie(_STATE_COOKIE, value=state, max_age=_STATE_TTL_SECONDS,
                                httponly=True, samesite="lax", secure=cfg.cookie_secure, path="/")
            return response
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
        cookie_value = create_session(cfg, email=email, picture=picture, name=info.get("name", "") or "")

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

    @router.get("/auth/sso/callback")
    def sso_callback(request: Request, token: str = "", state: str = ""):
        if not cfg.sso_enabled:
            raise HTTPException(status_code=404)
        if not token or not state:
            raise HTTPException(status_code=400, detail="Missing token/state.")
        cookie_state = request.cookies.get(_STATE_COOKIE, "")
        if not cookie_state or not hmac.compare_digest(state, cookie_state):
            log.warning("[extensive_auth] SSO state cookie mismatch from %s", client_ip(request))
            raise HTTPException(status_code=400, detail="State cookie mismatch.")
        if not consume_oauth_state(cfg, state):
            raise HTTPException(status_code=400, detail="Expired or invalid state.")
        try:
            claims = verify_sso_token(cfg.sso_secret, token, app=cfg.sso_app)
        except SsoError as exc:
            log.warning("[extensive_auth] SSO token rejected from %s: %s", client_ip(request), exc)
            raise HTTPException(status_code=403, detail="Sign-in token rejected.") from exc
        email = claims["email"]
        if not cfg.is_allowed(email):
            log.warning("[extensive_auth] SSO login denied by local allowlist: %s", email)
            raise HTTPException(status_code=403, detail="This email isn't on the allowlist.")
        cookie_value = create_session(cfg, email=email, picture=claims.get("picture", ""),
                                      name=claims.get("name", ""))
        log.info("[extensive_auth] sso login: %s", email)
        response = RedirectResponse(url=(cfg.root_path or "") + "/", status_code=302)
        response.set_cookie(cfg.cookie_name, cookie_value, max_age=int(cfg.session_ttl.total_seconds()),
                            httponly=True, samesite="lax", secure=cfg.cookie_secure, path="/")
        response.delete_cookie(_STATE_COOKIE, path="/")
        return response

    @router.get("/auth/logout")
    def logout(request: Request, everywhere: str = ""):
        delete_session(cfg, request)
        login_url = (cfg.root_path or "") + "/login"
        if cfg.sso_enabled and everywhere:
            target = sso_logout_url(cfg, return_url=_absolute(request, login_url))
        else:
            target = login_url
        response = RedirectResponse(url=target, status_code=302)
        response.delete_cookie(cfg.cookie_name, path="/")
        return response

    return router


def _absolute(request: Request, path: str) -> str:
    """Absolute URL for a path on this app, honouring the proxy's scheme/host."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    return f"{scheme}://{host}{path}"


def _sso_return_url(request: Request) -> str:
    """Where the SSO sends the browser back: this app's /auth/sso/callback.

    Derived from GOOGLE_REDIRECT_URI's origin when set (it already names the
    public host), otherwise from the request. nginx strips ROOT_PATH, so the
    callback lives at ROOT_PATH + /auth/sso/callback publicly.
    """
    cfg_ = _cfg_holder.get("cfg")
    root = (cfg_.root_path if cfg_ else "") or ""
    return _absolute(request, root + "/auth/sso/callback")
