# extensive-auth

Shared Google-OAuth + cookie-session + X-Api-Key authentication for the **extensive-*** ecosystem (extensive-snare, extensive-lpc, extensive-hub, future apps).

Tiny pip-installable package. Apps pull it in by Git URL:

```
extensive-auth @ git+https://github.com/extensivez953/extensive-auth.git@main
```

## Why

Each extensive-* app was reimplementing the same ~150 lines of Google-OAuth + session-cookie code. They were drifting (extensive-lpc shipped with a state-key-mismatch bug that snare didn't have). One canonical source = fewer bugs and faster bring-up of the next app.

## What it gives you

- `AuthConfig.from_env()` — read all auth config from env vars, fail-fast on missing required ones
- `build_auth_router(cfg)` — FastAPI APIRouter with `/auth/google/start`, `/auth/google/callback`, `/auth/logout`
- `get_session_email(cfg, request)` / `get_session_picture(cfg, request)` — read the current request's session
- `require_user(cfg)` — FastAPI Depends factory that 403s when not signed in
- `require_user_or_api_key(cfg)` — same, but also accepts a matching `X-Api-Key` header

## What it deliberately doesn't do

- **No login page.** Apps own their own login HTML/CSS. The package only handles the OAuth handshake.
- **No DB.** Sessions live in a process-local dict on the `AuthConfig` instance. Single-worker uvicorn deployments — which every extensive-* app uses — don't need anything more.
- **No multi-process session sharing.** Swap the in-memory store for Redis/sqlite if you scale out.

## Quick start

```python
from fastapi import FastAPI, Depends
from extensive_auth import AuthConfig, build_auth_router, require_user

cfg = AuthConfig.from_env()              # reads ALLOWED_EMAILS, GOOGLE_*, etc.
app = FastAPI()
app.include_router(build_auth_router(cfg))

@app.get("/api/me")
def me(user: dict = Depends(require_user(cfg))):
    return user
```

## Required env vars

| Var | Required | Notes |
|-----|----------|-------|
| `GOOGLE_CLIENT_ID` | yes | One client can serve N apps — just add each app's redirect URI |
| `GOOGLE_CLIENT_SECRET` | yes | |
| `GOOGLE_REDIRECT_URI` | yes | Must match an Authorized redirect URI in GCP |
| `SESSION_SECRET` | yes | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ALLOWED_EMAILS` | yes | Comma-separated. Single email = single-user mode. |
| `API_KEY` | optional | Enables `require_user_or_api_key`. Empty = api-key path disabled. |
| `COOKIE_NAME` | optional | Default `extensive_session` — set per-app to avoid cross-app cookie collisions on the same domain |
| `SESSION_SALT` | optional | Default `extensive-session` — same reason |
| `SESSION_TTL_DAYS` | optional | Default 14 |
| `ROOT_PATH` | optional | Sub-path the app is mounted under (e.g. `/lpc`). Used to build redirects after login/logout. |
| `COOKIE_SECURE` | optional | Set `false` ONLY for local-HTTP development |

For multi-app processes, `from_env(prefix="LPC_")` reads `LPC_GOOGLE_CLIENT_ID` etc.

## Tests

```bash
pip install -e ".[test]"
pytest
```
