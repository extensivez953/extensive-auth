"""Configuration for extensive-auth.

A single dataclass that an app builds once at startup (typically via
`AuthConfig.from_env()`) and passes to `build_auth_router()` and the
guard factories. No module-level singletons — the app owns the lifecycle.
"""
import os
from dataclasses import dataclass, field
from datetime import timedelta


def _parse_emails(raw: str) -> set[str]:
    """Comma-separated emails → lowercased set. Empty entries dropped."""
    return {e.strip().lower() for e in raw.split(",") if e.strip()}


@dataclass
class AuthConfig:
    """Per-app auth configuration.

    Most apps will build this with ``AuthConfig.from_env()``. The required
    fields raise at construction time if missing — fail fast at startup
    instead of on the first request.

    Cookie name and salt are scoped to the app so two extensive-* apps
    sharing the same domain don't collide on cookies.
    """
    # Required
    google_client_id: str
    google_client_secret: str
    google_redirect_uri: str
    session_secret: str

    # Allowlist of emails permitted to log in. A SINGLE-element set
    # implements snare's old single-user mode.
    allowed_emails: set[str]

    # Optional API key for X-Api-Key auth. Empty string disables api-key
    # auth path entirely. When non-empty, callers can pass the key in the
    # X-Api-Key header to authenticate without a session cookie.
    api_key: str = ""

    # App-scoped cookie name and signing salt. Defaults are deliberately
    # generic — set per-app to avoid cross-app cookie collisions.
    cookie_name: str = "extensive_session"
    session_salt: str = "extensive-session"

    # Session TTL.
    session_ttl: timedelta = field(default_factory=lambda: timedelta(days=14))

    # ROOT_PATH (sub-path the app is mounted under, e.g. "/lpc"). Used to
    # build redirect URLs when the OAuth flow needs to redirect back to /
    # or /login. Empty for root-mounted apps.
    root_path: str = ""

    # Cookie security. Set False ONLY for local-HTTP development.
    cookie_secure: bool = True

    # Class-level (not constructor) — process-local in-memory session
    # store keyed by signed-cookie session id. Each AuthConfig instance
    # gets its own dict so two apps in the same process don't share
    # sessions (though that's an unusual setup).
    _sessions: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_env(cls, *, prefix: str = "") -> "AuthConfig":
        """Build from environment variables.

        Recognised env vars (with optional prefix for multi-app processes):
          {prefix}GOOGLE_CLIENT_ID         — required
          {prefix}GOOGLE_CLIENT_SECRET     — required
          {prefix}GOOGLE_REDIRECT_URI      — required
          {prefix}SESSION_SECRET           — required (32+ random bytes hex)
          {prefix}ALLOWED_EMAILS           — required, comma-separated
          {prefix}API_KEY                  — optional
          {prefix}COOKIE_NAME              — optional, default extensive_session
          {prefix}SESSION_SALT             — optional, default extensive-session
          {prefix}SESSION_TTL_DAYS         — optional integer, default 14
          {prefix}ROOT_PATH                — optional, default ""
          {prefix}COOKIE_SECURE            — optional, "false" disables Secure
        """
        def _env(name: str, default: str | None = None) -> str | None:
            return os.environ.get(prefix + name, default)

        client_id     = (_env("GOOGLE_CLIENT_ID") or "").strip()
        client_secret = (_env("GOOGLE_CLIENT_SECRET") or "").strip()
        redirect_uri  = (_env("GOOGLE_REDIRECT_URI") or "").strip()
        secret        = (_env("SESSION_SECRET") or "").strip()
        allow_raw     = (_env("ALLOWED_EMAILS") or "").strip()

        missing: list[str] = []
        if not client_id:     missing.append(prefix + "GOOGLE_CLIENT_ID")
        if not client_secret: missing.append(prefix + "GOOGLE_CLIENT_SECRET")
        if not redirect_uri:  missing.append(prefix + "GOOGLE_REDIRECT_URI")
        if not secret:        missing.append(prefix + "SESSION_SECRET")
        if not allow_raw:     missing.append(prefix + "ALLOWED_EMAILS")
        if missing:
            raise RuntimeError(
                "extensive_auth: missing required env vars: " + ", ".join(missing)
            )

        ttl_raw = _env("SESSION_TTL_DAYS", "14") or "14"
        try:
            ttl_days = int(ttl_raw)
        except ValueError as exc:
            raise RuntimeError(
                f"extensive_auth: SESSION_TTL_DAYS must be an integer, got {ttl_raw!r}"
            ) from exc

        cookie_secure = (_env("COOKIE_SECURE", "true") or "true").lower() != "false"

        return cls(
            google_client_id=client_id,
            google_client_secret=client_secret,
            google_redirect_uri=redirect_uri,
            session_secret=secret,
            allowed_emails=_parse_emails(allow_raw),
            api_key=(_env("API_KEY") or "").strip(),
            cookie_name=(_env("COOKIE_NAME") or "extensive_session").strip(),
            session_salt=(_env("SESSION_SALT") or "extensive-session").strip(),
            session_ttl=timedelta(days=ttl_days),
            root_path=(_env("ROOT_PATH") or "").rstrip("/"),
            cookie_secure=cookie_secure,
        )

    def is_allowed(self, email: str) -> bool:
        return email.lower().strip() in self.allowed_emails
