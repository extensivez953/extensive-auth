"""Security headers middleware factory.

Adds Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
and Referrer-Policy to every response. Sane defaults plus per-directive
overrides so apps can permit specific CDNs without copy-pasting an
entire CSP string.

Usage::

    from extensive_auth import build_security_headers_middleware

    app.add_middleware(build_security_headers_middleware(
        # Anything passed here overrides the default for that directive.
        # Directive name is the same as the CSP key (script-src, etc.).
        csp_overrides={
            "script-src": "'self' https://cdn.jsdelivr.net",
            "img-src":    "'self' data: https://lh3.googleusercontent.com",
            "connect-src": "'self' wss: ws:",
        },
    ))

The factory returns a *class* suitable for ``app.add_middleware()`` — that's
how Starlette's middleware registration works. Don't try to instantiate it
yourself.
"""
from collections.abc import Iterable
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


# Defaults are deliberately strict. Apps loosen via ``csp_overrides``.
_DEFAULT_CSP_DIRECTIVES: dict[str, str] = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": "'self' 'unsafe-inline'",
    "img-src": "'self' data:",
    "connect-src": "'self'",
    "font-src": "'self' data:",
    "frame-src": "'none'",
    "frame-ancestors": "'none'",
    "base-uri": "'self'",
    "form-action": "'self'",
}


def _build_csp_value(overrides: dict[str, str] | None) -> str:
    """Merge defaults with overrides and serialise as a single CSP header value."""
    merged = dict(_DEFAULT_CSP_DIRECTIVES)
    if overrides:
        for key, value in overrides.items():
            merged[key.strip()] = value.strip()
    return "; ".join(f"{k} {v}" for k, v in merged.items())


def build_security_headers_middleware(
    *,
    csp_overrides: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
    exempt_paths: Iterable[str] | None = None,
) -> type[BaseHTTPMiddleware]:
    """Return a middleware class that attaches security headers to every response.

    Args:
        csp_overrides: Per-directive CSP overrides (e.g. ``{"script-src": "..."}``).
            Anything not overridden inherits the default.
        extra_headers: Additional response headers to set verbatim.
        exempt_paths: Path prefixes to skip entirely (e.g. ``["/healthz"]``).
            Useful when an upstream healthcheck is picky about CSP.
    """
    csp_value = _build_csp_value(csp_overrides)
    extras = dict(extra_headers or {})
    exempt = tuple(exempt_paths or ())

    class SecurityHeadersMiddleware(BaseHTTPMiddleware):
        def __init__(self, app: ASGIApp, **_: Any) -> None:
            super().__init__(app)

        async def dispatch(self, request, call_next):
            response = await call_next(request)
            path = request.url.path
            if exempt and any(path.startswith(p) for p in exempt):
                return response
            response.headers.setdefault("Content-Security-Policy", csp_value)
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("X-Frame-Options", "DENY")
            response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
            for key, value in extras.items():
                response.headers.setdefault(key, value)
            return response

    return SecurityHeadersMiddleware
