"""Per-IP rate limiting for the auth flow.

Used by build_auth_router to gate /auth/google/start and /auth/google/callback
so a single attacker IP can't drive thousands of OAuth handshakes per minute.

In-memory state keyed on AuthConfig instance — restart resets counters,
which is fine for a single-instance app. Multi-worker setups would swap
this for a shared store (Redis); the public API stays identical.
"""
import time
from dataclasses import dataclass, field

from fastapi import Request

# Tunables — sized for a personal/small-team app. An attacker burning
# 30 attempts in 10 minutes earns a 15-minute lockout.
DEFAULT_MAX_ATTEMPTS: int = 30
DEFAULT_WINDOW_SECONDS: int = 600
DEFAULT_LOCKOUT_SECONDS: int = 900


@dataclass
class RateLimitState:
    """In-memory rate-limit state. One per AuthConfig instance."""

    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    lockout_seconds: int = DEFAULT_LOCKOUT_SECONDS
    attempts: dict[str, list[float]] = field(default_factory=dict)
    lockouts: dict[str, float] = field(default_factory=dict)


def client_ip(request: Request) -> str:
    """Resolve the originating client IP, preferring X-Forwarded-For when set.

    Behind nginx the direct peer is always the proxy, so request.client.host
    is useless for rate-limiting on its own. nginx is configured to forward
    the real client IP via X-Forwarded-For (per the standard extensive-* nginx
    snippet); we read that and fall back to the peer address otherwise.
    """
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        # Take the first hop — that's the actual client. Trailing entries
        # are intermediary proxies and not trustworthy as identity.
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def is_rate_limited(state: RateLimitState, ip: str) -> bool:
    """Return True if *ip* is currently locked out OR has exceeded the window."""
    now = time.time()

    # Lockout still active?
    expiry = state.lockouts.get(ip)
    if expiry is not None:
        if now < expiry:
            return True
        del state.lockouts[ip]

    # Trim attempts to the active window
    attempts = state.attempts.get(ip, [])
    cutoff = now - state.window_seconds
    fresh = [t for t in attempts if t >= cutoff]
    if len(fresh) != len(attempts):
        state.attempts[ip] = fresh
    return len(fresh) >= state.max_attempts


def record_attempt(state: RateLimitState, ip: str) -> None:
    """Record one auth-flow attempt from *ip*. Locks the IP out if the
    threshold is now met."""
    now = time.time()
    attempts = state.attempts.setdefault(ip, [])
    attempts.append(now)
    # Trim opportunistically so the list doesn't grow unbounded.
    cutoff = now - state.window_seconds
    if attempts and attempts[0] < cutoff:
        state.attempts[ip] = [t for t in attempts if t >= cutoff]
    if len(state.attempts[ip]) >= state.max_attempts:
        state.lockouts[ip] = now + state.lockout_seconds


def reset(state: RateLimitState) -> None:
    """Drop all attempts and lockouts. Useful for tests."""
    state.attempts.clear()
    state.lockouts.clear()
