"""
auth/rate_limiter.py — IP-based rate limiting with sliding window.

Provides global (cross-account) brute-force protection independent of
the per-account lockout in authenticator.py.
"""

import time
import threading
from collections import defaultdict
from typing import Tuple

from utils.logger import get_logger

log = get_logger(__name__)


class SlidingWindowRateLimiter:
    """
    Thread-safe sliding window rate limiter.
    Tracks request timestamps per (namespace, key) pair.

    Usage:
        limiter = SlidingWindowRateLimiter()
        allowed, remaining, retry_after = limiter.check("login", "1.2.3.4")
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests   = max_requests
        self.window_seconds = window_seconds
        self._windows: defaultdict = defaultdict(list)
        self._blocked:  defaultdict = defaultdict(float)  # key → unblock_at
        self._lock = threading.Lock()

    def check(
        self, namespace: str, key: str, cost: int = 1
    ) -> Tuple[bool, int, float]:
        """
        Check and record a request.

        Returns:
            allowed (bool)    — whether the request is permitted
            remaining (int)   — requests remaining in this window
            retry_after (float) — seconds until retry is allowed (0 if allowed)
        """
        bucket = f"{namespace}:{key}"
        now    = time.time()

        with self._lock:
            # Check hard block first
            unblock = self._blocked.get(bucket, 0)
            if now < unblock:
                return False, 0, round(unblock - now, 1)

            # Prune old entries
            self._windows[bucket] = [
                t for t in self._windows[bucket]
                if now - t < self.window_seconds
            ]

            count = sum(self._windows[bucket].count(t) for t in self._windows[bucket])
            # simpler: just len
            current = len(self._windows[bucket])

            if current + cost > self.max_requests:
                # Block for the remainder of the window
                oldest = self._windows[bucket][0] if self._windows[bucket] else now
                retry  = round(self.window_seconds - (now - oldest) + 1, 1)
                self._blocked[bucket] = now + retry
                log.warning("Rate limit exceeded: %s", bucket)
                return False, 0, retry

            for _ in range(cost):
                self._windows[bucket].append(now)
            remaining = self.max_requests - len(self._windows[bucket])
            return True, remaining, 0.0

    def reset(self, namespace: str, key: str) -> None:
        bucket = f"{namespace}:{key}"
        with self._lock:
            self._windows.pop(bucket, None)
            self._blocked.pop(bucket, None)

    def is_blocked(self, namespace: str, key: str) -> bool:
        bucket = f"{namespace}:{key}"
        with self._lock:
            return time.time() < self._blocked.get(bucket, 0)

    def get_stats(self) -> dict:
        with self._lock:
            now     = time.time()
            blocked = sum(1 for v in self._blocked.values() if now < v)
            return {
                "tracked_keys": len(self._windows),
                "currently_blocked": blocked,
            }


# ── Singleton instances ────────────────────────────────────────────────────────

# Login: max 15 attempts per IP per 10 minutes
login_limiter = SlidingWindowRateLimiter(max_requests=15, window_seconds=600)

# Threat intel lookup: max 30 per IP per minute (API cost protection)
intel_limiter = SlidingWindowRateLimiter(max_requests=30, window_seconds=60)

# General API: max 120 per IP per minute
api_limiter = SlidingWindowRateLimiter(max_requests=120, window_seconds=60)


def check_login(ip: str) -> Tuple[bool, str]:
    """
    Returns (allowed, message).
    Call this before authenticate() to add IP-level protection.
    """
    allowed, remaining, retry = login_limiter.check("login", ip)
    if not allowed:
        return False, f"Too many login attempts from this IP. Retry in {retry:.0f}s."
    return True, ""


def record_failed_login(ip: str) -> None:
    """Add extra cost for a failed login attempt (counts double)."""
    login_limiter.check("login_fail", ip, cost=2)


def check_intel(ip: str) -> Tuple[bool, str]:
    allowed, _, retry = intel_limiter.check("intel", ip)
    if not allowed:
        return False, f"Intel lookup rate limit. Retry in {retry:.0f}s."
    return True, ""
