"""Sliding window rate limiters with bounded memory.

Architecture:
- Sliding log / window with microsecond granularity.
- Independent scopes: IP, Session/User, Route, Global instance.
- Produces RateLimitState evidence into RequestAssessment, never directly enforces.
- State is bounded via OrderedDict / LRU capacity eviction.
"""

import time
from collections import OrderedDict, deque
from dataclasses import dataclass

from waffy.config.models import RateLimitConfig
from waffy.core.models.domain import HttpRequestRecord, RateLimitState


@dataclass
class BucketState:
    timestamps: deque[float]


class BoundedSlidingWindowLimiter:
    """Sliding window rate limiter with LRU eviction for bounded memory."""

    def __init__(
        self,
        rate: int,
        window_seconds: float = 60.0,
        max_entries: int = 10000,
    ) -> None:
        self.rate = rate
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self.buckets: OrderedDict[str, BucketState] = OrderedDict()

    def check_and_record(self, key: str, now: float | None = None) -> tuple[bool, int, float]:
        """Record a hit for key and return (is_tripped, current_count, retry_after)."""
        current_time = now if now is not None else time.time()
        window_start = current_time - self.window_seconds

        if key in self.buckets:
            bucket = self.buckets[key]
            self.buckets.move_to_end(key)
        else:
            if len(self.buckets) >= self.max_entries:
                self.buckets.popitem(last=False)  # Evict oldest entry
            bucket = BucketState(timestamps=deque())
            self.buckets[key] = bucket

        # Evict timestamps strictly older than window
        while bucket.timestamps and bucket.timestamps[0] <= window_start:
            bucket.timestamps.popleft()

        bucket.timestamps.append(current_time)
        count = len(bucket.timestamps)

        if count > self.rate:
            oldest = bucket.timestamps[0]
            retry_after = max(1.0, (oldest + self.window_seconds) - current_time)
            return True, count, retry_after

        return False, count, 0.0


class RateLimitEngine:
    """Multi-scope rate limit evaluator."""

    def __init__(self, config: RateLimitConfig) -> None:
        self.config = config
        self.ip_limiter = BoundedSlidingWindowLimiter(
            rate=config.requests_per_ip_per_minute,
            window_seconds=60.0,
        )
        self.session_limiter = BoundedSlidingWindowLimiter(
            rate=config.requests_per_session_per_minute,
            window_seconds=60.0,
        )
        self.route_limiter = BoundedSlidingWindowLimiter(
            rate=config.requests_per_route_per_minute,
            window_seconds=60.0,
        )
        self.global_limiter = BoundedSlidingWindowLimiter(
            rate=config.global_requests_per_minute,
            window_seconds=60.0,
        )

    def evaluate(
        self,
        request: HttpRequestRecord,
        session_id: str | None = None,
        now: float | None = None,
    ) -> RateLimitState:
        """Evaluate request against all scopes and return RateLimitState evidence."""
        if not self.config.enabled:
            return RateLimitState(tripped=False)

        # 1. Global limit
        g_tripped, g_count, g_retry = self.global_limiter.check_and_record("global", now)
        if g_tripped:
            return RateLimitState(
                tripped=True,
                scope="global",
                current_rate=g_count,
                limit=self.config.global_requests_per_minute,
                retry_after_seconds=int(g_retry),
            )

        # 2. IP limit
        ip_tripped, ip_count, ip_retry = self.ip_limiter.check_and_record(request.client_ip, now)
        if ip_tripped:
            return RateLimitState(
                tripped=True,
                scope="ip",
                current_rate=ip_count,
                limit=self.config.requests_per_ip_per_minute,
                retry_after_seconds=int(ip_retry),
            )

        # 3. Session / User limit (if available)
        if session_id:
            s_tripped, s_count, s_retry = self.session_limiter.check_and_record(session_id, now)
            if s_tripped:
                return RateLimitState(
                    tripped=True,
                    scope="session",
                    current_rate=s_count,
                    limit=self.config.requests_per_session_per_minute,
                    retry_after_seconds=int(s_retry),
                )

        # 4. Route limit
        r_key = f"{request.method.value}:{request.path}"
        r_tripped, r_count, r_retry = self.route_limiter.check_and_record(r_key, now)
        if r_tripped:
            return RateLimitState(
                tripped=True,
                scope="route",
                current_rate=r_count,
                limit=self.config.requests_per_route_per_minute,
                retry_after_seconds=int(r_retry),
            )

        return RateLimitState(tripped=False, current_rate=ip_count)
