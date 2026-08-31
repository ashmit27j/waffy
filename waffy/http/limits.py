"""Inline transport resource-protection limits per spec §9.

NOTE: These limits protect waffy's own system resources directly at the transport
layer (closing or rejecting connections/streams) and are NOT evidence-producing detections.
Limits:
- Max in-flight requests per instance
- Max concurrent connections per source IP
- Connection idle timeout
- Minimum request upload rate (Slowloris / Slow-POST protection)
"""

import asyncio
import time
from collections import defaultdict
from typing import Any

from starlette.responses import Response

from waffy.config.models import HttpLimitsConfig
from waffy.core.exceptions import RequestMalformedError


class TransportResourceProtector:
    """Enforces inline transport limits directly to prevent resource starvation."""

    def __init__(self, config: HttpLimitsConfig) -> None:
        self.config = config
        self.active_requests: int = 0
        self.ip_concurrency: dict[str, int] = defaultdict(int)
        self.lock = asyncio.Lock()

    async def acquire_slot(self, client_ip: str) -> tuple[bool, Response | None]:
        """Check instance concurrency and per-IP concurrency limits."""
        async with self.lock:
            if self.active_requests >= self.config.max_in_flight_requests:
                return False, Response(
                    b'{"error": "Service Unavailable", '
                    b'"message": "Server resource limit exceeded"}',
                    status_code=503,
                    media_type="application/json",
                )

            if self.ip_concurrency[client_ip] >= self.config.max_concurrent_connections_per_ip:
                return False, Response(
                    b'{"error": "Too Many Requests", '
                    b'"message": "Connection limit per IP exceeded"}',
                    status_code=429,
                    headers={"Retry-After": "10"},
                    media_type="application/json",
                )

            self.active_requests += 1
            self.ip_concurrency[client_ip] += 1
            return True, None

    async def release_slot(self, client_ip: str) -> None:
        """Release active connection counters."""
        async with self.lock:
            self.active_requests = max(0, self.active_requests - 1)
            if client_ip in self.ip_concurrency:
                self.ip_concurrency[client_ip] -= 1
                if self.ip_concurrency[client_ip] <= 0:
                    del self.ip_concurrency[client_ip]

    async def monitor_body_stream(
        self,
        receive: Any,
        content_length: int | None = None,
        min_bytes_per_second: float = 100.0,
        grace_period_seconds: float = 1.0,
    ) -> bytes:
        """Stream request body with minimum upload rate guard to defeat slow-POST / slowloris."""
        _ = content_length
        body_chunks: list[bytes] = []
        bytes_received = 0
        start_time = time.monotonic()

        while True:
            try:
                # Idle timeout per chunk
                message = await asyncio.wait_for(
                    receive(), timeout=self.config.idle_timeout_seconds
                )
            except TimeoutError as e:
                raise RequestMalformedError("Request body idle timeout exceeded") from e

            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                if chunk:
                    body_chunks.append(chunk)
                    bytes_received += len(chunk)

                elapsed = time.monotonic() - start_time
                if elapsed > grace_period_seconds:
                    rate = bytes_received / elapsed
                    if rate < min_bytes_per_second:
                        raise RequestMalformedError(
                            f"Request upload rate ({rate:.1f} B/s) below minimum "
                            f"threshold ({min_bytes_per_second:.1f} B/s)"
                        )

                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                raise RequestMalformedError("Client disconnected during body upload")

        return b"".join(body_chunks)
