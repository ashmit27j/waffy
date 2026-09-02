#!/usr/bin/env python3
"""Throughput benchmark: sustained requests/sec through the default paranoia-1 pipeline.

Same in-process scope as latency_bench.py (see its docstring) — real seed
signatures at PL1, FakeUpstreamClient, SHADOW mode. A fixed pool of
concurrent workers drives requests back-to-back for a fixed wall-clock
duration; each worker uses its own client IP (well under the default
max_concurrent_connections_per_ip=50 and the pool's total width under
max_in_flight_requests=1000, config/default_config.toml) so the transport
resource-protection limiter itself isn't what's being measured.

"Without queue growth" is checked directly: completed-request counts are
bucketed per wall-clock second, and the run only reports success if the
per-second completion rate does not show a declining trend (which would
indicate work piling up faster than it drains).

Run: `uv run python scripts/benchmarks/throughput_bench.py`
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import build_pipeline, reference_environment, run_one_request  # noqa: E402

CONCURRENCY = 64
DURATION_SECONDS = 5.0
WARMUP_SECONDS = 1.0


async def _worker(
    worker_id: int,
    pipeline: Any,
    stop_at: float,
    per_second_counts: dict[int, int],
    start_time: float,
    lock: asyncio.Lock,
) -> int:
    client_ip = f"203.0.113.{worker_id % 250}"
    completed = 0
    while time.perf_counter() < stop_at:
        await run_one_request(pipeline, client_ip=client_ip)
        completed += 1
        bucket = int(time.perf_counter() - start_time)
        async with lock:
            per_second_counts[bucket] = per_second_counts.get(bucket, 0) + 1
    return completed


async def run_benchmark() -> dict[str, Any]:
    pipeline, upstream = build_pipeline()

    # Warmup outside the measured window.
    warmup_stop = time.perf_counter() + WARMUP_SECONDS
    warmup_lock = asyncio.Lock()
    warmup_counts: dict[int, int] = {}
    await asyncio.gather(
        *[
            _worker(i, pipeline, warmup_stop, warmup_counts, time.perf_counter(), warmup_lock)
            for i in range(CONCURRENCY)
        ]
    )
    upstream.recorded_requests.clear()

    lock = asyncio.Lock()
    per_second_counts: dict[int, int] = {}
    start_time = time.perf_counter()
    stop_at = start_time + DURATION_SECONDS

    results = await asyncio.gather(
        *[
            _worker(i, pipeline, stop_at, per_second_counts, start_time, lock)
            for i in range(CONCURRENCY)
        ]
    )
    actual_duration = time.perf_counter() - start_time
    total_completed = sum(results)

    # Drop the final, partial second bucket before trend-checking.
    full_buckets = [per_second_counts.get(s, 0) for s in range(int(actual_duration))]

    declining = False
    if len(full_buckets) >= 3:
        first_half = full_buckets[: len(full_buckets) // 2]
        second_half = full_buckets[len(full_buckets) // 2 :]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        # More than a 20% drop from first half to second half is treated as
        # queue growth / backpressure, not noise.
        declining = avg_second < avg_first * 0.8

    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "reference_environment": reference_environment(),
        "concurrency": CONCURRENCY,
        "duration_seconds_requested": DURATION_SECONDS,
        "duration_seconds_actual": round(actual_duration, 4),
        "total_requests_completed": total_completed,
        "requests_per_second": round(total_completed / actual_duration, 2),
        "per_second_completion_counts": full_buckets,
        "upstream_calls_recorded": len(upstream.recorded_requests),
        "queue_growth_detected": declining,
    }


def main() -> int:
    result = asyncio.run(run_benchmark())
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
