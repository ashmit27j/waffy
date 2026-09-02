#!/usr/bin/env python3
"""Latency benchmark: waffy's own added latency for the default paranoia-1 pipeline.

Scope (per docs/MASTER_SPEC.md §21 and this task's constraints):
  - In-process only, against FakeUpstreamClient — measures waffy's own added
    latency, not real network RTT to a real upstream.
  - Real seed signature set (config/rules/seed_rules.toml) at paranoia level 1
    (the shipped default), real HTTP parsing/normalization, real positive
    security (no routes configured — optional per spec §8), real rate
    limiting/bot detection/cookie rewriting, SHADOW enforcement mode (the
    shipped default). ML anomaly scoring is disabled here (a separate,
    evidence-only layer not exercised by this run) — see docs/PERFORMANCE.md.
  - Client IP is rotated per request so the sliding-window rate limiter does
    not throttle mid-run and skew the steady-state number.

Every number printed comes from an actual timed run on this machine — never
estimated. Run: `uv run python scripts/benchmarks/latency_bench.py`
"""

from __future__ import annotations

import asyncio
import json
import statistics
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import BENCH_BODY, build_pipeline, reference_environment, run_one_request  # noqa: E402

WARMUP_REQUESTS = 200
MEASURED_REQUESTS = 2000


def percentile(sorted_values: list[float], pct: float) -> float:
    """Nearest-rank percentile over an already-sorted list of samples."""
    if not sorted_values:
        return 0.0
    idx = max(0, min(len(sorted_values) - 1, int(round(pct / 100.0 * len(sorted_values))) - 1))
    return sorted_values[idx]


async def run_benchmark() -> dict[str, Any]:
    pipeline, upstream = build_pipeline()

    # Warmup: JIT-adjacent caches (compiled regex, dict growth, etc.) settle out.
    for i in range(WARMUP_REQUESTS):
        await run_one_request(pipeline, client_ip=f"198.51.100.{i % 250}")

    upstream.recorded_requests.clear()

    samples_sec: list[float] = []
    for i in range(MEASURED_REQUESTS):
        elapsed = await run_one_request(pipeline, client_ip=f"203.0.113.{i % 250}")
        samples_sec.append(elapsed)

    samples_ms = sorted(s * 1000.0 for s in samples_sec)

    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "reference_environment": reference_environment(),
        "request_body_size_bytes": len(BENCH_BODY),
        "warmup_requests": WARMUP_REQUESTS,
        "measured_requests": MEASURED_REQUESTS,
        "upstream_calls_recorded": len(upstream.recorded_requests),
        "latency_ms": {
            "min": round(samples_ms[0], 4),
            "p50": round(percentile(samples_ms, 50), 4),
            "p95": round(percentile(samples_ms, 95), 4),
            "p99": round(percentile(samples_ms, 99), 4),
            "max": round(samples_ms[-1], 4),
            "mean": round(statistics.mean(samples_ms), 4),
            "stdev": round(statistics.stdev(samples_ms), 4) if len(samples_ms) > 1 else 0.0,
        },
    }


def main() -> int:
    result = asyncio.run(run_benchmark())
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
