"""waffy/integration/metrics.py — Prometheus-format metrics counter registry.

Design
------
- ``MetricsRegistry`` maintains all counters/gauges as plain Python atomics
  (thread-safe ``int``/``float`` with a lock for reads).
- ``waffy-core`` increments counters on every request via the pipeline.
- ``waffy-api`` reads the counter snapshot over IPC (or, in embedded mode,
  shares the registry directly) and serves it as a Prometheus text exposition.
- The exposition format follows the Prometheus 0.0.4 text format which is also
  compatible with Netdata's Prometheus collector.

Exposed metrics
---------------
``waffy_requests_total``               — request count by outcome label
``waffy_score_histogram``              — bucket counts for total score
``waffy_signature_hits_total``         — per-signature hit counts
``waffy_rate_limit_trips_total``       — rate-limit trip events
``waffy_ban_list_size``                — current active ban count (gauge)
``waffy_budget_exceeded_total``        — signature engine time-budget overruns
``waffy_process_start_time_seconds``   — Unix epoch of process start
"""

import os
import time
from collections import defaultdict
from threading import Lock
from typing import Any

_START_TIME: float = time.time()


class MetricsRegistry:
    """Thread-safe counter/gauge registry producing Prometheus text output."""

    def __init__(self) -> None:
        self._lock = Lock()
        # Counters keyed by label dict (serialised as frozenset for hashing)
        self._requests: dict[str, int] = defaultdict(int)  # key = outcome label
        self._signature_hits: dict[str, int] = defaultdict(int)  # key = rule_id
        self._rate_limit_trips: int = 0
        self._budget_exceeded: int = 0
        self._ban_list_size: int = 0
        # Score histogram buckets (upper bounds in score units)
        _buckets = [5.0, 15.0, 25.0, 40.0, 60.0, 100.0, float("inf")]
        self._score_buckets: dict[float, int] = {b: 0 for b in _buckets}
        self._score_count: int = 0
        self._score_sum: float = 0.0

    # --- Increment methods (called by the pipeline) ----------------------- #

    def inc_request(self, outcome: str) -> None:
        """Increment request counter.  outcome: allow | log | challenge | block |
        rate_limit | shadow_allow | shadow_block."""
        with self._lock:
            self._requests[outcome] += 1

    def observe_score(self, score: float) -> None:
        with self._lock:
            self._score_count += 1
            self._score_sum += score
            for bound in self._score_buckets:
                if score <= bound:
                    self._score_buckets[bound] += 1

    def inc_signature_hit(self, rule_id: str) -> None:
        with self._lock:
            self._signature_hits[rule_id] += 1

    def inc_rate_limit_trip(self) -> None:
        with self._lock:
            self._rate_limit_trips += 1

    def inc_budget_exceeded(self) -> None:
        with self._lock:
            self._budget_exceeded += 1

    def set_ban_list_size(self, size: int) -> None:
        with self._lock:
            self._ban_list_size = size

    # --- Snapshot for IPC read -------------------------------------------- #

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serialisable snapshot of all metrics."""
        with self._lock:
            return {
                "requests": dict(self._requests),
                "signature_hits": dict(self._signature_hits),
                "rate_limit_trips": self._rate_limit_trips,
                "budget_exceeded": self._budget_exceeded,
                "ban_list_size": self._ban_list_size,
                "score_histogram": {
                    "buckets": {str(k): v for k, v in self._score_buckets.items()},
                    "count": self._score_count,
                    "sum": self._score_sum,
                },
            }

    # --- Prometheus text exposition --------------------------------------- #

    def prometheus_text(self) -> str:
        """Return Prometheus 0.0.4 text format exposition."""
        snap = self.snapshot()
        lines: list[str] = []

        # Process start time
        lines += [
            "# HELP waffy_process_start_time_seconds Unix timestamp of process start",
            "# TYPE waffy_process_start_time_seconds gauge",
            f"waffy_process_start_time_seconds {_START_TIME}",
        ]

        # Request counter
        lines += [
            "# HELP waffy_requests_total Total requests processed by waffy",
            "# TYPE waffy_requests_total counter",
        ]
        for outcome, count in snap["requests"].items():
            lines.append(f'waffy_requests_total{{outcome="{outcome}"}} {count}')

        # Rate limit trips
        lines += [
            "# HELP waffy_rate_limit_trips_total Total rate limit trips",
            "# TYPE waffy_rate_limit_trips_total counter",
            f"waffy_rate_limit_trips_total {snap['rate_limit_trips']}",
        ]

        # Budget exceeded
        lines += [
            "# HELP waffy_budget_exceeded_total Signature engine time-budget overruns",
            "# TYPE waffy_budget_exceeded_total counter",
            f"waffy_budget_exceeded_total {snap['budget_exceeded']}",
        ]

        # Ban list size
        lines += [
            "# HELP waffy_ban_list_size Current number of active bans",
            "# TYPE waffy_ban_list_size gauge",
            f"waffy_ban_list_size {snap['ban_list_size']}",
        ]

        # Signature hits
        lines += [
            "# HELP waffy_signature_hits_total Per-signature rule hit counts",
            "# TYPE waffy_signature_hits_total counter",
        ]
        for rule_id, count in snap["signature_hits"].items():
            lines.append(f'waffy_signature_hits_total{{rule_id="{rule_id}"}} {count}')

        # Score histogram
        hist = snap["score_histogram"]
        lines += [
            "# HELP waffy_score_histogram Distribution of request risk scores",
            "# TYPE waffy_score_histogram histogram",
        ]
        for bound_str, count in hist["buckets"].items():
            bound = bound_str if bound_str != "inf" else "+Inf"
            lines.append(f'waffy_score_histogram_bucket{{le="{bound}"}} {count}')
        lines.append(f"waffy_score_histogram_count {hist['count']}")
        lines.append(f"waffy_score_histogram_sum {hist['sum']}")

        # Process resource usage
        try:
            rss_mb = _get_rss_mb()
            lines += [
                "# HELP waffy_process_rss_bytes Process RSS memory in bytes",
                "# TYPE waffy_process_rss_bytes gauge",
                f"waffy_process_rss_bytes {int(rss_mb * 1024 * 1024)}",
            ]
        except Exception:
            pass  # Resource usage is best-effort

        return "\n".join(lines) + "\n"


def _get_rss_mb() -> float:
    """Return process RSS in MB.  Works on Linux via /proc; falls back on macOS."""
    try:
        with open(f"/proc/{os.getpid()}/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return float(line.split()[1]) / 1024.0
    except OSError:
        pass
    try:
        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF)
        # macOS returns bytes in ru_maxrss, Linux returns KB
        import platform
        if platform.system() == "Darwin":
            return usage.ru_maxrss / (1024 * 1024)
        return usage.ru_maxrss / 1024.0
    except Exception:
        return 0.0


# Module-level default registry shared across the process.
default_registry = MetricsRegistry()

__all__ = [
    "MetricsRegistry",
    "default_registry",
]
