"""Shared pipeline construction and raw-ASGI call harness for waffy benchmark scripts.

Per docs/MASTER_SPEC.md §21 and this task's constraints: these benchmarks
measure *waffy's own added latency* against an in-process `FakeUpstreamClient`
— never real network RTT, never a real upstream server. Requests are driven
directly through the ASGI `scope`/`receive`/`send` triplet rather than through
an httpx client, so the timed window is exactly `await pipeline(...)` and does
not include an HTTP client library's own transport overhead.
"""

from __future__ import annotations

import platform
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.helpers.fakes import FakeRuleStore, FakeUpstreamClient  # noqa: E402
from waffy.config.models import WaffyConfig  # noqa: E402
from waffy.core.enums import ParanoiaLevel  # noqa: E402
from waffy.detection.positive.models import PositiveSecurityEngine  # noqa: E402
from waffy.detection.signatures import SignatureEngine, load_all_rules_from_dir  # noqa: E402
from waffy.http.pipeline import WaffyPipelineApplication  # noqa: E402

RULES_DIR = REPO_ROOT / "config" / "rules"

# A representative small JSON API request body, well under the 10 MB
# max_body_bytes default bound (config/default_config.toml) and under the
# spec's illustrative "M KB" example in §21.
BENCH_BODY = (
    b'{"query": "wireless mechanical keyboard", "category": "electronics", '
    b'"page": 2, "sort": "relevance", "filters": {"in_stock": true, "min_rating": 4}}'
)
assert len(BENCH_BODY) < 2048, "benchmark body must stay a small, representative request"


def build_pipeline() -> tuple[WaffyPipelineApplication, FakeUpstreamClient]:
    """Build the default paranoia-1 pipeline: real seed signatures, no positive-security
    routes configured (optional per spec §8), ML anomaly scorer disabled (evidence-only
    layer measured separately), SHADOW enforcement mode (the shipped default).
    """
    config = WaffyConfig()
    assert config.detection.paranoia_level == ParanoiaLevel.PL1
    signatures = load_all_rules_from_dir(RULES_DIR)
    upstream = FakeUpstreamClient(status_code=200, body=b"upstream-ok")
    pipeline = WaffyPipelineApplication(
        config=config,
        upstream_client=upstream,
        rule_store=FakeRuleStore(),
        signature_engine=SignatureEngine(
            signatures, paranoia_level=config.detection.paranoia_level
        ),
        positive_engine=PositiveSecurityEngine([]),
    )
    return pipeline, upstream


def make_asgi_scope(client_ip: str = "203.0.113.50") -> dict[str, Any]:
    """Build a minimal, realistic ASGI HTTP scope for a POST request carrying BENCH_BODY."""
    headers = [
        (b"host", b"testserver"),
        (b"content-type", b"application/json"),
        (b"content-length", str(len(BENCH_BODY)).encode()),
        (b"user-agent", b"waffy-benchmark/1.0"),
    ]
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v1/search",
        "raw_path": b"/api/v1/search",
        "query_string": b"",
        "headers": headers,
        "client": (client_ip, 51234),
        "server": ("testserver", 80),
    }


async def run_one_request(
    pipeline: WaffyPipelineApplication, client_ip: str = "203.0.113.50"
) -> float:
    """Drive one request through the pipeline's raw ASGI interface, returning elapsed seconds."""
    scope = make_asgi_scope(client_ip)
    body_sent = False

    async def receive() -> dict[str, Any]:
        nonlocal body_sent
        if not body_sent:
            body_sent = True
            return {"type": "http.request", "body": BENCH_BODY, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message: dict[str, Any]) -> None:
        return None

    start = time.perf_counter()
    await pipeline(scope, receive, send)
    return time.perf_counter() - start


def reference_environment() -> dict[str, str]:
    """Describe the machine this benchmark ran on — a number without this is not usable."""
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "machine": platform.machine(),
    }
