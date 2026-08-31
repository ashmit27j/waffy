"""Unit and integration tests for Phase 6:
Rate Limiting, Bot Detection, Session/Cookie, and Inline Limits.
"""

import asyncio

import httpx
import pytest

from tests.helpers.fakes import (
    FakeRuleStore,
    FakeUpstreamClient,
)
from waffy.config.models import (
    BotDetectionConfig,
    CredentialStuffingConfig,
    HttpLimitsConfig,
    RateLimitConfig,
    WaffyConfig,
)
from waffy.core.enums import EnforcementMode, HttpMethod, ParanoiaLevel
from waffy.core.exceptions import RequestMalformedError
from waffy.core.models.domain import HttpRequestRecord
from waffy.detection.bot.engine import BotDetectionEngine, TimingRegularityTracker
from waffy.detection.positive.models import PositiveSecurityEngine
from waffy.detection.ratelimit.engine import (
    BoundedSlidingWindowLimiter,
    RateLimitEngine,
)
from waffy.detection.session.services import (
    CookieSecurityRewriter,
    CredentialStuffingDetector,
    CsrfProtector,
)
from waffy.detection.signatures.engine import SignatureEngine
from waffy.http.limits import TransportResourceProtector
from waffy.http.pipeline import WaffyPipelineApplication


def test_sliding_window_rate_limiter_and_bounded_memory() -> None:
    # Max rate = 3 per 10s window, max_entries = 5
    limiter = BoundedSlidingWindowLimiter(rate=3, window_seconds=10.0, max_entries=5)

    base_time = 1000.0
    # Requests 1, 2, 3 allowed
    assert not limiter.check_and_record("user_1", now=base_time)[0]
    assert not limiter.check_and_record("user_1", now=base_time + 1.0)[0]
    assert not limiter.check_and_record("user_1", now=base_time + 2.0)[0]

    # Request 4 trips limit
    tripped, count, retry = limiter.check_and_record("user_1", now=base_time + 3.0)
    assert tripped
    assert count == 4
    assert retry > 0.0

    # Request after window resets
    assert not limiter.check_and_record("user_1", now=base_time + 11.0)[0]

    # Bounded memory test under 100 distinct keys (capacity = 5)
    for i in range(100):
        limiter.check_and_record(f"ip_{i}", now=base_time + 12.0)

    assert len(limiter.buckets) <= 5


def test_rate_limit_engine_multi_scope() -> None:
    cfg = RateLimitConfig(
        requests_per_ip_per_minute=2,
        requests_per_session_per_minute=5,
        requests_per_route_per_minute=10,
        global_requests_per_minute=100,
    )
    engine = RateLimitEngine(cfg)

    req1 = HttpRequestRecord(
        method=HttpMethod.GET, path="/api/v1/data", client_ip="1.2.3.4"
    )

    # 1. First 2 requests within IP quota
    assert not engine.evaluate(req1, now=100.0).tripped
    assert not engine.evaluate(req1, now=101.0).tripped

    # 2. 3rd request trips IP rate limit
    st = engine.evaluate(req1, now=102.0)
    assert st.tripped
    assert st.scope == "ip"
    assert st.limit == 2


@pytest.mark.asyncio
async def test_inline_transport_limits_and_slowloris() -> None:
    limits_cfg = HttpLimitsConfig(
        max_in_flight_requests=2,
        max_concurrent_connections_per_ip=1,
        idle_timeout_seconds=0.5,
    )
    protector = TransportResourceProtector(limits_cfg)

    # 1. Per-IP connection concurrency
    acq1, resp1 = await protector.acquire_slot("10.0.0.1")
    assert acq1
    assert resp1 is None

    # Duplicate concurrent connection from same IP -> 429
    acq2, resp2 = await protector.acquire_slot("10.0.0.1")
    assert not acq2
    assert resp2 is not None
    assert resp2.status_code == 429

    await protector.release_slot("10.0.0.1")

    # 2. Slowloris / Slow-POST detection (Upload rate below threshold)
    async def slow_receive() -> dict[str, object]:
        await asyncio.sleep(0.05)
        return {"type": "http.request", "body": b"A", "more_body": True}

    with pytest.raises(RequestMalformedError, match="upload rate .* below minimum"):
        await protector.monitor_body_stream(
            slow_receive,
            min_bytes_per_second=10000.0,
            grace_period_seconds=0.01,
        )


def test_bot_heuristics() -> None:
    cfg = BotDetectionConfig(
        enabled=True,
        honeypot_endpoints=["/admin/hidden-trap.php"],
    )
    bot_engine = BotDetectionEngine(cfg)

    # 1. Known good search crawler -> Low score, not bot
    good_req = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/",
        client_ip="66.249.66.1",
        headers=[
            ("user-agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
            ("accept", "*/*"),
            ("accept-language", "en-US"),
        ],
    )
    good_assess = bot_engine.assess(good_req)
    assert not good_assess.is_bot

    # 2. Known bad scraper (curl / python-requests) -> High bot score
    bad_req = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/products",
        client_ip="1.2.3.4",
        headers=[("user-agent", "python-requests/2.31.0")],
    )
    bad_assess = bot_engine.assess(bad_req)
    assert bad_assess.is_bot
    assert bad_assess.bot_score >= 0.7

    # 3. Honeypot link trap
    trap_req = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/admin/hidden-trap.php",
        client_ip="5.5.5.5",
    )
    trap_assess = bot_engine.assess(trap_req)
    assert trap_assess.is_bot
    assert trap_assess.category == "honeypot_trap"

    # 4. Timing regularity tracker
    tracker = TimingRegularityTracker()
    # Machine-regular exact 1.0s interval
    for t in [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]:
        cov = tracker.record_and_get_cov("9.9.9.9", now=t)
    assert cov is not None
    assert cov < 0.05  # Perfect machine regularity


def test_cookie_security_rewriter() -> None:
    rewriter = CookieSecurityRewriter(
        enforce_secure=True,
        enforce_httponly=True,
        samesite_policy="Strict",
    )

    # Insecure cookie missing flags
    insecure = "session_id=xyz123; Path=/"
    rewritten = rewriter.rewrite_set_cookie_header(insecure)
    assert "HttpOnly" in rewritten
    assert "Secure" in rewritten
    assert "SameSite=Strict" in rewritten

    # Cookie that already has flags -> No duplicate flags
    secure = "token=abc; Path=/; Secure; HttpOnly; SameSite=Strict"
    rewritten2 = rewriter.rewrite_set_cookie_header(secure)
    assert rewritten2.count("Secure") == 1
    assert rewritten2.count("HttpOnly") == 1


def test_csrf_token_generator_and_validator() -> None:
    csrf = CsrfProtector(secret_key="my-secret-key")
    token = csrf.generate_token("session-user-1", timestamp=1000)

    # Valid token
    assert csrf.validate_token("session-user-1", token, max_age_seconds=5000000000)

    # Invalid session id
    assert not csrf.validate_token("different-user", token, max_age_seconds=5000000000)

    # Tampered token
    assert not csrf.validate_token("session-user-1", token + "bad", max_age_seconds=5000000000)


def test_credential_stuffing_detector() -> None:
    cfg = CredentialStuffingConfig(
        max_failed_logins_per_ip=3,
        max_failed_logins_per_account=2,
        window_seconds=60.0,
    )
    detector = CredentialStuffingDetector(cfg)

    # 1. Per-account velocity (2 failures ok, 3rd trips)
    assert not detector.record_failed_attempt("1.1.1.1", account="alice@test.com", now=10.0)[0]
    assert not detector.record_failed_attempt("1.1.1.2", account="alice@test.com", now=11.0)[0]
    tripped, reason = detector.record_failed_attempt("1.1.1.3", account="alice@test.com", now=12.0)
    assert tripped
    assert "account 'alice@test.com'" in reason

    # 2. Per-IP velocity (3 failures ok, 4th trips)
    detector2 = CredentialStuffingDetector(cfg)
    assert not detector2.record_failed_attempt("2.2.2.2", account="user1", now=10.0)[0]
    assert not detector2.record_failed_attempt("2.2.2.2", account="user2", now=11.0)[0]
    assert not detector2.record_failed_attempt("2.2.2.2", account="user3", now=12.0)[0]
    tripped_ip, reason_ip = detector2.record_failed_attempt("2.2.2.2", account="user4", now=13.0)
    assert tripped_ip
    assert "source IP" in reason_ip


@pytest.mark.asyncio
async def test_full_pipeline_rate_limit_to_rate_limit_action() -> None:
    # Full pipeline test: rate limit trip alone produces 429 RATE_LIMIT action in ACTIVE mode
    cfg = WaffyConfig()
    cfg.enforcement.mode = EnforcementMode.ACTIVE
    cfg.rate_limiting.requests_per_ip_per_minute = 2

    app = WaffyPipelineApplication(
        config=cfg,
        upstream_client=FakeUpstreamClient(status_code=200, body=b"OK"),
        rule_store=FakeRuleStore(),
        signature_engine=SignatureEngine([], paranoia_level=ParanoiaLevel(1)),
        positive_engine=PositiveSecurityEngine([]),
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Request 1: 200 OK
        r1 = await client.get("/test")
        assert r1.status_code == 200

        # Request 2: 200 OK
        r2 = await client.get("/test")
        assert r2.status_code == 200

        # Request 3: 429 Too Many Requests
        r3 = await client.get("/test")
        assert r3.status_code == 429
        assert "Retry-After" in r3.headers
