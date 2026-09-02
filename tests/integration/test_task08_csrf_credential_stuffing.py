"""Integration tests for prompts/08: wiring CredentialStuffingDetector and
CsrfProtector into the live WaffyPipelineApplication as evidence producers.

Coverage
--------
- CSRF: a state-changing request in embedded mode with a session cookie but
  a missing/invalid token is scored (CsrfViolation evidence -> total_score ->
  decision engine) end-to-end through the pipeline, changing the observable
  HTTP response from ALLOW/200 to CHALLENGE/403 -- not just exercised via the
  standalone CsrfProtector unit tests.
- Credential stuffing: a burst of failed logins against a configured
  ``login_failure_routes`` entry, observed via real upstream 401 responses,
  accumulates velocity evidence that later flips the decision engine's
  action for that source IP -- proven by asserting the request stops
  reaching the upstream once the CHALLENGE action is produced.
"""

import httpx
import pytest

from tests.helpers.fakes import FakeRuleStore, FakeUpstreamClient
from waffy.config.models import WaffyConfig
from waffy.core.enums import EnforcementMode, ParanoiaLevel
from waffy.detection.positive.models import PositiveSecurityEngine
from waffy.detection.session.services import CsrfProtector
from waffy.detection.signatures.engine import SignatureEngine
from waffy.http.pipeline import WaffyPipelineApplication


def _build_app(cfg: WaffyConfig, upstream: FakeUpstreamClient) -> WaffyPipelineApplication:
    return WaffyPipelineApplication(
        config=cfg,
        upstream_client=upstream,
        rule_store=FakeRuleStore(),
        signature_engine=SignatureEngine([], paranoia_level=ParanoiaLevel(1)),
        positive_engine=PositiveSecurityEngine([]),
    )


@pytest.mark.asyncio
async def test_csrf_violation_scored_end_to_end_through_pipeline() -> None:
    cfg = WaffyConfig()
    cfg.transport.mode = "embedded"
    cfg.csrf.enabled = True
    cfg.csrf.secret_key = "integration-test-secret"
    cfg.enforcement.mode = EnforcementMode.ACTIVE
    # High enough alone to reach MEDIUM threat (-> CHALLENGE) so the effect
    # of the evidence is observable in the HTTP response, not just internal.
    cfg.engine.weight_csrf_violation = cfg.engine.threshold_medium

    upstream = FakeUpstreamClient(status_code=200, body=b"profile updated")
    app = _build_app(cfg, upstream)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        cookies={"session_id": "sess-abc123"},
    ) as client:
        # Missing token entirely, but a session is established.
        r1 = await client.post(
            "/account/update",
            content=b"name=new-name",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert r1.status_code == 403
        assert len(upstream.recorded_requests) == 0  # never reached upstream

        # A garbage/invalid token is the same as missing.
        r2 = await client.post(
            "/account/update",
            content=b"name=new-name",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-CSRF-Token": "not-a-real-token",
            },
        )
        assert r2.status_code == 403
        assert len(upstream.recorded_requests) == 0

        # A correctly-signed token for this session validates cleanly and
        # the request is forwarded through to the (fake) upstream.
        protector = CsrfProtector(secret_key="integration-test-secret")
        valid_token = protector.generate_token("sess-abc123")
        r3 = await client.post(
            "/account/update",
            content=b"name=new-name",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-CSRF-Token": valid_token,
            },
        )
        assert r3.status_code == 200
        assert len(upstream.recorded_requests) == 1


@pytest.mark.asyncio
async def test_csrf_not_checked_outside_embedded_mode() -> None:
    """Per CsrfConfig's documented scope: proxy modes don't get token-based
    CSRF evidence (a future header-based mechanism is tracked separately),
    so a missing token must never affect the decision outside embedded mode.
    """
    cfg = WaffyConfig()
    cfg.transport.mode = "plaintext"
    cfg.csrf.enabled = True
    cfg.enforcement.mode = EnforcementMode.ACTIVE
    cfg.engine.weight_csrf_violation = cfg.engine.threshold_medium

    upstream = FakeUpstreamClient(status_code=200, body=b"ok")
    app = _build_app(cfg, upstream)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        cookies={"session_id": "sess-abc123"},
    ) as client:
        r = await client.post(
            "/account/update",
            content=b"name=new-name",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert r.status_code == 200
        assert len(upstream.recorded_requests) == 1


@pytest.mark.asyncio
async def test_credential_stuffing_velocity_scored_end_to_end_through_pipeline() -> None:
    cfg = WaffyConfig()
    cfg.enforcement.mode = EnforcementMode.ACTIVE
    cfg.credential_stuffing.enabled = True
    cfg.credential_stuffing.login_failure_routes = ["/login"]
    cfg.credential_stuffing.max_failed_logins_per_ip = 2
    cfg.credential_stuffing.window_seconds = 3600.0
    # High enough alone to reach MEDIUM threat (-> CHALLENGE) once tripped.
    cfg.engine.weight_credential_stuffing = cfg.engine.threshold_medium

    # Real (fake) upstream genuinely rejects every login attempt with 401 --
    # this is what teaches the detector about failed logins, not a canned
    # test fixture bypassing the pipeline.
    upstream = FakeUpstreamClient(status_code=401, body=b"invalid credentials")
    app = _build_app(cfg, upstream)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Attempts 1-3: below/at threshold, still forwarded to upstream and
        # rejected there (401), each one recorded as a failed login.
        for expected_upstream_count in (1, 2, 3):
            r = await client.post("/login", json={"username": "attacker", "password": "bad"})
            assert r.status_code == 401
            assert len(upstream.recorded_requests) == expected_upstream_count

        # Attempt 4: velocity evidence from the 3 prior failures now trips,
        # scoring pushes the decision to CHALLENGE, and the request never
        # reaches the upstream at all -- proving the evidence flowed through
        # scoring -> decision -> enforcement, not just the isolated detector.
        r4 = await client.post("/login", json={"username": "attacker", "password": "bad"})
        assert r4.status_code == 403
        assert len(upstream.recorded_requests) == 3


@pytest.mark.asyncio
async def test_credential_stuffing_ignores_waffy_own_block_response() -> None:
    """A 403 produced by waffy's own BLOCK/CHALLENGE enforcement action must
    never be misread as the upstream application's own login failure -- see
    the decision.action gate in WaffyPipelineApplication.__call__.
    """
    cfg = WaffyConfig()
    cfg.enforcement.mode = EnforcementMode.ACTIVE
    cfg.credential_stuffing.enabled = True
    cfg.credential_stuffing.login_failure_routes = ["/login"]
    cfg.credential_stuffing.max_failed_logins_per_ip = 100
    cfg.csrf.enabled = True
    cfg.transport.mode = "embedded"
    # Force every request on this route into CHALLENGE (403) via CSRF,
    # never touching the upstream at all.
    cfg.engine.weight_csrf_violation = cfg.engine.threshold_medium

    upstream = FakeUpstreamClient(status_code=200, body=b"unused")
    app = _build_app(cfg, upstream)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        cookies={"session_id": "sess-xyz"},
    ) as client:
        for _ in range(3):
            r = await client.post(
                "/login",
                content=b"username=attacker&password=bad",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            assert r.status_code == 403

        assert len(upstream.recorded_requests) == 0
        # No failed logins were ever recorded from waffy's own CHALLENGE
        # responses -- confirmed indirectly: the detector's internal state
        # for this IP stays empty.
        assert "127.0.0.1" not in app.credential_stuffing_detector.source_failures
