"""Unit tests for waffy foundation models, enums, exceptions, and protocols."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError as PydanticValidationError

from tests.helpers.fakes import (
    FakeCertificateProvider,
    FakeChallengeVerifier,
    FakeEventSink,
    FakeRuleStore,
    FakeUpstreamClient,
)
from waffy.config.models import WaffyConfig, load_config
from waffy.core.enums import (
    EnforcementAction,
    EnforcementMode,
    EventSeverity,
    FailureMode,
    HttpMethod,
    ParanoiaLevel,
    RuleStatus,
    SecurityEventType,
    SignatureCategory,
    TargetField,
    ThreatLevel,
)
from waffy.core.exceptions import (
    AuthenticationError,
    ConfigurationError,
    EnforcementError,
    IntegrationError,
    ModelInferenceError,
    ModelLoadError,
    RequestMalformedError,
    RuleEngineBudgetExceededError,
    RuleLoadError,
    TransportError,
    ValidationError,
    WaffyError,
)
from waffy.core.interfaces import (
    CertificateProvider,
    ChallengeVerifier,
    EventSink,
    RuleStore,
    UpstreamClient,
)
from waffy.core.models.domain import (
    AllowlistEntry,
    AnomalyEvidence,
    BanEntry,
    CandidateBan,
    Decision,
    HttpRequestRecord,
    PositiveSecurityViolation,
    RequestAssessment,
    SecurityEvent,
    Signature,
    SignatureMatch,
)


def test_enums_values() -> None:
    assert ThreatLevel.LOW == "low"
    assert ThreatLevel.CRITICAL == "critical"

    assert EnforcementAction.ALLOW == "allow"
    assert EnforcementAction.BLOCK == "block"
    assert EnforcementAction.CHALLENGE == "challenge"

    assert EnforcementMode.SHADOW == "shadow"
    assert EnforcementMode.ACTIVE == "active"

    assert FailureMode.FAIL_OPEN == "fail_open"
    assert FailureMode.FAIL_CLOSED == "fail_closed"

    assert ParanoiaLevel.PL1 == 1
    assert ParanoiaLevel.PL4 == 4

    assert HttpMethod.GET == "GET"
    assert HttpMethod.POST == "POST"

    assert SignatureCategory.SQLI == "sqli"
    assert SignatureCategory.XSS == "xss"


def test_exception_hierarchy() -> None:
    exceptions = [
        ConfigurationError("bad config"),
        TransportError("socket error"),
        RequestMalformedError("bad framing"),
        RuleLoadError("invalid regex"),
        RuleEngineBudgetExceededError("timeout"),
        ModelLoadError("model missing"),
        ModelInferenceError("feature error"),
        EnforcementError("store down"),
        ValidationError("allowlist conflict"),
        AuthenticationError("invalid token"),
        IntegrationError("siem unreachable"),
    ]

    for exc in exceptions:
        assert isinstance(exc, WaffyError)
        with pytest.raises(WaffyError):
            raise exc


def test_domain_models_valid() -> None:
    req = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/api/v1/users",
        client_ip="192.168.1.50",
        client_port=54321,
    )
    assert req.client_ip == "192.168.1.50"
    assert req.timestamp.tzinfo is not None

    req_v6 = HttpRequestRecord(
        method=HttpMethod.POST,
        path="/",
        client_ip="2001:db8::1",
    )
    assert req_v6.client_ip == "2001:db8::1"

    sig = Signature(
        id="SQLI-001",
        category=SignatureCategory.SQLI,
        pattern="union.*select",
        paranoia_level=ParanoiaLevel.PL1,
        target_fields=[TargetField.QUERY_PARAMS, TargetField.BODY_FIELDS],
    )
    assert sig.id == "SQLI-001"

    sig_match = SignatureMatch(
        signature_id="SQLI-001",
        category=SignatureCategory.SQLI,
        matched_field=TargetField.QUERY_PARAMS,
        field_name="q",
        matched_snippet="union select",
    )
    assert sig_match.score_weight == 5.0

    anomaly = AnomalyEvidence(
        model_id="route_users",
        model_version="1.0",
        anomaly_score=0.82,
        is_anomaly=True,
    )
    assert anomaly.is_anomaly

    pos_violation = PositiveSecurityViolation(
        route_id="/users",
        constraint_name="max_length",
        parameter_name="username",
        expected="len <= 20",
        actual="len = 50",
    )
    assert pos_violation.parameter_name == "username"

    assessment = RequestAssessment(
        request_id=req.request_id,
        client_ip=req.client_ip,
        signature_matches=[sig_match],
        anomaly_evidence=anomaly,
        total_score=15.0,
        threat_level=ThreatLevel.MEDIUM,
    )
    assert len(assessment.signature_matches) == 1

    decision = Decision(
        request_id=req.request_id,
        action=EnforcementAction.ALLOW,
        mode=EnforcementMode.SHADOW,
        threat_level=ThreatLevel.MEDIUM,
    )
    assert decision.action == EnforcementAction.ALLOW

    ban = BanEntry(
        target="192.168.1.100",
        reason="Repeated SQLi attacks",
        expires_at=datetime.now(UTC),
    )
    assert ban.status == RuleStatus.ACTIVE

    candidate_ban = CandidateBan(
        target="10.0.0.0/24",
        reason="Subnet scan",
    )
    assert candidate_ban.status == RuleStatus.CANDIDATE

    allowlist = AllowlistEntry(target="127.0.0.1", reason="Localhost")
    assert allowlist.created_by == "admin"

    event = SecurityEvent(
        type=SecurityEventType.REQUEST_DECISION,
        severity=EventSeverity.LOW,
        source_ip="127.0.0.1",
        correlation_id="abc-123",
        summary="Request processed",
    )
    assert event.severity == EventSeverity.LOW


def test_domain_models_invalid() -> None:
    with pytest.raises(PydanticValidationError):
        HttpRequestRecord(
            method=HttpMethod.GET,
            path="/",
            client_ip="not_an_ip",
        )

    with pytest.raises(PydanticValidationError):
        HttpRequestRecord(
            method=HttpMethod.GET,
            path="/",
            client_ip="127.0.0.1",
            client_port=99999,  # Port out of bounds
        )

    with pytest.raises(PydanticValidationError):
        BanEntry(
            target="invalid_ip_or_cidr",
            reason="test",
            expires_at=datetime.now(UTC),
        )


def test_config_loader_default() -> None:
    cfg = load_config()
    assert isinstance(cfg, WaffyConfig)
    assert cfg.enforcement.mode == EnforcementMode.SHADOW
    assert cfg.enforcement.failure_mode == FailureMode.FAIL_OPEN
    assert cfg.detection.paranoia_level == ParanoiaLevel.PL1
    assert "127.0.0.1" in cfg.allowlist.ips


def test_config_loader_from_file(tmp_path: Path) -> None:
    config_file = Path("config/default_config.toml")
    if config_file.is_file():
        cfg = load_config(config_file)
        assert cfg.enforcement.mode == EnforcementMode.SHADOW
        assert cfg.enforcement.failure_mode == FailureMode.FAIL_OPEN
        assert cfg.transport.port == 8080

    # Non-existent file
    with pytest.raises(ConfigurationError):
        load_config(tmp_path / "nonexistent.toml")

    # Malformed TOML
    bad_toml = tmp_path / "bad.toml"
    bad_toml.write_text("invalid = [toml unclosed", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(bad_toml)


@pytest.mark.asyncio
async def test_protocol_fake_implementations() -> None:
    upstream = FakeUpstreamClient(status_code=200, body=b"Hello")
    assert isinstance(upstream, UpstreamClient)
    req = HttpRequestRecord(method=HttpMethod.GET, path="/", client_ip="127.0.0.1")
    status, _headers, body = await upstream.forward(req)
    assert status == 200
    assert body == b"Hello"
    assert len(upstream.recorded_requests) == 1

    store = FakeRuleStore()
    assert isinstance(store, RuleStore)
    ban = BanEntry(
        target="1.2.3.4",
        reason="test",
        expires_at=datetime.fromtimestamp(datetime.now(UTC).timestamp() + 3600, tz=UTC),
    )
    await store.add_ban(ban)
    retrieved = await store.get_ban("1.2.3.4")
    assert retrieved is not None
    assert retrieved.target == "1.2.3.4"

    cert_provider = FakeCertificateProvider()
    assert isinstance(cert_provider, CertificateProvider)
    cert = await cert_provider.get_certificate("example.com")
    assert cert == ("CERT_DATA", "KEY_DATA")

    verifier = FakeChallengeVerifier()
    assert isinstance(verifier, ChallengeVerifier)
    chal = verifier.generate_challenge("127.0.0.1")
    assert "challenge_id" in chal
    assert verifier.verify_solution("127.0.0.1", "valid_solution")
    token = verifier.issue_trust_token("127.0.0.1")
    assert verifier.verify_trust_token("127.0.0.1", token)

    sink = FakeEventSink()
    assert isinstance(sink, EventSink)
    evt = SecurityEvent(
        type=SecurityEventType.INTERNAL_ERROR,
        severity=EventSeverity.HIGH,
        source_ip="127.0.0.1",
        correlation_id="corr-1",
        summary="Test event",
    )
    await sink.emit(evt)
    await sink.flush()
    assert len(sink.events) == 1
    assert sink.flushed is True
