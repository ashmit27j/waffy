"""Unit and integration tests for Phase 5:
Scoring, Decision, Enforcement, Validation, and Kill-switch.
"""

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from tests.helpers.fakes import (
    FakeEventSink,
    FakeRuleStore,
    FakeUpstreamClient,
)
from waffy.config.models import ApiConfig, EnforcementConfig, EngineConfig, WaffyConfig
from waffy.core.enums import (
    EnforcementAction,
    EnforcementMode,
    ParanoiaLevel,
    SignatureCategory,
    TargetField,
    ThreatLevel,
)
from waffy.core.exceptions import ValidationError
from waffy.core.models.domain import (
    AllowlistEntry,
    AnomalyEvidence,
    BanEntry,
    CandidateBan,
    PositiveSecurityViolation,
    RequestAssessment,
    SignatureMatch,
)
from waffy.detection.positive.models import PositiveSecurityEngine
from waffy.detection.signatures.engine import SignatureEngine
from waffy.detection.signatures.schema import load_all_rules_from_dir
from waffy.enforcement.allowlist import AllowlistManager
from waffy.enforcement.killswitch import KillSwitchService
from waffy.enforcement.validation import ActionValidationChain
from waffy.engine.decision import DecisionEngine
from waffy.engine.scoring import compute_assessment_score
from waffy.http.pipeline import WaffyPipelineApplication


def test_scoring_weighted_sum_and_thresholds() -> None:
    cfg = EngineConfig(
        weight_positive_violation=5.0,
        weight_anomaly=10.0,
        threshold_low=5.0,
        threshold_medium=15.0,
        threshold_high=25.0,
        threshold_critical=40.0,
    )

    assessment = RequestAssessment(
        request_id="req-1",
        client_ip="1.2.3.4",
        signature_matches=[
            SignatureMatch(
                signature_id="SQLI-1",
                category=SignatureCategory.SQLI,
                matched_field=TargetField.QUERY_PARAMS,
                score_weight=15.0,
            ),
            SignatureMatch(
                signature_id="XSS-1",
                category=SignatureCategory.XSS,
                matched_field=TargetField.BODY_FIELDS,
                score_weight=10.0,
            ),
        ],
        positive_violations=[
            PositiveSecurityViolation(
                route_id="/test",
                constraint_name="max_length",
                expected="<= 10",
                actual="50",
                score_weight=5.0,
            )
        ],
        anomaly_evidence=AnomalyEvidence(
            model_id="test",
            model_version="1.0",
            anomaly_score=0.8,
            is_anomaly=True,
        ),
    )

    # Total score = 15 + 10 + 5 + (0.8 * 10) = 38.0 -> HIGH
    score, threat_level = compute_assessment_score(assessment, cfg)
    assert score == pytest.approx(38.0, 0.1)
    assert threat_level == ThreatLevel.HIGH


def test_evidence_maturity_invariant_both_directions() -> None:
    eng_cfg = EngineConfig()
    enf_cfg = EnforcementConfig(mode=EnforcementMode.ACTIVE)
    decision_engine = DecisionEngine(eng_cfg, enf_cfg)

    # 1. Strong evidence (Paranoia-1 SQLi) -> Qualifies for BLOCK
    strong_assessment = RequestAssessment(
        request_id="req-strong",
        client_ip="1.2.3.4",
        threat_level=ThreatLevel.CRITICAL,
        total_score=45.0,
        signature_matches=[
            SignatureMatch(
                signature_id="SQLI-001",
                category=SignatureCategory.SQLI,
                matched_field=TargetField.QUERY_PARAMS,
                score_weight=45.0,
            )
        ],
    )
    decision_strong = decision_engine.decide(strong_assessment)
    assert decision_strong.action == EnforcementAction.BLOCK

    # 2. Weak / Ambiguous single signal -> Downgraded to CHALLENGE despite CRITICAL score
    weak_assessment = RequestAssessment(
        request_id="req-weak",
        client_ip="9.9.9.9",
        threat_level=ThreatLevel.CRITICAL,
        total_score=45.0,
        positive_violations=[
            PositiveSecurityViolation(
                route_id="/test",
                constraint_name="unknown_param",
                expected="none",
                actual="foo",
                score_weight=45.0,
            )
        ],
    )
    decision_weak = decision_engine.decide(weak_assessment)
    # Evidence maturity invariant prevents single ambiguous signal from blocking!
    assert decision_weak.action == EnforcementAction.CHALLENGE


def test_mode_branching() -> None:
    eng_cfg = EngineConfig()
    assessment = RequestAssessment(
        request_id="req-test",
        client_ip="1.2.3.4",
        threat_level=ThreatLevel.CRITICAL,
        total_score=50.0,
        signature_matches=[
            SignatureMatch(
                signature_id="SQLI-1",
                category=SignatureCategory.SQLI,
                matched_field=TargetField.QUERY_PARAMS,
                score_weight=50.0,
            )
        ],
    )

    # 1. SHADOW Mode
    shadow_engine = DecisionEngine(eng_cfg, EnforcementConfig(mode=EnforcementMode.SHADOW))
    dec_shadow = shadow_engine.decide(assessment)
    assert dec_shadow.mode == EnforcementMode.SHADOW
    assert any("SHADOW mode active" in r for r in dec_shadow.reasons)

    # 2. ASSISTED Mode
    assisted_engine = DecisionEngine(eng_cfg, EnforcementConfig(mode=EnforcementMode.ASSISTED))
    dec_assisted = assisted_engine.decide(assessment)
    assert dec_assisted.mode == EnforcementMode.ASSISTED
    assert any("ASSISTED mode active" in r for r in dec_assisted.reasons)

    # 3. ACTIVE Mode
    active_engine = DecisionEngine(eng_cfg, EnforcementConfig(mode=EnforcementMode.ACTIVE))
    dec_active = active_engine.decide(assessment)
    assert dec_active.mode == EnforcementMode.ACTIVE
    assert dec_active.action == EnforcementAction.BLOCK


@pytest.mark.asyncio
async def test_validation_chain_rejection_stages() -> None:
    store = FakeRuleStore()
    await store.add_allowlist_entry(AllowlistEntry(target="127.0.0.1", reason="admin"))
    enf_cfg = EnforcementConfig(max_bans_per_hour=4)
    api_cfg = ApiConfig(management_cidrs=["10.0.0.0/8"])
    chain = ActionValidationChain(enf_cfg, api_cfg, store)

    # 1. Schema failure (missing reason)
    with pytest.raises(ValidationError, match=r"\[schema\]"):
        await chain.validate_candidate_ban(CandidateBan(target="1.1.1.1", reason=""))

    # 2. Network validity failure
    with pytest.raises(ValidationError, match=r"\[network_validity\]"):
        await chain.validate_candidate_ban(CandidateBan(target="not.an.ip.address", reason="test"))

    # 3. Allowlist collision
    with pytest.raises(ValidationError, match=r"\[allowlist\]"):
        await chain.validate_candidate_ban(CandidateBan(target="127.0.0.1", reason="test"))

    # 4. Safety failure (management CIDR overlap)
    with pytest.raises(ValidationError, match=r"\[safety\]"):
        await chain.validate_candidate_ban(CandidateBan(target="10.1.2.3", reason="test"))

    # 4b. Safety failure (overly broad CIDR /16 on IPv4)
    with pytest.raises(ValidationError, match=r"\[safety\]: CIDR /16 is overly broad"):
        await chain.validate_candidate_ban(CandidateBan(target="192.168.0.0/16", reason="test"))

    # 5. Duplicate check (already banned)
    await store.add_ban(
        BanEntry(
            target="8.8.8.8",
            reason="existing",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    with pytest.raises(ValidationError, match=r"\[duplicate\]"):
        await chain.validate_candidate_ban(CandidateBan(target="8.8.8.8", reason="test"))

    # 6. Expiration check (duration <= 0)
    with pytest.raises(ValidationError, match=r"\[expiration\]"):
        await chain.validate_candidate_ban(
            CandidateBan(target="4.4.4.4", reason="test", duration_seconds=0)
        )

    # 7. Authorization check
    with pytest.raises(ValidationError, match=r"\[authorization\]"):
        await chain.validate_candidate_ban(
            CandidateBan(target="4.4.4.4", reason="test"), authorized=False
        )

    # 8. Rate cap check (max 2 per hour on fresh limiter)
    rate_limited_chain = ActionValidationChain(
        EnforcementConfig(max_bans_per_hour=2), api_cfg, store
    )
    valid_ban1 = await rate_limited_chain.validate_candidate_ban(
        CandidateBan(target="5.5.5.1", reason="test")
    )
    assert valid_ban1.target == "5.5.5.1"
    valid_ban2 = await rate_limited_chain.validate_candidate_ban(
        CandidateBan(target="5.5.5.2", reason="test")
    )
    assert valid_ban2.target == "5.5.5.2"
    with pytest.raises(ValidationError, match=r"\[rate_cap\]"):
        await rate_limited_chain.validate_candidate_ban(
            CandidateBan(target="5.5.5.3", reason="test")
        )


@pytest.mark.asyncio
async def test_allowlist_unconditional_override() -> None:
    store = FakeRuleStore()
    await store.add_allowlist_entry(AllowlistEntry(target="192.168.1.50", reason="Partner IP"))
    manager = AllowlistManager(store)
    assert await manager.is_allowlisted("192.168.1.50")
    assert not await manager.is_allowlisted("192.168.1.99")

    # Critical threat request from allowlisted IP must resolve to ALLOW
    eng_cfg = EngineConfig()
    enf_cfg = EnforcementConfig(mode=EnforcementMode.ACTIVE)
    decision_engine = DecisionEngine(eng_cfg, enf_cfg)

    assessment = RequestAssessment(
        request_id="req-allowed",
        client_ip="192.168.1.50",
        threat_level=ThreatLevel.CRITICAL,
        total_score=100.0,
        signature_matches=[
            SignatureMatch(
                signature_id="SQLI-1",
                category=SignatureCategory.SQLI,
                matched_field=TargetField.QUERY_PARAMS,
                score_weight=100.0,
            )
        ],
    )
    decision = decision_engine.decide(assessment, is_allowlisted=True)
    assert decision.action == EnforcementAction.ALLOW
    assert "Allowlisted source IP" in decision.reasons[0]


@pytest.mark.asyncio
async def test_kill_switch_engagement() -> None:
    store = FakeRuleStore()
    sink = FakeEventSink()
    enf_cfg = EnforcementConfig(mode=EnforcementMode.ACTIVE)

    # Populate active bans & allowlist
    await store.add_ban(
        BanEntry(
            target="1.1.1.1",
            reason="attack",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    await store.add_allowlist_entry(AllowlistEntry(target="127.0.0.1", reason="admin"))

    assert len(await store.list_active_bans()) == 1
    assert len(await store.list_allowlist()) == 1

    ks = KillSwitchService(enf_cfg, store, sink)
    result = await ks.engage(operator="admin_alice", reason="False positive cascade")

    assert result["status"] == "engaged"
    assert enf_cfg.mode == EnforcementMode.SHADOW
    assert len(await store.list_active_bans()) == 0
    # Allowlist must remain untouched
    assert len(await store.list_allowlist()) == 1
    assert len(sink.events) == 1
    assert sink.events[0].severity == "critical"


@pytest.mark.asyncio
async def test_full_pipeline_active_vs_shadow() -> None:
    rules = load_all_rules_from_dir("config/rules")
    sig_engine = SignatureEngine(rules, paranoia_level=ParanoiaLevel.PL1)
    pos_engine = PositiveSecurityEngine([])
    store = FakeRuleStore()
    upstream = FakeUpstreamClient(status_code=200, body=b"Hello from App")

    # 1. ACTIVE Mode Pipeline
    cfg_active = WaffyConfig()
    cfg_active.enforcement.mode = EnforcementMode.ACTIVE
    app_active = WaffyPipelineApplication(
        config=cfg_active,
        upstream_client=upstream,
        rule_store=store,
        signature_engine=sig_engine,
        positive_engine=pos_engine,
    )

    transport_active = httpx.ASGITransport(app=app_active)
    async with httpx.AsyncClient(
        transport=transport_active, base_url="http://testserver"
    ) as client:
        # Clear SQLi attack in ACTIVE mode -> 403 Forbidden
        attack_url = "/search?q=1+UNION+SELECT+null,username,password+FROM+users"
        resp_attack = await client.get(attack_url)
        assert resp_attack.status_code == 403
        data = resp_attack.json()
        assert data["error"] == "Forbidden"
        assert "password" not in data.get("message", "")  # Never echoes matched payload!

    # 2. SHADOW Mode Pipeline
    cfg_shadow = WaffyConfig()
    cfg_shadow.enforcement.mode = EnforcementMode.SHADOW
    app_shadow = WaffyPipelineApplication(
        config=cfg_shadow,
        upstream_client=upstream,
        rule_store=store,
        signature_engine=sig_engine,
        positive_engine=pos_engine,
    )

    transport_shadow = httpx.ASGITransport(app=app_shadow)
    async with httpx.AsyncClient(
        transport=transport_shadow, base_url="http://testserver"
    ) as client:
        # Clear SQLi attack in SHADOW mode -> Forwarded to upstream with 200 OK
        resp_shadow = await client.get(attack_url)
        assert resp_shadow.status_code == 200
        assert resp_shadow.content == b"Hello from App"
