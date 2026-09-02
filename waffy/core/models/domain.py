"""Pydantic v2 core domain models for waffy."""

from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from waffy.core.enums import (
    EnforcementAction,
    EnforcementMode,
    EventSeverity,
    HttpMethod,
    ParanoiaLevel,
    RuleStatus,
    SecurityEventType,
    SignatureCategory,
    TargetField,
    ThreatLevel,
)


class TLSInfo(BaseModel):
    """TLS connection metadata if terminated or forwarded via proxy."""

    version: str = "TLSv1.3"
    cipher_suite: str = ""
    client_cert_sha256: str | None = None
    ja3_fingerprint: str | None = None
    ja4_fingerprint: str | None = None


class HttpRequestRecord(BaseModel):
    """Internal canonical representation of an incoming HTTP request."""

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    method: HttpMethod
    path: str
    raw_path: str = ""
    query_string: str = ""
    raw_query_string: str = ""
    query_params: dict[str, list[str]] = Field(default_factory=dict)
    headers: list[tuple[str, str]] = Field(default_factory=lambda: list[tuple[str, str]]())
    cookies: dict[str, str] = Field(default_factory=dict)
    client_ip: str
    client_port: int = Field(default=0, ge=0, le=65535)
    tls_info: TLSInfo | None = None
    raw_body_size: int = Field(default=0, ge=0)
    parsed_body_summary: dict[str, Any] = Field(default_factory=dict)
    encoding_layers: int = Field(default=1, ge=1)

    @field_validator("timestamp")
    @classmethod
    def ensure_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v

    @field_validator("client_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            _ = IPv4Address(v) if "." in v else IPv6Address(v)
        except Exception as e:
            raise ValueError(f"Invalid IP address: '{v}'") from e
        return v


class Signature(BaseModel):
    """Negative-security detection signature rule definition."""

    id: str
    category: SignatureCategory
    pattern: str
    paranoia_level: ParanoiaLevel = ParanoiaLevel.PL1
    target_fields: list[TargetField] = Field(
        default_factory=lambda: [TargetField.PATH, TargetField.QUERY_PARAMS]
    )
    score_weight: float = Field(default=5.0, ge=0.0)
    description: str = ""
    references: list[str] = Field(default_factory=list)
    enabled: bool = True


class SignatureMatch(BaseModel):
    """Evidence record for a signature pattern hit."""

    signature_id: str
    category: SignatureCategory
    matched_field: TargetField
    field_name: str | None = None
    matched_snippet: str = ""  # redacted/truncated snippet
    offset: int = 0
    score_weight: float = Field(default=5.0, ge=0.0)


class AnomalyEvidence(BaseModel):
    """Statistical/ML anomaly evidence output."""

    model_id: str
    model_version: str
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    feature_vector_version: str = "v1"
    is_anomaly: bool = False
    details: dict[str, float] = Field(default_factory=dict)


class PositiveSecurityViolation(BaseModel):
    """Evidence record for positive-security / OpenAPI constraint violation."""

    route_id: str
    constraint_name: str
    parameter_name: str | None = None
    expected: str
    actual: str
    score_weight: float = Field(default=5.0, ge=0.0)


class RateLimitState(BaseModel):
    """Rate limiter status and velocity for client/session."""

    key: str = "default"
    limit: int = 100
    remaining: int = 100
    reset_seconds: float = 60.0
    scope: str = "ip"
    current_rate: int = 0
    retry_after_seconds: int = 0
    exceeded: bool = False
    tripped: bool = False


class BotAssessment(BaseModel):
    """Heuristic bot evaluation score and flags."""

    bot_score: float = Field(default=0.0, ge=0.0, le=1.0)
    is_bot: bool = False
    category: str | None = None
    matched_heuristics: list[str] = Field(default_factory=list)
    ja3_matched_bad: bool = False
    honeypot_triggered: bool = False
    timing_regularity_score: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class CsrfViolation(BaseModel):
    """Evidence: a state-changing request failed CSRF token validation."""

    route: str
    reason: Literal["missing_token", "invalid_token"]


class CredentialStuffingEvidence(BaseModel):
    """Evidence: failed-login velocity already tripped for this request's
    source IP or targeted account, based on failures recorded from prior
    responses (never mutated by the current request's own outcome).
    """

    tripped: bool = False
    scope: Literal["ip", "account", ""] = ""
    reason: str = ""


class RequestAssessment(BaseModel):
    """Aggregated security evidence collected across all inspection layers for one request."""

    request_id: str
    client_ip: str
    signature_matches: list[SignatureMatch] = Field(
        default_factory=lambda: list[SignatureMatch]()
    )
    anomaly_evidence: AnomalyEvidence | None = None
    positive_violations: list[PositiveSecurityViolation] = Field(
        default_factory=lambda: list[PositiveSecurityViolation]()
    )
    bot_assessment: BotAssessment | None = None
    rate_limit_state: RateLimitState | None = None
    csrf_violation: CsrfViolation | None = None
    credential_stuffing_evidence: CredentialStuffingEvidence | None = None
    total_score: float = Field(default=0.0, ge=0.0)
    threat_level: ThreatLevel = ThreatLevel.LOW


class Decision(BaseModel):
    """Outcome decision computed from RequestAssessment and mode policy."""

    request_id: str
    action: EnforcementAction = EnforcementAction.ALLOW
    mode: EnforcementMode = EnforcementMode.SHADOW
    threat_level: ThreatLevel = ThreatLevel.LOW
    reasons: list[str] = Field(default_factory=list)
    evidence_summary: dict[str, Any] = Field(default_factory=dict)


class BanEntry(BaseModel):
    """Active or historical persistent ban record."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    target: str  # IP or CIDR
    scope: str = "global"
    reason: str
    evidence_refs: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    status: RuleStatus = RuleStatus.ACTIVE

    @field_validator("created_at", "expires_at")
    @classmethod
    def ensure_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        try:
            if "/" in v:
                _ = IPv4Network(v, strict=False) if "." in v else IPv6Network(v, strict=False)
            else:
                _ = IPv4Address(v) if "." in v else IPv6Address(v)
        except Exception as e:
            raise ValueError(f"Invalid target IP/CIDR '{v}': {e}") from e
        return v


class CandidateBan(BaseModel):
    """Candidate ban proposing a new BanEntry before passing through validation chain."""

    target: str
    scope: str = "global"
    reason: str
    evidence_refs: list[str] = Field(default_factory=list)
    duration_seconds: int = 3600
    status: RuleStatus = RuleStatus.CANDIDATE


class AllowlistEntry(BaseModel):
    """Admin-declared allowlist entry outranking all adaptive decisions."""

    target: str  # IP or CIDR
    reason: str = "Admin allowlist"
    created_by: str = "admin"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("created_at")
    @classmethod
    def ensure_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        try:
            if "/" in v:
                _ = IPv4Network(v, strict=False) if "." in v else IPv6Network(v, strict=False)
            else:
                _ = IPv4Address(v) if "." in v else IPv6Address(v)
        except Exception as e:
            raise ValueError(f"Invalid allowlist IP/CIDR '{v}': {e}") from e
        return v


class VirtualPatchRule(BaseModel):
    """Virtual patch signature / rule addressing a specific vulnerability or CVE."""

    id: str
    cve_id: str
    target_path_regex: str
    match_conditions: dict[str, str] = Field(default_factory=dict)
    action: EnforcementAction = EnforcementAction.BLOCK
    expires_at: datetime | None = None
    status: RuleStatus = RuleStatus.ACTIVE


class SecurityEvent(BaseModel):
    """Structured security event for logging, audit trail, and SIEM forwarder."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    type: SecurityEventType
    severity: EventSeverity
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_ip: str
    correlation_id: str
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def ensure_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            _ = IPv4Address(v) if "." in v else IPv6Address(v)
        except Exception as e:
            raise ValueError(f"Invalid source IP '{v}': {e}") from e
        return v


class ModelMetadata(BaseModel):
    """Metadata tracking trained anomaly model version and parameters."""

    model_id: str
    route_id: str
    version: str
    trained_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    sample_count: int = Field(ge=0)
    feature_names: list[str] = Field(default_factory=list)
    threshold: float = 0.75
