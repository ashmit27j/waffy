"""waffy core enumeration types.

All enums representing domain vocabulary across detection, scoring, decision,
and enforcement.
"""

from enum import IntEnum, StrEnum


class ThreatLevel(StrEnum):
    """Threat level categories assigned based on cumulative assessment scores."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EnforcementAction(StrEnum):
    """Actions that the enforcement layer can take."""

    ALLOW = "allow"
    LOG = "log"
    CHALLENGE = "challenge"
    RATE_LIMIT = "rate_limit"
    BLOCK = "block"


class EnforcementMode(StrEnum):
    """Global operational mode for waffy.

    - SHADOW: Inspect and score all traffic, log decisions, but never block or challenge.
    - ASSISTED: Auto-apply low-risk actions, queue high-risk actions for operator review.
    - ACTIVE: Enforce all decisions inline per the decision matrix.
    """

    SHADOW = "shadow"
    ASSISTED = "assisted"
    ACTIVE = "active"


class FailureMode(StrEnum):
    """Operational behavior when waffy encounters an internal error or overload."""

    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"


class RuleStatus(StrEnum):
    """Lifecycle status for dynamic bans, virtual patch rules, and rate limits."""

    CANDIDATE = "candidate"
    VALIDATING = "validating"
    REJECTED = "rejected"
    SHADOWED = "shadowed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DEPLOYED = "deployed"
    ACTIVE = "active"
    EXPIRED = "expired"
    DISABLED = "disabled"
    REMOVED = "removed"


class SignatureCategory(StrEnum):
    """Categories of negative-security detection signatures."""

    SQLI = "sqli"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    LFI_RFI = "lfi_rfi"
    SSTI = "ssti"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    CRLF_INJECTION = "crlf_injection"
    OPEN_REDIRECT = "open_redirect"
    SSRF = "ssrf"
    SCANNER_FINGERPRINT = "scanner_fingerprint"
    VIRTUAL_PATCH = "virtual_patch"
    CUSTOM = "custom"


class ParanoiaLevel(IntEnum):
    """CRS Paranoia Levels governing sensitivity vs false positive trade-off."""

    PL1 = 1
    PL2 = 2
    PL3 = 3
    PL4 = 4


class HttpMethod(StrEnum):
    """Explicitly supported HTTP methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    CONNECT = "CONNECT"


class SecurityEventType(StrEnum):
    """Types of security events recorded for logging, audits, and SIEM."""

    REQUEST_DECISION = "request_decision"
    REQUEST_MALFORMED = "request_malformed"
    SIGNATURE_MATCH = "signature_match"
    POSITIVE_VIOLATION = "positive_violation"
    ANOMALY_DETECTED = "anomaly_detected"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    BOT_DETECTED = "bot_detected"
    BAN_CREATED = "ban_created"
    BAN_EXPIRED = "ban_expired"
    BAN_REMOVED = "ban_removed"
    RULE_RELOADED = "rule_reloaded"
    RULE_ENGINE_BUDGET_EXCEEDED = "rule_engine_budget_exceeded"
    KILL_SWITCH_ENGAGED = "kill_switch_engaged"
    INTERNAL_ERROR = "internal_error"


class EventSeverity(StrEnum):
    """Severity levels for emitted security events."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TargetField(StrEnum):
    """Target request locations inspected by detection signatures."""

    PATH = "path"
    QUERY_PARAMS = "query_params"
    HEADERS = "headers"
    COOKIES = "cookies"
    BODY_FIELDS = "body_fields"
    RAW_BODY = "raw_body"
    METHOD = "method"
