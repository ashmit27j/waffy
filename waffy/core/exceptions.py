"""waffy typed exception hierarchy.

All exceptions inherit from WaffyError. Each documents when it is raised
and whether the in-flight request proceeds (fail-open) or refuses service.
"""


class WaffyError(Exception):
    """Base exception for all waffy-specific errors."""

    def __init__(self, message: str, details: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(WaffyError):
    """Raised when configuration file is missing, invalid TOML, or violates schema constraints.

    Process fails closed at startup.
    """


class TransportError(WaffyError):
    """Raised when transport/connection errors occur (socket bind failure, upstream drop).

    If in request path and fail_open is configured, traffic is allowed through if feasible.
    """


class RequestMalformedError(WaffyError):
    """Raised when request parsing encounters ambiguous/malformed HTTP framing.

    Examples: CL/TE smuggling, bad chunking.
    Request is rejected immediately with 400 Bad Request at the transport layer,
    even in SHADOW mode.
    """


class RuleLoadError(WaffyError):
    """Raised during rule parsing/compilation if a signature file is malformed or invalid regex.

    Process fails closed at startup or hot-reload rejects new rule candidate without
    dropping existing rules.
    """


class RuleEngineBudgetExceededError(WaffyError):
    """Raised when regex/pattern matching against a request exceeds the time/step budget.

    Non-fatal: logged as RULE_ENGINE_BUDGET_EXCEEDED, and request proceeds through remaining
    collected evidence.
    """


class ModelLoadError(WaffyError):
    """Raised when ML model artifacts fail to load or are corrupted.

    Non-fatal: system falls back to signature-only scoring mode.
    """


class ModelInferenceError(WaffyError):
    """Raised when feature extraction or inference fails on a request.

    Non-fatal: anomaly evidence is omitted, and request proceeds through signature/rule scoring.
    """


class EnforcementError(WaffyError):
    """Raised when an enforcement action execution fails (e.g. state store persistence error).

    Request fails open per configured policy.
    """


class ValidationError(WaffyError):
    """Raised when a candidate enforcement action (ban/rule) fails validation chain checks.

    Rejects candidate action; details explain specific chain stage failure.
    """


class AuthenticationError(WaffyError):
    """Raised when an unauthorized or unauthenticated request touches the management API.

    API returns 401/403.
    """


class IntegrationError(WaffyError):
    """Raised when an external integration encounters an error.

    Examples: SIEM forwarder or metrics export failure.
    Logged without halting request flow.
    """
