"""Full pipeline orchestrator connecting:
transport -> parse -> normalize
-> detect (signatures + positive + anomaly + bot + ratelimit + csrf + credential-stuffing)
-> score -> decide -> enforce -> cookie rewriting.
"""

import logging
from collections.abc import Callable, MutableMapping
from typing import Any

from starlette.requests import Request
from starlette.responses import Response

from waffy.config.models import WaffyConfig
from waffy.core.enums import EnforcementAction, HttpMethod
from waffy.core.exceptions import RequestMalformedError
from waffy.core.interfaces import ChallengeVerifier, EventSink, RuleStore, UpstreamClient
from waffy.core.models.domain import (
    CredentialStuffingEvidence,
    CsrfViolation,
    HttpRequestRecord,
    RequestAssessment,
)
from waffy.detection.anomaly.scorer import AnomalyScorer
from waffy.detection.bot.engine import BotDetectionEngine
from waffy.detection.positive.models import PositiveSecurityEngine
from waffy.detection.ratelimit.engine import RateLimitEngine
from waffy.detection.session.services import (
    CookieSecurityRewriter,
    CredentialStuffingDetector,
    CsrfProtector,
)
from waffy.detection.signatures.engine import SignatureEngine
from waffy.enforcement.actions import EnforcementExecutor
from waffy.enforcement.allowlist import AllowlistManager
from waffy.engine.decision import DecisionEngine
from waffy.engine.scoring import compute_assessment_score
from waffy.http.limits import TransportResourceProtector
from waffy.http.parser import parse_asgi_request

logger = logging.getLogger("waffy.pipeline")

# CSRF only applies to state-changing methods -- GET/HEAD/OPTIONS/TRACE/CONNECT
# never carry a token to validate.
_CSRF_UNSAFE_METHODS = frozenset(
    {HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE}
)

# Common login-form field names, checked in order, for best-effort per-account
# (not just per-IP) credential-stuffing velocity tracking.
_ACCOUNT_FIELD_NAMES = ("username", "user", "email", "login")


def _extract_account_identifier(record: HttpRequestRecord) -> str | None:
    """Best-effort extraction of a submitted account identifier from a login
    request body, for per-account credential-stuffing velocity tracking.
    Only understands the two shapes ``waffy/http/body.py`` produces for JSON
    and form-urlencoded bodies -- the realistic content types for an HTML or
    API login form. Returns None on any other shape (e.g. multipart) rather
    than guessing; per-IP tracking still applies regardless.
    """
    summary = record.parsed_body_summary
    for field in _ACCOUNT_FIELD_NAMES:
        if field not in summary:
            continue
        value = summary[field]
        if isinstance(value, str):
            return value
        if isinstance(value, list) and value and isinstance(value[0], str):
            return value[0]
    return None


class WaffyPipelineApplication:
    """Complete inline request pipeline application."""

    def __init__(
        self,
        config: WaffyConfig,
        upstream_client: UpstreamClient,
        rule_store: RuleStore,
        signature_engine: SignatureEngine,
        positive_engine: PositiveSecurityEngine,
        anomaly_scorer: AnomalyScorer | None = None,
        challenge_verifier: ChallengeVerifier | None = None,
        event_sink: EventSink | None = None,
        tls_fingerprint_lookup: Callable[[str, int], str | None] | None = None,
    ) -> None:
        self.config = config
        self.upstream = upstream_client
        self.rule_store = rule_store
        self.signature_engine = signature_engine
        self.positive_engine = positive_engine
        self.anomaly_scorer = anomaly_scorer
        self.event_sink = event_sink
        # Optional: looks up a real, connection-level TLS ClientHello
        # fingerprint by (client_ip, client_port). Supplied by
        # waffy/proxy/standalone.py's TlsFingerprintRegistry.get in TLS
        # standalone mode; None (the default) in plaintext/middleware modes,
        # matching plaintext.py's documented "TLS signals absent, stays
        # neutral" contract. Kept as a plain Callable — not a direct import
        # of the proxy layer — to preserve the one-way
        # core -> config -> http -> detection -> engine -> enforcement -> proxy
        # module dependency flow from CLAUDE.md.
        self.tls_fingerprint_lookup = tls_fingerprint_lookup

        self.resource_protector = TransportResourceProtector(config.http_limits)
        self.rate_limit_engine = RateLimitEngine(config.rate_limiting)
        self.bot_engine = BotDetectionEngine(config.bot_detection)
        self.cookie_rewriter = CookieSecurityRewriter(
            enforce_secure=config.cookie_security.enforce_secure,
            enforce_httponly=config.cookie_security.enforce_httponly,
            samesite_policy=config.cookie_security.samesite_policy,
        )
        self.csrf_protector = CsrfProtector(secret_key=config.csrf.secret_key)
        self.credential_stuffing_detector = CredentialStuffingDetector(
            config.credential_stuffing
        )

        self.allowlist_manager = AllowlistManager(rule_store)
        self.decision_engine = DecisionEngine(config.engine, config.enforcement)
        self.executor = EnforcementExecutor(
            config.enforcement, upstream_client, challenge_verifier
        )

    def _check_csrf(self, record: HttpRequestRecord) -> CsrfViolation | None:
        """CSRF token evidence per MASTER_SPEC.md Section 10: token-based
        validation is what embedded-middleware mode relies on (proxy modes
        use a not-yet-implemented header-based check instead, per
        CsrfConfig's docstring), so this only ever produces evidence when
        ``transport.mode == "embedded"``. Only checked for state-changing
        methods, and only when a session cookie is present -- an anonymous
        POST with no session has no CSRF-protected state to defend.
        """
        if not self.config.csrf.enabled:
            return None
        if self.config.transport.mode != "embedded":
            return None
        if record.method not in _CSRF_UNSAFE_METHODS:
            return None

        session_id = record.cookies.get("session_id")
        if not session_id:
            return None

        token: str | None = None
        for hk, hv in record.headers:
            if hk.lower() == "x-csrf-token":
                token = hv
                break

        if not token:
            return CsrfViolation(route=record.path, reason="missing_token")

        if not self.csrf_protector.validate_token(
            session_id, token, max_age_seconds=self.config.csrf.max_age_seconds
        ):
            return CsrfViolation(route=record.path, reason="invalid_token")

        return None

    def _check_credential_stuffing(
        self, record: HttpRequestRecord
    ) -> CredentialStuffingEvidence | None:
        """Peek at failed-login velocity already recorded for this request's
        source IP / targeted account (from prior responses -- see the
        post-response recording in ``__call__``). Evidence-only: never
        records a new failed attempt itself.
        """
        if not self.config.credential_stuffing.enabled:
            return None
        if not self.credential_stuffing_detector.is_configured():
            return None

        account = _extract_account_identifier(record)
        tripped, scope, reason = self.credential_stuffing_detector.check_velocity(
            record.client_ip, account=account
        )
        if not tripped:
            return None
        return CredentialStuffingEvidence(tripped=True, scope=scope, reason=reason)

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        if scope["type"] != "http":
            response = Response(b"Not Implemented", status_code=501)
            await response(scope, receive, send)
            return

        client_ip = scope.get("client", ("127.0.0.1", 0))[0]

        # 0. Transport Resource Protection Limits (Direct connection bounds)
        acquired, limit_resp = await self.resource_protector.acquire_slot(client_ip)
        if not acquired and limit_resp is not None:
            await limit_resp(scope, receive, send)
            return

        try:
            request = Request(scope, receive)

            # 1. Transport & Parsing with Smuggling / Ambiguity checks
            try:
                record, raw_body = await parse_asgi_request(request, self.config.http)
            except RequestMalformedError as e:
                response = Response(
                    content=f'{{"error": "Bad Request", "reason": "{e.message}"}}'.encode(),
                    status_code=400,
                    media_type="application/json",
                )
                await response(scope, receive, send)
                return

            # 2. Check Allowlist (Unconditional override)
            is_allowed = await self.allowlist_manager.is_allowlisted(record.client_ip)

            # 3. Detection: Signatures
            sig_matches = self.signature_engine.match(record, raw_body)

            # 4. Detection: Positive Security
            pos_violations = self.positive_engine.validate(record)

            # 5. Detection: ML Anomaly evidence
            route_config = self.positive_engine.get_route_config(record.path)
            route_id = route_config.route_id if route_config else "default"
            anomaly_ev = None
            if self.anomaly_scorer:
                anomaly_ev = self.anomaly_scorer.score(route_id, record, raw_body)

            # 6. Detection: Rate Limiting
            rate_limit_st = self.rate_limit_engine.evaluate(record)

            # 7. Detection: Bot assessment (including real TLS fingerprint
            # evidence when a lookup was wired in for this listener)
            tls_fingerprint = None
            if self.tls_fingerprint_lookup is not None:
                tls_fingerprint = self.tls_fingerprint_lookup(
                    record.client_ip, record.client_port
                )
            bot_assess = self.bot_engine.assess(record, tls_fingerprint=tls_fingerprint)

            # 8. Detection: CSRF token validation (evidence only)
            csrf_violation = self._check_csrf(record)

            # 9. Detection: Credential-stuffing velocity (evidence only, from
            # failures already recorded by prior responses -- see step 13)
            cred_stuffing_ev = self._check_credential_stuffing(record)

            # 10. Aggregate Evidence into RequestAssessment
            assessment = RequestAssessment(
                request_id=record.request_id,
                client_ip=record.client_ip,
                signature_matches=sig_matches,
                anomaly_evidence=anomaly_ev,
                positive_violations=pos_violations,
                rate_limit_state=rate_limit_st,
                bot_assessment=bot_assess,
                csrf_violation=csrf_violation,
                credential_stuffing_evidence=cred_stuffing_ev,
            )

            # 11. Scoring: compute total score & threat level
            compute_assessment_score(assessment, self.config.engine)

            # 12. Decision: mode-aware decision with evidence-maturity invariant
            decision = self.decision_engine.decide(assessment, is_allowlisted=is_allowed)

            # 13. Enforcement: Single authorized execution point
            response = await self.executor.execute(record, raw_body, decision)

            # 14. Credential-stuffing bookkeeping: if this request hit a
            # configured login route and the response indicates a failed
            # login, record it so *future* requests see updated velocity
            # evidence in step 9. Never affects this request's own decision.
            # Gated on decision.action being ALLOW/LOG so a waffy-generated
            # BLOCK/CHALLENGE response (also status 403 by default) is never
            # misread as the upstream application's own login failure.
            if (
                self.config.credential_stuffing.enabled
                and self.credential_stuffing_detector.is_configured()
                and decision.action in (EnforcementAction.ALLOW, EnforcementAction.LOG)
                and record.path in self.config.credential_stuffing.login_failure_routes
                and response.status_code in (401, 403)
            ):
                account = _extract_account_identifier(record)
                self.credential_stuffing_detector.record_failed_attempt(
                    record.client_ip, account=account
                )

            # 15. Response-side Cookie Attribute Enforcement
            if self.config.cookie_security.enabled and "set-cookie" in response.headers:
                raw_cookie = response.headers["set-cookie"]
                response.headers["set-cookie"] = self.cookie_rewriter.rewrite_set_cookie_header(
                    raw_cookie
                )

            await response(scope, receive, send)
        finally:
            await self.resource_protector.release_slot(client_ip)
