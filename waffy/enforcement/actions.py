"""Enforcement actions execution for current request.

CLAUDE.md Non-negotiable rule:
Exactly one authorized code path may take an enforcement action.
- ALLOW: forward to upstream unmodified.
- LOG: forward to upstream + record SecurityEvent.
- RATE_LIMIT: respond 429 + Retry-After.
- BLOCK: respond 403 with generic non-leaking body (never echo matched payloads).
- CHALLENGE: respond with JS proof-of-work challenge or verification page.
"""

import logging

from starlette.responses import Response

from waffy.config.models import EnforcementConfig
from waffy.core.enums import EnforcementAction, EnforcementMode
from waffy.core.interfaces import ChallengeVerifier, UpstreamClient
from waffy.core.models.domain import Decision, HttpRequestRecord

logger = logging.getLogger("waffy.enforcement.actions")


class EnforcementExecutor:
    """The single authorized code path executing enforcement actions."""

    def __init__(
        self,
        config: EnforcementConfig,
        upstream_client: UpstreamClient,
        challenge_verifier: ChallengeVerifier | None = None,
    ) -> None:
        self.config = config
        self.upstream = upstream_client
        self.challenge_verifier = challenge_verifier

    async def execute(
        self,
        request: HttpRequestRecord,
        raw_body_bytes: bytes,
        decision: Decision,
    ) -> Response:
        """Execute decision action considering active enforcement mode."""
        # SHADOW mode: always forward traffic to upstream unmodified regardless of proposed action
        if decision.mode == EnforcementMode.SHADOW:
            logger.info(
                "SHADOW [Request %s from %s]: proposed action=%s, score=%s, reasons=%s",
                request.request_id,
                request.client_ip,
                decision.action.value,
                decision.evidence_summary.get("total_score", 0.0),
                decision.reasons,
            )
            return await self._forward_upstream(request, raw_body_bytes)

        # ASSISTED mode: route high-risk actions to pending or auto-apply low-risk
        if decision.mode == EnforcementMode.ASSISTED and decision.action in (
            EnforcementAction.BLOCK,
            EnforcementAction.RATE_LIMIT,
        ):
            logger.warning(
                "ASSISTED [Request %s from %s]: action %s pending operator approval; forwarding",
                request.request_id,
                request.client_ip,
                decision.action.value,
            )
            return await self._forward_upstream(request, raw_body_bytes)

        # ACTIVE mode or auto-applied action
        if decision.action in (EnforcementAction.ALLOW, EnforcementAction.LOG):
            return await self._forward_upstream(request, raw_body_bytes)

        if decision.action == EnforcementAction.BLOCK:
            return self._build_block_response(request, decision)

        if decision.action == EnforcementAction.RATE_LIMIT:
            return self._build_rate_limit_response()

        if decision.action == EnforcementAction.CHALLENGE:
            return self._build_challenge_response(request)

        # Fallback safety
        return await self._forward_upstream(request, raw_body_bytes)

    async def _forward_upstream(
        self,
        request: HttpRequestRecord,
        raw_body_bytes: bytes,
    ) -> Response:
        """Forward request to upstream app and return client response."""
        try:
            status_code, resp_headers, resp_body = await self.upstream.forward(
                request, raw_body_bytes
            )
            clean_headers: dict[str, str] = {}
            for hk, hv in resp_headers:
                if hk.lower() not in ("transfer-encoding", "connection"):
                    clean_headers[hk] = hv

            return Response(
                content=resp_body,
                status_code=status_code,
                headers=clean_headers,
            )
        except Exception as e:
            logger.error("Upstream forward error for request %s: %s", request.request_id, e)
            return Response(
                content=b'{"error": "Bad Gateway", "message": "Upstream unavailable"}',
                status_code=502,
                media_type="application/json",
            )

    def _build_block_response(
        self,
        request: HttpRequestRecord,
        decision: Decision,
    ) -> Response:
        """Construct generic, non-leaking block response (never echo matched payload)."""
        _ = decision
        generic_body = (
            f'{{"error": "Forbidden", "message": "Access Denied", '
            f'"request_id": "{request.request_id}"}}'
        )
        return Response(
            content=generic_body.encode(),
            status_code=self.config.block_status_code,
            media_type="application/json",
        )

    def _build_rate_limit_response(self) -> Response:
        """Construct 429 Too Many Requests response with Retry-After header."""
        return Response(
            content=b'{"error": "Too Many Requests", "message": "Rate limit exceeded"}',
            status_code=429,
            headers={"Retry-After": "60"},
            media_type="application/json",
        )

    def _build_challenge_response(self, request: HttpRequestRecord) -> Response:
        """Generate challenge / CAPTCHA response for client verification."""
        if self.challenge_verifier:
            chal_data = self.challenge_verifier.generate_challenge(request.client_ip)
            chal_id = chal_data.get("challenge_id")
            html = (
                f"<html><body><h2>Security Verification</h2>"
                f"<div id='challenge' data-id='{chal_id}'>Please complete verification</div>"
                f"</body></html>"
            )
        else:
            html = "<html><body><h2>Security Verification Required</h2></body></html>"

        return Response(
            content=html.encode(),
            status_code=403,
            media_type="text/html",
        )
