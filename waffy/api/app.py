"""waffy/api/app.py — FastAPI management API for waffy.

Process isolation guarantee
---------------------------
This module MUST NOT import anything from:
  - waffy.enforcement
  - waffy.detection
  - waffy.proxy
  - waffy.engine
  - waffy.http.pipeline

All state access goes through ``waffy.ipc.client.IpcClient``.
This constraint is enforced by ``tests/unit/test_phase8_api.py`` via a
static import-graph walk.

Authentication
--------------
Bearer token via ``Authorization: Bearer <token>`` header.
Token is configured in ``WaffyConfig.api.api_token``.
Requests from outside ``WaffyConfig.api.management_cidrs`` are rejected
with 403 before the token check.

Endpoints (full reference: docs/API.md)
----------------------------------------
GET  /api/v1/health                  — liveness + IPC reachability
GET  /api/v1/status                  — current mode, ban count, etc.
GET  /api/v1/events                  — recent SecurityEvent feed
GET  /api/v1/requests                — recent RequestAssessment feed
GET  /api/v1/bans                    — active ban list
DELETE /api/v1/bans/{ban_id}         — expire/delete ban
GET  /api/v1/allowlist               — allowlist entries
POST /api/v1/allowlist               — add allowlist entry
DELETE /api/v1/allowlist/{target}    — remove allowlist entry
GET  /api/v1/patches                 — virtual patch rules
GET  /api/v1/pending                 — pending-approval queue
POST /api/v1/pending/{ban_id}/approve — approve pending ban
POST /api/v1/pending/{ban_id}/reject  — reject pending ban
GET  /api/v1/models/candidates       — pending anomaly-model candidates awaiting promotion
POST /api/v1/models/candidates/{route_id}/{version}/promote — promote a candidate model
POST /api/v1/models/candidates/{route_id}/{version}/reject  — reject a candidate model
GET  /api/v1/mode                    — get current enforcement mode
POST /api/v1/mode                    — set enforcement mode
POST /api/v1/killswitch              — engage emergency kill-switch
POST /api/v1/rules/reload            — trigger rule-set reload
GET  /metrics                        — Prometheus text metrics (unauthenticated)
GET  /api/v1/metrics                 — JSON metrics snapshot (authenticated)
"""

from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse

from waffy.api.auth import AuthGuard
from waffy.api.models import (
    AllowlistActionResponse,
    AllowlistResponse,
    BanActionResponse,
    BanListResponse,
    CandidateModelsResponse,
    CreateAllowlistRequest,
    EventsResponse,
    HealthResponse,
    KillswitchRequest,
    MetricsSnapshotResponse,
    ModeResponse,
    OkResponse,
    PendingResponse,
    RequestsResponse,
    SetModeRequest,
    VirtualPatchesResponse,
)
from waffy.config.models import WaffyConfig
from waffy.integration.metrics import MetricsRegistry
from waffy.ipc.client import IpcClient, IpcClientError

logger = logging.getLogger("waffy.api")


def build_app(
    config: WaffyConfig,
    ipc: IpcClient,
    metrics: MetricsRegistry,
) -> FastAPI:
    """Build and return the FastAPI application.

    Parameters
    ----------
    config:
        Root ``WaffyConfig``; ``api.api_token`` and ``api.management_cidrs``
        are used for authentication / access control.
    ipc:
        ``IpcClient`` pointed at the waffy-core Unix domain socket.
        All state mutations go through this client.
    metrics:
        ``MetricsRegistry`` with counters to serve at ``/metrics``.
    """
    app = FastAPI(
        title="waffy Management API",
        description=(
            "REST management interface for waffy WAF. "
            "All mutating endpoints route through IPC to waffy-core."
        ),
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    auth = AuthGuard(config)

    # Convenience: create a re-usable dependency for authenticated endpoints.
    def require_auth(auth_result: None = Depends(auth)) -> None:  # noqa: B008
        """FastAPI dependency that enforces auth (CIDR + token) on each request."""

    # ------------------------------------------------------------------ #
    # Health / Status                                                      #
    # ------------------------------------------------------------------ #

    @app.get(
        "/api/v1/health",
        response_model=HealthResponse,
        tags=["health"],
        dependencies=[Depends(auth)],
    )
    async def health() -> HealthResponse:
        """Liveness probe: always returns 200 if the API process is up.

        Also attempts an IPC ``get_mode`` call to report core reachability.
        """
        ipc_ok = False
        try:
            await ipc.get_mode()
            ipc_ok = True
        except IpcClientError:
            ipc_ok = False
        return HealthResponse(ok=True, status="healthy", ipc_reachable=ipc_ok)

    @app.get(
        "/api/v1/status",
        response_model=ModeResponse,
        tags=["health"],
        dependencies=[Depends(auth)],
    )
    async def get_status() -> ModeResponse:
        """Readiness probe: returns current enforcement mode from waffy-core."""
        try:
            mode = await ipc.get_mode()
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"waffy-core IPC unavailable: {exc}",
            ) from exc
        return ModeResponse(ok=True, mode=mode)

    # ------------------------------------------------------------------ #
    # Events & Requests feed                                               #
    # ------------------------------------------------------------------ #

    @app.get(
        "/api/v1/events",
        response_model=EventsResponse,
        tags=["events"],
        dependencies=[Depends(auth)],
    )
    async def list_events(
        limit: int = Query(default=50, ge=1, le=1000),
    ) -> EventsResponse:
        """Return recent ``SecurityEvent`` records from waffy-core's ring buffer."""
        try:
            events = await ipc.read_events(limit=limit)
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        return EventsResponse(events=events, count=len(events))

    @app.get(
        "/api/v1/requests",
        response_model=RequestsResponse,
        tags=["events"],
        dependencies=[Depends(auth)],
    )
    async def list_requests(
        limit: int = Query(default=50, ge=1, le=1000),
    ) -> RequestsResponse:
        """Return recent ``RequestAssessment`` snapshots from waffy-core."""
        try:
            assessments = await ipc.read_requests(limit=limit)
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        return RequestsResponse(assessments=assessments, count=len(assessments))

    # ------------------------------------------------------------------ #
    # Ban list                                                             #
    # ------------------------------------------------------------------ #

    @app.get(
        "/api/v1/bans",
        response_model=BanListResponse,
        tags=["bans"],
        dependencies=[Depends(auth)],
    )
    async def list_bans() -> BanListResponse:
        """List all active bans from waffy-core."""
        try:
            bans = await ipc.read_bans()
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        return BanListResponse(bans=bans, count=len(bans))

    @app.delete(
        "/api/v1/bans/{ban_id}",
        response_model=BanActionResponse,
        tags=["bans"],
        dependencies=[Depends(auth)],
    )
    async def expire_ban(ban_id: str) -> BanActionResponse:
        """Expire / delete a ban by ID (routes through IPC → validation chain)."""
        try:
            await ipc.reject_pending(ban_id=ban_id)
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc
        return BanActionResponse(ok=True, ban_id=ban_id, message="Ban removed.")

    # ------------------------------------------------------------------ #
    # Allowlist                                                            #
    # ------------------------------------------------------------------ #

    @app.get(
        "/api/v1/allowlist",
        response_model=AllowlistResponse,
        tags=["allowlist"],
        dependencies=[Depends(auth)],
    )
    async def list_allowlist() -> AllowlistResponse:
        """List all allowlist entries from waffy-core."""
        try:
            entries = await ipc.read_allowlist()
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        return AllowlistResponse(entries=entries, count=len(entries))

    @app.post(
        "/api/v1/allowlist",
        response_model=AllowlistActionResponse,
        status_code=status.HTTP_201_CREATED,
        tags=["allowlist"],
        dependencies=[Depends(auth)],
    )
    async def add_allowlist(body: CreateAllowlistRequest) -> AllowlistActionResponse:
        """Add an IP/CIDR to the allowlist (routes through IPC → validation chain).

        The validation chain from Phase 5 runs inside waffy-core; invalid entries
        (e.g., overly broad CIDRs rejected by the safety stage) are rejected and
        the validator-stage reason is surfaced in the response.
        """
        try:
            await ipc.add_allowlist(target=body.target, reason=body.reason)
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        return AllowlistActionResponse(ok=True, message=f"Allowlisted {body.target}.")

    @app.delete(
        "/api/v1/allowlist/{target:path}",
        response_model=AllowlistActionResponse,
        tags=["allowlist"],
        dependencies=[Depends(auth)],
    )
    async def remove_allowlist(target: str) -> AllowlistActionResponse:
        """Remove an IP/CIDR from the allowlist."""
        try:
            removed = await ipc.remove_allowlist(target=target)
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc
        return AllowlistActionResponse(ok=True, removed=removed)

    # ------------------------------------------------------------------ #
    # Virtual patches                                                      #
    # ------------------------------------------------------------------ #

    @app.get(
        "/api/v1/patches",
        response_model=VirtualPatchesResponse,
        tags=["patches"],
        dependencies=[Depends(auth)],
    )
    async def list_patches() -> VirtualPatchesResponse:
        """List all virtual patch rules from waffy-core."""
        try:
            patches = await ipc.read_virtual_patches()
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        return VirtualPatchesResponse(patches=patches, count=len(patches))

    # ------------------------------------------------------------------ #
    # Pending-approval queue                                               #
    # ------------------------------------------------------------------ #

    @app.get(
        "/api/v1/pending",
        response_model=PendingResponse,
        tags=["pending"],
        dependencies=[Depends(auth)],
    )
    async def list_pending() -> PendingResponse:
        """List bans in PENDING_APPROVAL state (subset of the ban list)."""
        try:
            bans = await ipc.read_bans()
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        pending = [b for b in bans if b.get("status") == "pending_approval"]
        return PendingResponse(items=pending, count=len(pending))

    @app.post(
        "/api/v1/pending/{ban_id}/approve",
        response_model=OkResponse,
        tags=["pending"],
        dependencies=[Depends(auth)],
    )
    async def approve_pending(ban_id: str) -> OkResponse:
        """Approve a pending ban and make it active in waffy-core."""
        try:
            await ipc.approve_pending(ban_id=ban_id)
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc
        return OkResponse(ok=True, message=f"Ban {ban_id} approved.")

    @app.post(
        "/api/v1/pending/{ban_id}/reject",
        response_model=OkResponse,
        tags=["pending"],
        dependencies=[Depends(auth)],
    )
    async def reject_pending(ban_id: str) -> OkResponse:
        """Reject and discard a pending ban."""
        try:
            await ipc.reject_pending(ban_id=ban_id)
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc
        return OkResponse(ok=True, message=f"Ban {ban_id} rejected.")

    # ------------------------------------------------------------------ #
    # Anomaly model governance (prompts/10)                                #
    # ------------------------------------------------------------------ #

    @app.get(
        "/api/v1/models/candidates",
        response_model=CandidateModelsResponse,
        tags=["models"],
        dependencies=[Depends(auth)],
    )
    async def list_candidate_models() -> CandidateModelsResponse:
        """List anomaly-model candidates awaiting operator promotion.

        Each candidate carries its training metadata (sample count, training
        window, per-feature summary statistics) plus an ``active_comparison``
        against the route's currently-active model, if any -- everything an
        operator needs to catch a suspicious retrain before promoting it.
        Never auto-approves or auto-rejects; this is a human-review-only gate.
        """
        try:
            candidates = await ipc.read_candidate_models()
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        return CandidateModelsResponse(candidates=candidates, count=len(candidates))

    @app.post(
        "/api/v1/models/candidates/{route_id}/{version}/promote",
        response_model=OkResponse,
        tags=["models"],
        dependencies=[Depends(auth)],
    )
    async def promote_candidate_model(route_id: str, version: str) -> OkResponse:
        """Promote a candidate model to active for its route in waffy-core.

        Replaces that route's prior active model. If a live anomaly scorer
        is wired in waffy-core, this takes effect immediately.
        """
        try:
            await ipc.promote_model(route_id=route_id, version=version)
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc
        return OkResponse(ok=True, message=f"Model {route_id}/{version} promoted to active.")

    @app.post(
        "/api/v1/models/candidates/{route_id}/{version}/reject",
        response_model=OkResponse,
        tags=["models"],
        dependencies=[Depends(auth)],
    )
    async def reject_candidate_model(route_id: str, version: str) -> OkResponse:
        """Reject and discard a candidate model without ever activating it."""
        try:
            await ipc.reject_model(route_id=route_id, version=version)
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc
        return OkResponse(ok=True, message=f"Model {route_id}/{version} rejected.")

    # ------------------------------------------------------------------ #
    # Enforcement mode                                                     #
    # ------------------------------------------------------------------ #

    @app.get(
        "/api/v1/mode",
        response_model=ModeResponse,
        tags=["mode"],
        dependencies=[Depends(auth)],
    )
    async def get_mode() -> ModeResponse:
        """Read the current enforcement mode from waffy-core."""
        try:
            mode = await ipc.get_mode()
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        return ModeResponse(ok=True, mode=mode)

    @app.post(
        "/api/v1/mode",
        response_model=ModeResponse,
        tags=["mode"],
        dependencies=[Depends(auth)],
    )
    async def set_mode(body: SetModeRequest) -> ModeResponse:
        """Update the enforcement mode at runtime.

        Valid values: ``SHADOW``, ``ACTIVE``.
        The change takes effect immediately in waffy-core without restart.
        """
        try:
            _prev, new_mode = await ipc.set_mode(mode=body.mode)
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        return ModeResponse(ok=True, mode=new_mode)

    # ------------------------------------------------------------------ #
    # Kill-switch                                                          #
    # ------------------------------------------------------------------ #

    @app.post(
        "/api/v1/killswitch",
        response_model=OkResponse,
        tags=["killswitch"],
        dependencies=[Depends(auth)],
    )
    async def killswitch(body: KillswitchRequest) -> OkResponse:
        """Engage the emergency kill-switch in waffy-core.

        **Destructive**: sets waffy-core to SHADOW mode and revokes all
        active bans.  Requires ``confirm: true`` in the request body to
        prevent accidental activation.
        """
        if not body.confirm:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Kill-switch requires 'confirm: true' in the request body.",
            )
        try:
            await ipc.trigger_killswitch(reason=body.reason)
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc
        return OkResponse(
            ok=True, message="Kill-switch engaged. waffy-core is now in SHADOW mode."
        )

    # ------------------------------------------------------------------ #
    # Rule reload                                                          #
    # ------------------------------------------------------------------ #

    @app.post(
        "/api/v1/rules/reload",
        response_model=OkResponse,
        tags=["rules"],
        dependencies=[Depends(auth)],
    )
    async def reload_rules() -> OkResponse:
        """Trigger a hot-reload of signature rules in waffy-core."""
        try:
            loaded = await ipc.reload_rules()
        except IpcClientError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc
        return OkResponse(ok=True, message=f"Rules reloaded. {loaded} rules active.")

    # ------------------------------------------------------------------ #
    # Metrics — Prometheus text format                                     #
    # ------------------------------------------------------------------ #

    @app.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
    async def prometheus_metrics(_request: Request) -> PlainTextResponse:
        """Prometheus 0.0.4 / Netdata-compatible metrics exposition.

        Intentionally unauthenticated so Prometheus can scrape from localhost
        without a bearer token.  Bind the API on ``127.0.0.1`` (default) and
        use firewall rules to restrict access in production.
        """
        text = metrics.prometheus_text()
        return PlainTextResponse(content=text, media_type="text/plain; version=0.0.4")

    @app.get(
        "/api/v1/metrics",
        response_model=MetricsSnapshotResponse,
        tags=["metrics"],
        dependencies=[Depends(auth)],
    )
    async def metrics_snapshot() -> MetricsSnapshotResponse:
        """JSON snapshot of all counters (same data as /metrics, authenticated)."""
        snap = metrics.snapshot()
        return MetricsSnapshotResponse(ok=True, snapshot=snap)

    return app


__all__ = [
    "build_app",
]
