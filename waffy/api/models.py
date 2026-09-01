"""waffy/api/models.py — Request/response Pydantic v2 models for waffy-api endpoints.

These models are used only by the REST API layer and never by waffy-core's
request-path engine.  They map closely to the domain models but are kept
separate to avoid coupling the two processes at the schema level.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Generic envelope
# ---------------------------------------------------------------------------


class OkResponse(BaseModel):
    ok: bool = True
    message: str = ""


class ErrorResponse(BaseModel):
    ok: bool = False
    error: str


# ---------------------------------------------------------------------------
# Ban management
# ---------------------------------------------------------------------------


class BanListResponse(BaseModel):
    ok: bool = True
    bans: list[dict[str, Any]] = Field(default_factory=lambda: list[dict[str, Any]]())
    count: int = 0


class CreateBanRequest(BaseModel):
    target: str = Field(..., description="IP address or CIDR to ban")
    reason: str = Field(default="Manual API ban")
    duration_seconds: int = Field(default=3600, ge=1)


class BanActionResponse(BaseModel):
    ok: bool = True
    ban_id: str = ""
    message: str = ""


# ---------------------------------------------------------------------------
# Allowlist management
# ---------------------------------------------------------------------------


class AllowlistResponse(BaseModel):
    ok: bool = True
    entries: list[dict[str, Any]] = Field(default_factory=lambda: list[dict[str, Any]]())
    count: int = 0


class CreateAllowlistRequest(BaseModel):
    target: str = Field(..., description="IP address or CIDR to allowlist")
    reason: str = Field(default="Manual API allowlist entry")


class AllowlistActionResponse(BaseModel):
    ok: bool = True
    removed: bool = False
    message: str = ""


# ---------------------------------------------------------------------------
# Event / request feed
# ---------------------------------------------------------------------------


class EventsResponse(BaseModel):
    ok: bool = True
    events: list[dict[str, Any]] = Field(default_factory=lambda: list[dict[str, Any]]())
    count: int = 0


class RequestsResponse(BaseModel):
    ok: bool = True
    assessments: list[dict[str, Any]] = Field(default_factory=lambda: list[dict[str, Any]]())
    count: int = 0


# ---------------------------------------------------------------------------
# Virtual patches
# ---------------------------------------------------------------------------


class VirtualPatchesResponse(BaseModel):
    ok: bool = True
    patches: list[dict[str, Any]] = Field(default_factory=lambda: list[dict[str, Any]]())
    count: int = 0


# ---------------------------------------------------------------------------
# Pending approval queue
# ---------------------------------------------------------------------------


class PendingResponse(BaseModel):
    ok: bool = True
    items: list[dict[str, Any]] = Field(default_factory=lambda: list[dict[str, Any]]())
    count: int = 0


class ApproveRejectRequest(BaseModel):
    ban_id: str


# ---------------------------------------------------------------------------
# Mode management
# ---------------------------------------------------------------------------


class ModeResponse(BaseModel):
    ok: bool = True
    mode: str = ""


class SetModeRequest(BaseModel):
    mode: str = Field(..., description="Enforcement mode: SHADOW or ACTIVE")


# ---------------------------------------------------------------------------
# Kill-switch
# ---------------------------------------------------------------------------


class KillswitchRequest(BaseModel):
    reason: str = Field(default="Manual kill-switch via API")
    confirm: bool = Field(
        default=False,
        description="Must be set to true to confirm the destructive kill-switch action.",
    )


# ---------------------------------------------------------------------------
# Health / status
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    ok: bool = True
    status: str = "healthy"
    version: str = "0.1.0"
    ipc_reachable: bool = False


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


class MetricsSnapshotResponse(BaseModel):
    ok: bool = True
    snapshot: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "OkResponse",
    "ErrorResponse",
    "BanListResponse",
    "CreateBanRequest",
    "BanActionResponse",
    "AllowlistResponse",
    "CreateAllowlistRequest",
    "AllowlistActionResponse",
    "EventsResponse",
    "RequestsResponse",
    "VirtualPatchesResponse",
    "PendingResponse",
    "ApproveRejectRequest",
    "ModeResponse",
    "SetModeRequest",
    "KillswitchRequest",
    "HealthResponse",
    "MetricsSnapshotResponse",
]
