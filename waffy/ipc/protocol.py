"""waffy/ipc/protocol.py — Typed Pydantic v2 schema for the waffy-core ↔ waffy-api
Unix domain socket IPC protocol.

Design
------
- All messages are Pydantic v2 models serialised as newline-delimited JSON (NDJSON).
- Every request carries a ``request_id`` for correlation; every response carries
  the matching ``request_id`` plus an ``ok`` boolean.
- The protocol is versioned via ``PROTOCOL_VERSION``; both sides MUST reject
  frames with an incompatible major version.
- This module defines only the schema.  The server-side transport is in
  ``waffy/ipc/server.py``.  The client-side transport will be built in Phase 8
  alongside ``waffy-api``.

Supported commands
------------------
``read_events``          → recent ``SecurityEvent`` records
``read_requests``        → recent ``RequestAssessment`` snapshots
``read_bans``            → active ``BanEntry`` list
``read_allowlist``       → ``AllowlistEntry`` list
``read_virtual_patches`` → ``VirtualPatchRule`` list
``add_allowlist``        → submit a new allowlist entry
``remove_allowlist``     → remove an allowlist entry by target IP/CIDR
``approve_pending``      → approve a ``PENDING_APPROVAL`` ban
``reject_pending``       → reject a ``PENDING_APPROVAL`` ban
``read_candidate_models`` → list pending anomaly-model candidates awaiting promotion
``promote_model``        → promote a candidate anomaly model to active (prompts/10)
``reject_model``         → reject and discard a candidate anomaly model (prompts/10)
``trigger_killswitch``   → engage emergency kill-switch
``reload_rules``         → hot-reload signature rule set from disk
``get_mode``             → read current ``EnforcementMode``
``set_mode``             → update ``EnforcementMode`` at runtime
"""

from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Protocol versioning
# ---------------------------------------------------------------------------

PROTOCOL_VERSION: str = "1.0"
PROTOCOL_MAJOR: int = 1


# ---------------------------------------------------------------------------
# Base envelope
# ---------------------------------------------------------------------------


class IpcRequest(BaseModel):
    """Base class for all IPC requests sent from waffy-api → waffy-core."""

    protocol_version: str = PROTOCOL_VERSION
    request_id: str
    command: str  # overridden in subclasses with Literal narrowing


class IpcResponse(BaseModel):
    """Base class for all IPC responses sent from waffy-core → waffy-api."""

    protocol_version: str = PROTOCOL_VERSION
    request_id: str
    ok: bool
    error: str | None = None


# ---------------------------------------------------------------------------
# Read requests
# ---------------------------------------------------------------------------


class ReadEventsRequest(IpcRequest):
    command: str = "read_events"
    limit: int = Field(default=50, ge=1, le=1000)


class ReadEventsResponse(IpcResponse):
    events: list[dict[str, Any]] = Field(default_factory=lambda: [])


class ReadRequestsRequest(IpcRequest):
    command: str = "read_requests"
    limit: int = Field(default=50, ge=1, le=1000)


class ReadRequestsResponse(IpcResponse):
    assessments: list[dict[str, Any]] = Field(default_factory=lambda: [])


class ReadBansRequest(IpcRequest):
    command: str = "read_bans"


class ReadBansResponse(IpcResponse):
    bans: list[dict[str, Any]] = Field(default_factory=lambda: [])


class ReadAllowlistRequest(IpcRequest):
    command: str = "read_allowlist"


class ReadAllowlistResponse(IpcResponse):
    entries: list[dict[str, Any]] = Field(default_factory=lambda: [])


class ReadVirtualPatchesRequest(IpcRequest):
    command: str = "read_virtual_patches"


class ReadVirtualPatchesResponse(IpcResponse):
    patches: list[dict[str, Any]] = Field(default_factory=lambda: [])


# ---------------------------------------------------------------------------
# Write / mutation requests
# ---------------------------------------------------------------------------


class AddAllowlistRequest(IpcRequest):
    command: str = "add_allowlist"
    target: str  # IP or CIDR
    reason: str = "API submission"
    created_by: str = "waffy-api"


class AddAllowlistResponse(IpcResponse):
    pass


class RemoveAllowlistRequest(IpcRequest):
    command: str = "remove_allowlist"
    target: str  # IP or CIDR


class RemoveAllowlistResponse(IpcResponse):
    removed: bool = False


class ApprovePendingRequest(IpcRequest):
    command: str = "approve_pending"
    ban_id: str


class ApprovePendingResponse(IpcResponse):
    pass


class RejectPendingRequest(IpcRequest):
    command: str = "reject_pending"
    ban_id: str


class RejectPendingResponse(IpcResponse):
    pass


# ---------------------------------------------------------------------------
# Anomaly model governance (prompts/10)
# ---------------------------------------------------------------------------


class ReadCandidateModelsRequest(IpcRequest):
    command: str = "read_candidate_models"


class ReadCandidateModelsResponse(IpcResponse):
    candidates: list[dict[str, Any]] = Field(default_factory=lambda: [])


class PromoteModelRequest(IpcRequest):
    command: str = "promote_model"
    route_id: str
    version: str


class PromoteModelResponse(IpcResponse):
    pass


class RejectModelRequest(IpcRequest):
    command: str = "reject_model"
    route_id: str
    version: str


class RejectModelResponse(IpcResponse):
    pass


# ---------------------------------------------------------------------------
# Control requests
# ---------------------------------------------------------------------------


class TriggerKillswitchRequest(IpcRequest):
    command: str = "trigger_killswitch"
    reason: str = "IPC kill-switch request"


class TriggerKillswitchResponse(IpcResponse):
    pass


class ReloadRulesRequest(IpcRequest):
    command: str = "reload_rules"


class ReloadRulesResponse(IpcResponse):
    rules_loaded: int = 0


class GetModeRequest(IpcRequest):
    command: str = "get_mode"


class GetModeResponse(IpcResponse):
    mode: str = ""


class SetModeRequest(IpcRequest):
    command: str = "set_mode"
    mode: str  # EnforcementMode value string


class SetModeResponse(IpcResponse):
    previous_mode: str = ""
    new_mode: str = ""


# ---------------------------------------------------------------------------
# Dispatcher helper
# ---------------------------------------------------------------------------

# All concrete request types for use by the server dispatcher.
AnyIpcRequest = (
    ReadEventsRequest
    | ReadRequestsRequest
    | ReadBansRequest
    | ReadAllowlistRequest
    | ReadVirtualPatchesRequest
    | AddAllowlistRequest
    | RemoveAllowlistRequest
    | ApprovePendingRequest
    | RejectPendingRequest
    | ReadCandidateModelsRequest
    | PromoteModelRequest
    | RejectModelRequest
    | TriggerKillswitchRequest
    | ReloadRulesRequest
    | GetModeRequest
    | SetModeRequest
)

_COMMAND_MAP: dict[str, type[IpcRequest]] = {
    "read_events": ReadEventsRequest,
    "read_requests": ReadRequestsRequest,
    "read_bans": ReadBansRequest,
    "read_allowlist": ReadAllowlistRequest,
    "read_virtual_patches": ReadVirtualPatchesRequest,
    "add_allowlist": AddAllowlistRequest,
    "remove_allowlist": RemoveAllowlistRequest,
    "approve_pending": ApprovePendingRequest,
    "reject_pending": RejectPendingRequest,
    "read_candidate_models": ReadCandidateModelsRequest,
    "promote_model": PromoteModelRequest,
    "reject_model": RejectModelRequest,
    "trigger_killswitch": TriggerKillswitchRequest,
    "reload_rules": ReloadRulesRequest,
    "get_mode": GetModeRequest,
    "set_mode": SetModeRequest,
}


def parse_ipc_request(data: dict[str, Any]) -> IpcRequest:
    """Dispatch raw JSON dict to the correct typed request model.

    Raises ``ValueError`` if the command is unknown or the payload is
    malformed.
    """
    command = data.get("command", "")
    cls = _COMMAND_MAP.get(command)
    if cls is None:
        raise ValueError(f"Unknown IPC command: '{command}'")
    return cls.model_validate(data)


__all__ = [
    "PROTOCOL_VERSION",
    "PROTOCOL_MAJOR",
    "IpcRequest",
    "IpcResponse",
    "ReadEventsRequest",
    "ReadEventsResponse",
    "ReadRequestsRequest",
    "ReadRequestsResponse",
    "ReadBansRequest",
    "ReadBansResponse",
    "ReadAllowlistRequest",
    "ReadAllowlistResponse",
    "ReadVirtualPatchesRequest",
    "ReadVirtualPatchesResponse",
    "AddAllowlistRequest",
    "AddAllowlistResponse",
    "RemoveAllowlistRequest",
    "RemoveAllowlistResponse",
    "ApprovePendingRequest",
    "ApprovePendingResponse",
    "RejectPendingRequest",
    "RejectPendingResponse",
    "ReadCandidateModelsRequest",
    "ReadCandidateModelsResponse",
    "PromoteModelRequest",
    "PromoteModelResponse",
    "RejectModelRequest",
    "RejectModelResponse",
    "TriggerKillswitchRequest",
    "TriggerKillswitchResponse",
    "ReloadRulesRequest",
    "ReloadRulesResponse",
    "GetModeRequest",
    "GetModeResponse",
    "SetModeRequest",
    "SetModeResponse",
    "AnyIpcRequest",
    "parse_ipc_request",
]
