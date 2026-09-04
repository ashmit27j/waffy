"""waffy/ipc/server.py — waffy-core side of the Unix domain socket IPC server.

Architecture
------------
- Listens on a Unix domain socket (path configured via ``WaffyConfig.api.ipc_socket_path``).
- The socket file is created with mode ``0o600`` so only the owning user can
  connect.  The test suite asserts this permission.
- Accepts connections, reads newline-delimited JSON request frames, dispatches
  to the appropriate handler, and writes a newline-delimited JSON response.
- All I/O is async (``asyncio`` streams); each connection is handled in an
  independent coroutine so a slow client does not block others.
- The client half of this protocol will be built in Phase 8 alongside
  ``waffy-api``.

Windows development note
-------------------------
``asyncio.start_unix_server`` (used by this module) requires
``socket.AF_UNIX``, which native Windows Python does not provide. Developing
or running the test suite on a Windows machine requires WSL (Windows
Subsystem for Linux) — run everything under a WSL Ubuntu shell against the
repo path (e.g. ``/mnt/d/...``), not native Windows Python. See
``README.md``'s Prerequisites section and ``docs/DEPLOYMENT.md``.

Security notes
--------------
- Only the ``waffy-core`` service user and the ``waffy-api`` service user
  should be members of the group that owns the socket.  See
  ``docs/DEPLOYMENT.md`` for the recommended systemd ``User=/Group=`` setup.
- No authentication token is used beyond filesystem-level permissions (the
  two service users share the socket by group membership).  If the threat
  model requires more, a per-connection HMAC token can be added without
  changing the wire format.
"""

import asyncio
import contextlib
import json
import logging
import os
import stat
from collections import deque
from pathlib import Path

from waffy.config.models import WaffyConfig
from waffy.core.enums import EnforcementMode
from waffy.core.interfaces import RuleStore
from waffy.core.models.domain import RequestAssessment, SecurityEvent
from waffy.detection.anomaly.governance import ModelGovernanceService
from waffy.detection.anomaly.scorer import AnomalyScorer
from waffy.enforcement.allowlist import AllowlistManager
from waffy.enforcement.killswitch import KillSwitchService
from waffy.ipc.protocol import (
    PROTOCOL_MAJOR,
    AddAllowlistRequest,
    AddAllowlistResponse,
    ApprovePendingRequest,
    ApprovePendingResponse,
    GetModeRequest,
    GetModeResponse,
    IpcRequest,
    IpcResponse,
    PromoteModelRequest,
    PromoteModelResponse,
    ReadAllowlistRequest,
    ReadAllowlistResponse,
    ReadBansRequest,
    ReadBansResponse,
    ReadCandidateModelsRequest,
    ReadCandidateModelsResponse,
    ReadEventsRequest,
    ReadEventsResponse,
    ReadRequestsRequest,
    ReadRequestsResponse,
    ReadVirtualPatchesRequest,
    ReadVirtualPatchesResponse,
    RejectModelRequest,
    RejectModelResponse,
    RejectPendingRequest,
    RejectPendingResponse,
    ReloadRulesRequest,
    ReloadRulesResponse,
    RemoveAllowlistRequest,
    RemoveAllowlistResponse,
    SetModeRequest,
    SetModeResponse,
    TriggerKillswitchRequest,
    TriggerKillswitchResponse,
    parse_ipc_request,
)

logger = logging.getLogger("waffy.ipc.server")

# In-memory ring buffers shared with the pipeline for IPC read access.
_MAX_EVENTS: int = 500
_MAX_ASSESSMENTS: int = 500


class IpcStateStore:
    """Shared in-memory ring buffers written by the pipeline, read by IPC."""

    def __init__(
        self,
        max_events: int = _MAX_EVENTS,
        max_assessments: int = _MAX_ASSESSMENTS,
    ) -> None:
        self.events: deque[SecurityEvent] = deque(maxlen=max_events)
        self.assessments: deque[RequestAssessment] = deque(maxlen=max_assessments)

    def record_event(self, event: SecurityEvent) -> None:
        self.events.appendleft(event)

    def record_assessment(self, assessment: RequestAssessment) -> None:
        self.assessments.appendleft(assessment)


class IpcServer:
    """waffy-core Unix domain socket IPC server.

    Parameters
    ----------
    config:
        Root ``WaffyConfig``; ``config.api.ipc_socket_path`` is used for the
        socket path.
    rule_store:
        The same ``RuleStore`` instance used by the pipeline for ban/allowlist
        persistence.
    allowlist_manager:
        Shared ``AllowlistManager`` for runtime allowlist mutations.
    killswitch:
        Shared ``KillSwitchService`` for emergency mode changes.
    state_store:
        Ring-buffer of recent events and assessments for read queries.
    model_governance:
        Optional shared ``ModelGovernanceService`` for anomaly-model
        candidate listing/promotion/rejection (prompts/10). If ``None``
        (the default), the three ``*_model`` commands respond with a clear
        "not configured" error rather than crashing — a deployment that
        never trains anomaly models need not wire this up.
    anomaly_scorer:
        Optional shared ``AnomalyScorer`` instance — the *same* one the live
        pipeline scores requests against. When set, ``promote_model``
        calls ``reload_models()`` on it so a promotion takes effect
        immediately, without a process restart.
    """

    def __init__(
        self,
        config: WaffyConfig,
        rule_store: RuleStore,
        allowlist_manager: AllowlistManager,
        killswitch: KillSwitchService,
        state_store: IpcStateStore,
        model_governance: ModelGovernanceService | None = None,
        anomaly_scorer: AnomalyScorer | None = None,
    ) -> None:
        self.config = config
        self.rule_store = rule_store
        self.allowlist_manager = allowlist_manager
        self.killswitch = killswitch
        self.state_store = state_store
        self.model_governance = model_governance
        self.anomaly_scorer = anomaly_scorer
        self._server: asyncio.AbstractServer | None = None
        self._socket_path = Path(config.api.ipc_socket_path)

    async def start(self) -> None:
        """Create the socket file and start accepting connections."""
        # Remove stale socket from a previous run.
        if self._socket_path.exists():
            self._socket_path.unlink()

        self._server = await asyncio.start_unix_server(
            self._handle_connection,
            path=str(self._socket_path),
        )
        # Restrict socket permissions to owner only (0o600).
        os.chmod(self._socket_path, stat.S_IRUSR | stat.S_IWUSR)
        logger.info(
            "IPC server listening on %s (permissions 0o600)", self._socket_path
        )

    async def stop(self) -> None:
        """Stop accepting new connections and clean up the socket file."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        if self._socket_path.exists():
            self._socket_path.unlink(missing_ok=True)
        logger.info("IPC server stopped.")

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single IPC client connection."""
        peer = writer.get_extra_info("peername") or "unix"
        logger.debug("IPC connection from %s", peer)
        try:
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=30.0)
                except TimeoutError:
                    logger.debug("IPC connection idle timeout, closing.")
                    break
                if not line:
                    break  # EOF
                try:
                    raw = json.loads(line.decode())
                except json.JSONDecodeError as e:
                    err_resp = IpcResponse(
                        request_id="unknown", ok=False, error=f"JSON decode error: {e}"
                    )
                    writer.write(err_resp.model_dump_json().encode() + b"\n")
                    await writer.drain()
                    continue

                # Version check
                proto_ver = raw.get("protocol_version", "0.0")
                try:
                    major = int(proto_ver.split(".")[0])
                except (ValueError, AttributeError):
                    major = 0
                if major != PROTOCOL_MAJOR:
                    err_resp = IpcResponse(
                        request_id=raw.get("request_id", "unknown"),
                        ok=False,
                        error=f"Protocol version mismatch: got {proto_ver}",
                    )
                    writer.write(err_resp.model_dump_json().encode() + b"\n")
                    await writer.drain()
                    continue

                try:
                    request = parse_ipc_request(raw)
                except ValueError as e:
                    err_resp = IpcResponse(
                        request_id=raw.get("request_id", "unknown"),
                        ok=False,
                        error=str(e),
                    )
                    writer.write(err_resp.model_dump_json().encode() + b"\n")
                    await writer.drain()
                    continue

                response = await self._dispatch(request)
                writer.write(response.model_dump_json().encode() + b"\n")
                await writer.drain()
        except Exception:
            logger.exception("Unhandled error in IPC connection handler")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _dispatch(self, request: IpcRequest) -> IpcResponse:
        """Dispatch a typed IPC request to the appropriate handler."""
        rid = request.request_id
        try:
            if isinstance(request, ReadEventsRequest):
                items = list(self.state_store.events)[: request.limit]
                return ReadEventsResponse(
                    request_id=rid,
                    ok=True,
                    events=[e.model_dump(mode="json") for e in items],
                )

            if isinstance(request, ReadRequestsRequest):
                items_a = list(self.state_store.assessments)[: request.limit]
                return ReadRequestsResponse(
                    request_id=rid,
                    ok=True,
                    assessments=[a.model_dump(mode="json") for a in items_a],
                )

            if isinstance(request, ReadBansRequest):
                bans = await self.rule_store.list_active_bans()
                return ReadBansResponse(
                    request_id=rid,
                    ok=True,
                    bans=[b.model_dump(mode="json") for b in bans],
                )

            if isinstance(request, ReadAllowlistRequest):
                entries = await self.rule_store.list_allowlist()
                return ReadAllowlistResponse(
                    request_id=rid,
                    ok=True,
                    entries=[e.model_dump(mode="json") for e in entries],
                )

            if isinstance(request, ReadVirtualPatchesRequest):
                patches = await self.rule_store.list_virtual_patches()
                return ReadVirtualPatchesResponse(
                    request_id=rid,
                    ok=True,
                    patches=[p.model_dump(mode="json") for p in patches],
                )

            if isinstance(request, AddAllowlistRequest):
                await self.allowlist_manager.add_entry(
                    target=request.target,
                    reason=request.reason,
                    created_by=request.created_by,
                )
                return AddAllowlistResponse(request_id=rid, ok=True)

            if isinstance(request, RemoveAllowlistRequest):
                removed = await self.allowlist_manager.remove_entry(request.target)
                return RemoveAllowlistResponse(request_id=rid, ok=True, removed=removed)

            if isinstance(request, ApprovePendingRequest):
                removed = await self.rule_store.remove_ban(request.ban_id)
                return ApprovePendingResponse(request_id=rid, ok=removed)

            if isinstance(request, RejectPendingRequest):
                removed = await self.rule_store.remove_ban(request.ban_id)
                return RejectPendingResponse(request_id=rid, ok=removed)

            if isinstance(request, ReadCandidateModelsRequest):
                if self.model_governance is None:
                    return ReadCandidateModelsResponse(
                        request_id=rid, ok=True, candidates=[]
                    )
                candidates = self.model_governance.list_candidates()
                dumped = [
                    {
                        **c.model_dump(mode="json"),
                        "active_comparison": self.model_governance.compare_to_active(c),
                    }
                    for c in candidates
                ]
                return ReadCandidateModelsResponse(request_id=rid, ok=True, candidates=dumped)

            if isinstance(request, PromoteModelRequest):
                if self.model_governance is None:
                    return PromoteModelResponse(
                        request_id=rid, ok=False, error="Model governance not configured"
                    )
                promoted = self.model_governance.promote(request.route_id, request.version)
                if promoted and self.anomaly_scorer is not None:
                    self.anomaly_scorer.reload_models()
                if not promoted:
                    return PromoteModelResponse(
                        request_id=rid,
                        ok=False,
                        error=f"No candidate model {request.route_id}/{request.version}",
                    )
                return PromoteModelResponse(request_id=rid, ok=True)

            if isinstance(request, RejectModelRequest):
                if self.model_governance is None:
                    return RejectModelResponse(
                        request_id=rid, ok=False, error="Model governance not configured"
                    )
                rejected = self.model_governance.reject(request.route_id, request.version)
                if not rejected:
                    return RejectModelResponse(
                        request_id=rid,
                        ok=False,
                        error=f"No candidate model {request.route_id}/{request.version}",
                    )
                return RejectModelResponse(request_id=rid, ok=True)

            if isinstance(request, TriggerKillswitchRequest):
                await self.killswitch.engage(reason=request.reason)
                return TriggerKillswitchResponse(request_id=rid, ok=True)

            if isinstance(request, ReloadRulesRequest):
                # Actual rule hot-reload will be wired in Phase 9 (hardening).
                # For now we acknowledge the command and document the gap.
                logger.info(
                    "IPC reload_rules received — rule hot-reload not yet wired to "
                    "SignatureEngine; restart waffy-core to pick up new rules."
                )
                return ReloadRulesResponse(request_id=rid, ok=True, rules_loaded=0)

            if isinstance(request, GetModeRequest):
                mode = self.config.enforcement.mode
                return GetModeResponse(request_id=rid, ok=True, mode=mode.value)

            if isinstance(request, SetModeRequest):
                prev = self.config.enforcement.mode
                try:
                    new_mode = EnforcementMode(request.mode)
                except ValueError:
                    return SetModeResponse(
                        request_id=rid,
                        ok=False,
                        error=f"Invalid mode '{request.mode}'",
                    )
                self.config.enforcement.mode = new_mode
                logger.info("IPC set_mode: %s → %s", prev.value, new_mode.value)
                return SetModeResponse(
                    request_id=rid, ok=True,
                    previous_mode=prev.value, new_mode=new_mode.value,
                )

            return IpcResponse(
                request_id=rid, ok=False,
                error=f"Unhandled command '{request.command}'",
            )

        except Exception as exc:
            logger.exception("IPC handler error for command '%s'", request.command)
            return IpcResponse(request_id=rid, ok=False, error=str(exc))


__all__ = [
    "IpcStateStore",
    "IpcServer",
]
