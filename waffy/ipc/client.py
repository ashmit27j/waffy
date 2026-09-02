"""waffy/ipc/client.py — waffy-api-side IPC client.

This is the **only** way waffy-api code communicates with waffy-core state.
It speaks the NDJSON socket protocol defined in ``waffy/ipc/protocol.py``.

Design rules:
- This module intentionally imports **nothing** from waffy.enforcement,
  waffy.detection, waffy.proxy, or waffy.engine.  All waffy-core operations
  go through this wire protocol.
- Connections are short-lived (one per request) to avoid holding a persistent
  stream that could block waffy-core's connection handler.
- All errors are surfaced as ``IpcClientError`` so callers don't need to
  handle raw asyncio exceptions.
"""

import asyncio
import contextlib
import json
import logging
import uuid
from typing import Any

from waffy.ipc.protocol import (
    AddAllowlistRequest,
    AddAllowlistResponse,
    ApprovePendingRequest,
    ApprovePendingResponse,
    GetModeRequest,
    GetModeResponse,
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
)

logger = logging.getLogger("waffy.ipc.client")


class IpcClientError(Exception):
    """Raised when the IPC call fails at the transport or protocol level."""


class IpcClient:
    """Async Unix domain socket client for waffy-core IPC protocol.

    Parameters
    ----------
    socket_path:
        Path to the Unix domain socket (``WaffyConfig.api.ipc_socket_path``).
    timeout_seconds:
        Per-call timeout in seconds (default 10).
    """

    def __init__(
        self,
        socket_path: str = "/run/waffy/core.sock",
        timeout_seconds: float = 10.0,
    ) -> None:
        self.socket_path = socket_path
        self.timeout = timeout_seconds

    def _new_id(self) -> str:
        return str(uuid.uuid4())

    async def _call(self, request_dict: dict[str, Any]) -> dict[str, Any]:
        """Send one NDJSON frame to waffy-core and return the parsed response."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(path=self.socket_path),
                timeout=self.timeout,
            )
        except (OSError, TimeoutError) as exc:
            raise IpcClientError(
                f"Cannot connect to IPC socket '{self.socket_path}': {exc}"
            ) from exc

        try:
            writer.write(json.dumps(request_dict).encode() + b"\n")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
            if not line:
                raise IpcClientError("IPC server closed connection without response")
            return json.loads(line.decode())
        except (json.JSONDecodeError, TimeoutError) as exc:
            raise IpcClientError(f"IPC communication error: {exc}") from exc
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)

    # ---------------------------------------------------------------------- #
    # Read methods                                                             #
    # ---------------------------------------------------------------------- #

    async def read_events(self, limit: int = 50) -> list[dict[str, Any]]:
        raw = await self._call(
            ReadEventsRequest(
                request_id=self._new_id(), command="read_events", limit=limit
            ).model_dump()
        )
        resp = ReadEventsResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"read_events failed: {resp.error}")
        return list(resp.events)

    async def read_requests(self, limit: int = 50) -> list[dict[str, Any]]:
        raw = await self._call(
            ReadRequestsRequest(
                request_id=self._new_id(), command="read_requests", limit=limit
            ).model_dump()
        )
        resp = ReadRequestsResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"read_requests failed: {resp.error}")
        return list(resp.assessments)

    async def read_bans(self) -> list[dict[str, Any]]:
        raw = await self._call(
            ReadBansRequest(request_id=self._new_id(), command="read_bans").model_dump()
        )
        resp = ReadBansResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"read_bans failed: {resp.error}")
        return list(resp.bans)

    async def read_allowlist(self) -> list[dict[str, Any]]:
        raw = await self._call(
            ReadAllowlistRequest(
                request_id=self._new_id(), command="read_allowlist"
            ).model_dump()
        )
        resp = ReadAllowlistResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"read_allowlist failed: {resp.error}")
        return list(resp.entries)

    async def read_virtual_patches(self) -> list[dict[str, Any]]:
        raw = await self._call(
            ReadVirtualPatchesRequest(
                request_id=self._new_id(), command="read_virtual_patches"
            ).model_dump()
        )
        resp = ReadVirtualPatchesResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"read_virtual_patches failed: {resp.error}")
        return list(resp.patches)

    # ---------------------------------------------------------------------- #
    # Write / mutation methods                                                 #
    # ---------------------------------------------------------------------- #

    async def add_allowlist(
        self,
        target: str,
        reason: str = "API submission",
        created_by: str = "waffy-api",
    ) -> None:
        raw = await self._call(
            AddAllowlistRequest(
                request_id=self._new_id(),
                command="add_allowlist",
                target=target,
                reason=reason,
                created_by=created_by,
            ).model_dump()
        )
        resp = AddAllowlistResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"add_allowlist failed: {resp.error}")

    async def remove_allowlist(self, target: str) -> bool:
        raw = await self._call(
            RemoveAllowlistRequest(
                request_id=self._new_id(), command="remove_allowlist", target=target
            ).model_dump()
        )
        resp = RemoveAllowlistResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"remove_allowlist failed: {resp.error}")
        return resp.removed

    async def approve_pending(self, ban_id: str) -> None:
        raw = await self._call(
            ApprovePendingRequest(
                request_id=self._new_id(), command="approve_pending", ban_id=ban_id
            ).model_dump()
        )
        resp = ApprovePendingResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"approve_pending failed: {resp.error}")

    async def reject_pending(self, ban_id: str) -> None:
        raw = await self._call(
            RejectPendingRequest(
                request_id=self._new_id(), command="reject_pending", ban_id=ban_id
            ).model_dump()
        )
        resp = RejectPendingResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"reject_pending failed: {resp.error}")

    async def read_candidate_models(self) -> list[dict[str, Any]]:
        raw = await self._call(
            ReadCandidateModelsRequest(
                request_id=self._new_id(), command="read_candidate_models"
            ).model_dump()
        )
        resp = ReadCandidateModelsResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"read_candidate_models failed: {resp.error}")
        return list(resp.candidates)

    async def promote_model(self, route_id: str, version: str) -> None:
        raw = await self._call(
            PromoteModelRequest(
                request_id=self._new_id(),
                command="promote_model",
                route_id=route_id,
                version=version,
            ).model_dump()
        )
        resp = PromoteModelResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"promote_model failed: {resp.error}")

    async def reject_model(self, route_id: str, version: str) -> None:
        raw = await self._call(
            RejectModelRequest(
                request_id=self._new_id(),
                command="reject_model",
                route_id=route_id,
                version=version,
            ).model_dump()
        )
        resp = RejectModelResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"reject_model failed: {resp.error}")

    async def trigger_killswitch(self, reason: str = "API kill-switch request") -> None:
        raw = await self._call(
            TriggerKillswitchRequest(
                request_id=self._new_id(),
                command="trigger_killswitch",
                reason=reason,
            ).model_dump()
        )
        resp = TriggerKillswitchResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"trigger_killswitch failed: {resp.error}")

    async def reload_rules(self) -> int:
        raw = await self._call(
            ReloadRulesRequest(
                request_id=self._new_id(), command="reload_rules"
            ).model_dump()
        )
        resp = ReloadRulesResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"reload_rules failed: {resp.error}")
        return resp.rules_loaded

    async def get_mode(self) -> str:
        raw = await self._call(
            GetModeRequest(request_id=self._new_id(), command="get_mode").model_dump()
        )
        resp = GetModeResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"get_mode failed: {resp.error}")
        return resp.mode

    async def set_mode(self, mode: str) -> tuple[str, str]:
        raw = await self._call(
            SetModeRequest(
                request_id=self._new_id(), command="set_mode", mode=mode
            ).model_dump()
        )
        resp = SetModeResponse(**raw)
        if not resp.ok:
            raise IpcClientError(f"set_mode failed: {resp.error}")
        return resp.previous_mode, resp.new_mode


__all__ = [
    "IpcClient",
    "IpcClientError",
]
