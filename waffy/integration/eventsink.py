"""waffy/integration/eventsink.py — EventSink protocol implementations.

Provides:
- ``SyslogEventSink``: forwards ``SecurityEvent``s to a remote syslog/JSON-
  over-network receiver (Wazuh-compatible, UDP or TCP).  The event shape
  is kept intentionally similar to pirewall's own event schema (type,
  severity, timestamp, source_ip, correlation_id, summary) so an operator
  running both tools can correlate events by eye without any code coupling.
- ``FakeEventSink``: in-memory sink for testing.  Implements the same
  ``EventSink`` protocol; collected events are accessible via ``.events``.

Both implementations satisfy the ``EventSink`` Protocol from
``waffy/core/interfaces.py``.
"""

import asyncio
import json
import logging
import socket
import time
from collections import deque
from datetime import UTC, datetime
from typing import Any

from waffy.core.models.domain import SecurityEvent

logger = logging.getLogger("waffy.integration.eventsink")

# Wazuh-compatible syslog severity mapping.
_SEVERITY_MAP: dict[str, int] = {
    "info": 6,       # LOG_INFO
    "warning": 4,    # LOG_WARNING
    "error": 3,      # LOG_ERR
    "critical": 2,   # LOG_CRIT
}
# RFC 5424 facility: security/authorization messages (4) → 4 << 3 = 32
_FACILITY: int = 4


def _format_syslog_rfc5424(event: SecurityEvent) -> bytes:
    """Encode a SecurityEvent as an RFC 5424 syslog frame with a JSON body.

    The JSON body mirrors the format Wazuh agents emit so an operator can
    correlate waffy and Wazuh events in the same dashboard without any
    special decoder.
    """
    severity = _SEVERITY_MAP.get(event.severity.value.lower(), 6)
    pri = (_FACILITY << 3) | severity
    timestamp = event.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    body: dict[str, Any] = {
        "type": event.type.value,
        "severity": event.severity.value,
        "timestamp": timestamp,
        "source_ip": event.source_ip,
        "correlation_id": event.correlation_id,
        "summary": event.summary,
        "details": event.details,
        "waffy_event_id": event.id,
    }
    json_body = json.dumps(body, default=str)
    message = (
        f"<{pri}>1 {timestamp} waffy - - - - {json_body}"
    )
    return message.encode()


class SyslogEventSink:
    """Real EventSink that forwards SecurityEvents to a syslog/JSON receiver.

    Wazuh compatibility
    -------------------
    The JSON payload emitted in the syslog message body follows the shape
    Wazuh's own log events use (``type``, ``severity``, ``timestamp``,
    ``source_ip``, ``correlation_id``, ``summary``).  No Wazuh code is
    imported or required — the compatibility is structural/schematic only.

    Parameters
    ----------
    host:
        Syslog receiver hostname or IP.
    port:
        Syslog receiver port (default 514).
    protocol:
        ``"udp"`` (default) or ``"tcp"``.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 514,
        protocol: str = "udp",
    ) -> None:
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self._pending: deque[SecurityEvent] = deque()
        self._flush_lock = asyncio.Lock()

    async def emit(self, event: SecurityEvent) -> None:
        """Emit a security event to the syslog receiver."""
        self._pending.append(event)
        await self._send(event)

    async def _send(self, event: SecurityEvent) -> None:
        payload = _format_syslog_rfc5424(event)
        try:
            if self.protocol == "tcp":
                await self._send_tcp(payload)
            else:
                await self._send_udp(payload)
        except Exception:
            logger.exception(
                "Failed to forward SecurityEvent %s to syslog %s:%d",
                event.id,
                self.host,
                self.port,
            )

    async def _send_udp(self, payload: bytes) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, self._udp_blocking, payload
        )

    def _udp_blocking(self, payload: bytes) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload, (self.host, self.port))

    async def _send_tcp(self, payload: bytes) -> None:
        reader, writer = await asyncio.open_connection(self.host, self.port)
        try:
            writer.write(payload + b"\n")
            await writer.drain()
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:
                pass

    async def flush(self) -> None:
        """No-op: UDP is fire-and-forget; TCP flushes inline in emit."""


class FakeEventSink:
    """In-memory EventSink for testing.  Collects all emitted events."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def emit(self, event: SecurityEvent) -> None:
        self.events.append(event)

    async def flush(self) -> None:
        pass  # Nothing to flush.

    def clear(self) -> None:
        self.events.clear()


__all__ = [
    "SyslogEventSink",
    "FakeEventSink",
    "format_syslog_rfc5424",
]


def format_syslog_rfc5424(event: SecurityEvent) -> bytes:
    """Public alias for ``_format_syslog_rfc5424`` (used in tests)."""
    return _format_syslog_rfc5424(event)
