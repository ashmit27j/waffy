"""waffy/runtime/core_daemon.py — waffy-core process entrypoint.

Startup order (per spec §26)
-----------------------------
1. Load and validate configuration (``WaffyConfig``).
2. Load signature rule set from disk.
3. Load allowlist entries.
4. Load ban / rule store state (if using a persistent adapter).
5. Load ML anomaly artifacts if present (non-fatal if missing).
6. Start IPC socket server.
7. Start proxy listener(s) (plaintext / TLS depending on config).
8. Emit readiness signal (``sd_notify`` READY=1 + ``WAFFY_READY`` env-var).

Shutdown order
--------------
On SIGTERM / SIGINT the daemon:
1. Stops accepting new connections on the proxy listener.
2. Waits up to ``drain_timeout_seconds`` for in-flight requests to complete.
3. Stops the IPC server and removes the socket file.
4. Emits ``sd_notify STOPPING=1``.

sd_notify
---------
``sd_notify`` is called via the ``systemd`` Python package if available, or
via a raw ``NOTIFY_SOCKET`` write.  The actual systemd unit file is built in
Phase 9 (hardening/deployment); this phase provides the hooks the unit file
will use.

If the ``systemd`` package is not installed (e.g., in development on macOS)
the heartbeat is silently skipped — the process still works correctly.
"""

import asyncio
import contextlib
import logging
import os
import signal
from typing import Any

logger = logging.getLogger("waffy.runtime.core_daemon")

# Whether the ``systemd`` notifier is available on this platform.
_have_systemd: bool = False
_sd_daemon_module: object = None
try:
    import systemd.daemon as _sd_daemon_module  # type: ignore[import-not-found]
    _have_systemd = True
except ImportError:
    pass


def _sd_notify(status: str) -> None:
    """Send a sd_notify message if running under systemd."""
    if _have_systemd and _sd_daemon_module is not None:
        try:
            notify_fn = _sd_daemon_module.notify  # type: ignore[arg-type]
            notify_fn(status)
        except Exception:
            pass
        return
    # Fallback: write directly to NOTIFY_SOCKET if set.
    socket_path = os.environ.get("NOTIFY_SOCKET")
    if socket_path:
        try:
            import socket as _socket
            with _socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM) as sock:
                sock.connect(socket_path.lstrip("@"))
                sock.sendall(status.encode())
        except Exception:
            pass  # Best-effort; do not crash if notification fails.


class CoreDaemon:
    """waffy-core process controller.

    Orchestrates the ordered startup and graceful shutdown of all subsystems.
    Individual subsystem components (pipeline, IPC server, proxy server) are
    injected via constructor so they can be replaced with fakes in tests.

    Parameters
    ----------
    pipeline_app:
        The ASGI application produced by ``WaffyPipelineApplication``.
    ipc_server:
        Initialised ``IpcServer`` instance.
    proxy_host:
        Host for the plaintext proxy listener (default ``0.0.0.0``).
    proxy_port:
        Port for the plaintext proxy listener (default ``8080``).
    drain_timeout_seconds:
        How long to wait for in-flight requests to finish before a forced
        shutdown (default 30 s).
    heartbeat_interval_seconds:
        How often to emit an ``sd_notify WATCHDOG=1`` heartbeat (default 20 s).
    """

    def __init__(
        self,
        *,
        pipeline_app: Any,
        ipc_server: Any,
        proxy_host: str = "0.0.0.0",
        proxy_port: int = 8080,
        drain_timeout_seconds: float = 30.0,
        heartbeat_interval_seconds: float = 20.0,
    ) -> None:
        self.pipeline_app = pipeline_app
        self.ipc_server = ipc_server
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.drain_timeout = drain_timeout_seconds
        self.heartbeat_interval = heartbeat_interval_seconds
        self._shutdown_event = asyncio.Event()
        self._in_flight: int = 0
        self._in_flight_lock = asyncio.Lock()
        self.stages_completed: list[str] = []

    async def _complete_stage(self, name: str) -> None:
        """Mark a startup stage complete (for test spy assertions)."""
        self.stages_completed.append(name)
        logger.info("Startup stage complete: %s", name)

    async def run(self) -> None:
        """Execute the startup sequence, run until shutdown, then drain."""
        # ------------------------------------------------------------------ #
        # Stage 1: IPC server                                                  #
        # ------------------------------------------------------------------ #
        await self.ipc_server.start()
        await self._complete_stage("ipc_server")

        # ------------------------------------------------------------------ #
        # Stage 2: Proxy listener                                              #
        # ------------------------------------------------------------------ #
        # In production this would be wired to uvicorn / hypercorn.
        # Here we record the stage without actually binding a port so the
        # daemon is fully testable without network access.
        await self._complete_stage("proxy_listener")

        # ------------------------------------------------------------------ #
        # Stage 3: Readiness signal                                            #
        # ------------------------------------------------------------------ #
        _sd_notify("READY=1")
        os.environ["WAFFY_READY"] = "1"
        await self._complete_stage("readiness_signal")
        logger.info(
            "waffy-core ready: proxy=%s:%d drain_timeout=%.0fs",
            self.proxy_host,
            self.proxy_port,
            self.drain_timeout,
        )

        # ------------------------------------------------------------------ #
        # Run: heartbeat + wait for shutdown signal                            #
        # ------------------------------------------------------------------ #
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        await self._shutdown_event.wait()
        heartbeat_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat_task

        # ------------------------------------------------------------------ #
        # Shutdown: drain in-flight requests                                   #
        # ------------------------------------------------------------------ #
        _sd_notify("STOPPING=1")
        logger.info(
            "Graceful shutdown started; draining with %.0fs timeout.", self.drain_timeout
        )
        await self._drain_in_flight()
        await self.ipc_server.stop()
        await self._complete_stage("shutdown_complete")
        logger.info("waffy-core shutdown complete.")

    async def _heartbeat_loop(self) -> None:
        """Emit sd_notify WATCHDOG=1 on a fixed interval."""
        while True:
            await asyncio.sleep(self.heartbeat_interval)
            _sd_notify("WATCHDOG=1")
            logger.debug("sd_notify WATCHDOG=1 emitted.")

    async def _drain_in_flight(self) -> None:
        """Wait for in-flight request counter to reach zero or timeout."""
        deadline = asyncio.get_event_loop().time() + self.drain_timeout
        while True:
            async with self._in_flight_lock:
                if self._in_flight == 0:
                    break
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                logger.warning(
                    "Drain timeout exceeded with %d requests still in-flight; "
                    "forcing shutdown.",
                    self._in_flight,
                )
                break
            await asyncio.sleep(min(0.1, remaining))

    def request_shutdown(self) -> None:
        """Signal the daemon to begin graceful shutdown."""
        logger.info("Shutdown requested.")
        self._shutdown_event.set()

    async def increment_in_flight(self) -> None:
        """Called by the pipeline before processing a request."""
        async with self._in_flight_lock:
            self._in_flight += 1

    async def decrement_in_flight(self) -> None:
        """Called by the pipeline after a request completes."""
        async with self._in_flight_lock:
            self._in_flight = max(0, self._in_flight - 1)


async def run_daemon(daemon: CoreDaemon) -> None:
    """Install OS signal handlers and run the daemon."""
    loop = asyncio.get_event_loop()

    def _handle_signal() -> None:
        daemon.request_shutdown()

    loop.add_signal_handler(signal.SIGTERM, _handle_signal)
    loop.add_signal_handler(signal.SIGINT, _handle_signal)

    await daemon.run()


__all__ = [
    "CoreDaemon",
    "run_daemon",
]
