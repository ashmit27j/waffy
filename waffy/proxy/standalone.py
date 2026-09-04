"""waffy/proxy/standalone.py — TLS-terminating standalone reverse-proxy mode.

Architecture
------------
- Owns the public listener (default 443 / 80 redirect).
- Terminates TLS using the ``CertificateProvider`` protocol (a concrete
  ``FileCertificateProvider`` is provided that reads cert + key from
  configured file paths).
- Decrypts inbound HTTPS, passes the plaintext request through the full
  detection/scoring/decision/enforcement pipeline (``WaffyPipelineApplication``),
  then forwards the upstream response back to the client.
- Upstream connectivity uses the ``UpstreamClient`` protocol — a real
  ``HttpxUpstreamClient`` or any Fake for testing.

ACME / Let's Encrypt
--------------------
Automatic certificate provisioning (ACME / Let's Encrypt) is a **stretch goal**
and is intentionally **NOT implemented in this phase**.  The current
``CertificateProvider`` protocol is deliberately designed to accommodate an
ACME implementation in a later phase without changing call sites.  Until then
an operator must supply a pre-obtained PEM cert and key via configuration
(``transport.tls_cert_path`` / ``transport.tls_key_path``).
"""

import asyncio
import contextlib
import logging
import socket
import ssl
from pathlib import Path
from typing import Any, Literal

from waffy.core.interfaces import (
    CertificateProvider,
)
from waffy.proxy.tls_fingerprint import (
    MAX_CLIENT_HELLO_BYTES,
    TLS_HANDSHAKE_RECORD_TYPE,
    TlsFingerprintRegistry,
    build_fingerprint_aware_protocol,
    compute_ja3,
    parse_client_hello,
)

logger = logging.getLogger("waffy.proxy.standalone")


class FileCertificateProvider:
    """Concrete ``CertificateProvider`` that loads a cert/key pair from disk.

    This implementation covers the common case of a statically provisioned
    certificate (e.g., issued by an internal CA or Let's Encrypt via certbot
    in manual/hook mode).

    ACME stretch goal
    -----------------
    Automatic renewal via the ACME protocol (draft-ietf-acme-acme) is NOT
    implemented.  To add it: implement ``CertificateProvider.renew_certificate``
    using an ACME client library (e.g., ``acme`` from certbot) and arrange a
    periodic background task to call it before ``not_after`` is within a
    configurable renewal window.
    """

    def __init__(self, cert_path: str, key_path: str) -> None:
        self.cert_path = Path(cert_path)
        self.key_path = Path(key_path)

    async def get_certificate(self, domain: str) -> tuple[str, str] | None:
        """Read and return (cert_pem, key_pem) from disk.

        The *domain* argument is accepted for interface compatibility with
        future SNI-multiplexed ACME implementations but is not used by this
        file-based provider.
        """
        _ = domain
        if not self.cert_path.exists() or not self.key_path.exists():
            logger.error(
                "TLS certificate or key file not found: cert=%s key=%s",
                self.cert_path,
                self.key_path,
            )
            return None
        return self.cert_path.read_text(), self.key_path.read_text()

    async def renew_certificate(self, domain: str) -> bool:
        """Not implemented — ACME stretch goal (see module docstring)."""
        logger.warning(
            "renew_certificate called for '%s' but ACME is not implemented "
            "in this phase.  Provision the certificate manually and restart "
            "the process to pick up the new material.",
            domain,
        )
        return False


def build_ssl_context(cert_pem: str, key_pem: str) -> ssl.SSLContext:
    """Build a server-side ``ssl.SSLContext`` from PEM-encoded material.

    Settings applied:
    - TLS 1.2 minimum (TLS 1.0 / 1.1 disabled).
    - ``OP_NO_SSLv2`` / ``OP_NO_SSLv3`` unconditionally set.
    - ECDH cipher preference for forward secrecy.
    - Server-side cipher ordering enabled.
    """
    import tempfile

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_SSLv2  # type: ignore[attr-defined]
    ctx.options |= ssl.OP_NO_SSLv3  # type: ignore[attr-defined]
    ctx.set_ciphers(
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP"
    )
    # SSLContext.load_cert_chain requires file paths; write PEM material to
    # ephemeral temp files that are immediately unlinked after loading.
    with (
        tempfile.NamedTemporaryFile(mode="w", suffix=".crt", delete=False) as cert_f,
        tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as key_f,
    ):
        cert_f.write(cert_pem)
        key_f.write(key_pem)
        cert_path = cert_f.name
        key_path = key_f.name
    try:
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    finally:
        import os as _os
        _os.unlink(cert_path)
        _os.unlink(key_path)
    return ctx


class StandaloneProxyConfig:
    """Runtime configuration for the TLS standalone proxy mode."""

    def __init__(
        self,
        *,
        tls_host: str = "0.0.0.0",
        tls_port: int = 443,
        http_port: int = 80,
        cert_path: str = "/etc/waffy/tls/server.crt",
        key_path: str = "/etc/waffy/tls/server.key",
    ) -> None:
        self.tls_host = tls_host
        self.tls_port = tls_port
        self.http_port = http_port
        self.cert_provider: CertificateProvider = FileCertificateProvider(cert_path, key_path)


# ---------------------------------------------------------------------------
# Pre-accept ClientHello peek stage (prompts/13b)
#
# See docs/ARCHITECTURE.md's prompts/13/13b write-up for the full
# investigation. Summary: uvicorn/asyncio's ``loop.create_server(ssl=ctx)``
# performs the TLS handshake inside the transport layer, consuming the raw
# ClientHello before any application code runs -- there is no way to recover
# those bytes afterward once any asyncio Transport/Protocol has touched the
# socket. ``socket.MSG_PEEK`` on the bare, not-yet-asyncio-managed socket is
# the only way to see them without losing them, which is why this listener
# owns its own accept loop instead of delegating to uvicorn's ``ssl=``
# handling. ``asyncio.loop.start_tls()`` (a public, documented API) then
# performs the real handshake against those same, still-untouched bytes.
#
# Linux-only assumption: ``socket.MSG_PEEK`` is POSIX and this has only been
# exercised on the project's WSL/Linux development and test environment --
# consistent with CLAUDE.md's IPC layer already requiring
# ``socket.AF_UNIX``/``asyncio.start_unix_server``, which ties this project
# to POSIX already. Not verified on native Windows sockets.
# ---------------------------------------------------------------------------

Ja3CaptureMode = Literal["clienthello_peek", "post_handshake", "disabled"]
"""Mirrors ``waffy.config.models.TlsConfig.ja3_capture_mode`` -- kept as a
standalone type alias (not imported from ``waffy.config``) so this module
never depends on the config layer, matching every other proxy-layer module's
plain-callable/plain-value boundary with the layers above it."""


class _NullPlainProtocol(asyncio.Protocol):
    """Transient, do-nothing protocol for the brief plain-socket phase
    between ``loop.create_connection(sock=...)`` and ``loop.start_tls()``.

    No bytes are ever read through this protocol -- the ClientHello was
    already inspected via ``socket.MSG_PEEK`` before this protocol was ever
    attached, without consuming anything, so there is nothing for
    ``data_received`` to legitimately see before the TLS upgrade takes over.
    If it ever fires, that is logged (not silently ignored) since it would
    mean a real behavioral assumption broke.
    """

    def data_received(self, data: bytes) -> None:
        logger.warning(
            "Unexpected plaintext bytes (%d) reached the pre-TLS placeholder "
            "protocol before start_tls() -- MSG_PEEK/handoff assumption violated.",
            len(data),
        )


async def _wait_socket_readable(loop: asyncio.AbstractEventLoop, sock: socket.socket) -> None:
    """Wait until *sock* is readable, without reading anything from it."""
    fut: asyncio.Future[None] = loop.create_future()

    def _on_readable() -> None:
        if not fut.done():
            fut.set_result(None)

    loop.add_reader(sock.fileno(), _on_readable)
    try:
        await fut
    finally:
        loop.remove_reader(sock.fileno())


async def peek_client_hello_bytes(
    loop: asyncio.AbstractEventLoop,
    sock: socket.socket,
    *,
    max_bytes: int = MAX_CLIENT_HELLO_BYTES,
    timeout_seconds: float = 2.0,
) -> bytes | None:
    """Peek up to *max_bytes* off *sock* via ``socket.MSG_PEEK``, waiting for
    more to arrive as TCP segments trickle in, without ever consuming bytes
    from the kernel receive buffer.

    Every byte on this socket is attacker-controlled input, so this is
    deliberately bounded on two independent axes and never raises or blocks
    indefinitely:

    - **Size**: capped at *max_bytes* regardless of what the TLS record
      header claims its length is (an oversized/bogus declared length is
      simply truncated, matching ``parse_client_hello``'s own bound).
    - **Time**: capped at *timeout_seconds* wall-clock, covering both
      "nothing arrived at all" and "arrived but fragmented across many tiny
      TCP segments" cases.

    Returns ``None`` (never partial/ambiguous data) on: timeout, the peer
    closing before sending anything, or the first byte not looking like a
    TLS handshake record at all (fast rejection of non-TLS traffic on this
    port -- no point waiting further in that case). The socket is left
    completely untouched in every case, successful or not, so a normal TLS
    handshake (or whatever the peer actually sent) can proceed against it
    afterward with nothing lost.
    """
    deadline = loop.time() + timeout_seconds
    while True:
        try:
            peeked: bytes | None = sock.recv(max_bytes, socket.MSG_PEEK)
        except BlockingIOError:
            peeked = None
        except OSError:
            return None

        if peeked is not None:
            if len(peeked) == 0:
                return None  # peer closed before sending anything
            if peeked[0] != TLS_HANDSHAKE_RECORD_TYPE:
                return None  # not a TLS handshake record -- not worth waiting for more
            if len(peeked) >= 5:
                record_len = int.from_bytes(peeked[3:5], "big")
                needed = min(5 + record_len, max_bytes)
                if len(peeked) >= needed:
                    return peeked[:needed]
            # else: some bytes but not a full record yet -- fall through and wait

        remaining = deadline - loop.time()
        if remaining <= 0:
            return None
        try:
            await asyncio.wait_for(_wait_socket_readable(loop, sock), timeout=remaining)
        except TimeoutError:
            return None


class PreAcceptTlsServer:
    """Standalone TLS mode's listener: a custom TCP accept loop that peeks
    each connection's raw ClientHello via ``socket.MSG_PEEK`` (see
    ``peek_client_hello_bytes``) to compute a byte-accurate canonical JA3
    fingerprint *before* handing the untouched socket off to a normal TLS
    handshake via ``asyncio.loop.start_tls()``.

    Replaces the prior uvicorn-``ssl=``-delegated approach for standalone
    mode specifically (see module-level comment above and
    ``docs/ARCHITECTURE.md``) -- plaintext and middleware modes are
    unaffected, they never terminate TLS themselves.

    Scope note: this class tracks and cancels in-flight peek/handshake
    *setup* tasks on ``stop()``, but does not itself drain already-upgraded,
    actively-serving HTTP connections -- that's the same granularity
    ``waffy/http/limits.py::TransportResourceProtector`` and
    ``waffy/runtime/core_daemon.py``'s drain logic already provide one layer
    up, at the request level, not duplicated here.
    """

    def __init__(
        self,
        app: Any,  # noqa: ANN401 -- any ASGI-callable object; matches uvicorn.Config's own `app` typing
        ssl_context: ssl.SSLContext,
        *,
        host: str = "0.0.0.0",
        port: int = 443,
        fingerprint_registry: TlsFingerprintRegistry | None = None,
        peek_max_bytes: int = MAX_CLIENT_HELLO_BYTES,
        peek_timeout_seconds: float = 2.0,
        handshake_timeout_seconds: float = 10.0,
        backlog: int = 2048,
        capture_mode: Ja3CaptureMode = "clienthello_peek",
    ) -> None:
        """*capture_mode* mirrors ``TlsConfig.ja3_capture_mode`` (see
        ``waffy/config/models.py``) -- passed through explicitly here rather
        than importing ``WaffyConfig`` into this module, so this class stays
        usable/testable without constructing a full config object:

        - ``"clienthello_peek"``: peek the raw ClientHello for a
          byte-accurate canonical JA3 (falls back to ``"post_handshake"``'s
          signal per-connection on peek failure/timeout).
        - ``"post_handshake"``: skip the peek entirely, always use the
          post-handshake ``SSLObject``-derived signal.
        - ``"disabled"``: never populate *fingerprint_registry* at all.
        """
        self.ssl_context = ssl_context
        self.host = host
        self.port = port
        self.backlog = backlog
        self.peek_max_bytes = peek_max_bytes
        self.peek_timeout_seconds = peek_timeout_seconds
        self.capture_mode: Ja3CaptureMode = capture_mode
        # Bounds asyncio.loop.start_tls() itself -- independent of the peek
        # timeout above, since a peek failure/timeout still falls through to
        # a real handshake attempt (never drops the connection outright on
        # peek failure alone), and that attempt must not be allowed to hang
        # forever against a client that never completes a handshake.
        self.handshake_timeout_seconds = handshake_timeout_seconds
        self.registry = fingerprint_registry or TlsFingerprintRegistry()

        import uvicorn

        # Config/ServerState typed Any: uvicorn's Config/ServerState carry
        # partial stub coverage and this module already treats them as
        # opaque configuration/state containers, matching the prior
        # build_standalone_uvicorn_config's same Any-typing rationale.
        self._config: Any = uvicorn.Config(app=app, host=host, port=port, lifespan="off")
        self._server_state: Any = None
        self._app_state: dict[str, Any] = {}
        self._listen_sock: socket.socket | None = None
        self._accept_task: asyncio.Task[None] | None = None
        self._connection_tasks: set[asyncio.Task[None]] = set()

    @property
    def bound_port(self) -> int | None:
        """The actual bound port (useful when *port* was 0, e.g. in tests)."""
        if self._listen_sock is None:
            return None
        return int(self._listen_sock.getsockname()[1])

    async def start(self) -> None:
        """Bind the listening socket and start the accept loop."""
        from uvicorn.server import ServerState

        if not self._config.loaded:
            self._config.load()
        self._server_state = ServerState()
        self._app_state = self._config.lifespan_class(self._config).state

        listen_sock: socket.socket = self._config.bind_socket()
        listen_sock.listen(self.backlog)
        listen_sock.setblocking(False)
        self._listen_sock = listen_sock

        loop = asyncio.get_running_loop()
        self._accept_task = loop.create_task(self._accept_loop(loop))
        logger.info(
            "Standalone TLS pre-accept listener bound on %s:%d (peek timeout %.1fs)",
            self.host,
            self.bound_port or self.port,
            self.peek_timeout_seconds,
        )

    async def stop(self) -> None:
        """Stop accepting new connections and cancel any in-flight
        peek/handshake setup. Does not drain already-upgraded connections
        (see class docstring's scope note).
        """
        if self._accept_task is not None:
            self._accept_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._accept_task
            self._accept_task = None

        for task in list(self._connection_tasks):
            task.cancel()
        if self._connection_tasks:
            await asyncio.gather(*self._connection_tasks, return_exceptions=True)

        if self._listen_sock is not None:
            self._listen_sock.close()
            self._listen_sock = None

    async def _accept_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        assert self._listen_sock is not None
        while True:
            try:
                conn, addr = await loop.sock_accept(self._listen_sock)
            except asyncio.CancelledError:
                raise
            except OSError:
                logger.exception("Error accepting a standalone TLS connection")
                continue

            task = loop.create_task(self._handle_connection(loop, conn, addr))
            self._connection_tasks.add(task)
            task.add_done_callback(self._connection_tasks.discard)

    async def _handle_connection(
        self,
        loop: asyncio.AbstractEventLoop,
        conn: socket.socket,
        addr: tuple[Any, ...],
    ) -> None:
        peer = (str(addr[0]), int(addr[1]))
        conn.setblocking(False)
        try:
            if self.capture_mode == "clienthello_peek":
                peeked = await peek_client_hello_bytes(
                    loop,
                    conn,
                    max_bytes=self.peek_max_bytes,
                    timeout_seconds=self.peek_timeout_seconds,
                )
                fingerprint: str | None = None
                if peeked is not None:
                    info = parse_client_hello(peeked)
                    if info is not None:
                        fingerprint = compute_ja3(info)
                if fingerprint is not None:
                    self.registry.record(peer, fingerprint)
                # else: falls through to build_fingerprint_aware_protocol's
                # own post-handshake fallback below, exactly as if
                # capture_mode were "post_handshake" for this one connection.

            protocol_class = self._config.http_protocol_class
            if self.capture_mode == "disabled":
                # No fingerprint capture at all -- use uvicorn's own protocol
                # class unmodified, same neutral-signal behavior as
                # plaintext mode.
                real_protocol_class: Any = protocol_class
            else:
                # Any: the returned class's __init__ signature matches
                # uvicorn's concrete HTTP protocol implementation
                # (config/server_state/app_state/_loop), which
                # type[asyncio.Protocol] can't statically express -- same
                # dynamic-subclass rationale as the `# type: ignore[misc]`
                # on _FingerprintAwareProtocol's base list. Also the
                # "post_handshake" mode's sole capture path, since the peek
                # above is skipped entirely for that mode.
                real_protocol_class = build_fingerprint_aware_protocol(
                    self.registry, protocol_class
                )

            plain_transport, _plain_protocol = await loop.create_connection(
                _NullPlainProtocol, sock=conn
            )
            real_protocol = real_protocol_class(
                config=self._config,
                server_state=self._server_state,
                app_state=self._app_state,
                _loop=loop,
            )
            app_transport = await loop.start_tls(
                plain_transport,
                real_protocol,
                self.ssl_context,
                server_side=True,
                ssl_handshake_timeout=self.handshake_timeout_seconds,
            )
            # asyncio.loop.start_tls() always constructs its internal
            # SSLProtocol with call_connection_made=False (not a parameter we
            # can control) -- it assumes *protocol* already had
            # connection_made() called on it during an earlier plain phase
            # (the classic STARTTLS pattern, where the same protocol object
            # is reused). We instead hand it a fresh protocol for the TLS
            # phase specifically, so nothing ever calls its connection_made()
            # unless we do it ourselves here -- verified directly against
            # CPython 3.14's asyncio/sslproto.py: without this call,
            # H11Protocol/HttpToolsProtocol never runs their own
            # connection_made() (never sets scope["client"], never starts
            # reading), while data_received()/connection_lost() fire on it
            # regardless, corrupting request handling.
            real_protocol.connection_made(app_transport)
        except asyncio.CancelledError:
            self.registry.forget(peer)
            with contextlib.suppress(OSError):
                conn.close()
            raise
        except Exception:
            # Never let one connection's handshake/setup failure crash the
            # accept loop or the listener -- same fail-safe stance as every
            # other evidence/connection-handling path in this codebase.
            logger.debug(
                "Standalone TLS connection setup failed for %s", addr, exc_info=True
            )
            self.registry.forget(peer)
            with contextlib.suppress(OSError):
                conn.close()


__all__ = [
    "FileCertificateProvider",
    "Ja3CaptureMode",
    "PreAcceptTlsServer",
    "build_ssl_context",
    "peek_client_hello_bytes",
    "StandaloneProxyConfig",
]
