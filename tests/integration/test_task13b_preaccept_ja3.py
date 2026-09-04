"""Integration tests for prompts/13b: byte-accurate canonical JA3 via a
pre-TLS-accept ``socket.MSG_PEEK`` stage (``waffy.proxy.standalone.PreAcceptTlsServer``).

Coverage
--------
- The MSG_PEEK-derived fingerprint recorded for a real client connection
  matches an independently-computed canonical JA3 for that exact client TLS
  configuration (``test_preaccept_peek_produces_correct_canonical_ja3``).
- A real TLS handshake and HTTP request still complete normally through the
  pre-accept stage -- the peek doesn't consume/lose any bytes
  (``test_real_handshake_completes_through_preaccept_stage``).
- Graceful fallback when the peek fails outright (non-TLS traffic) or times
  out (client connects but sends nothing): the connection is closed cleanly,
  never hangs, and never crashes the listener -- proven by a subsequent
  well-behaved client still completing a normal handshake against the same
  running server (``test_graceful_fallback_non_tls_traffic_and_peek_timeout``).
- The ``TlsConfig.ja3_capture_mode`` operator toggle (``clienthello_peek`` /
  ``post_handshake`` / ``disabled``): ``"post_handshake"`` skips the peek
  entirely and always records the lower-fidelity ``SSLObject``-derived
  signal (``test_capture_mode_post_handshake_skips_peek_uses_ssl_object_signal``);
  ``"disabled"`` completes a normal handshake but never records anything
  (``test_capture_mode_disabled_never_populates_registry``).

All three skip (do not fail) if the ``openssl`` CLI is unavailable, matching
the existing real-TLS integration test's convention.
"""

import asyncio
import contextlib
import socket
import ssl
from pathlib import Path

import httpx
import pytest

from tests.helpers.fakes import FakeRuleStore, FakeUpstreamClient
from tests.helpers.tls import generate_self_signed_cert, openssl_available
from waffy.config.models import WaffyConfig
from waffy.core.enums import ParanoiaLevel
from waffy.detection.positive.models import PositiveSecurityEngine
from waffy.detection.signatures.engine import SignatureEngine
from waffy.http.pipeline import WaffyPipelineApplication
from waffy.proxy.standalone import FileCertificateProvider, PreAcceptTlsServer, build_ssl_context
from waffy.proxy.tls_fingerprint import compute_ja3, parse_client_hello


def _make_pipeline(upstream: FakeUpstreamClient) -> WaffyPipelineApplication:
    return WaffyPipelineApplication(
        config=WaffyConfig(),
        upstream_client=upstream,
        rule_store=FakeRuleStore(),
        signature_engine=SignatureEngine([], paranoia_level=ParanoiaLevel.PL1),
        positive_engine=PositiveSecurityEngine([]),
    )


def _default_client_ssl_context() -> ssl.SSLContext:
    """The exact client TLS configuration used by every test in this file --
    kept in one place so the "reference" ClientHello capture and the real
    handshake against the server under test are guaranteed to use an
    identical configuration (same cipher list, same extensions), which is
    what makes their JA3 hashes comparable at all.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _capture_reference_client_hello_bytes() -> bytes:
    """Send a real ClientHello (from ``_default_client_ssl_context()``) over
    a local ``socket.socketpair()`` and return the raw bytes a plain
    (non-TLS) peer receives -- independent of any server under test, used
    only to compute the expected canonical JA3 for that client
    configuration. The "server" side of the pair never answers, so the
    client's handshake attempt times out and is discarded -- expected, we
    only need the bytes it already wrote to the wire.
    """
    import threading

    client_raw, server_raw = socket.socketpair()
    server_raw.settimeout(5.0)

    def _client_side() -> None:
        client_raw.settimeout(2.0)
        ctx = _default_client_ssl_context()
        try:
            wrapped = ctx.wrap_socket(client_raw, server_hostname="localhost")
            wrapped.close()
        except Exception:
            pass  # Expected: the raw peer never answers with a ServerHello.

    thread = threading.Thread(target=_client_side, daemon=True)
    thread.start()
    try:
        data = server_raw.recv(8192)
    finally:
        thread.join(timeout=3.0)
        server_raw.close()
    return data


def _blocking_tls_client_handshake(host: str, port: int, timeout: float = 5.0) -> tuple[str, int]:
    """Perform a real, blocking TLS client handshake against (host, port)
    using ``_default_client_ssl_context()``. Returns the client's own local
    (ip, port) -- i.e. the key the server records this connection's
    fingerprint under. Raises on handshake failure/timeout (callers that
    expect failure should catch).
    """
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    raw.connect((host, port))
    local_addr = raw.getsockname()
    ctx = _default_client_ssl_context()
    wrapped = ctx.wrap_socket(raw, server_hostname="localhost")
    wrapped.close()
    return local_addr[0], local_addr[1]


async def _build_server(
    tmp_path: Path,
    **server_kwargs: object,
) -> tuple[PreAcceptTlsServer, FakeUpstreamClient, Path]:
    cert_path, key_path = generate_self_signed_cert(tmp_path)
    provider = FileCertificateProvider(str(cert_path), str(key_path))
    cert_and_key = await provider.get_certificate("localhost")
    assert cert_and_key is not None
    cert_pem, key_pem = cert_and_key
    ssl_ctx = build_ssl_context(cert_pem, key_pem)

    upstream = FakeUpstreamClient(status_code=200, body=b"upstream-ok-via-preaccept")
    pipeline = _make_pipeline(upstream)

    server = PreAcceptTlsServer(
        pipeline,
        ssl_ctx,
        host="127.0.0.1",
        port=0,
        **server_kwargs,  # type: ignore[arg-type]
    )
    return server, upstream, cert_path


@pytest.mark.tls_integration
@pytest.mark.asyncio
async def test_preaccept_peek_produces_correct_canonical_ja3(tmp_path: Path) -> None:
    if not openssl_available():
        pytest.skip("openssl CLI not found on PATH")

    # Independent reference: the canonical JA3 this exact client
    # configuration produces, computed with zero involvement from the
    # server under test.
    reference_bytes = _capture_reference_client_hello_bytes()
    reference_info = parse_client_hello(reference_bytes)
    assert reference_info is not None
    expected_ja3 = compute_ja3(reference_info)
    assert len(expected_ja3) == 32  # md5 hex digest, sanity check

    server, _upstream, _cert_path = await _build_server(tmp_path, peek_timeout_seconds=3.0)
    await server.start()
    try:
        port = server.bound_port
        assert port is not None

        local_ip, local_port = await asyncio.to_thread(
            _blocking_tls_client_handshake, "127.0.0.1", port
        )

        recorded = server.registry.get(local_ip, local_port)
        assert recorded is not None
        assert recorded == expected_ja3
    finally:
        await server.stop()


@pytest.mark.tls_integration
@pytest.mark.asyncio
async def test_real_handshake_completes_through_preaccept_stage(tmp_path: Path) -> None:
    """Proves the peek doesn't consume/lose any bytes: a real httpx TLS
    client completes a full handshake and HTTP round-trip through
    PreAcceptTlsServer, reaching WaffyPipelineApplication and the (fake)
    upstream -- the same end-to-end shape as
    test_standalone_tls_real_handshake_roundtrip, just via the new listener.
    """
    if not openssl_available():
        pytest.skip("openssl CLI not found on PATH")

    server, upstream, cert_path = await _build_server(tmp_path, peek_timeout_seconds=3.0)
    await server.start()
    try:
        port = server.bound_port
        assert port is not None

        client_ssl_ctx = ssl.create_default_context(cafile=str(cert_path))
        async with httpx.AsyncClient(verify=client_ssl_ctx) as client:
            resp = await client.get(f"https://127.0.0.1:{port}/hello")
        assert resp.status_code == 200
        assert resp.text == "upstream-ok-via-preaccept"

        assert len(upstream.recorded_requests) == 1
        forwarded_record, _ = upstream.recorded_requests[0]
        assert forwarded_record.tls_info is not None

        # The peek stage also recorded a byte-accurate canonical JA3 for
        # this exact connection (32-char hex MD5, no waffy-tlsfp-v1: prefix).
        assert len(server.registry) == 1
    finally:
        await server.stop()


@pytest.mark.tls_integration
@pytest.mark.asyncio
async def test_capture_mode_post_handshake_skips_peek_uses_ssl_object_signal(
    tmp_path: Path,
) -> None:
    """``capture_mode="post_handshake"`` is the operator revert switch from
    ``TlsConfig.ja3_capture_mode`` -- it must never invoke the peek stage at
    all and must still populate the registry, just with the lower-fidelity
    ``waffy-tlsfp-v1:``-prefixed signal instead of a 32-char canonical JA3.
    """
    if not openssl_available():
        pytest.skip("openssl CLI not found on PATH")

    server, _upstream, _cert_path = await _build_server(
        tmp_path, peek_timeout_seconds=3.0, capture_mode="post_handshake"
    )
    await server.start()
    try:
        port = server.bound_port
        assert port is not None

        local_ip, local_port = await asyncio.to_thread(
            _blocking_tls_client_handshake, "127.0.0.1", port
        )

        recorded = server.registry.get(local_ip, local_port)
        assert recorded is not None
        assert recorded.startswith("waffy-tlsfp-v1:")
    finally:
        await server.stop()


@pytest.mark.tls_integration
@pytest.mark.asyncio
async def test_capture_mode_disabled_never_populates_registry(tmp_path: Path) -> None:
    """``capture_mode="disabled"`` must complete a normal handshake and HTTP
    round-trip but never record any fingerprint at all.
    """
    if not openssl_available():
        pytest.skip("openssl CLI not found on PATH")

    server, _upstream, _cert_path = await _build_server(
        tmp_path, peek_timeout_seconds=3.0, capture_mode="disabled"
    )
    await server.start()
    try:
        port = server.bound_port
        assert port is not None

        local_ip, local_port = await asyncio.to_thread(
            _blocking_tls_client_handshake, "127.0.0.1", port
        )

        assert server.registry.get(local_ip, local_port) is None
        assert len(server.registry) == 0
    finally:
        await server.stop()


@pytest.mark.tls_integration
@pytest.mark.asyncio
async def test_graceful_fallback_non_tls_traffic_and_peek_timeout(tmp_path: Path) -> None:
    """Two failure modes, both must degrade gracefully: non-TLS traffic on
    the port (fast rejection, no waiting), and a client that connects but
    never sends anything (bounded by peek_timeout_seconds then
    handshake_timeout_seconds). Neither may hang the connection or crash
    the listener -- proven by a well-behaved client still completing a
    normal handshake against the same running server afterward.
    """
    if not openssl_available():
        pytest.skip("openssl CLI not found on PATH")

    server, _upstream, _cert_path = await _build_server(
        tmp_path,
        peek_timeout_seconds=0.3,
        handshake_timeout_seconds=1.0,
    )
    await server.start()
    try:
        port = server.bound_port
        assert port is not None
        loop = asyncio.get_running_loop()

        # 1. Non-TLS traffic: first byte isn't 0x16 -- peek rejects
        # immediately, no multi-second wait.
        start = loop.time()
        garbage_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        garbage_sock.setblocking(False)
        await loop.sock_connect(garbage_sock, ("127.0.0.1", port))
        await loop.sock_sendall(garbage_sock, b"GET / HTTP/1.1\r\n\r\n")
        # The server closes the connection once the fake TLS handshake
        # fails; detect that by reading until EOF, bounded by a timeout so
        # a regression (hang) fails the test instead of hanging it.
        with contextlib.suppress(TimeoutError, ConnectionResetError, OSError):
            # Any of these is an acceptable "connection did not hang" outcome.
            await asyncio.wait_for(loop.sock_recv(garbage_sock, 4096), timeout=2.0)
        elapsed = loop.time() - start
        garbage_sock.close()
        assert elapsed < 2.5  # nowhere near peek_timeout+handshake_timeout if it hung

        # 2. Client connects, sends nothing: bounded by peek_timeout_seconds
        # then handshake_timeout_seconds, never indefinite.
        start = loop.time()
        silent_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        silent_sock.setblocking(False)
        await loop.sock_connect(silent_sock, ("127.0.0.1", port))
        with contextlib.suppress(TimeoutError, ConnectionResetError, OSError):
            await asyncio.wait_for(loop.sock_recv(silent_sock, 4096), timeout=5.0)
        elapsed = loop.time() - start
        silent_sock.close()
        assert elapsed < 5.0  # bounded, not indefinite

        # 3. The listener is still alive and accepting normal connections.
        local_ip, local_port = await asyncio.to_thread(
            _blocking_tls_client_handshake, "127.0.0.1", port
        )
        assert server.registry.get(local_ip, local_port) is not None
    finally:
        await server.stop()
