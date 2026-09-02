"""Unit and integration tests for Phase 2 HTTP engine, parser, body, and normalization."""

import gzip
import importlib.util
import json
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
from starlette.requests import Request

from tests.helpers.fakes import FakeUpstreamClient
from waffy.config.models import HttpConfig, WaffyConfig
from waffy.core.enums import HttpMethod
from waffy.core.exceptions import RequestMalformedError
from waffy.http.body import decompress_body, parse_body, parse_safe_xml
from waffy.http.normalize import (
    normalize_path_for_detection,
    normalize_percent_encoding,
    normalize_query_string,
)
from waffy.http.parser import parse_asgi_request, validate_request_framing
from waffy.http.transport import ProxyApplication


def test_anti_evasion_table() -> None:
    # 1. Double percent-encoding
    double_encoded = "%252e%252e%252fetc%252fpasswd"
    norm, passes = normalize_percent_encoding(double_encoded, max_passes=5)
    assert norm == "../etc/passwd"
    assert passes >= 2

    # 2. Mixed encoding & traversal
    mixed = "/static/images/..%2f..%2f..%2fetc/shadow"
    norm_path, _ = normalize_path_for_detection(mixed)
    assert norm_path == "/etc/shadow"

    # 3. Traversal with double slashes & dots
    complex_path = "///app/./v1/../../etc/passwd"
    norm_path2, _ = normalize_path_for_detection(complex_path)
    assert norm_path2 == "/etc/passwd"

    # 4. Null byte injection removal
    null_byte_str = "admin%00.php"
    norm_query, _ = normalize_query_string(null_byte_str)
    assert "\x00" not in norm_query
    assert norm_query == "admin.php"

    # 5. Plus as space in query
    query_plus = "SELECT+*+FROM+users+WHERE+1=1"
    norm_q, _ = normalize_query_string(query_plus)
    assert norm_q == "SELECT * FROM users WHERE 1=1"


def test_malformed_framing_ambiguity() -> None:
    cfg = HttpConfig()

    # Both Content-Length and Transfer-Encoding present -> Smuggling vector
    headers_both = [
        (b"content-length", b"10"),
        (b"transfer-encoding", b"chunked"),
    ]
    with pytest.raises(RequestMalformedError, match="both Content-Length and Transfer-Encoding"):
        validate_request_framing(headers_both, cfg)

    # Conflicting duplicate Content-Length headers
    headers_conflict = [
        (b"content-length", b"10"),
        (b"content-length", b"20"),
    ]
    with pytest.raises(RequestMalformedError, match="Conflicting Content-Length"):
        validate_request_framing(headers_conflict, cfg)

    # Comma-delimited conflicting Content-Length
    headers_comma = [
        (b"content-length", b"15, 25"),
    ]
    with pytest.raises(RequestMalformedError, match="Conflicting Content-Length"):
        validate_request_framing(headers_comma, cfg)

    # Excessive headers count
    small_cfg = HttpConfig(max_header_count=3)
    headers_many = [(f"h{i}".encode(), b"v") for i in range(5)]
    with pytest.raises(RequestMalformedError, match="Header count"):
        validate_request_framing(headers_many, small_cfg)


def test_decompression_bomb_guard() -> None:
    cfg = HttpConfig(
        max_decompressed_body_bytes=10000,
        max_decompression_ratio=5.0,
    )

    # Large compressible data
    bomb_raw = b"A" * 50000
    bomb_compressed = gzip.compress(bomb_raw)

    with pytest.raises(RequestMalformedError, match="exceeds max limit|exceeds max allowed ratio"):
        decompress_body(bomb_compressed, "gzip", cfg)

    # Valid compressed payload within limit
    valid_raw = b'{"status": "ok"}'
    valid_compressed = gzip.compress(valid_raw)
    result = decompress_body(valid_compressed, "gzip", cfg)
    assert result == valid_raw


def test_safe_xml_xxe_protection() -> None:
    # 1. Malicious XXE with external entity definition is rejected by parser as undefined entity
    xxe_payload = b"""<?xml version="1.0"?>
    <!DOCTYPE root [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <root><name>&xxe;</name><status>active</status></root>
    """
    with pytest.raises(RequestMalformedError, match="undefined entity|Malformed XML"):
        parse_safe_xml(xxe_payload)

    # 2. Benign XML parses cleanly without external entity expansion
    benign_xml = b"""<?xml version="1.0"?>
    <root><name>alice</name><status>active</status></root>
    """
    parsed = parse_safe_xml(benign_xml)
    assert parsed["tag"] == "root"
    assert len(parsed["children"]) == 2
    assert parsed["children"][0]["text"] == "alice"


def test_multipart_parsing() -> None:
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    ct_header = f"multipart/form-data; boundary={boundary}"
    multipart_body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="username"\r\n\r\n'
        "john_doe\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n"
        "Hello file content\r\n"
        f"--{boundary}--\r\n"
    ).encode()

    cfg = HttpConfig()
    _, parsed = parse_body(multipart_body, ct_header, "", cfg)
    assert parsed["fields"]["username"] == ["john_doe"]
    assert len(parsed["files"]) == 1
    assert parsed["files"][0]["filename"] == "test.txt"
    assert parsed["files"][0]["content_type"] == "text/plain"
    assert parsed["files"][0]["size"] == len(b"Hello file content")


@pytest.mark.asyncio
async def test_end_to_end_proxy_pipeline() -> None:
    config = WaffyConfig()
    upstream = FakeUpstreamClient(
        status_code=200,
        headers=[("content-type", "application/json")],
        body=b'{"upstream": "response"}',
    )
    app = ProxyApplication(config, upstream)

    # Use httpx.AsyncClient with Starlette ASGI transport
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Benign GET request
        resp = await client.get("/api/v1/resource?query=hello+world")
        assert resp.status_code == 200
        assert resp.json() == {"upstream": "response"}
        assert len(upstream.recorded_requests) == 1
        recorded_req, _ = upstream.recorded_requests[0]
        assert recorded_req.path == "/api/v1/resource"
        assert recorded_req.query_string == "query=hello world"

        # 2. Benign POST JSON
        resp_post = await client.post("/api/v1/submit", json={"key": "value"})
        assert resp_post.status_code == 200
        assert len(upstream.recorded_requests) == 2
        rec_post, raw_b = upstream.recorded_requests[1]
        assert json.loads(raw_b.decode()) == {"key": "value"}
        assert rec_post.parsed_body_summary == {"key": "value"}


# ---------------------------------------------------------------------------
# HTTP/2 desync/evasion coverage (prompts/06)
#
# Investigation finding: this project's actual ASGI server dependency,
# uvicorn, ships ONLY h11 and httptools HTTP/1.x protocol implementations —
# no HTTP/2 support at all. HTTP/2 in the Python ASGI ecosystem normally
# comes from hypercorn, which is not a project dependency either (confirmed
# directly below, not assumed). This means no waffy deployment mode
# (standalone, plaintext, or middleware) can currently negotiate HTTP/2 at
# all — there is no live code path for an HTTP/2-specific smuggling attack
# today, regardless of what waffy/http/parser.py does or doesn't handle.
#
# The tests below still verify the forward-looking half of the question:
# waffy/http/parser.py's ambiguity/smuggling checks (validate_request_framing,
# parse_asgi_request) operate purely on the ASGI-normalized header list and
# body stream — never on HTTP/1.1 wire-level framing bytes — so they are
# structurally version-agnostic. Proven here with synthetic
# http_version="2" ASGI scopes (no real network socket, no h2/hypercorn
# dependency needed) rather than a real H2 connection, since no H2 server
# exists in this stack to produce one.
# ---------------------------------------------------------------------------


def _build_http2_scope(
    headers: list[tuple[bytes, bytes]], path: str = "/", query: bytes = b""
) -> dict[str, Any]:
    """A minimal ASGI HTTP scope shaped like what an H2-capable server would
    produce: http_version="2", scheme="https" (H2 in practice always runs
    over TLS via ALPN), pseudo-headers already translated into method/path/
    scheme by the (hypothetical) server, exactly like uvicorn does for H1.
    """
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "2",
        "method": "POST",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query,
        "headers": headers,
        "client": ("203.0.113.5", 51234),
        "server": ("testserver", 443),
    }


def _make_receive(body: bytes) -> Callable[[], Awaitable[dict[str, Any]]]:
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    return receive


def test_uvicorn_has_no_http2_protocol_implementation() -> None:
    """Direct, checked confirmation (not an assumption) that this project's
    ASGI server stack cannot currently negotiate HTTP/2 at all.

    If this test ever starts failing (a future uvicorn version bundles h2
    support, or h2/hypercorn gets added as a dependency), that's a signal to
    re-run the version-agnostic checks below against a REAL H2 connection,
    not just a synthetic scope — re-investigate before claiming HTTP/2
    compatibility anywhere.
    """
    assert importlib.util.find_spec("uvicorn.protocols.http.h2_impl") is None
    assert importlib.util.find_spec("h2") is None
    assert importlib.util.find_spec("hypercorn") is None


@pytest.mark.asyncio
async def test_http2_scope_smuggling_checks_are_version_agnostic() -> None:
    """The exact table of HTTP/1.1 CL/TE ambiguity cases from
    test_malformed_framing_ambiguity, replayed through the full
    parse_asgi_request() pipeline against an http_version="2" scope. Proves
    the rejection behavior is identical regardless of declared HTTP version,
    because the check only ever looks at the ASGI header list.
    """
    cfg = WaffyConfig().http

    cases: list[tuple[list[tuple[bytes, bytes]], str]] = [
        (
            [(b"content-length", b"10"), (b"transfer-encoding", b"chunked")],
            "both Content-Length and Transfer-Encoding",
        ),
        (
            [(b"content-length", b"10"), (b"content-length", b"20")],
            "Conflicting Content-Length",
        ),
        (
            [(b"content-length", b"15, 25")],
            "Conflicting Content-Length",
        ),
    ]

    for headers, expected_msg in cases:
        scope = _build_http2_scope(headers)
        request = Request(scope, _make_receive(b"x" * 10))
        with pytest.raises(RequestMalformedError, match=expected_msg):
            await parse_asgi_request(request, cfg)


@pytest.mark.asyncio
async def test_http2_excessive_header_count_rejected() -> None:
    """The header-count bound also holds for an http_version="2" scope."""
    cfg = HttpConfig(max_header_count=3)
    headers = [(f"h{i}".encode(), b"v") for i in range(5)]
    scope = _build_http2_scope(headers)
    request = Request(scope, _make_receive(b""))
    with pytest.raises(RequestMalformedError, match="Header count"):
        await parse_asgi_request(request, cfg)


@pytest.mark.asyncio
async def test_http2_clean_request_parses_normally() -> None:
    """A well-formed http_version="2" request parses into a valid
    HttpRequestRecord exactly like an equivalent HTTP/1.1 request would —
    no false-positive rejection introduced for legitimate H2-shaped traffic.
    """
    cfg = WaffyConfig().http
    body = b'{"key":"value"}'
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    scope = _build_http2_scope(headers, path="/api/v1/submit")
    request = Request(scope, _make_receive(body))

    record, raw_body = await parse_asgi_request(request, cfg)

    assert record.method == HttpMethod.POST
    assert record.path == "/api/v1/submit"
    assert raw_body == body
